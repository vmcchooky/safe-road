package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"safe-road/internal/config"
	"safe-road/internal/observability"
	"safe-road/internal/risk"
	"safe-road/internal/serve"
)

type analyzeRequest struct {
	Domain string `json:"domain"`
}

type statusResponse struct {
	Service        string            `json:"service"`
	Status         string            `json:"status"`
	Mode           string            `json:"mode,omitempty"`
	DeploymentTier string            `json:"deployment_tier,omitempty"`
	Redis          *risk.CacheStatus `json:"redis,omitempty"`
	Endpoints      []string          `json:"endpoints,omitempty"`
	Time           string            `json:"time"`
}

type app struct {
	risk           *risk.Service
	metrics        *observability.Registry
	deploymentTier string
}

func main() {
	addr := config.String("SAFE_ROAD_CORE_API_ADDR", ":8080")
	shutdownTimeout := config.DurationMillis("SAFE_ROAD_SHUTDOWN_TIMEOUT_MS", 10*time.Second)

	api := &app{
		risk:           risk.NewServiceFromEnv(),
		metrics:        observability.NewRegistry(),
		deploymentTier: config.String("SAFE_ROAD_DEPLOYMENT_TIER", "budget-vps"),
	}
	defer func() {
		if err := api.risk.Close(); err != nil {
			log.Printf("risk service close failed: %v", err)
		}
	}()
	logCacheStatus("core-api", api.risk)

	mux := http.NewServeMux()
	mux.HandleFunc("/", api.statusHandler)
	mux.HandleFunc("/healthz", healthHandler("core-api"))
	mux.HandleFunc("/readyz", healthHandler("core-api"))
	mux.HandleFunc("/v1/version", versionHandler)
	mux.HandleFunc("/metrics", api.metricsHandler)
	mux.HandleFunc("/v1/analyze", api.analyzeHandler)
	mux.HandleFunc("/v1/analysis/recent", api.recentAnalysisHandler)
	mux.HandleFunc("/dashboard", dashboardHandler)
	mux.HandleFunc("/dashboard/", dashboardHandler)

	server := &http.Server{
		Addr:              addr,
		Handler:           logRequests(mux, api.metrics),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	log.Printf("core-api listening on %s", addr)
	if err := serve.RunHTTPServer(server, shutdownTimeout); err != nil {
		log.Fatal(err)
	}
}

func healthHandler(service string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, statusResponse{
			Service: service,
			Status:  "ok",
			Time:    time.Now().UTC().Format(time.RFC3339Nano),
		})
	}
}

func (a *app) statusHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	cacheStatus := a.risk.CacheStatus(r.Context())
	writeJSON(w, http.StatusOK, statusResponse{
		Service:        "core-api",
		Status:         "ok",
		Mode:           "api",
		DeploymentTier: a.deploymentTier,
		Redis:          &cacheStatus,
		Endpoints: []string{
			"/",
			"/healthz",
			"/readyz",
			"/v1/version",
			"/v1/analyze?domain=example.com",
			"/v1/analysis/recent",
			"/dashboard",
		},
		Time: time.Now().UTC().Format(time.RFC3339Nano),
	})
}

func (a *app) metricsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"service": "core-api",
		"status":  "ok",
		"metrics": a.metrics.Snapshot(),
		"time":    time.Now().UTC().Format(time.RFC3339Nano),
	})
}

func versionHandler(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"service": "core-api",
		"version": "0.1.0",
	})
}

func (a *app) analyzeHandler(w http.ResponseWriter, r *http.Request) {
	var domain string

	switch r.Method {
	case http.MethodGet:
		domain = r.URL.Query().Get("domain")
	case http.MethodPost:
		defer r.Body.Close()
		var req analyzeRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		domain = req.Domain
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	response := a.risk.Analyze(r.Context(), domain)
	a.risk.RecordRecent(r.Context(), response)
	writeJSON(w, http.StatusOK, response)
}

func (a *app) recentAnalysisHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"items": a.risk.Recent(r.Context()),
	})
}

func logCacheStatus(service string, riskService *risk.Service) {
	status := riskService.CacheStatus(context.Background())
	if !status.Configured {
		return
	}
	if status.Status == "ok" {
		log.Printf("%s redis cache connected", service)
		return
	}
	log.Printf("%s redis cache unavailable at startup, continuing without hard dependency: %s", service, status.Error)
}

func logRequests(next http.Handler, metrics *observability.Registry) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		recorder := &statusLoggingResponseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(recorder, r)
		if metrics != nil {
			metrics.Observe(r.Method, r.URL.Path, recorder.statusCode, recorder.bytesWritten, time.Since(started))
		}
		log.Printf("%s %s %d %dB %s", r.Method, r.URL.Path, recorder.statusCode, recorder.bytesWritten, time.Since(started).Truncate(time.Millisecond))
	})
}

type statusLoggingResponseWriter struct {
	http.ResponseWriter
	statusCode   int
	bytesWritten int
}

func (w *statusLoggingResponseWriter) WriteHeader(statusCode int) {
	w.statusCode = statusCode
	w.ResponseWriter.WriteHeader(statusCode)
}

func (w *statusLoggingResponseWriter) Write(p []byte) (int, error) {
	if w.statusCode == 0 {
		w.statusCode = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(p)
	w.bytesWritten += n
	return n, err
}

func writeJSON(w http.ResponseWriter, statusCode int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		log.Printf("write response failed: %v", err)
	}
}

func writeError(w http.ResponseWriter, statusCode int, message string) {
	writeJSON(w, statusCode, map[string]string{"error": message})
}
