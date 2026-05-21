package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"safe-road/internal/agent"
	"safe-road/internal/auth"
	"safe-road/internal/config"
	"safe-road/internal/feed"
	"safe-road/internal/observability"
	"safe-road/internal/ratelimit"
	"safe-road/internal/risk"
	"safe-road/internal/serve"
	"safe-road/internal/store"
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
	sessionSecret  []byte
	adminPassword  string
	adminAPIKey    string
}

func main() {
	addr := config.String("SAFE_ROAD_CORE_API_ADDR", ":8080")
	shutdownTimeout := config.DurationMillis("SAFE_ROAD_SHUTDOWN_TIMEOUT_MS", 10*time.Second)

	secret, err := auth.GenerateSecureRandomString(32)
	if err != nil {
		log.Fatalf("failed to generate session secret: %v", err)
	}
	sessionSecret := []byte(secret)

	adminPassword := config.String("SAFE_ROAD_ADMIN_PASSWORD", "")
	adminAPIKey := config.String("SAFE_ROAD_ADMIN_API_KEY", "")

	if adminPassword == "" {
		var err error
		adminPassword, err = auth.GenerateSecureRandomString(16)
		if err != nil {
			log.Fatalf("failed to generate admin password: %v", err)
		}
		log.Println("┌─────────────────────────────────────────────────────────────────┐")
		log.Println("│ [WARNING] SAFE_ROAD_ADMIN_PASSWORD is not configured in .env!   │")
		log.Printf("│ Generated random admin password: %s │\n", adminPassword)
		log.Println("└─────────────────────────────────────────────────────────────────┘")
	} else if len(adminPassword) < 8 {
		log.Println("┌─────────────────────────────────────────────────────────────────┐")
		log.Println("│ [WARNING] SAFE_ROAD_ADMIN_PASSWORD is too weak (under 8 chars)! │")
		log.Println("│ For production, please configure a strong password in .env!     │")
		log.Println("└─────────────────────────────────────────────────────────────────┘")
	}

	if adminAPIKey == "" {
		var err error
		adminAPIKey, err = auth.GenerateSecureRandomString(24)
		if err != nil {
			log.Fatalf("failed to generate admin API key: %v", err)
		}
		log.Println("┌─────────────────────────────────────────────────────────────────┐")
		log.Println("│ [WARNING] SAFE_ROAD_ADMIN_API_KEY is not configured in .env!    │")
		log.Printf("│ Generated random admin API key: %s  │\n", adminAPIKey)
		log.Println("└─────────────────────────────────────────────────────────────────┘")
	}

	api := &app{
		risk:           risk.NewServiceFromEnv(),
		metrics:        observability.NewRegistry(),
		deploymentTier: config.String("SAFE_ROAD_DEPLOYMENT_TIER", "budget-vps"),
		sessionSecret:  sessionSecret,
		adminPassword:  adminPassword,
		adminAPIKey:    adminAPIKey,
	}
	defer func() {
		if err := api.risk.Close(); err != nil {
			log.Printf("risk service close failed: %v", err)
		}
	}()
	logCacheStatus("core-api", api.risk)

	// --- Rate limiting ---
	rlEnabled := config.Bool("SAFE_ROAD_RATELIMIT_ENABLED", true)
	var tiered *ratelimit.TieredMiddleware
	if rlEnabled {
		analyzeLimiter := ratelimit.New(config.Float64("SAFE_ROAD_RATELIMIT_ANALYZE_RPM", 10), config.Int("SAFE_ROAD_RATELIMIT_ANALYZE_BURST", 5))
		overrideLimiter := ratelimit.New(config.Float64("SAFE_ROAD_RATELIMIT_OVERRIDE_RPM", 20), config.Int("SAFE_ROAD_RATELIMIT_OVERRIDE_BURST", 5))
		telemetryLimiter := ratelimit.New(config.Float64("SAFE_ROAD_RATELIMIT_TELEMETRY_RPM", 30), config.Int("SAFE_ROAD_RATELIMIT_TELEMETRY_BURST", 10))
		defaultLimiter := ratelimit.New(config.Float64("SAFE_ROAD_RATELIMIT_DEFAULT_RPM", 60), config.Int("SAFE_ROAD_RATELIMIT_DEFAULT_BURST", 15))
		defer analyzeLimiter.Close()
		defer overrideLimiter.Close()
		defer telemetryLimiter.Close()
		defer defaultLimiter.Close()
		tiered = ratelimit.NewTieredMiddleware(
			defaultLimiter,
			ratelimit.Tier{PathPrefix: "/v1/analyze", Limiter: analyzeLimiter},
			ratelimit.Tier{PathPrefix: "/v1/overrides", Limiter: overrideLimiter},
			ratelimit.Tier{PathPrefix: "/v1/telemetry", Limiter: telemetryLimiter},
		)
		log.Printf("core-api rate limiting enabled (analyze=%.0f/min, default=%.0f/min)",
			config.Float64("SAFE_ROAD_RATELIMIT_ANALYZE_RPM", 10),
			config.Float64("SAFE_ROAD_RATELIMIT_DEFAULT_RPM", 60))
	}

	// --- Agent Engine ---
	var agentEngine *agent.Engine
	if config.Bool("SAFE_ROAD_AGENT_ENABLED", false) {
		agentEngine = agent.NewEngine()

		// Audit Task
		auditTask := agent.NewAuditTask(
			api.risk.StoreDB(),
			api.risk.AIClient(),
			api.risk.RedisCache(),
			agent.AuditConfig{
				MinOccurrences:      config.Int("SAFE_ROAD_AGENT_AUDIT_MIN_OCCURRENCES", 3),
				MaxPerCycle:         config.Int("SAFE_ROAD_AGENT_AUDIT_MAX_PER_CYCLE", 50),
				ConfidenceThreshold: config.Float64("SAFE_ROAD_AGENT_AUDIT_CONFIDENCE_THRESHOLD", 0.7),
				EnrichTimeout:       config.DurationSeconds("SAFE_ROAD_AGENT_ENRICH_TIMEOUT_SECONDS", 5*time.Second),
			},
		)
		agentEngine.Register(
			auditTask,
			config.DurationSeconds("SAFE_ROAD_AGENT_AUDIT_INTERVAL_SECONDS", 1*time.Hour),
			config.DurationSeconds("SAFE_ROAD_AGENT_AUDIT_TIMEOUT_SECONDS", 5*time.Minute),
			true,
		)

		// Feed Sync Task
		feedSourcesRaw := config.String("SAFE_ROAD_AGENT_FEED_SOURCES", "")
		var feedSources []string
		if feedSourcesRaw != "" {
			for _, s := range strings.Split(feedSourcesRaw, ",") {
				s = strings.TrimSpace(s)
				if s != "" {
					feedSources = append(feedSources, s)
				}
			}
		}
		feedSyncTask := agent.NewFeedSyncTask(
			api.risk.StoreDB(),
			agent.FeedSyncConfig{
				Sources:       feedSources,
				RedisAddr:     config.String("SAFE_ROAD_REDIS_ADDR", ""),
				RedisPassword: config.String("SAFE_ROAD_REDIS_PASSWORD", ""),
				RedisDB:       config.Int("SAFE_ROAD_REDIS_DB", 0),
				FeedKey:       config.String("SAFE_ROAD_THREAT_FEED_KEY", feed.DefaultThreatFeedKey),
				Timeout:       config.DurationSeconds("SAFE_ROAD_AGENT_FEED_TIMEOUT_SECONDS", 2*time.Minute),
			},
		)
		agentEngine.Register(
			feedSyncTask,
			config.DurationSeconds("SAFE_ROAD_AGENT_FEED_INTERVAL_SECONDS", 24*time.Hour),
			config.DurationSeconds("SAFE_ROAD_AGENT_FEED_TIMEOUT_SECONDS", 2*time.Minute),
			len(feedSources) > 0,
		)

		// Alert Task
		alertTask := agent.NewAlertTask(
			api.risk.StoreDB(),
			agent.AlertConfig{
				WebhookURL:      config.String("SAFE_ROAD_AGENT_WEBHOOK_URL", ""),
				MinEvents:       config.Int("SAFE_ROAD_AGENT_ALERT_MIN_EVENTS", 1),
				Timeout:         config.DurationSeconds("SAFE_ROAD_AGENT_ALERT_TIMEOUT_SECONDS", 30*time.Second),
				TelegramEnabled: config.Bool("SAFE_ROAD_ALERT_TELEGRAM_ENABLED", false),
				TelegramToken:   config.String("SAFE_ROAD_ALERT_TELEGRAM_TOKEN", ""),
				TelegramChatID:  config.String("SAFE_ROAD_ALERT_TELEGRAM_CHAT_ID", ""),
				SlackEnabled:    config.Bool("SAFE_ROAD_ALERT_SLACK_ENABLED", false),
				SlackWebhookURL: config.String("SAFE_ROAD_ALERT_SLACK_WEBHOOK_URL", ""),
				EmailEnabled:    config.Bool("SAFE_ROAD_ALERT_EMAIL_ENABLED", false),
				EmailSMTPHost:   config.String("SAFE_ROAD_ALERT_EMAIL_SMTP_HOST", ""),
				EmailSMTPPort:   config.Int("SAFE_ROAD_ALERT_EMAIL_SMTP_PORT", 0),
				EmailFrom:       config.String("SAFE_ROAD_ALERT_EMAIL_FROM", ""),
				EmailPassword:   config.String("SAFE_ROAD_ALERT_EMAIL_PASSWORD", ""),
				EmailTo:         config.String("SAFE_ROAD_ALERT_EMAIL_TO", ""),
			},
		)
		webhookURL := config.String("SAFE_ROAD_AGENT_WEBHOOK_URL", "")
		alertEnabled := webhookURL != "" ||
			config.Bool("SAFE_ROAD_ALERT_TELEGRAM_ENABLED", false) ||
			config.Bool("SAFE_ROAD_ALERT_SLACK_ENABLED", false) ||
			config.Bool("SAFE_ROAD_ALERT_EMAIL_ENABLED", false)

		agentEngine.Register(
			alertTask,
			config.DurationSeconds("SAFE_ROAD_AGENT_ALERT_INTERVAL_SECONDS", 15*time.Minute),
			config.DurationSeconds("SAFE_ROAD_AGENT_ALERT_TIMEOUT_SECONDS", 30*time.Second),
			alertEnabled,
		)

		// Whitelist Update Task
		whitelistUpdateTask := agent.NewWhitelistUpdateTask(
			api.risk.StoreDB(),
			api.risk.Whitelist(),
			agent.WhitelistUpdateConfig{
				SourceURL: config.String("SAFE_ROAD_AGENT_WHITELIST_SOURCE_URL", "https://tranco-list.eu/download/L/1000000"),
				Timeout:   config.DurationSeconds("SAFE_ROAD_AGENT_WHITELIST_TIMEOUT_SECONDS", 10*time.Minute),
				Enabled:   config.Bool("SAFE_ROAD_AGENT_WHITELIST_ENABLED", true),
			},
		)
		agentEngine.Register(
			whitelistUpdateTask,
			config.DurationSeconds("SAFE_ROAD_AGENT_WHITELIST_INTERVAL_SECONDS", 7*24*time.Hour),
			config.DurationSeconds("SAFE_ROAD_AGENT_WHITELIST_TIMEOUT_SECONDS", 10*time.Minute),
			config.Bool("SAFE_ROAD_AGENT_WHITELIST_ENABLED", true),
		)

		agentEngine.Start()
		defer agentEngine.Stop()
		log.Println("agent engine enabled")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", api.statusHandler)
	mux.HandleFunc("/healthz", healthHandler("core-api"))
	mux.HandleFunc("/readyz", healthHandler("core-api"))
	mux.HandleFunc("/v1/version", versionHandler)
	mux.HandleFunc("/metrics", api.metricsHandler)
	mux.HandleFunc("/v1/analyze", api.analyzeHandler)
	mux.HandleFunc("/v1/analysis/recent", api.recentAnalysisHandler)
	mux.HandleFunc("/v1/auth/login", api.authLoginHandler)
	mux.HandleFunc("/v1/auth/logout", api.authLogoutHandler)
	mux.HandleFunc("/v1/overrides", api.requireAuthFunc(api.overridesHandler))
	mux.HandleFunc("/v1/telemetry/recent", api.requireAuthFunc(api.telemetryRecentHandler))
	mux.HandleFunc("/v1/telemetry/stats", api.requireAuthFunc(api.telemetryStatsHandler))
	mux.HandleFunc("/v1/agent/status", api.requireAuthFunc(agentStatusHandler(agentEngine)))
	mux.HandleFunc("/v1/agent/trigger", api.requireAuthFunc(agentTriggerHandler(agentEngine)))
	mux.HandleFunc("/v1/groups", api.requireAuthFunc(api.groupsHandler))
	mux.HandleFunc("/v1/mappings", api.requireAuthFunc(api.mappingsHandler))
	mux.HandleFunc("/v1/group-overrides", api.requireAuthFunc(api.groupOverridesHandler))
	mux.HandleFunc("/dashboard", api.dashboardHandler)
	mux.HandleFunc("/dashboard/", api.dashboardHandler)

	var handler http.Handler = mux
	if tiered != nil {
		handler = tiered.Wrap(mux)
	}

	recoveryHandler := serve.Recovery(handler, api.metrics)

	server := &http.Server{
		Addr:              addr,
		Handler:           logRequests(recoveryHandler, api.metrics),
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
			"/v1/overrides",
			"/v1/telemetry/recent",
			"/v1/telemetry/stats",
			"/v1/agent/status",
			"/v1/agent/trigger?task=<name>",
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
		r.Body = http.MaxBytesReader(w, r.Body, 4096)
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

	clientInfo := extractClientInfo(r)
	response := a.risk.Analyze(r.Context(), domain, clientInfo)
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
		if metrics != nil && r.Context().Value(serve.ObservedPanicKey) == nil {
			metrics.Observe(r.Method, r.URL.Path, recorder.statusCode, recorder.bytesWritten, time.Since(started))
		}
		log.Printf("%s %s %d %dB %s", sanitizeLog(r.Method), sanitizeLog(r.URL.Path), recorder.statusCode, recorder.bytesWritten, time.Since(started).Truncate(time.Millisecond)) // #nosec G706 -- request values are escaped by sanitizeLog before logging.
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

func sanitizeLog(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
}

// --- Overrides API ---

type overrideRequest struct {
	Domain string `json:"domain"`
	Action string `json:"action"`
	Reason string `json:"reason"`
}

func (a *app) overridesHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		action := r.URL.Query().Get("action")
		overrides, err := a.risk.ListOverrides(action)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if overrides == nil {
			overrides = []store.Override{}
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": overrides})

	case http.MethodPost:
		r.Body = http.MaxBytesReader(w, r.Body, 10240)
		defer r.Body.Close()
		var req overrideRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		if req.Domain == "" || req.Action == "" {
			writeError(w, http.StatusBadRequest, "domain and action are required")
			return
		}
		if err := a.risk.UpsertOverride(req.Domain, req.Action, req.Reason); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "domain": req.Domain, "action": req.Action})

	case http.MethodDelete:
		domain := r.URL.Query().Get("domain")
		if domain == "" {
			writeError(w, http.StatusBadRequest, "domain query parameter is required")
			return
		}
		if err := a.risk.DeleteOverride(domain); err != nil {
			writeError(w, http.StatusNotFound, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "domain": domain})

	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// --- Telemetry API ---

func (a *app) telemetryRecentHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	limit := 50
	offset := 0
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	if limit > 100 {
		limit = 100
	}
	if v := r.URL.Query().Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			offset = n
		}
	}

	entries, err := a.risk.TelemetryRecent(limit, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if entries == nil {
		entries = []store.TelemetryEntry{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": entries})
}

func (a *app) telemetryStatsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	period := r.URL.Query().Get("period")
	since := time.Now().Add(-24 * time.Hour) // default 24h
	switch period {
	case "7d":
		since = time.Now().Add(-7 * 24 * time.Hour)
	case "30d":
		since = time.Now().Add(-30 * 24 * time.Hour)
	case "24h", "":
		period = "24h"
	}

	stats, err := a.risk.TelemetryStats(since)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	stats.Period = period
	writeJSON(w, http.StatusOK, stats)
}

// --- Agent API ---

func agentStatusHandler(engine *agent.Engine) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if engine == nil {
			writeJSON(w, http.StatusOK, agent.EngineStatus{Enabled: false})
			return
		}
		writeJSON(w, http.StatusOK, engine.Status())
	}
}

func agentTriggerHandler(engine *agent.Engine) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if engine == nil {
			writeError(w, http.StatusServiceUnavailable, "agent engine not enabled")
			return
		}
		taskName := r.URL.Query().Get("task")
		if taskName == "" {
			writeError(w, http.StatusBadRequest, "task query parameter is required")
			return
		}
		if !engine.Trigger(taskName) {
			writeError(w, http.StatusNotFound, "task not found: "+taskName)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "triggered", "task": taskName})
	}
}

func extractClientInfo(r *http.Request) risk.ClientInfo {
	ip := ""
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		ip = strings.TrimSpace(parts[0])
	}
	if ip == "" {
		if xri := r.Header.Get("X-Real-IP"); xri != "" {
			ip = strings.TrimSpace(xri)
		}
	}
	if ip == "" {
		remoteAddr := r.RemoteAddr
		if idx := strings.LastIndex(remoteAddr, ":"); idx != -1 {
			ip = remoteAddr[:idx]
		} else {
			ip = remoteAddr
		}
		ip = strings.Trim(ip, "[]")
	}

	clientID := r.URL.Query().Get("client_id")
	if clientID == "" {
		path := r.URL.Path
		path = strings.Trim(path, "/")
		parts := strings.Split(path, "/")
		if len(parts) >= 2 && parts[0] == "dns-query" {
			clientID = parts[1]
		} else if len(parts) == 1 && parts[0] != "" && parts[0] != "dns-query" {
			clientID = parts[0]
		}
	}

	return risk.ClientInfo{
		IP:       ip,
		ClientID: clientID,
	}
}

// --- Groups API ---

type groupRequest struct {
	Name            string   `json:"name"`
	Description     string   `json:"description"`
	BlockCategories []string `json:"block_categories"`
	StrictPhishing  bool     `json:"strict_phishing"`
	StrictMalware   bool     `json:"strict_malware"`
}

func (a *app) groupsHandler(w http.ResponseWriter, r *http.Request) {
	db := a.risk.StoreDB()
	if db == nil {
		writeError(w, http.StatusServiceUnavailable, "store not configured")
		return
	}

	switch r.Method {
	case http.MethodGet:
		id := r.URL.Query().Get("id")
		if id != "" {
			var gid int64
			if _, err := fmt.Sscanf(id, "%d", &gid); err != nil {
				writeError(w, http.StatusBadRequest, "invalid group id")
				return
			}
			g, err := db.GetGroup(gid)
			if err != nil {
				writeError(w, http.StatusNotFound, err.Error())
				return
			}
			writeJSON(w, http.StatusOK, g)
			return
		}
		groups, err := db.ListGroups()
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if groups == nil {
			groups = []store.ClientGroup{}
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": groups})

	case http.MethodPost:
		r.Body = http.MaxBytesReader(w, r.Body, 65536)
		defer r.Body.Close()
		var req groupRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		if req.Name == "" {
			writeError(w, http.StatusBadRequest, "name is required")
			return
		}
		id, err := db.CreateGroup(req.Name, req.Description, req.BlockCategories, req.StrictPhishing, req.StrictMalware)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{"id": id, "status": "created"})

	case http.MethodPut:
		r.Body = http.MaxBytesReader(w, r.Body, 65536)
		defer r.Body.Close()
		id := r.URL.Query().Get("id")
		if id == "" {
			writeError(w, http.StatusBadRequest, "id is required")
			return
		}
		var gid int64
		if _, err := fmt.Sscanf(id, "%d", &gid); err != nil {
			writeError(w, http.StatusBadRequest, "invalid group id")
			return
		}
		var req groupRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		if err := db.UpdateGroup(gid, req.Name, req.Description, req.BlockCategories, req.StrictPhishing, req.StrictMalware); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})

	case http.MethodDelete:
		id := r.URL.Query().Get("id")
		if id == "" {
			writeError(w, http.StatusBadRequest, "id is required")
			return
		}
		var gid int64
		if _, err := fmt.Sscanf(id, "%d", &gid); err != nil {
			writeError(w, http.StatusBadRequest, "invalid group id")
			return
		}
		if err := db.DeleteGroup(gid); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})

	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// --- Mappings API ---

type mappingRequest struct {
	MappingType string `json:"mapping_type"`
	Value       string `json:"value"`
	GroupID     int64  `json:"group_id"`
}

func (a *app) mappingsHandler(w http.ResponseWriter, r *http.Request) {
	db := a.risk.StoreDB()
	if db == nil {
		writeError(w, http.StatusServiceUnavailable, "store not configured")
		return
	}

	switch r.Method {
	case http.MethodGet:
		mappings, err := db.ListMappings()
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if mappings == nil {
			mappings = []store.ClientMapping{}
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": mappings})

	case http.MethodPost:
		r.Body = http.MaxBytesReader(w, r.Body, 10240)
		defer r.Body.Close()
		var req mappingRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		if req.MappingType == "" || req.Value == "" || req.GroupID == 0 {
			writeError(w, http.StatusBadRequest, "mapping_type, value, and group_id are required")
			return
		}
		id, err := db.AddMappingInt(req.MappingType, req.Value, req.GroupID)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{"id": id, "status": "created"})

	case http.MethodDelete:
		id := r.URL.Query().Get("id")
		if id == "" {
			writeError(w, http.StatusBadRequest, "id is required")
			return
		}
		var mid int64
		if _, err := fmt.Sscanf(id, "%d", &mid); err != nil {
			writeError(w, http.StatusBadRequest, "invalid mapping id")
			return
		}
		if err := db.DeleteMapping(mid); err != nil {
			writeError(w, http.StatusNotFound, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})

	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// --- Group Overrides API ---

type groupOverrideRequest struct {
	GroupID int64  `json:"group_id"`
	Domain  string `json:"domain"`
	Action  string `json:"action"`
	Reason  string `json:"reason"`
}

func (a *app) groupOverridesHandler(w http.ResponseWriter, r *http.Request) {
	db := a.risk.StoreDB()
	if db == nil {
		writeError(w, http.StatusServiceUnavailable, "store not configured")
		return
	}

	switch r.Method {
	case http.MethodGet:
		groupIDStr := r.URL.Query().Get("group_id")
		if groupIDStr == "" {
			writeError(w, http.StatusBadRequest, "group_id is required")
			return
		}
		var gid int64
		if _, err := fmt.Sscanf(groupIDStr, "%d", &gid); err != nil {
			writeError(w, http.StatusBadRequest, "invalid group_id")
			return
		}
		overrides, err := db.ListGroupOverrides(gid)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if overrides == nil {
			overrides = []store.GroupOverride{}
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": overrides})

	case http.MethodPost, http.MethodPut:
		r.Body = http.MaxBytesReader(w, r.Body, 10240)
		defer r.Body.Close()
		var req groupOverrideRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		if req.GroupID == 0 || req.Domain == "" || req.Action == "" {
			writeError(w, http.StatusBadRequest, "group_id, domain, and action are required")
			return
		}
		if err := db.UpsertGroupOverride(req.GroupID, req.Domain, req.Action, req.Reason); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})

	case http.MethodDelete:
		groupIDStr := r.URL.Query().Get("group_id")
		domain := r.URL.Query().Get("domain")
		if groupIDStr == "" || domain == "" {
			writeError(w, http.StatusBadRequest, "group_id and domain are required")
			return
		}
		var gid int64
		if _, err := fmt.Sscanf(groupIDStr, "%d", &gid); err != nil {
			writeError(w, http.StatusBadRequest, "invalid group_id")
			return
		}
		if err := db.DeleteGroupOverride(gid, domain); err != nil {
			writeError(w, http.StatusNotFound, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})

	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// --- Authentication & Session Handlers ---

func isHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	if strings.ToLower(r.Header.Get("X-Forwarded-Proto")) == "https" {
		return true
	}
	return false
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (a *app) authLoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	// Limit request body size to 4KB to prevent JSON memory exhaustion DoS attacks
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	defer r.Body.Close()

	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	// Use ConstantTimeCompare with SHA-256 hashing to secure comparisons against timing attacks
	userHash := sha256.Sum256([]byte(req.Username))
	expectedUserHash := sha256.Sum256([]byte("admin"))
	passHash := sha256.Sum256([]byte(req.Password))
	expectedPassHash := sha256.Sum256([]byte(a.adminPassword))

	userMatch := subtle.ConstantTimeCompare(userHash[:], expectedUserHash[:]) == 1
	passMatch := subtle.ConstantTimeCompare(passHash[:], expectedPassHash[:]) == 1

	if !userMatch || !passMatch {
		writeError(w, http.StatusUnauthorized, "invalid username or password")
		return
	}

	token, err := auth.GenerateSessionCookieValue("admin", 12*time.Hour, a.sessionSecret)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to generate session")
		return
	}

	http.SetCookie(w, &http.Cookie{ // #nosec G124 -- Secure is dynamically set via isHTTPS(r)
		Name:     "admin_session",
		Value:    token,
		Path:     "/",
		MaxAge:   int(12 * time.Hour / time.Second),
		HttpOnly: true,
		Secure:   isHTTPS(r),
		SameSite: http.SameSiteLaxMode,
	})

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (a *app) authLogoutHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	http.SetCookie(w, &http.Cookie{ // #nosec G124 -- Secure is dynamically set via isHTTPS(r)
		Name:     "admin_session",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   isHTTPS(r),
		SameSite: http.SameSiteLaxMode,
	})

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (a *app) requireAuthFunc(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// 1. Check Authorization Header for static API Key
		authHeader := r.Header.Get("Authorization")
		if strings.HasPrefix(authHeader, "Bearer ") {
			token := strings.TrimPrefix(authHeader, "Bearer ")

			// Use ConstantTimeCompare with SHA-256 hashing to secure token comparisons against timing attacks
			tokenHash := sha256.Sum256([]byte(token))
			expectedHash := sha256.Sum256([]byte(a.adminAPIKey))

			if subtle.ConstantTimeCompare(tokenHash[:], expectedHash[:]) == 1 {
				next(w, r)
				return
			}
		}

		// 2. Check Session Cookie
		cookie, err := r.Cookie("admin_session")
		if err == nil && cookie.Value != "" {
			_, err = auth.VerifySessionCookieValue(cookie.Value, a.sessionSecret)
			if err == nil {
				next(w, r)
				return
			}
		}

		writeError(w, http.StatusUnauthorized, "unauthorized")
	}
}
