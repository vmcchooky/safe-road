package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/miekg/dns"

	"safe-road/internal/config"
	"safe-road/internal/risk"
	"safe-road/internal/serve"
)

type policyResponse struct {
	Service string `json:"service"`
	risk.Policy
	Meta map[string]string `json:"meta,omitempty"`
}

type app struct {
	risk           *risk.Service
	upstreamDoHURL string
	upstreamClient *http.Client
	blockPageIP    string
	dnsTTL         uint32
}

func main() {
	addr := config.String("SAFE_ROAD_DNS_RESOLVER_ADDR", ":8081")
	shutdownTimeout := config.DurationMillis("SAFE_ROAD_SHUTDOWN_TIMEOUT_MS", 10*time.Second)

	resolver := &app{
		risk:           risk.NewServiceFromEnv(),
		upstreamDoHURL: config.String("SAFE_ROAD_UPSTREAM_DOH_URL", "https://cloudflare-dns.com/dns-query"),
		upstreamClient: &http.Client{Timeout: config.DurationMillis("SAFE_ROAD_UPSTREAM_DOH_TIMEOUT_MS", 3*time.Second)},
		blockPageIP:    config.String("SAFE_ROAD_BLOCK_PAGE_IP", "127.0.0.1"),
		dnsTTL:         uint32(config.Int("SAFE_ROAD_DNS_BLOCK_TTL_SECONDS", 60)),
	}
	defer func() {
		if err := resolver.risk.Close(); err != nil {
			log.Printf("risk service close failed: %v", err)
		}
	}()
	logCacheStatus("dns-resolver", resolver.risk)

	mux := http.NewServeMux()
	mux.HandleFunc("/", resolver.statusHandler)
	mux.HandleFunc("/healthz", healthHandler("dns-resolver"))
	mux.HandleFunc("/v1/policy", resolver.policyHandler)
	mux.HandleFunc("/dns-query", resolver.dohHandler)

	server := &http.Server{
		Addr:              addr,
		Handler:           logRequests(mux),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	log.Printf("dns-resolver listening on %s", addr)
	if err := serve.RunHTTPServer(server, shutdownTimeout); err != nil {
		log.Fatal(err)
	}
}

func healthHandler(service string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"service": service,
			"status":  "ok",
			"time":    time.Now().UTC().Format(time.RFC3339Nano),
		})
	}
}

func (a *app) statusHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"service":      "dns-resolver",
		"status":       "ok",
		"mode":         "doh",
		"upstream_doh": a.upstreamDoHURL,
		"redis":        a.risk.CacheStatus(r.Context()),
		"endpoints": []string{
			"/",
			"/healthz",
			"/v1/policy?domain=example.com",
			"/dns-query",
		},
		"time": time.Now().UTC().Format(time.RFC3339Nano),
	})
}

func (a *app) policyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	domain := r.URL.Query().Get("domain")
	policy := a.risk.Policy(r.Context(), domain)

	writeJSON(w, http.StatusOK, policyResponse{
		Service: "dns-resolver",
		Policy:  policy,
		Meta: map[string]string{
			"mode":         "doh",
			"upstream_doh": a.upstreamDoHURL,
		},
	})
}

func (a *app) dohHandler(w http.ResponseWriter, r *http.Request) {
	wire, err := readDNSMessage(w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	query := new(dns.Msg)
	if err := query.Unpack(wire); err != nil {
		http.Error(w, "invalid DNS message", http.StatusBadRequest)
		return
	}
	if len(query.Question) == 0 {
		http.Error(w, "DNS message has no question", http.StatusBadRequest)
		return
	}

	questionDomain := strings.TrimSuffix(query.Question[0].Name, ".")
	policy := a.risk.Policy(r.Context(), questionDomain)
	if policy.Policy == "block" {
		response, err := a.blockedDNSResponse(query)
		if err != nil {
			http.Error(w, "could not build blocked DNS response", http.StatusInternalServerError)
			return
		}
		writeDNSMessage(w, response)
		return
	}

	response, err := a.forwardDoH(r.Context(), wire)
	if err != nil {
		log.Printf("upstream DoH failed for %s: %v", questionDomain, err)
		servfail, packErr := servfailDNSResponse(query)
		if packErr != nil {
			http.Error(w, "upstream DoH failed", http.StatusBadGateway)
			return
		}
		writeDNSMessage(w, servfail)
		return
	}

	writeDNSMessage(w, response)
}

func readDNSMessage(w http.ResponseWriter, r *http.Request) ([]byte, error) {
	switch r.Method {
	case http.MethodGet:
		encoded := r.URL.Query().Get("dns")
		if encoded == "" {
			return nil, errors.New("missing dns query parameter")
		}
		return base64.RawURLEncoding.DecodeString(encoded)
	case http.MethodPost:
		defer r.Body.Close()
		return io.ReadAll(http.MaxBytesReader(w, r.Body, 65535))
	default:
		return nil, errors.New("method not allowed")
	}
}

func (a *app) forwardDoH(ctx context.Context, wire []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.upstreamDoHURL, bytes.NewReader(wire))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("Content-Type", "application/dns-message")

	resp, err := a.upstreamClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("upstream returned HTTP %d", resp.StatusCode)
	}

	return io.ReadAll(io.LimitReader(resp.Body, 65535))
}

func (a *app) blockedDNSResponse(query *dns.Msg) ([]byte, error) {
	response := new(dns.Msg)
	response.SetReply(query)
	response.Authoritative = true
	response.RecursionAvailable = true

	for _, question := range query.Question {
		switch question.Qtype {
		case dns.TypeA:
			ip := net.ParseIP(a.blockPageIP).To4()
			if ip == nil {
				continue
			}
			response.Answer = append(response.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypeA, Class: question.Qclass, Ttl: a.dnsTTL},
				A:   ip,
			})
		case dns.TypeAAAA:
			ip := net.ParseIP(a.blockPageIP).To16()
			if ip == nil || ip.To4() != nil {
				continue
			}
			response.Answer = append(response.Answer, &dns.AAAA{
				Hdr:  dns.RR_Header{Name: question.Name, Rrtype: dns.TypeAAAA, Class: question.Qclass, Ttl: a.dnsTTL},
				AAAA: ip,
			})
		}
	}

	return response.Pack()
}

func servfailDNSResponse(query *dns.Msg) ([]byte, error) {
	response := new(dns.Msg)
	response.SetRcode(query, dns.RcodeServerFailure)
	response.RecursionAvailable = true
	return response.Pack()
}

func writeDNSMessage(w http.ResponseWriter, wire []byte) {
	w.Header().Set("Content-Type", "application/dns-message")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(wire); err != nil {
		log.Printf("write DNS response failed: %v", err)
	}
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

func logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		recorder := &statusLoggingResponseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(recorder, r)
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
