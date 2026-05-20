package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"safe-road/internal/observability"
	"safe-road/internal/risk"
)

func TestStatusEndpointHTTP(t *testing.T) {
	app := &app{risk: risk.NewService(risk.Options{RedisTimeout: 10 * time.Millisecond}), metrics: observability.NewRegistry()}
	app.deploymentTier = "budget-vps"
	defer func() {
		if err := app.risk.Close(); err != nil {
			t.Fatal(err)
		}
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("/", app.statusHandler)
	mux.HandleFunc("/metrics", app.metricsHandler)
	testServer := httptest.NewServer(logRequests(mux, app.metrics))
	defer testServer.Close()

	response, err := http.Get(testServer.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", response.StatusCode)
	}
	if got := response.Header.Get("Content-Type"); got != "application/json" {
		t.Fatalf("expected application/json content type, got %q", got)
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}

	var payload statusResponse
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatal(err)
	}

	if payload.Service != "core-api" {
		t.Fatalf("expected service core-api, got %s", payload.Service)
	}
	if payload.Status != "ok" {
		t.Fatalf("expected ok status, got %s", payload.Status)
	}
	if payload.Mode != "api" {
		t.Fatalf("expected api mode, got %s", payload.Mode)
	}
	if payload.DeploymentTier != "budget-vps" {
		t.Fatalf("expected budget-vps deployment tier, got %s", payload.DeploymentTier)
	}
	if payload.Redis == nil || payload.Redis.Status != "disabled" {
		t.Fatalf("expected disabled redis status, got %#v", payload.Redis)
	}
	if len(payload.Endpoints) == 0 {
		t.Fatal("expected endpoint list")
	}
	if payload.Time == "" {
		t.Fatal("expected timestamp")
	}
}

func TestAnalyzeEndpointStillWorks(t *testing.T) {
	app := &app{risk: risk.NewService(risk.Options{RedisTimeout: 10 * time.Millisecond}), metrics: observability.NewRegistry(), deploymentTier: "budget-vps"}
	defer func() {
		if err := app.risk.Close(); err != nil {
			t.Fatal(err)
		}
	}()

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/v1/analyze?domain=secure-login-wallet-example.com", nil)

	app.analyzeHandler(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", recorder.Code)
	}

	var payload map[string]any
	if err := json.NewDecoder(recorder.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}

	if payload["verdict"] != "MALICIOUS" {
		t.Fatalf("expected malicious verdict, got %#v", payload["verdict"])
	}
	if payload["domain"] == "" {
		t.Fatal("expected domain in response")
	}
}

func TestMetricsEndpointHTTP(t *testing.T) {
	app := &app{risk: risk.NewService(risk.Options{RedisTimeout: 10 * time.Millisecond}), metrics: observability.NewRegistry(), deploymentTier: "budget-vps"}
	defer func() {
		if err := app.risk.Close(); err != nil {
			t.Fatal(err)
		}
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", app.metricsHandler)
	testServer := httptest.NewServer(logRequests(mux, app.metrics))
	defer testServer.Close()

	response, err := http.Get(testServer.URL + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", response.StatusCode)
	}

	var payload map[string]any
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	if payload["service"] != "core-api" {
		t.Fatalf("expected core-api service, got %#v", payload["service"])
	}
	metrics, ok := payload["metrics"].(map[string]any)
	if !ok {
		t.Fatalf("expected metrics object, got %#v", payload["metrics"])
	}
	if _, ok := metrics["request_summary"].(map[string]any); !ok {
		t.Fatalf("expected request_summary map, got %#v", metrics["request_summary"])
	}
}

func TestDashboardEndpointHTTP(t *testing.T) {
	app := &app{risk: risk.NewService(risk.Options{RedisTimeout: 10 * time.Millisecond}), metrics: observability.NewRegistry(), deploymentTier: "budget-vps"}
	defer func() {
		if err := app.risk.Close(); err != nil {
			t.Fatal(err)
		}
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("/dashboard", dashboardHandler)
	mux.HandleFunc("/dashboard/", dashboardHandler)
	testServer := httptest.NewServer(logRequests(mux, app.metrics))
	defer testServer.Close()

	response, err := http.Get(testServer.URL + "/dashboard")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", response.StatusCode)
	}
	if got := response.Header.Get("Content-Type"); got != "text/html; charset=utf-8" {
		t.Fatalf("expected text/html content type, got %q", got)
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	content := string(body)
	for _, fragment := range []string{"Safe Road Dashboard", "Quick checks", "Recent activity", "Analyze domain"} {
		if !strings.Contains(content, fragment) {
			t.Fatalf("expected dashboard content to contain %q", fragment)
		}
	}
}
