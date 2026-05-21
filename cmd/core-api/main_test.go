package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"safe-road/internal/auth"
	"safe-road/internal/config"
	"safe-road/internal/observability"
	"safe-road/internal/risk"
)

func TestStatusEndpointHTTP(t *testing.T) {
	app := &app{risk: risk.NewService(risk.Options{AnalysisConfig: config.DefaultAnalysisConfig(), RedisTimeout: 10 * time.Millisecond}), metrics: observability.NewRegistry()}
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
	app := &app{risk: risk.NewService(risk.Options{AnalysisConfig: config.DefaultAnalysisConfig(), RedisTimeout: 10 * time.Millisecond}), metrics: observability.NewRegistry(), deploymentTier: "budget-vps"}
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
	app := &app{risk: risk.NewService(risk.Options{AnalysisConfig: config.DefaultAnalysisConfig(), RedisTimeout: 10 * time.Millisecond}), metrics: observability.NewRegistry(), deploymentTier: "budget-vps"}
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
	sessionSecret := []byte("test_session_secret_32_bytes_long_!!!")
	app := &app{
		risk:           risk.NewService(risk.Options{AnalysisConfig: config.DefaultAnalysisConfig(), RedisTimeout: 10 * time.Millisecond}),
		metrics:        observability.NewRegistry(),
		deploymentTier: "budget-vps",
		sessionSecret:  sessionSecret,
		adminPassword:  "testpass",
		adminAPIKey:    "testkey",
	}
	defer func() {
		if err := app.risk.Close(); err != nil {
			t.Fatal(err)
		}
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("/dashboard", app.dashboardHandler)
	mux.HandleFunc("/dashboard/", app.dashboardHandler)
	testServer := httptest.NewServer(logRequests(mux, app.metrics))
	defer testServer.Close()

	// 1. Without cookie, it should show login HTML
	response, err := http.Get(testServer.URL + "/dashboard")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", response.StatusCode)
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	content := string(body)
	if !strings.Contains(content, "Admin Authentication") || !strings.Contains(content, "login-form") {
		t.Fatalf("expected login page, got: %s", content)
	}

	// 2. With valid cookie, it should show dashboard HTML
	cookieVal, err := auth.GenerateSessionCookieValue("admin", 1*time.Hour, sessionSecret)
	if err != nil {
		t.Fatal(err)
	}

	req, err := http.NewRequest(http.MethodGet, testServer.URL+"/dashboard", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(&http.Cookie{
		Name:  "admin_session",
		Value: cookieVal,
	})

	client := &http.Client{}
	response2, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer response2.Body.Close()

	if response2.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", response2.StatusCode)
	}

	body2, err := io.ReadAll(response2.Body)
	if err != nil {
		t.Fatal(err)
	}
	content2 := string(body2)
	for _, fragment := range []string{"Safe Road Dashboard", "Analyze domain"} {
		if !strings.Contains(content2, fragment) {
			t.Fatalf("expected dashboard content to contain %q, got: %s", fragment, content2)
		}
	}
}

func TestRestrictedAPIsAuth(t *testing.T) {
	sessionSecret := []byte("test_session_secret_32_bytes_long_!!!")
	app := &app{
		risk:           risk.NewService(risk.Options{AnalysisConfig: config.DefaultAnalysisConfig(), RedisTimeout: 10 * time.Millisecond}),
		metrics:        observability.NewRegistry(),
		deploymentTier: "budget-vps",
		sessionSecret:  sessionSecret,
		adminPassword:  "testpass",
		adminAPIKey:    "testkey",
	}
	defer func() {
		if err := app.risk.Close(); err != nil {
			t.Fatal(err)
		}
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/auth/login", app.authLoginHandler)
	mux.HandleFunc("/v1/auth/logout", app.authLogoutHandler)
	mux.HandleFunc("/v1/overrides", app.requireAuthFunc(app.overridesHandler))
	testServer := httptest.NewServer(logRequests(mux, app.metrics))
	defer testServer.Close()

	client := &http.Client{}

	// 1. Check REST API /v1/overrides with NO auth (expected 401 Unauthorized)
	req1, _ := http.NewRequest(http.MethodGet, testServer.URL+"/v1/overrides", nil)
	resp1, err := client.Do(req1)
	if err != nil {
		t.Fatal(err)
	}
	defer resp1.Body.Close()
	if resp1.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized, got %d", resp1.StatusCode)
	}

	// 2. Check REST API with WRONG Bearer Key (expected 401 Unauthorized)
	req2, _ := http.NewRequest(http.MethodGet, testServer.URL+"/v1/overrides", nil)
	req2.Header.Set("Authorization", "Bearer wrong_key")
	resp2, err := client.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized, got %d", resp2.StatusCode)
	}

	// 3. Check REST API with CORRECT Bearer Key (expected 200 OK)
	req3, _ := http.NewRequest(http.MethodGet, testServer.URL+"/v1/overrides", nil)
	req3.Header.Set("Authorization", "Bearer testkey")
	resp3, err := client.Do(req3)
	if err != nil {
		t.Fatal(err)
	}
	defer resp3.Body.Close()
	if resp3.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", resp3.StatusCode)
	}

	// 4. Check REST API with CORRECT Session Cookie (expected 200 OK)
	cookieVal, err := auth.GenerateSessionCookieValue("admin", 1*time.Hour, sessionSecret)
	if err != nil {
		t.Fatal(err)
	}
	req4, _ := http.NewRequest(http.MethodGet, testServer.URL+"/v1/overrides", nil)
	req4.AddCookie(&http.Cookie{
		Name:  "admin_session",
		Value: cookieVal,
	})
	resp4, err := client.Do(req4)
	if err != nil {
		t.Fatal(err)
	}
	defer resp4.Body.Close()
	if resp4.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", resp4.StatusCode)
	}

	// 5. Test Login API with wrong credentials
	loginBodyWrong := `{"username": "admin", "password": "wrong_password"}`
	resp5, err := client.Post(testServer.URL+"/v1/auth/login", "application/json", strings.NewReader(loginBodyWrong))
	if err != nil {
		t.Fatal(err)
	}
	defer resp5.Body.Close()
	if resp5.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized on wrong login, got %d", resp5.StatusCode)
	}

	// 6. Test Login API with correct credentials
	loginBodyCorrect := `{"username": "admin", "password": "testpass"}`
	resp6, err := client.Post(testServer.URL+"/v1/auth/login", "application/json", strings.NewReader(loginBodyCorrect))
	if err != nil {
		t.Fatal(err)
	}
	defer resp6.Body.Close()
	if resp6.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK on correct login, got %d", resp6.StatusCode)
	}

	// Read cookies from login response
	cookies := resp6.Cookies()
	var sessionCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == "admin_session" {
			sessionCookie = c
			break
		}
	}
	if sessionCookie == nil {
		t.Fatal("expected admin_session cookie to be returned")
	}

	// 7. Verify the returned cookie is valid and works for overrides API
	req7, _ := http.NewRequest(http.MethodGet, testServer.URL+"/v1/overrides", nil)
	req7.AddCookie(sessionCookie)
	resp7, err := client.Do(req7)
	if err != nil {
		t.Fatal(err)
	}
	defer resp7.Body.Close()
	if resp7.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK with login cookie, got %d", resp7.StatusCode)
	}

	// 8. Test Logout API
	req8, _ := http.NewRequest(http.MethodPost, testServer.URL+"/v1/auth/logout", nil)
	resp8, err := client.Do(req8)
	if err != nil {
		t.Fatal(err)
	}
	defer resp8.Body.Close()
	if resp8.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK on logout, got %d", resp8.StatusCode)
	}

	// Verify logout cookie is expired
	logoutCookies := resp8.Cookies()
	var logoutCookie *http.Cookie
	for _, c := range logoutCookies {
		if c.Name == "admin_session" {
			logoutCookie = c
			break
		}
	}
	if logoutCookie == nil {
		t.Fatal("expected admin_session cookie to be returned in logout response")
	}
	if logoutCookie.MaxAge != -1 {
		t.Fatalf("expected MaxAge of logout cookie to be -1, got %d", logoutCookie.MaxAge)
	}
}

func TestSecurityAuditLimits(t *testing.T) {
	app := &app{
		risk:           risk.NewService(risk.Options{AnalysisConfig: config.DefaultAnalysisConfig(), RedisTimeout: 10 * time.Millisecond}),
		metrics:        observability.NewRegistry(),
		deploymentTier: "budget-vps",
		adminAPIKey:    "testkey",
	}
	defer func() {
		if err := app.risk.Close(); err != nil {
			t.Fatal(err)
		}
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/analyze", app.analyzeHandler)
	mux.HandleFunc("/v1/overrides", app.requireAuthFunc(app.overridesHandler))
	mux.HandleFunc("/v1/telemetry/recent", app.requireAuthFunc(app.telemetryRecentHandler))
	testServer := httptest.NewServer(mux)
	defer testServer.Close()

	client := &http.Client{}

	// 1. Send huge body (5KB) to /v1/analyze (POST) -> expect 400 Bad Request due to MaxBytesReader capping at 4KB
	hugePayload := `{"domain": "` + strings.Repeat("a", 5000) + `"}`
	resp1, err := client.Post(testServer.URL+"/v1/analyze", "application/json", strings.NewReader(hugePayload))
	if err != nil {
		t.Fatal(err)
	}
	defer resp1.Body.Close()
	if resp1.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request, got %d", resp1.StatusCode)
	}

	// 2. Send valid small body (100 bytes) to /v1/analyze (POST) -> expect 200 OK
	validPayload := `{"domain": "example.com"}`
	resp2, err := client.Post(testServer.URL+"/v1/analyze", "application/json", strings.NewReader(validPayload))
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", resp2.StatusCode)
	}

	// 3. Test limit parameter capping in telemetry recent -> expect 200 OK and limit to be handled correctly
	req3, _ := http.NewRequest(http.MethodGet, testServer.URL+"/v1/telemetry/recent?limit=200", nil)
	req3.Header.Set("Authorization", "Bearer testkey")
	resp3, err := client.Do(req3)
	if err != nil {
		t.Fatal(err)
	}
	defer resp3.Body.Close()
	if resp3.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", resp3.StatusCode)
	}
}

