package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"safe-road/internal/risk"
)

func TestStatusHandler(t *testing.T) {
	app := &app{risk: risk.NewService(risk.Options{RedisTimeout: 10 * time.Millisecond})}
	defer func() {
		if err := app.risk.Close(); err != nil {
			t.Fatal(err)
		}
	}()

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/", nil)

	app.statusHandler(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", recorder.Code)
	}

	var payload statusResponse
	if err := json.NewDecoder(recorder.Body).Decode(&payload); err != nil {
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
	app := &app{risk: risk.NewService(risk.Options{RedisTimeout: 10 * time.Millisecond})}
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
