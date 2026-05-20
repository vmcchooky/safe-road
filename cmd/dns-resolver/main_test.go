package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"safe-road/internal/risk"
)

func TestStatusHandlerRoot(t *testing.T) {
	app := &app{
		risk:           risk.NewService(risk.Options{RedisTimeout: 10 * time.Millisecond}),
		upstreamDoHURL: "https://cloudflare-dns.com/dns-query",
	}
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

	var payload map[string]any
	if err := json.NewDecoder(recorder.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}

	if payload["service"] != "dns-resolver" {
		t.Fatalf("expected dns-resolver service, got %#v", payload["service"])
	}
	if payload["status"] != "ok" {
		t.Fatalf("expected ok status, got %#v", payload["status"])
	}
	if payload["mode"] != "doh" {
		t.Fatalf("expected doh mode, got %#v", payload["mode"])
	}
	if payload["upstream_doh"] != "https://cloudflare-dns.com/dns-query" {
		t.Fatalf("unexpected upstream_doh: %#v", payload["upstream_doh"])
	}
	if payload["time"] == "" {
		t.Fatal("expected time in status response")
	}

	redis, ok := payload["redis"].(map[string]any)
	if !ok {
		t.Fatalf("expected redis object, got %#v", payload["redis"])
	}
	if redis["status"] != "disabled" {
		t.Fatalf("expected disabled redis status, got %#v", redis["status"])
	}

	endpoints, ok := payload["endpoints"].([]any)
	if !ok || len(endpoints) == 0 {
		t.Fatalf("expected endpoints list, got %#v", payload["endpoints"])
	}
}

func TestStatusHandlerRejectsNonRootPath(t *testing.T) {
	app := &app{risk: risk.NewService(risk.Options{RedisTimeout: 10 * time.Millisecond})}
	defer func() {
		if err := app.risk.Close(); err != nil {
			t.Fatal(err)
		}
	}()

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/status", nil)

	app.statusHandler(recorder, request)

	if recorder.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", recorder.Code)
	}
}
