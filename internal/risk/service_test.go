package risk

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"

	"safe-road/internal/analysis"
	"safe-road/internal/cache"
)

func TestAnalyzeWithoutRedis(t *testing.T) {
	service := NewService(Options{
		RedisTimeout:  10 * time.Millisecond,
		TTLAllowed:    time.Hour,
		TTLSuspicious: time.Hour,
		TTLBlocked:    time.Hour,
		RecentLimit:   10,
	})

	result := service.Analyze(context.Background(), "secure-login-wallet-example.com")
	if result.Verdict != analysis.VerdictMalicious {
		t.Fatalf("expected malicious verdict, got %s", result.Verdict)
	}
	if result.CacheHit {
		t.Fatal("expected no cache hit when redis is disabled")
	}
	if result.AnalyzedAt == "" {
		t.Fatal("expected analyzed timestamp")
	}
}

func TestPolicyBlocksOnlyMalicious(t *testing.T) {
	service := NewService(Options{
		RedisTimeout:  10 * time.Millisecond,
		TTLAllowed:    time.Hour,
		TTLSuspicious: time.Hour,
		TTLBlocked:    time.Hour,
		RecentLimit:   10,
	})

	blocked := service.Policy(context.Background(), "secure-login-wallet-example.com")
	if blocked.Policy != "block" {
		t.Fatalf("expected malicious policy to block, got %s", blocked.Policy)
	}

	allowed := service.Policy(context.Background(), "example.com")
	if allowed.Policy != "allow" {
		t.Fatalf("expected safe policy to allow, got %s", allowed.Policy)
	}
}

func TestCacheStatusDisabled(t *testing.T) {
	service := NewService(Options{RedisTimeout: 10 * time.Millisecond})

	status := service.CacheStatus(context.Background())
	if status.Configured {
		t.Fatal("expected cache to be unconfigured")
	}
	if status.Status != "disabled" {
		t.Fatalf("expected disabled cache status, got %s", status.Status)
	}
}

func TestThreatFeedExactMatch(t *testing.T) {
	service, closeService := newTestServiceWithRedis(t)
	defer closeService()

	if _, err := service.redis.SetAdd(context.Background(), defaultThreatFeedKey, "bad.test"); err != nil {
		t.Fatal(err)
	}

	result := service.Analyze(context.Background(), "bad.test")
	if result.Verdict != analysis.VerdictMalicious {
		t.Fatalf("expected malicious feed verdict, got %s", result.Verdict)
	}
	if result.Score != 100 {
		t.Fatalf("expected feed score 100, got %d", result.Score)
	}
	if len(result.Reasons) != 1 || result.Reasons[0] != threatFeedReason {
		t.Fatalf("expected feed reason, got %#v", result.Reasons)
	}
}

func TestThreatFeedSuffixMatch(t *testing.T) {
	service, closeService := newTestServiceWithRedis(t)
	defer closeService()

	if _, err := service.redis.SetAdd(context.Background(), defaultThreatFeedKey, "bad.test"); err != nil {
		t.Fatal(err)
	}

	result := service.Analyze(context.Background(), "login.bad.test")
	if result.Verdict != analysis.VerdictMalicious {
		t.Fatalf("expected malicious feed verdict, got %s", result.Verdict)
	}
	if result.Score != 100 {
		t.Fatalf("expected feed score 100, got %d", result.Score)
	}
	if len(result.Reasons) != 1 || result.Reasons[0] != threatFeedReason {
		t.Fatalf("expected feed reason, got %#v", result.Reasons)
	}
}

func TestThreatFeedInvalidDomain(t *testing.T) {
	service, closeService := newTestServiceWithRedis(t)
	defer closeService()

	result := service.Analyze(context.Background(), "bad test")
	if result.Verdict != analysis.VerdictInvalid {
		t.Fatalf("expected invalid verdict, got %s", result.Verdict)
	}
}

func TestThreatFeedRedisDisabledFailOpen(t *testing.T) {
	service := NewService(Options{
		RedisTimeout:  10 * time.Millisecond,
		TTLAllowed:    time.Hour,
		TTLSuspicious: time.Hour,
		TTLBlocked:    time.Hour,
		RecentLimit:   10,
	})

	result := service.Analyze(context.Background(), "example.com")
	if result.Verdict != analysis.VerdictSafe {
		t.Fatalf("expected lexical safe result when redis is disabled, got %s", result.Verdict)
	}
}

func TestLocalAIRefinesSuspiciousDomain(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1beta/models/gemini-2.5-flash-lite:generateContent" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if got := r.URL.Query().Get("key"); got != "test-key" {
			t.Fatalf("expected api key in query, got %q", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"candidates": []map[string]any{{
				"content": map[string]any{
					"parts": []map[string]string{{"text": `{"verdict":"MALICIOUS","confidence":0.93,"reason":"local ai escalation"}`}},
				},
			}},
		})
	}))
	defer server.Close()

	service := NewService(Options{
		RedisTimeout:  10 * time.Millisecond,
		TTLAllowed:    time.Hour,
		TTLSuspicious: time.Hour,
		TTLBlocked:    time.Hour,
		RecentLimit:   10,
		GeminiBaseURL: server.URL + "/v1beta",
		GeminiAPIKey:  "test-key",
		GeminiModel:   "gemini-2.5-flash-lite",
		GeminiTimeout: time.Second,
	})

	result := service.Analyze(context.Background(), "secure-login-example.com")
	if result.Verdict != analysis.VerdictMalicious {
		t.Fatalf("expected local AI escalation to malicious, got %s", result.Verdict)
	}
	if result.Score < 85 {
		t.Fatalf("expected score to be upgraded, got %d", result.Score)
	}
}

func TestLocalAIFailureFailsOpen(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"candidates":[]}`))
	}))
	defer server.Close()

	service := NewService(Options{
		RedisTimeout:  10 * time.Millisecond,
		TTLAllowed:    time.Hour,
		TTLSuspicious: time.Hour,
		TTLBlocked:    time.Hour,
		RecentLimit:   10,
		GeminiBaseURL: server.URL + "/v1beta",
		GeminiAPIKey:  "test-key",
		GeminiModel:   "gemini-2.5-flash-lite",
		GeminiTimeout: time.Second,
	})

	result := service.Analyze(context.Background(), "secure-login-example.com")
	if result.Verdict != analysis.VerdictSuspicious {
		t.Fatalf("expected suspicious result to remain unchanged on ai failure, got %s", result.Verdict)
	}
}

func TestLocalAIFailureFailsOpenFromEnv(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1beta/models/gemini-2.5-flash-lite:generateContent" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":{"message":"upstream error"}}`))
	}))
	defer server.Close()

	t.Setenv("SAFE_ROAD_REDIS_ADDR", "")
	t.Setenv("SAFE_ROAD_GEMINI_BASE_URL", server.URL+"/v1beta")
	t.Setenv("SAFE_ROAD_GEMINI_API_KEY", "test-key")
	t.Setenv("SAFE_ROAD_GEMINI_MODEL", "gemini-2.5-flash-lite")
	t.Setenv("SAFE_ROAD_GEMINI_TIMEOUT_MS", "100")

	service := NewServiceFromEnv()
	result := service.Analyze(context.Background(), "secure-login-example.com")
	if result.Verdict != analysis.VerdictSuspicious {
		t.Fatalf("expected suspicious result to remain unchanged on ai error, got %s", result.Verdict)
	}
}

func TestLocalAITimeoutFailsOpenFromEnv(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1beta/models/gemini-2.5-flash-lite:generateContent" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"candidates":[{"content":{"parts":[{"text":"{\"verdict\":\"MALICIOUS\",\"confidence\":0.9,\"reason\":\"late response\"}"}]}}]}`))
	}))
	defer server.Close()

	t.Setenv("SAFE_ROAD_REDIS_ADDR", "")
	t.Setenv("SAFE_ROAD_GEMINI_BASE_URL", server.URL+"/v1beta")
	t.Setenv("SAFE_ROAD_GEMINI_API_KEY", "test-key")
	t.Setenv("SAFE_ROAD_GEMINI_MODEL", "gemini-2.5-flash-lite")
	t.Setenv("SAFE_ROAD_GEMINI_TIMEOUT_MS", "50")

	service := NewServiceFromEnv()
	result := service.Analyze(context.Background(), "secure-login-example.com")
	if result.Verdict != analysis.VerdictSuspicious {
		t.Fatalf("expected suspicious result to remain unchanged on ai timeout, got %s", result.Verdict)
	}
}

func newTestServiceWithRedis(t *testing.T) (*Service, func()) {
	t.Helper()

	server, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}

	service := NewService(Options{
		Redis:         cache.NewRedis(server.Addr(), "", 0),
		RedisTimeout:  100 * time.Millisecond,
		TTLAllowed:    time.Hour,
		TTLSuspicious: time.Hour,
		TTLBlocked:    time.Hour,
		RecentLimit:   10,
	})

	return service, func() {
		if err := service.Close(); err != nil {
			t.Fatal(err)
		}
		server.Close()
	}
}
