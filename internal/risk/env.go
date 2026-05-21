package risk

import (
	"log"
	"time"

	"safe-road/internal/cache"
	"safe-road/internal/config"
	"safe-road/internal/store"
)

func NewServiceFromEnv() *Service {
	redisCache := cache.NewRedis(
		config.String("SAFE_ROAD_REDIS_ADDR", ""),
		config.String("SAFE_ROAD_REDIS_PASSWORD", ""),
		config.Int("SAFE_ROAD_REDIS_DB", 0),
	)

	sqlitePath := config.String("SAFE_ROAD_SQLITE_PATH", "./data/safe-road.db")
	retentionDays := config.Int("SAFE_ROAD_TELEMETRY_RETENTION_DAYS", 30)
	storeDB, err := store.New(sqlitePath, retentionDays)
	if err != nil {
		log.Printf("sqlite store initialization failed, continuing without persistence: %v", err)
	}

	return NewService(Options{
		Redis:          redisCache,
		RedisTimeout:   config.DurationMillis("SAFE_ROAD_REDIS_TIMEOUT_MS", 250*time.Millisecond),
		TTLAllowed:     config.DurationSeconds("SAFE_ROAD_CACHE_TTL_ALLOWED_SECONDS", 3*time.Hour),
		TTLSuspicious:  config.DurationSeconds("SAFE_ROAD_CACHE_TTL_SUSPICIOUS_SECONDS", time.Hour),
		TTLBlocked:     config.DurationSeconds("SAFE_ROAD_CACHE_TTL_BLOCKED_SECONDS", 6*time.Hour),
		RecentLimit:    int64(config.Int("SAFE_ROAD_DASHBOARD_RECENT_LIMIT", 25)),
		ThreatFeedKey:  config.String("SAFE_ROAD_THREAT_FEED_KEY", defaultThreatFeedKey),
		AIProvider:     config.String("SAFE_ROAD_AI_PROVIDER", "gemini"),
		GeminiBaseURL:  config.String("SAFE_ROAD_GEMINI_BASE_URL", "https://generativelanguage.googleapis.com/v1beta"),
		GeminiAPIKey:   config.String("SAFE_ROAD_GEMINI_API_KEY", ""),
		GeminiModel:    config.String("SAFE_ROAD_GEMINI_MODEL", "gemini-2.5-flash-lite"),
		GeminiTimeout:  config.DurationMillis("SAFE_ROAD_GEMINI_TIMEOUT_MS", 3*time.Second),
		OllamaBaseURL:  config.String("SAFE_ROAD_OLLAMA_BASE_URL", "http://localhost:11434"),
		OllamaModel:    config.String("SAFE_ROAD_OLLAMA_MODEL", "gemma2:2b"),
		OllamaTimeout:  config.DurationMillis("SAFE_ROAD_OLLAMA_TIMEOUT_MS", 5000*time.Millisecond),
		WhitelistPath:  config.String("SAFE_ROAD_WHITELIST_PATH", "./data/whitelist.txt"),
		AnalysisConfig: config.LoadAnalysisConfig(config.String("SAFE_ROAD_ANALYSIS_CONFIG_PATH", "")),
		Store:          storeDB,
		EnrichEnabled:  config.Bool("SAFE_ROAD_ENRICH_ENABLED", true),
		EnrichTimeout:  config.DurationMillis("SAFE_ROAD_ENRICH_TIMEOUT_MS", 3*time.Second),
	})
}
