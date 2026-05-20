package risk

import (
	"time"

	"safe-road/internal/cache"
	"safe-road/internal/config"
)

func NewServiceFromEnv() *Service {
	redisCache := cache.NewRedis(
		config.String("SAFE_ROAD_REDIS_ADDR", ""),
		config.String("SAFE_ROAD_REDIS_PASSWORD", ""),
		config.Int("SAFE_ROAD_REDIS_DB", 0),
	)

	return NewService(Options{
		Redis:         redisCache,
		RedisTimeout:  config.DurationMillis("SAFE_ROAD_REDIS_TIMEOUT_MS", 250*time.Millisecond),
		TTLAllowed:    config.DurationSeconds("SAFE_ROAD_CACHE_TTL_ALLOWED_SECONDS", 3*time.Hour),
		TTLSuspicious: config.DurationSeconds("SAFE_ROAD_CACHE_TTL_SUSPICIOUS_SECONDS", time.Hour),
		TTLBlocked:    config.DurationSeconds("SAFE_ROAD_CACHE_TTL_BLOCKED_SECONDS", 6*time.Hour),
		RecentLimit:   int64(config.Int("SAFE_ROAD_DASHBOARD_RECENT_LIMIT", 25)),
		ThreatFeedKey: config.String("SAFE_ROAD_THREAT_FEED_KEY", defaultThreatFeedKey),
	})
}
