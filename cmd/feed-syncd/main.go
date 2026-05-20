package main

import (
	"context"
	"encoding/json"
	"flag"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"safe-road/internal/config"
	"safe-road/internal/feed"
)

func main() {
	source := flag.String("source", config.String("SAFE_ROAD_THREAT_FEED_SOURCE", ""), "local file path or HTTP(S) feed URL")
	redisAddr := flag.String("redis-addr", config.String("SAFE_ROAD_REDIS_ADDR", ""), "Redis address")
	redisPassword := flag.String("redis-password", config.String("SAFE_ROAD_REDIS_PASSWORD", ""), "Redis password")
	redisDB := flag.Int("redis-db", config.Int("SAFE_ROAD_REDIS_DB", 0), "Redis database")
	key := flag.String("key", config.String("SAFE_ROAD_THREAT_FEED_KEY", feed.DefaultThreatFeedKey), "Redis Set key for threat feed")
	replace := flag.Bool("replace", true, "delete the target set before writing parsed domains")
	once := flag.Bool("once", false, "run one sync cycle and exit")
	interval := flag.Duration("interval", config.DurationSeconds("SAFE_ROAD_FEED_SYNC_INTERVAL_SECONDS", 24*time.Hour), "time between sync cycles")
	timeout := flag.Duration("timeout", config.DurationMillis("SAFE_ROAD_FEED_SYNC_TIMEOUT_MS", 30*time.Second), "feed read and Redis write timeout")
	flag.Parse()

	if strings.TrimSpace(*source) == "" {
		log.Fatal("feed source is required through -source or SAFE_ROAD_THREAT_FEED_SOURCE")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	runSync := func() {
		report, err := feed.Sync(ctx, feed.SyncOptions{
			Source:        *source,
			RedisAddr:     *redisAddr,
			RedisPassword: *redisPassword,
			RedisDB:       *redisDB,
			Key:           *key,
			Replace:       *replace,
			Timeout:       *timeout,
		})
		if err != nil {
			log.Printf("feed sync failed: %v", err)
			return
		}

		encoded, marshalErr := json.Marshal(report)
		if marshalErr != nil {
			log.Printf("feed sync report encode failed: %v", marshalErr)
			return
		}

		log.Printf("feed sync report: %s", encoded)
	}

	runSync()
	if *once {
		return
	}

	ticker := time.NewTicker(*interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			runSync()
		}
	}
}
