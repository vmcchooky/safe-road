package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"strings"
	"time"

	"safe-road/internal/config"
	"safe-road/internal/feed"
)

const defaultThreatFeedKey = "safe-road:threat:feed"

type syncReport struct {
	Source     string          `json:"source"`
	Key        string          `json:"key"`
	DryRun     bool            `json:"dry_run"`
	Replace    bool            `json:"replace"`
	Stats      feed.ParseStats `json:"stats"`
	Written    int64           `json:"written"`
	RedisAddr  string          `json:"redis_addr,omitempty"`
	FinishedAt string          `json:"finished_at"`
}

func main() {
	source := flag.String("source", config.String("SAFE_ROAD_THREAT_FEED_SOURCE", ""), "local file path or HTTP(S) feed URL")
	redisAddr := flag.String("redis-addr", config.String("SAFE_ROAD_REDIS_ADDR", ""), "Redis address")
	redisPassword := flag.String("redis-password", config.String("SAFE_ROAD_REDIS_PASSWORD", ""), "Redis password")
	redisDB := flag.Int("redis-db", config.Int("SAFE_ROAD_REDIS_DB", 0), "Redis database")
	key := flag.String("key", config.String("SAFE_ROAD_THREAT_FEED_KEY", feed.DefaultThreatFeedKey), "Redis Set key for threat feed")
	dryRun := flag.Bool("dry-run", false, "parse feed and report counts without writing Redis")
	replace := flag.Bool("replace", true, "delete the target set before writing parsed domains")
	timeout := flag.Duration("timeout", config.DurationMillis("SAFE_ROAD_FEED_SYNC_TIMEOUT_MS", 30*time.Second), "feed read and Redis write timeout")
	flag.Parse()

	if strings.TrimSpace(*source) == "" {
		log.Fatal("feed source is required through -source or SAFE_ROAD_THREAT_FEED_SOURCE")
	}

	report, err := feed.Sync(context.Background(), feed.SyncOptions{
		Source:        *source,
		RedisAddr:     *redisAddr,
		RedisPassword: *redisPassword,
		RedisDB:       *redisDB,
		Key:           *key,
		DryRun:        *dryRun,
		Replace:       *replace,
		Timeout:       *timeout,
	})
	if err != nil {
		log.Fatal(err)
	}

	encoded, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(encoded))
}
