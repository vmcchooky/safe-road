package main

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"safe-road/internal/cache"
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
	key := flag.String("key", config.String("SAFE_ROAD_THREAT_FEED_KEY", defaultThreatFeedKey), "Redis Set key for threat feed")
	dryRun := flag.Bool("dry-run", false, "parse feed and report counts without writing Redis")
	replace := flag.Bool("replace", true, "delete the target set before writing parsed domains")
	timeout := flag.Duration("timeout", config.DurationMillis("SAFE_ROAD_FEED_SYNC_TIMEOUT_MS", 30*time.Second), "feed read and Redis write timeout")
	flag.Parse()

	if strings.TrimSpace(*source) == "" {
		log.Fatal("feed source is required through -source or SAFE_ROAD_THREAT_FEED_SOURCE")
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	reader, closeReader, err := openSource(ctx, *source)
	if err != nil {
		log.Fatal(err)
	}
	defer closeReader()

	parsed, err := feed.Parse(reader)
	if err != nil {
		log.Fatal(err)
	}

	report := syncReport{
		Source:     *source,
		Key:        *key,
		DryRun:     *dryRun,
		Replace:    *replace,
		Stats:      parsed.Stats,
		FinishedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}

	if !*dryRun {
		if strings.TrimSpace(*redisAddr) == "" {
			log.Fatal("redis address is required unless -dry-run is set")
		}

		redisCache := cache.NewRedis(*redisAddr, *redisPassword, *redisDB)
		defer func() {
			if err := redisCache.Close(); err != nil {
				log.Printf("redis close failed: %v", err)
			}
		}()

		if *replace {
			if err := redisCache.Delete(ctx, *key); err != nil {
				log.Fatal(err)
			}
		}

		written, err := redisCache.SetAdd(ctx, *key, parsed.Domains...)
		if err != nil {
			log.Fatal(err)
		}
		report.Written = written
		report.RedisAddr = *redisAddr
	}

	encoded, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(encoded))
}

func openSource(ctx context.Context, source string) (io.Reader, func(), error) {
	if strings.HasPrefix(source, "http://") || strings.HasPrefix(source, "https://") {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, source, nil)
		if err != nil {
			return nil, func() {}, err
		}

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return nil, func() {}, err
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			resp.Body.Close()
			return nil, func() {}, fmt.Errorf("feed source returned HTTP %d", resp.StatusCode)
		}

		return wrapMaybeCompressedReadCloser(resp.Body, source, resp.Header.Get("Content-Encoding"))
	}

	file, err := os.Open(source)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, func() {}, fmt.Errorf("feed source file does not exist: %s", source)
		}
		return nil, func() {}, err
	}

	return wrapMaybeCompressedReadCloser(file, source, "")
}

func wrapMaybeCompressedReadCloser(body io.ReadCloser, source string, contentEncoding string) (io.Reader, func(), error) {
	isCompressed := strings.EqualFold(strings.TrimSpace(contentEncoding), "gzip") || strings.HasSuffix(strings.ToLower(source), ".gz")
	if !isCompressed {
		return body, func() { _ = body.Close() }, nil
	}

	gzipReader, err := gzip.NewReader(body)
	if err != nil {
		_ = body.Close()
		return nil, func() {}, err
	}

	return gzipReader, func() {
		_ = gzipReader.Close()
		_ = body.Close()
	}, nil
}
