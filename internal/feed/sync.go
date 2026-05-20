package feed

import (
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"safe-road/internal/cache"
)

const DefaultThreatFeedKey = "safe-road:threat:feed"

type SyncOptions struct {
	Source        string
	RedisAddr     string
	RedisPassword string
	RedisDB       int
	Key           string
	DryRun        bool
	Replace       bool
	Timeout       time.Duration
	Client        *http.Client
}

type SyncReport struct {
	Source     string     `json:"source"`
	Key        string     `json:"key"`
	DryRun     bool       `json:"dry_run"`
	Replace    bool       `json:"replace"`
	Stats      ParseStats `json:"stats"`
	Written    int64      `json:"written"`
	RedisAddr  string     `json:"redis_addr,omitempty"`
	FinishedAt string     `json:"finished_at"`
}

func Sync(parent context.Context, options SyncOptions) (SyncReport, error) {
	if strings.TrimSpace(options.Source) == "" {
		return SyncReport{}, errors.New("feed source is required")
	}
	if strings.TrimSpace(options.Key) == "" {
		options.Key = DefaultThreatFeedKey
	}

	ctx := parent
	var cancel context.CancelFunc = func() {}
	if options.Timeout > 0 {
		ctx, cancel = context.WithTimeout(parent, options.Timeout)
	}
	defer cancel()

	reader, closeReader, err := OpenSource(ctx, options.Source, options.Client)
	if err != nil {
		return SyncReport{}, err
	}
	defer closeReader()

	parsed, err := Parse(reader)
	if err != nil {
		return SyncReport{}, err
	}

	report := SyncReport{
		Source:     options.Source,
		Key:        options.Key,
		DryRun:     options.DryRun,
		Replace:    options.Replace,
		Stats:      parsed.Stats,
		FinishedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}

	if options.DryRun {
		return report, nil
	}
	if strings.TrimSpace(options.RedisAddr) == "" {
		return SyncReport{}, errors.New("redis address is required unless dry-run is set")
	}

	redisCache := cache.NewRedis(options.RedisAddr, options.RedisPassword, options.RedisDB)
	defer func() {
		_ = redisCache.Close()
	}()

	if options.Replace {
		if err := redisCache.Delete(ctx, options.Key); err != nil {
			return SyncReport{}, err
		}
	}

	written, err := redisCache.SetAdd(ctx, options.Key, parsed.Domains...)
	if err != nil {
		return SyncReport{}, err
	}

	report.Written = written
	report.RedisAddr = options.RedisAddr
	return report, nil
}

func OpenSource(ctx context.Context, source string, client *http.Client) (io.ReadCloser, func(), error) {
	if client == nil {
		client = http.DefaultClient
	}

	if strings.HasPrefix(source, "http://") || strings.HasPrefix(source, "https://") {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, source, nil)
		if err != nil {
			return nil, func() {}, err
		}

		resp, err := client.Do(req)
		if err != nil {
			return nil, func() {}, err
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			_ = resp.Body.Close()
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

func wrapMaybeCompressedReadCloser(body io.ReadCloser, source string, contentEncoding string) (io.ReadCloser, func(), error) {
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
