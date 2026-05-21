package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"safe-road/internal/feed"
	"safe-road/internal/store"
)

// FeedSyncConfig holds configuration for the multi-source feed sync task.
type FeedSyncConfig struct {
	Sources       []string // Feed URLs (comma-separated in env)
	RedisAddr     string
	RedisPassword string
	RedisDB       int
	FeedKey       string
	Timeout       time.Duration
}

// FeedSyncTask downloads threat feed data from multiple sources and adds
// them to the Redis threat feed set.
type FeedSyncTask struct {
	store  *store.DB
	config FeedSyncConfig
}

// NewFeedSyncTask creates a FeedSyncTask with the given configuration.
func NewFeedSyncTask(db *store.DB, cfg FeedSyncConfig) *FeedSyncTask {
	if cfg.FeedKey == "" {
		cfg.FeedKey = feed.DefaultThreatFeedKey
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 30 * time.Second
	}
	return &FeedSyncTask{
		store:  db,
		config: cfg,
	}
}

func (t *FeedSyncTask) Name() string { return "feedsync" }

func (t *FeedSyncTask) Run(ctx context.Context) error {
	if len(t.config.Sources) == 0 {
		return nil // no sources configured, nothing to do
	}
	if strings.TrimSpace(t.config.RedisAddr) == "" {
		return nil // Redis required for feed sync
	}

	var (
		sourcesOK     int
		sourcesFailed int
		totalWritten  int64
	)

	for _, source := range t.config.Sources {
		source = strings.TrimSpace(source)
		if source == "" {
			continue
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		report, err := feed.Sync(ctx, feed.SyncOptions{
			Source:        source,
			RedisAddr:     t.config.RedisAddr,
			RedisPassword: t.config.RedisPassword,
			RedisDB:       t.config.RedisDB,
			Key:           t.config.FeedKey,
			DryRun:        false,
			Replace:       false, // additive mode — don't delete existing entries
			Timeout:       t.config.Timeout,
		})
		if err != nil {
			log.Printf("agent feedsync error for %s: %v", source, err)
			sourcesFailed++

			if t.store != nil && t.store.Enabled() {
				details := fmt.Sprintf(`{"source":"%s","error":"%s"}`, source, err.Error())
				_ = t.store.RecordAgentEvent("feedsync", "feed_error", "", details)
			}
			continue
		}

		sourcesOK++
		totalWritten += report.Written

		if t.store != nil && t.store.Enabled() {
			detailsJSON, _ := json.Marshal(report)
			_ = t.store.RecordAgentEvent("feedsync", "feed_synced", "", string(detailsJSON))
		}

		log.Printf("agent feedsync completed for %s: %d written, %d valid, %d invalid",
			source, report.Written, report.Stats.Valid, report.Stats.Invalid)
	}

	summary := fmt.Sprintf(`{"sources_ok":%d,"sources_failed":%d,"total_written":%d}`,
		sourcesOK, sourcesFailed, totalWritten)
	if t.store != nil && t.store.Enabled() {
		_ = t.store.RecordAgentEvent("feedsync", "feedsync_completed", "", summary)
	}

	log.Printf("agent feedsync cycle done: %d ok, %d failed, %d domains written",
		sourcesOK, sourcesFailed, totalWritten)

	if sourcesFailed > 0 && sourcesOK == 0 {
		return fmt.Errorf("all %d feed sources failed", sourcesFailed)
	}
	return nil
}
