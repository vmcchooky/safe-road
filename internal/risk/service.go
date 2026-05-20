package risk

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"safe-road/internal/ai"
	"safe-road/internal/analysis"
	"safe-road/internal/cache"
)

const recentAnalysisKey = "safe-road:analysis:recent"
const defaultThreatFeedKey = "safe-road:threat:feed"
const threatFeedReason = "matched local threat feed"

type Options struct {
	Redis         *cache.Redis
	RedisTimeout  time.Duration
	TTLAllowed    time.Duration
	TTLSuspicious time.Duration
	TTLBlocked    time.Duration
	RecentLimit   int64
	ThreatFeedKey string
	GeminiBaseURL string
	GeminiAPIKey  string
	GeminiModel   string
	GeminiTimeout time.Duration
}

type Service struct {
	redis         *cache.Redis
	redisTimeout  time.Duration
	ttlAllowed    time.Duration
	ttlSuspicious time.Duration
	ttlBlocked    time.Duration
	recentLimit   int64
	threatFeedKey string
	ai            *ai.Client
}

type Analysis struct {
	analysis.Result
	CacheHit   bool   `json:"cache_hit"`
	AnalyzedAt string `json:"analyzed_at"`
}

type Policy struct {
	Domain   string          `json:"domain"`
	Policy   string          `json:"policy"`
	Result   analysis.Result `json:"result"`
	CacheHit bool            `json:"cache_hit"`
}

type CacheStatus struct {
	Configured bool   `json:"configured"`
	Status     string `json:"status"`
	Error      string `json:"error,omitempty"`
}

func NewService(options Options) *Service {
	recentLimit := options.RecentLimit
	if recentLimit <= 0 {
		recentLimit = 25
	}
	threatFeedKey := options.ThreatFeedKey
	if threatFeedKey == "" {
		threatFeedKey = defaultThreatFeedKey
	}
	aiClient := ai.New(options.GeminiBaseURL, options.GeminiAPIKey, options.GeminiModel, options.GeminiTimeout)
	if !aiClient.Enabled() {
		aiClient = nil
	}

	return &Service{
		redis:         options.Redis,
		redisTimeout:  options.RedisTimeout,
		ttlAllowed:    options.TTLAllowed,
		ttlSuspicious: options.TTLSuspicious,
		ttlBlocked:    options.TTLBlocked,
		recentLimit:   recentLimit,
		threatFeedKey: threatFeedKey,
		ai:            aiClient,
	}
}

func (s *Service) Close() error {
	if s == nil || s.redis == nil {
		return nil
	}

	return s.redis.Close()
}

func (s *Service) Analyze(ctx context.Context, domain string) Analysis {
	result, cacheHit := s.analyze(ctx, domain)
	return Analysis{
		Result:     result,
		CacheHit:   cacheHit,
		AnalyzedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}
}

func (s *Service) Policy(ctx context.Context, domain string) Policy {
	result, cacheHit := s.analyze(ctx, domain)
	policy := "allow"
	if result.Verdict == analysis.VerdictMalicious {
		policy = "block"
	}

	return Policy{
		Domain:   result.Domain,
		Policy:   policy,
		Result:   result,
		CacheHit: cacheHit,
	}
}

func (s *Service) RecordRecent(ctx context.Context, item Analysis) {
	err := s.withRedis(ctx, func(redisCtx context.Context) error {
		return s.redis.PushJSON(redisCtx, recentAnalysisKey, item, s.recentLimit)
	})
	if err != nil && !errors.Is(err, cache.ErrDisabled) {
		log.Printf("recent analysis cache write failed: %v", err)
	}
}

func (s *Service) Recent(ctx context.Context) []Analysis {
	recent := make([]Analysis, 0, s.recentLimit)
	err := s.withRedis(ctx, func(redisCtx context.Context) error {
		return s.redis.ListJSON(redisCtx, recentAnalysisKey, 0, s.recentLimit-1, func(data []byte) error {
			var item Analysis
			if err := json.Unmarshal(data, &item); err != nil {
				return err
			}
			recent = append(recent, item)
			return nil
		})
	})
	if err != nil && !errors.Is(err, cache.ErrDisabled) {
		log.Printf("recent analysis cache read failed: %v", err)
	}

	return recent
}

func (s *Service) CacheStatus(ctx context.Context) CacheStatus {
	if s == nil || s.redis == nil || !s.redis.Enabled() {
		return CacheStatus{
			Configured: false,
			Status:     "disabled",
		}
	}

	err := s.withRedis(ctx, func(redisCtx context.Context) error {
		return s.redis.Ping(redisCtx)
	})
	if err != nil {
		return CacheStatus{
			Configured: true,
			Status:     "unavailable",
			Error:      err.Error(),
		}
	}

	return CacheStatus{
		Configured: true,
		Status:     "ok",
	}
}

func (s *Service) analyze(ctx context.Context, domain string) (analysis.Result, bool) {
	normalized, err := analysis.NormalizeDomain(domain)
	if err != nil {
		return analysis.Analyze(domain), false
	}

	cacheKey := fmt.Sprintf("safe-road:analysis:%s", normalized)
	var cached analysis.Result
	err = s.withRedis(ctx, func(redisCtx context.Context) error {
		found, err := s.redis.GetJSON(redisCtx, cacheKey, &cached)
		if err != nil || !found {
			return err
		}
		return nil
	})
	if err == nil && cached.Domain != "" {
		return cached, true
	}
	if err != nil && !errors.Is(err, cache.ErrDisabled) {
		log.Printf("analysis cache read failed for %s: %v", normalized, err)
	}

	result := s.feedResult(ctx, normalized)
	if result.Domain == "" {
		result = analysis.Analyze(normalized)
	}
	result = s.refineWithAI(ctx, result)
	err = s.withRedis(ctx, func(redisCtx context.Context) error {
		return s.redis.SetJSON(redisCtx, cacheKey, result, s.ttlFor(result.Verdict))
	})
	if err != nil && !errors.Is(err, cache.ErrDisabled) {
		log.Printf("analysis cache write failed for %s: %v", normalized, err)
	}

	return result, false
}

func (s *Service) feedResult(ctx context.Context, domain string) analysis.Result {
	matched, err := s.matchThreatFeed(ctx, domain)
	if err != nil {
		if !errors.Is(err, cache.ErrDisabled) {
			log.Printf("threat feed lookup failed for %s: %v", domain, err)
		}
		return analysis.Result{}
	}
	if !matched {
		return analysis.Result{}
	}

	return analysis.Result{
		Domain:     domain,
		Verdict:    analysis.VerdictMalicious,
		Confidence: 1,
		Score:      100,
		Reasons:    []string{threatFeedReason},
	}
}

func (s *Service) refineWithAI(ctx context.Context, current analysis.Result) analysis.Result {
	if s == nil || s.ai == nil {
		return current
	}
	if current.Verdict != analysis.VerdictSuspicious {
		return current
	}

	aiResult, err := s.ai.Refine(ctx, current.Domain, current)
	if err != nil {
		log.Printf("local AI refinement failed for %s: %v", current.Domain, err)
		return current
	}
	if aiResult.Verdict != analysis.VerdictMalicious {
		if len(aiResult.Reasons) > 0 {
			current.Reasons = append(current.Reasons, aiResult.Reasons...)
		}
		return current
	}

	current.Verdict = analysis.VerdictMalicious
	if aiResult.Score > current.Score {
		current.Score = aiResult.Score
	}
	if aiResult.Confidence > current.Confidence {
		current.Confidence = aiResult.Confidence
	}
	current.Reasons = append(current.Reasons, aiResult.Reasons...)
	return current
}

func (s *Service) matchThreatFeed(parent context.Context, domain string) (bool, error) {
	candidates := threatFeedCandidates(domain)
	return s.matchAnyThreatFeedCandidate(parent, candidates)
}

func (s *Service) matchAnyThreatFeedCandidate(parent context.Context, candidates []string) (bool, error) {
	var matched bool
	err := s.withRedis(parent, func(ctx context.Context) error {
		for _, candidate := range candidates {
			exists, err := s.redis.SetIsMember(ctx, s.threatFeedKey, candidate)
			if err != nil {
				return err
			}
			if exists {
				matched = true
				return nil
			}
		}
		return nil
	})
	if err != nil {
		return false, err
	}

	return matched, nil
}

func threatFeedCandidates(domain string) []string {
	parts := strings.Split(domain, ".")
	candidates := make([]string, 0, len(parts))
	for i := 0; i < len(parts); i++ {
		candidate := strings.Join(parts[i:], ".")
		if candidate != "" {
			candidates = append(candidates, candidate)
		}
	}

	return candidates
}

func (s *Service) ttlFor(verdict analysis.Verdict) time.Duration {
	switch verdict {
	case analysis.VerdictMalicious:
		return s.ttlBlocked
	case analysis.VerdictSuspicious:
		return s.ttlSuspicious
	default:
		return s.ttlAllowed
	}
}

func (s *Service) withRedis(parent context.Context, fn func(context.Context) error) error {
	if s == nil || s.redis == nil || !s.redis.Enabled() {
		return cache.ErrDisabled
	}

	ctx, cancel := context.WithTimeout(parent, s.redisTimeout)
	defer cancel()
	return fn(ctx)
}
