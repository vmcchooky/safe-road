package risk

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	"strings"
	"sync"
	"time"

	"safe-road/internal/ai"
	"safe-road/internal/analysis"
	"safe-road/internal/cache"
	"safe-road/internal/config"
	"safe-road/internal/store"
	"safe-road/internal/tlsinspect"
	"safe-road/internal/whois"
)

const recentAnalysisKey = "safe-road:analysis:recent"
const defaultThreatFeedKey = "safe-road:threat:feed"
const threatFeedReason = "matched local threat feed"

type Options struct {
	Redis          *cache.Redis
	RedisTimeout   time.Duration
	TTLAllowed     time.Duration
	TTLSuspicious  time.Duration
	TTLBlocked     time.Duration
	RecentLimit    int64
	ThreatFeedKey  string
	AIProvider     string
	GeminiBaseURL  string
	GeminiAPIKey   string
	GeminiModel    string
	GeminiTimeout  time.Duration
	OllamaBaseURL  string
	OllamaModel    string
	OllamaTimeout  time.Duration
	WhitelistPath  string
	AnalysisConfig config.AnalysisConfig
	Store          *store.DB
	// Enrichment (TLS + WHOIS)
	EnrichEnabled bool
	EnrichTimeout time.Duration
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
	whitelist     *Whitelist
	analyzer      *analysis.Analyzer
	store         *store.DB
	enrichEnabled bool
	enrichTimeout time.Duration
}

type ClientInfo struct {
	IP       string `json:"ip"`
	ClientID string `json:"client_id"`
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
	aiClient := ai.NewClient(ai.Config{
		Provider:      options.AIProvider,
		GeminiBaseURL: options.GeminiBaseURL,
		GeminiAPIKey:  options.GeminiAPIKey,
		GeminiModel:   options.GeminiModel,
		GeminiTimeout: options.GeminiTimeout,
		OllamaBaseURL: options.OllamaBaseURL,
		OllamaModel:   options.OllamaModel,
		OllamaTimeout: options.OllamaTimeout,
	})
	if !aiClient.Enabled() {
		aiClient = nil
	}

	wl := NewWhitelist(options.Store)
	if options.WhitelistPath != "" {
		_ = wl.LoadFromFile(options.WhitelistPath)
	} else if options.Store != nil && options.Store.Enabled() {
		_ = wl.LoadFromDB()
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
		whitelist:     wl,
		analyzer:      analysis.NewAnalyzer(options.AnalysisConfig),
		store:         options.Store,
		enrichEnabled: options.EnrichEnabled,
		enrichTimeout: options.EnrichTimeout,
	}
}

func (s *Service) Close() error {
	if s == nil {
		return nil
	}
	var redisErr, storeErr error
	if s.redis != nil {
		redisErr = s.redis.Close()
	}
	if s.store != nil {
		storeErr = s.store.Close()
	}
	return errors.Join(redisErr, storeErr)
}

func (s *Service) Analyze(ctx context.Context, domain string, client ClientInfo) Analysis {
	normalized, err := analysis.NormalizeDomain(domain)
	var result analysis.Result
	var cacheHit bool

	if err != nil {
		result = s.analyzer.Analyze(domain)
		cacheHit = false
	} else {
		// Get group
		var group *store.ClientGroup
		if s.store != nil && s.store.Enabled() {
			g, err := s.store.GetGroupForClient(client.IP, client.ClientID)
			if err == nil {
				group = g
			}
		}
		if group == nil {
			group = &store.ClientGroup{ID: 1, Name: "default", StrictMalware: true}
		}

		// 1. Check Overrides
		if s.store != nil && s.store.Enabled() {
			override, err := s.store.GetEffectiveOverride(group.ID, normalized)
			if err == nil && override != nil {
				verdict := analysis.VerdictSafe
				score := 0
				if override.Action == "block" {
					verdict = analysis.VerdictMalicious
					score = 100
				}
				reason := fmt.Sprintf("admin override: %s", override.Action)
				if override.Reason != "" {
					reason = fmt.Sprintf("admin override: %s (%s)", override.Action, override.Reason)
				}
				result = analysis.Result{
					Domain:     normalized,
					Verdict:    verdict,
					Confidence: 1.0,
					Score:      score,
					Reasons:    []string{reason},
					Category:   analysis.ClassifyCategory(normalized),
				}
				cacheHit = false
			}
		}

		// 2. Check Whitelist
		if result.Domain == "" && s.whitelist.IsAllowed(normalized) {
			result = analysis.Result{
				Domain:     normalized,
				Verdict:    analysis.VerdictSafe,
				Confidence: 1.0,
				Score:      0,
				Reasons:    []string{"whitelisted"},
				Category:   "uncategorized",
			}
			cacheHit = false
		}

		if result.Domain == "" {
			// 3. Fallback to threat assessment
			result, cacheHit = s.analyze(ctx, normalized)
		}
	}

	a := Analysis{
		Result:     result,
		CacheHit:   cacheHit,
		AnalyzedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}
	s.recordTelemetry(a, client)
	return a
}

func (s *Service) Policy(ctx context.Context, domain string, client ClientInfo) Policy {
	normalized, err := analysis.NormalizeDomain(domain)
	if err != nil {
		res := s.analyzer.Analyze(domain)
		return Policy{
			Domain:   domain,
			Policy:   "block",
			Result:   res,
			CacheHit: false,
		}
	}

	// 1. Get Group for Client
	var group *store.ClientGroup
	if s.store != nil && s.store.Enabled() {
		g, err := s.store.GetGroupForClient(client.IP, client.ClientID)
		if err == nil {
			group = g
		}
	}
	if group == nil {
		group = &store.ClientGroup{
			ID:             1,
			Name:           "default",
			StrictMalware:  true,
			StrictPhishing: false,
		}
	}

	// 2. Check Overrides
	if s.store != nil && s.store.Enabled() {
		override, err := s.store.GetEffectiveOverride(group.ID, normalized)
		if err == nil && override != nil {
			policyAction := override.Action
			verdict := analysis.VerdictSafe
			score := 0
			if policyAction == "block" {
				verdict = analysis.VerdictMalicious
				score = 100
			}
			reason := fmt.Sprintf("admin override: %s", policyAction)
			if override.Reason != "" {
				reason = fmt.Sprintf("admin override: %s (%s)", policyAction, override.Reason)
			}
			policyResult := Policy{
				Domain: normalized,
				Policy: policyAction,
				Result: analysis.Result{
					Domain:     normalized,
					Verdict:    verdict,
					Confidence: 1.0,
					Score:      score,
					Reasons:    []string{reason},
					Category:   analysis.ClassifyCategory(normalized),
				},
				CacheHit: false,
			}
			s.recordTelemetry(Analysis{
				Result:     policyResult.Result,
				CacheHit:   false,
				AnalyzedAt: time.Now().UTC().Format(time.RFC3339Nano),
			}, client)
			return policyResult
		}
	}

	// 3. Check Whitelist
	if s.whitelist.IsAllowed(normalized) {
		policyResult := Policy{
			Domain: normalized,
			Policy: "allow",
			Result: analysis.Result{
				Domain:     normalized,
				Verdict:    analysis.VerdictSafe,
				Confidence: 1.0,
				Score:      0,
				Reasons:    []string{"whitelisted"},
				Category:   "uncategorized",
			},
			CacheHit: false,
		}
		s.recordTelemetry(Analysis{
			Result:     policyResult.Result,
			CacheHit:   false,
			AnalyzedAt: time.Now().UTC().Format(time.RFC3339Nano),
		}, client)
		return policyResult
	}

	// 4. Get Threat Assessment
	result, cacheHit := s.analyze(ctx, normalized)

	// 5. Dynamic enforcement
	policy := "allow"
	if result.Verdict == analysis.VerdictMalicious && group.StrictMalware {
		policy = "block"
	}

	if group.StrictPhishing {
		isPhishing := false
		for _, r := range result.Reasons {
			if strings.Contains(strings.ToLower(r), "phishing") {
				isPhishing = true
				break
			}
		}
		if result.Score >= 40 && (isPhishing || result.Category == "phishing") {
			policy = "block"
		}
	}

	if len(group.BlockCategories) > 0 && result.Category != "" && result.Category != "uncategorized" {
		for _, blockedCat := range group.BlockCategories {
			if strings.ToLower(strings.TrimSpace(blockedCat)) == strings.ToLower(result.Category) {
				policy = "block"
				break
			}
		}
	}

	policyResult := Policy{
		Domain:   result.Domain,
		Policy:   policy,
		Result:   result,
		CacheHit: cacheHit,
	}

	s.recordTelemetry(Analysis{
		Result:     result,
		CacheHit:   cacheHit,
		AnalyzedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}, client)

	return policyResult
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
		return s.analyzer.Analyze(domain), false
	}

	// 1. Check Cache
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

	// 2. Check Threat Feed
	result := s.feedResult(ctx, normalized)
	if result.Domain == "" {
		// 3. Lexical Analysis
		result = s.analyzer.Analyze(normalized)
	}
	// 4. TLS + WHOIS Enrichment (suspicious zone only)
	s.enrichSuspicious(ctx, normalized, &result)
	// 5. AI Refinement
	result = s.refineWithAI(ctx, result)
	
	// Cache the final result
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

// enrichSuspicious runs TLS + WHOIS analysis in parallel for domains in the
// "suspicious zone" (score 20-69). Modifies result in-place. Always fail-open.
func (s *Service) enrichSuspicious(ctx context.Context, domain string, result *analysis.Result) {
	if !s.enrichEnabled || s.enrichTimeout <= 0 {
		return
	}
	// Only enrich the uncertain middle band.
	if result.Score < 20 || result.Score >= 70 {
		return
	}

	enrichCtx, cancel := context.WithTimeout(ctx, s.enrichTimeout)
	defer cancel()

	var (
		tlsResult   tlsinspect.Result
		whoisResult whois.Result
		wg          sync.WaitGroup
	)
	wg.Add(2)
	go func() {
		defer wg.Done()
		tlsResult = tlsinspect.Inspect(enrichCtx, domain)
	}()
	go func() {
		defer wg.Done()
		whoisResult = whois.Lookup(enrichCtx, domain)
	}()
	wg.Wait()

	// Merge scores and reasons.
	result.Score += tlsResult.Score + whoisResult.Score
	result.Reasons = append(result.Reasons, tlsResult.Reasons...)
	result.Reasons = append(result.Reasons, whoisResult.Reasons...)

	// Cap and recalculate verdict.
	if result.Score > 100 {
		result.Score = 100
	}
	switch {
	case result.Score >= 70:
		result.Verdict = analysis.VerdictMalicious
	case result.Score >= 40:
		result.Verdict = analysis.VerdictSuspicious
	default:
		result.Verdict = analysis.VerdictSafe
	}
	result.Confidence = math.Min(1, 0.45+float64(result.Score)/120)
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

// --- Local Overrides ---

func (s *Service) checkOverride(domain string) *analysis.Result {
	if s.store == nil {
		return nil
	}
	override, err := s.store.GetOverride(domain)
	if err != nil {
		log.Printf("override check failed for %s: %v", domain, err)
		return nil // fail-open
	}
	if override == nil {
		return nil
	}

	switch override.Action {
	case "block":
		reason := "admin override: block"
		if override.Reason != "" {
			reason = fmt.Sprintf("admin override: block (%s)", override.Reason)
		}
		return &analysis.Result{
			Domain:     domain,
			Verdict:    analysis.VerdictMalicious,
			Confidence: 1.0,
			Score:      100,
			Reasons:    []string{reason},
		}
	case "allow":
		reason := "admin override: allow"
		if override.Reason != "" {
			reason = fmt.Sprintf("admin override: allow (%s)", override.Reason)
		}
		return &analysis.Result{
			Domain:     domain,
			Verdict:    analysis.VerdictSafe,
			Confidence: 1.0,
			Score:      0,
			Reasons:    []string{reason},
		}
	}
	return nil
}

// --- Telemetry ---

func (s *Service) recordTelemetry(a Analysis, client ClientInfo) {
	if s.store == nil {
		return
	}
	s.store.RecordAnalysis(store.TelemetryEntry{
		Domain:     a.Result.Domain,
		Verdict:    string(a.Result.Verdict),
		Score:      a.Result.Score,
		Confidence: a.Result.Confidence,
		Reasons:    a.Result.Reasons,
		CacheHit:   a.CacheHit,
		Source:     inferSource(a),
		AnalyzedAt: a.AnalyzedAt,
		ClientIP:   client.IP,
		ClientID:   client.ClientID,
	})
}

func inferSource(a Analysis) string {
	if a.CacheHit {
		return "cache"
	}
	for _, r := range a.Result.Reasons {
		if strings.HasPrefix(r, "admin override") {
			return "override"
		}
		if r == "whitelisted" {
			return "whitelist"
		}
		if r == threatFeedReason {
			return "feed"
		}
	}
	return "lexical"
}

// --- Store API wrappers ---

// ListOverrides returns all local overrides, optionally filtered by action.
func (s *Service) ListOverrides(action string) ([]store.Override, error) {
	if s.store == nil {
		return nil, nil
	}
	return s.store.ListOverrides(action)
}

// UpsertOverride creates or updates a local override for a domain.
func (s *Service) UpsertOverride(domain, action, reason string) error {
	if s.store == nil {
		return fmt.Errorf("store not configured")
	}
	normalized, err := analysis.NormalizeDomain(domain)
	if err != nil {
		return fmt.Errorf("invalid domain: %w", err)
	}
	return s.store.UpsertOverride(normalized, action, reason)
}

// DeleteOverride removes a local override for a domain.
func (s *Service) DeleteOverride(domain string) error {
	if s.store == nil {
		return fmt.Errorf("store not configured")
	}
	normalized, err := analysis.NormalizeDomain(domain)
	if err != nil {
		return fmt.Errorf("invalid domain: %w", err)
	}
	return s.store.DeleteOverride(normalized)
}

// TelemetryRecent returns recent telemetry entries.
func (s *Service) TelemetryRecent(limit, offset int) ([]store.TelemetryEntry, error) {
	if s.store == nil {
		return nil, nil
	}
	return s.store.QueryRecent(limit, offset)
}

// TelemetryStats returns aggregate telemetry statistics.
func (s *Service) TelemetryStats(since time.Time) (store.Stats, error) {
	if s.store == nil {
		return store.Stats{}, nil
	}
	return s.store.QueryStats(since)
}

// --- Accessors for Agent Engine ---

// StoreDB returns the underlying SQLite store, or nil if not configured.
func (s *Service) StoreDB() *store.DB {
	if s == nil {
		return nil
	}
	return s.store
}

// AIClient returns the Gemini AI client, or nil if not configured.
func (s *Service) AIClient() *ai.Client {
	if s == nil {
		return nil
	}
	return s.ai
}

// RedisCache returns the Redis cache client, or nil if not configured.
func (s *Service) RedisCache() *cache.Redis {
	if s == nil {
		return nil
	}
	return s.redis
}

// Whitelist returns the whitelist client.
func (s *Service) Whitelist() *Whitelist {
	if s == nil {
		return nil
	}
	return s.whitelist
}

