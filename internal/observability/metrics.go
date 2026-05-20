package observability

import (
	"fmt"
	"sync"
	"time"
)

type Registry struct {
	startedAt time.Time
	mu        sync.Mutex
	requests  map[string]*RequestSummary
}

type RequestSummary struct {
	Count               int64 `json:"count"`
	Bytes               int64 `json:"bytes"`
	TotalDurationMillis int64 `json:"total_duration_ms"`
	MaxDurationMillis   int64 `json:"max_duration_ms"`
	LastStatus          int   `json:"last_status"`
}

type Snapshot struct {
	StartedAt      string                    `json:"started_at"`
	UptimeSeconds  int64                     `json:"uptime_seconds"`
	RequestSummary map[string]RequestSummary `json:"request_summary"`
}

func NewRegistry() *Registry {
	return &Registry{
		startedAt: time.Now().UTC(),
		requests:  make(map[string]*RequestSummary),
	}
}

func (r *Registry) Observe(method, path string, statusCode int, bytesWritten int, duration time.Duration) {
	if r == nil {
		return
	}

	key := fmt.Sprintf("%s %s %d", method, path, statusCode)

	r.mu.Lock()
	defer r.mu.Unlock()

	summary, ok := r.requests[key]
	if !ok {
		summary = &RequestSummary{}
		r.requests[key] = summary
	}

	durationMillis := duration.Milliseconds()
	summary.Count++
	summary.Bytes += int64(bytesWritten)
	summary.TotalDurationMillis += durationMillis
	if durationMillis > summary.MaxDurationMillis {
		summary.MaxDurationMillis = durationMillis
	}
	summary.LastStatus = statusCode
}

func (r *Registry) Snapshot() Snapshot {
	if r == nil {
		return Snapshot{}
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	requestSummary := make(map[string]RequestSummary, len(r.requests))
	for key, value := range r.requests {
		requestSummary[key] = *value
	}

	return Snapshot{
		StartedAt:      r.startedAt.Format(time.RFC3339Nano),
		UptimeSeconds:  int64(time.Since(r.startedAt).Seconds()),
		RequestSummary: requestSummary,
	}
}
