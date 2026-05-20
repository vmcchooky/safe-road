package ai

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"safe-road/internal/analysis"
)

const (
	defaultModel   = "gemini-2.5-flash-lite"
	defaultBaseURL = "https://generativelanguage.googleapis.com/v1beta"
)

type Client struct {
	baseURL string
	apiKey  string
	model   string
	timeout time.Duration
	http    *http.Client
}

type Result struct {
	Verdict    string  `json:"verdict"`
	Confidence float64 `json:"confidence"`
	Reason     string  `json:"reason"`
}

type generateRequest struct {
	Contents []content        `json:"contents"`
	Config   generationConfig `json:"generationConfig"`
}

type generationConfig struct {
	Temperature      float64 `json:"temperature,omitempty"`
	ResponseMimeType string  `json:"responseMimeType,omitempty"`
}

type content struct {
	Role  string `json:"role,omitempty"`
	Parts []part `json:"parts"`
}

type part struct {
	Text string `json:"text"`
}

type generateResponse struct {
	Candidates []struct {
		Content struct {
			Parts []part `json:"parts"`
		} `json:"content"`
	} `json:"candidates"`
	Error struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

func New(baseURL, apiKey, model string, timeout time.Duration) *Client {
	baseURL = strings.TrimSpace(baseURL)
	apiKey = strings.TrimSpace(apiKey)
	if model == "" {
		model = defaultModel
	}
	if baseURL == "" {
		baseURL = defaultBaseURL
	}

	if timeout <= 0 {
		timeout = 3 * time.Second
	}

	if apiKey == "" {
		return &Client{model: model, timeout: timeout}
	}

	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		apiKey:  apiKey,
		model:   model,
		timeout: timeout,
		http: &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
			},
		},
	}
}

func (c *Client) Enabled() bool {
	return c != nil && c.apiKey != "" && c.http != nil
}

func (c *Client) Refine(ctx context.Context, domain string, current analysis.Result) (analysis.Result, error) {
	if !c.Enabled() {
		return analysis.Result{}, errors.New("ai client disabled")
	}

	prompt := buildPrompt(domain, current)
	reqBody, err := json.Marshal(generateRequest{
		Contents: []content{{
			Role:  "user",
			Parts: []part{{Text: prompt}},
		}},
		Config: generationConfig{
			Temperature:      0,
			ResponseMimeType: "application/json",
		},
	})
	if err != nil {
		return analysis.Result{}, err
	}

	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	requestURL := fmt.Sprintf("%s/models/%s:generateContent?key=%s", c.baseURL, url.PathEscape(c.model), url.QueryEscape(c.apiKey))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, requestURL, bytes.NewReader(reqBody))
	if err != nil {
		return analysis.Result{}, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return analysis.Result{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return analysis.Result{}, fmt.Errorf("gemini returned HTTP %d", resp.StatusCode)
	}

	var envelope generateResponse
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return analysis.Result{}, err
	}
	if envelope.Error.Message != "" {
		return analysis.Result{}, errors.New(envelope.Error.Message)
	}

	text, err := firstResponseText(envelope)
	if err != nil {
		return analysis.Result{}, err
	}

	var parsed Result
	if err := json.Unmarshal([]byte(extractJSON(text)), &parsed); err != nil {
		return analysis.Result{}, err
	}

	result := analysis.Result{Domain: current.Domain}
	switch strings.ToUpper(strings.TrimSpace(parsed.Verdict)) {
	case string(analysis.VerdictMalicious):
		result.Verdict = analysis.VerdictMalicious
		result.Score = 85
	case string(analysis.VerdictSuspicious):
		result.Verdict = analysis.VerdictSuspicious
		result.Score = 55
	default:
		result.Verdict = analysis.VerdictSafe
		result.Score = 0
	}

	if parsed.Confidence < 0 {
		parsed.Confidence = 0
	}
	if parsed.Confidence > 1 {
		parsed.Confidence = 1
	}
	result.Confidence = parsed.Confidence
	if parsed.Reason != "" {
		result.Reasons = []string{"local ai classification: " + parsed.Reason}
	}

	return result, nil
}

func firstResponseText(envelope generateResponse) (string, error) {
	if len(envelope.Candidates) == 0 {
		return "", errors.New("gemini returned no candidates")
	}
	parts := envelope.Candidates[0].Content.Parts
	if len(parts) == 0 {
		return "", errors.New("gemini returned no content parts")
	}

	var builder strings.Builder
	for _, item := range parts {
		builder.WriteString(item.Text)
	}

	return strings.TrimSpace(builder.String()), nil
}

func extractJSON(text string) string {
	text = strings.TrimSpace(text)
	text = strings.TrimPrefix(text, "```json")
	text = strings.TrimPrefix(text, "```")
	text = strings.TrimSuffix(text, "```")
	text = strings.TrimSpace(text)
	if strings.HasPrefix(text, "{") && strings.HasSuffix(text, "}") {
		return text
	}

	start := strings.Index(text, "{")
	end := strings.LastIndex(text, "}")
	if start >= 0 && end > start {
		return text[start : end+1]
	}

	return text
}

func buildPrompt(domain string, current analysis.Result) string {
	return fmt.Sprintf(`Bạn là chuyên gia bảo mật. Phân tích domain sau: %s
Kết quả hiện tại: verdict=%s, score=%d, confidence=%.2f

Trả lời CHÍNH XÁC theo JSON:
{"verdict": "SAFE|SUSPICIOUS|MALICIOUS", "confidence": 0.0-1.0, "reason": "giải thích ngắn"}`,
		domain, current.Verdict, current.Score, current.Confidence)
}
