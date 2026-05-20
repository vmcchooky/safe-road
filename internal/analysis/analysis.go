package analysis

import (
	"encoding/json"
	"math"
	"net/url"
	"strings"
	"unicode"
	"unicode/utf8"
)

type Verdict string

const (
	VerdictInvalid    Verdict = "INVALID"
	VerdictSafe       Verdict = "SAFE"
	VerdictSuspicious Verdict = "SUSPICIOUS"
	VerdictMalicious  Verdict = "MALICIOUS"
)

type Result struct {
	Domain     string   `json:"domain"`
	Verdict    Verdict  `json:"verdict"`
	Confidence float64  `json:"confidence"`
	Score      int      `json:"score"`
	Reasons    []string `json:"reasons"`
}

func Analyze(input string) Result {
	domain, err := NormalizeDomain(input)
	if err != nil {
		return Result{
			Domain:     strings.TrimSpace(input),
			Verdict:    VerdictInvalid,
			Confidence: 1,
			Score:      100,
			Reasons:    []string{err.Error()},
		}
	}

	score := 0
	reasons := make([]string, 0, 6)

	if strings.HasPrefix(domain, "xn--") || strings.Contains(domain, ".xn--") {
		score += 35
		reasons = append(reasons, "punycode detected")
	}

	if len(domain) > 24 {
		score += 15
		reasons = append(reasons, "domain is long")
	}

	if hyphenCount := strings.Count(domain, "-"); hyphenCount >= 3 {
		score += 10
		reasons = append(reasons, "many hyphens")
	}

	if digitRatio(domain) > 0.25 {
		score += 10
		reasons = append(reasons, "high digit ratio")
	}

	if mixedScripts(domain) {
		score += 25
		reasons = append(reasons, "mixed script characters")
	}

	if keywordCount, keywordScore := suspiciousKeywordStats(domain); keywordScore > 0 {
		score += keywordScore
		reasons = append(reasons, "phishing keyword pattern")
		if keywordCount >= 2 {
			reasons = append(reasons, "multiple phishing keywords")
		}
	}

	if score > 100 {
		score = 100
	}

	verdict := VerdictSafe
	switch {
	case score >= 70:
		verdict = VerdictMalicious
	case score >= 40:
		verdict = VerdictSuspicious
	}

	return Result{
		Domain:     domain,
		Verdict:    verdict,
		Confidence: math.Min(1, 0.45+float64(score)/120),
		Score:      score,
		Reasons:    reasons,
	}
}

func NormalizeDomain(input string) (string, error) {
	value := strings.TrimSpace(strings.ToLower(input))
	if value == "" {
		return "", errInvalidDomain("domain is empty")
	}

	if strings.Contains(value, "://") {
		parsed, err := url.Parse(value)
		if err != nil || parsed.Hostname() == "" {
			return "", errInvalidDomain("domain could not be parsed from url")
		}
		value = parsed.Hostname()
	}

	if strings.Count(value, ":") == 1 {
		parts := strings.SplitN(value, ":", 2)
		if parts[0] != "" {
			value = parts[0]
		}
	}

	value = strings.TrimSuffix(value, ".")
	if value == "" {
		return "", errInvalidDomain("domain is empty")
	}

	for _, r := range value {
		if r == '.' || r == '-' || unicode.IsLetter(r) || unicode.IsDigit(r) {
			continue
		}
		if r > utf8.RuneSelf {
			continue
		}
		return "", errInvalidDomain("domain contains invalid characters")
	}

	return value, nil
}

func MarshalResult(result Result) ([]byte, error) {
	return json.MarshalIndent(result, "", "  ")
}

func digitRatio(value string) float64 {
	if value == "" {
		return 0
	}

	digitCount := 0
	for _, r := range value {
		if unicode.IsDigit(r) {
			digitCount++
		}
	}

	return float64(digitCount) / float64(len(value))
}

func mixedScripts(value string) bool {
	hasLatin := false
	hasNonLatin := false

	for _, r := range value {
		if r == '.' || r == '-' || unicode.IsDigit(r) {
			continue
		}
		if r <= utf8.RuneSelf {
			hasLatin = true
			continue
		}
		hasNonLatin = true
	}

	return hasLatin && hasNonLatin
}

func suspiciousKeywordStats(value string) (int, int) {
	keywords := []string{"login", "secure", "verify", "account", "update", "support", "wallet"}
	keywordCount := 0
	for _, keyword := range keywords {
		if strings.Contains(value, keyword) {
			keywordCount++
		}
	}

	if keywordCount == 0 {
		return 0, 0
	}

	keywordScore := 15 + keywordCount*10
	if keywordCount >= 2 {
		keywordScore += 10
	}

	return keywordCount, keywordScore
}

type invalidDomainError string

func (e invalidDomainError) Error() string {
	return string(e)
}

func errInvalidDomain(message string) error {
	return invalidDomainError(message)
}
