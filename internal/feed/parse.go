package feed

import (
	"encoding/csv"
	"errors"
	"io"
	"net/url"
	"strings"

	"safe-road/internal/analysis"
)

type ParseStats struct {
	Valid      int `json:"valid"`
	Invalid    int `json:"invalid"`
	Duplicates int `json:"duplicates"`
	Skipped    int `json:"skipped"`
}

type ParseResult struct {
	Domains []string   `json:"domains"`
	Stats   ParseStats `json:"stats"`
}

func Parse(r io.Reader) (ParseResult, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return ParseResult{}, err
	}

	if isProbablyCSV(string(data)) {
		csvRows, csvErr := csv.NewReader(strings.NewReader(string(data))).ReadAll()
		if csvErr == nil {
			return parseCSVRows(csvRows), nil
		}
	}

	return parseLines(strings.Split(string(data), "\n")), nil
}

func parseCSVRows(rows [][]string) ParseResult {
	seen := map[string]struct{}{}
	result := ParseResult{}

	for _, row := range rows {
		if len(row) == 0 {
			result.Stats.Skipped++
			continue
		}

		domain, ok := firstDomain(row)
		if !ok {
			result.Stats.Invalid++
			continue
		}

		addDomain(&result, seen, domain)
	}

	return result
}

func parseLines(lines []string) ParseResult {
	seen := map[string]struct{}{}
	result := ParseResult{}

	for _, line := range lines {
		line = stripComment(strings.TrimSpace(line))
		if line == "" {
			result.Stats.Skipped++
			continue
		}

		domain, err := normalizeCandidate(line)
		if err != nil {
			result.Stats.Invalid++
			continue
		}

		addDomain(&result, seen, domain)
	}

	return result
}

func firstDomain(fields []string) (string, bool) {
	for _, field := range fields {
		field = stripComment(strings.TrimSpace(field))
		if field == "" {
			continue
		}

		domain, err := normalizeCandidate(field)
		if err == nil {
			return domain, true
		}
	}

	return "", false
}

func addDomain(result *ParseResult, seen map[string]struct{}, domain string) {
	if _, exists := seen[domain]; exists {
		result.Stats.Duplicates++
		return
	}

	seen[domain] = struct{}{}
	result.Domains = append(result.Domains, domain)
	result.Stats.Valid++
}

func stripComment(value string) string {
	if strings.HasPrefix(value, "#") {
		return ""
	}
	if index := strings.Index(value, "#"); index >= 0 {
		return strings.TrimSpace(value[:index])
	}

	return value
}

func normalizeCandidate(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", errors.New("empty feed candidate")
	}

	if strings.Contains(value, "://") {
		parsed, err := url.Parse(value)
		if err != nil || parsed.Hostname() == "" {
			return "", errors.New("invalid feed url candidate")
		}
		value = parsed.Hostname()
	}

	domain, err := analysis.NormalizeDomain(value)
	if err != nil {
		return "", err
	}
	if !strings.Contains(domain, ".") {
		return "", errors.New("feed candidate must be a domain, not a single label")
	}

	return domain, nil
}

func isProbablyCSV(data string) bool {
	for _, line := range strings.Split(data, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		return strings.Contains(line, ",")
	}

	return false
}
