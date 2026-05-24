package feed

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"errors"
	"fmt"
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
	var result ParseResult
	err := ParseEach(r, func(domain string) error {
		result.Domains = append(result.Domains, domain)
		return nil
	}, &result.Stats)
	if err != nil {
		return ParseResult{}, err
	}
	return result, nil
}

func ParseEach(r io.Reader, onDomain func(domain string) error, stats *ParseStats) error {
	if onDomain == nil {
		return errors.New("domain handler is required")
	}
	if stats == nil {
		stats = &ParseStats{}
	}

	seen := map[string]struct{}{}
	reader, isCSV, err := detectFormat(r)
	if err != nil {
		return err
	}
	if isCSV {
		return parseCSVStream(reader, seen, stats, onDomain)
	}
	return parseTextStream(reader, seen, stats, onDomain)
}

func parseCSVStream(r io.Reader, seen map[string]struct{}, stats *ParseStats, onDomain func(string) error) error {
	reader := csv.NewReader(r)
	for {
		row, err := reader.Read()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}

		domain, ok := firstDomain(row)
		if !ok {
			stats.Invalid++
			continue
		}

		if err := addDomain(stats, seen, domain, onDomain); err != nil {
			return err
		}
	}
}

func parseTextStream(r io.Reader, seen map[string]struct{}, stats *ParseStats, onDomain func(string) error) error {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		if err := parseTextLine(scanner.Text(), seen, stats, onDomain); err != nil {
			return err
		}
	}
	if err := scanner.Err(); err != nil {
		if errors.Is(err, bufio.ErrTooLong) {
			return fmt.Errorf("feed line exceeds 1048576 bytes: %w", err)
		}
		return err
	}
	return nil
}

func parseTextLine(line string, seen map[string]struct{}, stats *ParseStats, onDomain func(string) error) error {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		stats.Skipped++
		return nil
	}

	parsedAny := false
	lineHadValid := false
	lineInvalid := 0
	for _, field := range strings.Fields(line) {
		if strings.HasPrefix(field, "#") {
			break
		}
		field = stripComment(strings.TrimSpace(field))
		if field == "" {
			continue
		}
		parsedAny = true

		domain, err := normalizeCandidate(field)
		if err != nil {
			lineInvalid++
			continue
		}

		lineHadValid = true
		if err := addDomain(stats, seen, domain, onDomain); err != nil {
			return err
		}
	}
	if !parsedAny {
		stats.Skipped++
		return nil
	}
	if lineHadValid {
		stats.Invalid += lineInvalid
		return nil
	}
	if lineInvalid > 0 {
		stats.Invalid++
	}
	return nil
}

func detectFormat(r io.Reader) (io.Reader, bool, error) {
	buffered := bufio.NewReader(r)
	var prefix bytes.Buffer
	for {
		line, err := buffered.ReadString('\n')
		if line != "" {
			_, _ = prefix.WriteString(line)
			trimmed := strings.TrimSpace(line)
			if trimmed != "" && !strings.HasPrefix(trimmed, "#") {
				return io.MultiReader(bytes.NewReader(prefix.Bytes()), buffered), strings.Contains(trimmed, ","), nil
			}
		}
		if errors.Is(err, io.EOF) {
			return bytes.NewReader(prefix.Bytes()), false, nil
		}
		if err != nil {
			return nil, false, err
		}
		if prefix.Len() > 1024*1024 {
			return nil, false, errors.New("feed line exceeds 1048576 bytes")
		}
	}
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

func addDomain(stats *ParseStats, seen map[string]struct{}, domain string, onDomain func(string) error) error {
	if _, exists := seen[domain]; exists {
		stats.Duplicates++
		return nil
	}

	seen[domain] = struct{}{}
	stats.Valid++
	return onDomain(domain)
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
