package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"safe-road/internal/feed"
)

func TestOpenSourceHandlesGzipHTTP(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		w.WriteHeader(http.StatusOK)
		writer := gzip.NewWriter(w)
		_, _ = writer.Write([]byte("bad.test\n"))
		_ = writer.Close()
	}))
	defer server.Close()

	reader, closeReader, err := openSource(context.Background(), server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer closeReader()

	parsed, err := feed.Parse(reader)
	if err != nil {
		t.Fatal(err)
	}

	if parsed.Stats.Valid != 1 {
		t.Fatalf("expected 1 valid domain, got %d", parsed.Stats.Valid)
	}
	if len(parsed.Domains) != 1 || parsed.Domains[0] != "bad.test" {
		t.Fatalf("unexpected domains: %#v", parsed.Domains)
	}
}

func TestWrapMaybeCompressedReadCloserWithGzipSuffix(t *testing.T) {
	var buf bytes.Buffer
	writer := gzip.NewWriter(&buf)
	_, _ = writer.Write([]byte("evil.test\n"))
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	reader, closeReader, err := wrapMaybeCompressedReadCloser(io.NopCloser(bytes.NewReader(buf.Bytes())), "feed.txt.gz", "")
	if err != nil {
		t.Fatal(err)
	}
	defer closeReader()

	parsed, err := feed.Parse(reader)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.Domains) != 1 || parsed.Domains[0] != "evil.test" {
		t.Fatalf("unexpected domains: %#v", parsed.Domains)
	}
}
