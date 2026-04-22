package proxy

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rs/zerolog"
)

func TestStreamDebugReadCloser_SpoolsFullStream(t *testing.T) {
	dir := t.TempDir()
	payload := "event: x\ndata: {\"a\":1}\n\n" + strings.Repeat("y", 5000)
	inner := io.NopCloser(strings.NewReader(payload))
	line := &streamDebugLine{ID: "req-test-1", Method: "POST", Path: "/v1", Host: "h"}
	r := newStreamDebugReadCloser(zerolog.Nop(), dir, line, inner)

	b, _ := io.ReadAll(r)
	if string(b) != payload {
		t.Fatalf("pass-through size mismatch: got %d want %d", len(b), len(payload))
	}
	_ = r.Close()

	bodyPath := filepath.Join(dir, "stream-debug", "req-test-1.raw")
	raw, err := os.ReadFile(bodyPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != payload {
		t.Fatalf("file content mismatch, got %d bytes", len(raw))
	}

	index, _ := os.ReadFile(filepath.Join(dir, "stream-debug.jsonl"))
	var meta streamDebugLine
	if err := json.Unmarshal(bytes.TrimSpace(index), &meta); err != nil {
		t.Fatal(err)
	}
	if meta.ID != "req-test-1" || meta.Method != "POST" {
		t.Fatalf("meta: %#v", meta)
	}
	if meta.Bytes != int64(len(payload)) {
		t.Fatalf("captured_bytes: got %d want %d", meta.Bytes, len(payload))
	}
	if meta.BodyPath != bodyPath {
		t.Fatalf("body_path: %q", meta.BodyPath)
	}
	if meta.UpstreamBodyPath != "" {
		t.Fatalf("expected no upstream path in this test, got %q", meta.UpstreamBodyPath)
	}
}

func TestStreamDebugReadCloser_SanitizeEmptyID(t *testing.T) {
	dir := t.TempDir()
	inner := io.NopCloser(strings.NewReader("ok"))
	r := newStreamDebugReadCloser(zerolog.Nop(), dir, &streamDebugLine{ID: ""}, inner)
	_, _ = io.Copy(io.Discard, r)
	_ = r.Close()

	_, err := os.Stat(filepath.Join(dir, "stream-debug", "unknown.raw"))
	if err != nil {
		t.Fatal(err)
	}
}

// TestStreamDebugUpstreamTee_MatchesClientWithoutUnredact checks that with no
// transform between upstream tee and client tee, .upstream.raw and .raw match
// and the index lists both paths and byte counts.
func TestStreamDebugUpstreamTee_MatchesClientWithoutUnredact(t *testing.T) {
	dir := t.TempDir()
	payload := "data: {\"a\":1}\n\ndata: {\"a\":2}\n"
	inner := io.NopCloser(strings.NewReader(payload))
	line := &streamDebugLine{ID: "chain-test-id", Method: "POST", Path: "/v1", Host: "h"}
	tee := newStreamUpstreamTeeReadCloser(zerolog.Nop(), dir, line, inner)
	r := newStreamDebugReadCloser(zerolog.Nop(), dir, line, tee)
	out, _ := io.ReadAll(r)
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if string(out) != payload {
		t.Fatalf("pass-through: got %q", out)
	}
	up, err := os.ReadFile(filepath.Join(dir, "stream-debug", "chain-test-id.upstream.raw"))
	if err != nil {
		t.Fatal(err)
	}
	client, err := os.ReadFile(filepath.Join(dir, "stream-debug", "chain-test-id.raw"))
	if err != nil {
		t.Fatal(err)
	}
	if string(up) != payload || string(client) != payload || string(up) != string(client) {
		t.Fatalf("upstream and client should equal origin bytes")
	}
	index, _ := os.ReadFile(filepath.Join(dir, "stream-debug.jsonl"))
	var meta streamDebugLine
	if err := json.Unmarshal(bytes.TrimSpace(index), &meta); err != nil {
		t.Fatal(err)
	}
	if meta.UpstreamBytes != int64(len(payload)) || meta.Bytes != int64(len(payload)) {
		t.Fatalf("captured bytes: upstream=%d client=%d want %d", meta.UpstreamBytes, meta.Bytes, len(payload))
	}
	if meta.UpstreamBodyPath == "" || !strings.HasSuffix(meta.UpstreamBodyPath, "chain-test-id.upstream.raw") {
		t.Fatalf("upstream_body_path: %q", meta.UpstreamBodyPath)
	}
}
