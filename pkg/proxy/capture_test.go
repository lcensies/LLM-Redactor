package proxy

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestCaptureWriterAppendsJSONLines(t *testing.T) {
	// Path includes a missing subdirectory to verify it is created.
	dir := filepath.Join(t.TempDir(), "missing", "nested")
	path := filepath.Join(dir, "capture.jsonl")

	w, err := newCaptureWriter(path)
	if err != nil {
		t.Fatalf("newCaptureWriter: %v", err)
	}
	if w == nil {
		t.Fatal("expected non-nil writer for non-empty path")
	}

	want := []captureLine{
		{TS: 1, Method: "POST", URL: "https://api.example.com/v1/x", Body: "hello", BodyRaw: "secret"},
		{TS: 2, Method: "GET", URL: "https://api.example.com/v1/y", Body: "world"},
	}
	for _, l := range want {
		if err := w.Write(l); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open capture file: %v", err)
	}
	defer f.Close()

	var got []captureLine
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var l captureLine
		if err := json.Unmarshal(sc.Bytes(), &l); err != nil {
			t.Fatalf("unmarshal line %q: %v", sc.Text(), err)
		}
		got = append(got, l)
	}
	if len(got) != len(want) {
		t.Fatalf("got %d lines, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("line %d = %+v, want %+v", i, got[i], want[i])
		}
	}

	// body_raw must be omitted when empty.
	if data, _ := json.Marshal(want[1]); jsonHasKey(data, "body_raw") {
		t.Errorf("expected body_raw omitted when empty, got %s", data)
	}
}

func TestCaptureWriterAppendModeAcrossOpens(t *testing.T) {
	path := filepath.Join(t.TempDir(), "capture.jsonl")

	w1, err := newCaptureWriter(path)
	if err != nil {
		t.Fatalf("newCaptureWriter 1: %v", err)
	}
	if err := w1.Write(captureLine{TS: 1, Method: "POST", URL: "u1", Body: "a"}); err != nil {
		t.Fatalf("write 1: %v", err)
	}
	_ = w1.Close()

	// Reopening the same path must append, not truncate.
	w2, err := newCaptureWriter(path)
	if err != nil {
		t.Fatalf("newCaptureWriter 2: %v", err)
	}
	if err := w2.Write(captureLine{TS: 2, Method: "POST", URL: "u2", Body: "b"}); err != nil {
		t.Fatalf("write 2: %v", err)
	}
	_ = w2.Close()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	lines := 0
	for _, b := range data {
		if b == '\n' {
			lines++
		}
	}
	if lines != 2 {
		t.Fatalf("expected 2 lines after append, got %d (%q)", lines, data)
	}
}

func TestNewCaptureWriterEmptyPathIsNoOp(t *testing.T) {
	w, err := newCaptureWriter("")
	if err != nil {
		t.Fatalf("newCaptureWriter(\"\"): %v", err)
	}
	if w != nil {
		t.Fatal("expected nil writer for empty path")
	}
	// Write/Close on a nil writer must not panic.
	if err := w.Write(captureLine{TS: 1}); err != nil {
		t.Fatalf("nil Write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("nil Close: %v", err)
	}
}

func jsonHasKey(data []byte, key string) bool {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(data, &m); err != nil {
		return false
	}
	_, ok := m[key]
	return ok
}
