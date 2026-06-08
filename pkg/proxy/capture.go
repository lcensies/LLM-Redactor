package proxy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
)

// captureLine is one JSON line appended to the --capture file. It records the
// full outbound (client→upstream) request so an external harness can assert
// that protected content never crossed the wire.
type captureLine struct {
	TS      int64  `json:"ts"`
	Method  string `json:"method"`
	URL     string `json:"url"`
	Body    string `json:"body"`               // sent body (post-redaction)
	BodyRaw string `json:"body_raw,omitempty"` // original body (pre-redaction), if it differed
}

// captureWriter appends one JSON line per outbound request to a file. It is
// opt-in (created only when --capture is set), append-mode, and safe for
// concurrent use across the proxy's request handlers.
type captureWriter struct {
	mu   sync.Mutex
	path string
	f    *os.File
}

// newCaptureWriter opens (creating parent dirs as needed) the capture file in
// append mode. A nil writer is returned when path is empty, in which case
// writes are no-ops.
func newCaptureWriter(path string) (*captureWriter, error) {
	if path == "" {
		return nil, nil
	}
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, err
		}
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}
	return &captureWriter{path: path, f: f}, nil
}

// Write appends a single capture record as one JSON line. It is a no-op on a
// nil writer so callers need not branch.
func (c *captureWriter) Write(line captureLine) error {
	if c == nil || c.f == nil {
		return nil
	}
	payload, err := json.Marshal(line)
	if err != nil {
		return err
	}
	payload = append(payload, '\n')

	c.mu.Lock()
	defer c.mu.Unlock()
	_, err = c.f.Write(payload)
	return err
}

// Close closes the underlying file. Safe on a nil writer.
func (c *captureWriter) Close() error {
	if c == nil || c.f == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	err := c.f.Close()
	c.f = nil
	return err
}
