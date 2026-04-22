package proxy

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/rs/zerolog"
)

var streamDebugIndexMu sync.Mutex

// streamDebugLine is one JSON line in stream-debug.jsonl (index + metadata;
// full bytes live in the referenced body_path files).
type streamDebugLine struct {
	ID               string `json:"id"`
	Method           string `json:"method"`
	Path             string `json:"path"`
	Host             string `json:"host"`
	BodyPath         string `json:"body_path"`
	Bytes            int64  `json:"captured_bytes"`
	UpstreamBodyPath string `json:"upstream_body_path,omitempty"`
	UpstreamBytes    int64  `json:"upstream_captured_bytes,omitempty"`
}

// streamDebugReadCloser spools the full response stream to disk as bytes are
// read, then appends a JSONL index line on Close. The client still receives
// the same data (after unredact). Uses O(disk) not O(stream size) memory.
type streamDebugReadCloser struct {
	inner  io.ReadCloser
	out    *os.File
	n      int64
	log    zerolog.Logger
	logged bool
	line   *streamDebugLine
	jpath  string
}

// sanitizeStreamDebugID makes a request id safe to use in a file name.
func sanitizeStreamDebugID(id string) string {
	safeID := id
	if safeID == "" {
		safeID = "unknown"
	}
	safeID = strings.Map(func(r rune) rune {
		if r < 0x20 || r == '/' || r == '\\' || r == '.' {
			return -1
		}
		return r
	}, safeID)
	if safeID == "" {
		safeID = "unknown"
	}
	return safeID
}

// newStreamUpstreamTeeReadCloser spools the raw response from the origin (before
// unredact) to stream-debug/<id>.upstream.raw. The reader passes bytes through
// unchanged. Use the same *streamDebugLine as newStreamDebugReadCloser so the
// index line lists both files.
func newStreamUpstreamTeeReadCloser(log zerolog.Logger, sessionDir string, line *streamDebugLine, inner io.ReadCloser) io.ReadCloser {
	if line == nil {
		return inner
	}
	safeID := sanitizeStreamDebugID(line.ID)
	dir := filepath.Join(sessionDir, "stream-debug")
	if err := os.MkdirAll(dir, 0755); err != nil {
		log.Warn().Err(err).Str("dir", dir).Msg("stream debug: could not create directory; upstream capture disabled for this response")
		return inner
	}
	outPath := filepath.Join(dir, safeID+".upstream.raw")
	f, err := os.Create(outPath)
	if err != nil {
		log.Warn().Err(err).Str("path", outPath).Msg("stream debug: could not create upstream body file; upstream capture disabled for this response")
		return inner
	}
	line.UpstreamBodyPath = outPath
	line.UpstreamBytes = 0
	return &streamUpstreamTeeReadCloser{
		inner: inner,
		out:   f,
		log:   log,
		line:  line,
	}
}

type streamUpstreamTeeReadCloser struct {
	inner io.ReadCloser
	out   *os.File
	n     int64
	log   zerolog.Logger
	line  *streamDebugLine
}

func (s *streamUpstreamTeeReadCloser) Read(p []byte) (int, error) {
	n, err := s.inner.Read(p)
	if n > 0 && s.out != nil {
		written, werr := s.out.Write(p[:n])
		if werr != nil {
			s.log.Warn().Err(werr).Msg("stream debug: upstream write error; capture may be incomplete")
		} else {
			s.n += int64(written)
		}
	}
	return n, err
}

func (s *streamUpstreamTeeReadCloser) Close() error {
	if s.out != nil {
		_ = s.out.Close()
		s.out = nil
	}
	if s.line != nil {
		s.line.UpstreamBytes = s.n
	}
	return s.inner.Close()
}

func newStreamDebugReadCloser(log zerolog.Logger, sessionDir string, line *streamDebugLine, inner io.ReadCloser) io.ReadCloser {
	if line == nil {
		return inner
	}
	safeID := sanitizeStreamDebugID(line.ID)
	dir := filepath.Join(sessionDir, "stream-debug")
	if err := os.MkdirAll(dir, 0755); err != nil {
		log.Warn().Err(err).Str("dir", dir).Msg("stream debug: could not create directory; capture disabled for this response")
		return inner
	}
	outPath := filepath.Join(dir, safeID+".raw")
	f, err := os.Create(outPath)
	if err != nil {
		log.Warn().Err(err).Str("path", outPath).Msg("stream debug: could not create body file; capture disabled for this response")
		return inner
	}
	line.BodyPath = outPath
	line.Bytes = 0
	return &streamDebugReadCloser{
		inner:  inner,
		out:    f,
		log:    log,
		line:   line,
		jpath:  filepath.Join(sessionDir, "stream-debug.jsonl"),
	}
}

func (s *streamDebugReadCloser) Read(p []byte) (int, error) {
	n, err := s.inner.Read(p)
	if n > 0 && s.out != nil {
		written, werr := s.out.Write(p[:n])
		if werr != nil {
			s.log.Warn().Err(werr).Msg("stream debug: write error; capture may be incomplete")
		} else {
			s.n += int64(written)
		}
	}
	return n, err
}

func (s *streamDebugReadCloser) Close() error {
	// Close inner first so the upstream tee (if any) finishes and populates
	// line.UpstreamBytes before we write the index line.
	err := s.inner.Close()
	if s.out != nil {
		_ = s.out.Close()
		s.out = nil
	}
	s.flush()
	return err
}

func (s *streamDebugReadCloser) flush() {
	if s.logged {
		return
	}
	s.logged = true

	if s.line != nil {
		s.line.Bytes = s.n
	}

	payload, err := json.Marshal(s.line)
	if err != nil {
		s.log.Warn().Err(err).Msg("stream debug: failed to marshal record")
		return
	}
	payload = append(payload, '\n')

	streamDebugIndexMu.Lock()
	defer streamDebugIndexMu.Unlock()

	f, err := os.OpenFile(s.jpath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		s.log.Warn().Err(err).Str("path", s.jpath).Msg("stream debug: failed to open index file")
		return
	}
	defer f.Close()

	if _, err := f.Write(payload); err != nil {
		s.log.Warn().Err(err).Str("path", s.jpath).Msg("stream debug: failed to write index line")
	}
}
