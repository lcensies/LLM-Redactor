package redactor

import (
	"bytes"
	"io"
	"strings"

	json "github.com/goccy/go-json"
)

// streamUnredactLineReader buffers an HTTP body until newline boundaries, then
// unredacts per line: JSON objects/arrays in SSE "data: …" and NDJSON lines are
// walked with unredactValueJSON; other text uses UnredactContent on the whole
// line. This avoids global substring unredact corrupting stream chunk joints.
type streamUnredactLineReader struct {
	redactor *Redactor
	inner    io.ReadCloser
	buf      []byte
	pending  []byte
	err      error
}

func newStreamUnredactLineReader(r *Redactor, inner io.ReadCloser) *streamUnredactLineReader {
	return &streamUnredactLineReader{redactor: r, inner: inner}
}

func (s *streamUnredactLineReader) Read(p []byte) (int, error) {
	for len(s.pending) == 0 && s.err == nil {
		if err := s.fill(); err != nil {
			if len(s.pending) == 0 {
				return 0, err
			}
			break
		}
	}
	if len(s.pending) == 0 {
		return 0, s.err
	}
	n := copy(p, s.pending)
	s.pending = s.pending[n:]
	if s.err != nil && len(s.pending) == 0 {
		return n, s.err
	}
	return n, nil
}

func (s *streamUnredactLineReader) fill() error {
	if s.err != nil {
		return s.err
	}
	var tmp [4096]byte
	n, err := s.inner.Read(tmp[:])
	if n > 0 {
		s.buf = append(s.buf, tmp[:n]...)
	}
	for {
		idx := bytes.IndexByte(s.buf, '\n')
		if idx < 0 {
			break
		}
		line := s.buf[:idx+1]
		s.buf = s.buf[idx+1:]
		s.pending = append(s.pending, s.redactor.unredactStreamLineWithEnding(line)...)
	}
	if err != nil {
		if err == io.EOF {
			if len(s.buf) > 0 {
				s.pending = append(s.pending, s.redactor.unredactStreamLineWithEnding(s.buf)...)
				s.buf = nil
			}
			s.err = io.EOF
		} else {
			s.err = err
		}
		return s.err
	}
	return nil
}

func (s *streamUnredactLineReader) Close() error {
	if s.inner == nil {
		return nil
	}
	return s.inner.Close()
}

// unredactStreamLineWithEnding processes one logical line, including a trailing
// "\n" or "\r\n" if present. Lines without a trailing newline (final chunk) are
// supported.
func (r *Redactor) unredactStreamLineWithEnding(line []byte) []byte {
	if len(line) == 0 {
		return line
	}
	orig := string(line)
	eol := ""
	trim := orig
	if strings.HasSuffix(orig, "\r\n") {
		eol = "\r\n"
		trim = orig[:len(orig)-2]
	} else if strings.HasSuffix(orig, "\n") {
		eol = "\n"
		trim = orig[:len(orig)-1]
	}
	if trim == "" {
		if eol == "" {
			return line
		}
		// empty line, keep
		return line
	}
	return []byte(r.unredactStreamLineNoEOL(trim) + eol)
}

// unredactStreamLineNoEOL applies path-aware unredact to one line of text
// without trailing newline/CR.
func (r *Redactor) unredactStreamLineNoEOL(line string) string {
	trimL := strings.TrimLeft(line, " \t")
	if strings.HasPrefix(trimL, "data:") {
		leading := line[:len(line)-len(trimL)]
		afterData := trimL[len("data:"):]
		j := 0
		for j < len(afterData) && (afterData[j] == ' ' || afterData[j] == '\t') {
			j++
		}
		payload := afterData[j:]
		if s := strings.TrimSpace(payload); s == "" {
			return line
		}
		if strings.EqualFold(strings.TrimSpace(payload), "[DONE]") {
			return line
		}
		if !json.Valid([]byte(payload)) {
			return r.UnredactContent(line)
		}
		var v interface{}
		if err := json.Unmarshal([]byte(payload), &v); err != nil {
			return r.UnredactContent(line)
		}
		out, changed := r.unredactValueJSON(v, false, false, false, nil)
		if !changed {
			return line
		}
		b, err := json.Marshal(out)
		if err != nil {
			return line
		}
		return leading + "data:" + afterData[:j] + string(b)
	}

	if json.Valid([]byte(trimL)) {
		lead := line[:len(line)-len(strings.TrimLeft(line, " \t"))]
		var v interface{}
		if err := json.Unmarshal([]byte(trimL), &v); err != nil {
			return r.UnredactContent(line)
		}
		out, changed := r.unredactValueJSON(v, false, false, false, nil)
		if !changed {
			return line
		}
		b, err := json.Marshal(out)
		if err != nil {
			return line
		}
		return string(lead) + string(b)
	}
	return r.UnredactContent(line)
}
