package proxy

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/wangyihang/llm-prism/pkg/config"
	"github.com/wangyihang/llm-prism/pkg/llms/providers"
	"github.com/wangyihang/llm-prism/pkg/redactor"
	"github.com/wangyihang/llm-prism/pkg/utils/logging"
)

type contextKey string

const requestIDKey contextKey = "requestID"

func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey, id)
}

func GetRequestID(ctx context.Context) string {
	if id, ok := ctx.Value(requestIDKey).(string); ok {
		return id
	}
	return ""
}

func Setup(cli *config.CLI, rdr *redactor.Redactor, logs *logging.Loggers) (*httputil.ReverseProxy, error) {
	u, err := url.Parse(cli.Run.ApiURL)
	if err != nil {
		return nil, fmt.Errorf("invalid API URL: %w", err)
	}

	p := providers.GetProvider(cli.Run.Provider, u, cli.Run.ApiKey)
	rp := httputil.NewSingleHostReverseProxy(u)

	d := rp.Director
	rp.Director = func(r *http.Request) {
		d(r)
		p.Director(r)
		requestID := GetRequestID(r.Context())
		if rdr != nil && r.Method == http.MethodPost && r.Body != nil {
			body, _ := io.ReadAll(r.Body)
			redacted, err := rdr.RedactRequest(body, map[string]string{
				"request_id": requestID,
				"source":     "request",
				"path":       r.URL.Path,
				"method":     r.Method,
			})
			if err == nil {
				r.Body = io.NopCloser(bytes.NewReader(redacted))
				r.ContentLength = int64(len(redacted))
				r.Header.Set("Content-Length", fmt.Sprint(len(redacted)))
			} else {
				r.Body = io.NopCloser(bytes.NewReader(body))
			}
		}
	}

	rp.ModifyResponse = func(res *http.Response) error {
		return nil
	}

	return rp, nil
}
