package usage

import (
	"context"
	"net/http"
	"strings"
	"time"
)

type collectorContextKey struct{}

func (c *Collector) WrapMCP(next http.Handler) http.Handler {
	if c == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		writer := &responseWriter{ResponseWriter: w}
		c.beginHTTPRequest()
		defer func() {
			statusCode := writer.statusCode
			if statusCode == 0 {
				statusCode = http.StatusOK
			}
			c.finishHTTPRequest(statusCode, normalizeClientFamily(r.UserAgent()), time.Since(start), writer.bytesWritten)
		}()
		requestContext := context.WithValue(r.Context(), collectorContextKey{}, c)
		next.ServeHTTP(writer, r.WithContext(requestContext))
	})
}

func FromContext(ctx context.Context) *Collector {
	collector, _ := ctx.Value(collectorContextKey{}).(*Collector)
	return collector
}

type responseWriter struct {
	http.ResponseWriter
	statusCode   int
	bytesWritten int
}

func (w *responseWriter) WriteHeader(statusCode int) {
	if w.statusCode != 0 {
		return
	}
	w.statusCode = statusCode
	w.ResponseWriter.WriteHeader(statusCode)
}

func (w *responseWriter) Write(data []byte) (int, error) {
	if w.statusCode == 0 {
		w.WriteHeader(http.StatusOK)
	}
	written, err := w.ResponseWriter.Write(data)
	w.bytesWritten += written
	return written, err
}

func (w *responseWriter) Flush() {
	if w.statusCode == 0 {
		w.WriteHeader(http.StatusOK)
	}
	_ = http.NewResponseController(w.ResponseWriter).Flush()
}

func (w *responseWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

func normalizeClientFamily(userAgent string) string {
	normalized := strings.ToLower(userAgent)
	switch {
	case strings.Contains(normalized, "pojun-agent"):
		return "pojun-agent"
	case strings.Contains(normalized, "codex"):
		return "codex"
	case strings.Contains(normalized, "claude"):
		return "claude"
	case strings.Contains(normalized, "python"):
		return "python"
	default:
		return "other"
	}
}
