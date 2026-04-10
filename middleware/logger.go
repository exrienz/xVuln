package middleware

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
	"xvulnv2/db"

	"github.com/gorilla/mux"
)

type responseWriter struct {
	http.ResponseWriter
	status int
	size   int
	body   bytes.Buffer
}

const maxLoggedResponseBodyBytes = 128 * 1024

func (rw *responseWriter) WriteHeader(status int) {
	rw.status = status
	rw.ResponseWriter.WriteHeader(status)
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	n, err := rw.ResponseWriter.Write(b)
	rw.size += n
	if remaining := maxLoggedResponseBodyBytes - rw.body.Len(); remaining > 0 {
		if len(b) > remaining {
			rw.body.Write(b[:remaining])
		} else {
			rw.body.Write(b)
		}
	}
	return n, err
}

func formatDuration(d time.Duration) time.Duration {
	if d < time.Millisecond {
		return d.Round(time.Microsecond)
	}
	return d.Round(time.Millisecond)
}

func Logger(next http.Handler) http.Handler {
	return logger("backend", true, next)
}

func ConsoleLogger(server string) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return logger(server, false, next)
	}
}

func logger(server string, persist bool, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		var bodyBytes []byte
		if r.Body != nil {
			bodyBytes, _ = io.ReadAll(r.Body)
			r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		}

		rw := &responseWriter{ResponseWriter: w, status: 200}
		next.ServeHTTP(rw, r)

		duration := time.Since(start)
		scannerID := r.Header.Get("X-Scanner-ID")
		if scannerID == "" {
			scannerID = r.Header.Get("X-Scan-Token")
		}
		if scannerID == "" {
			scannerID = "-"
		}

		ip := r.RemoteAddr
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			ip = xff
		}

		route := "-"
		if current := mux.CurrentRoute(r); current != nil {
			if template, err := current.GetPathTemplate(); err == nil && template != "" {
				route = template
			}
		}

		target := r.URL.Path
		if r.URL.RawQuery != "" {
			target += "?" + r.URL.RawQuery
		}

		log.Printf("[http] server=%s method=%s path=%s route=%s status=%d bytes=%d dur=%s ip=%s scanner=%s ua=%q",
			server,
			r.Method,
			target,
			route,
			rw.status,
			rw.size,
			formatDuration(duration),
			ip,
			scannerID,
			r.UserAgent(),
		)

		if !persist {
			return
		}

		headersJSON := "{}"
		responseBody := ""
		durationMs := 0
		if scannerID != "-" {
			headerMap := map[string]string{}
			for key, values := range r.Header {
				headerMap[key] = strings.Join(values, ", ")
			}
			if encoded, err := json.Marshal(headerMap); err == nil {
				headersJSON = string(encoded)
			}
			responseBody = rw.body.String()
			durationMs = int(duration.Milliseconds())
		}

		go func() {
			db.DB.Exec(`INSERT INTO request_logs (method, path, query, body, request_headers, route, status, response_size, response_body, duration_ms, scanner_id, ip, user_agent, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				r.Method,
				r.URL.Path,
				r.URL.RawQuery,
				string(bodyBytes),
				headersJSON,
				route,
				rw.status,
				rw.size,
				responseBody,
				durationMs,
				scannerID,
				ip,
				r.UserAgent(),
				start.Format(time.RFC3339),
			)
		}()
	})
}
