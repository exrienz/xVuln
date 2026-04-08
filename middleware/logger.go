package middleware

import (
	"bytes"
	"io"
	"net/http"
	"time"
	"xvulnv2/db"
)

type responseWriter struct {
	http.ResponseWriter
	status int
	size   int
}

func (rw *responseWriter) WriteHeader(status int) {
	rw.status = status
	rw.ResponseWriter.WriteHeader(status)
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	n, err := rw.ResponseWriter.Write(b)
	rw.size += n
	return n, err
}

func Logger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		var bodyBytes []byte
		if r.Body != nil {
			bodyBytes, _ = io.ReadAll(r.Body)
			r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		}

		rw := &responseWriter{ResponseWriter: w, status: 200}
		next.ServeHTTP(rw, r)

		scannerID := r.Header.Get("X-Scanner-ID")
		if scannerID == "" {
			scannerID = r.Header.Get("X-Scan-Token")
		}

		ip := r.RemoteAddr
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			ip = xff
		}

		go func() {
			db.DB.Exec(`INSERT INTO request_logs (method, path, query, body, status, response_size, scanner_id, ip, user_agent, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				r.Method,
				r.URL.Path,
				r.URL.RawQuery,
				string(bodyBytes),
				rw.status,
				rw.size,
				scannerID,
				ip,
				r.UserAgent(),
				start.Format(time.RFC3339),
			)
		}()
	})
}
