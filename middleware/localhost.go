package middleware

import (
	"encoding/json"
	"net"
	"net/http"
)

// LocalhostOnly restricts access to requests originating from localhost.
// It inspects r.RemoteAddr (NOT X-Forwarded-For, which can be spoofed)
// and allows only 127.0.0.1, ::1, and [::1].
// Returns 403 Forbidden with JSON body for all other sources.
func LocalhostOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			// If we can't parse the address, deny access
			host = r.RemoteAddr
		}

		if !isLocalhost(host) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "access denied: this endpoint is restricted to localhost",
			})
			return
		}

		next.ServeHTTP(w, r)
	})
}

// isLocalhost checks if the given IP address is a loopback address.
func isLocalhost(host string) bool {
	ip := net.ParseIP(host)
	if ip == nil {
		return host == "localhost"
	}
	return ip.IsLoopback()
}
