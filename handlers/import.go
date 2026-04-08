package handlers

import (
	"encoding/json"
	"io"
	"net/http"
)

// POST /api/import-menu — V04: SSRF via user-controlled URL
func ImportMenu(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var body struct {
		URL string `json:"url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.URL == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "url is required"})
		return
	}

	// V04 — SSRF: server fetches user-supplied URL without validation
	resp, err := http.Get(body.URL)
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		json.NewEncoder(w).Encode(map[string]string{"error": "failed to fetch menu from URL"})
		return
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MB limit
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "failed to read response"})
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"message":       "menu data imported",
		"bytes_fetched": len(data),
		"content_type":  resp.Header.Get("Content-Type"),
	})
}
