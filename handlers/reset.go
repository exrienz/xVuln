package handlers

import (
	"encoding/json"
	"net/http"
	"xvulnv2/db"
)

// POST /api/reset — benchmark state reset
func Reset(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	db.Reset()
	json.NewEncoder(w).Encode(map[string]string{
		"message": "database reset to initial state",
		"status":  "ok",
	})
}
