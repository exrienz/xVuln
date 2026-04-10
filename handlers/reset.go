package handlers

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"xvulnv2/db"
)

// POST /api/reset — benchmark state reset
func Reset(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	db.Reset()
	resetGeneratedFiles("./static/uploads/menus")
	resetGeneratedFiles("./static/exports/tmp")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "database reset to initial state",
		"status":  "ok",
	})
}

func resetGeneratedFiles(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		os.Remove(filepath.Join(dir, entry.Name()))
	}
}
