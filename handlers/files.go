package handlers

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
)

// GET /api/files?name= — V13: path traversal via filename parameter
func GetFile(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	name := r.URL.Query().Get("name")
	if name == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "name parameter required"})
		return
	}

	// V13 — Path Traversal: filename not sanitized, allows ../../etc/passwd
	basePath := "./uploads"
	fullPath := filepath.Join(basePath, name)

	data, err := os.ReadFile(fullPath)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "file not found"})
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Content-Disposition", "inline; filename="+filepath.Base(name))
	w.Write(data)
}
