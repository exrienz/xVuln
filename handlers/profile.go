package handlers

import (
	"encoding/json"
	"net/http"
	"xvulnv2/db"
	"xvulnv2/middleware"
	"xvulnv2/models"
)

// GET /api/user/profile?id= — V06: IDOR via id query param
func GetProfile(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, ok := middleware.GetSessionUserID(r)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"})
		return
	}

	// V06 — IDOR: uses ?id= param instead of session user
	// V08 — Sensitive Data Exposure: returns password in response
	id := r.URL.Query().Get("id")
	if id == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "id parameter required"})
		return
	}

	var user models.User
	err := db.DB.QueryRow("SELECT id, username, email, password, role, created_at FROM users WHERE id=?", id).
		Scan(&user.ID, &user.Username, &user.Email, &user.Password, &user.Role, &user.CreatedAt)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "user not found"})
		return
	}

	// V08 — password returned in response
	json.NewEncoder(w).Encode(user)
}

// POST /api/user/update — V10: mass assignment via JSON body
func UpdateProfile(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	userID, ok := middleware.GetSessionUserID(r)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"})
		return
	}

	// V10 — Mass Assignment: role field accepted directly
	var body struct {
		Username string `json:"username"`
		Email    string `json:"email"`
		Password string `json:"password"`
		Role     string `json:"role"` // should never be accepted from user input
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid request body"})
		return
	}

	if body.Role == "" {
		body.Role = "user"
	}

	_, err := db.DB.Exec("UPDATE users SET username=?, email=?, password=?, role=? WHERE id=?",
		body.Username, body.Email, body.Password, body.Role, userID)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "failed to update profile"})
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"message": "profile updated"})
}
