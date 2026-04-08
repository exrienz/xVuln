package handlers

import (
	"encoding/json"
	"net/http"
	"xvulnv2/db"
	"xvulnv2/middleware"
	"xvulnv2/models"
)

// POST /register
func Register(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var body struct {
		Username string `json:"username"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid request body"})
		return
	}
	if body.Username == "" || body.Email == "" || body.Password == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "username, email, and password are required"})
		return
	}

	// V10 — Mass Assignment: role accepted from user input
	role := r.URL.Query().Get("role")
	if role == "" {
		role = "user"
	}

	var existing int
	db.DB.QueryRow("SELECT COUNT(*) FROM users WHERE email=? OR username=?", body.Email, body.Username).Scan(&existing)
	if existing > 0 {
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(map[string]string{"error": "username or email already exists"})
		return
	}

	// Store password in plaintext (realistic developer mistake)
	res, err := db.DB.Exec("INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)",
		body.Username, body.Email, body.Password, role)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "failed to create account"})
		return
	}
	id, _ := res.LastInsertId()
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "account created successfully",
		"user_id": id,
	})
}

// POST /login
// V12 — No rate limiting on login
func Login(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var body struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid request body"})
		return
	}

	var user models.User
	err := db.DB.QueryRow("SELECT id, username, email, password, role FROM users WHERE email=? AND password=?",
		body.Email, body.Password).Scan(&user.ID, &user.Username, &user.Email, &user.Password, &user.Role)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid credentials"})
		return
	}

	sess, _ := middleware.GetSession(r)
	sess.Values["user_id"] = user.ID
	sess.Values["username"] = user.Username
	sess.Values["role"] = user.Role
	sess.Save(r, w)

	json.NewEncoder(w).Encode(map[string]interface{}{
		"message":  "login successful",
		"user_id":  user.ID,
		"username": user.Username,
		"role":     user.Role,
	})
}

// POST /logout
func Logout(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	sess, _ := middleware.GetSession(r)
	sess.Values = map[interface{}]interface{}{}
	sess.Options.MaxAge = -1
	sess.Save(r, w)
	json.NewEncoder(w).Encode(map[string]string{"message": "logged out"})
}

// GET /api/me
func Me(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	userID, ok := middleware.GetSessionUserID(r)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "not authenticated"})
		return
	}
	var user models.User
	db.DB.QueryRow("SELECT id, username, email, role FROM users WHERE id=?", userID).
		Scan(&user.ID, &user.Username, &user.Email, &user.Role)
	json.NewEncoder(w).Encode(user)
}
