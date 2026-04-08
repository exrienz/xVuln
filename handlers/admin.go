package handlers

import (
	"encoding/json"
	"net/http"
	"runtime"
	"xvulnv2/db"
	"xvulnv2/middleware"
)

// GET /admin/orders — V07: checks X-Admin-Token header, not session role
func AdminGetOrders(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// V07 — Broken Auth: checks header token instead of verified session role
	token := r.Header.Get("X-Admin-Token")
	if token != "restaurant-admin-2024" {
		// fallback: check session but no role verification
		sess, _ := middleware.GetSession(r)
		if sess.Values["user_id"] == nil {
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{"error": "forbidden"})
			return
		}
		// BUG: only checks if logged in, not if role == "admin"
	}

	rows, err := db.DB.Query(`
		SELECT o.id, o.user_id, u.username, o.total, o.status, o.note, o.created_at
		FROM orders o
		JOIN users u ON o.user_id = u.id
		ORDER BY o.id DESC
	`)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "failed to fetch orders"})
		return
	}
	defer rows.Close()

	type AdminOrder struct {
		ID        int     `json:"id"`
		UserID    int     `json:"user_id"`
		Username  string  `json:"username"`
		Total     float64 `json:"total"`
		Status    string  `json:"status"`
		Note      string  `json:"note"`
		CreatedAt string  `json:"created_at"`
	}

	var orders []AdminOrder
	for rows.Next() {
		var o AdminOrder
		rows.Scan(&o.ID, &o.UserID, &o.Username, &o.Total, &o.Status, &o.Note, &o.CreatedAt)
		orders = append(orders, o)
	}
	if orders == nil {
		orders = []AdminOrder{}
	}
	json.NewEncoder(w).Encode(orders)
}

// GET /admin/users — V07: same broken auth pattern
func AdminGetUsers(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	token := r.Header.Get("X-Admin-Token")
	if token != "restaurant-admin-2024" {
		sess, _ := middleware.GetSession(r)
		if sess.Values["user_id"] == nil {
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{"error": "forbidden"})
			return
		}
	}

	rows, err := db.DB.Query("SELECT id, username, email, password, role, created_at FROM users ORDER BY id")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "failed to fetch users"})
		return
	}
	defer rows.Close()

	type AdminUser struct {
		ID        int    `json:"id"`
		Username  string `json:"username"`
		Email     string `json:"email"`
		Password  string `json:"password"` // Exposed
		Role      string `json:"role"`
		CreatedAt string `json:"created_at"`
	}

	var users []AdminUser
	for rows.Next() {
		var u AdminUser
		rows.Scan(&u.ID, &u.Username, &u.Email, &u.Password, &u.Role, &u.CreatedAt)
		users = append(users, u)
	}
	if users == nil {
		users = []AdminUser{}
	}
	json.NewEncoder(w).Encode(users)
}

// GET /api/debug/info — V09: debug endpoint left exposed in production
func DebugInfo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	var userCount, orderCount, menuCount int
	db.DB.QueryRow("SELECT COUNT(*) FROM users").Scan(&userCount)
	db.DB.QueryRow("SELECT COUNT(*) FROM orders").Scan(&orderCount)
	db.DB.QueryRow("SELECT COUNT(*) FROM menu_items").Scan(&menuCount)

	json.NewEncoder(w).Encode(map[string]interface{}{
		"version":     "1.4.2",
		"environment": "production",
		"db_path":     "./restaurant.db",
		"session_key": "restaurant-secret-key-2024",
		"admin_token": "restaurant-admin-2024",
		"heap_alloc":  memStats.HeapAlloc,
		"goroutines":  runtime.NumGoroutine(),
		"users":       userCount,
		"orders":      orderCount,
		"menu_items":  menuCount,
	})
}
