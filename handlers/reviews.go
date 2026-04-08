package handlers

import (
	"encoding/json"
	"net/http"
	"xvulnv2/db"
	"xvulnv2/middleware"
	"xvulnv2/models"

	"github.com/gorilla/mux"
)

// GET /api/reviews?item_id=
func GetReviews(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	itemID := r.URL.Query().Get("item_id")

	var rows *db.Rows
	var err error
	if itemID != "" {
		rows, err = db.DB.Query("SELECT id, user_id, menu_item_id, rating, comment, created_at FROM reviews WHERE menu_item_id=? ORDER BY id DESC", itemID)
	} else {
		rows, err = db.DB.Query("SELECT id, user_id, menu_item_id, rating, comment, created_at FROM reviews ORDER BY id DESC LIMIT 20")
	}
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "failed to fetch reviews"})
		return
	}
	defer rows.Close()

	var reviews []models.Review
	for rows.Next() {
		var rv models.Review
		rows.Scan(&rv.ID, &rv.UserID, &rv.MenuItemID, &rv.Rating, &rv.Comment, &rv.CreatedAt)
		reviews = append(reviews, rv)
	}
	if reviews == nil {
		reviews = []models.Review{}
	}
	json.NewEncoder(w).Encode(reviews)
}

// POST /api/reviews — V03: stored XSS (comment stored and rendered unescaped)
func PostReview(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	userID, ok := middleware.GetSessionUserID(r)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"})
		return
	}

	var body struct {
		MenuItemID int    `json:"menu_item_id"`
		Rating     int    `json:"rating"`
		Comment    string `json:"comment"` // V03 — stored as-is, no sanitization
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid request body"})
		return
	}

	if body.Rating < 1 || body.Rating > 5 {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "rating must be between 1 and 5"})
		return
	}

	res, err := db.DB.Exec("INSERT INTO reviews (user_id, menu_item_id, rating, comment) VALUES (?, ?, ?, ?)",
		userID, body.MenuItemID, body.Rating, body.Comment)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "failed to submit review"})
		return
	}
	id, _ := res.LastInsertId()
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message":   "review submitted",
		"review_id": id,
	})
}

// GET /api/reviews/{id}
func GetReview(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	id := mux.Vars(r)["id"]
	var rv models.Review
	err := db.DB.QueryRow("SELECT id, user_id, menu_item_id, rating, comment, created_at FROM reviews WHERE id=?", id).
		Scan(&rv.ID, &rv.UserID, &rv.MenuItemID, &rv.Rating, &rv.Comment, &rv.CreatedAt)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "review not found"})
		return
	}
	json.NewEncoder(w).Encode(rv)
}
