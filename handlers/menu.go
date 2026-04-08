package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"xvulnv2/db"
	"xvulnv2/middleware"
	"xvulnv2/models"

	"github.com/gorilla/mux"
)

// GET /api/menu — returns all available menu items
func GetMenu(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	category := r.URL.Query().Get("category")
	var rows *db.Rows
	var err error

	if category != "" {
		// V01 — SQL Injection: category param interpolated directly
		query := fmt.Sprintf("SELECT id, name, description, price, category, image_url, available FROM menu_items WHERE category='%s' AND available=1", category)
		rows, err = db.QueryRows(query)
	} else {
		rows, err = db.QueryRows("SELECT id, name, description, price, category, image_url, available FROM menu_items WHERE available=1 ORDER BY id")
	}
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "failed to fetch menu"})
		return
	}
	defer rows.Close()

	var items []models.MenuItem
	for rows.Next() {
		var item models.MenuItem
		rows.Scan(&item.ID, &item.Name, &item.Description, &item.Price, &item.Category, &item.ImageURL, &item.Available)
		items = append(items, item)
	}
	if items == nil {
		items = []models.MenuItem{}
	}
	json.NewEncoder(w).Encode(items)
}

// GET /api/menu/{id}
func GetMenuItem(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	id := mux.Vars(r)["id"]

	// V01 — SQL Injection: id concatenated directly into query
	query := fmt.Sprintf("SELECT id, name, description, price, category, image_url, available FROM menu_items WHERE id=%s", id)
	row := db.DB.QueryRow(query)

	var item models.MenuItem
	err := row.Scan(&item.ID, &item.Name, &item.Description, &item.Price, &item.Category, &item.ImageURL, &item.Available)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "item not found"})
		return
	}
	json.NewEncoder(w).Encode(item)
}

// GET /api/search?q=
func SearchMenu(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	q := r.URL.Query().Get("q")
	if q == "" {
		json.NewEncoder(w).Encode([]models.MenuItem{})
		return
	}

	// V02 — SQL Injection: search term concatenated directly
	query := fmt.Sprintf("SELECT id, name, description, price, category, image_url, available FROM menu_items WHERE name LIKE '%%%s%%' OR description LIKE '%%%s%%'", q, q)
	rows, err := db.QueryRows(query)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "search failed"})
		return
	}
	defer rows.Close()

	var items []models.MenuItem
	for rows.Next() {
		var item models.MenuItem
		rows.Scan(&item.ID, &item.Name, &item.Description, &item.Price, &item.Category, &item.ImageURL, &item.Available)
		items = append(items, item)
	}
	if items == nil {
		items = []models.MenuItem{}
	}
	json.NewEncoder(w).Encode(items)
}

// DELETE /api/menu/{id} — V11: any authenticated user can delete
func DeleteMenuItem(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, ok := middleware.GetSessionUserID(r)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"})
		return
	}

	// V11 — Broken Function Level Auth: no admin role check
	id := mux.Vars(r)["id"]
	res, err := db.DB.Exec("UPDATE menu_items SET available=0 WHERE id=?", id)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "failed to delete item"})
		return
	}
	affected, _ := res.RowsAffected()
	if affected == 0 {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "item not found"})
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"message": "item removed from menu"})
}
