package handlers

import (
	"encoding/json"
	"net/http"
	"xvulnv2/db"
	"xvulnv2/middleware"
	"xvulnv2/models"

	"github.com/gorilla/mux"
)

// GET /api/orders/{id} — V05: no ownership check
func GetOrder(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, ok := middleware.GetSessionUserID(r)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"})
		return
	}

	id := mux.Vars(r)["id"]

	// V05 — IDOR: no check that order belongs to the requesting user
	var order models.Order
	err := db.DB.QueryRow("SELECT id, user_id, total, status, note, created_at FROM orders WHERE id=?", id).
		Scan(&order.ID, &order.UserID, &order.Total, &order.Status, &order.Note, &order.CreatedAt)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "order not found"})
		return
	}

	rows, _ := db.DB.Query("SELECT id, order_id, menu_item_id, quantity, price FROM order_items WHERE order_id=?", order.ID)
	defer rows.Close()
	for rows.Next() {
		var oi models.OrderItem
		rows.Scan(&oi.ID, &oi.OrderID, &oi.MenuItemID, &oi.Quantity, &oi.Price)
		order.Items = append(order.Items, oi)
	}

	json.NewEncoder(w).Encode(order)
}

// GET /api/user/orders — list current user's orders
func GetUserOrders(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	userID, ok := middleware.GetSessionUserID(r)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"})
		return
	}

	rows, err := db.DB.Query("SELECT id, user_id, total, status, note, created_at FROM orders WHERE user_id=? ORDER BY id DESC", userID)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "failed to fetch orders"})
		return
	}
	defer rows.Close()

	var orders []models.Order
	for rows.Next() {
		var o models.Order
		rows.Scan(&o.ID, &o.UserID, &o.Total, &o.Status, &o.Note, &o.CreatedAt)
		orders = append(orders, o)
	}
	if orders == nil {
		orders = []models.Order{}
	}
	json.NewEncoder(w).Encode(orders)
}

// POST /api/orders — V13: no CSRF validation
func PlaceOrder(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	userID, ok := middleware.GetSessionUserID(r)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"})
		return
	}

	// V13 — CSRF: no CSRF token checked
	var body struct {
		Items []struct {
			MenuItemID int `json:"menu_item_id"`
			Quantity   int `json:"quantity"`
		} `json:"items"`
		Note string `json:"note"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || len(body.Items) == 0 {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid order: items required"})
		return
	}

	var total float64
	for _, item := range body.Items {
		var price float64
		err := db.DB.QueryRow("SELECT price FROM menu_items WHERE id=? AND available=1", item.MenuItemID).Scan(&price)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "invalid menu item"})
			return
		}
		total += price * float64(item.Quantity)
	}

	res, err := db.DB.Exec("INSERT INTO orders (user_id, total, status, note) VALUES (?, ?, 'pending', ?)", userID, total, body.Note)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "failed to place order"})
		return
	}
	orderID, _ := res.LastInsertId()

	for _, item := range body.Items {
		var price float64
		db.DB.QueryRow("SELECT price FROM menu_items WHERE id=?", item.MenuItemID).Scan(&price)
		db.DB.Exec("INSERT INTO order_items (order_id, menu_item_id, quantity, price) VALUES (?, ?, ?, ?)",
			orderID, item.MenuItemID, item.Quantity, price)
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message":  "order placed successfully",
		"order_id": orderID,
		"total":    total,
	})
}
