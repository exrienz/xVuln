package handlers

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"xvulnv2/middleware"
)

// POST /api/cart/restore — V14: insecure deserialization of base64-encoded JSON cart
func RestoreCart(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, ok := middleware.GetSessionUserID(r)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"})
		return
	}

	var body struct {
		CartData string `json:"cart_data"` // base64-encoded JSON
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.CartData == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "cart_data required"})
		return
	}

	// V14 — Insecure Deserialization: base64 decoded and parsed without validation
	decoded, err := base64.StdEncoding.DecodeString(body.CartData)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid cart data encoding"})
		return
	}

	var cart map[string]interface{}
	if err := json.Unmarshal(decoded, &cart); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid cart data"})
		return
	}

	// Use the cart data directly — discount, promo codes, item prices accepted from client
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "cart restored",
		"cart":    cart,
	})
}

// GET /api/cart — get cart placeholder
func GetCart(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, ok := middleware.GetSessionUserID(r)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"})
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{
		"items":    []interface{}{},
		"total":    0,
		"discount": 0,
	})
}
