package handlers

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"xvulnv2/config"
	"xvulnv2/db"
	"xvulnv2/middleware"

	"github.com/gorilla/mux"
)

const (
	// Fake-but-realistic lab secrets left in source on purpose for source review exercises.
	kitchenTelemetryAPIKey   = "lab_live_kitchen_telemetry_2026"
	legacyPaymentsSharedKey  = "lab_live_tablepay_shared_secret"
	legacyKitchenJWTSecret   = "kitchen-legacy-secret"
	menuUploadDir            = "./static/uploads/menus"
	recipeDir                = "./recipes"
	tempInvoiceExportDir     = "./static/exports/tmp"
	requestSmugglingBoundary = "\r\n0\r\n\r\n"
)

type labJWTClaims struct {
	Sub   int    `json:"sub"`
	Email string `json:"email"`
	Role  string `json:"role"`
	Iss   string `json:"iss"`
	Iat   int64  `json:"iat"`
	Exp   int64  `json:"exp"`
}

var (
	labRateLimitMu      sync.Mutex
	labRateLimitBuckets = map[string][]time.Time{}
)

func ensureAdvancedVulnsEnabled(w http.ResponseWriter) bool {
	if config.Get().EnableAdvancedVulns {
		return true
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotFound)
	json.NewEncoder(w).Encode(map[string]string{
		"error": "advanced lab module disabled in this environment",
	})
	return false
}

// POST /api/admin/menu/upload-image — V15: unrestricted file upload
func UploadMenuImage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if !ensureAdvancedVulnsEnabled(w) {
		return
	}

	userID, ok := middleware.GetSessionUserID(r)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"})
		return
	}

	if err := r.ParseMultipartForm(8 << 20); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "multipart form required"})
		return
	}

	menuItemID, err := strconv.Atoi(r.FormValue("menu_item_id"))
	if err != nil || menuItemID <= 0 {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "menu_item_id is required"})
		return
	}

	file, header, err := r.FormFile("image")
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "image file is required"})
		return
	}
	defer file.Close()

	// V15 — Unrestricted File Upload: accepts any extension/content and makes it web-accessible.
	filename := filepath.Base(header.Filename)
	if filename == "." || filename == "" {
		filename = fmt.Sprintf("menu-%d-upload.bin", menuItemID)
	}
	data, err := io.ReadAll(io.LimitReader(file, 4<<20))
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "failed to read uploaded file"})
		return
	}

	storedPath := filepath.Join(menuUploadDir, filename)
	if err := os.WriteFile(storedPath, data, 0644); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "failed to persist uploaded file"})
		return
	}

	publicURL := "/static/uploads/menus/" + filename
	db.DB.Exec("UPDATE menu_items SET image_url=? WHERE id=?", publicURL, menuItemID)
	db.DB.Exec("INSERT INTO files (name, path, uploaded_by) VALUES (?, ?, ?)", filename, storedPath, userID)

	json.NewEncoder(w).Encode(map[string]interface{}{
		"message":      "menu asset uploaded",
		"menu_item_id": menuItemID,
		"filename":     filename,
		"content_type": header.Header.Get("Content-Type"),
		"stored_path":  storedPath,
		"public_url":   publicURL,
		"size":         len(data),
	})
}

// GET /api/orders/{id}/invoice/export — V19: insecure temporary file usage
func ExportInvoice(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if !ensureAdvancedVulnsEnabled(w) {
		return
	}

	userID, ok := middleware.GetSessionUserID(r)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"})
		return
	}

	orderID := mux.Vars(r)["id"]
	type invoiceOrder struct {
		ID        int
		UserID    int
		Username  string
		Total     float64
		Status    string
		Note      string
		CreatedAt string
	}

	var order invoiceOrder
	err := db.DB.QueryRow(`
		SELECT o.id, o.user_id, u.username, o.total, o.status, o.note, o.created_at
		FROM orders o
		JOIN users u ON o.user_id = u.id
		WHERE o.id=? AND o.user_id=?
	`, orderID, userID).Scan(&order.ID, &order.UserID, &order.Username, &order.Total, &order.Status, &order.Note, &order.CreatedAt)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "order not found"})
		return
	}

	publicName := fmt.Sprintf("invoice-order-%d.json", order.ID)
	publicURL := "/static/exports/tmp/" + publicName
	publicPath := filepath.Join(tempInvoiceExportDir, publicName)

	// V19 — predictable, publicly served temporary export file with permissive mode.
	payload := map[string]interface{}{
		"order_id":    order.ID,
		"user_id":     order.UserID,
		"username":    order.Username,
		"total":       order.Total,
		"status":      order.Status,
		"note":        order.Note,
		"created_at":  order.CreatedAt,
		"exported_at": time.Now().UTC().Format(time.RFC3339),
		"temporary":   true,
	}
	data, _ := json.MarshalIndent(payload, "", "  ")
	if err := os.WriteFile(publicPath, data, 0644); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "failed to write invoice export"})
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"message":     "invoice export generated",
		"order_id":    order.ID,
		"temp_path":   publicPath,
		"public_url":  publicURL,
		"expires":     "manual cleanup only",
		"size":        len(data),
		"exported_by": userID,
	})
}

// GET /api/kitchen/recipes/view?source= — V17: LFI / RFI
func ViewRecipe(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if !ensureAdvancedVulnsEnabled(w) {
		return
	}

	source := r.URL.Query().Get("source")
	if source == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "source parameter required"})
		return
	}

	// V17 — RFI: remote recipe templates fetched directly from attacker-controlled URLs.
	if strings.HasPrefix(source, "http://") || strings.HasPrefix(source, "https://") {
		if !allowLabRequest(w, r, "recipe_remote_fetch", 6, time.Minute) {
			return
		}
		resp, err := http.Get(source)
		if err != nil {
			w.WriteHeader(http.StatusBadGateway)
			json.NewEncoder(w).Encode(map[string]string{"error": "failed to fetch remote recipe source"})
			return
		}
		defer resp.Body.Close()

		data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		json.NewEncoder(w).Encode(map[string]interface{}{
			"mode":         "remote",
			"source":       source,
			"status":       resp.StatusCode,
			"content_type": resp.Header.Get("Content-Type"),
			"bytes":        len(data),
			"content":      string(data),
		})
		return
	}

	// V17 — LFI: relative path traversal through unsanitized recipe source.
	resolvedPath := filepath.Join(recipeDir, source)
	data, err := os.ReadFile(resolvedPath)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "recipe source not found"})
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"mode":          "local",
		"source":        source,
		"resolved_path": resolvedPath,
		"bytes":         len(data),
		"content":       string(data),
	})
}

// POST /api/staff/session — V20 support: weak JWT issuance
func CreateStaffSession(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if !ensureAdvancedVulnsEnabled(w) {
		return
	}

	var body struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid request body"})
		return
	}

	var claims labJWTClaims
	err := db.DB.QueryRow("SELECT id, email, role FROM users WHERE email=? AND password=?", body.Email, body.Password).
		Scan(&claims.Sub, &claims.Email, &claims.Role)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid credentials"})
		return
	}

	claims.Iss = "kitchen-display-service"
	claims.Iat = time.Now().Unix()
	claims.Exp = time.Now().Add(15 * time.Minute).Unix()

	token, err := issueLabJWT(claims)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "failed to issue staff token"})
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "staff token issued",
		"token":   token,
		"panel":   "/api/staff/panel",
		"role":    claims.Role,
	})
}

// GET /api/staff/panel — V20: JWT auth with weak secret, alg confusion, no exp validation
func GetStaffPanel(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if !ensureAdvancedVulnsEnabled(w) {
		return
	}

	claims, header, err := parseLabJWTFromRequest(r)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid or missing staff token"})
		return
	}
	if claims.Role != "admin" && claims.Role != "staff" {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{"error": "staff role required"})
		return
	}

	inventory, err := readInventorySnapshot()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "failed to load kitchen panel"})
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "kitchen control panel loaded",
		"auth": map[string]interface{}{
			"alg":   header["alg"],
			"role":  claims.Role,
			"email": claims.Email,
		},
		"inventory": inventory,
	})
}

// GET /api/kitchen/inventory — inventory snapshot for lab workflows
func GetKitchenInventory(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if !ensureAdvancedVulnsEnabled(w) {
		return
	}

	claims, _, err := parseLabJWTFromRequest(r)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid or missing staff token"})
		return
	}
	if claims.Role != "admin" && claims.Role != "staff" {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{"error": "staff role required"})
		return
	}

	inventory, err := readInventorySnapshot()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "failed to load inventory"})
		return
	}
	json.NewEncoder(w).Encode(inventory)
}

// POST /api/kitchen/inventory/adjust — V16: API9 improper inventory management
func AdjustKitchenInventory(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if !ensureAdvancedVulnsEnabled(w) {
		return
	}

	claims, _, err := parseLabJWTFromRequest(r)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid or missing staff token"})
		return
	}
	if claims.Role != "admin" && claims.Role != "staff" {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{"error": "staff role required"})
		return
	}

	var body struct {
		MenuItemID int    `json:"menu_item_id"`
		Delta      int    `json:"delta"`
		SetTo      *int   `json:"set_to"`
		Location   string `json:"location"`
		Reason     string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.MenuItemID <= 0 {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "menu_item_id is required"})
		return
	}

	if body.Location == "" {
		body.Location = "main-kitchen"
	}

	var currentStock int
	err = db.DB.QueryRow("SELECT stock FROM inventory WHERE menu_item_id=?", body.MenuItemID).Scan(&currentStock)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "inventory item not found"})
		return
	}

	// V16 — Improper inventory management: allows arbitrary direct stock rewrites,
	// negative inventory, and unrealistic deltas with no workflow validation.
	nextStock := currentStock + body.Delta
	if body.SetTo != nil {
		nextStock = *body.SetTo
	}

	_, err = db.DB.Exec(
		"UPDATE inventory SET stock=?, location=?, updated_at=CURRENT_TIMESTAMP WHERE menu_item_id=?",
		nextStock, body.Location, body.MenuItemID,
	)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "failed to update inventory"})
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"message":      "inventory updated",
		"menu_item_id": body.MenuItemID,
		"previous":     currentStock,
		"stock":        nextStock,
		"location":     body.Location,
		"reason":       body.Reason,
		"updated_by":   claims.Email,
	})
}

// POST /api/kitchen/dispatch — V18: request smuggling simulation
func DispatchKitchenTicket(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if !ensureAdvancedVulnsEnabled(w) {
		return
	}
	if !allowLabRequest(w, r, "dispatch_smuggling", 10, time.Minute) {
		return
	}

	body, _ := io.ReadAll(io.LimitReader(r.Body, 8<<10))
	response := map[string]interface{}{
		"message":                 "kitchen dispatch queued",
		"frontend_interpretation": "single_request",
		"backend_interpretation":  "single_request",
		"bytes_received":          len(body),
	}

	transferEncoding := strings.ToLower(r.Header.Get("Transfer-Encoding"))
	contentLength := r.Header.Get("Content-Length")
	if transferEncoding != "" && contentLength != "" {
		response["frontend_interpretation"] = "content_length"
		response["backend_interpretation"] = "transfer_encoding"
		response["desync"] = true

		if idx := bytes.Index(body, []byte(requestSmugglingBoundary)); idx >= 0 {
			tail := strings.TrimSpace(string(body[idx+len(requestSmugglingBoundary):]))
			method, path := parseEmbeddedRequestLine(tail)
			if path != "" {
				response["smuggled_request"] = map[string]string{
					"method": method,
					"path":   path,
				}
				if preview := smuggledResponsePreview(path); preview != nil {
					response["smuggled_response_preview"] = preview
				}
			}
		}
	}

	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(response)
}

func readInventorySnapshot() ([]map[string]interface{}, error) {
	rows, err := db.DB.Query(`
		SELECT i.menu_item_id, m.name, i.stock, i.location, i.updated_at
		FROM inventory i
		JOIN menu_items m ON i.menu_item_id = m.id
		ORDER BY i.menu_item_id
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var inventory []map[string]interface{}
	for rows.Next() {
		var (
			menuItemID int
			name       string
			stock      int
			location   string
			updatedAt  string
		)
		rows.Scan(&menuItemID, &name, &stock, &location, &updatedAt)
		inventory = append(inventory, map[string]interface{}{
			"menu_item_id": menuItemID,
			"name":         name,
			"stock":        stock,
			"location":     location,
			"updated_at":   updatedAt,
		})
	}
	if inventory == nil {
		inventory = []map[string]interface{}{}
	}
	return inventory, nil
}

func issueLabJWT(claims labJWTClaims) (string, error) {
	header := map[string]string{
		"alg": "HS256",
		"typ": "JWT",
	}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	headerSegment := encodeJWTPart(headerJSON)
	payloadSegment := encodeJWTPart(payloadJSON)
	signature := signJWT(headerSegment, payloadSegment, legacyKitchenJWTSecret)
	return headerSegment + "." + payloadSegment + "." + signature, nil
}

func parseLabJWTFromRequest(r *http.Request) (labJWTClaims, map[string]interface{}, error) {
	raw := strings.TrimSpace(r.Header.Get("Authorization"))
	if strings.HasPrefix(strings.ToLower(raw), "bearer ") {
		raw = strings.TrimSpace(raw[7:])
	}
	if raw == "" {
		raw = r.URL.Query().Get("token")
	}
	return parseLabJWT(raw)
}

func parseLabJWT(token string) (labJWTClaims, map[string]interface{}, error) {
	var claims labJWTClaims
	if token == "" {
		return claims, nil, fmt.Errorf("token required")
	}

	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return claims, nil, fmt.Errorf("invalid token format")
	}

	headerBytes, err := decodeJWTPart(parts[0])
	if err != nil {
		return claims, nil, err
	}
	payloadBytes, err := decodeJWTPart(parts[1])
	if err != nil {
		return claims, nil, err
	}

	var header map[string]interface{}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return claims, nil, err
	}
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return claims, nil, err
	}

	alg, _ := header["alg"].(string)
	// V20 — accepts alg=none, treats RS256/HS256 interchangeably via shared secret,
	// and skips exp/iss/aud validation entirely.
	if strings.EqualFold(alg, "none") || len(parts) == 2 || parts[2] == "" {
		return claims, header, nil
	}

	expectedSig := signJWT(parts[0], parts[1], legacyKitchenJWTSecret)
	if hmac.Equal([]byte(expectedSig), []byte(parts[2])) {
		return claims, header, nil
	}
	return claims, nil, fmt.Errorf("signature verification failed")
}

func encodeJWTPart(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func decodeJWTPart(part string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(part)
}

func signJWT(headerPart, payloadPart, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(headerPart + "." + payloadPart))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func parseEmbeddedRequestLine(raw string) (string, string) {
	lines := strings.Split(raw, "\n")
	if len(lines) == 0 {
		return "", ""
	}
	firstLine := strings.Fields(strings.TrimSpace(lines[0]))
	if len(firstLine) < 2 {
		return "", ""
	}
	return firstLine[0], firstLine[1]
}

func smuggledResponsePreview(path string) map[string]interface{} {
	switch {
	case strings.HasPrefix(path, "/admin/users"):
		var count int
		db.DB.QueryRow("SELECT COUNT(*) FROM users").Scan(&count)
		return map[string]interface{}{
			"effect":     "backend would dispatch an internal admin user listing request",
			"user_count": count,
		}
	case strings.HasPrefix(path, "/api/debug/info"):
		return map[string]interface{}{
			"effect":      "backend would reach the debug handler with sensitive runtime data",
			"environment": config.Get().Environment,
			"version":     config.AppVersion,
		}
	default:
		return map[string]interface{}{
			"effect": "backend would enqueue the hidden request for the next hop",
		}
	}
}

func allowLabRequest(w http.ResponseWriter, r *http.Request, bucket string, limit int, window time.Duration) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	key := bucket + ":" + host
	now := time.Now()

	labRateLimitMu.Lock()
	defer labRateLimitMu.Unlock()

	var recent []time.Time
	for _, ts := range labRateLimitBuckets[key] {
		if now.Sub(ts) <= window {
			recent = append(recent, ts)
		}
	}
	if len(recent) >= limit {
		w.WriteHeader(http.StatusTooManyRequests)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "lab endpoint rate limit exceeded",
		})
		labRateLimitBuckets[key] = recent
		return false
	}

	labRateLimitBuckets[key] = append(recent, now)
	return true
}
