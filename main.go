package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"xvulnv2/config"
	"xvulnv2/db"
	"xvulnv2/handlers"
	"xvulnv2/middleware"
	"xvulnv2/trigger"

	"github.com/gorilla/mux"
)

func main() {
	cfg := config.Load()

	// Ensure directories exist
	os.MkdirAll("./logs", 0755)
	os.MkdirAll("./uploads", 0755)
	os.MkdirAll("./recipes", 0755)
	os.MkdirAll("./static/uploads/menus", 0755)
	os.MkdirAll("./static/exports/tmp", 0755)

	// Create sample upload files for path traversal demo
	os.WriteFile("./uploads/menu_export.csv", []byte("id,name,price\n1,Margherita Pizza,14.99\n2,Pepperoni Feast,17.99\n"), 0644)
	os.WriteFile("./uploads/specials.txt", []byte("Today's Specials:\n- Chef's Tasting Menu: $89\n- Wine Pairing: $45\n"), 0644)
	os.WriteFile("./recipes/pasta.txt", []byte("Pasta Station Notes:\n- Finish with lemon zest\n- Hold truffle oil until pass\n"), 0644)
	os.WriteFile("./recipes/salmon.txt", []byte("Salmon Pass:\n- Fire skin side first\n- Butter baste for 90 seconds\n"), 0644)

	// Init database
	db.Init(cfg.DBPath)
	db.Seed()

	// Init sessions
	middleware.InitSession(cfg.SessionKey)

	// Init trigger engine — validates vulns.json schema and pre-compiles all
	// regex patterns. Panics on invalid configuration (fail-fast before traffic).
	trigger.LoadVulns("./vulns.json")
	log.Printf("[main] trigger engine mode: %s", cfg.TriggerEngine)

	// ─── Backend API Router (port 4443) ───────────────────────────────────────
	api := mux.NewRouter()
	api.Use(middleware.CORS)
	api.Use(middleware.Logger)

	// Auth
	api.HandleFunc("/register", handlers.Register).Methods("POST", "OPTIONS")
	api.HandleFunc("/login", handlers.Login).Methods("POST", "OPTIONS")
	api.HandleFunc("/logout", handlers.Logout).Methods("POST", "OPTIONS")
	api.HandleFunc("/api/me", handlers.Me).Methods("GET", "OPTIONS")

	// Menu
	api.HandleFunc("/api/menu", handlers.GetMenu).Methods("GET", "OPTIONS")
	api.HandleFunc("/api/menu/{id}", handlers.GetMenuItem).Methods("GET", "OPTIONS")
	api.HandleFunc("/api/menu/{id}", handlers.DeleteMenuItem).Methods("DELETE", "OPTIONS")
	api.HandleFunc("/api/search", handlers.SearchMenu).Methods("GET", "OPTIONS")

	// Orders
	api.HandleFunc("/api/orders/{id}/invoice/export", handlers.ExportInvoice).Methods("GET", "OPTIONS")
	api.HandleFunc("/api/orders", handlers.PlaceOrder).Methods("POST", "OPTIONS")
	api.HandleFunc("/api/orders/{id}", handlers.GetOrder).Methods("GET", "OPTIONS")
	api.HandleFunc("/api/user/orders", handlers.GetUserOrders).Methods("GET", "OPTIONS")

	// Reviews
	api.HandleFunc("/api/reviews", handlers.GetReviews).Methods("GET", "OPTIONS")
	api.HandleFunc("/api/reviews", handlers.PostReview).Methods("POST", "OPTIONS")
	api.HandleFunc("/api/reviews/{id}", handlers.GetReview).Methods("GET", "OPTIONS")

	// Import (SSRF)
	api.HandleFunc("/api/import-menu", handlers.ImportMenu).Methods("POST", "OPTIONS")

	// Profile (IDOR + sensitive data exposure + mass assignment)
	api.HandleFunc("/api/user/profile", handlers.GetProfile).Methods("GET", "OPTIONS")
	api.HandleFunc("/api/user/update", handlers.UpdateProfile).Methods("POST", "OPTIONS")

	// Admin (broken auth)
	api.HandleFunc("/admin/orders", handlers.AdminGetOrders).Methods("GET", "OPTIONS")
	api.HandleFunc("/admin/users", handlers.AdminGetUsers).Methods("GET", "OPTIONS")

	// Debug (security misconfiguration)
	api.HandleFunc("/api/debug/info", handlers.DebugInfo).Methods("GET", "OPTIONS")

	// Files (path traversal)
	api.HandleFunc("/api/files", handlers.GetFile).Methods("GET", "OPTIONS")

	// Advanced lab scenarios (enabled via APP_ENV/ENABLE_ADVANCED_VULNS)
	api.HandleFunc("/api/admin/menu/upload-image", handlers.UploadMenuImage).Methods("POST", "OPTIONS")
	api.HandleFunc("/api/kitchen/recipes/view", handlers.ViewRecipe).Methods("GET", "OPTIONS")
	api.HandleFunc("/api/staff/session", handlers.CreateStaffSession).Methods("POST", "OPTIONS")
	api.HandleFunc("/api/staff/panel", handlers.GetStaffPanel).Methods("GET", "OPTIONS")
	api.HandleFunc("/api/kitchen/inventory", handlers.GetKitchenInventory).Methods("GET", "OPTIONS")
	api.HandleFunc("/api/kitchen/inventory/adjust", handlers.AdjustKitchenInventory).Methods("POST", "OPTIONS")
	api.HandleFunc("/api/kitchen/dispatch", handlers.DispatchKitchenTicket).Methods("POST", "OPTIONS")

	// Cart (insecure deserialization)
	api.HandleFunc("/api/cart", handlers.GetCart).Methods("GET", "OPTIONS")
	api.HandleFunc("/api/cart/restore", handlers.RestoreCart).Methods("POST", "OPTIONS")

	// Benchmark reset — protected: localhost-only unless ALLOW_REMOTE_RESET=true
	if cfg.AllowRemoteReset {
		api.HandleFunc("/api/reset", handlers.Reset).Methods("POST", "OPTIONS")
	} else {
		api.Handle("/api/reset", middleware.LocalhostOnly(http.HandlerFunc(handlers.Reset))).Methods("POST", "OPTIONS")
	}

	// Trigger engine stays internal to the benchmark harness and is not exposed
	// on the public HTTP surface. This prevents generic crawlers from discovering
	// scoring helpers as application endpoints.

	// ─── Frontend Static Server (port 4444) ───────────────────────────────────
	fe := mux.NewRouter()
	fe.Use(middleware.ConsoleLogger("frontend"))
	fe.PathPrefix("/static/").Handler(
		http.StripPrefix("/static/", http.FileServer(http.Dir("./static"))),
	)
	// Serve index.html for all SPA routes
	fe.PathPrefix("/").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "./static/index.html")
	})

	backendAddr := ":" + cfg.BackendPort
	frontendAddr := ":" + cfg.FrontendPort

	fmt.Println("🍽️  The Local Plate — Restaurant App")
	fmt.Printf("   Frontend  →  http://localhost:%s\n", cfg.FrontendPort)
	fmt.Printf("   Backend   →  http://localhost:%s\n", cfg.BackendPort)
	fmt.Printf("   Version   →  %s (%s, advanced_vulns=%t)\n\n", config.AppVersion, cfg.Environment, cfg.EnableAdvancedVulns)

	// Start backend in background goroutine
	go func() {
		log.Printf("[backend] listening on %s", backendAddr)
		if err := http.ListenAndServe(backendAddr, api); err != nil {
			log.Fatalf("backend error: %v", err)
		}
	}()

	// Start frontend (blocking)
	log.Printf("[frontend] listening on %s", frontendAddr)
	log.Fatal(http.ListenAndServe(frontendAddr, fe))
}
