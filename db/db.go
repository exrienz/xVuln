package db

import (
	"database/sql"
	"log"
	"strings"

	_ "github.com/mattn/go-sqlite3"
)

var DB *sql.DB

func Init(path string) {
	var err error
	DB, err = sql.Open("sqlite3", path+"?_journal_mode=WAL&_foreign_keys=on")
	if err != nil {
		log.Fatalf("failed to open database: %v", err)
	}
	if err = DB.Ping(); err != nil {
		log.Fatalf("failed to ping database: %v", err)
	}
	migrate()
}

func migrate() {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT NOT NULL UNIQUE,
			email TEXT NOT NULL UNIQUE,
			password TEXT NOT NULL,
			role TEXT NOT NULL DEFAULT 'user',
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS menu_items (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			description TEXT,
			price REAL NOT NULL,
			category TEXT NOT NULL,
			image_url TEXT,
			available INTEGER NOT NULL DEFAULT 1
		)`,
		`CREATE TABLE IF NOT EXISTS orders (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			total REAL NOT NULL,
			status TEXT NOT NULL DEFAULT 'pending',
			note TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES users(id)
		)`,
		`CREATE TABLE IF NOT EXISTS order_items (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			order_id INTEGER NOT NULL,
			menu_item_id INTEGER NOT NULL,
			quantity INTEGER NOT NULL DEFAULT 1,
			price REAL NOT NULL,
			FOREIGN KEY (order_id) REFERENCES orders(id),
			FOREIGN KEY (menu_item_id) REFERENCES menu_items(id)
		)`,
		`CREATE TABLE IF NOT EXISTS inventory (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			menu_item_id INTEGER NOT NULL UNIQUE,
			stock INTEGER NOT NULL DEFAULT 0,
			location TEXT NOT NULL DEFAULT 'main-kitchen',
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (menu_item_id) REFERENCES menu_items(id)
		)`,
		`CREATE TABLE IF NOT EXISTS reviews (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			menu_item_id INTEGER NOT NULL,
			rating INTEGER NOT NULL,
			comment TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES users(id),
			FOREIGN KEY (menu_item_id) REFERENCES menu_items(id)
		)`,
		`CREATE TABLE IF NOT EXISTS request_logs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			method TEXT,
			path TEXT,
			query TEXT,
			body TEXT,
			request_headers TEXT NOT NULL DEFAULT '{}',
			route TEXT,
			status INTEGER,
			response_size INTEGER,
			response_body TEXT NOT NULL DEFAULT '',
			duration_ms INTEGER NOT NULL DEFAULT 0,
			scanner_id TEXT,
			ip TEXT,
			user_agent TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS files (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			path TEXT NOT NULL,
			uploaded_by INTEGER,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS scan_sessions (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			scanner_id TEXT NOT NULL UNIQUE,
			status TEXT NOT NULL DEFAULT 'active',
			started_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			completed_at DATETIME
		)`,
	}

	for _, stmt := range stmts {
		if _, err := DB.Exec(stmt); err != nil {
			log.Fatalf("migration error: %v\nStatement: %s", err, stmt)
		}
	}

	ensureOptionalColumn("request_logs", "request_headers", "TEXT NOT NULL DEFAULT '{}'")
	ensureOptionalColumn("request_logs", "route", "TEXT")
	ensureOptionalColumn("request_logs", "response_body", "TEXT NOT NULL DEFAULT ''")
	ensureOptionalColumn("request_logs", "duration_ms", "INTEGER NOT NULL DEFAULT 0")
}

func ensureOptionalColumn(table, column, definition string) {
	stmt := "ALTER TABLE " + table + " ADD COLUMN " + column + " " + definition
	if _, err := DB.Exec(stmt); err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
			return
		}
		log.Fatalf("migration error adding column %s.%s: %v", table, column, err)
	}
}

func Reset() {
	tables := []string{"order_items", "orders", "reviews", "inventory", "menu_items", "users", "request_logs", "files", "scan_sessions"}
	for _, t := range tables {
		if _, err := DB.Exec("DELETE FROM " + t); err != nil {
			log.Printf("reset error on table %s: %v", t, err)
		}
		DB.Exec("DELETE FROM sqlite_sequence WHERE name=?", t)
	}
	Seed()
}
