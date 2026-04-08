package config

import (
	"os"
)

type Config struct {
	BackendPort   string
	FrontendPort  string
	DBPath        string
	SessionKey    string
	LogPath       string
	// TriggerEngine controls which vulnerability detection engine is active.
	// "legacy"  — use only the old hardcoded trigger strings (no pattern evaluation)
	// "pattern" — use only the new regex/heuristic engine
	// "both"    — run pattern engine; fall back to legacy on no match (default)
	TriggerEngine string
	// AllowRemoteReset when true disables the localhost-only guard on /api/reset.
	// Set ALLOW_REMOTE_RESET=true in trusted environments that need remote resets.
	AllowRemoteReset bool
}

func Load() *Config {
	backendPort := os.Getenv("BACKEND_PORT")
	if backendPort == "" {
		backendPort = "4443"
	}
	frontendPort := os.Getenv("FRONTEND_PORT")
	if frontendPort == "" {
		frontendPort = "4444"
	}
	dbPath := os.Getenv("DB_PATH")
	if dbPath == "" {
		dbPath = "./restaurant.db"
	}
	sessionKey := os.Getenv("SESSION_KEY")
	if sessionKey == "" {
		sessionKey = "restaurant-secret-key-2024"
	}
	logPath := os.Getenv("LOG_PATH")
	if logPath == "" {
		logPath = "./logs/requests.log"
	}
	triggerEngine := os.Getenv("TRIGGER_ENGINE")
	if triggerEngine == "" {
		triggerEngine = "both"
	}
	allowRemoteReset := os.Getenv("ALLOW_REMOTE_RESET") == "true"
	return &Config{
		BackendPort:      backendPort,
		FrontendPort:     frontendPort,
		DBPath:           dbPath,
		SessionKey:       sessionKey,
		LogPath:          logPath,
		TriggerEngine:    triggerEngine,
		AllowRemoteReset: allowRemoteReset,
	}
}
