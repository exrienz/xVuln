package config

import (
	"os"
)

const (
	AppVersion        = "1.7.0"
	DefaultSessionKey = "lab-session-key-change-me"
	LabAdminToken     = "lab-admin-bypass-token"
)

type Config struct {
	BackendPort  string
	FrontendPort string
	DBPath       string
	SessionKey   string
	LogPath      string
	Environment  string
	// TriggerEngine controls which vulnerability detection engine is active.
	// "legacy"  — use only the old hardcoded trigger strings (no pattern evaluation)
	// "pattern" — use only the new regex/heuristic engine
	// "both"    — run pattern engine; fall back to legacy on no match (default)
	TriggerEngine string
	// AllowRemoteReset when true disables the localhost-only guard on /api/reset.
	// Set ALLOW_REMOTE_RESET=true in trusted environments that need remote resets.
	AllowRemoteReset bool
	// EnableAdvancedVulns gates the advanced lab scenarios introduced in v1.7.0.
	// It defaults to true for lab/staging and false for production.
	EnableAdvancedVulns bool
}

var current *Config

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
		sessionKey = DefaultSessionKey
	}
	logPath := os.Getenv("LOG_PATH")
	if logPath == "" {
		logPath = "./logs/requests.log"
	}
	environment := os.Getenv("APP_ENV")
	if environment == "" {
		environment = "lab"
	}
	triggerEngine := os.Getenv("TRIGGER_ENGINE")
	if triggerEngine == "" {
		triggerEngine = "both"
	}
	allowRemoteReset := os.Getenv("ALLOW_REMOTE_RESET") == "true"
	enableAdvancedVulns := os.Getenv("ENABLE_ADVANCED_VULNS")
	advancedVulnsEnabled := environment != "production"
	if enableAdvancedVulns != "" {
		advancedVulnsEnabled = enableAdvancedVulns == "true"
	}

	current = &Config{
		BackendPort:         backendPort,
		FrontendPort:        frontendPort,
		DBPath:              dbPath,
		SessionKey:          sessionKey,
		LogPath:             logPath,
		Environment:         environment,
		TriggerEngine:       triggerEngine,
		AllowRemoteReset:    allowRemoteReset,
		EnableAdvancedVulns: advancedVulnsEnabled,
	}
	return current
}

func Get() *Config {
	if current == nil {
		return Load()
	}
	return current
}
