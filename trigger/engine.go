// Package trigger implements a payload-agnostic vulnerability detection engine.
// It loads vulnerability definitions from vulns.json, pre-compiles all regex
// patterns at startup, and evaluates request/response snapshots against
// configurable detection strategies (pattern_match, response_body_match,
// status_code, timing_anomaly, field_presence, error_signature).
//
// The legacy "trigger" string in vulns.json is preserved for backward
// compatibility. The new "triggers" array adds pattern-based detection on top.
package trigger

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"regexp"
	"sync"
	"time"
)

// ─── Schema types ─────────────────────────────────────────────────────────────

// VulnDef represents a single vulnerability entry from vulns.json.
// The "trigger" field (singular) is the legacy hardcoded payload string.
// The "triggers" field (plural) is the new array of detection strategy objects.
type VulnDef struct {
	ID             string         `json:"id"`
	Category       string         `json:"category,omitempty"`
	Type           string         `json:"type"`
	CWE            string         `json:"cwe"`
	OWASP          string         `json:"owasp"`
	Endpoint       string         `json:"endpoint"`
	Param          string         `json:"param"`
	Flow           string         `json:"flow,omitempty"`
	FeatureFlag    string         `json:"feature_flag,omitempty"`
	LabOnly        bool           `json:"lab_only,omitempty"`
	DetectionHints []string       `json:"detection_hints,omitempty"`
	Trigger        string         `json:"trigger"`            // legacy: hardcoded example payload
	Triggers       []TriggerEntry `json:"triggers,omitempty"` // new: pattern-based strategies
	Validation     string         `json:"validation"`
	Severity       string         `json:"severity"`
}

// TriggerEntry defines a single detection strategy for a vulnerability.
// Only the fields relevant to the chosen Strategy need to be populated.
type TriggerEntry struct {
	// Strategy is the detection method: pattern_match | response_body_match |
	// status_code | timing_anomaly | field_presence | error_signature | response_diff
	Strategy string `json:"strategy"`

	// Description explains what this heuristic detects (included in match output).
	Description string `json:"description"`

	// HeuristicName is a stable identifier included in match logs and API responses.
	HeuristicName string `json:"heuristic_name"`

	// Target specifies where pattern_match applies:
	// "request.url" | "request.body" | "request.headers" | "request.method"
	Target string `json:"target,omitempty"`

	// Pattern is a Go-compatible regex for pattern_match, response_body_match, error_signature.
	Pattern string `json:"pattern,omitempty"`

	// HeaderName restricts pattern_match (target=request.headers) to a single header.
	HeaderName string `json:"header_name,omitempty"`

	// Fields lists JSON keys to check in the response body (field_presence strategy).
	Fields []string `json:"fields,omitempty"`

	// StatusCodes lists HTTP status codes to match (status_code strategy).
	StatusCodes []int `json:"status_codes,omitempty"`

	// Negate inverts the match result (e.g., "confirm 429 never appears" for rate-limit checks).
	Negate bool `json:"negate,omitempty"`

	// ThresholdMs is the timing threshold in milliseconds (timing_anomaly strategy).
	// Defaults to timingAnomalyThresholdMs if not set.
	ThresholdMs int `json:"threshold_ms,omitempty"`

	// compiled is the pre-compiled regex pattern. Not serialised to JSON.
	compiled *regexp.Regexp
}

// ─── Evaluation types ─────────────────────────────────────────────────────────

// ReqSnapshot is a point-in-time snapshot of an HTTP request.
type ReqSnapshot struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
}

// RespSnapshot is a point-in-time snapshot of an HTTP response.
type RespSnapshot struct {
	Status     int    `json:"status"`
	Body       string `json:"body"`
	DurationMs int    `json:"duration_ms"`
}

// EvalInput is the body accepted by POST /api/trigger/evaluate.
type EvalInput struct {
	VulnID   string       `json:"vuln_id"`
	Request  ReqSnapshot  `json:"request"`
	Response RespSnapshot `json:"response"`
}

// MatchResult describes a single heuristic that fired during evaluation.
type MatchResult struct {
	Strategy      string `json:"strategy"`
	HeuristicName string `json:"heuristic_name"`
	Description   string `json:"description"`
}

// EvalResult is the response returned by POST /api/trigger/evaluate.
type EvalResult struct {
	VulnID      string        `json:"vuln_id"`
	Matched     bool          `json:"matched"`
	Matches     []MatchResult `json:"matches"`
	EvaluatedAt string        `json:"evaluated_at"`
}

// ─── Global state ─────────────────────────────────────────────────────────────

var (
	mu      sync.RWMutex
	vulnsDB []VulnDef
)

// ─── Public API ───────────────────────────────────────────────────────────────

// LoadVulns reads the vulns.json file at path, validates every TriggerEntry,
// and pre-compiles all regex patterns. It is intended to be called once at
// application startup. Any misconfiguration (bad regex, unknown strategy, etc.)
// is treated as a fatal error — fail-fast before the server accepts traffic.
func LoadVulns(path string) []VulnDef {
	data, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("[trigger] cannot read %s: %v", path, err)
	}

	var defs []VulnDef
	if err := json.Unmarshal(data, &defs); err != nil {
		log.Fatalf("[trigger] cannot parse %s: %v", path, err)
	}

	for i := range defs {
		for j := range defs[i].Triggers {
			entry := &defs[i].Triggers[j]

			if err := ValidateEntry(entry); err != nil {
				log.Fatalf("[trigger] invalid entry %s/%s: %v",
					defs[i].ID, entry.HeuristicName, err)
			}

			if entry.Pattern != "" {
				compiled, err := regexp.Compile(entry.Pattern)
				if err != nil {
					log.Fatalf("[trigger] bad regex in %s/%s: %v",
						defs[i].ID, entry.HeuristicName, err)
				}
				entry.compiled = compiled
			}
		}
	}

	mu.Lock()
	vulnsDB = defs
	mu.Unlock()

	log.Printf("[trigger] loaded %d vulnerability definitions from %s", len(defs), path)
	return defs
}

// GetVulns returns all loaded VulnDef entries (thread-safe read).
func GetVulns() []VulnDef {
	mu.RLock()
	defer mu.RUnlock()
	return vulnsDB
}

// GetVulnByID looks up a single VulnDef by its ID (e.g., "V01").
func GetVulnByID(id string) (VulnDef, bool) {
	mu.RLock()
	defer mu.RUnlock()
	for _, v := range vulnsDB {
		if v.ID == id {
			return v, true
		}
	}
	return VulnDef{}, false
}

// Evaluate runs every TriggerEntry strategy for def against the given request/
// response snapshot. Any strategy that fires is included in EvalResult.Matches.
// All matches are logged with the heuristic name for audit purposes.
func Evaluate(input EvalInput, def VulnDef) EvalResult {
	return evaluate(input, def, true)
}

// EvaluateQuiet is identical to Evaluate but suppresses per-match logs.
func EvaluateQuiet(input EvalInput, def VulnDef) EvalResult {
	return evaluate(input, def, false)
}

func evaluate(input EvalInput, def VulnDef, emitLogs bool) EvalResult {
	result := EvalResult{
		VulnID:      def.ID,
		Matches:     []MatchResult{},
		EvaluatedAt: time.Now().UTC().Format(time.RFC3339),
	}

	for _, entry := range def.Triggers {
		matched, err := dispatchStrategy(entry, input)
		if err != nil {
			log.Printf("[trigger] strategy error %s/%s: %v",
				def.ID, entry.HeuristicName, err)
			continue
		}
		if matched {
			if emitLogs {
				log.Printf("[trigger] MATCH vuln=%s strategy=%s heuristic=%s",
					def.ID, entry.Strategy, entry.HeuristicName)
			}
			result.Matches = append(result.Matches, MatchResult{
				Strategy:      entry.Strategy,
				HeuristicName: entry.HeuristicName,
				Description:   entry.Description,
			})
		}
	}

	result.Matched = len(result.Matches) > 0
	return result
}

// dispatchStrategy routes a TriggerEntry to the appropriate strategy function.
func dispatchStrategy(entry TriggerEntry, input EvalInput) (bool, error) {
	switch entry.Strategy {
	case "pattern_match":
		return runPatternMatch(entry, input)
	case "response_body_match":
		return runResponseBodyMatch(entry, input)
	case "status_code":
		return runStatusCode(entry, input)
	case "timing_anomaly":
		return runTimingAnomaly(entry, input)
	case "field_presence":
		return runFieldPresence(entry, input)
	case "error_signature":
		return runErrorSignature(entry, input)
	case "response_diff":
		// TODO: requires baseline + attack request pair; deferred to future iteration
		return false, nil
	default:
		return false, fmt.Errorf("unknown strategy %q", entry.Strategy)
	}
}
