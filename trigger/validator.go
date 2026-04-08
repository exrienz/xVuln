package trigger

import (
	"fmt"
	"regexp"
)

// maxPatternLen caps regex pattern length to mitigate ReDoS risk.
// Patterns longer than this are rejected at startup.
const maxPatternLen = 500

// validStrategies is the set of recognised detection strategy names.
var validStrategies = map[string]bool{
	"pattern_match":       true,
	"response_body_match": true,
	"status_code":         true,
	"timing_anomaly":      true,
	"field_presence":      true,
	"error_signature":     true,
	"response_diff":       true, // stub — no-op until two-request diffing is implemented
}

// validTargets is the set of recognised targets for the pattern_match strategy.
var validTargets = map[string]bool{
	"request.url":     true,
	"request.body":    true,
	"request.headers": true,
	"request.method":  true,
}

// ValidateEntry checks a TriggerEntry for schema correctness before the
// application starts serving traffic. It does NOT compile the regex — that is
// done by LoadVulns after validation passes.
//
// Rules enforced:
//   - heuristic_name must be non-empty
//   - strategy must be a known value
//   - strategy-specific required fields must be present
//   - regex patterns must be syntactically valid and within maxPatternLen
//   - HTTP status codes must be in the range 100–599
func ValidateEntry(e *TriggerEntry) error {
	if e.HeuristicName == "" {
		return fmt.Errorf("heuristic_name is required")
	}
	if !validStrategies[e.Strategy] {
		return fmt.Errorf("unknown strategy %q", e.Strategy)
	}

	switch e.Strategy {
	case "pattern_match":
		if e.Pattern == "" {
			return fmt.Errorf("pattern_match requires a non-empty pattern")
		}
		if e.Target == "" {
			return fmt.Errorf("pattern_match requires a target")
		}
		if !validTargets[e.Target] {
			return fmt.Errorf("invalid target %q; valid: request.url, request.body, request.headers, request.method", e.Target)
		}
		if err := validateRegex(e.Pattern); err != nil {
			return err
		}

	case "response_body_match", "error_signature":
		if e.Pattern == "" {
			return fmt.Errorf("%s requires a non-empty pattern", e.Strategy)
		}
		if err := validateRegex(e.Pattern); err != nil {
			return err
		}

	case "status_code":
		if len(e.StatusCodes) == 0 {
			return fmt.Errorf("status_code requires at least one value in status_codes")
		}
		for _, code := range e.StatusCodes {
			if code < 100 || code > 599 {
				return fmt.Errorf("invalid HTTP status code %d", code)
			}
		}

	case "field_presence":
		if len(e.Fields) == 0 {
			return fmt.Errorf("field_presence requires at least one value in fields")
		}

	case "timing_anomaly":
		// threshold_ms is optional; runtime default applied in strategies.go

	case "response_diff":
		// Stub — no validation required until implemented
	}

	return nil
}

// validateRegex checks that pattern is syntactically valid and short enough
// to be considered safe from catastrophic backtracking (ReDoS).
func validateRegex(pattern string) error {
	if len(pattern) > maxPatternLen {
		return fmt.Errorf("pattern length %d exceeds limit %d (ReDoS mitigation)",
			len(pattern), maxPatternLen)
	}
	if _, err := regexp.Compile(pattern); err != nil {
		return fmt.Errorf("invalid regex: %v", err)
	}
	return nil
}
