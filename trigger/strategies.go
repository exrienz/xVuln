package trigger

import (
	"encoding/json"
	"fmt"
	"strings"
)

// timingAnomalyThresholdMs is the default response time (ms) above which
// a timing_anomaly fires. Covers most sleep()-based blind injection payloads.
const timingAnomalyThresholdMs = 2000

// ─── Strategy implementations ─────────────────────────────────────────────────

// runPatternMatch applies entry.compiled against a region of the request.
// Supported targets: "request.url", "request.body", "request.headers", "request.method".
func runPatternMatch(entry TriggerEntry, input EvalInput) (bool, error) {
	if entry.compiled == nil {
		return false, fmt.Errorf("pattern_match missing compiled regex")
	}

	var target string
	switch entry.Target {
	case "request.url":
		target = input.Request.URL
	case "request.body":
		target = input.Request.Body
	case "request.headers":
		if entry.HeaderName != "" {
			// Case-insensitive header lookup
			target = headerValue(input.Request.Headers, entry.HeaderName)
		} else {
			// Concatenate all headers as "Key: Value\n" for broad matching
			var sb strings.Builder
			for k, v := range input.Request.Headers {
				sb.WriteString(k)
				sb.WriteString(": ")
				sb.WriteString(v)
				sb.WriteString("\n")
			}
			target = sb.String()
		}
	case "request.method":
		target = input.Request.Method
	default:
		return false, fmt.Errorf("invalid target %q for pattern_match", entry.Target)
	}

	matched := entry.compiled.MatchString(target)
	if entry.Negate {
		return !matched, nil
	}
	return matched, nil
}

// runResponseBodyMatch applies entry.compiled against the response body.
func runResponseBodyMatch(entry TriggerEntry, input EvalInput) (bool, error) {
	if entry.compiled == nil {
		return false, fmt.Errorf("response_body_match missing compiled regex")
	}
	matched := entry.compiled.MatchString(input.Response.Body)
	if entry.Negate {
		return !matched, nil
	}
	return matched, nil
}

// runStatusCode checks whether the response status code is (or is not, if
// Negate=true) in the entry's StatusCodes list.
// Use Negate=true to detect the *absence* of a code (e.g., 429 never appeared).
func runStatusCode(entry TriggerEntry, input EvalInput) (bool, error) {
	inList := false
	for _, code := range entry.StatusCodes {
		if input.Response.Status == code {
			inList = true
			break
		}
	}
	if entry.Negate {
		return !inList, nil
	}
	return inList, nil
}

// runTimingAnomaly fires when response time meets or exceeds the threshold.
// Uses entry.ThresholdMs if set, otherwise falls back to timingAnomalyThresholdMs.
func runTimingAnomaly(entry TriggerEntry, input EvalInput) (bool, error) {
	threshold := entry.ThresholdMs
	if threshold <= 0 {
		threshold = timingAnomalyThresholdMs
	}
	matched := input.Response.DurationMs >= threshold
	if entry.Negate {
		return !matched, nil
	}
	return matched, nil
}

// runFieldPresence checks for the presence of any of entry.Fields as a key
// at any depth in the JSON response body. Falls back to substring search for
// non-JSON responses.
func runFieldPresence(entry TriggerEntry, input EvalInput) (bool, error) {
	if len(entry.Fields) == 0 {
		return false, fmt.Errorf("field_presence requires at least one field")
	}

	body := input.Response.Body

	// Try JSON parsing first
	var parsed interface{}
	if err := json.Unmarshal([]byte(body), &parsed); err == nil {
		for _, field := range entry.Fields {
			if deepContainsKey(parsed, field) {
				if entry.Negate {
					return false, nil
				}
				return true, nil
			}
		}
		if entry.Negate {
			return true, nil
		}
		return false, nil
	}

	// Non-JSON fallback: plain string search for `"fieldname"`
	for _, field := range entry.Fields {
		if strings.Contains(body, `"`+field+`"`) {
			if entry.Negate {
				return false, nil
			}
			return true, nil
		}
	}
	if entry.Negate {
		return true, nil
	}
	return false, nil
}

// runErrorSignature applies entry.compiled against the response body.
// Intended for matching known database and server error strings that
// indicate injection vulnerabilities.
func runErrorSignature(entry TriggerEntry, input EvalInput) (bool, error) {
	if entry.compiled == nil {
		return false, fmt.Errorf("error_signature missing compiled regex")
	}
	matched := entry.compiled.MatchString(input.Response.Body)
	if entry.Negate {
		return !matched, nil
	}
	return matched, nil
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

// deepContainsKey recursively searches for a key in an unmarshalled JSON value.
func deepContainsKey(v interface{}, key string) bool {
	switch val := v.(type) {
	case map[string]interface{}:
		if _, ok := val[key]; ok {
			return true
		}
		for _, child := range val {
			if deepContainsKey(child, key) {
				return true
			}
		}
	case []interface{}:
		for _, item := range val {
			if deepContainsKey(item, key) {
				return true
			}
		}
	}
	return false
}

// headerValue retrieves a header value with case-insensitive key matching.
func headerValue(headers map[string]string, name string) string {
	nameLower := strings.ToLower(name)
	for k, v := range headers {
		if strings.ToLower(k) == nameLower {
			return v
		}
	}
	return ""
}
