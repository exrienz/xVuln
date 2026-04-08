package handlers

import (
	"encoding/json"
	"net/http"
	"xvulnv2/trigger"
)

// GET /api/vulns
// Returns all vulnerability definitions loaded from vulns.json, including
// both the legacy "trigger" string and the new "triggers" detection arrays.
// No authentication required (consistent with lab design; see also V09).
func GetVulns(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	vulns := trigger.GetVulns()
	json.NewEncoder(w).Encode(vulns)
}

// POST /api/trigger/evaluate
// Accepts a request/response snapshot and a vuln_id, runs every configured
// detection strategy against the snapshot, and returns which heuristics fired.
//
// If the vulnerability has no "triggers" array (legacy-only entry), the response
// includes the legacy trigger string so the caller can perform manual comparison.
//
// No authentication required — open endpoint intended for scanner integration.
func EvaluateTrigger(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var input trigger.EvalInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid request body"})
		return
	}

	if input.VulnID == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "vuln_id is required"})
		return
	}

	def, ok := trigger.GetVulnByID(input.VulnID)
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "vulnerability not found: " + input.VulnID,
		})
		return
	}

	// Legacy fallback: if no triggers array is configured, return the legacy trigger
	// string so callers can fall back to manual string-matching workflows.
	if len(def.Triggers) == 0 {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"vuln_id":        def.ID,
			"matched":        false,
			"matches":        []interface{}{},
			"note":           "no pattern triggers configured; use legacy trigger string for manual verification",
			"legacy_trigger": def.Trigger,
		})
		return
	}

	result := trigger.Evaluate(input, def)
	json.NewEncoder(w).Encode(result)
}
