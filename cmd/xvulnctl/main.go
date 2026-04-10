// xvulnctl is a CLI tool for managing xVulnv2 benchmark operations.
// It operates directly on the SQLite database.
package main

import (
	"database/sql"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"xvulnv2/db"
	"xvulnv2/trigger"

	_ "github.com/mattn/go-sqlite3"
)

//go:embed report_template.html
var reportFS embed.FS

var scannerIDRegex = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	dbPath := os.Getenv("DB_PATH")
	if dbPath == "" {
		dbPath = "./restaurant.db"
	}
	db.Init(dbPath)

	switch os.Args[1] {
	case "reset":
		cmdReset()
	case "scan":
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "Usage: xvulnctl scan <start|stop> --scanner=ID")
			os.Exit(1)
		}
		switch os.Args[2] {
		case "start":
			cmdScanStart()
		case "stop":
			cmdScanStop()
		default:
			fmt.Fprintf(os.Stderr, "Unknown scan subcommand: %s\n", os.Args[2])
			os.Exit(1)
		}
	case "report":
		if len(os.Args) < 3 || os.Args[2] != "generate" {
			fmt.Fprintln(os.Stderr, "Usage: xvulnctl report generate --scanner=ID")
			os.Exit(1)
		}
		cmdReportGenerate()
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`xvulnctl — xVulnv2 Benchmark CLI

Usage:
  xvulnctl reset                          Reset database to seed state
  xvulnctl scan start --scanner=ID        Start a new scan session
  xvulnctl scan stop  --scanner=ID        Stop an active scan session
  xvulnctl report generate --scanner=ID   Generate HTML benchmark report

Environment:
  DB_PATH    Path to SQLite database (default: ./restaurant.db)

Scanner ID must match: [a-zA-Z0-9_-]{1,64}`)
}

func extractFlag(name string) string {
	prefix := "--" + name + "="
	for _, arg := range os.Args {
		if strings.HasPrefix(arg, prefix) {
			return strings.TrimPrefix(arg, prefix)
		}
	}
	return ""
}

func validateScannerID(id string) {
	if id == "" {
		fmt.Fprintln(os.Stderr, "Error: --scanner=ID is required")
		os.Exit(1)
	}
	if !scannerIDRegex.MatchString(id) {
		fmt.Fprintf(os.Stderr, "Error: invalid scanner ID %q — must match [a-zA-Z0-9_-]{1,64}\n", id)
		os.Exit(1)
	}
}

func cmdReset() {
	db.Reset()
	fmt.Println("✅ Database reset to initial seed state")
}

func cmdScanStart() {
	scannerID := extractFlag("scanner")
	validateScannerID(scannerID)

	var existing string
	err := db.DB.QueryRow("SELECT status FROM scan_sessions WHERE scanner_id = ?", scannerID).Scan(&existing)
	if err == nil {
		if existing == "active" {
			fmt.Fprintf(os.Stderr, "Error: scan session %q is already active\n", scannerID)
			os.Exit(1)
		}
		db.DB.Exec("DELETE FROM scan_sessions WHERE scanner_id = ?", scannerID)
	}

	_, err = db.DB.Exec(
		"INSERT INTO scan_sessions (scanner_id, status, started_at) VALUES (?, 'active', ?)",
		scannerID, time.Now().UTC().Format(time.RFC3339),
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating scan session: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("🔍 Scan session started\n")
	fmt.Printf("   Scanner ID : %s\n", scannerID)
	fmt.Printf("   Started    : %s\n", time.Now().UTC().Format(time.RFC3339))
	fmt.Printf("\n   Tag requests with header:\n")
	fmt.Printf("     X-Scanner-ID: %s\n", scannerID)
	fmt.Printf("   or:\n")
	fmt.Printf("     X-Scan-Token: %s\n", scannerID)
}

func cmdScanStop() {
	scannerID := extractFlag("scanner")
	validateScannerID(scannerID)

	var status string
	err := db.DB.QueryRow("SELECT status FROM scan_sessions WHERE scanner_id = ?", scannerID).Scan(&status)
	if err == sql.ErrNoRows {
		fmt.Fprintf(os.Stderr, "Error: no scan session found for %q\n", scannerID)
		os.Exit(1)
	}
	if status == "completed" {
		fmt.Fprintf(os.Stderr, "Warning: scan session %q is already completed\n", scannerID)
		os.Exit(0)
	}

	now := time.Now().UTC().Format(time.RFC3339)
	_, err = db.DB.Exec(
		"UPDATE scan_sessions SET status = 'completed', completed_at = ? WHERE scanner_id = ?",
		now, scannerID,
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error stopping scan session: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("⏹️  Scan session stopped\n")
	fmt.Printf("   Scanner ID  : %s\n", scannerID)
	fmt.Printf("   Completed   : %s\n", now)
}

type ReportData struct {
	ScannerID         string
	StartedAt         string
	CompletedAt       string
	Duration          string
	GeneratedAt       string
	TotalRequests     int
	UniqueEndpoints   int
	VulnEndpointsHit  int
	AvgResponseSize   int
	RequestsPerSecond string
	Benchmark         BenchmarkScorecard
	MethodSegments    []MethodSegment
	StatusCodes       []StatusCodeEntry
	VulnCoverage      []VulnCoverageEntry
	TopEndpoints      []EndpointEntry
	RequestLogs       []RequestLogEntry
	LogSampleSize     int
}

type MethodSegment struct {
	Method  string
	Count   int
	Percent int
}

type StatusCodeEntry struct {
	Code  int
	Count int
	Class string
}

type VulnCoverageEntry struct {
	ID            string
	Type          string
	Endpoint      string
	Access        string
	Severity      string
	SeverityClass string
	ScoringMode   string
	RequestCount  int
	EvidenceCount int
	MatchCount    int
	Outcome       string
	OutcomeClass  string
}

type EndpointEntry struct {
	Path       string
	Count      int
	BarPercent int
}

type RequestLogEntry struct {
	Index  int
	Time   string
	Method string
	Path   string
	Query  string
	Status int
	Size   int
	IsVuln bool
}

type LoggedRequest struct {
	Method         string
	Path           string
	Query          string
	Body           string
	RequestHeaders string
	Route          string
	Status         int
	ResponseSize   int
	ResponseBody   string
	DurationMs     int
	CreatedAt      string
}

type BenchmarkScorecard struct {
	KnownFindings           int
	AutoConfirmableFindings int
	ContextRequiredFindings int
	ExercisedFindings       int
	ConfirmedFindings       int
	InconclusiveFindings    int
	NotExercisedFindings    int
	Coverage                string
	CandidateRequests       int
	ConfirmedRequests       int
	AutoDetectionLabel      string
}

func cmdReportGenerate() {
	scannerID := extractFlag("scanner")
	validateScannerID(scannerID)

	reportsDir := "./reports"
	os.MkdirAll(reportsDir, 0755)

	outPath := filepath.Join(reportsDir, scannerID+".html")
	absOut, _ := filepath.Abs(outPath)
	absReports, _ := filepath.Abs(reportsDir)
	if !strings.HasPrefix(absOut, absReports) {
		fmt.Fprintln(os.Stderr, "Error: path traversal detected in scanner ID")
		os.Exit(1)
	}

	var startedAt, completedAt sql.NullString
	err := db.DB.QueryRow(
		"SELECT started_at, completed_at FROM scan_sessions WHERE scanner_id = ?",
		scannerID,
	).Scan(&startedAt, &completedAt)

	startStr := "N/A"
	endStr := "N/A"
	if err == nil {
		if startedAt.Valid {
			startStr = startedAt.String
		}
		if completedAt.Valid {
			endStr = completedAt.String
		} else {
			now := time.Now().UTC().Format(time.RFC3339)
			db.DB.Exec("UPDATE scan_sessions SET status = 'completed', completed_at = ? WHERE scanner_id = ?", now, scannerID)
			endStr = now
		}
	}

	duration := "N/A"
	if startStr != "N/A" && endStr != "N/A" {
		tStart, e1 := time.Parse(time.RFC3339, startStr)
		tEnd, e2 := time.Parse(time.RFC3339, endStr)
		if e1 == nil && e2 == nil {
			duration = formatDuration(tEnd.Sub(tStart))
		}
	}

	rows, err := db.DB.Query(
		`SELECT method, path, query, body, COALESCE(request_headers, '{}'), COALESCE(route, ''), status, response_size, COALESCE(response_body, ''), COALESCE(duration_ms, 0), created_at
		 FROM request_logs
		 WHERE scanner_id = ?
		 ORDER BY id ASC`,
		scannerID,
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error querying request logs: %v\n", err)
		os.Exit(1)
	}
	defer rows.Close()

	var allLogs []LoggedRequest
	for rows.Next() {
		var r LoggedRequest
		if err := rows.Scan(
			&r.Method,
			&r.Path,
			&r.Query,
			&r.Body,
			&r.RequestHeaders,
			&r.Route,
			&r.Status,
			&r.ResponseSize,
			&r.ResponseBody,
			&r.DurationMs,
			&r.CreatedAt,
		); err != nil {
			fmt.Fprintf(os.Stderr, "Error scanning request logs: %v\n", err)
			os.Exit(1)
		}
		allLogs = append(allLogs, r)
	}

	totalRequests := len(allLogs)

	methodCounts := map[string]int{}
	statusCounts := map[int]int{}
	endpointCounts := map[string]int{}
	totalSize := 0
	for _, r := range allLogs {
		methodCounts[r.Method]++
		statusCounts[r.Status]++
		endpointCounts[r.Path]++
		totalSize += r.ResponseSize
	}

	var methodSegments []MethodSegment
	for method, count := range methodCounts {
		percent := 0
		if totalRequests > 0 {
			percent = int(math.Round(float64(count) / float64(totalRequests) * 100))
		}
		methodSegments = append(methodSegments, MethodSegment{Method: method, Count: count, Percent: percent})
	}
	sort.Slice(methodSegments, func(i, j int) bool {
		return methodSegments[i].Count > methodSegments[j].Count
	})

	var statusCodes []StatusCodeEntry
	for code, count := range statusCounts {
		class := "s2xx"
		if code >= 300 && code < 400 {
			class = "s3xx"
		} else if code >= 400 && code < 500 {
			class = "s4xx"
		} else if code >= 500 {
			class = "s5xx"
		}
		statusCodes = append(statusCodes, StatusCodeEntry{Code: code, Count: count, Class: class})
	}
	sort.Slice(statusCodes, func(i, j int) bool {
		return statusCodes[i].Code < statusCodes[j].Code
	})

	uniqueEndpoints := len(endpointCounts)
	avgSize := 0
	if totalRequests > 0 {
		avgSize = totalSize / totalRequests
	}

	type epCount struct {
		path  string
		count int
	}
	var sortedEP []epCount
	for path, count := range endpointCounts {
		sortedEP = append(sortedEP, epCount{path: path, count: count})
	}
	sort.Slice(sortedEP, func(i, j int) bool {
		return sortedEP[i].count > sortedEP[j].count
	})

	maxEP := 20
	if len(sortedEP) < maxEP {
		maxEP = len(sortedEP)
	}
	maxCount := 1
	if len(sortedEP) > 0 {
		maxCount = sortedEP[0].count
	}
	var topEndpoints []EndpointEntry
	for i := 0; i < maxEP; i++ {
		topEndpoints = append(topEndpoints, EndpointEntry{
			Path:       sortedEP[i].path,
			Count:      sortedEP[i].count,
			BarPercent: int(math.Round(float64(sortedEP[i].count) / float64(maxCount) * 100)),
		})
	}

	rps := "N/A"
	if totalRequests > 0 && startStr != "N/A" && endStr != "N/A" {
		tStart, e1 := time.Parse(time.RFC3339, startStr)
		tEnd, e2 := time.Parse(time.RFC3339, endStr)
		if e1 == nil && e2 == nil {
			seconds := tEnd.Sub(tStart).Seconds()
			if seconds > 0 {
				rps = fmt.Sprintf("%.1f", float64(totalRequests)/seconds)
			}
		}
	}

	defs := loadVulnDefinitions()
	benchmark, vulnCoverage, confirmedPaths := buildBehavioralBenchmark(defs, allLogs)

	logSampleSize := 500
	startIdx := 0
	if len(allLogs) > logSampleSize {
		startIdx = len(allLogs) - logSampleSize
	}
	var requestLogs []RequestLogEntry
	for i := startIdx; i < len(allLogs); i++ {
		r := allLogs[i]
		requestLogs = append(requestLogs, RequestLogEntry{
			Index:  i + 1,
			Time:   r.CreatedAt,
			Method: r.Method,
			Path:   r.Path,
			Query:  r.Query,
			Status: r.Status,
			Size:   r.ResponseSize,
			IsVuln: confirmedPaths[r.PathWithQuery()],
		})
	}

	data := ReportData{
		ScannerID:         scannerID,
		StartedAt:         startStr,
		CompletedAt:       endStr,
		Duration:          duration,
		GeneratedAt:       time.Now().UTC().Format("2006-01-02 15:04:05 UTC"),
		TotalRequests:     totalRequests,
		UniqueEndpoints:   uniqueEndpoints,
		VulnEndpointsHit:  benchmark.ExercisedFindings,
		AvgResponseSize:   avgSize,
		RequestsPerSecond: rps,
		Benchmark:         benchmark,
		MethodSegments:    methodSegments,
		StatusCodes:       statusCodes,
		VulnCoverage:      vulnCoverage,
		TopEndpoints:      topEndpoints,
		RequestLogs:       requestLogs,
		LogSampleSize:     logSampleSize,
	}

	tmplContent, err := reportFS.ReadFile("report_template.html")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading template: %v\n", err)
		os.Exit(1)
	}
	tmpl, err := template.New("report").Parse(string(tmplContent))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing template: %v\n", err)
		os.Exit(1)
	}

	outFile, err := os.Create(outPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating report file: %v\n", err)
		os.Exit(1)
	}
	defer outFile.Close()

	if err := tmpl.Execute(outFile, data); err != nil {
		fmt.Fprintf(os.Stderr, "Error rendering report: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("📄 Report generated successfully\n")
	fmt.Printf("   Scanner ID        : %s\n", scannerID)
	fmt.Printf("   Requests          : %d\n", totalRequests)
	fmt.Printf("   Auto-confirmed    : %d / %d\n", benchmark.ConfirmedFindings, benchmark.AutoConfirmableFindings)
	fmt.Printf("   Coverage          : %s\n", benchmark.Coverage)
	fmt.Printf("   Confirmed requests: %d\n", benchmark.ConfirmedRequests)
	fmt.Printf("   Output            : %s\n", outPath)
}

func loadVulnDefinitions() []trigger.VulnDef {
	return trigger.LoadVulns("./vulns.json")
}

func (r LoggedRequest) PathWithQuery() string {
	if r.Query == "" {
		return r.Path
	}
	return r.Path + "?" + r.Query
}

func buildBehavioralBenchmark(defs []trigger.VulnDef, logs []LoggedRequest) (BenchmarkScorecard, []VulnCoverageEntry, map[string]bool) {
	requestCounts := map[string]int{}
	evidenceCounts := map[string]int{}
	confirmedCounts := map[string]int{}
	confirmedPaths := map[string]bool{}
	candidateRequests := 0
	confirmedRequests := 0

	for _, req := range logs {
		input := trigger.EvalInput{
			Request: trigger.ReqSnapshot{
				Method:  req.Method,
				URL:     req.PathWithQuery(),
				Headers: parseHeaderMap(req.RequestHeaders),
				Body:    req.Body,
			},
			Response: trigger.RespSnapshot{
				Status:     req.Status,
				Body:       req.ResponseBody,
				DurationMs: req.DurationMs,
			},
		}

		requestHadEvidence := false
		requestConfirmed := false
		for _, def := range defs {
			if !matchesEndpointSurface(def, req) {
				continue
			}
			requestCounts[def.ID]++

			input.VulnID = def.ID
			result := trigger.EvaluateQuiet(input, def)
			if !result.Matched {
				continue
			}
			evidenceCounts[def.ID]++
			requestHadEvidence = true
			if isTrafficAutoConfirmable(def) && isConfirmedBehavior(def, req, result) {
				confirmedCounts[def.ID]++
				requestConfirmed = true
			}
		}

		if requestHadEvidence {
			candidateRequests++
		}
		if requestConfirmed {
			confirmedRequests++
			confirmedPaths[req.PathWithQuery()] = true
		}
	}

	autoConfirmableFindings := 0
	contextRequiredFindings := 0
	confirmedFindings := 0
	exercisedFindings := 0
	inconclusiveFindings := 0
	var coverage []VulnCoverageEntry
	for _, def := range defs {
		requestCount := requestCounts[def.ID]
		evidenceCount := evidenceCounts[def.ID]
		confirmedCount := confirmedCounts[def.ID]
		autoConfirmable := isTrafficAutoConfirmable(def)
		if autoConfirmable {
			autoConfirmableFindings++
		} else {
			contextRequiredFindings++
		}
		if requestCount > 0 || evidenceCount > 0 {
			exercisedFindings++
		}

		outcome := "Not Exercised"
		outcomeClass := "outcome-fn"
		scoringMode := "Context Required"

		if autoConfirmable {
			scoringMode = "Auto-Confirmable"
			if confirmedCount > 0 {
				confirmedFindings++
				outcome = "Confirmed"
				outcomeClass = "outcome-tp"
			} else if evidenceCount > 0 {
				inconclusiveFindings++
				outcome = "Evidence, Needs Review"
				outcomeClass = "outcome-review"
			} else if requestCount > 0 {
				inconclusiveFindings++
				outcome = "Exercised, No Match"
				outcomeClass = "outcome-review"
			}
		} else {
			if evidenceCount > 0 {
				outcome = "Evidence, Manual Validation"
				outcomeClass = "outcome-review"
			} else if requestCount > 0 {
				outcome = "Reached, Manual Validation"
				outcomeClass = "outcome-review"
			}
		}

		coverage = append(coverage, VulnCoverageEntry{
			ID:            def.ID,
			Type:          def.Type,
			Endpoint:      def.Endpoint,
			Access:        accessRequirementForFinding(def),
			Severity:      def.Severity,
			SeverityClass: strings.ToLower(def.Severity),
			ScoringMode:   scoringMode,
			RequestCount:  requestCount,
			EvidenceCount: evidenceCount,
			MatchCount:    confirmedCount,
			Outcome:       outcome,
			OutcomeClass:  outcomeClass,
		})
	}

	return BenchmarkScorecard{
		KnownFindings:           len(defs),
		AutoConfirmableFindings: autoConfirmableFindings,
		ContextRequiredFindings: contextRequiredFindings,
		ExercisedFindings:       exercisedFindings,
		ConfirmedFindings:       confirmedFindings,
		InconclusiveFindings:    inconclusiveFindings,
		NotExercisedFindings:    len(defs) - exercisedFindings,
		Coverage:                ratioPercent(confirmedFindings, autoConfirmableFindings),
		CandidateRequests:       candidateRequests,
		ConfirmedRequests:       confirmedRequests,
		AutoDetectionLabel:      "Auto-confirmable findings are only credited when the logged traffic satisfies the per-finding confirmation rules. Findings that require actor identity, forged-token provenance, or multi-step state are shown as context required and are excluded from the auto-confirm coverage denominator.",
	}, coverage, confirmedPaths
}

func endpointSignatures(def trigger.VulnDef) []string {
	var signatures []string
	for _, part := range strings.Split(def.Endpoint, ",") {
		fields := strings.Fields(strings.TrimSpace(part))
		if len(fields) < 2 {
			continue
		}
		method := strings.ToUpper(fields[0])
		path := fields[1]
		if !strings.HasPrefix(path, "/") {
			continue
		}
		if idx := strings.Index(path, "{"); idx > 0 {
			path = path[:idx]
		}
		path = strings.TrimRight(path, "/")
		if path == "" {
			continue
		}
		signatures = append(signatures, method+" "+path)
	}
	return signatures
}

func matchesEndpointSurface(def trigger.VulnDef, req LoggedRequest) bool {
	for _, signature := range endpointSignatures(def) {
		parts := strings.SplitN(signature, " ", 2)
		if len(parts) != 2 {
			continue
		}
		if req.Method != parts[0] {
			continue
		}
		if requestMatchesPathPattern(req, parts[1]) {
			return true
		}
	}
	return false
}

func requestMatchesPathPattern(req LoggedRequest, signaturePath string) bool {
	pattern := pathPattern(signaturePath)
	if req.Route != "" && req.Route != "-" {
		normalizedRoute := normalizePath(req.Route)
		if pattern.MatchString(normalizedRoute) {
			return true
		}
	}
	return pattern.MatchString(normalizePath(req.Path))
}

func pathPattern(signaturePath string) *regexp.Regexp {
	var pattern strings.Builder
	pattern.WriteString("^")
	for i := 0; i < len(signaturePath); i++ {
		ch := signaturePath[i]
		if ch == '{' {
			for i < len(signaturePath) && signaturePath[i] != '}' {
				i++
			}
			pattern.WriteString("[^/]+")
			continue
		}
		pattern.WriteString(regexp.QuoteMeta(string(ch)))
	}
	pattern.WriteString("/?$")
	return regexp.MustCompile(pattern.String())
}

func normalizePath(path string) string {
	if path == "" {
		return "/"
	}
	path = strings.TrimSpace(path)
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	if path != "/" {
		path = strings.TrimRight(path, "/")
	}
	return path
}

func parseHeaderMap(raw string) map[string]string {
	if strings.TrimSpace(raw) == "" {
		return map[string]string{}
	}
	headers := map[string]string{}
	if err := json.Unmarshal([]byte(raw), &headers); err != nil {
		return map[string]string{}
	}
	return headers
}

func ratioPercent(numerator, denominator int) string {
	if denominator == 0 {
		return "0.0%"
	}
	return fmt.Sprintf("%.1f%%", (float64(numerator)/float64(denominator))*100)
}

func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%.0fs", d.Seconds())
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm %ds", int(d.Minutes()), int(d.Seconds())%60)
	}
	return fmt.Sprintf("%dh %dm %ds", int(d.Hours()), int(d.Minutes())%60, int(d.Seconds())%60)
}

func isTrafficAutoConfirmable(def trigger.VulnDef) bool {
	switch def.ID {
	case "V01", "V02", "V03", "V04", "V08", "V09", "V13", "V14", "V15", "V16", "V17", "V18", "V19":
		return true
	default:
		return false
	}
}

func accessRequirementForFinding(def trigger.VulnDef) string {
	switch def.ID {
	case "V01", "V02", "V04", "V09", "V10", "V13", "V17", "V18":
		return "Public"
	case "V03", "V05", "V06", "V08", "V11", "V12", "V14", "V15", "V19":
		return "Any user session"
	case "V07":
		return "Unauth bypass or any session"
	case "V16":
		return "Staff/admin JWT"
	case "V20":
		return "Credentials or forged JWT"
	default:
		return "Context specific"
	}
}

func isConfirmedBehavior(def trigger.VulnDef, req LoggedRequest, result trigger.EvalResult) bool {
	matched := matchedHeuristics(result)

	switch def.ID {
	case "V01":
		return matched["email_in_response"] || matched["db_error_leaked"]
	case "V02":
		return matched["email_in_search_response"] || matched["db_error_in_search"]
	case "V03":
		return matched["xss_payload_in_comment"] && matched["unescaped_html_in_review_response"]
	case "V04":
		return matched["cloud_metadata_in_response"] || (matched["ssrf_internal_url_in_body"] && matched["ssrf_bytes_fetched_present"])
	case "V08":
		return matched["plaintext_password_in_response"] || matched["password_value_in_json"]
	case "V09":
		return matched["hardcoded_secret_in_response"] || allFieldsPresent(req.ResponseBody, []string{"admin_token", "session_key"})
	case "V13":
		return matched["go_module_content_leaked"] || matched["system_file_content_leaked"]
	case "V14":
		return matched["manipulated_cart_values_echoed"]
	case "V15":
		return matched["dangerous_upload_publicly_served"]
	case "V16":
		return matched["invalid_stock_value_accepted"]
	case "V17":
		return matched["local_or_remote_content_included"] || (matched["recipe_source_lfi_or_rfi_pattern"] && allFieldsPresent(req.ResponseBody, []string{"resolved_path", "content"}))
	case "V18":
		return matched["parser_mismatch_reported"] || (matched["te_cl_header_conflict"] && allFieldsPresent(req.ResponseBody, []string{"desync", "smuggled_request", "frontend_interpretation", "backend_interpretation"}))
	case "V19":
		return matched["predictable_public_invoice_url"] || allFieldsPresent(req.ResponseBody, []string{"temp_path", "public_url", "expires"})
	default:
		return false
	}
}

func matchedHeuristics(result trigger.EvalResult) map[string]bool {
	heuristics := make(map[string]bool, len(result.Matches))
	for _, match := range result.Matches {
		heuristics[match.HeuristicName] = true
	}
	return heuristics
}

func allFieldsPresent(body string, fields []string) bool {
	if strings.TrimSpace(body) == "" || len(fields) == 0 {
		return false
	}

	var parsed interface{}
	if err := json.Unmarshal([]byte(body), &parsed); err == nil {
		for _, field := range fields {
			if !deepContainsKey(parsed, field) {
				return false
			}
		}
		return true
	}

	for _, field := range fields {
		if !strings.Contains(body, `"`+field+`"`) {
			return false
		}
	}
	return true
}

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
