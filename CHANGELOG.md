# Changelog — xVulnv2 Restaurant Vulnerability Lab

All notable changes to this project are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/).

---

## [1.7.0] — 2026-04-08

### Added

- Introduced advanced vulnerability scenarios including file upload, race conditions, JWT issues, and request smuggling
- Advanced lab-only routes for:
  - menu asset upload (`POST /api/admin/menu/upload-image`)
  - invoice export (`GET /api/orders/{id}/invoice/export`)
  - kitchen recipe viewer (`GET /api/kitchen/recipes/view`)
  - kitchen inventory APIs (`GET /api/kitchen/inventory`, `POST /api/kitchen/inventory/adjust`)
  - staff JWT session/panel (`POST /api/staff/session`, `GET /api/staff/panel`)
  - kitchen dispatch smuggling simulation (`POST /api/kitchen/dispatch`)
- Inventory persistence (`inventory` table) seeded with low-stock items to support race-condition and API9 scenarios
- Public temp export directory and menu upload directory under `static/` to support realistic file-handling scenarios
- New recipe fixtures under `recipes/` for kitchen file-viewer flows
- Benchmark schema support in `vulns.json` for `category`, `flow`, `feature_flag`, `lab_only`, and `detection_hints`
- Nine new ground-truth entries (V16–V24) covering:
  - unrestricted file upload
  - race condition
  - API9 improper inventory management
  - LFI/RFI
  - HTTP request smuggling
  - insecure temporary file usage
  - sensitive information in source code
  - unmaintained third-party components
  - JWT validation flaws

### Changed

- `config/config.go` — added `APP_ENV`, `ENABLE_ADVANCED_VULNS`, global config access, and bumped app version to `1.7.0`
- `handlers/orders.go` — order placement now performs lab-only stock reservation using a vulnerable read/sleep/write pattern
- `handlers/admin.go` — debug endpoint version now reports `1.7.0` and the configured environment
- `handlers/reset.go` — reset now clears generated uploads and temp exports for deterministic reruns
- `main.go` — creates advanced-lab directories/files at startup and registers all new routes
- `README.md` / `known_findings.md` — expanded architecture, API, exploit, and operator notes for the new scenarios

### Security

- Advanced scenarios are disabled automatically when `APP_ENV=production` unless `ENABLE_ADVANCED_VULNS=true` is explicitly set
- Added lightweight in-memory rate limiting on remote recipe fetches and request-smuggling simulation endpoints to reduce infrastructure abuse
- Hardcoded secrets introduced for source-review exercises are lab-only placeholders, not real credentials

### Backward Compatibility

- Existing V01–V15 flows remain unchanged
- No destructive database migrations were introduced; new tables are additive only
- Rollback is supported by setting `ENABLE_ADVANCED_VULNS=false`

---

## [1.6.0] — 2026-04-08

### Added

- **CLI-based scan/report workflow** — all sensitive operations (reset, scan lifecycle, report generation) are now orchestrated via `make` commands instead of public API endpoints.
  - `make build` — compile server + CLI tool
  - `make run` — build and start the application
  - `make reset` — reset database to seed state (CLI only)
  - `make scan SCANNER={custom_header}` — start a scan session tied to a custom header identifier
  - `make scan-stop SCANNER={custom_header}` — stop an active scan session
  - `make report SCANNER={custom_header}` — generate HTML pentest report scoped to scan session
  - `make clean` — remove binaries, reports, and database

- **`xvulnctl` CLI tool** (`cmd/xvulnctl/`) — standalone Go binary for benchmark operations. Shares the `db` package for direct SQLite access; never exposes HTTP endpoints.

- **`scan_sessions` table** — tracks scan lifecycle (scanner_id, status, started_at, completed_at). Each session is uniquely keyed by scanner ID.

- **HTML pentest report generator** — self-contained dark-themed HTML report with:
  - Scan summary statistics (requests, endpoints, duration, RPS)
  - HTTP method and status code distribution
  - Vulnerability endpoint coverage matrix (cross-referenced with `vulns.json`)
  - Top endpoints by request count
  - Request log with vulnerability indicator highlighting

- **`ALLOW_REMOTE_RESET` environment variable** — feature flag to bypass localhost guard on `/api/reset` in trusted environments (default: `false`).

- **Makefile** — primary orchestration interface with input validation for `SCANNER` variable.

- **`.gitignore`** — excludes binaries, database files, and generated reports.

### Changed

- `main.go` — `/api/reset` route now wrapped with `LocalhostOnly` middleware (unless `ALLOW_REMOTE_RESET=true`)
- `config/config.go` — added `AllowRemoteReset` field
- `db/db.go` — added `scan_sessions` table to migration and `Reset()` cascade

### Security

- `/api/reset` restricted to localhost-only access by default — returns 403 to non-localhost callers
- `LocalhostOnly` middleware (`middleware/localhost.go`) inspects `r.RemoteAddr` directly, ignores `X-Forwarded-For` to prevent header spoofing
- Scanner ID validated with strict regex `^[a-zA-Z0-9_-]{1,64}$` at both Makefile and CLI levels (defence-in-depth)
- Report output path protected against path traversal via `filepath.Abs` prefix check
- No sensitive data (passwords, session keys) included in generated reports
- Feature flag `ALLOW_REMOTE_RESET` for controlled rollback to remote reset capability

### Backward Compatibility

- `/api/reset` route remains registered — existing local `curl -X POST http://localhost:4443/api/reset` workflows continue to work
- Set `ALLOW_REMOTE_RESET=true` to restore pre-1.6.0 behavior for remote reset access
- All non-sensitive endpoints unchanged

---

## [1.5.0] — 2026-04-08

### Added

- **Generalized Trigger Engine** (`trigger/` package) — payload-agnostic vulnerability detection system replacing hardcoded payload string matching.
  - `trigger/engine.go` — core engine: `LoadVulns`, `GetVulns`, `GetVulnByID`, `Evaluate`
  - `trigger/strategies.go` — 6 detection strategies: `pattern_match`, `response_body_match`, `status_code`, `timing_anomaly`, `field_presence`, `error_signature`; `response_diff` stubbed for future iteration
  - `trigger/validator.go` — schema validation with ReDoS mitigation (500-character pattern length cap, pre-compile at startup)

- **Internal trigger evaluation payload** — accepts a `{ vuln_id, request, response }` snapshot and returns which heuristics fired when invoked by the benchmark harness. No public HTTP route is exposed.

- **`TRIGGER_ENGINE` environment variable** — feature flag (`legacy` | `pattern` | `both`, default: `both`) for staged rollout and rollback.

- **`triggers` array in `vulns.json`** — all 15 vulnerability entries updated with pattern-based detection strategies. The legacy `trigger` string is preserved in every entry for full backward compatibility.

### Changed

- `config/config.go` — added `TriggerEngine` field populated from `TRIGGER_ENGINE` env var
- `main.go` — trigger engine initialised at startup (fail-fast regex validation); no crawler-visible trigger evaluation routes registered
- `vulns.json` — each entry extended with a `triggers` array; `trigger` string unchanged

### Security

- All regex patterns validated at startup before the server accepts traffic (ReDoS mitigation)
- Pattern length capped at 500 characters per entry
- Match events logged with heuristic name for audit trail
- No injection risk in dynamic pattern evaluation — patterns loaded from file, not user input

### Backward Compatibility

- All 15 existing `trigger` (singular) strings preserved verbatim — no entries removed or modified
- Entries without a `triggers` array continue to work; the internal evaluator returns the legacy string as a fallback
- Setting `TRIGGER_ENGINE=legacy` bypasses the new engine entirely

---

## [1.4.0] — 2026-04-08

### Added

- Initial release of xVulnv2 Restaurant Vulnerability Lab
- 15 OWASP-mapped embedded vulnerabilities (V01–V15)
- Dual-port architecture: API on :4443, frontend on :4444
- xBow pentest pipeline integration via `vulns.json` and `known_findings.md`
- Request logging middleware with scanner ID capture
- SQLite-backed database with seeded demo data
