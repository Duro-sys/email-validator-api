# 📧 Email Validator API

A fast, dependency-free email validation API. No external services required.

Validates emails through **4 layers**: syntax, domain existence, MX records, and disposable/role detection. Returns a **score (0–100)** and status: `valid`, `risky`, or `invalid`.

---

## Endpoints

### `POST /validate-email`
Validate a single email address.

**Request body:**
```json
{ "email": "user@example.com" }
```

**Response:**
```json
{
  "success": true,
  "email": "user@example.com",
  "score": 90,
  "status": "valid",
  "checks": {
    "syntax_valid": true,
    "domain_exists": true,
    "mx_found": true,
    "is_disposable": false,
    "is_free_provider": false,
    "is_role_based": false
  },
  "mx_records": ["mail.example.com"],
  "provider": "custom/business",
  "suggestion": null
}
```

---

### `POST /validate-bulk`
Validate up to 10 emails at once.

**Request body:**
```json
{ "emails": ["user1@gmail.com", "fake@mailinator.com", "info@company.com"] }
```

**Response:**
```json
{
  "success": true,
  "summary": { "total": 3, "valid": 1, "risky": 1, "invalid": 1 },
  "results": [...]
}
```

---

## Score & Status Logic

| Score | Status  | Meaning                                      |
|-------|---------|----------------------------------------------|
| 70–100 | `valid`  | Deliverable, real email                     |
| 40–69  | `risky`  | Exists but suspicious (role-based, etc.)    |
| 0–39   | `invalid`| Doesn't exist or disposable                 |

---

## What gets checked

| Check | Description |
|-------|-------------|
| Syntax | RFC 5322 format validation |
| Domain exists | DNS A record lookup |
| MX records | Domain configured to receive email |
| Disposable | 100+ known temp email providers |
| Free provider | Gmail, Yahoo, Hotmail, etc. |
| Role-based | admin@, info@, support@, etc. |
| Typo suggestion | Catches `gmial.com`, `yahooo.com`, etc. |

---

## Built with
- Node.js + Express
- Native `dns.promises` (no paid APIs)
- Zero external dependencies for validation
