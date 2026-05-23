# EmailGuard API

**A fast, free REST API for detecting disposable and temporary email addresses.**

[![License: MIT](https://img.shields.io/badge/License-MIT-teal.svg)](LICENSE)
[![Node.js](https://img.shields.io/badge/Node.js-18%2B-green.svg)](https://nodejs.org)
[![Domains](https://img.shields.io/badge/Blocked%20Domains-9%2C241-red.svg)](#blocklist)
[![Version](https://img.shields.io/badge/Version-2.1.0-blue.svg)](#changelog)

Built with Node.js + Express. Hosted on Render. No database required — everything runs in-memory for zero-latency lookups.

**Live API:** `https://email-validator-api-uk66.onrender.com`  
**Docs / Demo:** [https://email-validator-api-uk66.onrender.com](https://email-validator-api-uk66.onrender.com)

---

## Table of Contents

- [Features](#features)
- [Quick Start](#quick-start)
- [Endpoints](#endpoints)
  - [POST /v1/verify](#post-v1verify)
  - [POST /v1/verify/bulk](#post-v1verifybulk)
  - [GET /v1/domain/:domain](#get-v1domaindomain)
  - [GET /v1/rate-limit/status](#get-v1rate-limitstatus)
  - [GET /health](#get-health)
- [Confidence Scoring](#confidence-scoring)
- [Rate Limits](#rate-limits)
- [Response Headers](#response-headers)
- [Error Codes](#error-codes)
- [Self-Hosting](#self-hosting)
- [Environment Variables](#environment-variables)
- [Changelog](#changelog)
- [License](#license)

---

## Features

- **9,241 blocked domains** — merged from three open-source community blocklists
- **Confidence scoring** — 0–100 score with `very_low` → `very_high` label across 8 independent signals
- **DNS + MX verification** — checks if the domain actually exists and can receive email
- **Bulk endpoint** — verify up to 50 emails in a single request
- **In-memory rate limiter** — proper 1-hour sliding window with RFC-compliant headers
- **Webhook support** — fire callbacks on `disposable.detected` and `bulk.complete` events
- **Zero database** — blocklist loaded into a `Set` at startup; sub-millisecond lookups

---

## Quick Start

```bash
curl -X POST https://email-validator-api-uk66.onrender.com/v1/verify \
  -H "Content-Type: application/json" \
  -d '{"email": "test@mailinator.com"}'
```

Response:

```json
{
  "status": "invalid",
  "verdict": "disposable",
  "email": "test@mailinator.com",
  "domain": "mailinator.com",
  "is_disposable": true,
  "confidence": { "score": 80, "label": "very_high" },
  "risk_level": "high",
  "reasons": ["Domain is in the known disposable email blocklist"],
  "dns": {
    "domain_exists": true,
    "has_mx": true,
    "primary_mx": "mail.mailinator.com"
  },
  "rate_limit": { "remaining": 49 }
}
```

---

## Endpoints

### POST /v1/verify

Validate a single email address.

**Request body**

| Parameter  | Type    | Required | Default | Description                          |
|------------|---------|----------|---------|--------------------------------------|
| `email`    | string  | Yes      | —       | Email address to validate            |
| `check_dns`| boolean | No       | `true`  | Perform DNS + MX lookup              |

**Example**

```bash
curl -X POST https://email-validator-api-uk66.onrender.com/v1/verify \
  -H "Content-Type: application/json" \
  -d '{"email": "hello@gmail.com", "check_dns": true}'
```

**Response — valid (200)**

```json
{
  "status": "valid",
  "verdict": "legitimate",
  "email": "hello@gmail.com",
  "domain": "gmail.com",
  "local_part": "hello",
  "is_disposable": false,
  "confidence": { "score": 2, "label": "very_low" },
  "confidence_score": 2,
  "risk_level": "low",
  "reasons": [],
  "dns": {
    "domain_exists": true,
    "has_mx": true,
    "mx_records": [{ "priority": 5, "exchange": "gmail-smtp-in.l.google.com" }],
    "primary_mx": "gmail-smtp-in.l.google.com"
  },
  "checks": {
    "in_blocklist": false,
    "suspicious_pattern": false,
    "dns_checked": true
  },
  "checked_at": "2025-05-23T10:00:00.000Z",
  "rate_limit": { "remaining": 49 }
}
```

**Response — disposable (200)**

```json
{
  "status": "invalid",
  "verdict": "disposable",
  "email": "test@mailinator.com",
  "domain": "mailinator.com",
  "local_part": "test",
  "is_disposable": true,
  "confidence": { "score": 80, "label": "very_high" },
  "confidence_score": 80,
  "risk_level": "high",
  "reasons": ["Domain is in the known disposable email blocklist"],
  "dns": {
    "domain_exists": true,
    "has_mx": true,
    "mx_records": [{ "priority": 10, "exchange": "mail.mailinator.com" }],
    "primary_mx": "mail.mailinator.com"
  },
  "checks": {
    "in_blocklist": true,
    "suspicious_pattern": false,
    "dns_checked": true
  },
  "checked_at": "2025-05-23T10:00:00.000Z",
  "rate_limit": { "remaining": 48 }
}
```

**Response — suspicious / risky (200)**

```json
{
  "status": "risky",
  "verdict": "suspicious",
  "email": "user@xn--04--jda1b.xn--p1ai",
  "domain": "xn--04--jda1b.xn--p1ai",
  "is_disposable": false,
  "confidence": { "score": 38, "label": "medium" },
  "risk_level": "medium",
  "reasons": [
    "No MX records found — domain cannot receive email",
    "Domain name is predominantly numeric — uncommon for legitimate providers"
  ]
}
```

**Verdict reference**

| `status`  | `verdict`    | Confidence score | Meaning                              |
|-----------|--------------|------------------|--------------------------------------|
| `valid`   | `legitimate` | 0–29             | Looks like a real email              |
| `risky`   | `suspicious` | 30–59            | Mixed signals — flag for review      |
| `invalid` | `disposable` | 60–100           | Almost certainly disposable / fake   |

---

### POST /v1/verify/bulk

Verify up to 50 emails in a single API call. DNS is disabled by default for speed.

**Request body**

| Parameter  | Type     | Required | Default | Description                      |
|------------|----------|----------|---------|----------------------------------|
| `emails`   | string[] | Yes      | —       | Array of email strings (max 50)  |
| `check_dns`| boolean  | No       | `false` | Run DNS + MX per email           |

**Example**

```bash
curl -X POST https://email-validator-api-uk66.onrender.com/v1/verify/bulk \
  -H "Content-Type: application/json" \
  -d '{
    "emails": ["hello@gmail.com", "test@mailinator.com", "user@guerrillamail.com"],
    "check_dns": false
  }'
```

**Response (200)**

```json
{
  "status": "ok",
  "summary": {
    "total": 3,
    "valid": 1,
    "invalid": 2,
    "risky": 0
  },
  "results": [
    { "status": "valid",   "verdict": "legitimate", "email": "hello@gmail.com",         "confidence": { "score": 5,  "label": "very_low"  } },
    { "status": "invalid", "verdict": "disposable", "email": "test@mailinator.com",      "confidence": { "score": 80, "label": "very_high" } },
    { "status": "invalid", "verdict": "disposable", "email": "user@guerrillamail.com",   "confidence": { "score": 80, "label": "very_high" } }
  ]
}
```

> Each item in `results` is a full verify object (same shape as `/v1/verify`).

---

### GET /v1/domain/:domain

Check a domain directly without specifying the local part. Always performs a full DNS + MX lookup.

**Example**

```bash
curl https://email-validator-api-uk66.onrender.com/v1/domain/mailinator.com
```

**Response (200)**

```json
{
  "status": "ok",
  "domain": "mailinator.com",
  "is_disposable": true,
  "confidence": { "score": 80, "label": "very_high" },
  "confidence_score": 80,
  "risk_level": "high",
  "reasons": ["Domain is in the known disposable email blocklist"],
  "dns": {
    "domain_exists": true,
    "has_mx": true,
    "mx_records": [{ "priority": 10, "exchange": "mail.mailinator.com" }],
    "primary_mx": "mail.mailinator.com"
  },
  "checked_at": "2025-05-23T10:00:00.000Z"
}
```

---

### GET /v1/rate-limit/status

Check your current quota without consuming a verification request.

**Example**

```bash
curl https://email-validator-api-uk66.onrender.com/v1/rate-limit/status
```

**Response (200)**

```json
{
  "status": "ok",
  "identifier": "103.x.x.x",
  "limit": 50,
  "used": 12,
  "remaining": 38,
  "reset_at": "2025-05-23T15:00:00.000Z"
}
```

---

### GET /health

Service health check. Returns domain count and uptime.

```bash
curl https://email-validator-api-uk66.onrender.com/health
```

```json
{
  "status": "ok",
  "version": "2.1.0",
  "domains_loaded": 9241,
  "uptime_seconds": 3600,
  "rate_limit": { "anon": 50, "key": 1000, "window": "1h" },
  "timestamp": "2025-05-23T10:00:00.000Z"
}
```

---

## Confidence Scoring

Every response includes a `confidence` object with a `score` (0–100) and a `label`.

**Higher score = more likely to be disposable or invalid.**

### Signals

| Signal                              | Weight | Notes                                          |
|-------------------------------------|--------|------------------------------------------------|
| Domain in blocklist                 | +80    | Primary signal                                 |
| No MX records                       | +15    | Domain cannot receive email                    |
| Domain NXDOMAIN (doesn't exist)     | +12    | DNS resolution failure                         |
| MX points to known temp provider    | +10    | 30+ known temp-mail MX signatures checked      |
| Suspicious random-looking pattern   | +8     | Long random strings, excessive hyphens         |
| Single-character local part         | +5     | e.g. `x@domain.com`                           |
| Excessive dots in domain            | +4     | 4+ sub-labels                                  |
| Numeric-heavy domain name           | +4     | >60% of domain name is digits                  |
| Has valid MX (not in blocklist)     | −10    | Legitimacy signal                              |
| Domain resolves (not in blocklist)  | −5     | Legitimacy signal                              |

### Labels

| Score   | Label       | Meaning                                  |
|---------|-------------|------------------------------------------|
| 0–19    | `very_low`  | Almost certainly legitimate              |
| 20–39   | `low`       | Minor concerns, likely fine              |
| 40–59   | `medium`    | Mixed signals — flag for manual review   |
| 60–79   | `high`      | Strong disposable indicators             |
| 80–100  | `very_high` | Almost certainly disposable              |

---

## Rate Limits

Limits are enforced per IP (anonymous) or per API key, using a **fixed 1-hour window**.

| Tier        | Limit         | Header                    |
|-------------|---------------|---------------------------|
| Anonymous   | 50 req/hour   | `X-RateLimit-Limit: 50`   |
| API key     | 1,000 req/hour| `X-RateLimit-Limit: 1000` |

When exceeded, the API returns `HTTP 429` with:

```json
{
  "status": "error",
  "code": "RATE_LIMIT_EXCEEDED",
  "message": "Rate limit of 50 requests/hour exceeded. Resets in 42 minute(s).",
  "retry_after_seconds": 2520,
  "reset_at": "2025-05-23T15:00:00.000Z"
}
```

> Need higher limits? [Contact me](mailto:hi@elvishpatel.in) for an API key.

---

## Response Headers

Every response from `/v1/*` includes these headers:

| Header                  | Value                                      |
|-------------------------|--------------------------------------------|
| `X-RateLimit-Limit`     | Your tier's max requests per hour          |
| `X-RateLimit-Remaining` | Requests left in the current window        |
| `X-RateLimit-Reset`     | Unix timestamp when the window resets      |
| `Retry-After`           | Seconds to wait *(only on 429 responses)*  |

---

## Error Codes

| HTTP | Code                  | Meaning                                          |
|------|-----------------------|--------------------------------------------------|
| 400  | `MISSING_EMAIL`       | `email` field missing or not a string            |
| 400  | `MISSING_EMAILS`      | `emails` array missing or empty (bulk)           |
| 400  | `TOO_MANY_EMAILS`     | More than 50 emails in bulk request              |
| 400  | `INVALID_FORMAT`      | Email failed basic format check                  |
| 400  | `INVALID_DOMAIN`      | Domain param is malformed                        |
| 401  | `INVALID_API_KEY`     | `X-Api-Key` header is invalid or revoked         |
| 429  | `RATE_LIMIT_EXCEEDED` | Hourly quota exhausted                           |
| 500  | `INTERNAL_ERROR`      | Unexpected server error                          |

---

## Self-Hosting

### Prerequisites

- Node.js 18+
- npm

### Install

```bash
git clone https://github.com/elvishpatel/disposable-email-checker-api.git
cd disposable-email-checker-api
npm install
```

### Run

```bash
# Development
node index.js

# With auto-restart
npx nodemon index.js
```

The server starts on port `3000` by default:

```
🚀 Email Validator API v2.1 running on port 3000
   Domains loaded : 9241
   Rate limits    : 50 req/h (anon) · 1000 req/h (key)
   Health         : http://localhost:3000/health
```

### Deploy to Render

1. Push your repo to GitHub
2. Go to [render.com](https://render.com) → New → Web Service
3. Connect the repo, set:
   - **Build command:** `npm install`
   - **Start command:** `npm start`
   - **Region:** Singapore (closest to India)
4. Add environment variables (see below)
5. Click **Deploy**

Every future `git push` to `main` triggers an automatic redeploy.

---

## Environment Variables

| Variable          | Default              | Description                                      |
|-------------------|----------------------|--------------------------------------------------|
| `PORT`            | `3000`               | Server port (Render sets this automatically)     |
| `ADMIN_SECRET`    | —                    | Required to provision API keys via `POST /v1/keys`|
| `ALLOWED_ORIGINS` | `http://localhost:3000` | Comma-separated CORS origins                  |
| `ANON_RATE_LIMIT` | `50`                 | Requests per hour for anonymous (IP) clients     |
| `KEY_RATE_LIMIT`  | `1000`               | Requests per hour for API key holders            |
| `NODE_ENV`        | `development`        | Set to `production` on Render                    |

**Example `.env`:**

```env
PORT=3000
ADMIN_SECRET=your_long_random_secret_here
ALLOWED_ORIGINS=https://yourdomain.com,http://localhost:3000
ANON_RATE_LIMIT=50
KEY_RATE_LIMIT=1000
NODE_ENV=production
```

---

## Project Structure

```
disposable-email-checker-api/
├── index.js                  # Main server — all routes, rate limiter, validation logic
├── disposable_domains.json   # Blocklist (9,241 domains)
├── package.json
├── .gitignore
├── README.md
└── public/
    └── index.html            # Landing page + live demo UI
```

**Runtime files (gitignored — created on first use):**

```
api_keys.json       # Provisioned API keys
analytics.json      # Request analytics (rolling 30 days)
webhooks.json       # Registered webhook endpoints
```

> These files are ephemeral on Render's free tier — they reset on each redeploy. Use a persistent store (Redis, Postgres) if you need durable analytics or webhook registrations in production.

---

## Changelog

### v2.1.0
- **Rate limiter:** Replaced file-based storage with in-memory `Map`; fixed window to 1 hour (was 24h); proper `X-RateLimit-Reset` (Unix epoch) and `Retry-After` headers
- **Confidence:** Added 4 new signals — temp MX provider check (30 signatures), single-char local part, excessive dots, numeric-heavy domain; added `label` field (`very_low` → `very_high`)
- **New endpoint:** `GET /v1/rate-limit/status` — check quota without burning a request
- **Bulk webhook:** `bulk.complete` event now fires after every bulk request

### v1.0.0
- Initial release — single email verify, blocklist check only

---

## License

MIT © [Elvish Patel](https://elvishpatel.in)

See [LICENSE](LICENSE) for full terms.
