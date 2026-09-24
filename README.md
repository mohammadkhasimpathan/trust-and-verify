# Trust & Verify — Unified Cyber Defense Suite

> **Cybersecurity education and threat-simulation dashboard**

**IMPORTANT DISCLAIMER:** Trust & Verify is a cybersecurity education and awareness platform. All scanning results are based on heuristic analysis and simulated threat intelligence. Results are **NOT** equivalent to professional antivirus, SOC, mobile carrier, or threat-intelligence verdicts. No real hardware access, real malware detection, or carrier-level SIM security is provided.

---

## Overview

Trust & Verify is a browser-based cybersecurity simulation dashboard that demonstrates common attack vectors and defenses across five modules:

| Module | Description |
|---|---|
| 📧 Email Threat Scanner | Analyzes raw email headers for SPF/DKIM/DMARC failures and display-name spoofing |
| 💬 SMS Security Shield | Detects smishing, brand impersonation, urgency coercion, and cyberbullying indicators |
| 📞 Phone Scam Scanner | Looks up caller IDs against a simulated threat blacklist |
| 🤖 AI Call Interceptor | Simulates AI-assisted scam call interception with real-time transcript playback |
| 🔒 SIM & Device Shield | Simulates SIM swap attack detection, device binding, and anti-IMSI hijack protection |

---

## Architecture

```
trust-verify/
├── server.js              # Express API (Node.js backend)
├── public/
│   ├── index.html         # Single-page application
│   ├── style.css          # Cyberpunk design system
│   ├── app.js             # Frontend controller (all modules)
│   ├── manifest.json      # PWA manifest
│   ├── sw.js              # Service worker (offline support)
│   └── utils/
│       ├── headerAnalyzer.js   # Email header analysis logic
│       ├── fileScanner.js      # File attachment scanning logic
│       ├── smsAnalyzer.js      # SMS phishing/abuse detection
│       ├── callScanner.js      # Phone number analysis + AI interceptor scenarios
│       └── simRegistry.js      # SIM security simulation engine
├── tests/
│   ├── analyzers.test.js  # Unit tests for all analyzer utilities
│   └── api.smoke.test.js  # API smoke tests (all 3 endpoints)
├── uploads/               # Temporary upload staging (auto-cleaned after each request)
├── .env.example           # Environment variable template
└── package.json
```

### Key Design Points

- **Utilities are dual-mode**: Each `utils/*.js` file exports via `module.exports` in Node.js and attaches to `window.*` in the browser.
- **No database**: All state is in-memory (session) or browser `localStorage` (SIM registration).
- **Offline support**: The service worker caches all static assets for offline use. API calls are never cached.

---

## Prerequisites

- **Node.js** ≥ 18.x (tested on 22.x)
- **npm** ≥ 9.x

---

## Installation

```bash
git clone <repo-url>
cd trust-verify
npm install
```

---

## Development

```bash
npm run dev
# → http://localhost:3000
```

---

## Production

```bash
NODE_ENV=production node server.js
```

---

## Environment Variables

Copy `.env.example` to `.env` and adjust as needed:

```bash
cp .env.example .env
```

| Variable | Default | Description |
|---|---|---|
| `PORT` | `3000` | Server listen port |
| `NODE_ENV` | `development` | Set to `production` to suppress stack traces in API errors |

---

## API Endpoints

All endpoints return JSON. All upload endpoints enforce a **10 MB** file size limit.

### `POST /api/analyze-headers`
Analyzes raw email headers for authentication failures and spoofing indicators.

**Request body:** `application/json`
```json
{ "headers": "<raw email header string>" }
```

**Response:**
```json
{
  "threatLevel": "High",
  "score": 65,
  "logs": ["[CRITICAL] SPF verification failed.", "..."],
  "details": [{ "type": "danger", "title": "...", "message": "..." }]
}
```

### `POST /api/scan-file`
Scans an uploaded file attachment for malware indicators.

**Request:** `multipart/form-data`, field `attachment`

**Response:**
```json
{
  "threatLevel": "Critical",
  "score": 100,
  "hash": "<sha256>",
  "size": 1234,
  "logs": [...],
  "details": [...]
}
```

### `POST /api/scan-eml`
Parses a full `.eml` file and analyzes headers + attachments.

**Request:** `multipart/form-data`, field `emlFile`

**Response:**
```json
{
  "subject": "...",
  "from": "...",
  "to": "...",
  "date": "...",
  "headerResults": { ... },
  "attachments": [{ "filename": "...", "results": { ... } }]
}
```

---

## Rate Limiting

All `/api/*` routes are rate-limited to **100 requests per 15 minutes per IP** (development-friendly). Exceeding the limit returns:
```json
{ "error": "Too many requests. Please try again later." }
```

---

## PWA (Progressive Web App)

Trust & Verify is installable as a PWA on supported browsers:
- Click the **Install App** button in the sidebar
- The service worker caches all static assets for offline operation
- **API endpoints are never cached** — threat analysis always requires network access

---

## Security Notes

| Feature | Status |
|---|---|
| Security headers (helmet) | ✅ Active |
| API rate limiting | ✅ 100 req/15min per IP |
| Upload size limit | ✅ 10 MB max |
| Temp file cleanup | ✅ try/finally on all upload routes |
| Binary file safety | ✅ Null-byte detection, no crash |
| SIM PIN storage | ✅ Salted SHA-256 hash (Web Crypto), no plaintext |
| SIM token generation | ✅ `crypto.getRandomValues()`, no `Math.random()` |
| Stack traces in responses | ✅ Hidden in production |
| CSP | ⚠️ Disabled (Phase 1 task — requires inline script refactor) |

---

## Testing

```bash
npm test
```

Tests use the Node.js built-in test runner (`node:test`) — no extra dependencies required.

- **`tests/analyzers.test.js`** — Unit tests for all 5 analyzer modules
- **`tests/api.smoke.test.js`** — API smoke tests (starts a real server on port 3001)

---

## Known Limitations

1. **Content Security Policy is disabled** — The current app uses inline scripts. A strict CSP requires refactoring inline event handlers and scripts into external files. Planned for Phase 1.
2. **`prompt()` / `alert()` usage** — The SIM unbind flow uses native browser `prompt()`/`alert()`. Planned replacement with custom modal UI in Phase 1.
3. **Frontend analysis is client-side only** — The SMS, phone, and AI interceptor modules run entirely in the browser. No server-side validation of those inputs.
4. **SIM module uses `localStorage`** — Not a secure hardware enclave. Suitable for education/simulation only.
5. **File scanning is heuristic-only** — No connection to VirusTotal, ClamAV, or other AV engines. Planned for Phase 2.

---

## Deployment Limitation — Express + Netlify

> ⚠️ **IMPORTANT**: The current Netlify configuration (`netlify.toml`) publishes only the `public/` directory as static files. **The Express API (`server.js`) is NOT executed by Netlify.**
>
> All `/api/*` routes will return 404 on a pure Netlify static deployment.
>
> **To fully deploy this application**, the backend must either:
> - Be migrated to **Netlify Functions** (serverless)
> - Or deployed separately to a Node.js host (Railway, Render, Fly.io, etc.)
>
> This migration is planned for a later deployment phase.

---

## Phase History

| Phase | Status | Scope |
|---|---|---|
| Phase 0 | ✅ Complete | Security hardening, stability, testing, documentation |
| Phase 1 | 🔜 Planned | UI refactor, CSP, custom modal dialogs, mobile responsiveness |
| Phase 2 | 🔜 Planned | URL scanner, QR scanner, VirusTotal integration |
| Phase 3 | 🔜 Planned | Serverless backend migration, user accounts |
