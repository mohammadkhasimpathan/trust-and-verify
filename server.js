/**
 * server.js
 * Main Express server for Trust & Verify Unified Cyber Defense Suite.
 * Provides APIs for email header spoofing analysis and file attachment scanning.
 *
 * Phase 0 hardening:
 *  - helmet for security headers
 *  - express-rate-limit on all API routes
 *  - Multer file-size limit (10 MB)
 *  - try/finally temp-file cleanup on every upload path
 *  - centralized error handler (no stack traces in production)
 *  - input validation on /api/analyze-headers
 *  - binary-safe file handling (never crashes on non-UTF-8 content)
 */

'use strict';

const express = require('express');
const path = require('path');
const multer = require('multer');
const crypto = require('crypto');
const fs = require('fs');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const { analyzeHeaders } = require('./public/utils/headerAnalyzer');
const { analyzeFile } = require('./public/utils/fileScanner');
// Phase 1 utilities (loaded after headerAnalyzer so they are available for require() inside it)
require('./public/utils/emailParser');
require('./public/utils/domainUtils');

const app = express();
const PORT = process.env.PORT || 3000;
const IS_PRODUCTION = process.env.NODE_ENV === 'production';

// ─── Security Headers ──────────────────────────────────────────────────────
// helmet is applied before any other middleware so all responses get headers.
// CSP is intentionally permissive to avoid breaking the existing app's inline
// scripts, Google Fonts, and service-worker.
// A stricter CSP requiring nonces/hashes is planned for Phase 1 (UI refactor).
app.use(
  helmet({
    contentSecurityPolicy: false, // See note above — Phase 1 task
    crossOriginEmbedderPolicy: false // Needed for Web Audio API in some browsers
  })
);

// ─── Body Size Limit ───────────────────────────────────────────────────────
// Prevent extremely large header payloads from consuming excessive memory.
const MAX_HEADER_SIZE = '64kb';
app.use(express.json({ limit: MAX_HEADER_SIZE }));
app.use(express.urlencoded({ extended: true, limit: MAX_HEADER_SIZE }));

// ─── Static Assets ─────────────────────────────────────────────────────────
app.use(express.static(path.join(__dirname, 'public')));

// ─── Rate Limiting ─────────────────────────────────────────────────────────
// Applied to all API endpoints to prevent abuse.
// Limits are development-friendly (100 req / 15 min per IP).
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests. Please try again later.' }
});
app.use('/api/', apiLimiter);

// ─── CSRF Protection ───────────────────────────────────────────────────────
app.use((req, res, next) => {
  if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)) {
    const origin = req.headers.origin || req.headers.referer;
    // Allow if no origin (e.g. local same-origin without it in some strict cases) 
    // or if it matches our host. In a real environment, match exactly.
    if (origin) {
      try {
        const originUrl = new URL(origin);
        const hostUrl = new URL(`${req.protocol}://${req.get('host')}`);
        if (originUrl.host !== hostUrl.host) {
          return res.status(403).json({ error: 'CSRF token mismatch or invalid origin.' });
        }
      } catch (e) {
        // Invalid URL format
      }
    }
  }
  next();
});


// ─── Upload Directory ──────────────────────────────────────────────────────
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { mode: 0o700 });
}

// ─── Multer Configuration ──────────────────────────────────────────────────
// 10 MB file size limit. Files are stored in the uploads/ staging directory
// and MUST be deleted by the route handler after processing (see try/finally).
const FILE_SIZE_LIMIT = 10 * 1024 * 1024; // 10 MB

const upload = multer({
  dest: 'uploads/',
  limits: { fileSize: FILE_SIZE_LIMIT }
});

// ─── Helper: safe temp-file deletion ──────────────────────────────────────
function safeDeleteFile(filePath) {
  if (!filePath) return;
  fs.unlink(filePath, (err) => {
    if (err && err.code !== 'ENOENT') {
      console.error(`[cleanup] Failed to delete temp file ${path.basename(filePath)}:`, err.code);
    }
  });
}

// ─── Helper: detect binary content ────────────────────────────────────────
// A simplistic heuristic: check for null bytes in the first 8 KB.
// This is NOT malware detection — it's used to avoid feeding garbled binary
// data into regex-based text-content scanners.
function isBinaryBuffer(buffer) {
  const sampleLength = Math.min(buffer.length, 8192);
  for (let i = 0; i < sampleLength; i++) {
    if (buffer[i] === 0) return true;
  }
  return false;
}

// ─── API: Analyze Email Headers ────────────────────────────────────────────
/**
 * POST /api/analyze-headers
 * Body: { headers: "<raw header string>" }
 */
app.post('/api/analyze-headers', (req, res, next) => {
  try {
    const { headers } = req.body;

    if (!headers) {
      return res.status(400).json({ error: 'No email headers provided for analysis.' });
    }
    if (typeof headers !== 'string') {
      return res.status(400).json({ error: 'Headers must be a plain text string.' });
    }
    if (headers.length > 65536) {
      return res.status(400).json({ error: 'Header payload is too large. Maximum 64 KB accepted.' });
    }

    const results = analyzeHeaders(headers);
    return res.json(results);
  } catch (err) {
    next(err);
  }
});

// ─── API: Scan File Attachment ─────────────────────────────────────────────
/**
 * POST /api/scan-file
 * Multipart form-data, field name: "attachment"
 */
app.post('/api/scan-file', upload.single('attachment'), (req, res, next) => {
  const filePath = req.file ? req.file.path : null;

  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file attachment provided for scanning.' });
    }

    const filename = req.file.originalname;
    console.log(`[scan-file] Received: ${filename} (${req.file.size} bytes)`);

    // Read file into buffer
    const fileBuffer = fs.readFileSync(filePath);

    // Compute SHA-256 hash
    const sha256 = crypto.createHash('sha256').update(fileBuffer).digest('hex');

    // For content scanning, only pass text to the regex engine.
    // Binary files are still hashed and have their extensions checked.
    let contentString = '';
    if (!isBinaryBuffer(fileBuffer)) {
      contentString = fileBuffer.toString('utf8');
    } else {
      console.log(`[scan-file] Binary content detected in ${filename} — skipping text-pattern scan.`);
    }

    // Run analysis
    const results = analyzeFile(filename, contentString, sha256);
    results.hash = sha256;
    results.size = req.file.size;

    // Cleanup BEFORE responding so it always runs
    safeDeleteFile(filePath);

    return res.json(results);
  } catch (err) {
    safeDeleteFile(filePath);
    next(err);
  }
});

// ─── API: Scan Raw EML File ────────────────────────────────────────────────
/**
 * POST /api/scan-eml
 * Multipart form-data, field name: "emlFile"
 *
 * Phase 1 response structure:
 *  {
 *    message:        { from, to, cc, replyTo, returnPath, subject, date, messageId },
 *    authentication: { spf, dkim, dmarc, dkimDomain, raw },
 *    routing:        { hops, originatingIP, hopCount },
 *    links:          string[],
 *    attachments:    [{ filename, contentType, extension, size, hash, riskCategory, findings }],
 *    findings:       structured findings array,
 *    score:          number,
 *    threatLevel:    string,
 *    logs:           string[],
 *    parsedHeaders:  [{name, value, raw}],
 *    headerResults:  full analyzeHeaders() output (backward compat)
 *  }
 */
app.post('/api/scan-eml', upload.single('emlFile'), async (req, res, next) => {
  const filePath = req.file ? req.file.path : null;

  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No EML file provided.' });
    }

    console.log(`[scan-eml] Received EML file: ${req.file.originalname} (${req.file.size} bytes)`);

    const fileBuffer = fs.readFileSync(filePath);

    let simpleParser;
    try {
      simpleParser = require('mailparser').simpleParser;
    } catch (e) {
      safeDeleteFile(filePath);
      return res.status(500).json({
        error: 'EML parsing library is unavailable on this server. Cannot process .eml files.'
      });
    }

    // Parse EML
    const email = await simpleParser(fileBuffer);

    // ── Reconstruct raw header block ────────────────────────────────────
    // mailparser gives us parsed headers; we rebuild a raw block so
    // analyzeHeaders() can use its own RFC 5322-aware parser.
    let rawHeaders = '';
    email.headers.forEach((value, key) => {
      const safeVal = Array.isArray(value)
        ? value.map(v => (typeof v === 'object' ? JSON.stringify(v) : String(v))).join(', ')
        : typeof value === 'object' ? JSON.stringify(value) : String(value);
      rawHeaders += `${key}: ${safeVal}\n`;
    });

    // ── Run header analysis ──────────────────────────────────────────────
    const headerResults = analyzeHeaders(rawHeaders);

    // ── Build message envelope ───────────────────────────────────────────
    const getAddr = (field) => (field ? field.text || String(field) : null);

    const message = {
      from:       getAddr(email.from),
      to:         getAddr(email.to),
      cc:         getAddr(email.cc),
      replyTo:    getAddr(email.replyTo),
      returnPath: email.headers.get('return-path') || null,
      subject:    email.subject || null,
      date:       email.date ? email.date.toISOString() : null,
      messageId:  email.messageId || null
    };

    // ── Scan attachments ──────────────────────────────────────────────────
    const attachments = [];
    if (email.attachments && email.attachments.length > 0) {
      for (const att of email.attachments) {
        const attHash = crypto.createHash('sha256').update(att.content).digest('hex');
        let contentStr = '';
        if (!isBinaryBuffer(att.content)) {
          contentStr = att.content.toString('utf8');
        }
        const scan = analyzeFile(att.filename || 'unknown', contentStr, attHash);

        const filename = att.filename || 'unnamed';
        const ext = filename.includes('.') ? filename.split('.').pop().toLowerCase() : '';

        attachments.push({
          filename,
          extension: ext,
          contentType: att.contentType || 'application/octet-stream',
          size:        att.size || att.content.length,
          hash:        attHash,
          riskCategory: scan.threatLevel,
          score:       scan.score,
          findings:    scan.details || [],
          logs:        scan.logs || []
        });
      }
    }

    // Cleanup before responding
    safeDeleteFile(filePath);

    return res.json({
      message,
      authentication: headerResults.authentication || {
        spf:  null, dkim: null, dmarc: null
      },
      routing:        headerResults.routing  || { hops: [], originatingIP: null, hopCount: 0 },
      links:          headerResults.links    || [],
      attachments,
      findings:       headerResults.findings || [],
      score:          headerResults.score,
      threatLevel:    headerResults.threatLevel,
      logs:           headerResults.logs,
      parsedHeaders:  headerResults.parsedHeaders || [],
      // Backward compat: keep headerResults object available
      headerResults
    });
  } catch (err) {
    safeDeleteFile(filePath);
    next(err);
  }
});

// ─── API: SSL Inspection ───────────────────────────────────────────────────
/**
 * POST /api/inspect-ssl
 * Body: { hostname: "example.com", port: 443 }
 */
const tls = require('tls');
const dns = require('dns');
const { promisify } = require('util');
const resolve4 = promisify(dns.resolve4);

function isPrivateIP(ip) {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4) return true; // Block non-IPv4 for simplicity here
  
  if (parts[0] === 10) return true;
  if (parts[0] === 127) return true;
  if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
  if (parts[0] === 192 && parts[1] === 168) return true;
  if (parts[0] === 169 && parts[1] === 254) return true;
  if (parts[0] === 0) return true;
  
  return false;
}

app.post('/api/inspect-ssl', async (req, res, next) => {
  try {
    let { hostname, port } = req.body;
    port = port || 443;

    if (!hostname || typeof hostname !== 'string') {
      return res.status(400).json({ error: 'Hostname is required.' });
    }
    
    // Validate hostname format loosely to prevent injection
    if (!/^[a-zA-Z0-9.-]+$/.test(hostname)) {
      return res.status(400).json({ error: 'Invalid hostname characters.' });
    }

    if (hostname.toLowerCase() === 'localhost' || hostname.toLowerCase().includes('localdomain')) {
      return res.status(403).json({ error: 'Localhost inspection is prohibited (SSRF protection).' });
    }

    // SSRF DNS Resolution
    let ips;
    try {
      ips = await resolve4(hostname);
    } catch (e) {
      return res.status(400).json({ error: 'DNS resolution failed. Hostname may not exist.' });
    }

    if (!ips || ips.length === 0) {
      return res.status(400).json({ error: 'No IPv4 addresses found for hostname.' });
    }

    const targetIp = ips[0];
    if (isPrivateIP(targetIp)) {
      return res.status(403).json({ error: 'Target resolves to a private/reserved IP (SSRF protection).' });
    }

    // Attempt TLS Connection
    const options = {
      host: targetIp,
      servername: hostname, // SNI
      port: port,
      rejectUnauthorized: false, // We want to inspect bad certs too
      timeout: 5000 // 5 seconds
    };

    const socket = tls.connect(options, () => {
      const cert = socket.getPeerCertificate(true); // detailed
      const protocol = socket.getProtocol();
      const cipher = socket.getCipher();
      const authorized = socket.authorized;
      const authorizationError = socket.authorizationError;

      // Hostname verification
      const hostnameMatched = tls.checkServerIdentity(hostname, cert) === undefined;

      // Expiry calculation
      let daysUntilExpiry = 0;
      if (cert.valid_to) {
        const toDate = new Date(cert.valid_to);
        const now = new Date();
        daysUntilExpiry = (toDate - now) / (1000 * 60 * 60 * 24);
      }

      const result = {
        hostname,
        targetIp,
        protocol,
        cipher,
        authorized,
        authorizationError,
        hostnameMatched,
        daysUntilExpiry,
        certificate: {
          subject: cert.subject,
          issuer: cert.issuer,
          valid_from: cert.valid_from,
          valid_to: cert.valid_to,
          fingerprint256: cert.fingerprint256,
          serialNumber: cert.serialNumber
        }
      };

      socket.end();
      res.json(result);
    });

    socket.on('timeout', () => {
      socket.destroy();
      res.status(504).json({ error: 'TLS connection timed out.' });
    });

    socket.on('error', (err) => {
      socket.destroy();
      res.status(502).json({ error: `TLS connection error: ${err.message}` });
    });

  } catch (err) {
    next(err);
  }
});

// ─── Multer Error Handler ──────────────────────────────────────────────────
// Catches file-size-limit and other Multer-specific errors before they reach
// the generic error handler.
app.use((err, req, res, next) => {
  if (err.code === 'LIMIT_FILE_SIZE') {
    return res.status(413).json({
      error: `File too large. Maximum upload size is ${Math.round(FILE_SIZE_LIMIT / 1024 / 1024)} MB.`
    });
  }
  next(err);
});

// ─── Phase 4: Threat Intelligence ──────────────────────────────────────────
const threatIntelRouter = require('./server/threatIntel/index');
app.use('/api/threat-intel', threatIntelRouter);

// ─── Centralized Error Handler ─────────────────────────────────────────────
// Catches all errors thrown by route handlers. Stack traces are only logged
// server-side; the client receives a safe generic message in production.
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  const status = err.status || err.statusCode || 500;
  console.error(`[error] ${req.method} ${req.path} → ${err.message}`);

  const body = { error: 'An internal server error occurred.' };
  if (!IS_PRODUCTION) {
    body.detail = err.message;
  }

  res.status(status).json(body);
});

// ─── Phase 7: Accounts and Sync ──────────────────────────────────────────────
const session = require('express-session');
const { runMigrations } = require('./server/db/migrations/setup');
runMigrations();

app.use(session({
  secret: process.env.SESSION_SECRET || 'trust-verify-local-secret-38917398127391',
  resave: false,
  saveUninitialized: false,
  cookie: { 
    secure: IS_PRODUCTION, 
    httpOnly: true, 
    sameSite: 'lax',
    maxAge: 7 * 24 * 60 * 60 * 1000 // 1 week
  }
}));

const authRouter = require('./server/auth/authRouter');
const syncRouter = require('./server/sync/syncRouter');

app.use('/api/auth', authRouter);
app.use('/api/sync', syncRouter);

// ─── Start Server ──────────────────────────────────────────────────────────
if (require.main === module) {
  app.listen(PORT, () => {
    console.log('==================================================');
    console.log(`  Trust & Verify Security Engine`);
    console.log(`  Environment : ${IS_PRODUCTION ? 'PRODUCTION' : 'DEVELOPMENT'}`);
    console.log(`  Port        : ${PORT}`);
    console.log(`  Dashboard   : http://localhost:${PORT}`);
    console.log('==================================================');
  });
}

module.exports = app;
