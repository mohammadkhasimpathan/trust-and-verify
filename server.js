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
 */
app.post('/api/scan-eml', upload.single('emlFile'), async (req, res, next) => {
  const filePath = req.file ? req.file.path : null;

  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No EML file provided.' });
    }

    console.log(`[scan-eml] Received EML file: ${req.file.originalname} (${req.file.size} bytes)`);

    const fileBuffer = fs.readFileSync(filePath);

    // mailparser is a required production dependency declared in package.json.
    // The require is kept inside the route so startup never fails even if the
    // module somehow cannot be loaded (defensive programming).
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

    // Extract raw headers
    let rawHeaders = '';
    email.headers.forEach((value, key) => {
      if (Array.isArray(value)) {
        value.forEach((val) => {
          rawHeaders += `${key}: ${typeof val === 'object' ? JSON.stringify(val) : val}\n`;
        });
      } else if (typeof value === 'object') {
        rawHeaders += `${key}: ${JSON.stringify(value)}\n`;
      } else {
        rawHeaders += `${key}: ${value}\n`;
      }
    });

    const headerResults = analyzeHeaders(rawHeaders);

    // Scan inline attachments
    const attachmentResults = [];
    if (email.attachments && email.attachments.length > 0) {
      for (const attachment of email.attachments) {
        const attachHash = crypto.createHash('sha256').update(attachment.content).digest('hex');
        let contentStr = '';
        if (!isBinaryBuffer(attachment.content)) {
          contentStr = attachment.content.toString('utf8');
        }
        const scan = analyzeFile(attachment.filename, contentStr, attachHash);
        attachmentResults.push({
          filename: attachment.filename,
          contentType: attachment.contentType,
          size: attachment.size,
          hash: attachHash,
          results: scan
        });
      }
    }

    // Cleanup before responding
    safeDeleteFile(filePath);

    return res.json({
      subject: email.subject,
      from: email.from ? email.from.text : 'Unknown',
      to: email.to ? email.to.text : 'Unknown',
      date: email.date,
      headerResults,
      attachments: attachmentResults
    });
  } catch (err) {
    safeDeleteFile(filePath);
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

// ─── Start Server ──────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log('==================================================');
  console.log(`  Trust & Verify Security Engine`);
  console.log(`  Environment : ${IS_PRODUCTION ? 'PRODUCTION' : 'DEVELOPMENT'}`);
  console.log(`  Port        : ${PORT}`);
  console.log(`  Dashboard   : http://localhost:${PORT}`);
  console.log('==================================================');
});
