/**
 * tests/api.smoke.test.js
 * API smoke tests for Trust & Verify Express backend.
 * Uses Node.js built-in test runner (node:test) and http module.
 *
 * Run: node --test tests/api.smoke.test.js
 * (Server must NOT already be running on port 3001 when this test runs.)
 *
 * IMPORTANT: Uses a dedicated port (3001) to avoid conflicting with a running
 * dev server on port 3000.
 */

'use strict';

const { test, describe, before, after } = require('node:test');
const assert = require('node:assert/strict');
const http = require('http');
const path = require('path');
const fs = require('fs');

// ─── Inline minimal HTTP request helper ────────────────────────────────────
function httpRequest(options, body) {
  return new Promise((resolve, reject) => {
    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => (data += chunk));
      res.on('end', () => {
        try {
          resolve({ status: res.statusCode, body: JSON.parse(data) });
        } catch (e) {
          resolve({ status: res.statusCode, body: data });
        }
      });
    });
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

function postJSON(path, payload) {
  const body = JSON.stringify(payload);
  return httpRequest(
    {
      hostname: 'localhost',
      port: TEST_PORT,
      path,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body)
      }
    },
    body
  );
}

function postMultipart(urlPath, fieldName, filename, content, contentType) {
  const boundary = '----TrustVerifyTestBoundary';
  const CRLF = '\r\n';

  const header =
    `--${boundary}${CRLF}` +
    `Content-Disposition: form-data; name="${fieldName}"; filename="${filename}"${CRLF}` +
    `Content-Type: ${contentType}${CRLF}${CRLF}`;
  const footer = `${CRLF}--${boundary}--${CRLF}`;

  const bodyBuffer = Buffer.concat([
    Buffer.from(header),
    Buffer.isBuffer(content) ? content : Buffer.from(content),
    Buffer.from(footer)
  ]);

  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        hostname: 'localhost',
        port: TEST_PORT,
        path: urlPath,
        method: 'POST',
        headers: {
          'Content-Type': `multipart/form-data; boundary=${boundary}`,
          'Content-Length': bodyBuffer.length
        }
      },
      (res) => {
        let data = '';
        res.on('data', (c) => (data += c));
        res.on('end', () => {
          try {
            resolve({ status: res.statusCode, body: JSON.parse(data) });
          } catch (e) {
            resolve({ status: res.statusCode, body: data });
          }
        });
      }
    );
    req.on('error', reject);
    req.write(bodyBuffer);
    req.end();
  });
}

// ─── Bring up a test server instance ──────────────────────────────────────
const TEST_PORT = 3001;
let server;

before(async () => {
  // Temporarily set TEST_PORT so server.js picks it up
  process.env.PORT = String(TEST_PORT);
  process.env.NODE_ENV = 'test';

  // Require server — this starts it listening on TEST_PORT
  // We suppress console output from server startup
  const originalLog = console.log;
  console.log = () => {};
  require('../server');
  console.log = originalLog;

  // Give it 200ms to bind
  await new Promise((r) => setTimeout(r, 200));
});

// ─── /api/analyze-headers ──────────────────────────────────────────────────
describe('POST /api/analyze-headers', () => {

  test('valid request returns analysis result', async () => {
    const res = await postJSON('/api/analyze-headers', {
      headers: 'From: "Test User" <user@example.com>\nReceived-SPF: pass'
    });
    assert.equal(res.status, 200);
    assert.ok(typeof res.body.score === 'number');
    assert.ok(typeof res.body.threatLevel === 'string');
    assert.ok(Array.isArray(res.body.logs));
  });

  test('missing headers field returns 400', async () => {
    const res = await postJSON('/api/analyze-headers', {});
    assert.equal(res.status, 400);
    assert.ok(res.body.error, 'Expected error field in response');
  });

  test('headers is not a string returns 400', async () => {
    const res = await postJSON('/api/analyze-headers', { headers: 12345 });
    assert.equal(res.status, 400);
    assert.ok(res.body.error);
  });

  test('extremely large headers payload returns 400', async () => {
    // 70 KB of data — over the 64 KB limit
    const res = await postJSON('/api/analyze-headers', {
      headers: 'X-Custom: ' + 'A'.repeat(70_000)
    });
    // Could be 400 (input validation) or 413 (body-parser size limit)
    assert.ok([400, 413].includes(res.status), `Expected 400 or 413, got ${res.status}`);
  });
});

// ─── /api/scan-file ────────────────────────────────────────────────────────
describe('POST /api/scan-file', () => {

  test('valid text file returns analysis result', async () => {
    const content = 'Hello, this is a plain text file for testing.';
    const res = await postMultipart(
      '/api/scan-file',
      'attachment',
      'test.txt',
      content,
      'text/plain'
    );
    assert.equal(res.status, 200);
    assert.ok(typeof res.body.score === 'number');
    assert.ok(typeof res.body.threatLevel === 'string');
    assert.ok(typeof res.body.hash === 'string');
  });

  test('suspicious script file gets elevated score', async () => {
    const content = 'var s = new WScript.Shell(); s.Run("cmd.exe /c powershell -ep bypass");';
    const res = await postMultipart(
      '/api/scan-file',
      'attachment',
      'malicious.vbs',
      content,
      'text/plain'
    );
    assert.equal(res.status, 200);
    assert.ok(res.body.score >= 75, `Expected elevated score for script, got ${res.body.score}`);
  });

  test('missing file attachment returns 400', async () => {
    // POST with no file
    const body = JSON.stringify({});
    const res = await new Promise((resolve, reject) => {
      const req = http.request(
        {
          hostname: 'localhost',
          port: TEST_PORT,
          path: '/api/scan-file',
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(body)
          }
        },
        (res2) => {
          let data = '';
          res2.on('data', (c) => (data += c));
          res2.on('end', () => resolve({ status: res2.statusCode, body: JSON.parse(data) }));
        }
      );
      req.on('error', reject);
      req.write(body);
      req.end();
    });
    assert.equal(res.status, 400);
    assert.ok(res.body.error);
  });

  test('oversized upload returns 413', async () => {
    // Send 11 MB of data to exceed the 10 MB limit
    const bigContent = Buffer.alloc(11 * 1024 * 1024, 'A');
    const res = await postMultipart(
      '/api/scan-file',
      'attachment',
      'big.bin',
      bigContent,
      'application/octet-stream'
    );
    assert.equal(res.status, 413, `Expected 413 for oversized upload, got ${res.status}`);
    assert.ok(res.body.error, 'Expected JSON error in response');
  });

  test('binary file (null bytes) does not crash the server', async () => {
    // Simulate a binary file: MZ header + null bytes
    const binaryContent = Buffer.from([0x4d, 0x5a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    const res = await postMultipart(
      '/api/scan-file',
      'attachment',
      'test.exe',
      binaryContent,
      'application/octet-stream'
    );
    // Should complete without crashing
    assert.ok([200, 400].includes(res.status), `Expected 200 or 400 for binary, got ${res.status}`);
  });
});

// ─── /api/scan-eml ────────────────────────────────────────────────────────
describe('POST /api/scan-eml', () => {

  const SAMPLE_EML = `From: "Test Sender" <sender@example.com>
To: recipient@example.com
Subject: Test EML for Phase 0 smoke tests
Date: Thu, 24 Sep 2026 10:00:00 +0000
MIME-Version: 1.0
Content-Type: text/plain

This is a test EML file body for smoke testing Trust & Verify Phase 0.
No malicious content.`;

  test('valid EML file returns structured analysis', async () => {
    const res = await postMultipart(
      '/api/scan-eml',
      'emlFile',
      'test.eml',
      SAMPLE_EML,
      'message/rfc822'
    );
    assert.equal(res.status, 200);
    assert.ok(typeof res.body.subject !== 'undefined', 'Expected subject field');
    assert.ok(res.body.headerResults, 'Expected headerResults');
    assert.ok(Array.isArray(res.body.attachments), 'Expected attachments array');
  });

  test('missing EML file returns 400', async () => {
    const body = JSON.stringify({});
    const res = await new Promise((resolve, reject) => {
      const req = http.request(
        {
          hostname: 'localhost',
          port: TEST_PORT,
          path: '/api/scan-eml',
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(body)
          }
        },
        (res2) => {
          let data = '';
          res2.on('data', (c) => (data += c));
          res2.on('end', () => resolve({ status: res2.statusCode, body: JSON.parse(data) }));
        }
      );
      req.on('error', reject);
      req.write(body);
      req.end();
    });
    assert.equal(res.status, 400);
    assert.ok(res.body.error);
  });
});

// ─── Verify temp file cleanup ──────────────────────────────────────────────
describe('Temp file cleanup', () => {

  test('uploads/ directory is empty after successful scan', async () => {
    const uploadsDir = path.join(__dirname, '..', 'uploads');
    const content = 'cleanup verification test content';
    await postMultipart('/api/scan-file', 'attachment', 'cleanup-check.txt', content, 'text/plain');

    // Allow async cleanup to run
    await new Promise((r) => setTimeout(r, 100));
    const files = fs.readdirSync(uploadsDir).filter((f) => !f.startsWith('.'));
    assert.equal(files.length, 0, `Expected 0 temp files, found: ${files.join(', ')}`);
  });
});

console.log('\n[TEST] API smoke tests completed.');
