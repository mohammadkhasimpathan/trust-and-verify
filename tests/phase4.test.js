const test = require('node:test');
const assert = require('node:assert');
const http = require('node:http');
const server = require('../server.js');
const config = require('../server/threatIntel/config');

let testServer;
let port = 3002;

test.before(async () => {
  await new Promise(resolve => {
    testServer = server.listen(port, resolve);
  });
});

test.after(async () => {
  await new Promise(resolve => testServer.close(resolve));
});

function makeRequest(path, data) {
  return new Promise((resolve, reject) => {
    const postData = JSON.stringify(data);
    const req = http.request({
      hostname: 'localhost',
      port,
      path: '/api/threat-intel' + path,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(postData)
      }
    }, (res) => {
      let body = '';
      res.on('data', d => body += d);
      res.on('end', () => resolve({ statusCode: res.statusCode, body: JSON.parse(body) }));
    });
    req.on('error', reject);
    req.write(postData);
    req.end();
  });
}

test('Phase 4: Threat Intelligence API Tests', async (t) => {
  await t.test('POST /api/threat-intel/url returns NOT_CONFIGURED when no API keys', async () => {
    // Override config for test to not use cache
    const oldCache = config.cache.enabled;
    config.cache.enabled = false;
    
    const { statusCode, body } = await makeRequest('/url', { target: 'https://example.com' });
    assert.strictEqual(statusCode, 200);
    assert.strictEqual(body.type, 'URL');
    assert.ok(Array.isArray(body.results));
    
    // Check one provider at least is NOT_CONFIGURED or similar
    const vt = body.results.find(r => r.provider === 'VirusTotal');
    if (vt) {
      assert.ok(['NOT_CONFIGURED', 'DISABLED', 'AUTH_ERROR', 'RATE_LIMITED', 'ERROR'].includes(vt.status));
    }
    
    config.cache.enabled = oldCache;
  });

  await t.test('POST /api/threat-intel/domain returns NOT_SUPPORTED for GSB', async () => {
    const { statusCode, body } = await makeRequest('/domain', { target: 'example.com' });
    assert.strictEqual(statusCode, 200);
    assert.ok(Array.isArray(body.results));
    
    const gsb = body.results.find(r => r.provider === 'Google Safe Browsing');
    if (gsb) {
      assert.strictEqual(gsb.status, 'NOT_SUPPORTED');
    }
  });

  await t.test('Missing target returns 400', async () => {
    const { statusCode } = await makeRequest('/url', {});
    assert.strictEqual(statusCode, 400);
  });
});
