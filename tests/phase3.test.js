'use strict';

const { test, describe, before, after } = require('node:test');
const assert = require('node:assert/strict');
const http = require('http');
const app = require('../server');

const UrlAnalyzer = require('../public/utils/urlAnalyzer');
const DomainAnalyzer = require('../public/utils/domainAnalyzer');

describe('Phase 3 Analyzers', () => {
  test('UrlAnalyzer: detects insecure HTTP', () => {
    const res = UrlAnalyzer.analyze('http://example.com');
    assert(res.indicators.some(i => i.id === 'INSECURE_HTTP'));
  });

  test('UrlAnalyzer: detects IP hostname', () => {
    const res = UrlAnalyzer.analyze('https://192.168.1.1');
    assert(res.indicators.some(i => i.id === 'IP_HOSTNAME'));
  });

  test('DomainAnalyzer: extracts registrable domain', () => {
    const res = DomainAnalyzer.analyze('sub.example.com');
    assert.strictEqual(res.registrableDomain, 'example.com');
  });

  test('DomainAnalyzer: detects Punycode', () => {
    const res = DomainAnalyzer.analyze('xn--e1awd7f.com');
    assert(res.indicators.some(i => i.id === 'PUNYCODE_DOMAIN'));
  });
});

describe('Phase 3 SSL API', () => {
  let server;
  let port = 3005;

  before((done) => {
    server = app.listen(port, done);
  });

  after((done) => {
    server.close(done);
  });

  test('POST /api/inspect-ssl blocks localhost (SSRF)', () => {
    return new Promise((resolve, reject) => {
      const postData = JSON.stringify({ hostname: 'localhost' });
      
      const options = {
        hostname: 'localhost',
        port: port,
        path: '/api/inspect-ssl',
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(postData)
        }
      };
      
      const req = http.request(options, (res) => {
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => {
          assert.strictEqual(res.statusCode, 403);
          assert.match(data, /SSRF/i);
          resolve();
        });
      });
      
      req.on('error', reject);
      req.write(postData);
      req.end();
    });
  });
});
