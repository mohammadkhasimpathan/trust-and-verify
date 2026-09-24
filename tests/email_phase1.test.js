/**
 * tests/email_phase1.test.js
 * Phase 1 unit tests for Trust & Verify Email Threat Scanner.
 * Tests: emailParser.js, domainUtils.js, headerAnalyzer.js (Phase 1 enhancements).
 *
 * Run: node --test tests/email_phase1.test.js
 *
 * IMPORTANT: All test data is synthetic. No real malware, no external requests.
 */

'use strict';

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');

const EmailParser = require('../public/utils/emailParser');
const DomainUtils = require('../public/utils/domainUtils');
const { analyzeHeaders } = require('../public/utils/headerAnalyzer');

// ─── emailParser: parseHeaders ────────────────────────────────────────────────
describe('emailParser.parseHeaders', () => {

  test('parses simple headers correctly', () => {
    const raw = 'From: sender@example.com\nTo: recipient@example.com\n';
    const headers = EmailParser.parseHeaders(raw);
    assert.ok(headers.length >= 2);
    const from = headers.find(h => h.name === 'from');
    assert.ok(from, 'Should have From header');
    assert.equal(from.value.trim(), 'sender@example.com');
  });

  test('handles folded multiline headers as single value', () => {
    const raw = 'Received: from mail.example.com\n\tby mx.example.net\n\twith ESMTP\n\tid ABC123\nFrom: test@example.com\n';
    const headers = EmailParser.parseHeaders(raw);
    const received = headers.find(h => h.name === 'received');
    assert.ok(received, 'Should parse folded Received header');
    assert.ok(received.value.includes('mail.example.com'), 'Value should contain folded content');
    assert.ok(received.value.includes('mx.example.net'), 'Value should include continuation line');
    assert.ok(!received.value.includes('\t'), 'Tab folding should be normalized');
  });

  test('handles CRLF line endings', () => {
    const raw = 'From: test@example.com\r\nTo: other@example.com\r\n';
    const headers = EmailParser.parseHeaders(raw);
    const from = headers.find(h => h.name === 'from');
    assert.ok(from, 'Should parse CRLF headers');
    assert.equal(from.value.trim(), 'test@example.com');
  });

  test('stops parsing at empty line (header/body separator)', () => {
    const raw = 'From: test@example.com\n\nThis is the body\nFake-Header: should-not-appear\n';
    const headers = EmailParser.parseHeaders(raw);
    const fake = headers.find(h => h.name === 'fake-header');
    assert.equal(fake, undefined, 'Should not parse body content as header');
  });

  test('header names are lowercased', () => {
    const raw = 'DKIM-Signature: v=1; d=example.com\nX-CUSTOM: value\n';
    const headers = EmailParser.parseHeaders(raw);
    assert.ok(headers.find(h => h.name === 'dkim-signature'));
    assert.ok(headers.find(h => h.name === 'x-custom'));
  });

  test('returns empty array for null/empty input', () => {
    assert.deepEqual(EmailParser.parseHeaders(''), []);
    assert.deepEqual(EmailParser.parseHeaders(null), []);
  });
});

// ─── emailParser: extractAddress ─────────────────────────────────────────────
describe('emailParser.extractAddress', () => {

  test('extracts address and display name from angle-bracket format', () => {
    const r = EmailParser.extractAddress('"John Doe" <john@example.com>');
    assert.equal(r.displayName, 'John Doe');
    assert.equal(r.address, 'john@example.com');
    assert.equal(r.domain, 'example.com');
  });

  test('extracts bare address without display name', () => {
    const r = EmailParser.extractAddress('john@example.com');
    assert.equal(r.address, 'john@example.com');
    assert.equal(r.domain, 'example.com');
    assert.equal(r.displayName, null);
  });

  test('extracts angle-bracket without display name', () => {
    const r = EmailParser.extractAddress('<john@example.com>');
    assert.equal(r.address, 'john@example.com');
  });

  test('handles null/empty input', () => {
    const r = EmailParser.extractAddress('');
    assert.equal(r.address, null);
  });
});

// ─── emailParser: normalizeDomain ─────────────────────────────────────────────
describe('emailParser.normalizeDomain', () => {

  test('lowercases domain', () => {
    assert.equal(EmailParser.normalizeDomain('EXAMPLE.COM'), 'example.com');
  });

  test('removes trailing dot', () => {
    assert.equal(EmailParser.normalizeDomain('example.com.'), 'example.com');
  });

  test('handles empty/null', () => {
    assert.equal(EmailParser.normalizeDomain(''), '');
    assert.equal(EmailParser.normalizeDomain(null), '');
  });
});

// ─── emailParser: IDN / Punycode / Homograph ─────────────────────────────────
describe('emailParser.analyzeIDN', () => {

  test('detects Punycode domains', () => {
    const r = EmailParser.analyzeIDN('xn--pypal-4ve.com');
    assert.equal(r.isPunycode, true);
  });

  test('detects Cyrillic homograph', () => {
    // Cyrillic 'а' (U+0430) in place of Latin 'a'
    const r = EmailParser.analyzeIDN('p\u0430ypal.com');
    assert.ok(r.homographs.length > 0, 'Should detect Cyrillic homograph');
    assert.equal(r.homographs[0].unicode, 'U+0430');
    assert.equal(r.homographs[0].lookalike, 'a');
  });

  test('clean ASCII domain produces no homographs', () => {
    const r = EmailParser.analyzeIDN('example.com');
    assert.equal(r.homographs.length, 0);
    assert.equal(r.isPunycode, false);
    assert.equal(r.isNonASCII, false);
  });

  test('non-ASCII domain is flagged', () => {
    const r = EmailParser.analyzeIDN('exàmple.com');
    assert.equal(r.isNonASCII, true);
  });
});

// ─── emailParser: IP validation ───────────────────────────────────────────────
describe('emailParser: IP validation', () => {

  test('classifies valid IPv4', () => {
    assert.equal(EmailParser.classifyIP('203.0.113.10'), 'ipv4');
  });

  test('classifies valid IPv6', () => {
    assert.equal(EmailParser.classifyIP('::1'), 'ipv6');
    assert.equal(EmailParser.classifyIP('2001:db8::1'), 'ipv6');
  });

  test('returns null for invalid IP', () => {
    assert.equal(EmailParser.classifyIP('not-an-ip'), null);
    assert.equal(EmailParser.classifyIP('999.999.999.999'), null);
  });

  test('validates each octet for IPv4', () => {
    assert.equal(EmailParser.isValidIPv4('256.0.0.1'), false);
    assert.equal(EmailParser.isValidIPv4('192.168.1.1'), true);
  });
});

// ─── emailParser: URL extraction ──────────────────────────────────────────────
describe('emailParser.extractURLs', () => {

  test('extracts http and https URLs', () => {
    const text = 'Visit https://example.com and http://another.com/path?q=1';
    const urls = EmailParser.extractURLs(text);
    assert.ok(urls.includes('https://example.com'));
    assert.ok(urls.includes('http://another.com/path?q=1'));
  });

  test('deduplicates URLs', () => {
    const text = 'https://example.com https://example.com';
    const urls = EmailParser.extractURLs(text);
    assert.equal(urls.filter(u => u === 'https://example.com').length, 1);
  });

  test('returns empty array for text with no URLs', () => {
    assert.deepEqual(EmailParser.extractURLs('No links here'), []);
    assert.deepEqual(EmailParser.extractURLs(''), []);
  });
});

// ─── emailParser: Received header parsing ────────────────────────────────────
describe('emailParser.parseReceivedHeader', () => {

  test('extracts from, by, and IP', () => {
    const val = 'from mail.example.com (mail.example.com [203.0.113.5]) by mx.target.com with ESMTP; Thu, 24 Sep 2026 09:00:00 +0000';
    const r = EmailParser.parseReceivedHeader(val, 1);
    assert.equal(r.from, 'mail.example.com');
    assert.equal(r.by, 'mx.target.com');
    assert.equal(r.ip, '203.0.113.5');
    assert.equal(r.hopNumber, 1);
  });

  test('handles missing fields gracefully', () => {
    const r = EmailParser.parseReceivedHeader('minimal received header', 2);
    assert.equal(r.from, null);
    assert.equal(r.hopNumber, 2);
  });
});

// ─── domainUtils: brand impersonation ────────────────────────────────────────
describe('domainUtils.detectBrandImpersonation', () => {

  test('detects display name brand spoofing', () => {
    const result = DomainUtils.detectBrandImpersonation({
      displayName: 'PayPal Support',
      domain: 'attacker-scam-portal.com'
    });
    assert.ok(result.length > 0, 'Should detect brand spoofing');
    assert.equal(result[0].brand, 'PayPal');
    assert.equal(result[0].type, 'display_name_mismatch');
  });

  test('does NOT flag legitimate PayPal domain', () => {
    const result = DomainUtils.detectBrandImpersonation({
      displayName: 'PayPal',
      domain: 'paypal.com'
    });
    assert.equal(result.length, 0, 'paypal.com should not be flagged');
  });

  test('detects PayPal subdomain legitimately', () => {
    const result = DomainUtils.detectBrandImpersonation({
      displayName: 'PayPal',
      domain: 'mail.paypal.com'
    });
    assert.equal(result.length, 0, 'mail.paypal.com is authoritative and should not be flagged');
  });

  test('detects reverse subdomain trick', () => {
    const result = DomainUtils.detectBrandImpersonation({
      displayName: 'PayPal',
      domain: 'paypal.com.attacker.net'
    });
    assert.ok(result.length > 0, 'Should detect reverse subdomain trick');
    assert.equal(result[0].type, 'reverse_subdomain');
  });

  test('detects domain keyword impersonation without display name match', () => {
    const result = DomainUtils.detectBrandImpersonation({
      displayName: 'Account Services',
      domain: 'microsoftsecurity-alert.com'
    });
    assert.ok(result.some(r => r.brand === 'Microsoft'), 'Should flag Microsoft keyword in domain');
  });

  test('does NOT flag Google domain for Google keyword', () => {
    const result = DomainUtils.detectBrandImpersonation({
      displayName: 'Google Security',
      domain: 'accounts.google.com'
    });
    assert.equal(result.length, 0);
  });

  test('returns empty array for null input', () => {
    const result = DomainUtils.detectBrandImpersonation(null);
    assert.deepEqual(result, []);
  });
});

// ─── domainUtils: Authentication-Results parsing ─────────────────────────────
describe('domainUtils.parseAuthResults', () => {

  test('parses spf=pass, dkim=pass, dmarc=pass', () => {
    const r = DomainUtils.parseAuthResults('mx.example.com; spf=pass smtp.mailfrom=test@example.com; dkim=pass header.d=example.com; dmarc=pass');
    assert.equal(r.spf, 'pass');
    assert.equal(r.dkim, 'pass');
    assert.equal(r.dmarc, 'pass');
  });

  test('parses spf=fail, dkim=fail, dmarc=fail', () => {
    const r = DomainUtils.parseAuthResults('mx.example.com; spf=fail; dkim=fail; dmarc=fail');
    assert.equal(r.spf, 'fail');
    assert.equal(r.dkim, 'fail');
    assert.equal(r.dmarc, 'fail');
  });

  test('parses spf=softfail separately from fail', () => {
    const r = DomainUtils.parseAuthResults('mx.example.com; spf=softfail');
    assert.equal(r.spf, 'softfail');
  });

  test('extracts DKIM signing domain', () => {
    const r = DomainUtils.parseAuthResults('mx.x.com; dkim=pass header.d=sendgrid.net');
    assert.equal(r.dkimDomain, 'sendgrid.net');
  });

  test('returns nulls for empty string', () => {
    const r = DomainUtils.parseAuthResults('');
    assert.equal(r.spf, null);
    assert.equal(r.dkim, null);
    assert.equal(r.dmarc, null);
  });
});

// ─── domainUtils: SPF/DKIM/DMARC score weights ───────────────────────────────
describe('domainUtils: score weights', () => {

  test('SPF softfail scores less than SPF fail', () => {
    assert.ok(DomainUtils.spfScore('softfail') < DomainUtils.spfScore('fail'), 'softfail < fail');
  });

  test('SPF pass scores 0', () => {
    assert.equal(DomainUtils.spfScore('pass'), 0);
  });

  test('DKIM pass scores 0', () => {
    assert.equal(DomainUtils.dkimScore('pass'), 0);
  });

  test('DMARC pass scores 0', () => {
    assert.equal(DomainUtils.dmarcScore('pass'), 0);
  });

  test('DKIM fail scores non-zero', () => {
    assert.ok(DomainUtils.dkimScore('fail') > 0);
  });

  test('DMARC fail scores non-zero', () => {
    assert.ok(DomainUtils.dmarcScore('fail') > 0);
  });
});

// ─── headerAnalyzer: Phase 1 features ────────────────────────────────────────
describe('analyzeHeaders (Phase 1)', () => {

  // Helper to build a header block
  function h(fields) {
    return Object.entries(fields).map(([k, v]) => `${k}: ${v}`).join('\n');
  }

  test('returns extended Phase 1 fields', () => {
    const r = analyzeHeaders(h({ From: 'test@example.com' }));
    assert.ok(Array.isArray(r.findings), 'Should have findings[]');
    assert.ok(Array.isArray(r.parsedHeaders), 'Should have parsedHeaders[]');
    assert.ok(typeof r.authentication === 'object', 'Should have authentication{}');
    assert.ok(typeof r.routing === 'object', 'Should have routing{}');
    assert.ok(Array.isArray(r.links), 'Should have links[]');
  });

  test('Reply-To vs From mismatch is detected and flagged', () => {
    const r = analyzeHeaders(h({
      From: 'support@company.com',
      'Reply-To': 'harvest@attacker-redirector.net'
    }));
    const f = r.findings.find(f => f.title.includes('Reply-To Domain Mismatch'));
    assert.ok(f, 'Should have Reply-To mismatch finding');
    assert.ok(f.evidence.includes('company.com'), 'Evidence should include From domain');
    assert.ok(f.evidence.includes('attacker-redirector.net'), 'Evidence should include Reply-To domain');
    assert.ok(f.recommendation, 'Finding should have recommendation');
  });

  test('Reply-To same as From domain is NOT flagged', () => {
    const r = analyzeHeaders(h({
      From: 'support@company.com',
      'Reply-To': 'billing@company.com'
    }));
    const f = r.findings.find(f => f.title.includes('Reply-To Domain Mismatch'));
    assert.equal(f, undefined, 'Same-domain Reply-To should not be flagged');
  });

  test('Return-Path cross-domain mismatch is flagged (LOW severity)', () => {
    const r = analyzeHeaders(h({
      From: 'billing@company.com',
      'Return-Path': '<bounce@external-mailer.net>'
    }));
    const f = r.findings.find(f => f.title.includes('Return-Path Domain Mismatch'));
    assert.ok(f, 'Should have Return-Path mismatch finding');
    assert.equal(f.severity, 'LOW', 'Return-Path mismatch should be LOW severity');
    assert.ok(f.explanation.includes('Legitimate bulk mailers'), 'Should acknowledge legitimate use');
  });

  test('SPF softfail produces MEDIUM severity, not HIGH', () => {
    const r = analyzeHeaders(h({
      From: 'test@example.com',
      'Authentication-Results': 'mx.x.com; spf=softfail smtp.mailfrom=test@example.com; dkim=pass'
    }));
    const f = r.findings.find(f => f.title.includes('SPF Soft Failure'));
    assert.ok(f, 'Should have SPF softfail finding');
    assert.equal(f.severity, 'MEDIUM', 'SPF softfail should be MEDIUM not HIGH');
    assert.ok(r.score < 30, `Softfail score should be lower than hard fail, got ${r.score}`);
  });

  test('SPF fail produces HIGH severity', () => {
    const r = analyzeHeaders(h({
      From: 'test@example.com',
      'Authentication-Results': 'mx.x.com; spf=fail smtp.mailfrom=test@example.com'
    }));
    const f = r.findings.find(f => f.title.includes('SPF Authentication Failed'));
    assert.ok(f, 'Should have SPF fail finding');
    assert.equal(f.severity, 'HIGH');
  });

  test('SPF fail scores higher than SPF softfail', () => {
    const rFail = analyzeHeaders(h({
      From: 'a@x.com',
      'Authentication-Results': 'mx.x.com; spf=fail'
    }));
    const rSoft = analyzeHeaders(h({
      From: 'a@x.com',
      'Authentication-Results': 'mx.x.com; spf=softfail'
    }));
    assert.ok(rFail.score > rSoft.score, `fail score (${rFail.score}) should exceed softfail (${rSoft.score})`);
  });

  test('DKIM fail produces HIGH severity finding', () => {
    const r = analyzeHeaders(h({
      From: 'test@example.com',
      'Authentication-Results': 'mx.x.com; dkim=fail'
    }));
    const f = r.findings.find(f => f.title.includes('DKIM Signature Verification Failed'));
    assert.ok(f, 'Should have DKIM fail finding');
    assert.equal(f.severity, 'HIGH');
  });

  test('DKIM third-party signing is INFO only (legitimate)', () => {
    const r = analyzeHeaders(h({
      From: 'newsletter@company.com',
      'Authentication-Results': 'mx.x.com; dkim=pass header.d=sendgrid.net'
    }));
    const f = r.findings.find(f => f.title.includes('DKIM Signed by Third-Party'));
    assert.ok(f, 'Should note third-party DKIM signing');
    assert.equal(f.severity, 'INFO', 'Third-party DKIM signing should be INFO only');
  });

  test('DMARC fail produces HIGH severity finding', () => {
    const r = analyzeHeaders(h({
      From: 'test@example.com',
      'Authentication-Results': 'mx.x.com; dmarc=fail'
    }));
    const f = r.findings.find(f => f.title.includes('DMARC Alignment Failed'));
    assert.ok(f, 'Should have DMARC fail finding');
    assert.equal(f.severity, 'HIGH');
  });

  test('findings include evidence, explanation, and recommendation', () => {
    const r = analyzeHeaders(h({
      From: 'support@company.com',
      'Reply-To': 'harvest@attacker.net',
      'Authentication-Results': 'mx.x.com; spf=fail; dkim=fail; dmarc=fail'
    }));
    for (const f of r.findings) {
      assert.ok(f.evidence !== undefined, `Finding "${f.title}" should have evidence`);
      assert.ok(f.explanation !== undefined, `Finding "${f.title}" should have explanation`);
      assert.ok(f.recommendation !== undefined, `Finding "${f.title}" should have recommendation`);
    }
  });

  test('Received header chain is analyzed', () => {
    const headers = `From: test@example.com
Received: from mail.example.com (mail.example.com [203.0.113.5]) by mx.target.com with ESMTP
Received: from dynamic.dialup.user.isp.net (dynamic.dialup.user.isp.net [198.51.100.22]) by mail.example.com`;
    const r = analyzeHeaders(headers);
    assert.ok(r.routing.hops.length >= 2, 'Should parse multiple Received headers');
    const suspiciousHop = r.routing.hops.find(h => h.suspicious);
    assert.ok(suspiciousHop, 'Should detect suspicious dynamic hop');
  });

  test('X-Originating-IP is extracted when present', () => {
    const r = analyzeHeaders(h({
      From: 'test@example.com',
      'X-Originating-IP': '203.0.113.42'
    }));
    assert.equal(r.routing.originatingIP, '203.0.113.42');
  });

  test('X-Originating-IP absent is handled gracefully', () => {
    const r = analyzeHeaders(h({ From: 'test@example.com' }));
    assert.equal(r.routing.originatingIP, null);
  });

  test('IDN homograph domain is detected and scored', () => {
    // Cyrillic 'а' at start — looks like PayPal but with Cyrillic characters
    const r = analyzeHeaders(h({ From: `test@p\u0430ypal.com` }));
    const f = r.findings.find(f => f.title.includes('Unicode Homograph'));
    assert.ok(f, 'Should detect homograph in domain');
    assert.ok(f.severity === 'HIGH', 'Homograph should be HIGH severity');
    assert.ok(f.evidence.includes('U+0430'));
  });

  test('clean ASCII domain produces no IDN findings', () => {
    const r = analyzeHeaders(h({ From: 'test@example.com' }));
    const f = r.findings.find(f => f.category === 'DOMAIN' && f.title.includes('Homograph'));
    assert.equal(f, undefined, 'Clean domain should produce no IDN findings');
  });

  test('URL extraction works from header text', () => {
    const raw = `From: test@example.com\nX-Custom: visit https://example.com/path`;
    const r = analyzeHeaders(raw);
    assert.ok(r.links.includes('https://example.com/path'), 'Should extract URL from header value');
  });

  test('score is always between 0 and 100', () => {
    const worstCase = `From: "PayPal" <phish@attacker.net>
Reply-To: harvest@evil.net
Authentication-Results: mx.x.com; spf=fail; dkim=fail; dmarc=fail
Received: from localhost by localhost;
Received: from dynamic.dialup by mx;`;
    const r = analyzeHeaders(worstCase);
    assert.ok(r.score >= 0, 'Score should be >= 0');
    assert.ok(r.score <= 100, 'Score should be <= 100');
  });

  test('folded Received header is treated as single logical header', () => {
    const raw = `From: test@example.com
Received: from mail.example.com
\tby mx.example.net
\twith ESMTP
\tid ABC123`;
    const r = analyzeHeaders(raw);
    assert.equal(r.routing.hops.length, 1, 'Folded Received should be treated as single hop');
    assert.ok(r.routing.hops[0].from, 'from field should be extracted');
  });

  // ── False positive tests ──────────────────────────────────────────────────

  test('legitimate Google email scores safe', () => {
    const headers = `From: "Google" <no-reply@accounts.google.com>
To: user@gmail.com
Authentication-Results: mx.google.com; spf=pass; dkim=pass header.d=google.com; dmarc=pass
DKIM-Signature: v=1; a=rsa-sha256; d=google.com; s=abc;`;
    const r = analyzeHeaders(headers);
    assert.ok(r.score < 25, `Google email should score safe, got ${r.score}`);
    assert.ok(['Safe', 'Low'].includes(r.threatLevel));
  });

  test('legitimate Mailchimp third-party sender does not score Critical', () => {
    const headers = `From: "Newsletter" <newsletter@company.com>
Reply-To: unsubscribe@list.company.com
Return-Path: <bounce-id@mcsv.net>
Authentication-Results: mx.x.com; spf=pass smtp.mailfrom=bounce-id@mcsv.net; dkim=pass header.d=mcsv.net; dmarc=pass`;
    const r = analyzeHeaders(headers);
    assert.ok(r.threatLevel !== 'Critical', `Mailchimp sender should not score Critical, got ${r.threatLevel}`);
  });

  test('SPF softfail alone does not produce Critical score', () => {
    const r = analyzeHeaders(h({
      From: 'test@example.com',
      'Authentication-Results': 'mx.x.com; spf=softfail'
    }));
    assert.notEqual(r.threatLevel, 'Critical', 'SPF softfail alone should not be Critical');
  });

  test('different-domain Reply-To alone does not produce High score', () => {
    const r = analyzeHeaders(h({
      From: 'newsletter@company.com',
      'Reply-To': 'noreply@mailplatform.com',
      'Authentication-Results': 'mx.x.com; spf=pass; dkim=pass'
    }));
    assert.ok(r.score < 45, `Reply-To mismatch alone should not be High, got ${r.score}`);
  });
});

// ─── Regression: backward-compatible fields ───────────────────────────────────
describe('analyzeHeaders backward compatibility', () => {

  test('returns threatLevel string', () => {
    const r = analyzeHeaders('From: test@example.com');
    assert.ok(typeof r.threatLevel === 'string');
  });

  test('returns numeric score', () => {
    const r = analyzeHeaders('From: test@example.com');
    assert.ok(typeof r.score === 'number');
  });

  test('returns logs array', () => {
    const r = analyzeHeaders('From: test@example.com');
    assert.ok(Array.isArray(r.logs));
  });

  test('returns details array (backward compat)', () => {
    const r = analyzeHeaders(`From: test@example.com
Authentication-Results: mx.x.com; spf=fail`);
    assert.ok(Array.isArray(r.details));
    // details[] items should still have type/title/message
    if (r.details.length > 0) {
      const d = r.details[0];
      assert.ok('type' in d);
      assert.ok('title' in d);
      assert.ok('message' in d);
    }
  });

  test('null headers still returns Unknown', () => {
    const r = analyzeHeaders(null);
    assert.equal(r.threatLevel, 'Unknown');
    assert.equal(r.score, 0);
  });
});

console.log('\n[TEST] Email Phase 1 unit tests completed.');
