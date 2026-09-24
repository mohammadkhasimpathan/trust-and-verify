/**
 * tests/analyzers.test.js
 * Unit tests for Trust & Verify analyzer utilities.
 * Uses Node.js built-in test runner (node:test) — no external test framework needed.
 *
 * Run: node --test tests/analyzers.test.js
 *
 * IMPORTANT: All test data is synthetic.
 * No real malicious files, malware samples, or attack infrastructure are used.
 */

'use strict';

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');

const { analyzeHeaders } = require('../public/utils/headerAnalyzer');
const { analyzeFile, THREAT_HASHES } = require('../public/utils/fileScanner');
const { analyzeSMS } = require('../public/utils/smsAnalyzer');
const { analyzePhoneNumber, CALLED_BLACKLIST } = require('../public/utils/callScanner');

// ─── EMAIL HEADER ANALYZER ──────────────────────────────────────────────────
describe('analyzeHeaders', () => {

  test('safe corporate email returns low score', () => {
    const headers = `From: "Google Workspace Team" <workspace-noreply@google.com>
To: user@gmail.com
Subject: Monthly report
Received: from mail.google.com (209.85.220.41) by mx.google.com;
Received-SPF: pass (google.com: domain of workspace-noreply@google.com designates 209.85.220.41 as permitted sender)
Authentication-Results: mx.google.com; dkim=pass header.i=@google.com; dmarc=pass`;
    const result = analyzeHeaders(headers);
    assert.ok(result.score < 25, `Expected score < 25, got ${result.score}`);
    assert.equal(result.threatLevel, 'Safe');
  });

  test('SPF failure increases score and returns at least Medium', () => {
    const headers = `From: "Microsoft Security Center" <no-reply@microsoft.com>
Received: from malicious.phishing.net (203.0.113.88) by exchange.company.com;
Received-SPF: fail (exchange.company.com: domain of microsoft.com does not designate 203.0.113.88 as authorized sender)
Authentication-Results: exchange.company.com; dkim=fail header.i=@microsoft.com; dmarc=fail`;
    const result = analyzeHeaders(headers);
    assert.ok(result.score >= 25, `Expected score >= 25 for SPF fail, got ${result.score}`);
    assert.ok(['Medium', 'High', 'Critical'].includes(result.threatLevel));
  });

  test('DKIM failure is flagged in details', () => {
    const headers = `From: "Someone" <user@example.com>
Authentication-Results: mx.example.com; dkim=fail`;
    const result = analyzeHeaders(headers);
    const dkimFinding = result.details.some(d => d.title.includes('DKIM'));
    assert.ok(dkimFinding, 'Expected a DKIM-related finding');
  });

  test('DMARC failure is flagged in details', () => {
    const headers = `From: "Someone" <user@example.com>
Authentication-Results: mx.example.com; dmarc=fail`;
    const result = analyzeHeaders(headers);
    const dmarcFinding = result.details.some(d => d.title.includes('DMARC'));
    assert.ok(dmarcFinding, 'Expected a DMARC-related finding');
  });

  test('display name spoofing (PayPal brand, unrelated domain) returns danger finding', () => {
    // The From domain must NOT contain the brand keyword for spoofing to trigger.
    // 'attacker-scam-portal.com' does not contain 'paypal'.
    const headers = `From: "PayPal Account Security" <verification@attacker-scam-portal.com>
Received-SPF: softfail`;
    const result = analyzeHeaders(headers);
    const spoofFinding = result.details.some(d => d.title.includes('Spoofing'));
    assert.ok(spoofFinding, 'Expected a Display Name Spoofing finding');
    assert.ok(result.score >= 35, `Expected score >= 35, got ${result.score}`);
  });

  test('empty headers returns Unknown threat level and score 0', () => {
    const result = analyzeHeaders('');
    assert.equal(result.threatLevel, 'Unknown');
    assert.equal(result.score, 0);
  });

  test('null headers returns Unknown threat level', () => {
    const result = analyzeHeaders(null);
    assert.equal(result.threatLevel, 'Unknown');
  });

  test('result has required fields', () => {
    const result = analyzeHeaders('From: user@example.com');
    assert.ok(Array.isArray(result.logs));
    assert.ok(Array.isArray(result.details));
    assert.ok(typeof result.score === 'number');
    assert.ok(typeof result.threatLevel === 'string');
  });

  test('score is capped at 100', () => {
    // Construct headers with many failure signals
    const headers = `From: "PayPal" <phish@attack.com>
Received-SPF: fail
Authentication-Results: mx.x.com; dkim=fail; dmarc=fail; spf=fail
Received: from localhost by localhost;
Received: from dynamic.dialup.isp by mx.x.com;`;
    const result = analyzeHeaders(headers);
    assert.ok(result.score <= 100, `Score must be <= 100, got ${result.score}`);
  });
});

// ─── FILE SCANNER ───────────────────────────────────────────────────────────
describe('analyzeFile', () => {

  test('safe PDF filename returns low score', () => {
    const result = analyzeFile('quarterly-report.pdf', 'Hello World document content', '');
    assert.ok(result.score < 25, `Expected score < 25 for PDF, got ${result.score}`);
    assert.equal(result.threatLevel, 'Safe');
  });

  test('executable extension (.exe) returns Critical score', () => {
    const result = analyzeFile('invoice.exe', '', '');
    assert.ok(result.score >= 75, `Expected Critical score for .exe, got ${result.score}`);
    assert.equal(result.threatLevel, 'Critical');
  });

  test('script extension (.ps1) returns Critical score', () => {
    const result = analyzeFile('setup.ps1', '', '');
    assert.ok(result.score >= 75, `Expected Critical score for .ps1, got ${result.score}`);
  });

  test('macro-enabled document (.docm) returns at least Medium', () => {
    const result = analyzeFile('report.docm', '', '');
    assert.ok(result.score >= 25, `Expected >= Medium for .docm, got ${result.score}`);
  });

  test('suspicious content (WScript.Shell) is flagged', () => {
    const result = analyzeFile('run.vbs', 'var s = new ActiveXObject("WScript.Shell"); s.Run("cmd");', '');
    const finding = result.details.some(d => d.title.includes('WScript'));
    assert.ok(finding, 'Expected WScript.Shell pattern to be flagged');
  });

  test('known threat hash returns score 100', () => {
    const knownHash = Object.keys(THREAT_HASHES)[0];
    const result = analyzeFile('sample.exe', '', knownHash);
    assert.equal(result.score, 100);
    assert.equal(result.threatLevel, 'Critical');
  });

  test('unknown hash does not trigger hash match finding', () => {
    const result = analyzeFile('document.txt', 'plain text content', 'aabbccdd00112233');
    const hashFinding = result.details.some(d => d.title.includes('Signature Match'));
    assert.ok(!hashFinding, 'Unknown hash should not trigger a signature match');
  });

  test('missing filename returns Unknown', () => {
    const result = analyzeFile('', '', '');
    assert.equal(result.threatLevel, 'Unknown');
  });

  test('result has required fields', () => {
    const result = analyzeFile('test.txt', 'content', '');
    assert.ok(Array.isArray(result.logs));
    assert.ok(Array.isArray(result.details));
    assert.ok(typeof result.score === 'number');
    assert.ok(typeof result.threatLevel === 'string');
  });

  test('binary-like content (null byte) does not crash the analyzer', () => {
    // Simulate what happens when binary content is passed as a string
    const binaryLike = 'MZ\x00\x00\x00\x00\x00PK\x00\x00corrupt binary data';
    assert.doesNotThrow(() => {
      analyzeFile('binary.bin', binaryLike, '');
    });
  });
});

// ─── SMS ANALYZER ───────────────────────────────────────────────────────────
describe('analyzeSMS', () => {

  test('safe friendly text returns Safe', () => {
    const result = analyzeSMS('Hey! Want to grab coffee later today?');
    assert.equal(result.threatLevel, 'Safe');
    assert.equal(result.score, 0);
  });

  test('phishing URL in SMS is flagged', () => {
    const result = analyzeSMS('Your account is suspended! Click here: https://bit.ly/verify-now');
    assert.ok(result.score >= 25, `Expected score >= 25 for phishing SMS`);
  });

  test('urgency keywords increase score', () => {
    const result = analyzeSMS('IMMEDIATE ACTION REQUIRED: verify now or account will lock in 24h');
    assert.ok(result.score >= 15, `Expected urgency to increase score`);
  });

  test('brand impersonation (PayPal) is flagged', () => {
    const result = analyzeSMS('PayPal: Unauthorized login detected. Verify at link.');
    const finding = result.details.some(d => d.title.includes('Brand Impersonation'));
    assert.ok(finding, 'Expected brand impersonation finding');
  });

  test('empty SMS returns Unknown', () => {
    const result = analyzeSMS('');
    assert.equal(result.threatLevel, 'Unknown');
  });

  test('result has required fields', () => {
    const result = analyzeSMS('Test message');
    assert.ok(Array.isArray(result.logs));
    assert.ok(Array.isArray(result.details));
    assert.ok(typeof result.score === 'number');
    assert.ok(typeof result.threatLevel === 'string');
  });

  test('score is capped at 100', () => {
    const result = analyzeSMS(
      'kill yourself kys you loser idiot worthless freak or else expose you know where you live track you leak your https://bit.ly/x urgent action required pay now suspend'
    );
    assert.ok(result.score <= 100, `Score must be <= 100, got ${result.score}`);
  });
});

// ─── PHONE SCANNER ──────────────────────────────────────────────────────────
describe('analyzePhoneNumber', () => {

  test('known blacklisted number returns score 100 and Critical', () => {
    const blacklistedNumber = Object.keys(CALLED_BLACKLIST)[0];
    const result = analyzePhoneNumber(blacklistedNumber);
    assert.equal(result.score, 100);
    assert.equal(result.threatLevel, 'Critical');
    assert.ok(result.callerProfile, 'Should have a caller profile for blacklisted number');
  });

  test('unknown clean number returns Safe', () => {
    const result = analyzePhoneNumber('+12125551234');
    assert.ok(result.score < 25, `Expected safe score for unknown number, got ${result.score}`);
    assert.equal(result.threatLevel, 'Safe');
  });

  test('toll-free VoIP prefix increases score', () => {
    const result = analyzePhoneNumber('+18005559999');
    assert.ok(result.score >= 35, `Expected elevated score for toll-free VoIP, got ${result.score}`);
  });

  test('empty number returns Unknown', () => {
    const result = analyzePhoneNumber('');
    assert.equal(result.threatLevel, 'Unknown');
    assert.equal(result.score, 0);
  });

  test('result has required fields', () => {
    const result = analyzePhoneNumber('+12125551234');
    assert.ok(Array.isArray(result.logs));
    assert.ok(Array.isArray(result.details));
    assert.ok(typeof result.score === 'number');
    assert.ok(typeof result.threatLevel === 'string');
  });
});

console.log('\n[TEST] All analyzer unit tests completed.');
