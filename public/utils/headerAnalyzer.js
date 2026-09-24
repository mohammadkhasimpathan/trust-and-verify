/**
 * headerAnalyzer.js
 * Email header analysis engine for Trust & Verify.
 *
 * Phase 1 additions:
 *  - RFC 5322-correct folded header parsing (delegates to emailParser.js)
 *  - Reply-To vs From domain mismatch detection
 *  - Return-Path vs From domain mismatch detection
 *  - Structured Authentication-Results parsing (spf / dkim / dmarc individually)
 *  - Calibrated SPF scoring: softfail (15) vs fail (30) — no longer identical
 *  - DKIM signing domain vs From domain comparison
 *  - DKIM-Signature field extraction (d=, s=, a=, c=)
 *  - Received header chain analysis (hops, IPs, timestamps, suspicious patterns)
 *  - X-Originating-IP extraction and IP validation
 *  - IDN / Punycode / homograph detection on sender domain
 *  - Improved brand impersonation (structured brand definitions, domain tricks)
 *  - URL extraction from header text
 *  - Structured findings with severity / evidence / explanation / recommendation
 *  - Explainable scoring (score += per-indicator contributions listed)
 *  - Backward-compatible return shape (score, threatLevel, logs, details)
 *  - Extended return shape (parsedHeaders, authentication, routing, links, findings)
 *
 * HEURISTIC ANALYSIS ONLY.
 * No DNS lookups, no external APIs, no network connections are made.
 * All verdicts are educational simulations based on header text analysis.
 */

'use strict';

// ─── Dependency Loading ───────────────────────────────────────────────────────
// Support both Node.js (require) and browser (globals injected via script tags)
let EmailParser, DomainUtils;

if (typeof require === 'function') {
  try {
    EmailParser = require('./emailParser');
    DomainUtils = require('./domainUtils');
  } catch (e) {
    // If running in browser without bundler, fall back to globals
    EmailParser = (typeof window !== 'undefined') ? window.EmailParser : null;
    DomainUtils = (typeof window !== 'undefined') ? window.DomainUtils : null;
  }
} else {
  EmailParser = window.EmailParser;
  DomainUtils = window.DomainUtils;
}

// ─── Finding Builder ──────────────────────────────────────────────────────────

/**
 * Build a structured finding object.
 * @param {Object} opts
 * @returns {{ severity, category, title, evidence, explanation, recommendation, type }}
 */
function mkFinding(opts) {
  return {
    severity:       opts.severity || 'MEDIUM',     // INFO | LOW | MEDIUM | HIGH | CRITICAL
    category:       opts.category || 'IDENTITY',   // AUTHENTICATION | IDENTITY | ROUTING | DOMAIN | ATTACHMENT | LINK | FORMAT
    title:          opts.title || 'Unknown Finding',
    evidence:       opts.evidence || '',
    explanation:    opts.explanation || '',
    recommendation: opts.recommendation || '',
    // Backward-compatible field used by the existing UI
    type:  (opts.severity === 'HIGH' || opts.severity === 'CRITICAL') ? 'danger' : 'warning',
    // Backward-compatible message field
    message: opts.explanation || opts.evidence || ''
  };
}

// ─── Main Analyzer ────────────────────────────────────────────────────────────

/**
 * Analyze raw email headers.
 *
 * @param {string} rawHeaders - Raw RFC 5322 email headers (may include body)
 * @returns {{
 *   threatLevel: string,
 *   score: number,
 *   logs: string[],
 *   details: Array,
 *   findings: Array,
 *   parsedHeaders: Array,
 *   authentication: Object,
 *   routing: Object,
 *   links: string[],
 *   scoreBreakdown: Array
 * }}
 */
function analyzeHeaders(rawHeaders) {
  // ── Null / empty guard ───────────────────────────────────────────────────
  if (!rawHeaders || (typeof rawHeaders === 'string' && rawHeaders.trim() === '')) {
    return {
      threatLevel: 'Unknown',
      score: 0,
      logs: ['[ERROR] No headers provided for analysis.'],
      details: [],
      findings: [],
      parsedHeaders: [],
      authentication: { spf: null, dkim: null, dmarc: null },
      routing: { hops: [], originatingIP: null },
      links: []
    };
  }

  // ── Shared accumulators ──────────────────────────────────────────────────
  const logs = [];
  const details = [];     // backward-compat { type, title, message }
  const findings = [];    // Phase 1 structured findings
  const scoreBreakdown = [];
  let score = 0;

  function addScore(points, reason) {
    score += points;
    scoreBreakdown.push({ points, reason });
    logs.push(`[SCORE +${points}] ${reason}`);
  }

  function addFinding(finding) {
    findings.push(finding);
    // Keep backward-compat details[] in sync
    details.push({
      type: finding.type,
      title: finding.title,
      message: finding.message,
      severity: finding.severity,
      category: finding.category,
      evidence: finding.evidence,
      explanation: finding.explanation,
      recommendation: finding.recommendation
    });
  }

  // ── Parse headers ────────────────────────────────────────────────────────
  const parsedHeaders = EmailParser ? EmailParser.parseHeaders(rawHeaders) : _fallbackParse(rawHeaders);

  function getH(name) {
    if (EmailParser) return EmailParser.getHeader(parsedHeaders, name);
    return _fallbackGetHeader(rawHeaders, name);
  }

  function getAllH(name) {
    if (EmailParser) return EmailParser.getAllHeaders(parsedHeaders, name);
    const v = getH(name);
    return v ? [v] : [];
  }

  // ── Extract core address fields ──────────────────────────────────────────
  const fromRaw = getH('from') || '';
  const replyToRaw = getH('reply-to') || '';
  const returnPathRaw = getH('return-path') || '';
  const dkimSigRaw = getH('dkim-signature') || '';

  const fromAddr = EmailParser
    ? EmailParser.extractAddress(fromRaw)
    : { address: null, displayName: null, domain: null };

  const replyToAddr = replyToRaw
    ? (EmailParser ? EmailParser.extractAddress(replyToRaw) : { address: null, displayName: null, domain: null })
    : null;

  const returnPathAddr = returnPathRaw
    ? (EmailParser ? EmailParser.extractReturnPath(returnPathRaw) : null)
    : null;

  const normFrom = fromAddr.domain ? (EmailParser ? EmailParser.normalizeDomain(fromAddr.domain) : fromAddr.domain.toLowerCase()) : '';

  // ── From header ──────────────────────────────────────────────────────────
  if (!fromRaw) {
    addScore(20, 'Missing From header');
    addFinding(mkFinding({
      severity: 'HIGH',
      category: 'FORMAT',
      title: 'Missing From Header',
      evidence: 'No From: header detected.',
      explanation: 'The From header identifies the visible sender of an email. Its absence is unusual and may indicate automated spam tools or header stripping.',
      recommendation: 'Treat emails without a From header with extreme caution.'
    }));
    logs.push('[CRITICAL] Missing standard From: header.');
  } else {
    logs.push(`[OK] From: ${fromAddr.address || fromRaw}`);
  }

  // ── IDN / Punycode on sender domain ─────────────────────────────────────
  if (normFrom && EmailParser) {
    const idnInfo = EmailParser.analyzeIDN(normFrom);
    if (idnInfo.homographs.length > 0) {
      const chars = idnInfo.homographs.map(h => `"${h.char}" (${h.unicode}, looks like "${h.lookalike}")`).join(', ');
      addScore(25, `Domain contains Unicode homograph character(s): ${normFrom}`);
      addFinding(mkFinding({
        severity: 'HIGH',
        category: 'DOMAIN',
        title: 'Unicode Homograph in Sender Domain',
        evidence: `Domain: ${normFrom}\nSuspicious characters: ${chars}`,
        explanation: 'The sender domain contains Unicode characters visually similar to common ASCII letters. This is a known phishing technique used to impersonate legitimate domains (e.g., using Cyrillic "а" instead of Latin "a"). NOTE: Not all internationalized domains are malicious; however, mixed-script domains targeting brand impersonation are high-risk.',
        recommendation: 'Verify the sender domain using a trusted channel. Do not click links or reply without verification.'
      }));
    } else if (idnInfo.isPunycode) {
      addScore(8, `Sender domain uses Punycode internationalization: ${normFrom}`);
      addFinding(mkFinding({
        severity: 'LOW',
        category: 'DOMAIN',
        title: 'Punycode Internationalized Domain',
        evidence: `Domain: ${normFrom}`,
        explanation: 'The sender domain uses Punycode encoding (xn--...), indicating an internationalized domain name. Punycode domains are legitimate in many languages. However, they can also be used to visually impersonate ASCII domains. This is flagged for awareness only.',
        recommendation: 'Review the full Punycode domain. Legitimate organizations rarely use Punycode if they also operate an ASCII domain.'
      }));
    } else if (idnInfo.isNonASCII) {
      addScore(15, `Sender domain contains non-ASCII characters: ${normFrom}`);
      addFinding(mkFinding({
        severity: 'MEDIUM',
        category: 'DOMAIN',
        title: 'Non-ASCII Characters in Sender Domain',
        evidence: `Domain: ${normFrom}`,
        explanation: 'The sender domain contains non-ASCII (international) characters. While internationalized domains are legitimate in many countries, their use in combination with brand impersonation is a phishing risk.',
        recommendation: 'Confirm the sender\'s domain through an independent trusted source.'
      }));
    }
  }

  // ── Brand impersonation ──────────────────────────────────────────────────
  if (DomainUtils && fromAddr) {
    const impersonations = DomainUtils.detectBrandImpersonation(fromAddr);
    for (const imp of impersonations) {
      if (imp.type === 'reverse_subdomain') {
        addScore(40, `Reverse subdomain brand trick: ${imp.domain} (brand: ${imp.brand})`);
        addFinding(mkFinding({
          severity: 'CRITICAL',
          category: 'DOMAIN',
          title: `Reverse Subdomain Brand Impersonation — ${imp.brand}`,
          evidence: `From domain: ${imp.domain}`,
          explanation: imp.note,
          recommendation: 'This is a well-known phishing technique. Do not interact with this email. Report it as phishing.'
        }));
      } else if (imp.type === 'display_name_mismatch') {
        addScore(35, `Brand display name spoofing: "${fromAddr.displayName}" vs domain ${imp.domain}`);
        addFinding(mkFinding({
          severity: 'HIGH',
          category: 'IDENTITY',
          title: `Display Name Brand Spoofing — ${imp.brand}`,
          evidence: `Display name: "${fromAddr.displayName}"\nSending domain: ${imp.domain}`,
          explanation: `The email claims to be from "${imp.brand}" (via display name), but the sending domain "${imp.domain}" is not an authoritative ${imp.brand} domain. This is a common phishing technique. The visible name can be set to anything — only the domain is technically meaningful.`,
          recommendation: 'Do not trust the display name alone. Verify the sending domain. Report as phishing if unsolicited.'
        }));
      } else if (imp.type === 'domain_impersonation') {
        addScore(25, `Domain contains brand keyword not matching authority: ${imp.domain}`);
        addFinding(mkFinding({
          severity: 'MEDIUM',
          category: 'DOMAIN',
          title: `Domain Keyword Impersonation — ${imp.brand}`,
          evidence: `Sending domain: ${imp.domain}`,
          explanation: imp.note,
          recommendation: 'Verify the sender is actually from the claimed brand by checking the domain against official brand websites.'
        }));
      }
      logs.push(`[WARN] Brand impersonation (${imp.type}): ${imp.brand} / ${imp.domain}`);
    }
    if (impersonations.length === 0 && fromAddr.domain) {
      logs.push(`[OK] No brand impersonation detected for domain: ${fromAddr.domain}`);
    }
  }

  // ── Reply-To vs From ─────────────────────────────────────────────────────
  if (replyToAddr && replyToAddr.domain && normFrom) {
    const normReplyTo = EmailParser ? EmailParser.normalizeDomain(replyToAddr.domain) : replyToAddr.domain.toLowerCase();
    if (normReplyTo && normReplyTo !== normFrom) {
      addScore(20, `Reply-To domain (${normReplyTo}) differs from From domain (${normFrom})`);
      addFinding(mkFinding({
        severity: 'MEDIUM',
        category: 'IDENTITY',
        title: 'Reply-To Domain Mismatch',
        evidence: `From: ${fromAddr.address || normFrom}\nReply-To: ${replyToAddr.address || normReplyTo}\nFrom domain: ${normFrom}\nReply-To domain: ${normReplyTo}`,
        explanation: 'The Reply-To address is on a different domain than the From address. When a recipient replies, the reply will be sent to the Reply-To address, not back to the apparent sender. Some legitimate organizations (marketing services, ticketing systems) intentionally use different Reply-To domains. However, this is also a technique used by phishing campaigns to redirect responses to attacker-controlled addresses.',
        recommendation: 'Before replying, confirm which address replies will be sent to. If unexpected, verify the sender through an independent channel.'
      }));
      logs.push(`[WARN] Reply-To domain (${normReplyTo}) ≠ From domain (${normFrom}).`);
    } else if (normReplyTo) {
      logs.push(`[OK] Reply-To domain matches From domain: ${normReplyTo}`);
    }
  } else if (replyToAddr) {
    logs.push(`[INFO] Reply-To present: ${replyToAddr.address || replyToRaw}`);
  }

  // ── Return-Path vs From ──────────────────────────────────────────────────
  if (returnPathAddr) {
    const returnPathDomain = returnPathAddr.includes('@')
      ? returnPathAddr.split('@')[1]
      : null;
    const normReturnPath = returnPathDomain
      ? (EmailParser ? EmailParser.normalizeDomain(returnPathDomain) : returnPathDomain.toLowerCase())
      : '';

    if (normReturnPath && normFrom && normReturnPath !== normFrom) {
      // Only flag if the TLD / registrable domain differs (subdomains of same domain are normal)
      const fromBase = getRegistrablePart(normFrom);
      const rpBase = getRegistrablePart(normReturnPath);
      if (fromBase !== rpBase) {
        addScore(10, `Return-Path domain (${normReturnPath}) differs from From domain (${normFrom})`);
        addFinding(mkFinding({
          severity: 'LOW',
          category: 'IDENTITY',
          title: 'Return-Path Domain Mismatch',
          evidence: `From: ${fromAddr.address || normFrom}\nReturn-Path: ${returnPathAddr}\nFrom domain: ${normFrom}\nReturn-Path domain: ${normReturnPath}`,
          explanation: 'The Return-Path (envelope sender) is on a different domain than the visible From address. Delivery bounce messages go to the Return-Path address. Legitimate bulk mailers, marketing platforms, and mailing lists routinely use different Return-Path domains. This is a weak signal on its own; it becomes more significant when combined with other authentication failures.',
          recommendation: 'This is expected for newsletters and marketing email. Combined with SPF/DKIM failures, it indicates higher risk.'
        }));
        logs.push(`[INFO] Return-Path domain (${normReturnPath}) ≠ From domain (${normFrom}) — cross-domain bounce envelope.`);
      } else {
        logs.push(`[OK] Return-Path is a subdomain of the From domain: ${normReturnPath}`);
      }
    } else if (normReturnPath) {
      logs.push(`[OK] Return-Path domain matches From domain: ${normReturnPath}`);
    }
  }

  // ── SPF Analysis ─────────────────────────────────────────────────────────
  const receivedSPFRaw = getH('received-spf') || '';
  const authResultsRaw = getH('authentication-results') || '';

  let spfStatus = null;
  let spfSource = null;

  // Parse from Received-SPF first, then fall back to Authentication-Results
  if (receivedSPFRaw && DomainUtils) {
    const parsed = DomainUtils.parseReceivedSPF(receivedSPFRaw);
    if (parsed.status && parsed.status !== 'unknown') {
      spfStatus = parsed.status;
      spfSource = 'Received-SPF';
    }
  }

  if (!spfStatus && authResultsRaw && DomainUtils) {
    const parsed = DomainUtils.parseAuthResults(authResultsRaw);
    if (parsed.spf) {
      spfStatus = parsed.spf;
      spfSource = 'Authentication-Results';
    }
  }

  const spfPoints = DomainUtils ? DomainUtils.spfScore(spfStatus) : _legacySPFScore(spfStatus);

  if (spfStatus === 'pass') {
    logs.push(`[OK] SPF: pass (source: ${spfSource || 'header'})`);
  } else if (spfStatus === 'fail') {
    addScore(spfPoints, `SPF: fail — server not authorized by domain's SPF policy`);
    addFinding(mkFinding({
      severity: 'HIGH',
      category: 'AUTHENTICATION',
      title: 'SPF Authentication Failed',
      evidence: `SPF status: fail\nSource: ${spfSource || 'header'}\nFrom domain: ${normFrom || 'unknown'}`,
      explanation: 'SPF (Sender Policy Framework) records publish a list of authorized mail servers for a domain. An SPF FAIL means the server that sent this email is not on that authorized list. This is a strong indicator that the email may be spoofed. Note: fail is more definitive than softfail.',
      recommendation: 'Do not trust the sender identity. Verify through an independent trusted channel before acting on this email.'
    }));
  } else if (spfStatus === 'softfail') {
    addScore(spfPoints, `SPF: softfail — server is probably not authorized, but domain has not enforced a hard deny`);
    addFinding(mkFinding({
      severity: 'MEDIUM',
      category: 'AUTHENTICATION',
      title: 'SPF Soft Failure',
      evidence: `SPF status: softfail\nSource: ${spfSource || 'header'}\nFrom domain: ${normFrom || 'unknown'}`,
      explanation: 'SPF softfail (~all) indicates the sending server is "probably not" authorized, but the domain has chosen not to enforce a hard failure. Some legitimate forwarders produce SPF softfail. It is a warning, not a definitive fail. This is less severe than an SPF hard fail.',
      recommendation: 'Combined with other authentication results, a softfail raises the risk level. Treat the email cautiously.'
    }));
  } else if (spfStatus === 'neutral' || spfStatus === 'none') {
    addScore(spfPoints, `SPF: ${spfStatus} — no enforcement policy defined`);
    addFinding(mkFinding({
      severity: 'LOW',
      category: 'AUTHENTICATION',
      title: `SPF: ${(spfStatus || 'unknown').toUpperCase()}`,
      evidence: `SPF status: ${spfStatus}\nSource: ${spfSource || 'header or absent'}`,
      explanation: `SPF result is "${spfStatus}". This means either no SPF record exists, or the record does not assert whether the sender is authorized. Many small domains lack SPF records. This alone is not proof of phishing, but it reduces email trustworthiness.`,
      recommendation: 'Treat with caution, especially if other signals are present.'
    }));
  } else if (spfStatus) {
    addScore(spfPoints, `SPF: ${spfStatus}`);
    logs.push(`[WARN] SPF status: ${spfStatus}`);
  } else {
    addScore(10, 'SPF: not present in headers — cannot verify sender authorization');
    addFinding(mkFinding({
      severity: 'LOW',
      category: 'AUTHENTICATION',
      title: 'SPF Not Present in Headers',
      evidence: 'No Received-SPF or spf= in Authentication-Results found.',
      explanation: 'SPF authentication result was not included in the email headers. This may indicate the receiving server does not perform SPF checks, or the headers were stripped. Without SPF, sender authenticity cannot be verified.',
      recommendation: 'Consider the email unverified from an SPF perspective.'
    }));
  }

  // ── DKIM Analysis ────────────────────────────────────────────────────────
  let dkimStatus = null;
  let dkimDomain = null;
  let dkimSigParams = {};

  if (authResultsRaw && DomainUtils) {
    const parsed = DomainUtils.parseAuthResults(authResultsRaw);
    dkimStatus = parsed.dkim;
    dkimDomain = parsed.dkimDomain;
  }

  // Parse DKIM-Signature parameters
  if (dkimSigRaw) {
    const dkimD = dkimSigRaw.match(/[;\s]d=([^;\s]+)/i);
    const dkimS = dkimSigRaw.match(/[;\s]s=([^;\s]+)/i);
    const dkimA = dkimSigRaw.match(/[;\s]a=([^;\s]+)/i);
    const dkimC = dkimSigRaw.match(/[;\s]c=([^;\s]+)/i);
    dkimSigParams = {
      signingDomain: dkimD ? dkimD[1] : null,
      selector:      dkimS ? dkimS[1] : null,
      algorithm:     dkimA ? dkimA[1] : null,
      canonicalization: dkimC ? dkimC[1] : null
    };
    if (!dkimDomain && dkimSigParams.signingDomain) {
      dkimDomain = dkimSigParams.signingDomain.toLowerCase();
    }
  }

  const dkimPoints = DomainUtils ? DomainUtils.dkimScore(dkimStatus) : _legacyDKIMScore(dkimStatus, !!dkimSigRaw);

  if (dkimStatus === 'pass') {
    logs.push(`[OK] DKIM: pass`);
    // Check signing domain vs From domain
    if (dkimDomain && normFrom && dkimDomain !== normFrom) {
      const dkimBase = getRegistrablePart(dkimDomain);
      const fromBase = getRegistrablePart(normFrom);
      if (dkimBase !== fromBase) {
        addFinding(mkFinding({
          severity: 'INFO',
          category: 'AUTHENTICATION',
          title: 'DKIM Signed by Third-Party Domain',
          evidence: `DKIM signing domain: ${dkimDomain}\nFrom domain: ${normFrom}`,
          explanation: 'The DKIM signature is valid, but it was signed by a different domain than the visible From address. This is normal for legitimate third-party email senders (e.g., marketing platforms, ESPs like SendGrid, Mailchimp). It does not indicate spoofing on its own.',
          recommendation: 'This is informational. Combined with SPF/DMARC pass, this is expected behavior for legitimate bulk senders.'
        }));
        logs.push(`[INFO] DKIM signing domain (${dkimDomain}) differs from From domain (${normFrom}) — third-party ESP pattern.`);
      }
    }
  } else if (dkimStatus === 'fail') {
    addScore(dkimPoints, 'DKIM: fail — signature validation failed');
    addFinding(mkFinding({
      severity: 'HIGH',
      category: 'AUTHENTICATION',
      title: 'DKIM Signature Verification Failed',
      evidence: `DKIM status: fail${dkimDomain ? `\nSigning domain: ${dkimDomain}` : ''}\nFrom domain: ${normFrom || 'unknown'}`,
      explanation: 'DKIM (DomainKeys Identified Mail) adds a cryptographic signature to email. A DKIM failure means either the message content was altered after signing, or the DKIM signature was fabricated. This significantly reduces email authenticity.',
      recommendation: 'This email should not be trusted. Do not click links or act on instructions without independent verification.'
    }));
  } else if (!dkimStatus && !dkimSigRaw) {
    addScore(dkimPoints, 'DKIM: no signature present');
    addFinding(mkFinding({
      severity: 'LOW',
      category: 'AUTHENTICATION',
      title: 'No DKIM Signature Present',
      evidence: 'No DKIM-Signature header. No dkim= result in Authentication-Results.',
      explanation: 'The email does not include a DKIM cryptographic signature. Without DKIM, it is impossible to verify that the email content originated from the claimed sender. Many smaller email servers do not sign outgoing mail. This is a weak signal on its own.',
      recommendation: 'Consider the email unverified from a DKIM perspective. Do not rely solely on the From address.'
    }));
  } else if (dkimSigRaw && !dkimStatus) {
    logs.push('[INFO] DKIM-Signature present; authentication result not available in pasted headers.');
  } else if (dkimStatus) {
    addScore(dkimPoints, `DKIM: ${dkimStatus}`);
    logs.push(`[WARN] DKIM status: ${dkimStatus}`);
  }

  // ── DMARC Analysis ───────────────────────────────────────────────────────
  let dmarcStatus = null;

  if (authResultsRaw && DomainUtils) {
    const parsed = DomainUtils.parseAuthResults(authResultsRaw);
    dmarcStatus = parsed.dmarc;
  }

  const dmarcPoints = DomainUtils ? DomainUtils.dmarcScore(dmarcStatus) : _legacyDMARCScore(dmarcStatus);

  if (dmarcStatus === 'pass') {
    logs.push(`[OK] DMARC: pass`);
  } else if (dmarcStatus === 'fail') {
    addScore(dmarcPoints, 'DMARC: fail — policy alignment check failed');
    addFinding(mkFinding({
      severity: 'HIGH',
      category: 'AUTHENTICATION',
      title: 'DMARC Alignment Failed',
      evidence: `DMARC status: fail\nFrom domain: ${normFrom || 'unknown'}`,
      explanation: 'DMARC (Domain-based Message Authentication) requires that at least one of SPF or DKIM aligns with the visible From domain. A DMARC failure means neither alignment passed. DMARC failures are a strong indicator of spoofing when the domain has published a DMARC policy.',
      recommendation: 'This email failed DMARC alignment. Treat the sender identity as unverified.'
    }));
  } else if (dmarcStatus === 'none') {
    addScore(dmarcPoints, 'DMARC: none — domain has published no DMARC policy');
    addFinding(mkFinding({
      severity: 'LOW',
      category: 'AUTHENTICATION',
      title: 'No DMARC Policy Enforced',
      evidence: `DMARC status: none\nFrom domain: ${normFrom || 'unknown'}`,
      explanation: 'DMARC result "none" means the domain has not published a DMARC policy, or a policy exists but takes no action. Without a DMARC policy, spoofing emails from this domain is easier.',
      recommendation: 'Consider this informational. A domain without DMARC enforcement is easier to spoof.'
    }));
  } else if (!dmarcStatus) {
    logs.push('[INFO] DMARC: result not present in authentication headers.');
  } else {
    addScore(dmarcPoints, `DMARC: ${dmarcStatus}`);
    logs.push(`[INFO] DMARC status: ${dmarcStatus}`);
  }

  // ── Authentication-Results structured parsing ────────────────────────────
  const authParsed = (authResultsRaw && DomainUtils)
    ? DomainUtils.parseAuthResults(authResultsRaw)
    : { spf: spfStatus, dkim: dkimStatus, dmarc: dmarcStatus, raw: authResultsRaw, dkimDomain };

  // ── Received header chain analysis ──────────────────────────────────────
  const receivedValues = getAllH('received');
  const hops = [];
  let suspiciousHops = 0;

  // Received headers arrive newest-first; hop #1 = most recent (closest to recipient)
  receivedValues.forEach((val, idx) => {
    const hop = EmailParser
      ? EmailParser.parseReceivedHeader(val, idx + 1)
      : { hopNumber: idx + 1, from: null, by: null, ip: null, timestamp: null, raw: val };
    hops.push(hop);

    // Suspicious patterns
    const valLower = val.toLowerCase();
    const hopFlags = [];

    if (valLower.includes('localhost') && idx > 0) hopFlags.push('localhost relay in mid-chain');
    if (/dynamic|dhcp|dialup|dyn\./.test(valLower)) hopFlags.push('dynamic/dialup hostname');
    if (/\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3}/.test(valLower)) hopFlags.push('IP-literal hostname pattern');
    if (hop.ip) {
      // Private/loopback IP in mid-chain is suspicious
      if (idx > 0 && isPrivateIP(hop.ip)) hopFlags.push(`private IP address (${hop.ip}) in non-first hop`);
    }

    if (hopFlags.length > 0) {
      suspiciousHops++;
      hop.suspicious = true;
      hop.flags = hopFlags;
    } else {
      hop.suspicious = false;
      hop.flags = [];
    }
  });

  if (suspiciousHops > 0) {
    addScore(Math.min(suspiciousHops * 10, 20), `${suspiciousHops} suspicious Received hop(s) detected`);
    addFinding(mkFinding({
      severity: suspiciousHops >= 2 ? 'MEDIUM' : 'LOW',
      category: 'ROUTING',
      title: `Suspicious Mail Relay Hops (${suspiciousHops} detected)`,
      evidence: hops.filter(h => h.suspicious).map(h => `Hop ${h.hopNumber}: ${h.flags.join('; ')}`).join('\n'),
      explanation: 'One or more Received headers contain patterns associated with suspicious relay behavior: dynamic IP ranges, localhost relays in mid-chain, or residential dialup addresses. These patterns are common in spam botnets and compromised hosts. This is a contextual indicator — a single dynamic hop does not prove malice.',
      recommendation: 'Review the full Received chain. Combined with SPF/DKIM failures, suspicious hops increase the overall risk.'
    }));
  }

  if (receivedValues.length > 0) {
    logs.push(`[INFO] Received chain: ${receivedValues.length} hop(s) analyzed${suspiciousHops > 0 ? `, ${suspiciousHops} flagged` : ', none suspicious'}.`);
  }

  // ── X-Originating-IP ────────────────────────────────────────────────────
  const xOriginatingIP = getH('x-originating-ip') || getH('x-originating-ip') || null;
  let originatingIP = null;

  if (xOriginatingIP) {
    // Strip bracket notation [x.x.x.x]
    const stripped = xOriginatingIP.trim().replace(/^\[|\]$/g, '');
    const ipClass = EmailParser ? EmailParser.classifyIP(stripped) : null;
    if (ipClass) {
      originatingIP = stripped;
      logs.push(`[INFO] X-Originating-IP: ${originatingIP} (${ipClass})`);
    } else {
      logs.push(`[WARN] X-Originating-IP present but value is not a valid IP: "${xOriginatingIP}"`);
    }
  } else {
    logs.push('[INFO] X-Originating-IP: not present.');
  }

  // ── URL extraction from header text ─────────────────────────────────────
  const links = EmailParser ? EmailParser.extractURLs(rawHeaders) : [];
  if (links.length > 0) {
    logs.push(`[INFO] URLs found in headers: ${links.length}`);
  }

  // ── Score normalization ──────────────────────────────────────────────────
  const finalScore = Math.min(Math.round(score), 100);

  // ── Threat level ─────────────────────────────────────────────────────────
  let threatLevel = 'Safe';
  if (finalScore >= 70) threatLevel = 'Critical';
  else if (finalScore >= 45) threatLevel = 'High';
  else if (finalScore >= 25) threatLevel = 'Medium';
  else if (finalScore > 0)  threatLevel = 'Low';

  logs.push(`[RESULT] Threat Score: ${finalScore}/100 — ${threatLevel}`);

  // ── Build routing object ─────────────────────────────────────────────────
  const routing = {
    hops,
    originatingIP,
    hopCount: hops.length,
    suspiciousHops
  };

  // ── Build authentication object ──────────────────────────────────────────
  const authentication = {
    spf: authParsed.spf || spfStatus,
    dkim: authParsed.dkim || dkimStatus,
    dmarc: authParsed.dmarc || dmarcStatus,
    dkimDomain: authParsed.dkimDomain || dkimDomain,
    dkimSigParams,
    raw: authResultsRaw
  };

  return {
    // Backward-compatible fields
    threatLevel,
    score: finalScore,
    logs,
    details,
    // Phase 1 extended fields
    findings,
    parsedHeaders,
    authentication,
    routing,
    links,
    scoreBreakdown,
    // Address fields for UI
    fromAddress: fromAddr,
    replyToAddress: replyToAddr,
    returnPath: returnPathAddr
  };
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/**
 * Extract the registrable domain part (domain + TLD) from a full hostname.
 * Very simplified — does not use a full Public Suffix List.
 * @param {string} hostname
 * @returns {string}
 */
function getRegistrablePart(hostname) {
  if (!hostname) return '';
  const parts = hostname.toLowerCase().replace(/\.$/, '').split('.');
  if (parts.length <= 2) return hostname.toLowerCase();
  // Take last two parts as registrable domain
  return parts.slice(-2).join('.');
}

/**
 * Check if an IPv4 address is in a private/loopback range.
 * @param {string} ip
 * @returns {boolean}
 */
function isPrivateIP(ip) {
  if (!ip) return false;
  const parts = ip.split('.').map(Number);
  if (parts[0] === 127) return true; // loopback
  if (parts[0] === 10) return true;  // RFC 1918
  if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true; // RFC 1918
  if (parts[0] === 192 && parts[1] === 168) return true; // RFC 1918
  return false;
}

// ─── Fallback parsing (used if emailParser.js not available) ─────────────────

function _fallbackParse(rawHeaders) {
  const result = [];
  if (!rawHeaders) return result;
  const lines = rawHeaders.replace(/\r\n/g, '\n').split('\n');
  for (const line of lines) {
    const ci = line.indexOf(':');
    if (ci > 0 && !line.startsWith(' ') && !line.startsWith('\t')) {
      result.push({ name: line.substring(0, ci).toLowerCase().trim(), value: line.substring(ci + 1).trim(), raw: line });
    }
  }
  return result;
}

function _fallbackGetHeader(raw, name) {
  if (!raw) return null;
  const regex = new RegExp(`^${name}:\\s*(.+)$`, 'im');
  const m = raw.match(regex);
  return m ? m[1].trim() : null;
}

function _legacySPFScore(status) {
  if (status === 'fail') return 30;
  if (status === 'softfail') return 15;
  return 10;
}
function _legacyDKIMScore(status, hasSig) {
  if (status === 'fail') return 25;
  if (!status && !hasSig) return 15;
  return 0;
}
function _legacyDMARCScore(status) {
  if (status === 'fail') return 25;
  return 10;
}

// ─── Export ──────────────────────────────────────────────────────────────────

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { analyzeHeaders };
} else {
  window.analyzeHeaders = analyzeHeaders;
}
