/**
 * domainUtils.js
 * Domain analysis utilities for Trust & Verify Phase 1.
 *
 * Responsibilities:
 *  - Brand impersonation detection with structured brand definitions
 *  - Domain similarity detection (substring, reverse-subdomain tricks)
 *  - Authentication-Results structured parsing
 *
 * No DNS queries are made. No network connections. All analysis is local.
 */

'use strict';

// ─── Structured Brand Definitions ────────────────────────────────────────────
// Each brand has:
//   name:        Display name for UI
//   domains:     Authoritative domains for this brand (exact match = NOT spoofing)
//   keywords:    Display-name keywords that trigger impersonation check
//
// This is a heuristic list for educational simulation.
// It is NOT an authoritative list. Real threat intelligence should be used
// in a production security product.

const BRAND_DEFINITIONS = [
  {
    name: 'PayPal',
    domains: ['paypal.com', 'paypal.me', 'paypalobjects.com'],
    keywords: ['paypal', 'pay pal']
  },
  {
    name: 'Google',
    domains: ['google.com', 'gmail.com', 'googlemail.com', 'google.co.uk', 'google.ca', 'google.com.au', 'accounts.google.com', 'no-reply.accounts.google.com'],
    keywords: ['google', 'gmail', 'g-suite', 'gsuite', 'google workspace']
  },
  {
    name: 'Microsoft',
    domains: ['microsoft.com', 'outlook.com', 'live.com', 'hotmail.com', 'office.com', 'onedrive.com', 'sharepoint.com', 'azure.com', 'microsoftonline.com'],
    keywords: ['microsoft', 'outlook', 'office', 'azure', 'onedrive', 'sharepoint', 'windows', 'xbox']
  },
  {
    name: 'Apple',
    domains: ['apple.com', 'icloud.com', 'me.com', 'mac.com'],
    keywords: ['apple', 'icloud', 'itunes', 'app store', 'appstore']
  },
  {
    name: 'Amazon',
    domains: ['amazon.com', 'amazon.co.uk', 'amazon.ca', 'amazon.com.au', 'amazon.de', 'amazon.fr', 'amazon.co.jp', 'amazon.in', 'amazonses.com', 'aws.amazon.com'],
    keywords: ['amazon', 'amazon prime', 'amazon web services', 'aws']
  },
  {
    name: 'Netflix',
    domains: ['netflix.com'],
    keywords: ['netflix']
  },
  {
    name: 'Facebook',
    domains: ['facebook.com', 'fb.com', 'messenger.com', 'instagram.com', 'whatsapp.com', 'meta.com'],
    keywords: ['facebook', 'instagram', 'messenger', 'whatsapp', 'meta']
  },
  {
    name: 'Twitter/X',
    domains: ['twitter.com', 'x.com', 't.co'],
    keywords: ['twitter', 'twitterinc']
  },
  {
    name: 'LinkedIn',
    domains: ['linkedin.com'],
    keywords: ['linkedin']
  },
  {
    name: 'Chase',
    domains: ['chase.com', 'jpmorgan.com'],
    keywords: ['chase', 'jpmorgan', 'j.p. morgan']
  },
  {
    name: 'Bank of America',
    domains: ['bankofamerica.com', 'bofa.com'],
    keywords: ['bank of america', 'bankofamerica', 'bofa']
  },
  {
    name: 'DHL',
    domains: ['dhl.com', 'dhl.de', 'dhl.co.uk'],
    keywords: ['dhl', 'dhl express']
  },
  {
    name: 'FedEx',
    domains: ['fedex.com', 'fedex.com.'],
    keywords: ['fedex', 'fedex express']
  },
  {
    name: 'UPS',
    domains: ['ups.com'],
    keywords: ['ups', 'united parcel service']
  },
  {
    name: 'IRS',
    domains: ['irs.gov'],
    keywords: ['irs', 'internal revenue service']
  },
  {
    name: 'DocuSign',
    domains: ['docusign.com', 'docusign.net'],
    keywords: ['docusign']
  },
  {
    name: 'Dropbox',
    domains: ['dropbox.com'],
    keywords: ['dropbox']
  }
];

/**
 * Check whether a domain is an authoritative (legitimate) domain for a brand.
 * Exact match on registrable domain or approved sender domain.
 * @param {string} domain - The email domain to check
 * @param {Object} brand - Brand definition object
 * @returns {boolean}
 */
function isAuthoritativeDomain(domain, brand) {
  if (!domain) return false;
  const d = domain.toLowerCase().replace(/\.$/, '');
  return brand.domains.some(bd => d === bd || d.endsWith('.' + bd));
}

/**
 * Check whether a display name (or any text) contains a brand keyword.
 * @param {string} text
 * @param {Object} brand
 * @returns {boolean}
 */
function containsBrandKeyword(text, brand) {
  if (!text) return false;
  const lower = text.toLowerCase();
  return brand.keywords.some(kw => lower.includes(kw));
}

/**
 * Check whether a domain impersonates a brand by containment tricks.
 * Example: paypal-login.attacker.com contains "paypal" but is not authoritative.
 *
 * Detects:
 *   - brand-keyword.attacker.com
 *   - legitimate.com.attacker.com (reverse subdomain trick)
 *   - attackerpaypal.com
 *
 * @param {string} domain
 * @param {Object} brand
 * @returns {boolean}
 */
function domainContainsBrandKeyword(domain, brand) {
  if (!domain) return false;
  const d = domain.toLowerCase().replace(/\.$/, '');
  if (isAuthoritativeDomain(d, brand)) return false; // legitimate
  return brand.keywords.some(kw => d.includes(kw));
}

/**
 * Detect reverse-subdomain tricks.
 * Example: paypal.com.malicious.net → the TLD is .malicious.net
 * @param {string} domain
 * @param {Object} brand
 * @returns {{ detected: boolean, note: string|null }}
 */
function detectReverseSubdomainTrick(domain, brand) {
  if (!domain) return { detected: false, note: null };
  const d = domain.toLowerCase().replace(/\.$/, '');
  for (const authDomain of brand.domains) {
    // If the sender domain contains the legitimate domain as a subdomain label
    // e.g. "paypal.com.attacker.net" contains "paypal.com"
    if (d.startsWith(authDomain + '.') || d.includes('.' + authDomain + '.')) {
      return {
        detected: true,
        note: `Domain "${d}" appears to embed legitimate domain "${authDomain}" as a subdomain — common phishing trick.`
      };
    }
  }
  return { detected: false, note: null };
}

/**
 * Main brand impersonation check.
 * Checks display name and email domain against all brand definitions.
 *
 * Returns an array of impersonation findings (may be empty for legitimate email).
 *
 * @param {{ displayName: string|null, domain: string|null }} fromAddr
 * @returns {Array<{ brand: string, type: string, domain: string, note: string }>}
 */
function detectBrandImpersonation(fromAddr) {
  const findings = [];
  if (!fromAddr) return findings;

  const { displayName, domain } = fromAddr;

  for (const brand of BRAND_DEFINITIONS) {
    // Case 1: Display name contains brand keyword but domain is not authoritative
    if (displayName && containsBrandKeyword(displayName, brand)) {
      if (!isAuthoritativeDomain(domain, brand)) {
        // Reverse subdomain trick is a separate, more severe case
        const reverseTrick = detectReverseSubdomainTrick(domain, brand);
        if (reverseTrick.detected) {
          findings.push({
            brand: brand.name,
            type: 'reverse_subdomain',
            domain,
            note: reverseTrick.note
          });
        } else {
          findings.push({
            brand: brand.name,
            type: 'display_name_mismatch',
            domain,
            note: `Display name claims "${brand.name}" but sending domain "${domain}" is not an authoritative ${brand.name} domain.`
          });
        }
      }
    }

    // Case 2: Domain contains brand keyword but is not authoritative
    if (domain && domainContainsBrandKeyword(domain, brand)) {
      if (!isAuthoritativeDomain(domain, brand)) {
        // Avoid duplicating with Case 1
        const alreadyFound = findings.some(f => f.brand === brand.name && f.domain === domain);
        if (!alreadyFound) {
          findings.push({
            brand: brand.name,
            type: 'domain_impersonation',
            domain,
            note: `Sending domain "${domain}" contains the keyword "${brand.keywords[0]}" but is not an authoritative ${brand.name} domain.`
          });
        }
      }
    }
  }

  return findings;
}

// ─── Authentication-Results Parser ────────────────────────────────────────────

const SPF_STATUSES  = ['pass', 'fail', 'softfail', 'neutral', 'none', 'temperror', 'permerror'];
const DKIM_STATUSES = ['pass', 'fail', 'neutral', 'none', 'policy', 'permerror', 'temperror'];
const DMARC_STATUSES = ['pass', 'fail', 'none', 'quarantine', 'reject'];

/**
 * Parse an Authentication-Results header value into structured components.
 * @param {string} value - Raw Authentication-Results header value
 * @returns {{ spf: string|null, dkim: string|null, dmarc: string|null, raw: string, dkimDomain: string|null }}
 */
function parseAuthResults(value) {
  if (!value) return { spf: null, dkim: null, dmarc: null, raw: '', dkimDomain: null };

  const lower = value.toLowerCase();

  let spf = null;
  let dkim = null;
  let dmarc = null;
  let dkimDomain = null;

  // SPF
  for (const status of SPF_STATUSES) {
    if (lower.includes(`spf=${status}`)) { spf = status; break; }
  }

  // DKIM — also extract header.d= if present
  for (const status of DKIM_STATUSES) {
    if (lower.includes(`dkim=${status}`)) {
      dkim = status;
      const domainMatch = value.match(/dkim=[a-z]+\s+header\.d=([^\s;]+)/i) ||
                          value.match(/header\.i=@([^\s;]+)/i);
      if (domainMatch) dkimDomain = domainMatch[1].toLowerCase();
      break;
    }
  }

  // DMARC
  for (const status of DMARC_STATUSES) {
    if (lower.includes(`dmarc=${status}`)) { dmarc = status; break; }
  }

  return { spf, dkim, dmarc, raw: value, dkimDomain };
}

/**
 * Parse a Received-SPF header value into a structured result.
 * @param {string} value
 * @returns {{ status: string|null, raw: string }}
 */
function parseReceivedSPF(value) {
  if (!value) return { status: null, raw: '' };
  const lower = value.toLowerCase().trim();
  for (const status of SPF_STATUSES) {
    if (lower.startsWith(status) || lower.includes(` ${status}`) || lower.includes(`(${status}`)) {
      return { status, raw: value };
    }
  }
  return { status: 'unknown', raw: value };
}

// ─── SPF Score Weights ────────────────────────────────────────────────────────
// Weights are carefully differentiated between statuses.
// softfail is less severe than fail — it means "probably not authorized."

const SPF_SCORE_MAP = {
  pass:      0,
  softfail: 15,  // Less severe than fail
  fail:     30,
  neutral:   5,
  none:     10,
  temperror: 8,
  permerror:12,
  unknown:  10
};

const DKIM_SCORE_MAP = {
  pass:      0,
  fail:     25,
  neutral:   5,
  none:     15,
  policy:    5,
  temperror: 8,
  permerror:12
};

const DMARC_SCORE_MAP = {
  pass:       0,
  fail:      25,
  none:      10,
  quarantine:15,
  reject:    20
};

/**
 * Get score contribution for an SPF status.
 * @param {string|null} status
 * @returns {number}
 */
function spfScore(status) {
  if (!status) return SPF_SCORE_MAP.unknown;
  return SPF_SCORE_MAP[status] !== undefined ? SPF_SCORE_MAP[status] : SPF_SCORE_MAP.unknown;
}

/**
 * Get score contribution for a DKIM status.
 * @param {string|null} status
 * @returns {number}
 */
function dkimScore(status) {
  if (!status) return DKIM_SCORE_MAP.none;
  return DKIM_SCORE_MAP[status] !== undefined ? DKIM_SCORE_MAP[status] : DKIM_SCORE_MAP.none;
}

/**
 * Get score contribution for a DMARC status.
 * @param {string|null} status
 * @returns {number}
 */
function dmarcScore(status) {
  if (!status) return DMARC_SCORE_MAP.none;
  return DMARC_SCORE_MAP[status] !== undefined ? DMARC_SCORE_MAP[status] : DMARC_SCORE_MAP.none;
}

// ─── Export ──────────────────────────────────────────────────────────────────

const DomainUtils = {
  BRAND_DEFINITIONS,
  isAuthoritativeDomain,
  containsBrandKeyword,
  domainContainsBrandKeyword,
  detectReverseSubdomainTrick,
  detectBrandImpersonation,
  parseAuthResults,
  parseReceivedSPF,
  spfScore,
  dkimScore,
  dmarcScore
};

if (typeof module !== 'undefined' && module.exports) {
  module.exports = DomainUtils;
} else {
  window.DomainUtils = DomainUtils;
}
