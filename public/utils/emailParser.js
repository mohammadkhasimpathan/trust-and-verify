/**
 * emailParser.js
 * RFC 5322-compliant email header parser for Trust & Verify Phase 1.
 *
 * Responsibilities:
 *  - Parse raw headers into structured { name, value, raw } objects
 *  - Handle folded/multiline continuation headers correctly
 *  - Extract individual fields (From, To, Reply-To, Return-Path, etc.)
 *  - Extract email addresses and domains safely
 *  - Extract URLs from header values and body text
 *
 * This module runs in both Node.js (CommonJS) and the browser (global).
 * No network requests are made. All analysis is local and heuristic.
 */

'use strict';

// ─── Header Parsing ─────────────────────────────────────────────────────────

/**
 * Parse a raw header block into an array of { name, value, raw } objects.
 * Handles RFC 5322 folded (multiline) headers correctly.
 * Folded lines begin with a space or tab (WSP).
 *
 * @param {string} rawText - Raw email header block
 * @returns {Array<{name:string, value:string, raw:string}>}
 */
function parseHeaders(rawText) {
  if (!rawText || typeof rawText !== 'string') return [];

  const headers = [];
  // Normalize CRLF to LF
  const normalized = rawText.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
  const lines = normalized.split('\n');

  let currentName = null;
  let currentValueLines = [];
  let currentRawLines = [];

  function flushCurrent() {
    if (currentName !== null) {
      const raw = currentRawLines.join('\n');
      // Join folded value lines, replacing folding whitespace with a single space
      const value = currentValueLines
        .map((l, i) => (i === 0 ? l : l.replace(/^[ \t]+/, '')))
        .join(' ')
        .trim();
      headers.push({ name: currentName.toLowerCase().trim(), value, raw });
    }
  }

  for (const line of lines) {
    // Folded continuation: starts with space or tab
    if (currentName !== null && (line.startsWith(' ') || line.startsWith('\t'))) {
      currentValueLines.push(line);
      currentRawLines.push(line);
      continue;
    }

    // New header: colon separator
    const colonIdx = line.indexOf(':');
    if (colonIdx > 0) {
      flushCurrent();
      currentName = line.substring(0, colonIdx);
      const valueStart = line.substring(colonIdx + 1);
      currentValueLines = [valueStart];
      currentRawLines = [line];
    } else if (line.trim() === '') {
      // Empty line = end of header block
      flushCurrent();
      currentName = null;
      currentValueLines = [];
      currentRawLines = [];
      // Stop after blank line (body begins)
      break;
    }
    // Lines without a colon and not folded are malformed — skip
  }
  // Flush last header
  flushCurrent();

  return headers;
}

/**
 * Get the first header value matching the given name (case-insensitive).
 * @param {Array} headers - Parsed headers array
 * @param {string} name - Header name to look for
 * @returns {string|null}
 */
function getHeader(headers, name) {
  const lower = name.toLowerCase();
  const found = headers.find(h => h.name === lower);
  return found ? found.value : null;
}

/**
 * Get all header values matching the given name.
 * @param {Array} headers - Parsed headers array
 * @param {string} name - Header name to look for
 * @returns {string[]}
 */
function getAllHeaders(headers, name) {
  const lower = name.toLowerCase();
  return headers.filter(h => h.name === lower).map(h => h.value);
}

// ─── Address / Domain Extraction ────────────────────────────────────────────

/**
 * Extract an email address from a header value.
 * Handles formats:
 *   "Display Name" <addr@domain.com>
 *   addr@domain.com
 *   <addr@domain.com>
 * @param {string} value
 * @returns {{ address: string|null, displayName: string|null, domain: string|null }}
 */
function extractAddress(value) {
  if (!value) return { address: null, displayName: null, domain: null };

  // Try "Display Name" <addr@domain>
  const angleMatch = value.match(/^"?([^"<]*)"?\s*<([^>]+)>/);
  if (angleMatch) {
    const displayName = angleMatch[1].trim() || null;
    const address = angleMatch[2].trim().toLowerCase();
    const domain = address.includes('@') ? address.split('@')[1] : null;
    return { address, displayName, domain };
  }

  // Try bare address (allow non-ASCII for IDN)
  const bareMatch = value.match(/([^\s<>"']+\@[^\s<>"']+\.[a-zA-Z0-9-]{2,})/i);
  if (bareMatch) {
    const address = bareMatch[1].toLowerCase();
    const domain = address.split('@')[1];
    return { address, displayName: null, domain };
  }

  return { address: null, displayName: null, domain: null };
}

/**
 * Normalize a domain: lowercase, remove trailing dot, trim whitespace.
 * @param {string} domain
 * @returns {string}
 */
function normalizeDomain(domain) {
  if (!domain) return '';
  return domain.toLowerCase().trim().replace(/\.$/, '');
}

/**
 * Extract Return-Path address (often in <addr> format).
 * @param {string} value
 * @returns {string|null}
 */
function extractReturnPath(value) {
  if (!value) return null;
  const match = value.match(/<([^>]*)>/);
  if (match) return match[1].trim().toLowerCase() || null;
  const bare = value.match(/([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})/);
  return bare ? bare[1].toLowerCase() : null;
}

// ─── URL Extraction ──────────────────────────────────────────────────────────

/**
 * Extract all URLs from a text string.
 * Does NOT fetch them. Returns raw URL strings.
 * @param {string} text
 * @returns {string[]}
 */
function extractURLs(text) {
  if (!text) return [];
  const urlRegex = /https?:\/\/[^\s<>"')\]]+/gi;
  return [...new Set((text.match(urlRegex) || []))];
}

/**
 * Safely parse a URL string into its components without making any network request.
 * @param {string} urlStr
 * @returns {{ href:string, protocol:string, hostname:string, port:string, pathname:string, search:string, hash:string }|null}
 */
function parseURL(urlStr) {
  try {
    // URL constructor is available in Node >= 10 and all modern browsers
    const u = new URL(urlStr);
    return {
      href: u.href,
      protocol: u.protocol,
      hostname: u.hostname,
      port: u.port,
      pathname: u.pathname,
      search: u.search,
      hash: u.hash
    };
  } catch {
    return null;
  }
}

// ─── IP Validation ───────────────────────────────────────────────────────────

const IPV4_RE = /^(\d{1,3}\.){3}\d{1,3}$/;
const IPV6_RE = /^[\da-fA-F:]{2,39}$/;

/**
 * Check if a string is a syntactically valid IPv4 address.
 * @param {string} str
 * @returns {boolean}
 */
function isValidIPv4(str) {
  if (!IPV4_RE.test(str)) return false;
  return str.split('.').every(o => {
    const n = Number(o);
    return n >= 0 && n <= 255;
  });
}

/**
 * Check if a string is a syntactically valid IPv6 address.
 * Uses a simplified check sufficient for display/logging purposes.
 * @param {string} str
 * @returns {boolean}
 */
function isValidIPv6(str) {
  // Strip bracket notation [::1]
  const clean = str.replace(/^\[|\]$/g, '');
  return IPV6_RE.test(clean) && (clean.includes(':'));
}

/**
 * Check if a string looks like a valid IP (v4 or v6).
 * @param {string} str
 * @returns {'ipv4'|'ipv6'|null}
 */
function classifyIP(str) {
  if (!str) return null;
  const trimmed = str.trim().replace(/^\[|\]$/g, '');
  if (isValidIPv4(trimmed)) return 'ipv4';
  if (isValidIPv6(trimmed)) return 'ipv6';
  return null;
}

/**
 * Extract first IP address from a Received header value.
 * @param {string} value
 * @returns {string|null}
 */
function extractIPFromReceived(value) {
  if (!value) return null;
  // Try [x.x.x.x] format
  const bracketMatch = value.match(/\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]/);
  if (bracketMatch) return bracketMatch[1];
  // Try bare IP
  const bareMatch = value.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/);
  if (bareMatch) return bareMatch[1];
  return null;
}

// ─── IDN / Punycode / Homograph Detection ────────────────────────────────────

/**
 * Check if a domain contains Punycode (xn-- prefix).
 * @param {string} domain
 * @returns {boolean}
 */
function hasPunycode(domain) {
  return /xn--/i.test(domain);
}

/**
 * Unicode homograph lookalike map for common Latin letters.
 * Maps suspicious Unicode codepoints to their ASCII lookalike.
 */
const HOMOGRAPH_MAP = {
  '\u0430': 'a', // Cyrillic а
  '\u0435': 'e', // Cyrillic е
  '\u043e': 'o', // Cyrillic о
  '\u0440': 'r', // Cyrillic р
  '\u0441': 'c', // Cyrillic с
  '\u0445': 'x', // Cyrillic х
  '\u0456': 'i', // Cyrillic і
  '\u0406': 'I', // Cyrillic І
  '\u0409': 'lj',// Cyrillic Љ
  '\u00e0': 'a', // à
  '\u00e1': 'a', // á
  '\u00e2': 'a', // â
  '\u00e4': 'a', // ä
  '\u00e8': 'e', // è
  '\u00e9': 'e', // é
  '\u00ec': 'i', // ì
  '\u00ed': 'i', // í
  '\u00f2': 'o', // ò
  '\u00f3': 'o', // ó
  '\u00f9': 'u', // ù
  '\u00fa': 'u', // ú
  '\u0261': 'g', // ɡ (script g)
  '\u1d0f': 'o', // ᴏ (small capital o)
};

/**
 * Detect suspicious Unicode characters in a domain that could be homographs.
 * @param {string} domain
 * @returns {Array<{char: string, unicode: string, lookalike: string}>}
 */
function detectHomographs(domain) {
  const suspicious = [];
  for (const ch of domain) {
    const cp = ch.codePointAt(0);
    if (cp > 127 && HOMOGRAPH_MAP[ch]) {
      suspicious.push({
        char: ch,
        unicode: `U+${cp.toString(16).toUpperCase().padStart(4, '0')}`,
        lookalike: HOMOGRAPH_MAP[ch]
      });
    }
  }
  return suspicious;
}

/**
 * Check a domain for IDN-related suspicious signals.
 * @param {string} domain
 * @returns {{ isPunycode: boolean, homographs: Array, isNonASCII: boolean }}
 */
function analyzeIDN(domain) {
  if (!domain) return { isPunycode: false, homographs: [], isNonASCII: false };
  const isNonASCII = /[^\x00-\x7F]/.test(domain);
  return {
    isPunycode: hasPunycode(domain),
    homographs: detectHomographs(domain),
    isNonASCII
  };
}

// ─── Received Header Chain Parsing ───────────────────────────────────────────

/**
 * Parse a single Received header value into structured data.
 * Received headers are complex; this extracts key fields best-effort.
 * @param {string} value
 * @param {number} hopNumber - position in the raw header list (1 = first seen = last delivered)
 * @returns {{ from: string|null, by: string|null, ip: string|null, timestamp: string|null, raw: string }}
 */
function parseReceivedHeader(value, hopNumber) {
  const fromMatch = value.match(/from\s+([^\s;]+)/i);
  const byMatch = value.match(/by\s+([^\s;]+)/i);
  const ip = extractIPFromReceived(value);

  // Timestamp: often after semicolon at end
  const semiIdx = value.lastIndexOf(';');
  const timestamp = semiIdx >= 0 ? value.substring(semiIdx + 1).trim() : null;

  return {
    hopNumber,
    from: fromMatch ? fromMatch[1] : null,
    by: byMatch ? byMatch[1] : null,
    ip: ip && isValidIPv4(ip) ? ip : null,
    timestamp,
    raw: value
  };
}

// ─── Export ──────────────────────────────────────────────────────────────────

const EmailParser = {
  parseHeaders,
  getHeader,
  getAllHeaders,
  extractAddress,
  extractReturnPath,
  normalizeDomain,
  extractURLs,
  parseURL,
  classifyIP,
  isValidIPv4,
  isValidIPv6,
  extractIPFromReceived,
  hasPunycode,
  detectHomographs,
  analyzeIDN,
  parseReceivedHeader
};

if (typeof module !== 'undefined' && module.exports) {
  module.exports = EmailParser;
} else {
  window.EmailParser = EmailParser;
}
