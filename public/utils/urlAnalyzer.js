/**
 * urlAnalyzer.js
 * Analyzes URLs for security indicators without fetching them.
 */

// RiskTypes constants.
// In Node.js, load via require (each file gets its own module scope — no collision).
// In browser, riskTypes.js is loaded before this file and declares SEVERITY, CATEGORY,
// and SOURCE as consts in the shared global script scope. They are already available;
// redeclaring them here would cause "already declared" SyntaxErrors.
// We expose them via a local _rt alias to support both environments cleanly.
const _rt = (typeof require === 'function')
  ? (() => { try { return require('../core/riskTypes'); } catch(e) { return (typeof window !== 'undefined' ? window.RiskTypes : {}); } })()
  : (typeof window !== 'undefined' ? window.RiskTypes : {});
/* jshint ignore:start */
// In the browser these names are already const-declared by riskTypes.js; we read
// them via the _rt alias to avoid SyntaxErrors from duplicate declarations.
/* jshint ignore:end */

const SUSPICIOUS_TOKENS = ['login', 'verify', 'verification', 'secure', 'account', 'update', 'password', 'wallet', 'payment', 'invoice', 'refund', 'support', 'signin', 'confirm', 'unlock'];
const SHORTENER_DOMAINS = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'ow.ly'];
const REDIRECT_PARAMS = ['url', 'redirect', 'redirect_url', 'return', 'returnUrl', 'next', 'continue', 'dest', 'destination', 'target'];

class UrlAnalyzer {
  static analyze(inputUrl) {
    const indicators = [];
    let normalizedUrl = inputUrl.trim();
    let normalizationApplied = false;

    // Basic normalization for schemeless inputs
    if (!/^https?:\/\//i.test(normalizedUrl)) {
      normalizedUrl = 'http://' + normalizedUrl;
      normalizationApplied = true;
    }

    let parsed = null;
    try {
      parsed = new URL(normalizedUrl);
    } catch (e) {
      indicators.push({
        id: 'URL_MALFORMED',
        category: _rt.CATEGORY.CONTENT,
        severity: _rt.SEVERITY.MEDIUM,
        weight: 30,
        source: _rt.SOURCE.LOCAL_HEURISTIC,
        title: 'Malformed URL',
        description: 'The provided URL could not be parsed.',
        evidence: `Input: ${inputUrl}`,
        recommendation: 'Ensure the URL is correctly formatted.'
      });
      return { indicators, parsed: null, normalizedUrl, normalizationApplied };
    }

    // 1. Insecure HTTP
    if (parsed.protocol === 'http:') {
      indicators.push({
        id: 'INSECURE_HTTP',
        category: _rt.CATEGORY.NETWORK,
        severity: _rt.SEVERITY.LOW,
        weight: 10,
        source: _rt.SOURCE.LOCAL_HEURISTIC,
        title: 'Insecure HTTP Protocol',
        description: 'The URL uses unencrypted HTTP.',
        evidence: parsed.protocol,
        recommendation: 'Avoid submitting sensitive information over HTTP.'
      });
    }

    // 2. IP Address Host
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(parsed.hostname) || /^\[?[a-fA-F0-9:]+\]?$/.test(parsed.hostname)) {
      indicators.push({
        id: 'IP_HOSTNAME',
        category: _rt.CATEGORY.DOMAIN,
        severity: _rt.SEVERITY.MEDIUM,
        weight: 30,
        source: _rt.SOURCE.LOCAL_HEURISTIC,
        title: 'IP Address Hostname',
        description: 'The URL uses an IP address instead of a domain name, which is common in phishing.',
        evidence: parsed.hostname,
        recommendation: 'Verify the destination is intended to be an IP.'
      });
    }

    // 3. Punycode
    if (parsed.hostname.includes('xn--')) {
      indicators.push({
        id: 'PUNYCODE_DOMAIN',
        category: _rt.CATEGORY.DOMAIN,
        severity: _rt.SEVERITY.HIGH,
        weight: 40,
        source: _rt.SOURCE.LOCAL_HEURISTIC,
        title: 'Punycode Domain',
        description: 'Internationalized domain detected, which may be used for homograph attacks.',
        evidence: parsed.hostname,
        recommendation: 'Verify the characters in the domain visually.'
      });
    }

    // 4. Userinfo
    if (parsed.username || parsed.password) {
      indicators.push({
        id: 'URL_USERINFO',
        category: _rt.CATEGORY.AUTHENTICATION,
        severity: _rt.SEVERITY.HIGH,
        weight: 50,
        source: _rt.SOURCE.LOCAL_HEURISTIC,
        title: 'Credentials in URL',
        description: 'The URL contains embedded credentials.',
        evidence: `Username: ${parsed.username ? '***' : 'none'}, Password: ${parsed.password ? '***' : 'none'}`,
        recommendation: 'Do not trust URLs with embedded credentials.'
      });
    }

    // 5. Excessive Subdomains
    const parts = parsed.hostname.split('.');
    if (parts.length > 4) {
      indicators.push({
        id: 'EXCESSIVE_SUBDOMAINS',
        category: _rt.CATEGORY.DOMAIN,
        severity: _rt.SEVERITY.MEDIUM,
        weight: 20,
        source: _rt.SOURCE.LOCAL_HEURISTIC,
        title: 'Excessive Subdomains',
        description: 'The hostname has an unusually deep structure.',
        evidence: parsed.hostname,
        recommendation: 'Check the actual registrable domain carefully.'
      });
    }

    // 6. Suspicious Tokens
    const lowerHost = parsed.hostname.toLowerCase();
    const foundTokens = SUSPICIOUS_TOKENS.filter(t => lowerHost.includes(t));
    if (foundTokens.length > 0) {
      indicators.push({
        id: 'SUSPICIOUS_TOKEN',
        category: _rt.CATEGORY.CONTENT,
        severity: _rt.SEVERITY.MEDIUM,
        weight: 15,
        source: _rt.SOURCE.LOCAL_HEURISTIC,
        title: 'Suspicious Hostname Tokens',
        description: 'Security-related terms were found in the hostname.',
        evidence: foundTokens.join(', '),
        recommendation: 'Ensure this is legitimately related to the service.'
      });
    }

    // 7. Length Analysis
    if (parsed.hostname.length > 63) {
      indicators.push({
        id: 'LONG_HOSTNAME',
        category: _rt.CATEGORY.DOMAIN,
        severity: _rt.SEVERITY.LOW,
        weight: 5,
        source: _rt.SOURCE.LOCAL_HEURISTIC,
        title: 'Unusually Long Hostname',
        description: 'The hostname length exceeds common usage patterns.',
        evidence: `Length: ${parsed.hostname.length}`,
        recommendation: 'Review for obfuscation.'
      });
    }
    if (normalizedUrl.length > 255) {
      indicators.push({
        id: 'LONG_URL',
        category: _rt.CATEGORY.CONTENT,
        severity: _rt.SEVERITY.LOW,
        weight: 5,
        source: _rt.SOURCE.LOCAL_HEURISTIC,
        title: 'Unusually Long URL',
        description: 'The URL is very long, which can hide malicious parameters.',
        evidence: `Length: ${normalizedUrl.length}`,
        recommendation: 'Review query parameters.'
      });
    }

    // 8. Redirect Parameters
    let nestedUrl = null;
    for (const [key, val] of parsed.searchParams.entries()) {
      if (REDIRECT_PARAMS.includes(key.toLowerCase())) {
        try {
          const nested = new URL(val);
          nestedUrl = nested.href;
          indicators.push({
            id: 'URL_REDIRECT',
            category: _rt.CATEGORY.ROUTING,
            severity: _rt.SEVERITY.MEDIUM,
            weight: 20,
            source: _rt.SOURCE.LOCAL_HEURISTIC,
            title: 'Redirect Parameter Detected',
            description: 'The URL instructs the server to redirect to another destination.',
            evidence: `Parameter: ${key}, Destination: ${nestedUrl}`,
            recommendation: 'Verify the nested destination.'
          });
          break; // just take the first one
        } catch (e) {
          // not a valid URL, ignore
        }
      }
    }

    // 9. Shortened URL
    if (SHORTENER_DOMAINS.includes(lowerHost)) {
      indicators.push({
        id: 'SHORTENED_URL',
        category: _rt.CATEGORY.ROUTING,
        severity: _rt.SEVERITY.MEDIUM,
        weight: 20,
        source: _rt.SOURCE.LOCAL_HEURISTIC,
        title: 'Shortened URL',
        description: 'The final destination cannot be verified from the shortened URL alone.',
        evidence: lowerHost,
        recommendation: 'Use caution as the destination is hidden.'
      });
    }

    return { indicators, parsed, normalizedUrl, normalizationApplied, nestedUrl };
  }
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = UrlAnalyzer;
} else {
  window.UrlAnalyzer = UrlAnalyzer;
}
