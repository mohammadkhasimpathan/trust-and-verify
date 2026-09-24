/**
 * domainAnalyzer.js
 * Analyzes domains for security indicators (registrable domain, IDN, brand impersonation).
 */

// RiskTypes constants.
// In Node.js, load via require (each file gets its own module scope — no collision).
// In browser, riskTypes.js is loaded before this file and declares SEVERITY, CATEGORY,
// and SOURCE as consts in the shared global script scope. They are already available;
// redeclaring them here would cause "already declared" SyntaxErrors.
// We expose them via a local _rt alias to support both environments cleanly.
var _rt = (typeof require === 'function')
  ? (() => { try { return require('../core/riskTypes'); } catch(e) { return (typeof window !== 'undefined' ? window.RiskTypes : {}); } })()
  : (typeof window !== 'undefined' ? window.RiskTypes : {});
/* jshint ignore:start */
// In the browser these names are already const-declared by riskTypes.js; we read
// them via the _rt alias to avoid SyntaxErrors from duplicate declarations.
/* jshint ignore:end */

const MONITORED_BRAND_TOKENS = [
  "microsoft", "google", "apple", "amazon", "paypal", "instagram", "facebook", "whatsapp"
];

// Simple TLD list for registrable domain heuristic (since no external libs are allowed unless justified)
const BASIC_TLDS = ['.com', '.net', '.org', '.edu', '.gov', '.co.uk', '.io', '.co', '.us', '.info', '.biz', '.tv', '.me'];

class DomainAnalyzer {
  static extractRegistrableDomain(hostname) {
    let bestTld = '';
    for (const tld of BASIC_TLDS) {
      if (hostname.endsWith(tld)) {
        bestTld = tld;
        break;
      }
    }
    
    if (bestTld) {
      const remaining = hostname.slice(0, -(bestTld.length));
      const parts = remaining.split('.');
      const sld = parts[parts.length - 1];
      return sld + bestTld;
    }
    
    // Fallback: just return last two parts
    const parts = hostname.split('.');
    if (parts.length >= 2) {
      return parts.slice(-2).join('.');
    }
    return hostname;
  }

  static analyze(hostname) {
    const indicators = [];
    const lowerHost = hostname.toLowerCase();
    
    let parsed = null;
    let effectiveHost = lowerHost;
    
    // Strip port if present
    if (effectiveHost.includes(':')) {
      effectiveHost = effectiveHost.split(':')[0];
    }
    
    // Remove trailing dot
    if (effectiveHost.endsWith('.')) {
      effectiveHost = effectiveHost.slice(0, -1);
    }
    
    const registrableDomain = this.extractRegistrableDomain(effectiveHost);
    const subdomains = effectiveHost === registrableDomain ? '' : effectiveHost.slice(0, -(registrableDomain.length + 1));
    
    // 1. Brand token outside registrable domain
    for (const brand of MONITORED_BRAND_TOKENS) {
      if (subdomains.includes(brand)) {
        indicators.push({
          id: 'BRAND_SUBDOMAIN',
          category: _rt.CATEGORY.DOMAIN,
          severity: _rt.SEVERITY.HIGH,
          weight: 40,
          source: _rt.SOURCE.LOCAL_HEURISTIC,
          title: 'Brand Token in Subdomain',
          description: 'A brand-like token appears outside the registrable domain.',
          evidence: `Token: ${brand}, Registrable: ${registrableDomain}`,
          recommendation: 'Verify the actual registrable domain before trusting the site.'
        });
      }
    }
    
    // 2. Punycode
    if (effectiveHost.includes('xn--')) {
      indicators.push({
        id: 'PUNYCODE_DOMAIN',
        category: _rt.CATEGORY.DOMAIN,
        severity: _rt.SEVERITY.HIGH,
        weight: 40,
        source: _rt.SOURCE.LOCAL_HEURISTIC,
        title: 'Punycode Domain',
        description: 'Internationalized domain detected. Additional verification is recommended because visually similar characters can be used for impersonation.',
        evidence: effectiveHost,
        recommendation: 'Ensure you intended to visit this internationalized domain.'
      });
    } else if (/[^\x00-\x7F]/.test(effectiveHost)) {
      indicators.push({
        id: 'NON_ASCII_DOMAIN',
        category: _rt.CATEGORY.DOMAIN,
        severity: _rt.SEVERITY.MEDIUM,
        weight: 30,
        source: _rt.SOURCE.LOCAL_HEURISTIC,
        title: 'Non-ASCII Domain',
        description: 'Internationalized domain detected. Additional verification is recommended.',
        evidence: effectiveHost,
        recommendation: 'Verify the characters visually.'
      });
    }
    
    // 3. Unusual Characters / Length
    if (effectiveHost.length > 63) {
      indicators.push({
        id: 'LONG_HOSTNAME',
        category: _rt.CATEGORY.DOMAIN,
        severity: _rt.SEVERITY.LOW,
        weight: 5,
        source: _rt.SOURCE.LOCAL_HEURISTIC,
        title: 'Unusually Long Hostname',
        description: 'The hostname length exceeds common usage patterns.',
        evidence: `Length: ${effectiveHost.length}`,
        recommendation: 'Review for obfuscation.'
      });
    }

    return { indicators, hostname: effectiveHost, registrableDomain, subdomains };
  }
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = DomainAnalyzer;
} else {
  window.DomainAnalyzer = DomainAnalyzer;
}
