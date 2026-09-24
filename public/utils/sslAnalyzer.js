/**
 * sslAnalyzer.js
 * Frontend adapter to call the backend /api/inspect-ssl endpoint.
 */

const { SEVERITY, CATEGORY, SOURCE } = (typeof window !== 'undefined' && window.RiskTypes) ? window.RiskTypes : require('../core/riskTypes');

class SslAnalyzer {
  static async inspect(hostname, port = 443) {
    try {
      const response = await fetch('/api/inspect-ssl', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ hostname, port })
      });

      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.error || 'SSL inspection failed.');
      }

      return this.processBackendResult(data);
    } catch (e) {
      return {
        indicators: [{
          id: 'SSL_INSPECTION_FAILED',
          category: CATEGORY.NETWORK,
          severity: SEVERITY.HIGH,
          weight: 40,
          source: SOURCE.LOCAL_HEURISTIC,
          title: 'SSL Inspection Failed',
          description: e.message,
          evidence: e.message,
          recommendation: 'Verify the hostname is correct and reachable over the specified port.'
        }],
        sslData: null
      };
    }
  }

  static processBackendResult(data) {
    const indicators = [];
    const cert = data.certificate;
    
    if (data.authorized === false) {
      indicators.push({
        id: 'CERTIFICATE_NOT_AUTHORIZED',
        category: CATEGORY.AUTHENTICATION,
        severity: SEVERITY.CRITICAL,
        weight: 80,
        source: SOURCE.LIVE_CONNECTION || SOURCE.LOCAL_HEURISTIC,
        title: 'Certificate Not Authorized',
        description: 'The certificate is not trusted by the server.',
        evidence: data.authorizationError || 'Unknown Error',
        recommendation: 'Do not trust this server connection.'
      });
    }

    if (!data.hostnameMatched) {
      indicators.push({
        id: 'CERTIFICATE_HOSTNAME_MISMATCH',
        category: CATEGORY.AUTHENTICATION,
        severity: SEVERITY.CRITICAL,
        weight: 80,
        source: SOURCE.LIVE_CONNECTION || SOURCE.LOCAL_HEURISTIC,
        title: 'Hostname Mismatch',
        description: 'The certificate does not match the requested hostname.',
        evidence: `Requested: ${data.hostname}, Found: ${cert.subject?.CN || 'Unknown'}`,
        recommendation: 'The connection may be intercepted or misconfigured.'
      });
    }

    if (data.daysUntilExpiry < 0) {
      indicators.push({
        id: 'CERTIFICATE_EXPIRED',
        category: CATEGORY.AUTHENTICATION,
        severity: SEVERITY.CRITICAL,
        weight: 80,
        source: SOURCE.LIVE_CONNECTION || SOURCE.LOCAL_HEURISTIC,
        title: 'Certificate Expired',
        description: 'The TLS certificate has expired.',
        evidence: `Expired on ${cert.valid_to}`,
        recommendation: 'Do not submit sensitive information.'
      });
    } else if (data.daysUntilExpiry < 15) {
      indicators.push({
        id: 'CERTIFICATE_EXPIRING_SOON',
        category: CATEGORY.AUTHENTICATION,
        severity: SEVERITY.MEDIUM,
        weight: 20,
        source: SOURCE.LIVE_CONNECTION || SOURCE.LOCAL_HEURISTIC,
        title: 'Certificate Expiring Soon',
        description: 'The TLS certificate will expire in less than 15 days.',
        evidence: `Expires in ${Math.floor(data.daysUntilExpiry)} days.`,
        recommendation: 'Server administrator should renew the certificate.'
      });
    }

    // TLS version
    if (data.protocol === 'TLSv1.1' || data.protocol === 'TLSv1') {
      indicators.push({
        id: 'TLS_VERSION_WEAK',
        category: CATEGORY.NETWORK,
        severity: SEVERITY.HIGH,
        weight: 40,
        source: SOURCE.LIVE_CONNECTION || SOURCE.LOCAL_HEURISTIC,
        title: 'Weak TLS Version',
        description: 'The server uses an outdated and insecure TLS protocol.',
        evidence: data.protocol,
        recommendation: 'Upgrade to TLS 1.2 or 1.3.'
      });
    }

    return { indicators, sslData: data };
  }
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = SslAnalyzer;
} else {
  window.SslAnalyzer = SslAnalyzer;
}
