/**
 * historyManager.js
 * Handles sanitization and formatting of history records.
 */

function generateUUID() {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
    const r = Math.random() * 16 | 0, v = c === 'x' ? r : (r & 0x3 | 0x8);
    return v.toString(16);
  });
}

function sanitizeUrl(url) {
  if (!url) return '';
  try {
    const parsed = new URL(url);
    if (parsed.username || parsed.password) {
       return `${parsed.protocol}//[REDACTED_CREDENTIALS]@${parsed.host}${parsed.pathname}${parsed.search}`;
    }
    return url;
  } catch(e) {
    return url; // Cannot parse, return as is (might be just a domain)
  }
}

async function createScanRecord(moduleName, rawTarget, riskResult) {
  const id = generateUUID();
  const timestamp = new Date().toISOString();
  
  // Safe display representation
  let safeTarget = sanitizeUrl(rawTarget);
  
  // Basic Hash if Web Crypto available
  let fingerprint = 'unknown';
  if (typeof window !== 'undefined' && window.crypto && window.crypto.subtle) {
    try {
      const enc = new TextEncoder().encode(safeTarget);
      const hashBuffer = await window.crypto.subtle.digest('SHA-256', enc);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      fingerprint = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    } catch(e){}
  }
  
  return {
    id,
    createdAt: timestamp,
    updatedAt: timestamp,
    module: moduleName,
    target: {
      type: moduleName,
      display: safeTarget,
      fingerprint: fingerprint
    },
    result: riskResult,
    source: {
      localAnalysis: true,
      externalThreatIntel: false
    },
    metadata: {
      appVersion: '1.0.0',
      engineVersion: '1.0.0' // Assuming Phase 2 engine version
    }
  };
}

if (typeof window !== 'undefined') window.historyManager = { createScanRecord, sanitizeUrl, generateUUID };
if (typeof module !== 'undefined') module.exports = { createScanRecord, sanitizeUrl, generateUUID };
