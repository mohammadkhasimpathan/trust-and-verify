/**
 * headerAnalyzer.js
 * Analyzes raw email headers for signs of spoofing, phishing, and authentication failures.
 */

function analyzeHeaders(rawHeaders) {
  const reports = [];
  let score = 0; // 0 (Safe) to 100 (Critical)
  const details = [];

  if (!rawHeaders || rawHeaders.trim() === '') {
    return {
      threatLevel: 'Unknown',
      score: 0,
      logs: ['[ERROR] No headers provided for analysis.'],
      details: []
    };
  }

  // Split headers by line
  const lines = rawHeaders.split(/\r?\n/);
  
  // 1. Check Display Name vs Email Address Mismatch (Display Name Spoofing)
  // Example: From: "Google Security" <security-alert-xyz@attacker.com>
  let fromHeader = '';
  for (const line of lines) {
    if (line.match(/^From:/i)) {
      fromHeader = line;
      break;
    }
  }

  if (fromHeader) {
    const displayNameMatch = fromHeader.match(/From:\s*"?([^"<]+)"?\s*<([^>]+)>/i);
    if (displayNameMatch) {
      const displayName = displayNameMatch[1].trim();
      const email = displayNameMatch[2].trim();
      const emailDomain = email.split('@')[1] || '';
      
      // If display name contains a well-known brand but domain doesn't match
      const brands = ['google', 'microsoft', 'paypal', 'netflix', 'amazon', 'apple', 'facebook', 'bank', 'support'];
      const displayNameLower = displayName.toLowerCase();
      
      let brandFound = null;
      for (const brand of brands) {
        if (displayNameLower.includes(brand)) {
          brandFound = brand;
          break;
        }
      }

      if (brandFound && !emailDomain.toLowerCase().includes(brandFound)) {
        score += 35;
        details.push({
          type: 'danger',
          title: 'Display Name Spoofing Detected',
          message: `The sender display name claims to be "${displayName}", but the email address domain is "@${emailDomain}" which is unaffiliated. This is a common phishing technique.`
        });
        reports.push(`[CRITICAL] Display Name Spoofing: Brand "${brandFound.toUpperCase()}" claimed in name, but domain is "@${emailDomain}"`);
      } else {
        reports.push(`[OK] Sender header structure: "${displayName}" <${email}>`);
      }
    } else {
      reports.push(`[WARN] From header has atypical format: ${fromHeader}`);
    }
  } else {
    score += 20;
    reports.push(`[CRITICAL] Missing standard 'From:' header in email.`);
    details.push({
      type: 'warning',
      title: 'Missing Sender Identity',
      message: 'The email header does not contain a standard "From" field, which is highly unusual and often indicates automated spam tools.'
    });
  }

  // Helper to extract values from headers
  const getHeaderValue = (headerName) => {
    const regex = new RegExp(`^${headerName}:\\s*(.*)$`, 'i');
    for (let i = 0; i < lines.length; i++) {
      let line = lines[i];
      if (regex.test(line)) {
        // Handle multiline headers
        let value = line.match(regex)[1];
        let j = i + 1;
        while (j < lines.length && (lines[j].startsWith(' ') || lines[j].startsWith('\t'))) {
          value += ' ' + lines[j].trim();
          j++;
        }
        return value;
      }
    }
    return null;
  };

  // 2. Check SPF (Sender Policy Framework)
  // Look in Received-SPF or Authentication-Results
  const receivedSPF = getHeaderValue('Received-SPF') || '';
  const authResults = getHeaderValue('Authentication-Results') || '';

  let spfStatus = 'unknown';
  if (receivedSPF.toLowerCase().includes('fail') || receivedSPF.toLowerCase().includes('softfail')) {
    spfStatus = 'fail';
  } else if (receivedSPF.toLowerCase().includes('pass')) {
    spfStatus = 'pass';
  } else if (authResults) {
    if (authResults.toLowerCase().includes('spf=fail') || authResults.toLowerCase().includes('spf=softfail')) {
      spfStatus = 'fail';
    } else if (authResults.toLowerCase().includes('spf=pass')) {
      spfStatus = 'pass';
    }
  }

  if (spfStatus === 'fail') {
    score += 30;
    reports.push(`[CRITICAL] SPF verification failed. The sending server is not authorized by the sender domain's SPF record.`);
    details.push({
      type: 'danger',
      title: 'SPF Authentication Failed',
      message: 'SPF (Sender Policy Framework) check failed. This means the server sending the email is not listed in the domain owner\'s DNS, a strong indicator of email spoofing.'
    });
  } else if (spfStatus === 'pass') {
    reports.push(`[OK] SPF verification passed.`);
  } else {
    score += 10;
    reports.push(`[WARN] SPF record authentication results are missing or inconclusive.`);
    details.push({
      type: 'warning',
      title: 'Missing SPF Authentication',
      message: 'No SPF record check could be validated. Phishing emails often target domains with missing or unconfigured SPF records.'
    });
  }

  // 3. Check DKIM (DomainKeys Identified Mail)
  let dkimStatus = 'unknown';
  if (authResults) {
    if (authResults.toLowerCase().includes('dkim=fail')) {
      dkimStatus = 'fail';
    } else if (authResults.toLowerCase().includes('dkim=pass')) {
      dkimStatus = 'pass';
    }
  }
  
  // Also scan if a DKIM-Signature header exists
  const dkimSignature = getHeaderValue('DKIM-Signature');

  if (dkimStatus === 'fail') {
    score += 25;
    reports.push(`[CRITICAL] DKIM signature verification failed. The email message may have been altered in transit.`);
    details.push({
      type: 'danger',
      title: 'DKIM Validation Failed',
      message: 'DKIM cryptographic signature verification failed. This implies that either the email contents were tampered with during delivery or the sender spoofed the signature.'
    });
  } else if (dkimStatus === 'pass') {
    reports.push(`[OK] DKIM signature validated successfully.`);
  } else if (!dkimSignature) {
    score += 15;
    reports.push(`[WARN] Email lacks a DKIM cryptographic signature.`);
    details.push({
      type: 'warning',
      title: 'No DKIM Cryptographic Signature',
      message: 'The email does not contain a DKIM signature. Without DKIM, it is impossible to cryptographically verify that the email actually originated from the claimed sender domain.'
    });
  } else {
    reports.push(`[OK] DKIM signature is present (Pending client verification).`);
  }

  // 4. Check DMARC
  let dmarcStatus = 'unknown';
  if (authResults) {
    if (authResults.toLowerCase().includes('dmarc=fail')) {
      dmarcStatus = 'fail';
    } else if (authResults.toLowerCase().includes('dmarc=pass')) {
      dmarcStatus = 'pass';
    }
  }

  if (dmarcStatus === 'fail') {
    score += 25;
    reports.push(`[CRITICAL] DMARC alignment check failed.`);
    details.push({
      type: 'danger',
      title: 'DMARC Alignment Failure',
      message: 'DMARC (Domain-based Message Authentication) failed. DMARC requires that the sender address aligns with SPF and/or DKIM domains. Failures suggest spoofing.'
    });
  } else if (dmarcStatus === 'pass') {
    reports.push(`[OK] DMARC alignment passed.`);
  } else {
    reports.push(`[WARN] DMARC policy check omitted in authentication headers.`);
  }

  // 5. Look for suspicious/abnormal relays in "Received" headers
  let hopCount = 0;
  let suspiciousRelays = 0;
  for (const line of lines) {
    if (line.match(/^Received:/i)) {
      hopCount++;
      // Check for generic/suspicious relay markers (e.g. generic hosting, dyn-ip, localhost overrides)
      if (line.toLowerCase().includes('localhost') && hopCount > 1) {
        suspiciousRelays++;
      }
      if (line.toLowerCase().includes('dynamic') || line.toLowerCase().includes('dhcp') || line.toLowerCase().includes('dialup')) {
        suspiciousRelays++;
      }
    }
  }

  if (suspiciousRelays > 0) {
    score += 15;
    reports.push(`[WARN] Detected ${suspiciousRelays} suspicious mail relay hops.`);
    details.push({
      type: 'warning',
      title: 'Suspicious Relay Path',
      message: 'The email passed through dynamic IP ranges or abnormal mail relays, which are often used by botnets or personal computers sending spam.'
    });
  } else if (hopCount > 0) {
    reports.push(`[INFO] Email path check: analyzed ${hopCount} mail hop relay(s).`);
  }

  // Determine threat level based on score
  let threatLevel = 'Safe';
  if (score >= 70) {
    threatLevel = 'Critical';
  } else if (score >= 45) {
    threatLevel = 'High';
  } else if (score >= 25) {
    threatLevel = 'Medium';
  } else if (score > 0) {
    threatLevel = 'Low';
  }

  return {
    threatLevel,
    score: Math.min(score, 100),
    logs: reports,
    details
  };
}

// Support both CommonJS node environment and global browser export
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { analyzeHeaders };
} else {
  window.analyzeHeaders = analyzeHeaders;
}
