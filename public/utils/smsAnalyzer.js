/**
 * smsAnalyzer.js
 * Analyzes SMS/text messages for spam, phishing (smishing), and cyberbullying/harassment signatures.
 */

var _re = (typeof require === 'function' && typeof window === 'undefined') 
  ? require('../core/riskEngine') 
  : (typeof window !== 'undefined' ? window.RiskEngine : null);

function analyzeSMS(smsText) {
  const logs = [];
  const details = [];
  const indicators = [];
  let score = 0;

  if (!smsText || smsText.trim() === '') {
    return {
      threatLevel: 'Unknown',
      score: 0,
      logs: ['[ERROR] No SMS content provided for evaluation.'],
      details: [],
      indicators: []
    };
  }

  logs.push(`[INFO] Initializing SMS text integrity evaluation...`);
  logs.push(`[INFO] Raw Text length: ${smsText.length} characters.`);

  const textLower = smsText.toLowerCase();

  // ==========================================
  // PART A: Phishing & Smishing Heuristics
  // ==========================================
  
  // 1. Phishing links detection (HTTP, shorteners)
  const linkMatches = smsText.match(/https?:\/\/[^\s]+/gi) || [];
  const shortenerRegex = /bit\.ly|tinyurl\.com|t\.co|ow\.ly|is\.gd|buff\.ly|rebrand\.ly/i;
  
  if (linkMatches.length > 0) {
    let linkRisk = 25;
    logs.push(`[WARN] Hyperlink(s) detected in text message.`);
    
    linkMatches.forEach(link => {
      if (shortenerRegex.test(link)) {
        linkRisk += 20;
        logs.push(`[CRITICAL] Link obfuscation shortener flagged: ${link}`);
        details.push({
          type: 'danger',
          title: 'Obfuscated Link Shortener',
          message: 'SMS contains a shortened URL (e.g., bit.ly). Attackers hide malicious phishing portals or download links behind shorteners to bypass filters.'
        });
        indicators.push({
          id: 'SMS_SHORTENED_URL',
          category: 'LINK',
          severity: 'HIGH',
          weight: 20,
          title: 'Obfuscated Link Shortener',
          description: 'SMS contains a shortened URL. Attackers hide malicious phishing portals behind shorteners.',
          evidence: `Link: ${link}`,
          recommendation: 'Do not click the link. Verify through an independent channel.',
          source: 'LOCAL_HEURISTIC'
        });
      } else {
        details.push({
          type: 'warning',
          title: 'External Link in SMS',
          message: `Contains link "${link}". Legitimate institutions rarely send direct login links via text message.`
        });
        indicators.push({
          id: 'SMS_EXTERNAL_URL',
          category: 'LINK',
          severity: 'LOW',
          weight: 5, // Account for the initial +25 that applies to all links (handled below)
          title: 'External Link in SMS',
          description: `Legitimate institutions rarely send direct login links via text message.`,
          evidence: `Link: ${link}`,
          recommendation: 'Verify the link destination carefully before clicking.',
          source: 'LOCAL_HEURISTIC'
        });
      }
    });
    score += linkRisk;
  }

  // 2. Urgent Call-to-Action / Account Suspensions
  const urgencyKeywords = [
    'immediate', 'action required', 'suspend', 'block', 'lock', 'restrict', 'unauthorized', 
    'security alert', 'compromised', 'verify now', 'must update', 'log in immediately', 
    'final warning', 'prevent closure', 'close in 24h', 'pay now', 'expired'
  ];

  let urgencyTriggers = 0;
  urgencyKeywords.forEach(kw => {
    if (textLower.includes(kw)) {
      urgencyTriggers++;
    }
  });

  if (urgencyTriggers > 0) {
    score += Math.min(urgencyTriggers * 15, 40);
    logs.push(`[CRITICAL] Triggered ${urgencyTriggers} urgent call-to-action indicators.`);
    details.push({
      type: 'danger',
      title: 'Urgent Coercive Phishing Language',
      message: 'The text message demands immediate action or warns of account suspension. Artificial panic is the primary weapon in social engineering.'
    });
    indicators.push({
      id: 'SMS_URGENCY_KEYWORD',
      category: 'CONTENT',
      severity: 'HIGH',
      weight: Math.min(urgencyTriggers * 15, 40),
      title: 'Urgent Coercive Phishing Language',
      description: 'The text message demands immediate action or warns of account suspension. Artificial panic is a common tactic.',
      evidence: `${urgencyTriggers} urgency indicator(s) found.`,
      recommendation: 'Do not let urgency force you into clicking links or providing info. Verify the sender independently.',
      source: 'LOCAL_HEURISTIC'
    });
  }

  // 3. Brand Spoofing Checks
  const brands = ['paypal', 'amazon', 'cashapp', 'venmo', 'irs', 'netflix', 'ups', 'fedex', 'dhl', 'bank', 'chase', 'wells fargo', 'usps'];
  let brandFlagged = null;
  
  for (const b of brands) {
    if (textLower.includes(b)) {
      brandFlagged = b;
      break;
    }
  }

  if (brandFlagged) {
    score += 20;
    logs.push(`[WARN] Text claims to represent brand identity: ${brandFlagged.toUpperCase()}`);
    details.push({
      type: 'warning',
      title: `Brand Impersonation Risk`,
      message: `The text references the service "${brandFlagged.toUpperCase()}". Phishing attacks leverage familiar brands to lower user suspicion.`
    });
    indicators.push({
      id: 'SMS_BRAND_SPOOF',
      category: 'IDENTITY',
      severity: 'MEDIUM',
      weight: 20,
      title: 'Brand Impersonation Risk',
      description: `The text references the service "${brandFlagged.toUpperCase()}". Phishing attacks leverage familiar brands.`,
      evidence: `Brand: ${brandFlagged.toUpperCase()}`,
      recommendation: 'Verify the message through the official application or website rather than SMS links.',
      source: 'LOCAL_HEURISTIC'
    });
  }

  // ==========================================
  // PART B: Cyberbullying & Harassment Heuristics
  // ==========================================

  // 1. Direct Threats / Blackmail Coercion
  const threatKeywords = [
    'or else', 'expose you', 'ruin your life', 'tell everyone', 'post your picture', 
    'watch your back', 'know where you live', 'hurt you', 'beat you', 'kill you',
    'leak your', 'find you', 'track you', 'hack your account'
  ];

  let threatCount = 0;
  threatKeywords.forEach(kw => {
    if (textLower.includes(kw)) {
      threatCount++;
    }
  });

  if (threatCount > 0) {
    score += Math.min(threatCount * 25, 55);
    logs.push(`[CRITICAL] Coercive threat language detected.`);
    details.push({
      type: 'danger',
      title: 'Harassment & Threat Coercion',
      message: 'The SMS contains language indicative of blackmail, physical threat, or cyberbullying coercion. Immediately capture logs for security record.'
    });
    indicators.push({
      id: 'SMS_HARASSMENT_THREAT',
      category: 'BEHAVIOR',
      severity: 'CRITICAL',
      weight: Math.min(threatCount * 25, 55),
      title: 'Harassment & Threat Coercion',
      description: 'The SMS contains language indicative of blackmail, physical threat, or cyberbullying coercion.',
      evidence: `${threatCount} threat indicator(s) found.`,
      recommendation: 'Do not respond to threats. Capture evidence and report to authorities or HR if applicable.',
      source: 'LOCAL_HEURISTIC'
    });
  }

  // 2. Insult, Toxic, or Self-Harm Coercion
  const toxicKeywords = [
    'stupid', 'idiot', 'loser', 'worthless', 'kill yourself', 'kys', 'hate you', 'freak', 
    'ugly', 'fat', 'pathetic', 'shut up', 'nobody likes', 'go die', 'disgusting'
  ];

  let toxicCount = 0;
  toxicKeywords.forEach(kw => {
    if (textLower.includes(kw)) {
      toxicCount++;
    }
  });

  if (toxicCount > 0) {
    score += Math.min(toxicCount * 20, 50);
    logs.push(`[CRITICAL] Toxic/insult statements detected.`);
    details.push({
      type: 'danger',
      title: 'Cyberbullying & Verbal Abuse',
      message: 'Identified derogatory names, hostile insults, or messages encouraging self-harm. Cyberbullying and repetitive toxic inputs present high psychological threats.'
    });
    indicators.push({
      id: 'SMS_TOXIC_LANGUAGE',
      category: 'BEHAVIOR',
      severity: 'CRITICAL',
      weight: Math.min(toxicCount * 20, 50),
      title: 'Cyberbullying & Verbal Abuse',
      description: 'Identified derogatory names, hostile insults, or messages encouraging self-harm.',
      evidence: `${toxicCount} toxic indicator(s) found.`,
      recommendation: 'Block the sender. If this is persistent, escalate to moderation or authorities.',
      source: 'LOCAL_HEURISTIC'
    });
  }

  let finalRiskResult = null;
  if (_re) {
    finalRiskResult = _re.analyze({
      module: 'sms',
      indicators,
      metadata: { textLength: smsText.length }
    });
  }

  // Cap score at 100 (legacy)
  score = Math.min(score, 100);

  // Determine threat level based on final score
  let threatLevel = 'Safe';
  if (score >= 80) {
    threatLevel = 'Critical';
  } else if (score >= 50) {
    threatLevel = 'High';
  } else if (score >= 25) {
    threatLevel = 'Medium';
  } else if (score > 0) {
    threatLevel = 'Low';
  }

  logs.push(`[SUCCESS] SMS evaluation complete. Score computed: ${score}% [Rating: ${threatLevel}]`);

  return {
    threatLevel: finalRiskResult ? (finalRiskResult.severity.charAt(0) + finalRiskResult.severity.slice(1).toLowerCase()) : threatLevel,
    score: finalRiskResult ? finalRiskResult.score : score,
    logs,
    details: finalRiskResult ? finalRiskResult.indicators.map(i => ({
      type: (i.severity === 'HIGH' || i.severity === 'CRITICAL') ? 'danger' : 'warning',
      title: i.title,
      message: i.description
    })) : details,
    indicators: finalRiskResult ? finalRiskResult.indicators : indicators,
    verdict: finalRiskResult ? finalRiskResult.verdict : 'UNKNOWN',
    summary: finalRiskResult ? finalRiskResult.summary : ''
  };
}

// Support both CommonJS node environment and global browser export
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { analyzeSMS };
} else {
  window.analyzeSMS = analyzeSMS;
}
