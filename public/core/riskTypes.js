/**
 * public/core/riskTypes.js
 * Centralized types, enums, and severity thresholds for the Unified Risk Engine.
 */

const SEVERITY = {
  SAFE: 'SAFE',
  INFO: 'INFO',
  LOW: 'LOW',
  MEDIUM: 'MEDIUM',
  HIGH: 'HIGH',
  CRITICAL: 'CRITICAL'
};

const VERDICT = {
  SAFE: 'SAFE',
  INFORMATIONAL: 'INFORMATIONAL',
  SUSPICIOUS: 'SUSPICIOUS',
  HIGH_RISK: 'HIGH_RISK',
  CRITICAL_RISK: 'CRITICAL_RISK'
};

const CONFIDENCE = {
  LOW: 'LOW',
  MEDIUM: 'MEDIUM',
  HIGH: 'HIGH'
};

const SOURCE = {
  LOCAL_HEURISTIC: 'LOCAL_HEURISTIC',
  USER_INPUT: 'USER_INPUT',
  SIMULATION: 'SIMULATION'
};

const CATEGORY = {
  AUTHENTICATION: 'AUTHENTICATION',
  IDENTITY: 'IDENTITY',
  DOMAIN: 'DOMAIN',
  NETWORK: 'NETWORK',
  ROUTING: 'ROUTING',
  CONTENT: 'CONTENT',
  ATTACHMENT: 'ATTACHMENT',
  LINK: 'LINK',
  BEHAVIOR: 'BEHAVIOR',
  REPUTATION: 'REPUTATION',
  DEVICE: 'DEVICE',
  SIMULATION: 'SIMULATION'
};

// Centralized score thresholds mapping numeric ranges to severity/verdict
const THRESHOLDS = [
  { min: 80, max: 100, severity: SEVERITY.CRITICAL, verdict: VERDICT.CRITICAL_RISK },
  { min: 60, max: 79,  severity: SEVERITY.HIGH,     verdict: VERDICT.HIGH_RISK },
  { min: 30, max: 59,  severity: SEVERITY.MEDIUM,   verdict: VERDICT.SUSPICIOUS },
  { min: 10, max: 29,  severity: SEVERITY.LOW,      verdict: VERDICT.INFORMATIONAL },
  { min: 0,  max: 9,   severity: SEVERITY.SAFE,     verdict: VERDICT.SAFE }
];

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { SEVERITY, VERDICT, CONFIDENCE, SOURCE, CATEGORY, THRESHOLDS };
} else {
  window.RiskTypes = { SEVERITY, VERDICT, CONFIDENCE, SOURCE, CATEGORY, THRESHOLDS };
}
