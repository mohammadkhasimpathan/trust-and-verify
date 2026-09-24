/**
 * public/core/riskEngine.js
 * The core Unified Risk Engine. Normalizes scores, categorizes risk, and produces structured outputs.
 */

let _riskTypes;
if (typeof require === 'function') {
  try { _riskTypes = require('./riskTypes'); } catch (e) { /* browser fallback below */ }
}
if (!_riskTypes && typeof window !== 'undefined') { _riskTypes = window.RiskTypes; }
// _riskTypes.THRESHOLDS, CONFIDENCE, SEVERITY are accessed via _riskTypes to avoid
// redeclaring consts that riskTypes.js already placed in the browser global scope.

class RiskEngine {
  /**
   * Generates a normalized risk result.
   * 
   * @param {Object} input
   * @param {string} input.module - e.g., 'email', 'sms', 'file'
   * @param {Array} input.indicators - Array of risk indicators
   * @param {Object} input.metadata - Additional module-specific metadata
   * @param {string} input.engineVersion - Version of the engine (e.g. "2.0")
   */
  static analyze({ module, indicators = [], metadata = {}, engineVersion = '2.0' }) {
    if (!module) throw new Error('RiskEngine requires a module identifier.');

    // 1. Deduplicate Indicators (keep highest weight if duplicate ID)
    const uniqueIndicators = new Map();
    for (const ind of indicators) {
      if (!ind || !ind.id) continue;
      const existing = uniqueIndicators.get(ind.id);
      if (!existing || (ind.weight > existing.weight)) {
        uniqueIndicators.set(ind.id, {
          ...ind,
          weight: typeof ind.weight === 'number' ? ind.weight : 0,
          severity: ind.severity || _riskTypes.SEVERITY.INFO,
          source: ind.source || 'LOCAL_HEURISTIC'
        });
      }
    }

    const processedIndicators = Array.from(uniqueIndicators.values());

    // 2. Aggregate Score
    let rawScore = 0;
    let hasSimulation = false;
    let confidence = _riskTypes.CONFIDENCE.HIGH; // Default to HIGH, degrade if weak heuristics are used

    processedIndicators.forEach(ind => {
      rawScore += ind.weight;
      if (ind.source === 'SIMULATION') hasSimulation = true;
      if (ind.severity === _riskTypes.SEVERITY.INFO && ind.weight === 0) {
        // purely informational, doesn't affect confidence negatively by default
      }
    });

    // 3. Normalize Score
    let score = Math.max(0, Math.min(100, rawScore));

    // 4. Determine Severity & Verdict based on centralized thresholds
    let finalSeverity = _riskTypes.SEVERITY.SAFE;
    let finalVerdict = 'SAFE';

    for (const t of _riskTypes.THRESHOLDS) {
      if (score >= t.min && score <= t.max) {
        finalSeverity = t.severity;
        finalVerdict = t.verdict;
        break;
      }
    }

    // 5. Generate Summary
    const summary = this._generateSummary(score, finalSeverity, processedIndicators);

    // 6. Build Result
    return {
      module,
      score,
      severity: finalSeverity,
      confidence,
      verdict: finalVerdict,
      summary,
      indicators: processedIndicators,
      recommendations: this._extractRecommendations(processedIndicators),
      metadata: {
        ...metadata,
        simulated: hasSimulation
      },
      timestamp: new Date().toISOString(),
      engineVersion
    };
  }

  static _generateSummary(score, severity, indicators) {
    if (score === 0 || indicators.length === 0) {
      return 'No significant risk indicators detected. Content appears benign.';
    }

    const highRiskCount = indicators.filter(i => i.severity === _riskTypes.SEVERITY.CRITICAL || i.severity === _riskTypes.SEVERITY.HIGH).length;
    const medRiskCount = indicators.filter(i => i.severity === _riskTypes.SEVERITY.MEDIUM).length;

    if (highRiskCount > 1) {
      return `Multiple high-risk indicators were detected. The analyzed content demonstrates a strong correlation with malicious activity.`;
    } else if (highRiskCount === 1) {
      return `A high-risk indicator was detected alongside other structural anomalies. Caution advised.`;
    } else if (medRiskCount > 0) {
      return `Suspicious patterns detected. The content deviates from standard security baselines.`;
    } else {
      return `Minor informational anomalies detected. Low overall risk profile.`;
    }
  }

  static _extractRecommendations(indicators) {
    const recs = new Set();
    indicators.forEach(i => {
      if (i.recommendation && i.weight > 0) {
        recs.add(i.recommendation);
      }
    });
    return Array.from(recs);
  }
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = RiskEngine;
} else {
  window.RiskEngine = RiskEngine;
}
