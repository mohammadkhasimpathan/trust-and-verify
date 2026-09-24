const { processAiRequest } = require('./aiService');

async function explainRisk(orgId, userId, riskResult) {
  const response = await processAiRequest(orgId, userId, 'RISK_EXPLAINER', riskResult);
  if (response.status !== 'SUCCESS') {
    return { error: response.reason || 'AI unavailable' };
  }
  return {
    explanation: response.text,
    aiConfidence: response.confidence
  };
}

module.exports = { explainRisk };
