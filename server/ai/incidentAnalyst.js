const { processAiRequest } = require('./aiService');

async function analyzeIncident(orgId, userId, incidentData) {
  const response = await processAiRequest(orgId, userId, 'INCIDENT_ANALYST', incidentData);
  if (response.status !== 'SUCCESS') {
    return { error: response.reason || 'AI unavailable' };
  }
  return {
    analysis: response.text,
    aiConfidence: response.confidence
  };
}

module.exports = { analyzeIncident };
