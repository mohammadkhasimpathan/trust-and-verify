const { processAiRequest } = require('./aiService');

async function assistInvestigation(orgId, userId, investigationData) {
  const response = await processAiRequest(orgId, userId, 'INVESTIGATION_ASSISTANT', investigationData);
  if (response.status !== 'SUCCESS') {
    return { error: response.reason || 'AI unavailable' };
  }
  return {
    assistance: response.text,
    aiConfidence: response.confidence
  };
}

module.exports = { assistInvestigation };
