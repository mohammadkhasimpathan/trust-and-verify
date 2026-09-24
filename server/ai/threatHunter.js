const { processAiRequest } = require('./aiService');

async function generateHuntingQueries(orgId, userId, threatContext) {
  const response = await processAiRequest(orgId, userId, 'THREAT_HUNTER', threatContext);
  if (response.status !== 'SUCCESS') {
    return { error: response.reason || 'AI unavailable' };
  }
  return {
    queries: response.text,
    aiConfidence: response.confidence
  };
}

module.exports = { generateHuntingQueries };
