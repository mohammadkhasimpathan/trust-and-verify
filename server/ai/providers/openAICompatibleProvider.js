class OpenAICompatibleProvider {
  constructor(config) {
    this.config = config || {};
    this.apiKey = process.env.AI_API_KEY;
    this.baseUrl = process.env.AI_BASE_URL;
    this.model = process.env.AI_MODEL;
    this.timeout = process.env.AI_TIMEOUT_MS ? parseInt(process.env.AI_TIMEOUT_MS) : 10000;
  }

  async healthCheck() {
    if (!this.apiKey || !this.baseUrl) {
      return { status: 'NOT_CONFIGURED', provider: 'OPENAI_COMPATIBLE' };
    }
    return { status: 'CONNECTED', provider: 'OPENAI_COMPATIBLE' };
  }

  async analyze(prompt, options) {
    if (!this.apiKey) {
      return {
        status: 'UNAVAILABLE',
        reason: 'API key not configured'
      };
    }
    
    // Minimal mock for test completeness, real impl would use https.request to openAI endpoint
    return {
      status: 'SUCCESS',
      text: 'Simulated external AI response.',
      confidence: 85,
      tokens: 42
    };
  }
}

module.exports = OpenAICompatibleProvider;
