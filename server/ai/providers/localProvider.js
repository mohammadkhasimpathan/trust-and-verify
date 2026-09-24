class LocalProvider {
  constructor(config) {
    this.config = config || {};
    this.baseUrl = process.env.AI_BASE_URL || 'http://127.0.0.1:8080';
  }

  async healthCheck() {
    // Return NOT_CONFIGURED by default for local to not block CI or non-AI dev
    return { status: 'NOT_CONFIGURED', provider: 'LOCAL' };
  }

  async analyze(prompt, options) {
    return {
      status: 'UNAVAILABLE',
      reason: 'Local AI not actively running',
      confidence: 0,
      text: ''
    };
  }
}

module.exports = LocalProvider;
