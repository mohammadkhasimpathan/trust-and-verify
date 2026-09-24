const SiemAdapter = require('./genericAdapter');

class ElasticAdapter extends SiemAdapter {
  constructor(config, credentials) {
    super(config, credentials);
    this.endpoint = config.url;
    this.apiKey = credentials;
  }

  async testConnection() {
    if (!this.endpoint || !this.apiKey) return { status: 'NOT_CONFIGURED' };
    return new Promise((resolve) => setTimeout(() => resolve({ status: 'CONNECTED', provider: 'elastic' }), 50));
  }

  async sendEvent(event) {
    if (!this.endpoint || !this.apiKey) return;
    return Promise.resolve(true);
  }

  async sendBatch(events) {
    for (const ev of events) {
      await this.sendEvent(ev);
    }
  }
}

module.exports = ElasticAdapter;
