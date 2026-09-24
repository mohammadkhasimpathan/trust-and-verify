class SiemAdapter {
  constructor(config, credentials) {
    this.config = config;
    this.credentials = credentials;
  }

  async testConnection() {
    throw new Error('Not implemented');
  }

  async sendEvent(event) {
    throw new Error('Not implemented');
  }

  async sendBatch(events) {
    throw new Error('Not implemented');
  }
}

module.exports = SiemAdapter;
