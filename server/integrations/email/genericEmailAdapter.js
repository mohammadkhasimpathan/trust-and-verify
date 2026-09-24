class EmailIntegrationAdapter {
  constructor(config, credentials) {
    this.config = config;
    this.credentials = credentials;
  }

  async testConnection() {
    return { status: 'NOT_CONFIGURED' };
  }

  async connect() {
    throw new Error('Not implemented');
  }

  async disconnect() {
    throw new Error('Not implemented');
  }

  async fetchMessage(messageId) {
    throw new Error('Not implemented');
  }

  async fetchHeaders(messageId) {
    throw new Error('Not implemented');
  }
}

module.exports = EmailIntegrationAdapter;
