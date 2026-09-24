const SiemAdapter = require('./genericAdapter');

class SentinelAdapter extends SiemAdapter {
  constructor(config, credentials) {
    super(config, credentials);
    this.workspaceId = config.workspaceId;
    this.sharedKey = credentials;
  }

  async testConnection() {
    if (!this.workspaceId || !this.sharedKey) return { status: 'NOT_CONFIGURED' };
    return new Promise((resolve) => setTimeout(() => resolve({ status: 'CONNECTED', provider: 'sentinel' }), 50));
  }

  async sendEvent(event) {
    if (!this.workspaceId || !this.sharedKey) return;
    return Promise.resolve(true);
  }

  async sendBatch(events) {
    for (const ev of events) {
      await this.sendEvent(ev);
    }
  }
}

module.exports = SentinelAdapter;
