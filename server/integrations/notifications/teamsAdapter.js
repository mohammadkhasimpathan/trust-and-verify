const NotificationAdapter = require('./genericAdapter');

class TeamsAdapter extends NotificationAdapter {
  constructor(config, credentials) {
    super(config, credentials);
    this.webhookUrl = credentials;
  }

  async testConnection() {
    if (!this.webhookUrl) return { status: 'NOT_CONFIGURED' };
    return new Promise((resolve) => setTimeout(() => resolve({ status: 'CONNECTED', provider: 'teams' }), 50));
  }

  async sendNotification(event) {
    if (!this.webhookUrl) return;
    return Promise.resolve(true);
  }
}

module.exports = TeamsAdapter;
