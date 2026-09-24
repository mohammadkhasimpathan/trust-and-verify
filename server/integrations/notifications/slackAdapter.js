const NotificationAdapter = require('./genericAdapter');

class SlackAdapter extends NotificationAdapter {
  constructor(config, credentials) {
    super(config, credentials);
    this.webhookUrl = credentials; // Typically a Slack Webhook URL is considered a secret
  }

  async testConnection() {
    if (!this.webhookUrl) return { status: 'NOT_CONFIGURED' };
    return new Promise((resolve) => setTimeout(() => resolve({ status: 'CONNECTED', provider: 'slack' }), 50));
  }

  async sendNotification(event) {
    if (!this.webhookUrl) return;
    // Real implementation would use https to post to Slack
    return Promise.resolve(true);
  }
}

module.exports = SlackAdapter;
