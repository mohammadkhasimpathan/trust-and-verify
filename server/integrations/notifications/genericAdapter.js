class NotificationAdapter {
  constructor(config, credentials) {
    this.config = config;
    this.credentials = credentials;
  }

  async testConnection() {
    throw new Error('Not implemented');
  }

  async sendNotification(event) {
    throw new Error('Not implemented');
  }
}

module.exports = NotificationAdapter;
