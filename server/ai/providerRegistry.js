const LocalProvider = require('./providers/localProvider');
const OpenAICompatibleProvider = require('./providers/openAICompatibleProvider');

class ProviderRegistry {
  constructor() {
    this.providers = {
      LOCAL: new LocalProvider(),
      OPENAI_COMPATIBLE: new OpenAICompatibleProvider()
    };
  }

  getProvider(type) {
    return this.providers[type] || this.providers.LOCAL;
  }
}

module.exports = new ProviderRegistry();
