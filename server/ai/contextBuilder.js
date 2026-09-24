const { redactSensitiveData } = require('./redaction');

function buildContext(data, options = {}) {
  // We stringify and redact
  const rawJson = JSON.stringify(data);
  const redacted = redactSensitiveData(rawJson);
  
  // Isolate untrusted user data from trusted system instructions if present
  // For Phase 12 simulation we return a simple structured string
  return `=== TRUSTED DATA ===\n${redacted}\n=== UNTRUSTED / RAW DATA ===\n${options.untrustedContext ? redactSensitiveData(options.untrustedContext) : 'None'}`;
}

module.exports = {
  buildContext
};
