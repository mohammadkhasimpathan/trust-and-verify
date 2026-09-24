function redactSensitiveData(text) {
  if (!text) return text;
  
  let redacted = text;
  
  // Basic redaction rules for passwords, API keys, tokens
  redacted = redacted.replace(/password['"]?\s*[:=]\s*['"]?[^\s'",]+['"]?/gi, 'password="<REDACTED>"');
  redacted = redacted.replace(/api[_-]?key['"]?\s*[:=]\s*['"]?[^\s'",]+['"]?/gi, 'api_key="<REDACTED>"');
  redacted = redacted.replace(/bearer\s+[A-Za-z0-9_.-]+/gi, 'Bearer <REDACTED>');
  
  // PII minimization
  redacted = redacted.replace(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g, '<EMAIL>');
  redacted = redacted.replace(/\b\d{3}[-.]?\d{3}[-.]?\d{4}\b/g, '<PHONE>');

  return redacted;
}

module.exports = {
  redactSensitiveData
};
