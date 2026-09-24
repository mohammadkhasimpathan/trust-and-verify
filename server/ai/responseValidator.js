function validateResponse(response, schema) {
  if (!response || response.status === 'UNAVAILABLE') {
    return response;
  }
  
  // Basic validation that output is an object for JSON requests
  if (schema === 'json' && typeof response.text !== 'string') {
    return { status: 'INVALID_OUTPUT', reason: 'Expected string but got ' + typeof response.text };
  }
  
  return response;
}

module.exports = {
  validateResponse
};
