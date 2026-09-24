const threatIntel = require('./index');

async function fetchThreatIntel(type, target) {
  // type can be 'url', 'domain', 'hash', 'ip'
  // executeProviders expects 'URL', 'DOMAIN', 'HASH'
  let mappedType = type.toUpperCase();
  if (mappedType === 'IP') mappedType = 'DOMAIN'; // fallback if they treat IP like domain in phase 4, or skip if not supported.
  return await threatIntel.executeProviders(target, mappedType);
}

module.exports = {
  fetchThreatIntel
};
