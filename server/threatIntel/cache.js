// Simple in-memory cache
const cacheStore = new Map();

module.exports = {
  get: (key) => {
    const item = cacheStore.get(key);
    if (!item) return null;
    if (Date.now() > item.expiry) {
      cacheStore.delete(key);
      return null;
    }
    return item.value;
  },
  set: (key, value, ttlSecs) => {
    cacheStore.set(key, {
      value,
      expiry: Date.now() + (ttlSecs * 1000)
    });
  }
};
