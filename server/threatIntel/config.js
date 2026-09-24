module.exports = {
  enabled: true,
  providers: {
    virustotal: true,
    googleSafeBrowsing: true,
    phishtank: true,
    urlhaus: true
  },
  timeouts: {
    provider: 8000,
    overall: 15000
  },
  cache: {
    enabled: true,
    ttlSecs: 300 // 5 mins
  }
};
