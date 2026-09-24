/**
 * sw.js
 * Service Worker for Trust & Verify.
 * Enables offline launch, static asset caching, and local execution.
 *
 * Phase 0 fixes:
 *  - Added ./utils/simRegistry.js to the cached asset list (was missing).
 *  - Bumped cache version to trust-verify-v2 so old caches are evicted.
 *  - API routes (/api/*) are NEVER served from cache — always fetched live
 *    to prevent stale threat-analysis results from being returned.
 *  - Cache install failure is surfaced as a console error without crashing.
 */

const CACHE_NAME = 'trust-verify-v2';

const STATIC_ASSETS = [
  './',
  './index.html',
  './style.css',
  './app.js',
  './logo.png',
  './manifest.json',
  './utils/headerAnalyzer.js',
  './utils/fileScanner.js',
  './utils/smsAnalyzer.js',
  './utils/callScanner.js',
  './utils/simRegistry.js'   // <-- was missing in v1
];

// ─── Install ───────────────────────────────────────────────────────────────
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches
      .open(CACHE_NAME)
      .then((cache) => {
        console.log('[Service Worker] Caching application shell (v2)...');
        return cache.addAll(STATIC_ASSETS);
      })
      .catch((err) => {
        console.error('[Service Worker] Cache install failed:', err);
        // Allow activation to proceed even if some assets failed to cache.
      })
  );
  // Take control immediately without waiting for old workers to die.
  self.skipWaiting();
});

// ─── Activate ──────────────────────────────────────────────────────────────
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((cacheNames) => {
      return Promise.all(
        cacheNames.map((name) => {
          if (name !== CACHE_NAME) {
            console.log('[Service Worker] Removing old cache:', name);
            return caches.delete(name);
          }
        })
      );
    })
  );
  // Claim all open clients so updated assets are used immediately.
  self.clients.claim();
});

// ─── Fetch ─────────────────────────────────────────────────────────────────
self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);

  // NEVER cache API responses — threat analysis must always be fresh.
  if (url.pathname.startsWith('/api/')) {
    event.respondWith(fetch(event.request));
    return;
  }

  // For static assets: cache-first strategy with network fallback.
  event.respondWith(
    caches.match(event.request).then((cachedResponse) => {
      if (cachedResponse) {
        return cachedResponse;
      }
      return fetch(event.request).catch(() => {
        // Optional: return a generic offline page in a future phase.
        console.warn('[Service Worker] Network fetch failed for:', url.pathname);
      });
    })
  );
});
