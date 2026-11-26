const CACHE_NAME = 'nl-pwa-static-v1';
const STATIC_ASSETS = [
  './manifest.json',
  './apple-touch-icon.png',
  './icon-192.png',
  './icon-512.png'
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then((cache) => cache.addAll(STATIC_ASSETS))
      .catch(() => {})
      .then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys.filter((k) => k !== CACHE_NAME).map((k) => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (event) => {
  const req = event.request;
  if (req.method !== 'GET') return;

  const url = new URL(req.url);
  // Zero-Trust: never cache APIs, Supabase RPCs, or cross-origin requests
  if (url.origin !== self.location.origin) return;
  if (url.pathname.includes('/api/')) return;

  const isStaticIcon = STATIC_ASSETS.some((p) => url.pathname.endsWith(p.replace('./', '/')));
  if (isStaticIcon) {
    event.respondWith(
      caches.match(req).then((cached) => cached || fetch(req))
    );
    return;
  }

  // Network-first for HTML so production updates are always immediate
  event.respondWith(
    fetch(req).catch(() => caches.match(req))
  );
});
