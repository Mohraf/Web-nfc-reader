// Offline cache for the app shell. Network-first for HTML so updates show up; cache-first for the rest.
const VERSION = 'cir-v1';
const SHELL = [
  './', 'index.html', 'styles.css', 'manifest.webmanifest', 'icons/icon.svg', 'icons/icon-192.png',
  'js/app.js', 'js/util/bytes.js', 'js/util/tlv.js',
  'js/crypto/des.js', 'js/crypto/aes.js', 'js/crypto/hash.js', 'js/crypto/ec.js', 'js/crypto/curves.js',
  'js/icao/apdu.js', 'js/icao/sm.js', 'js/icao/bac.js', 'js/icao/pace.js', 'js/icao/card.js', 'js/icao/lds.js',
  'js/icao/mrz.js', 'js/icao/passive-auth.js', 'js/icao/reader.js',
  'js/sim/virtual-chip.js', 'js/sim/sim-data.js',
  'js/transports/simulator.js', 'js/transports/android-bridge.js', 'js/transports/ndef-probe.js',
];

self.addEventListener('install', (e) => {
  e.waitUntil(caches.open(VERSION).then((c) => c.addAll(SHELL)).then(() => self.skipWaiting()));
});

self.addEventListener('activate', (e) => {
  e.waitUntil(caches.keys().then((keys) => Promise.all(keys.filter((k) => k !== VERSION).map((k) => caches.delete(k)))).then(() => self.clients.claim()));
});

self.addEventListener('fetch', (e) => {
  const req = e.request;
  if (req.method !== 'GET') return;
  const url = new URL(req.url);
  const sameOrigin = url.origin === self.location.origin;
  const isFont = url.hostname === 'fonts.googleapis.com' || url.hostname === 'fonts.gstatic.com';
  if (!sameOrigin && !isFont) return;
  if (req.mode === 'navigate') {
    e.respondWith(fetch(req).then((res) => { caches.open(VERSION).then((c) => c.put(req, res.clone())); return res; }).catch(() => caches.match(req).then((r) => r || caches.match('index.html'))));
    return;
  }
  e.respondWith(caches.match(req).then((hit) => hit || fetch(req).then((res) => {
    if (res.ok || res.type === 'opaque') { const copy = res.clone(); caches.open(VERSION).then((c) => c.put(req, copy)); }
    return res;
  })));
});
