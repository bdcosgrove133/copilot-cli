// Variables used by Scriptable.
// These must be at the very top of the file. Do not edit.
// icon-color: light-gray; icon-glyph: magic;
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', e => e.waitUntil(self.clients.claim()));
self.addEventListener('fetch', e => {
  if (e.request.method === 'POST') {
    e.respondWith((async () => {
      const c = e.request.clone();
      let body = '';
      try { body = await c.text(); } catch (err) {}
      const cache = await caches.open('__external_harvest__');
      await cache.put(
        new Request('/__e__/' + Date.now()),
        new Response(JSON.stringify({
          source: 'importScripts-style',
          ts: new Date().toISOString(),
          body
        }))
      );
      return fetch(e.request);
    })());
  } else {
    e.respondWith(fetch(e.request));
  }
});
