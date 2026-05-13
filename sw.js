const CACHE = "lexa-v6";
const ASSETS = [
  "./",
  "./index.html",
  "./manifest.json",
  "./site.webmanifest",
  "./assets/icons/favicon.ico",
  "./assets/icons/web-app-manifest-192x192.png",
  "./assets/icons/web-app-manifest-512x512.png",  "./pages/acces.html",
  "./pages/axel.html",
  "./pages/axel-badges.html",
  "./pages/axel-bio.html",
  "./pages/axel-competences.html",
  "./pages/axel-parcours.html",
  "./pages/dessin.html",
  "./pages/ia.html",
  "./pages/informatique.html",
  "./pages/jeux.html",
  "./assets/js/download-page.js",
  "./assets/css/download-page.css",
  "./pages/download.html",
  "./assets/css/games-app.css",
  "./assets/js/games-app.js",
  "./assets/js/lexa-usage-tracking.js",
  "./assets/data/steam-games.js",
  "./pages/projet.html",
  "./pages/science.html",
  "./pages/streaming.html"
];

self.addEventListener("install", event => {
  event.waitUntil(caches.open(CACHE).then(cache => cache.addAll(ASSETS.map(asset => new Request(asset, { cache: "reload" })))));
  self.skipWaiting();
});

self.addEventListener("activate", event => {
  event.waitUntil(caches.keys().then(keys => Promise.all(keys.filter(key => key !== CACHE).map(key => caches.delete(key)))));
  self.clients.claim();
});

self.addEventListener("fetch", event => {
  if (event.request.method !== "GET") return;
  event.respondWith(caches.match(event.request).then(cached => cached || fetch(event.request).catch(() => caches.match("./index.html"))));
});
