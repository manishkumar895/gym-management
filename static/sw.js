const CACHE_NAME = "gym-management-v2";

const STATIC_ASSETS = [
    "/static/manifest.json",
    "/static/css/style.css",
    "/static/icons/icon-192.png",
    "/static/icons/icon-512.png"
];

// Install service worker
self.addEventListener("install", event => {
    event.waitUntil(
        caches.open(CACHE_NAME)
            .then(cache => cache.addAll(STATIC_ASSETS))
            .then(() => self.skipWaiting())
    );
});

// Activate service worker
self.addEventListener("activate", event => {
    event.waitUntil(
        caches.keys().then(cacheNames => {
            return Promise.all(
                cacheNames
                    .filter(name => name.startsWith("gym-management-") && name !== CACHE_NAME)
                    .map(name => caches.delete(name))
            );
        }).then(() => self.clients.claim())
    );
});

// Handle network requests
self.addEventListener("fetch", event => {
    const request = event.request;
    const url = new URL(request.url);

    // Only handle GET requests from this website
    if (request.method !== "GET" || url.origin !== self.location.origin) {
        return;
    }

    // Never cache login, dashboard, member, payment or other dynamic pages
    if (url.pathname === "/login" ||
        url.pathname.startsWith("/members") ||
        url.pathname.startsWith("/payments") ||
        url.pathname.startsWith("/dashboard") ||
        url.pathname.startsWith("/logout")) {
        return;
    }

    // Cache-first strategy for static assets only
    if (url.pathname.startsWith("/static/")) {
        event.respondWith(
            caches.match(request).then(cachedResponse => {
                return cachedResponse || fetch(request).then(response => {
                    if (response.ok) {
                        const responseCopy = response.clone();

                        caches.open(CACHE_NAME).then(cache => {
                            cache.put(request, responseCopy);
                        });
                    }

                    return response;
                });
            })
        );
    }
});