// Service Worker для my-savings
// Показывает уведомления о подписках и вкладах (Web Push + локальные)

self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', e => e.waitUntil(self.clients.claim()));

// Принимаем Web Push от сервера
self.addEventListener('push', event => {
  if (!event.data) return;
  let data;
  try { data = event.data.json(); } catch { data = { title: 'my-savings', body: event.data.text() }; }

  const { title, body, tag, url } = data;
  event.waitUntil(
    self.registration.showNotification(title, {
      body,
      icon: '/icon.png',
      badge: '/icon.png',
      tag: tag || 'my-savings',
      data: { url: url || '/' },
    })
  );
});

// Клик по уведомлению — открываем приложение и передаём action
self.addEventListener('notificationclick', event => {
  event.notification.close();
  const rawUrl = event.notification.data?.url || '/';
  // Строим абсолютный URL относительно scope SW (учитывает /my-savings/ на GitHub Pages)
  const targetUrl = new URL(rawUrl, self.registration.scope).href;
  event.waitUntil(
    self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then(clients => {
      const existing = clients.find(c => c.url.includes(self.location.origin));
      if (existing) {
        // Фокусируем вкладку и посылаем action через postMessage
        return existing.focus().then(() => {
          existing.postMessage({ type: 'NOTIF_ACTION', url: targetUrl });
        });
      }
      return self.clients.openWindow(targetUrl);
    })
  );
});
