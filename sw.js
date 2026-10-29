// Service Worker для my-savings
// Показывает уведомления о подписках и вкладах

self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', e => e.waitUntil(self.clients.claim()));

// Принимаем сообщения от страницы (для будущего расширения)
self.addEventListener('message', event => {
  if (event.data && event.data.type === 'CHECK_NOTIFICATIONS') {
    // страница сама считает и вызывает Notification — SW только в резерве
  }
});

// Клик по уведомлению — открываем приложение
self.addEventListener('notificationclick', event => {
  event.notification.close();
  event.waitUntil(
    self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then(clients => {
      // Если вкладка уже открыта — фокусируем её
      const existing = clients.find(c => c.url.includes(self.location.origin));
      if (existing) return existing.focus();
      // Иначе открываем новую
      return self.clients.openWindow('/');
    })
  );
});
