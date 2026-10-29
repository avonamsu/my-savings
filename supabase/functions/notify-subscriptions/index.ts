// Edge Function: notify-subscriptions
// Без внешних зависимостей — только Web Crypto API + fetch

const VAPID_PUBLIC_KEY = 'BEX9eDHaS6ld8LS2GwbhcyueetVT3pcIsYpmS3Tc0LDO2SllalZmx_H689dpwblvvJfECFNh51x4IRbO1A-ZnfY';
const VAPID_PRIVATE_KEY = Deno.env.get('VAPID_PRIVATE_KEY')!;
const SUPABASE_URL = Deno.env.get('SUPABASE_URL')!;
const SUPABASE_SERVICE_KEY = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;
const NOTIFY_DAYS = [0, 1, 3, 7];

// --- Supabase REST helpers ---

async function sbGet(table: string, select = '*') {
  const res = await fetch(`${SUPABASE_URL}/rest/v1/${table}?select=${select}`, {
    headers: {
      'apikey': SUPABASE_SERVICE_KEY,
      'Authorization': `Bearer ${SUPABASE_SERVICE_KEY}`,
    },
  });
  if (!res.ok) throw new Error(`sbGet ${table}: ${res.status} ${await res.text()}`);
  return res.json();
}

// --- Base64 helpers ---

function base64UrlToUint8Array(base64: string): Uint8Array {
  const pad = base64.length % 4;
  const padded = pad ? base64 + '='.repeat(4 - pad) : base64;
  const binary = atob(padded.replace(/-/g, '+').replace(/_/g, '/'));
  return new Uint8Array([...binary].map(c => c.charCodeAt(0)));
}

function uint8ArrayToBase64Url(arr: Uint8Array): string {
  return btoa(String.fromCharCode(...arr))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

// --- VAPID JWT ---

async function signVapidJwt(audience: string): Promise<string> {
  const header = { typ: 'JWT', alg: 'ES256' };
  const payload = {
    aud: audience,
    exp: Math.floor(Date.now() / 1000) + 12 * 3600,
    sub: 'mailto:push@my-savings.app',
  };
  const encode = (obj: object) => uint8ArrayToBase64Url(
    new TextEncoder().encode(JSON.stringify(obj))
  );
  const unsignedToken = `${encode(header)}.${encode(payload)}`;
  // VAPID private key stored as raw base64url — import as JWK with public key coords from VAPID_PUBLIC_KEY
  const pubKeyBytes = base64UrlToUint8Array(VAPID_PUBLIC_KEY); // 65 bytes: 0x04 + x(32) + y(32)
  const x = uint8ArrayToBase64Url(pubKeyBytes.slice(1, 33));
  const y = uint8ArrayToBase64Url(pubKeyBytes.slice(33, 65));
  const key = await crypto.subtle.importKey(
    'jwk',
    { kty: 'EC', crv: 'P-256', d: VAPID_PRIVATE_KEY, x, y, key_ops: ['sign'] },
    { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']
  );
  const signature = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' }, key,
    new TextEncoder().encode(unsignedToken)
  );
  return `${unsignedToken}.${uint8ArrayToBase64Url(new Uint8Array(signature))}`;
}

// --- AES-128-GCM encryption ---

function concat(...arrays: Uint8Array[]): Uint8Array {
  const total = arrays.reduce((s, a) => s + a.length, 0);
  const result = new Uint8Array(total);
  let offset = 0;
  for (const arr of arrays) { result.set(arr, offset); offset += arr.length; }
  return result;
}

async function encryptPayload(payload: string, p256dhBase64: string, authBase64: string): Promise<Uint8Array> {
  const encoder = new TextEncoder();
  const p256dh = base64UrlToUint8Array(p256dhBase64);
  const auth = base64UrlToUint8Array(authBase64);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const localKeyPair = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey', 'deriveBits']
  );
  const receiverPublicKey = await crypto.subtle.importKey(
    'raw', p256dh, { name: 'ECDH', namedCurve: 'P-256' }, false, []
  );
  const sharedSecret = await crypto.subtle.deriveBits(
    { name: 'ECDH', public: receiverPublicKey }, localKeyPair.privateKey, 256
  );
  const localPublicKeyRaw = await crypto.subtle.exportKey('raw', localKeyPair.publicKey);
  const prkInfo = concat(encoder.encode('WebPush: info\0'), new Uint8Array(p256dh), new Uint8Array(localPublicKeyRaw));
  const prkSalt = await crypto.subtle.importKey('raw', new Uint8Array(sharedSecret), 'HKDF', false, ['deriveBits']);
  const prk = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: auth, info: prkInfo }, prkSalt, 256
  );
  const prkKey = await crypto.subtle.importKey('raw', prk, 'HKDF', false, ['deriveBits']);
  const cekInfo = encoder.encode('Content-Encoding: aes128gcm\0');
  const nonceInfo = encoder.encode('Content-Encoding: nonce\0');
  const cek = await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info: cekInfo }, prkKey, 128);
  const nonce = await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info: nonceInfo }, prkKey, 96);
  const aesKey = await crypto.subtle.importKey('raw', cek, 'AES-GCM', false, ['encrypt']);
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce }, aesKey,
    concat(encoder.encode(payload), new Uint8Array([2]))
  );
  const rs = new Uint8Array(4); new DataView(rs.buffer).setUint32(0, 4096, false);
  const keyId = new Uint8Array(localPublicKeyRaw);
  return concat(salt, rs, new Uint8Array([keyId.length]), keyId, new Uint8Array(ciphertext));
}

// --- Send push ---

// Returns: 'ok' | 'failed' | 'expired' (404/410 = подписка протухла, нужно удалить)
async function sendPush(sub: { endpoint: string; p256dh: string; auth: string }, payload: string): Promise<'ok' | 'failed' | 'expired'> {
  const url = new URL(sub.endpoint);
  const jwt = await signVapidJwt(`${url.protocol}//${url.host}`);
  const resp = await fetch(sub.endpoint, {
    method: 'POST',
    headers: {
      'Authorization': `vapid t=${jwt},k=${VAPID_PUBLIC_KEY}`,
      'Content-Type': 'application/octet-stream',
      'Content-Encoding': 'aes128gcm',
      'TTL': '86400',
    },
    body: await encryptPayload(payload, sub.p256dh, sub.auth),
  });
  if (resp.status === 404 || resp.status === 410) return 'expired'; // подписка недействительна
  return (resp.status === 200 || resp.status === 201) ? 'ok' : 'failed';
}

// --- Main ---

Deno.serve(async (req) => {
  if (req.method !== 'POST' && req.method !== 'GET') {
    return new Response('Method not allowed', { status: 405 });
  }

  try {
    const [userStates, pushSubs] = await Promise.all([
      sbGet('user_state', 'user_id,state,notif_prefs'),
      sbGet('push_subscriptions', 'user_id,endpoint,p256dh,auth'),
    ]);

    const subsByUser = new Map<string, any[]>();
    for (const ps of pushSubs) {
      if (!subsByUser.has(ps.user_id)) subsByUser.set(ps.user_id, []);
      subsByUser.get(ps.user_id)!.push(ps);
    }

    const nowUtc = new Date();
    const currentUtcHour = nowUtc.getUTCHours();
    const todayDate = new Date(nowUtc);
    todayDate.setUTCHours(0, 0, 0, 0);
    const todayTs = todayDate.getTime();
    let sent = 0, skipped = 0;

    for (const { user_id, state, notif_prefs } of userStates) {
      const pushList = subsByUser.get(user_id);
      if (!pushList?.length) continue;

      // Проверяем время: если пользователь задал своё время, уведомляем только в тот час
      if (notif_prefs?.time_utc) {
        const [prefH] = (notif_prefs.time_utc as string).split(':').map(Number);
        if (prefH !== currentUtcHour) { skipped++; continue; }
      } else {
        // По умолчанию 06:00 UTC (09:00 МСК)
        if (currentUtcHour !== 6) { skipped++; continue; }
      }

      // Вспомогательная функция отправки с авто-удалением протухших подписок
      async function dispatchPush(payload: string) {
        for (const ps of pushList!) {
          try {
            const result = await sendPush(ps, payload);
            if (result === 'ok') sent++;
            else if (result === 'expired') {
              await fetch(`${SUPABASE_URL}/rest/v1/push_subscriptions?endpoint=eq.${encodeURIComponent(ps.endpoint)}`, {
                method: 'DELETE',
                headers: { 'apikey': SUPABASE_SERVICE_KEY, 'Authorization': `Bearer ${SUPABASE_SERVICE_KEY}` },
              });
              skipped++;
            } else skipped++;
          } catch (e) {
            console.error('Push error:', e);
            skipped++;
          }
        }
      }

      // ── 1. Подписки: за 0/1/3/7 дней до списания ──
      const subs = (state?.goals ?? []).filter((g: any) => g.type === 'subscription' && g.subDate);
      for (const g of subs) {
        const period = g.subPeriod || 1;
        let next = new Date(g.subDate + 'T00:00:00Z');
        while (next.getTime() < todayTs) next.setUTCMonth(next.getUTCMonth() + period);
        const daysLeft = Math.round((next.getTime() - todayTs) / 86400000);
        if (!NOTIFY_DAYS.includes(daysLeft)) continue;

        const amtStr = g.subCurrency && g.subCurrency !== 'RUB' && g.subAmountOrig
          ? `${Number(g.subAmountOrig).toFixed(2)} ${g.subCurrency}`
          : `${Math.round(g.amount)} ₽`;
        const dateStr = next.toLocaleDateString('ru-RU', { day: 'numeric', month: 'long', timeZone: 'UTC' });
        const emoji = g.emoji || '🔄';
        const dayWord = daysLeft === 0 ? 'списание сегодня' : daysLeft === 1 ? 'завтра' : `через ${daysLeft} ${daysLeft < 5 ? 'дня' : 'дней'}`;
        await dispatchPush(JSON.stringify({
          title: `${emoji} ${g.name} — ${dayWord}`,
          body: `${amtStr} · ${dateStr}`,
          tag: `sub_${g.id}_d${daysLeft}`,
          url: `/?action=renew&id=${g.id}`, // открывает модалку продления при клике
        }));
      }

      // ── 2. Вклады: за 7/3/1/0 дней до окончания ──
      const deposits = (state?.savings ?? []).filter((s: any) => s.isDeposit && s.dateEnd);
      for (const d of deposits) {
        const endDate = new Date(d.dateEnd + 'T00:00:00Z');
        const daysLeft = Math.round((endDate.getTime() - todayTs) / 86400000);
        if (!NOTIFY_DAYS.includes(daysLeft)) continue;

        const amtStr = `${Math.round(d.amount).toLocaleString('ru-RU')} ₽`;
        const dateStr = endDate.toLocaleDateString('ru-RU', { day: 'numeric', month: 'long', timeZone: 'UTC' });
        const dayWord = daysLeft === 0 ? 'истекает сегодня' : daysLeft === 1 ? 'истекает завтра' : `истекает через ${daysLeft} ${daysLeft < 5 ? 'дня' : 'дней'}`;
        await dispatchPush(JSON.stringify({
          title: `🏦 ${d.name || 'Вклад'} — ${dayWord}`,
          body: `${amtStr} · ${dateStr}`,
          tag: `deposit_${d.id}_d${daysLeft}`,
          url: `/?action=deposit&id=${d.id}`, // открывает счета и выделяет вклад
        }));
      }

      // ── 3. Ежемесячный итог: только 1-го числа ──
      if (nowUtc.getUTCDate() === 1) {
        const totalSavings = (state?.savings ?? []).reduce((sum: number, s: any) => sum + (s.amount || 0), 0);
        const totalGoals = (state?.goals ?? [])
          .filter((g: any) => g.type !== 'subscription')
          .reduce((sum: number, g: any) => sum + (g.saved || 0), 0);
        const total = totalSavings + totalGoals;

        // Название прошлого месяца
        const prevMonth = new Date(nowUtc);
        prevMonth.setUTCMonth(prevMonth.getUTCMonth() - 1);
        const monthName = prevMonth.toLocaleDateString('ru-RU', { month: 'long', timeZone: 'UTC' });

        await dispatchPush(JSON.stringify({
          title: `📊 Итог за ${monthName}`,
          body: `Всего накоплено: ${Math.round(total).toLocaleString('ru-RU')} ₽`,
          tag: `monthly_${prevMonth.getUTCFullYear()}_${prevMonth.getUTCMonth()}`,
          url: '/',
        }));
      }
    }

    return new Response(JSON.stringify({ sent, skipped }), {
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (e) {
    console.error('Fatal error:', e);
    return new Response(JSON.stringify({ error: String(e) }), { status: 500 });
  }
});
