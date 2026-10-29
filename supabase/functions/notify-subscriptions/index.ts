// Edge Function: notify-subscriptions
// Отправляет Web Push уведомления о подписках (за 7, 3, 1 день и в день списания)
// Запускается ежедневно через Supabase Cron в 09:00 по московскому времени (06:00 UTC)

import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';

const VAPID_PUBLIC_KEY = 'BEX9eDHaS6ld8LS2GwbhcyueetVT3pcIsYpmS3Tc0LDO2SllalZmx_H689dpwblvvJfECFNh51x4IRbO1A-ZnfY';
const VAPID_PRIVATE_KEY = Deno.env.get('VAPID_PRIVATE_KEY')!;
const SUPABASE_URL = Deno.env.get('SUPABASE_URL')!;
const SUPABASE_SERVICE_KEY = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;

const NOTIFY_DAYS = [0, 1, 3, 7];

// --- VAPID helpers ---

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

  const privateKeyBytes = base64UrlToUint8Array(VAPID_PRIVATE_KEY);
  const key = await crypto.subtle.importKey(
    'pkcs8',
    privateKeyBytes,
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['sign']
  );
  const signature = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    key,
    new TextEncoder().encode(unsignedToken)
  );
  return `${unsignedToken}.${uint8ArrayToBase64Url(new Uint8Array(signature))}`;
}

async function sendPush(sub: { endpoint: string; p256dh: string; auth: string }, payload: string): Promise<boolean> {
  const url = new URL(sub.endpoint);
  const audience = `${url.protocol}//${url.host}`;
  const jwt = await signVapidJwt(audience);

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

  return resp.status === 200 || resp.status === 201;
}

// AES-128-GCM encryption for Web Push payload
async function encryptPayload(payload: string, p256dhBase64: string, authBase64: string): Promise<Uint8Array> {
  const encoder = new TextEncoder();
  const p256dh = base64UrlToUint8Array(p256dhBase64);
  const auth = base64UrlToUint8Array(authBase64);
  const plaintext = encoder.encode(payload);

  // Generate salt and local key pair
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const localKeyPair = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveKey', 'deriveBits']
  );

  // Import receiver public key
  const receiverPublicKey = await crypto.subtle.importKey(
    'raw', p256dh,
    { name: 'ECDH', namedCurve: 'P-256' },
    false, []
  );

  // ECDH shared secret
  const sharedSecret = await crypto.subtle.deriveBits(
    { name: 'ECDH', public: receiverPublicKey },
    localKeyPair.privateKey, 256
  );

  // Export local public key
  const localPublicKeyRaw = await crypto.subtle.exportKey('raw', localKeyPair.publicKey);

  // HKDF for PRK
  const authKey = await crypto.subtle.importKey('raw', auth, 'HKDF', false, ['deriveBits']);
  const prkInfo = concat(encoder.encode('WebPush: info\0'), new Uint8Array(p256dh), new Uint8Array(localPublicKeyRaw));
  const prkSalt = await crypto.subtle.importKey('raw', new Uint8Array(sharedSecret), 'HKDF', false, ['deriveBits']);
  const prk = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: auth, info: prkInfo },
    prkSalt, 256
  );

  // CEK and nonce
  const prkKey = await crypto.subtle.importKey('raw', prk, 'HKDF', false, ['deriveBits']);
  const cekInfo = encoder.encode('Content-Encoding: aes128gcm\0');
  const nonceInfo = encoder.encode('Content-Encoding: nonce\0');
  const cek = await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info: cekInfo }, prkKey, 128);
  const nonce = await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info: nonceInfo }, prkKey, 96);

  // Encrypt
  const aesKey = await crypto.subtle.importKey('raw', cek, 'AES-GCM', false, ['encrypt']);
  const paddedPlaintext = concat(plaintext, new Uint8Array([2])); // padding delimiter
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce },
    aesKey, paddedPlaintext
  );

  // Build header: salt(16) + rs(4) + keyid_len(1) + keyid + ciphertext
  const rs = new Uint8Array(4); new DataView(rs.buffer).setUint32(0, 4096, false);
  const keyId = new Uint8Array(localPublicKeyRaw);
  return concat(salt, rs, new Uint8Array([keyId.length]), keyId, new Uint8Array(ciphertext));
}

function concat(...arrays: Uint8Array[]): Uint8Array {
  const total = arrays.reduce((s, a) => s + a.length, 0);
  const result = new Uint8Array(total);
  let offset = 0;
  for (const arr of arrays) { result.set(arr, offset); offset += arr.length; }
  return result;
}

// --- Main handler ---

Deno.serve(async (req) => {
  // Allow cron calls (no auth check needed since we use service role internally)
  if (req.method !== 'POST' && req.method !== 'GET') {
    return new Response('Method not allowed', { status: 405 });
  }

  const sb = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY);

  // Get all users' state (goals with subscriptions)
  const { data: userStates, error: statesErr } = await sb
    .from('user_state')
    .select('user_id, state');

  if (statesErr) {
    return new Response(JSON.stringify({ error: statesErr.message }), { status: 500 });
  }

  // Get all push subscriptions
  const { data: pushSubs, error: subsErr } = await sb
    .from('push_subscriptions')
    .select('user_id, endpoint, p256dh, auth');

  if (subsErr) {
    return new Response(JSON.stringify({ error: subsErr.message }), { status: 500 });
  }

  const subsByUser = new Map<string, typeof pushSubs>();
  for (const ps of pushSubs ?? []) {
    if (!subsByUser.has(ps.user_id)) subsByUser.set(ps.user_id, []);
    subsByUser.get(ps.user_id)!.push(ps);
  }

  const now = new Date();
  now.setUTCHours(0, 0, 0, 0);
  const todayTs = now.getTime();

  let sent = 0, skipped = 0;

  for (const { user_id, state } of userStates ?? []) {
    const pushList = subsByUser.get(user_id);
    if (!pushList || pushList.length === 0) continue;

    const goals: any[] = state?.goals ?? [];
    const subs = goals.filter((g: any) => g.type === 'subscription' && g.subDate);

    for (const g of subs) {
      const period = g.subPeriod || 1;
      let next = new Date(g.subDate + 'T00:00:00Z');
      while (next.getTime() < todayTs) {
        next.setUTCMonth(next.getUTCMonth() + period);
      }
      const daysLeft = Math.round((next.getTime() - todayTs) / 86400000);
      if (!NOTIFY_DAYS.includes(daysLeft)) continue;

      const amtStr = g.subCurrency && g.subCurrency !== 'RUB' && g.subAmountOrig
        ? `${Number(g.subAmountOrig).toFixed(2)} ${g.subCurrency}`
        : `${Math.round(g.amount)} ₽`;
      const dateStr = next.toLocaleDateString('ru-RU', { day: 'numeric', month: 'long', timeZone: 'UTC' });
      const emoji = g.emoji || '🔄';

      let title: string, body: string;
      if (daysLeft === 0) {
        title = `${emoji} ${g.name} — списание сегодня`;
        body = `${amtStr} · ${dateStr}`;
      } else {
        const dayWord = daysLeft === 1 ? 'завтра' : `через ${daysLeft} ${daysLeft < 5 ? 'дня' : 'дней'}`;
        title = `${emoji} ${g.name} — ${dayWord}`;
        body = `${amtStr} · ${dateStr}`;
      }

      const payload = JSON.stringify({ title, body, tag: `sub_${g.id}_d${daysLeft}`, url: '/' });

      for (const ps of pushList) {
        try {
          const ok = await sendPush(ps, payload);
          if (ok) sent++; else skipped++;
        } catch (e) {
          console.error('Push error:', e);
          skipped++;
        }
      }
    }
  }

  return new Response(JSON.stringify({ sent, skipped }), {
    headers: { 'Content-Type': 'application/json' }
  });
});
