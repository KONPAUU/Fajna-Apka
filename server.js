// server.js  — CommonJS (bez "type":"module")
const express = require('express');
const axios = require('axios');
const crypto = require('crypto');
const qs = require('querystring');

const app = express();
app.use(express.json());
const PORT = process.env.PORT || 3100;

/* ========= ENV =========
KICK_CLIENT_ID
KICK_CLIENT_SECRET
KICK_REDIRECT_URI           (np. https://fajna-apka.onrender.com/oauth/callback)
AUTH_URL                    (np. https://id.kick.com/oauth/authorize)
TOKEN_URL                   (opcjonalnie; domyślnie https://id.kick.com/oauth/token)
ALLOWED_SLUGS               (np. holly-s,rybsonlol)
CHATROOM_ID_OVERRIDES       (np. holly-s:56494133,rybsonlol:123456)
BOT_USERNAME                (np. holly_s – tylko informacyjne)
======================== */

const OAUTH_AUTHORIZE = process.env.AUTH_URL || 'https://id.kick.com/oauth/authorize';
const OAUTH_TOKEN = process.env.TOKEN_URL || 'https://id.kick.com/oauth/token';
const API_BASE = process.env.KICK_API_BASE || 'https://kick.com/api';

const CLIENT_ID = process.env.KICK_CLIENT_ID;
const CLIENT_SECRET = process.env.KICK_CLIENT_SECRET;
const REDIRECT_URI = process.env.KICK_REDIRECT_URI || '';

const ALLOWED = new Set(
  (process.env.ALLOWED_SLUGS || '')
    .split(',')
    .map(s => s.trim())
    .filter(Boolean)
);

// parse "slug:chatroomId,slug2:chatroomId2"
function parseOverrides(src) {
  const map = new Map();
  (src || '').split(',').forEach(pair => {
    const [slugRaw, idRaw] = pair.split(':');
    const slug = (slugRaw || '').trim();
    const id = Number((idRaw || '').trim());
    if (slug && Number.isFinite(id)) map.set(slug, id);
  });
  return map;
}
const CHAT_OVERRIDES = parseOverrides(process.env.CHATROOM_ID_OVERRIDES);

// ===== prosty storage tokenów w pamięci =====
let TOKENS = null; // {access_token, refresh_token, token_type, expires_in, obtained_at, scope}

// utils
const nowSec = () => Math.floor(Date.now() / 1000);

// ===== PKCE helpery =====
function genPKCE() {
  const verifier = crypto.randomBytes(32).toString('base64url');
  const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
  return { verifier, challenge };
}
let PKCE_CURRENT = null;

// ====== ROUTES ======
app.get('/health', (_, res) => res.type('text/plain').send('ok'));

// Podgląd tokenów (bez wartości)
app.get('/tokens', (_, res) => {
  if (!TOKENS) return res.json({ has_access_token: false, has_refresh_token: false });
  const { access_token, refresh_token, token_type, expires_in, obtained_at, scope } = TOKENS;
  res.json({
    has_access_token: !!access_token,
    has_refresh_token: !!refresh_token,
    token_type,
    expires_in,
    obtained_at,
    scope
  });
});

// ===== OAuth start
app.get(['/oauth/start', '/auth/start'], async (req, res) => {
  if (!CLIENT_ID || !REDIRECT_URI) {
    return res.status(500).send('Brak KICK_CLIENT_ID lub KICK_REDIRECT_URI w ENV');
  }
  PKCE_CURRENT = genPKCE();
  const state = 'dbg' + Date.now();
  const url =
    OAUTH_AUTHORIZE +
    '?' +
    qs.stringify({
      response_type: 'code',
      client_id: CLIENT_ID,
      redirect_uri: REDIRECT_URI,
      scope: 'user:read chat:write',
      state,
      code_challenge: PKCE_CURRENT.challenge,
      code_challenge_method: 'S256'
    });
  return res.redirect(url);
});

// ===== OAuth callback
app.get(['/oauth/callback', '/auth/callback'], async (req, res) => {
  try {
    const { code } = req.query;
    if (!code) return res.status(400).send('Brak code');
    if (!PKCE_CURRENT) return res.status(400).send('Brak PKCE verifier – uruchom /oauth/start');

    const body = qs.stringify({
      grant_type: 'authorization_code',
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      redirect_uri: REDIRECT_URI,
      code_verifier: PKCE_CURRENT.verifier,
      code
    });

    const { data } = await axios.post(OAUTH_TOKEN, body, {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    });

    TOKENS = {
      access_token: data.access_token,
      refresh_token: data.refresh_token,
      token_type: data.token_type,
      expires_in: Number(data.expires_in || 7200),
      obtained_at: nowSec(),
      scope: data.scope
    };

    return res
      .type('text/plain')
      .send('Tokeny zapisane ✅. Możesz sprawdzić /tokens albo wysłać /chat/test');
  } catch (e) {
    return res
      .status(400)
      .type('text/plain')
      .send('Błąd callback: ' + (e.response?.status || '') + ' ' + (e.message || e.toString()));
  }
});

// ===== odświeżanie tokena
async function ensureAccessToken() {
  if (!TOKENS?.access_token) throw new Error('Brak access_token – uruchom /oauth/start');
  const expiresAt = (TOKENS.obtained_at || 0) + (TOKENS.expires_in || 0);
  if (nowSec() < expiresAt - 90) return TOKENS.access_token;

  if (!TOKENS.refresh_token) throw new Error('Brak refresh_token – autoryzuj ponownie');
  const body = qs.stringify({
    grant_type: 'refresh_token',
    client_id: CLIENT_ID,
    client_secret: CLIENT_SECRET,
    refresh_token: TOKENS.refresh_token
  });

  const { data } = await axios.post(OAUTH_TOKEN, body, {
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
  });

  TOKENS = {
    ...TOKENS,
    access_token: data.access_token,
    refresh_token: data.refresh_token || TOKENS.refresh_token,
    token_type: data.token_type || TOKENS.token_type,
    expires_in: Number(data.expires_in || 7200),
    obtained_at: nowSec(),
    scope: data.scope || TOKENS.scope
  };
  return TOKENS.access_token;
}

// ===== pomocnicze: chatroomId ze slug
async function getChatroomIdForSlug(slug) {
  if (CHAT_OVERRIDES.has(slug)) return CHAT_OVERRIDES.get(slug);

  // fallback: spróbuj pobrać meta kanału (może działać/nie działać – dlatego override jest zalecany)
  try {
    const { data } = await axios.get(`${API_BASE}/v2/channels/${encodeURIComponent(slug)}`);
    const id = data?.data?.chatroom?.id || data?.chatroom?.id || data?.chatroom_id;
    if (Number.isFinite(Number(id))) return Number(id);
  } catch (_) {}
  throw new Error(
    `Nie znam chatroom_id dla sluga "${slug}". Ustaw CHATROOM_ID_OVERRIDES, np.: holly-s:56494133`
  );
}

// ===== wysyłka wiadomości (próbuje kilka ścieżek v2)
async function sendChat({ slug, text }) {
  if (!slug || !text) throw new Error('Brak slug albo text');
  if (!ALLOWED.has(slug)) throw new Error(`Slug "${slug}" nie jest na liście ALLOWED_SLUGS`);

  const chatroomId = await getChatroomIdForSlug(slug);
  const token = await ensureAccessToken();

  const headers = {
    Authorization: `Bearer ${token}`,
    'Content-Type': 'application/json',
    Accept: 'application/json'
  };

  const bodies = [
    // 1) najczęściej spotykany
    {
      url: `${API_BASE}/v2/messages/send`,
      body: { chatroom_id: chatroomId, content: text }
    },
    // 2) alternatywy (różne wersje API w zależności od rolloutów)
    { url: `${API_BASE}/v2/chatrooms/${chatroomId}/messages`, body: { content: text } },
    { url: `${API_BASE}/v2/chats/${chatroomId}/messages`, body: { content: text } }
  ];

  let lastErr;
  for (const attempt of bodies) {
    try {
      const { data, status } = await axios.post(attempt.url, attempt.body, { headers });
      if (status < 300) return { ok: true, endpoint: attempt.url, data };
    } catch (e) {
      lastErr = {
        status: e.response?.status,
        data: e.response?.data,
        message: e.message
      };
    }
  }
  throw new Error('Nie udało się wysłać wiadomości. Ostatni błąd: ' + JSON.stringify(lastErr));
}

// ===== test wysyłki: POST (zalecane)
app.post('/chat/test', async (req, res) => {
  try {
    const { slug, text } = req.body || {};
    const out = await sendChat({ slug, text });
    return res.json({ ok: true, used: out.endpoint });
  } catch (e) {
    return res.status(400).json({ ok: false, error: String(e.message || e) });
  }
});

// ===== test wysyłki: GET (dla wygody w przeglądarce)
app.get('/chat/test', async (req, res) => {
  try {
    const { slug, text } = req.query || {};
    const out = await sendChat({ slug, text });
    return res.json({ ok: true, used: out.endpoint });
  } catch (e) {
    // zwracamy 405 w treści, żebyś widział różnicę kiedy ktoś użyje GET
    return res.status(405).json({ ok: false, error: String(e.message || e) });
  }
});

app.listen(PORT, () => {
  console.log(`auth+bot app listening on :${PORT}`);
  console.log(`Using OAuth prefix: /oauth (authorize: ${OAUTH_AUTHORIZE})`);
});
