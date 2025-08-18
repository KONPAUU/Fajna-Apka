// server.js  (ESM)
import express from 'express';
import axios from 'axios';
import crypto from 'crypto';
import qs from 'querystring';

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const PORT = process.env.PORT || 3100;

// ===== In-memory token store (na Render bez dysku wystarczy) =====
let TOKENS = {
  access_token: null,
  refresh_token: null,
  token_type: 'Bearer',
  scope: null,
  obtained_at: 0,
  expires_in: 0
};

// ===== PKCE helpers =====
const randomBase64URL = (len = 32) =>
  crypto.randomBytes(len).toString('base64url');

const sha256b64url = (input) =>
  crypto.createHash('sha256').update(input).digest('base64url');

// ====== OAuth config ======
const KICK_ID_BASE = 'https://id.kick.com';
const AUTHORIZE_URL = `${KICK_ID_BASE}/oauth/authorize`;
const TOKEN_URL = `${KICK_ID_BASE}/oauth/token`;

const CLIENT_ID = process.env.KICK_CLIENT_ID;
const CLIENT_SECRET = process.env.KICK_CLIENT_SECRET || '';
const REDIRECT_URI = process.env.KICK_REDIRECT_URI; // np. https://fajna-apka.onrender.com/oauth/callback

// trzymamy ostatni verifier/state w pamięci na czas logowania
let lastVerifier = null;
let lastState = null;

// ====== Health ======
app.get('/health', (_req, res) => res.type('text').send('ok'));

// ====== pokaż wygenerowany URL do autoryzacji (debug) ======
app.get('/oauth/url', (_req, res) => {
  const state = `dbg${Date.now()}`;
  const verifier = randomBase64URL(64);
  const challenge = sha256b64url(verifier);

  const url = `${AUTHORIZE_URL}?response_type=code&client_id=${encodeURIComponent(
    CLIENT_ID
  )}&redirect_uri=${encodeURIComponent(
    REDIRECT_URI
  )}&scope=${encodeURIComponent('user:read chat:write')}&state=${encodeURIComponent(
    state
  )}&code_challenge=${encodeURIComponent(
    challenge
  )}&code_challenge_method=S256`;

  res.type('text').send(url);
});

// ====== start OAuth (redirect) ======
app.get('/oauth/start', (_req, res) => {
  lastVerifier = randomBase64URL(64);
  lastState = `dbg${Date.now()}`;
  const challenge = sha256b64url(lastVerifier);

  const url = `${AUTHORIZE_URL}?response_type=code&client_id=${encodeURIComponent(
    CLIENT_ID
  )}&redirect_uri=${encodeURIComponent(
    REDIRECT_URI
  )}&scope=${encodeURIComponent('user:read chat:write')}&state=${encodeURIComponent(
    lastState
  )}&code_challenge=${encodeURIComponent(
    challenge
  )}&code_challenge_method=S256`;

  return res.redirect(url);
});

// ====== callback z Kick ======
app.get('/oauth/callback', async (req, res) => {
  try {
    const { code, state } = req.query;
    if (!code) return res.status(400).send('Brak code w callbacku.');
    if (!state || state !== lastState) return res.status(400).send('Zły state.');

    const data = {
      grant_type: 'authorization_code',
      client_id: CLIENT_ID,
      redirect_uri: REDIRECT_URI,
      code_verifier: lastVerifier,
      code
    };
    // jeśli masz app typu confidential, dołóż client_secret
    if (CLIENT_SECRET) data.client_secret = CLIENT_SECRET;

    const r = await axios.post(TOKEN_URL, qs.stringify(data), {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    });

    TOKENS = {
      ...TOKENS,
      ...r.data,
      obtained_at: Math.floor(Date.now() / 1000)
    };

    return res
      .type('text')
      .send('Tokeny zapisane ✅. Możesz sprawdzić /tokens albo wysłać /chat/test');
  } catch (e) {
    const msg =
      e?.response?.data
        ? JSON.stringify(e.response.data)
        : String(e.message || e);
    return res.status(500).type('text').send(`Błąd callback: ${msg}`);
  }
});

// ====== podgląd tokenów (minimalny) ======
app.get('/tokens', (_req, res) => {
  const { access_token, refresh_token, token_type, scope, expires_in, obtained_at } =
    TOKENS || {};
  res.json({
    has_access_token: !!access_token,
    has_refresh_token: !!refresh_token,
    token_type,
    expires_in,
    obtained_at,
    scope
  });
});

// ===== helper: czy access wygasł? =====
function isExpired() {
  if (!TOKENS?.access_token || !TOKENS?.expires_in || !TOKENS?.obtained_at)
    return true;
  const now = Math.floor(Date.now() / 1000);
  // odśwież 60s przed czasem
  return now >= TOKENS.obtained_at + TOKENS.expires_in - 60;
}

// ===== helper: refresh tokena =====
async function ensureAccessToken() {
  if (!TOKENS?.access_token) throw new Error('Brak access token – wykonaj /oauth/start');
  if (!isExpired()) return TOKENS.access_token;

  if (!TOKENS?.refresh_token) throw new Error('Brak refresh token – zaloguj ponownie');

  const data = {
    grant_type: 'refresh_token',
    client_id: CLIENT_ID,
    refresh_token: TOKENS.refresh_token
  };
  if (CLIENT_SECRET) data.client_secret = CLIENT_SECRET;

  const r = await axios.post(TOKEN_URL, qs.stringify(data), {
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
  });

  TOKENS = {
    ...TOKENS,
    ...r.data,
    obtained_at: Math.floor(Date.now() / 1000)
  };
  return TOKENS.access_token;
}

// ====== wysyłka wiadomości na nowym, oficjalnym endpointcie ======
async function sendChatMessage({ text, replyToId = null }) {
  if (!text || !text.trim()) throw new Error('Brak treści wiadomości');
  const access = await ensureAccessToken();

  // Oficjalny endpoint: https://api.kick.com/public/v1/chat
  // Jako bot: type = "bot" (broadcaster_user_id ignorowany)
  const body = {
    content: text.substring(0, 500),
    type: 'bot'
  };
  if (replyToId) body.reply_to_message_id = String(replyToId);

  const r = await axios.post('https://api.kick.com/public/v1/chat', body, {
    headers: {
      Authorization: `Bearer ${access}`,
      'Content-Type': 'application/json',
      Accept: 'application/json'
    },
    // mały timeout, żeby szybciej zobaczyć ewentualny błąd
    timeout: 10000
  });

  return r.data; // { data: { is_sent, message_id }, message }
}

// ====== GET test (querystring) ======
app.get('/chat/test', async (req, res) => {
  try {
    const text = (req.query.text || '').toString();
    // slug jest opcjonalny – ignorujemy (Kick i tak wyśle na kanał konta z tokena)
    const result = await sendChatMessage({ text });
    return res.json({ ok: true, result });
  } catch (e) {
    const err =
      e?.response?.data
        ? e.response.data
        : { message: e.message || 'unknown error' };
    return res.status(400).json({ ok: false, error: err });
  }
});

// ====== POST test (JSON: { text, replyToId? }) ======
app.post('/chat/test', async (req, res) => {
  try {
    const { text, replyToId } = req.body || {};
    const result = await sendChatMessage({ text, replyToId });
    return res.json({ ok: true, result });
  } catch (e) {
    const err =
      e?.response?.data
        ? e.response.data
        : { message: e.message || 'unknown error' };
    return res.status(400).json({ ok: false, error: err });
  }
});

app.listen(PORT, () => {
  console.log(`auth+bot app listening on :${PORT}`);
  console.log(
    `Using OAuth prefix: /oauth (authorize: ${AUTHORIZE_URL})`
  );
});
