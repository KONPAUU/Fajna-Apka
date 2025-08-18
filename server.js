// server.js  (ESM)
// Node 18+ / package.json musi mieć:  "type": "module"

import express from 'express';
import crypto from 'crypto';
import axios from 'axios';
import fs from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';

// ---------------------------
// Konfiguracja z ENV + defaulty
// ---------------------------
const PORT = process.env.PORT || 3100;

const KICK_CLIENT_ID = process.env.KICK_CLIENT_ID || '';
const KICK_CLIENT_SECRET = process.env.KICK_CLIENT_SECRET || ''; // opcjonalny (PKCE działa i bez)
const KICK_REDIRECT_URI =
  process.env.KICK_REDIRECT_URI || 'http://localhost:3100/oauth/callback';

const AUTH_URL = process.env.AUTH_URL || 'https://id.kick.com/oauth/authorize';
const TOKEN_URL = process.env.TOKEN_URL || 'https://id.kick.com/oauth/token';
const KICK_API_BASE = process.env.KICK_API_BASE || 'https://kick.com/api/v2';

// dozwolone slugi (po przecinku/spacji/nowej linii)
const ALLOWED_SLUGS = (process.env.ALLOWED_SLUGS || '')
  .split(/[,\s]+/)
  .map((s) => s.trim())
  .filter(Boolean);

// overrides w formacie: "slug1:123,slug2:456" lub po liniach
const CHATROOM_ID_OVERRIDES = parseOverrides(
  process.env.CHATROOM_ID_OVERRIDES || ''
);

function parseOverrides(str) {
  const map = new Map();
  (str || '')
    .split(/[\n,]+/)
    .map((s) => s.trim())
    .filter(Boolean)
    .forEach((pair) => {
      const [slug, id] = pair.split(':').map((x) => x.trim());
      if (slug && id) map.set(slug, id);
    });
  return map;
}

// ---------------------------
// Prosty storage tokenów
// (in-memory + plik tymczasowy w katalogu roboczym)
// ---------------------------
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const TOKENS_PATH = path.join(__dirname, '.tokens.json');

let tokens = null; // { access_token, refresh_token, token_type, expires_in, obtained_at, scope }

async function loadTokens() {
  try {
    const raw = await fs.readFile(TOKENS_PATH, 'utf8');
    tokens = JSON.parse(raw);
  } catch {
    tokens = null;
  }
}

async function saveTokens(obj) {
  tokens = {
    ...obj,
    obtained_at: Date.now(),
  };
  try {
    await fs.writeFile(TOKENS_PATH, JSON.stringify(tokens), 'utf8');
  } catch {
    // brak uprawnień do zapisu? trudno – zostają w pamięci
  }
}

function tokenExpiresSoon() {
  if (!tokens?.access_token || !tokens?.expires_in || !tokens?.obtained_at) {
    return true;
  }
  const expiresAt = tokens.obtained_at + (tokens.expires_in - 60) * 1000; // bufor 60s
  return Date.now() >= expiresAt;
}

// ---------------------------
// PKCE utils
// ---------------------------
function base64url(input) {
  return Buffer.from(input)
    .toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}
function genVerifier() {
  return base64url(crypto.randomBytes(32));
}
function challengeS256(verifier) {
  const hash = crypto.createHash('sha256').update(verifier).digest();
  return base64url(hash);
}

// Trzymamy aktualny verifier dla trwającej autoryzacji
let currentCodeVerifier = null;

// ---------------------------
// Express app
// ---------------------------
const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// prosty UA do wywołań na kick.com
const http = axios.create({
  headers: {
    'User-Agent':
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123 Safari/537.36',
    Accept: 'application/json, text/plain, */*',
    Origin: 'https://kick.com',
    Referer: 'https://kick.com/',
  },
  timeout: 15000,
});

// ---------------------------
// Health
// ---------------------------
app.get('/health', (_req, res) => res.type('text').send('ok'));

// ---------------------------
// OAuth – start
// ---------------------------
app.get('/oauth/start', (req, res) => {
  if (!KICK_CLIENT_ID || !KICK_REDIRECT_URI) {
    return res
      .status(500)
      .send('Brak KICK_CLIENT_ID lub KICK_REDIRECT_URI w ENV');
  }
  const verifier = genVerifier();
  const challenge = challengeS256(verifier);
  currentCodeVerifier = verifier;

  const scope = encodeURIComponent('user:read chat:write');
  const url =
    `${AUTH_URL}?response_type=code` +
    `&client_id=${encodeURIComponent(KICK_CLIENT_ID)}` +
    `&redirect_uri=${encodeURIComponent(KICK_REDIRECT_URI)}` +
    `&scope=${scope}` +
    `&code_challenge=${encodeURIComponent(challenge)}` +
    `&code_challenge_method=S256` +
    `&state=dbg${Date.now()}`;

  res.redirect(url);
});

// pomocniczo – wypisuje URL autoryzacji (bez redirectu)
app.get('/oauth/url', (_req, res) => {
  const verifier = genVerifier();
  const challenge = challengeS256(verifier);
  currentCodeVerifier = verifier;

  const scope = encodeURIComponent('user:read chat:write');
  const url =
    `${AUTH_URL}?response_type=code` +
    `&client_id=${encodeURIComponent(KICK_CLIENT_ID)}` +
    `&redirect_uri=${encodeURIComponent(KICK_REDIRECT_URI)}` +
    `&scope=${scope}` +
    `&code_challenge=${encodeURIComponent(challenge)}` +
    `&code_challenge_method=S256` +
    `&state=dbg${Date.now()}`;

  res.type('text').send(url);
});

// ---------------------------
// OAuth – callback (wymiana code -> tokeny)
// ---------------------------
app.get('/oauth/callback', async (req, res) => {
  try {
    const { code } = req.query;
    if (!code) return res.status(400).send('Brak ?code=');

    if (!currentCodeVerifier) {
      // np. restart – nadal da się wymienić jeśli backend pamięta verifier;
      // gdy go brak – poproś o ponowny /oauth/start
      return res
        .status(400)
        .send('Brak code_verifier (uruchom ponownie /oauth/start).');
    }

    const form = new URLSearchParams();
    form.set('grant_type', 'authorization_code');
    form.set('code', String(code));
    form.set('redirect_uri', KICK_REDIRECT_URI);
    form.set('client_id', KICK_CLIENT_ID);
    form.set('code_verifier', currentCodeVerifier);
    if (KICK_CLIENT_SECRET) form.set('client_secret', KICK_CLIENT_SECRET);

    const r = await axios.post(TOKEN_URL, form.toString(), {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      timeout: 15000,
    });

    await saveTokens(r.data);
    currentCodeVerifier = null;

    res
      .status(200)
      .type('text')
      .send('Tokeny zapisane ✅. Możesz sprawdzić /tokens albo wysłać /chat/test');
  } catch (err) {
    const msg =
      err?.response?.status === 404
        ? 'Błąd callback: 404'
        : `Błąd callback: ${err?.response?.status || ''} ${err.message}`;
    res.status(500).type('text').send(msg);
  }
});

// Podgląd co mamy (bez wycieku sekretów)
app.get('/tokens', async (_req, res) => {
  await loadTokens();
  const info = tokens
    ? {
        has_access_token: !!tokens.access_token,
        has_refresh_token: !!tokens.refresh_token,
        token_type: tokens.token_type,
        expires_in: tokens.expires_in,
        obtained_at: tokens.obtained_at,
        scope: tokens.scope,
      }
    : { has_access_token: false, has_refresh_token: false };
  res.json(info);
});

// ---------------------------
// Odświeżanie tokenu przy potrzebie
// ---------------------------
async function ensureAccessToken() {
  if (!tokens) await loadTokens();
  if (!tokens?.access_token) {
    throw new Error('Brak access_token – wykonaj /oauth/start');
  }
  if (!tokenExpiresSoon()) return tokens.access_token;

  if (!tokens.refresh_token) {
    throw new Error('Brak refresh_token – wykonaj /oauth/start');
  }

  const form = new URLSearchParams();
  form.set('grant_type', 'refresh_token');
  form.set('refresh_token', tokens.refresh_token);
  form.set('client_id', KICK_CLIENT_ID);
  if (KICK_CLIENT_SECRET) form.set('client_secret', KICK_CLIENT_SECRET);

  const r = await axios.post(TOKEN_URL, form.toString(), {
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    timeout: 15000,
  });
  await saveTokens({ ...tokens, ...r.data });
  return tokens.access_token;
}

// ---------------------------
// Chatroom ID resolver
// ---------------------------
async function resolveChatroomId(slug) {
  // override?
  if (CHATROOM_ID_OVERRIDES.has(slug)) {
    return CHATROOM_ID_OVERRIDES.get(slug);
  }

  // z API v2
  const url = `${KICK_API_BASE}/channels/${encodeURIComponent(slug)}`;
  const r = await http.get(url);
  // oczekiwany kształt: { data: { chatroom: { id: ... } } } albo { chatroom: { id: ... } }
  const body = r.data || {};
  const id =
    body?.chatroom?.id ||
    body?.data?.chatroom?.id ||
    body?.channel?.chatroom?.id;
  if (!id) {
    throw new Error('Nie udało się odczytać chatroom_id z API');
  }
  return String(id);
}

// ---------------------------
// Wysyłanie wiadomości
// ---------------------------
async function sendMessageToChat({ slug, text }) {
  if (!slug || !text) throw new Error('slug i text są wymagane');
  // kontrola sluga – musi być w ALLOWED_SLUGS jeśli lista ustawiona
  if (ALLOWED_SLUGS.length && !ALLOWED_SLUGS.includes(slug)) {
    throw new Error(`Slug ${slug} nie jest dozwolony (ALLOWED_SLUGS)`);
  }

  const accessToken = await ensureAccessToken();
  const chatroomId = await resolveChatroomId(slug);

  const payload = { chatroom_id: chatroomId, content: text };
  const r = await http.post(`${KICK_API_BASE}/messages/send`, payload, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });

  return r.data || { ok: true };
}

// ---------------------------
// /chat/test  – GET i POST
// GET  /chat/test?slug=holly-s&text=siema
// POST /chat/test   {"slug":"holly-s","text":"siema"}
// ---------------------------
async function handleChatTest(slug, text, res) {
  try {
    const data = await sendMessageToChat({ slug, text });
    res.json({ ok: true, result: data });
  } catch (err) {
    const status = err?.response?.status || 500;
    const details = err?.response?.data || err.message;
    res.status(status).json({ ok: false, error: details });
  }
}

app.get('/chat/test', (req, res) => {
  const { slug, text } = req.query;
  return handleChatTest(String(slug || ''), String(text || ''), res);
});

app.post('/chat/test', (req, res) => {
  const { slug, text } = req.body || {};
  return handleChatTest(String(slug || ''), String(text || ''), res);
});

// ---------------------------
// Fallback /subscribe (na razie 200 z info – żeby nie było 404)
// ---------------------------
app.all('/subscribe', (_req, res) => {
  res.json({ ok: false, error: { status: 501, message: 'Not Implemented' } });
});

// ---------------------------
// Start
// ---------------------------
app.listen(PORT, () => {
  console.log(`auth+bot app listening on :${PORT}`);
  console.log(
    `Using OAuth prefix: /oauth (authorize: ${AUTH_URL})`
  );
});
