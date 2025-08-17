// server.js  (ESM)
import express from 'express';
import axios from 'axios';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import bodyParser from 'body-parser';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// ======= ENV =======
const PORT = process.env.PORT || 3100;

// Używamy /oauth (Kick ma /oauth/authorize i /oauth/token)
const OAUTH_PREFIX = process.env.OAUTH_PREFIX || '/oauth';

const KICK_CLIENT_ID = process.env.KICK_CLIENT_ID || '';
const KICK_CLIENT_SECRET = process.env.KICK_CLIENT_SECRET || '';
// DOKŁADNIE taki jak w Kick Developer i tu w kodzie – z /oauth/callback
const KICK_REDIRECT_URI =
  process.env.KICK_REDIRECT_URI || 'https://YOUR-RENDER-URL.onrender.com/oauth/callback';

// Do testów wysyłki
const DEFAULT_SLUG = (process.env.DEFAULT_SLUG || '').trim();

// ======= PROSTE PRZECHOWYWANIE TOKENÓW =======
const DATA_DIR = process.env.DATA_DIR || '/data';
const TOKENS_FILE = path.join(DATA_DIR, 'tokens.json');

function readTokens() {
  try {
    const raw = fs.readFileSync(TOKENS_FILE, 'utf8');
    return JSON.parse(raw);
  } catch {
    return { access_token: null, refresh_token: null, token_type: 'Bearer', expires_in: 0, obtained_at: 0 };
  }
}
function writeTokens(tok) {
  try {
    fs.mkdirSync(DATA_DIR, { recursive: true });
    fs.writeFileSync(TOKENS_FILE, JSON.stringify(tok, null, 2));
  } catch (e) {
    console.error('[tokens] save error:', e.message);
  }
}
let TOKENS = readTokens();

// ======= PKCE helpers =======
function base64url(buf) {
  return buf
    .toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}
function createPkce() {
  const verifier = base64url(crypto.randomBytes(32));
  const challenge = base64url(crypto.createHash('sha256').update(verifier).digest());
  return { verifier, challenge };
}

// ======= OAuth URLs (Kick) =======
const AUTH_BASE = 'https://id.kick.com/oauth';
const AUTHORIZE_URL = `${AUTH_BASE}/authorize`;
const TOKEN_URL = `${AUTH_BASE}/token`;

// ======= ACCESS TOKEN MANAGEMENT =======
function tokenExpired() {
  if (!TOKENS?.access_token || !TOKENS?.obtained_at) return true;
  const now = Math.floor(Date.now() / 1000);
  // odśwież 60s wcześniej
  return now >= (TOKENS.obtained_at + (TOKENS.expires_in || 0) - 60);
}

async function refreshAccessTokenIfNeeded() {
  if (!tokenExpired()) return TOKENS.access_token;
  if (!TOKENS.refresh_token) throw new Error('Brak refresh_token – uruchom /oauth/start');

  const params = new URLSearchParams();
  params.set('grant_type', 'refresh_token');
  params.set('refresh_token', TOKENS.refresh_token);
  params.set('client_id', KICK_CLIENT_ID);
  params.set('client_secret', KICK_CLIENT_SECRET);

  const { data } = await axios.post(TOKEN_URL, params.toString(), {
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  });
  TOKENS = {
    ...TOKENS,
    access_token: data.access_token,
    token_type: data.token_type || 'Bearer',
    expires_in: data.expires_in || 7200,
    obtained_at: Math.floor(Date.now() / 1000),
  };
  if (data.refresh_token) {
    TOKENS.refresh_token = data.refresh_token; // czasem bywa rotacja
  }
  writeTokens(TOKENS);
  return TOKENS.access_token;
}

// ======= KICK API helpers =======
async function getChannelMetaBySlug(slug) {
  const url = `https://kick.com/api/v2/channels/${encodeURIComponent(slug)}`;
  const { data } = await axios.get(url, { timeout: 15000 });
  // interesuje nas chatroom_id do wysyłki
  const chatroomId = data?.chatroom?.id || data?.chatroom_id || null;
  const channelId = data?.id || null;
  return { chatroomId, channelId, raw: data };
}

async function sendChatMessage(slug, text) {
  if (!text || !slug) throw new Error('Brak slug lub text');
  const token = await refreshAccessTokenIfNeeded();
  const { chatroomId } = await getChannelMetaBySlug(slug);
  if (!chatroomId) throw new Error(`Nie znaleziono chatroom_id dla ${slug}`);

  const url = 'https://kick.com/api/v2/messages/send';
  const payload = { chatroom_id: chatroomId, content: text };
  const { data } = await axios.post(url, payload, {
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json',
    },
    timeout: 15000,
  });
  return data;
}

// ======= ROUTES =======

// zdrowie
app.get('/health', (_req, res) => res.type('text/plain').send('ok'));

// podgląd tokenów bez wrażliwych danych
app.get('/tokens', (_req, res) => {
  const has_access_token = Boolean(TOKENS?.access_token);
  const has_refresh_token = Boolean(TOKENS?.refresh_token);
  res.json({
    has_access_token,
    has_refresh_token,
    token_type: TOKENS?.token_type || 'Bearer',
    expires_in: TOKENS?.expires_in || 0,
    obtained_at: TOKENS?.obtained_at || 0,
  });
});

// ===== OAuth flow =====
app.get(`${OAUTH_PREFIX}/start`, (req, res) => {
  const state = `dbg${Date.now()}`;
  const { verifier, challenge } = createPkce();
  // trzymamy w ciasteczkach (prosto i wystarczająco do authu)
  res.cookie('pkce_verifier', verifier, { httpOnly: true, sameSite: 'lax' });
  res.cookie('oauth_state', state, { httpOnly: true, sameSite: 'lax' });

  const u = new URL(AUTHORIZE_URL);
  u.searchParams.set('response_type', 'code');
  u.searchParams.set('client_id', KICK_CLIENT_ID);
  u.searchParams.set('redirect_uri', KICK_REDIRECT_URI);
  u.searchParams.set('scope', 'user:read chat:write');
  u.searchParams.set('state', state);
  u.searchParams.set('code_challenge', challenge);
  u.searchParams.set('code_challenge_method', 'S256');

  res.redirect(u.toString());
});

// alias bez prefiksu (gdybyś miał już zapisane /callback w Kick Dev)
app.get('/callback', async (req, res) => {
  // przekieruj na prawidłowy endpoint z zachowaniem query
  const q = req.url.split('?')[1] || '';
  res.redirect(`${OAUTH_PREFIX}/callback?${q}`);
});

app.get(`${OAUTH_PREFIX}/callback`, async (req, res) => {
  try {
    const { code, state } = req.query;
    const cookies = req.headers.cookie || '';
    const verifier = (cookies.match(/pkce_verifier=([^;]+)/) || [])[1];
    const savedState = (cookies.match(/oauth_state=([^;]+)/) || [])[1];

    if (!code || !verifier) throw new Error('Brak code lub verifier');
    if (savedState && state && savedState !== state) throw new Error('Błędny state');

    const params = new URLSearchParams();
    params.set('grant_type', 'authorization_code');
    params.set('code', code);
    params.set('redirect_uri', KICK_REDIRECT_URI);
    params.set('client_id', KICK_CLIENT_ID);
    params.set('client_secret', KICK_CLIENT_SECRET);
    params.set('code_verifier', verifier);

    const { data } = await axios.post(TOKEN_URL, params.toString(), {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    });

    TOKENS = {
      access_token: data.access_token,
      refresh_token: data.refresh_token || TOKENS.refresh_token,
      token_type: data.token_type || 'Bearer',
      expires_in: data.expires_in || 7200,
      obtained_at: Math.floor(Date.now() / 1000),
    };
    writeTokens(TOKENS);

    res.type('text/plain').send('Tokeny zapisane ✅. Możesz sprawdzić /tokens albo wysłać /chat/test');
  } catch (e) {
    res.status(404).type('text/plain').send(`Błąd callback: ${e?.response?.status || ''} ${e.message}`);
  }
});

// ===== Chat test =====
app.get('/chat/test', async (req, res) => {
  try {
    const slug = (req.query.slug || DEFAULT_SLUG || '').toString().trim();
    const text = (req.query.text || 'test').toString();
    if (!slug) return res.status(400).json({ ok: false, error: 'Brak slug' });
    const out = await sendChatMessage(slug, text);
    res.json({ ok: true, slug, result: out });
  } catch (e) {
    res.status(400).json({ ok: false, error: e.message });
  }
});

// ===== Webhooks =====
app.all('/subscribe', async (_req, res) => {
  try {
    const token = await refreshAccessTokenIfNeeded();

    // Tworzymy subskrypcję livestream.status.updated dla kanału zalogowanego usera
    const url = 'https://api.kick.com/v2/webhooks/subscriptions';
    const payload = {
      name: 'livestream.status.updated',
      version: 1,
      transport: {
        method: 'webhook',
        callback: `${originFromEnvOrGuess()}/webhook`,
      },
      // bez filtra = dla właściciela tokena
    };

    const { data } = await axios.post(url, payload, {
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      timeout: 15000,
    });

    res.json({ ok: true, created: data });
  } catch (e) {
    const status = e?.response?.status || 500;
    res.status(200).json({
      ok: false,
      error: { status, message: e?.response?.data || e.message },
    });
  }
});

// Odbiór webhooków (na start – tylko 200 OK i log)
app.post('/webhook', async (req, res) => {
  try {
    console.log('Webhook payload:', JSON.stringify(req.body));
    // TODO: tu możesz dodać start/stop pętli lub inne akcje
    res.json({ ok: true });
  } catch {
    res.json({ ok: true });
  }
});

// ===== Helpers =====
function originFromEnvOrGuess() {
  // jeśli podałeś w env BASE_URL – użyj go; inaczej z REDIRECT_URI
  const envBase = process.env.BASE_URL;
  if (envBase) return envBase.replace(/\/+$/, '');
  try {
    const u = new URL(KICK_REDIRECT_URI);
    return `${u.protocol}//${u.host}`;
  } catch {
    return 'https://your-service.onrender.com';
  }
}

// ===== START =====
app.listen(PORT, () => {
  console.log(`auth+bot app listening on :${PORT}`);
  console.log(`Using OAuth prefix: ${OAUTH_PREFIX} (authorize: ${AUTHORIZE_URL})`);
});
