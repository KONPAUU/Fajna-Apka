// server.js (ESM) — Kick OAuth z prefixem /oauth (konfigurowalny przez ENV)

import express from 'express';
import crypto from 'crypto';

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ====== ENV ======
const {
  PORT = 3100,
  KICK_CLIENT_ID = '',
  KICK_CLIENT_SECRET = '',
  KICK_REDIRECT_URI = '',
  // Domyślnie /oauth — możesz zmienić na /oauth2 jeśli kiedyś wrócą:
  KICK_OAUTH_PREFIX = '/oauth',
  // Zakresy – możesz dopasować do swoich checkboxów w Kick Dev
  KICK_SCOPES = 'user:read chat:read chat:write',
  LOG_LEVEL = 'info',
} = process.env;

const log = (level, ...args) => {
  const allow = { error: 0, warn: 1, info: 2, debug: 3 };
  const cur = allow[LOG_LEVEL] ?? 2;
  if (allow[level] <= cur) console[level](...args);
};

// ====== Stałe Kick ID ======
const KICK_ID_BASE = 'https://id.kick.com';
const OAUTH_AUTHORIZE = `${KICK_ID_BASE}${KICK_OAUTH_PREFIX}/authorize`;
const OAUTH_TOKEN = `${KICK_ID_BASE}${KICK_OAUTH_PREFIX}/token`;

// ====== Pamięć procesu na PKCE i tokeny ======
const pkceByState = new Map();
/** @type {{access_token?: string, refresh_token?: string, token_type?: string, expires_in?: number, obtained_at?: number}} */
let tokenBag = {};

// ====== Pomocniki ======
function randomBase64Url(len = 32) {
  return crypto.randomBytes(len).toString('base64url');
}
function sha256Base64Url(input) {
  const hash = crypto.createHash('sha256').update(input).digest();
  return Buffer.from(hash).toString('base64url');
}
function toForm(data) {
  return new URLSearchParams(Object.entries(data).filter(([, v]) => v !== undefined && v !== null)).toString();
}
function hasAccessToken() {
  if (!tokenBag.access_token || !tokenBag.expires_in || !tokenBag.obtained_at) return false;
  const ageSec = Math.floor((Date.now() - tokenBag.obtained_at) / 1000);
  return ageSec < tokenBag.expires_in - 60; // bufor 60s
}

// ====== Health ======
app.get('/health', (_req, res) => res.type('text/plain').send('ok'));

// ====== URL do autoryzacji (do podejrzenia) ======
app.get('/auth/url', (_req, res) => {
  if (!KICK_CLIENT_ID || !KICK_REDIRECT_URI) {
    return res.status(500).send('Brak KICK_CLIENT_ID albo KICK_REDIRECT_URI');
  }
  const state = `dbg${Date.now()}`;
  const code_verifier = randomBase64Url(64);
  const code_challenge = sha256Base64Url(code_verifier);
  pkceByState.set(state, { code_verifier, created_at: Date.now() });

  const url = new URL(OAUTH_AUTHORIZE);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('client_id', KICK_CLIENT_ID);
  url.searchParams.set('redirect_uri', KICK_REDIRECT_URI);
  url.searchParams.set('scope', KICK_SCOPES);
  url.searchParams.set('state', state);
  url.searchParams.set('code_challenge', code_challenge);
  url.searchParams.set('code_challenge_method', 'S256');

  return res.type('text/plain').send(url.toString());
});

// ====== Start autoryzacji (redirect) ======
app.get('/auth/start', (_req, res) => {
  const url = new URL(`${_req.protocol}://${_req.get('host')}/auth/url`);
  // pobieramy wygenerowany URL jako tekst i przekierujemy — prostsze: zróbmy go tu bez dodatkowego fetchu:
  const state = `dbg${Date.now()}`;
  const code_verifier = randomBase64Url(64);
  const code_challenge = sha256Base64Url(code_verifier);
  pkceByState.set(state, { code_verifier, created_at: Date.now() });

  const auth = new URL(OAUTH_AUTHORIZE);
  auth.searchParams.set('response_type', 'code');
  auth.searchParams.set('client_id', KICK_CLIENT_ID);
  auth.searchParams.set('redirect_uri', KICK_REDIRECT_URI);
  auth.searchParams.set('scope', KICK_SCOPES);
  auth.searchParams.set('state', state);
  auth.searchParams.set('code_challenge', code_challenge);
  auth.searchParams.set('code_challenge_method', 'S256');

  return res.redirect(auth.toString());
});

// ====== Callback z Kick ======
app.get('/callback', async (req, res) => {
  try {
    const { code, state, error, error_description } = req.query;

    if (error) {
      log('error', 'OAuth error:', error, error_description);
      return res.status(400).type('text/plain').send(`Błąd OAuth: ${error} ${error_description || ''}`);
    }
    if (!code || !state) {
      return res.status(400).type('text/plain').send('Brak code albo state');
    }
    const pkce = pkceByState.get(state);
    if (!pkce) {
      return res.status(400).type('text/plain').send('Brak lub przedawniony state/PKCE');
    }
    pkceByState.delete(state); // jednorazowo

    // Wymiana code -> tokeny
    const form = toForm({
      grant_type: 'authorization_code',
      code,
      redirect_uri: KICK_REDIRECT_URI,
      client_id: KICK_CLIENT_ID,
      client_secret: KICK_CLIENT_SECRET,
      code_verifier: pkce.code_verifier,
    });

    const r = await fetch(OAUTH_TOKEN, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: form,
    });

    if (!r.ok) {
      const t = await r.text();
      log('error', 'Token exchange failed', r.status, t);
      return res.status(404).type('text/plain').send(`Błąd callback: ${r.status} ${t}`);
    }

    const tok = await r.json();
    tokenBag = {
      access_token: tok.access_token,
      refresh_token: tok.refresh_token,
      token_type: tok.token_type,
      expires_in: tok.expires_in,
      obtained_at: Date.now(),
    };
    log('info', 'Tokeny zapisane. access_token?', !!tokenBag.access_token, 'refresh_token?', !!tokenBag.refresh_token);

    return res
      .status(200)
      .type('text/plain')
      .send('OK — tokeny zapisane. Możesz sprawdzić /tokens');
  } catch (e) {
    log('error', 'Callback err', e);
    return res.status(500).type('text/plain').send('Błąd serwera w /callback');
  }
});

// ====== Podgląd statusu tokenów ======
app.get('/tokens', (_req, res) => {
  return res.json({
    has_access_token: hasAccessToken(),
    has_refresh_token: !!tokenBag.refresh_token,
    token_type: tokenBag.token_type || null,
    expires_in: tokenBag.expires_in || null,
    obtained_at: tokenBag.obtained_at || null,
  });
});

// ====== Odświeżanie tokenu (gdy trzeba) ======
app.post('/oauth/refresh', async (_req, res) => {
  try {
    if (!tokenBag.refresh_token) {
      return res.status(400).json({ ok: false, error: 'Brak refresh_token — uruchom /auth/start' });
    }
    const form = toForm({
      grant_type: 'refresh_token',
      refresh_token: tokenBag.refresh_token,
      client_id: KICK_CLIENT_ID,
      client_secret: KICK_CLIENT_SECRET,
    });

    const r = await fetch(OAUTH_TOKEN, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: form,
    });

    if (!r.ok) {
      const t = await r.text();
      log('error', 'Refresh failed', r.status, t);
      return res.status(400).json({ ok: false, error: `refresh_failed_${r.status}`, details: t });
    }

    const tok = await r.json();
    tokenBag = {
      access_token: tok.access_token,
      refresh_token: tok.refresh_token || tokenBag.refresh_token, // czasem nie zwracają
      token_type: tok.token_type,
      expires_in: tok.expires_in,
      obtained_at: Date.now(),
    };
    return res.json({ ok: true, token_type: tokenBag.token_type, expires_in: tokenBag.expires_in });
  } catch (e) {
    log('error', 'Refresh err', e);
    return res.status(500).json({ ok: false, error: 'server_error' });
  }
});

// ====== Start ======
app.listen(PORT, () => {
  console.log(`auth app listening on :${PORT}`);
  console.log(`Using OAuth prefix: ${KICK_OAUTH_PREFIX} (authorize: ${OAUTH_AUTHORIZE})`);
});
