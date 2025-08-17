// server.js
const express = require('express');
const axios = require('axios').default;
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const app = express();

// ===== ENV =====
const PORT = process.env.PORT || 3100;
const KICK_CLIENT_ID = process.env.KICK_CLIENT_ID || '';
const KICK_CLIENT_SECRET = process.env.KICK_CLIENT_SECRET || '';
const KICK_REDIRECT_URI = process.env.KICK_REDIRECT_URI || ''; // np. https://fajna-apka.onrender.com/callback
const ID_BASE = process.env.KICK_ID_BASE || 'https://id.kick.com';

// ===== PROSTA "PAMIĘĆ" =====
const DATA_DIR = process.env.DATA_DIR || '.';
const TOKENS_PATH = path.join(DATA_DIR, 'tokens.json');
const PKCE_PATH = path.join(DATA_DIR, 'pkce.json');

function saveJSON(file, obj) {
  fs.writeFileSync(file, JSON.stringify(obj, null, 2), 'utf-8');
}
function loadJSON(file) {
  if (!fs.existsSync(file)) return null;
  try { return JSON.parse(fs.readFileSync(file, 'utf-8')); }
  catch { return null; }
}

// ===== POMOCNICZE =====
function b64url(input) {
  return input.toString('base64')
    .replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}
function makePKCE() {
  const verifier = b64url(crypto.randomBytes(32));
  const challenge = b64url(
    crypto.createHash('sha256').update(verifier).digest()
  );
  return { verifier, challenge };
}
function urlSearch(params) {
  return new URLSearchParams(params);
}

// ===== ROUTES =====
app.get('/health', (_, res) => res.type('text').send('ok'));

// Generuje URL (pomocniczo – tylko podgląd)
app.get('/auth/url', (req, res) => {
  if (!KICK_CLIENT_ID || !KICK_REDIRECT_URI) {
    return res.status(500).send('Brak KICK_CLIENT_ID lub KICK_REDIRECT_URI');
  }
  const { verifier, challenge } = makePKCE();
  const state = 'dbg' + Date.now();

  // Zapisujemy, aby /callback miał verifier po powrocie
  saveJSON(PKCE_PATH, { verifier, state, created_at: Date.now() });

  const scope = [
    'user:read',
    'chat:write',
    'offline_access',           // konieczne, by dostać refresh_token
    'webhook:subscribe'
  ].join(' ');

  const authUrl = new URL(ID_BASE + '/oauth2/authorize');
  authUrl.search = urlSearch({
    response_type: 'code',
    client_id: KICK_CLIENT_ID,
    redirect_uri: KICK_REDIRECT_URI,
    scope,
    state,
    code_challenge: challenge,
    code_challenge_method: 'S256'
  }).toString();

  res.type('text').send(authUrl.toString());
});

// Autoryzacja – od razu przekierowuje na Kick
app.get('/auth/start', (req, res) => {
  if (!KICK_CLIENT_ID || !KICK_REDIRECT_URI) {
    return res.status(500).send('Brak KICK_CLIENT_ID lub KICK_REDIRECT_URI');
  }
  const { verifier, challenge } = makePKCE();
  const state = 'dbg' + Date.now();
  saveJSON(PKCE_PATH, { verifier, state, created_at: Date.now() });

  const scope = [
    'user:read',
    'chat:write',
    'offline_access',
    'webhook:subscribe'
  ].join(' ');

  const authUrl = new URL(ID_BASE + '/oauth2/authorize');
  authUrl.search = urlSearch({
    response_type: 'code',
    client_id: KICK_CLIENT_ID,
    redirect_uri: KICK_REDIRECT_URI,
    scope,
    state,
    code_challenge: challenge,
    code_challenge_method: 'S256'
  }).toString();

  res.redirect(authUrl.toString());
});

// Callback – wymiana code -> token (z fallbackiem /oauth2/token i /oauth/token)
app.get('/callback', async (req, res) => {
  const { code, state } = req.query || {};
  if (!code) return res.status(400).send('Brak "code" w callback');

  const pkce = loadJSON(PKCE_PATH);
  if (!pkce || !pkce.verifier) {
    return res.status(400).send('Brak code_verifier – uruchom /auth/start');
  }
  if (state && pkce.state && state !== pkce.state) {
    return res.status(400).send('Nieprawidłowy state');
  }

  const body = urlSearch({
    grant_type: 'authorization_code',
    code: code.toString(),
    redirect_uri: KICK_REDIRECT_URI,
    client_id: KICK_CLIENT_ID,
    client_secret: KICK_CLIENT_SECRET,
    code_verifier: pkce.verifier
  });

  const headers = {
    'Content-Type': 'application/x-www-form-urlencoded',
    'Accept': 'application/json'
  };

  const tokenPaths = ['/oauth2/token', '/oauth/token']; // fallback
  let tokenResp = null, lastErr = null;

  for (const p of tokenPaths) {
    try {
      tokenResp = await axios.post(ID_BASE + p, body, { headers, timeout: 15000 });
      if (tokenResp?.data?.access_token) break;
    } catch (e) {
      lastErr = e;
      if (e?.response?.status === 404) continue; // próbuj następny path
      // dla innych błędów: przerwij
      break;
    }
  }

  if (!tokenResp || !tokenResp.data || !tokenResp.data.access_token) {
    const status = lastErr?.response?.status || 'unknown';
    const msg = lastErr?.response?.data || lastErr?.message || 'token exchange failed';
    return res
      .status(500)
      .type('text')
      .send(`Błąd callback (token): ${status} ${typeof msg === 'string' ? msg : JSON.stringify(msg)}`);
  }

  // Zapis tokenów
  const saved = {
    obtained_at: Date.now(),
    ...tokenResp.data
  };
  saveJSON(TOKENS_PATH, saved);

  res.type('text').send('OK – tokeny zapisane');
});

// Prosty podgląd tokenów (do szybkiej weryfikacji)
app.get('/tokens', (req, res) => {
  const t = loadJSON(TOKENS_PATH);
  if (!t) return res.status(404).send('Brak zapisanych tokenów');
  res.json({
    has_access_token: Boolean(t.access_token),
    has_refresh_token: Boolean(t.refresh_token),
    token_type: t.token_type || null,
    expires_in: t.expires_in || null,
    obtained_at: t.obtained_at || null
  });
});

app.listen(PORT, () => {
  console.log(`kick-echo auth helper listening on :${PORT}`);
});
