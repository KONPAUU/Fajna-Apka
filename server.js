// server.js (ESM)
import express from 'express';
import axios from 'axios';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const app = express();

// ===== ENV =====
const PORT = process.env.PORT || 3100;
const KICK_CLIENT_ID = process.env.KICK_CLIENT_ID || '';
const KICK_CLIENT_SECRET = process.env.KICK_CLIENT_SECRET || '';
const KICK_REDIRECT_URI = process.env.KICK_REDIRECT_URI || ''; // np. https://fajna-apka.onrender.com/callback
const ID_BASE = process.env.KICK_ID_BASE || 'https://id.kick.com';

// ===== ŚCIEŻKI =====
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const DATA_DIR = process.env.DATA_DIR || __dirname;
const TOKENS_PATH = path.join(DATA_DIR, 'tokens.json');
const PKCE_PATH = path.join(DATA_DIR, 'pkce.json');

// ===== I/O =====
function saveJSON(file, obj) {
  fs.writeFileSync(file, JSON.stringify(obj, null, 2), 'utf-8');
}
function loadJSON(file) {
  if (!fs.existsSync(file)) return null;
  try { return JSON.parse(fs.readFileSync(file, 'utf-8')); }
  catch { return null; }
}

// ===== HELPERY =====
const b64url = (input) =>
  Buffer.from(input).toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');

function makePKCE() {
  const verifier = b64url(crypto.randomBytes(32));
  const challenge = b64url(crypto.createHash('sha256').update(verifier).digest());
  return { verifier, challenge };
}

const urlParams = (obj) => new URLSearchParams(obj);

// ===== ROUTES =====
app.get('/health', (_, res) => res.type('text').send('ok'));

// Podgląd wygenerowanego URL (nie przekierowuje)
app.get('/auth/url', (req, res) => {
  if (!KICK_CLIENT_ID || !KICK_REDIRECT_URI) {
    return res.status(500).type('text').send('Brak KICK_CLIENT_ID lub KICK_REDIRECT_URI');
  }
  const { verifier, challenge } = makePKCE();
  const state = 'dbg' + Date.now();
  saveJSON(PKCE_PATH, { verifier, state, created_at: Date.now() });

  const scope = ['user:read', 'chat:write', 'offline_access', 'webhook:subscribe'].join(' ');
  const authUrl = new URL(ID_BASE + '/oauth2/authorize');
  authUrl.search = urlParams({
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

// Prawdziwy start – przekierowanie do Kick
app.get('/auth/start', (req, res) => {
  if (!KICK_CLIENT_ID || !KICK_REDIRECT_URI) {
    return res.status(500).type('text').send('Brak KICK_CLIENT_ID lub KICK_REDIRECT_URI');
  }
  const { verifier, challenge } = makePKCE();
  const state = 'dbg' + Date.now();
  saveJSON(PKCE_PATH, { verifier, state, created_at: Date.now() });

  const scope = ['user:read', 'chat:write', 'offline_access', 'webhook:subscribe'].join(' ');
  const authUrl = new URL(ID_BASE + '/oauth2/authorize');
  authUrl.search = urlParams({
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

// Callback – wymiana code -> token (próbuje /oauth2/token i /oauth/token)
app.get('/callback', async (req, res) => {
  const { code, state } = req.query || {};
  if (!code) return res.status(400).type('text').send('Brak "code" w callback');

  const pkce = loadJSON(PKCE_PATH);
  if (!pkce?.verifier) return res.status(400).type('text').send('Brak code_verifier – uruchom /auth/start');
  if (state && pkce.state && state !== pkce.state) return res.status(400).type('text').send('Nieprawidłowy state');

  const body = urlParams({
    grant_type: 'authorization_code',
    code: String(code),
    redirect_uri: KICK_REDIRECT_URI,
    client_id: KICK_CLIENT_ID,
    client_secret: KICK_CLIENT_SECRET,
    code_verifier: pkce.verifier
  });

  const headers = { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' };
  const tokenPaths = ['/oauth2/token', '/oauth/token'];
  let tokenResp = null;
  let lastErr = null;

  for (const p of tokenPaths) {
    try {
      const r = await axios.post(ID_BASE + p, body, { headers, timeout: 15000 });
      if (r?.data?.access_token) { tokenResp = r; break; }
    } catch (e) {
      lastErr = e;
      if (e?.response?.status === 404) continue; // spróbuj drugi endpoint
      break; // inne błędy – przerwij
    }
  }

  if (!tokenResp?.data?.access_token) {
    const status = lastErr?.response?.status || 'unknown';
    const msg = lastErr?.response?.data || lastErr?.message || 'token exchange failed';
    return res.status(500).type('text').send(`Błąd callback (token): ${status} ${typeof msg === 'string' ? msg : JSON.stringify(msg)}`);
  }

  const saved = { obtained_at: Date.now(), ...tokenResp.data };
  saveJSON(TOKENS_PATH, saved);

  res.type('text').send('OK – tokeny zapisane');
});

// Podgląd tokenów
app.get('/tokens', (req, res) => {
  const t = loadJSON(TOKENS_PATH);
  if (!t) return res.status(404).type('text').send('Brak zapisanych tokenów');
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
