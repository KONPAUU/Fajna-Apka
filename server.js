// ---------- deps ----------
const express = require('express');
const axios = require('axios');
const crypto = require('crypto');
const qs = require('querystring');

// ---------- app ----------
const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const PORT = process.env.PORT || 3100;

// ---------- env ----------
const KICK_CLIENT_ID = process.env.KICK_CLIENT_ID || '';
const KICK_CLIENT_SECRET = process.env.KICK_CLIENT_SECRET || '';
const KICK_REDIRECT_URI =
  process.env.KICK_REDIRECT_URI || 'https://YOUR-RENDER-URL/oauth/callback';

// OAuth endpoints (v1, bez “2”)
const AUTH_BASE = 'https://id.kick.com/oauth';
const AUTH_URL = `${AUTH_BASE}/authorize`;
const TOKEN_URL = `${AUTH_BASE}/token`;

// dozwolone kanały (po przecinku). używaj “holly-s”
const ALLOWED_SLUGS = (process.env.ALLOWED_SLUGS || '')
  .split(',')
  .map(s => s.trim().toLowerCase())
  .filter(Boolean);

// override: "holly-s:12345,inna-nazwa:6789" akceptuje też holly_s
const CHATROOM_ID_OVERRIDES = (() => {
  const raw = process.env.CHATROOM_ID_OVERRIDES || '';
  const map = new Map();
  raw.split(',').map(x => x.trim()).filter(Boolean).forEach(pair => {
    const [k, v] = pair.split(':').map(s => s.trim());
    if (!k || !v) return;
    const hyph = k.replace(/_/g, '-').toLowerCase();
    const undr = k.replace(/-/g, '_').toLowerCase();
    map.set(hyph, v);
    map.set(undr, v);
  });
  return map;
})();

// pamięć na tokeny (prosto – w RAM)
let TOKENS = {
  access_token: null,
  refresh_token: null,
  token_type: 'Bearer',
  scope: null,
  obtained_at: 0,
  expires_in: 0
};

// ---------- utils ----------
const nowSec = () => Math.floor(Date.now() / 1000);

function normalizeSlug(s) {
  if (!s) return '';
  return s.toLowerCase().trim();
}
function hyphenSlug(s) {
  return normalizeSlug(s).replace(/_/g, '-');
}
function underscoreSlug(s) {
  return normalizeSlug(s).replace(/-/g, '_');
}

function haveValidAccessToken() {
  if (!TOKENS.access_token || !TOKENS.expires_in || !TOKENS.obtained_at) return false;
  // odświeżamy 60s przed wygaśnięciem
  return nowSec() < (TOKENS.obtained_at + TOKENS.expires_in - 60);
}

async function refreshIfNeeded() {
  if (haveValidAccessToken()) return;
  if (!TOKENS.refresh_token) throw new Error('Brak refresh_token – uruchom /oauth/start');
  const body = {
    grant_type: 'refresh_token',
    refresh_token: TOKENS.refresh_token,
    client_id: KICK_CLIENT_ID,
    client_secret: KICK_CLIENT_SECRET,
    redirect_uri: KICK_REDIRECT_URI
  };
  const { data } = await axios.post(TOKEN_URL, qs.stringify(body), {
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    timeout: 15000
  });
  TOKENS.access_token = data.access_token;
  TOKENS.refresh_token = data.refresh_token || TOKENS.refresh_token;
  TOKENS.token_type = data.token_type || 'Bearer';
  TOKENS.scope = data.scope || TOKENS.scope;
  TOKENS.expires_in = data.expires_in || 7200;
  TOKENS.obtained_at = nowSec();
}

// GET /api/v2/channels/{slug} (MUST be GET)
async function fetchChannelMetaV2(slugHyphen) {
  const url = `https://kick.com/api/v2/channels/${slugHyphen}`;
  const { data } = await axios.get(url, { timeout: 12000 });
  // popularny układ: { chatroom: { id }, user: {...}, ... }
  const chatroomId =
    data?.chatroom?.id ||
    data?.chatroom_id ||
    null;
  return { chatroomId, raw: data };
}

// HTML fallback: wyciągamy chatroom_id ze strony kanału
async function fetchChannelMetaFromHTML(slugHyphen) {
  const url = `https://kick.com/${slugHyphen}`;
  const { data: html } = await axios.get(url, { timeout: 12000 });
  // spróbuj kilka regexów bo Kick często zmienia strukturę
  const regexes = [
    /"chatroom"\s*:\s*\{[^}]*"id"\s*:\s*(\d+)/i,
    /data-chatroom-id\s*=\s*"(\d+)"/i,
    /"chatroom_id"\s*:\s*(\d+)/i
  ];
  for (const re of regexes) {
    const m = html.match(re);
    if (m && m[1]) {
      return { chatroomId: m[1], raw: null };
    }
  }
  return { chatroomId: null, raw: null };
}

async function resolveChatroomId(slugInput) {
  const hyph = hyphenSlug(slugInput);
  const undr = underscoreSlug(slugInput);

  // override?
  if (CHATROOM_ID_OVERRIDES.has(hyph)) return CHATROOM_ID_OVERRIDES.get(hyph);
  if (CHATROOM_ID_OVERRIDES.has(undr)) return CHATROOM_ID_OVERRIDES.get(undr);

  // v2 (GET!)
  try {
    const { chatroomId } = await fetchChannelMetaV2(hyph);
    if (chatroomId) return String(chatroomId);
  } catch (e) {
    // 403/405/… – spróbuj HTML
  }

  // HTML fallback
  try {
    const { chatroomId } = await fetchChannelMetaFromHTML(hyph);
    if (chatroomId) return String(chatroomId);
  } catch (e) { /* ignore */ }

  throw new Error(`Nie mogę znaleźć chatroom_id dla sluga "${slugInput}". Ustaw CHATROOM_ID_OVERRIDES.`);
}

// faktyczna wysyłka wiadomości
async function sendChatMessage({ slug, text }) {
  if (!slug || !text) throw new Error('Brak slug albo text');
  const normSlug = hyphenSlug(slug);

  if (ALLOWED_SLUGS.length && !ALLOWED_SLUGS.includes(normSlug)) {
    throw new Error(`Slug "${slug}" nie jest dozwolony (ALLOWED_SLUGS).`);
  }

  await refreshIfNeeded();
  const chatroomId = await resolveChatroomId(normSlug);

  const url = 'https://kick.com/api/v2/messages/send';
  const payload = {
    chatroom_id: chatroomId,
    content: text
  };

  const { data } = await axios.post(url, payload, {
    headers: {
      Authorization: `Bearer ${TOKENS.access_token}`,
      'Content-Type': 'application/json'
    },
    timeout: 15000,
    // niektóre regiony potrzebują user-agent
    validateStatus: s => s >= 200 && s < 500
  });

  if (data?.message?.id || data?.id) {
    return { ok: true, chatroom_id: chatroomId, message_id: data?.message?.id || data?.id || null };
  }

  // 4xx z treścią (np. 403/405) – pokaż co przyszło
  throw new Error(
    data?.message
      ? `Kick API error: ${data.message}`
      : `Kick API rejected the request (sprawdź scope i token).`
  );
}

// ---------- routes ----------
app.get('/health', (_, res) => res.type('text/plain').send('ok'));

// —— OAuth PKCE (prosty) ——
function makeVerifier() {
  return crypto.randomBytes(32).toString('base64url');
}
function makeChallenge(verifier) {
  return crypto.createHash('sha256').update(verifier).digest('base64url');
}
let PKCE = { verifier: null, state: null };

app.get('/oauth/start', (req, res) => {
  const state = 'dbg' + Date.now();
  const verifier = makeVerifier();
  const challenge = makeChallenge(verifier);
  PKCE = { verifier, state };

  const params = qs.stringify({
    response_type: 'code',
    client_id: KICK_CLIENT_ID,
    redirect_uri: KICK_REDIRECT_URI,
    scope: 'user:read chat:write',
    state,
    code_challenge: challenge,
    code_challenge_method: 'S256'
  });

  res.redirect(`${AUTH_URL}?${params}`);
});

app.get('/oauth/callback', async (req, res) => {
  try {
    const { code, state } = req.query;
    if (!code) throw new Error('Brak code w callbacku');
    if (!state || state !== PKCE.state) throw new Error('Błędny state');

    const body = {
      grant_type: 'authorization_code',
      code,
      code_verifier: PKCE.verifier,
      client_id: KICK_CLIENT_ID,
      client_secret: KICK_CLIENT_SECRET,
      redirect_uri: KICK_REDIRECT_URI
    };

    const { data } = await axios.post(TOKEN_URL, qs.stringify(body), {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      timeout: 15000
    });

    TOKENS.access_token = data.access_token;
    TOKENS.refresh_token = data.refresh_token;
    TOKENS.token_type = data.token_type || 'Bearer';
    TOKENS.scope = data.scope || 'user:read chat:write';
    TOKENS.expires_in = data.expires_in || 7200;
    TOKENS.obtained_at = nowSec();

    res
      .status(200)
      .type('text/plain')
      .send('Tokeny zapisane ✅. Wejdź na /tokens albo /chat/test');
  } catch (e) {
    res
      .status(400)
      .type('text/plain')
      .send(`Błąd callback: ${e.message || e}`);
  }
});

app.get('/tokens', (req, res) => {
  res.json({
    has_access_token: !!TOKENS.access_token,
    has_refresh_token: !!TOKENS.refresh_token,
    token_type: TOKENS.token_type,
    expires_in: TOKENS.expires_in,
    obtained_at: TOKENS.obtained_at,
    scope: TOKENS.scope
  });
});

// —— chat/test ——
// GET: /chat/test?slug=holly-s&text=siema
app.get('/chat/test', async (req, res) => {
  try {
    const { slug, text } = req.query;
    const out = await sendChatMessage({ slug, text });
    res.json(out);
  } catch (e) {
    res.status(200).json({ ok: false, error: e.message || String(e) });
  }
});

// POST: JSON { slug, text }
app.post('/chat/test', async (req, res) => {
  try {
    const { slug, text } = req.body || {};
    const out = await sendChatMessage({ slug, text });
    res.json(out);
  } catch (e) {
    res.status(200).json({ ok: false, error: e.message || String(e) });
  }
});

// safety net
app.all('*', (req, res) => {
  res.status(404).type('text/plain').send('Not Found');
});

// ---------- start ----------
app.listen(PORT, () => {
  console.log(`auth+bot app listening on :${PORT}`);
  console.log(`Using OAuth prefix: /oauth (authorize: ${AUTH_URL})`);
});
