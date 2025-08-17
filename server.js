// ESM (package.json musi mieć "type": "module")
import express from 'express';
import crypto from 'crypto';
import fs from 'fs/promises';
import path from 'path';

// ===== Konfig =====
const PORT = process.env.PORT || 3100;
const OAUTH_PREFIX = '/oauth'; // uwaga: NIE /oauth2
const TOKENS_PATH = process.env.TOKENS_PATH || '/tmp/kick_tokens.json';

const KICK_CLIENT_ID = process.env.KICK_CLIENT_ID || '';
const KICK_CLIENT_SECRET = process.env.KICK_CLIENT_SECRET || '';
const KICK_REDIRECT_URI = process.env.KICK_REDIRECT_URI || '';
const ALLOWED_SLUGS = (process.env.ALLOWED_SLUGS || '')
  .split(',')
  .map(s => s.trim())
  .filter(Boolean);

// "slug:chatroomId,slug2:chatroomId2"
const CHATROOM_ID_OVERRIDES = Object.fromEntries(
  (process.env.CHATROOM_ID_OVERRIDES || '')
    .split(',')
    .map(x => x.trim())
    .filter(Boolean)
    .map(pair => {
      const [slug, id] = pair.split(':').map(s => s.trim());
      return [slug, id];
    })
);

if (!KICK_CLIENT_ID || !KICK_CLIENT_SECRET || !KICK_REDIRECT_URI) {
  console.log('[warn] Brak KICK_CLIENT_ID / KICK_CLIENT_SECRET / KICK_REDIRECT_URI w ENV.');
}

const app = express();
app.use(express.json());

// ===== Prosty storage tokenów (do /tmp, żeby nie było EACCES) =====
async function loadTokens() {
  try {
    const raw = await fs.readFile(TOKENS_PATH, 'utf8');
    return JSON.parse(raw);
  } catch {
    return null;
  }
}
async function saveTokens(tokens) {
  try {
    await fs.mkdir(path.dirname(TOKENS_PATH), { recursive: true });
    await fs.writeFile(TOKENS_PATH, JSON.stringify(tokens), 'utf8');
  } catch (e) {
    console.log('[warn] Nie udało się zapisać tokenów:', e.message);
  }
}

// ===== PKCE helpers =====
const pending = new Map(); // state -> {verifier, createdAt}

function genCodeVerifier() {
  return crypto.randomBytes(32).toString('base64url');
}
function codeChallenge(verifier) {
  const hash = crypto.createHash('sha256').update(verifier).digest();
  return Buffer.from(hash).toString('base64url');
}
function newState() {
  return crypto.randomBytes(16).toString('hex');
}

// ===== OAuth URLs =====
function authUrl(state, challenge) {
  const u = new URL('https://id.kick.com/oauth/authorize');
  u.searchParams.set('response_type', 'code');
  u.searchParams.set('client_id', KICK_CLIENT_ID);
  u.searchParams.set('redirect_uri', KICK_REDIRECT_URI);
  // zakresy: user:read + chat:read + chat:write
  u.searchParams.set('scope', 'user:read chat:read chat:write');
  u.searchParams.set('state', state);
  u.searchParams.set('code_challenge', challenge);
  u.searchParams.set('code_challenge_method', 'S256');
  return u.toString();
}

async function exchangeCodeForToken(code, verifier) {
  const body = new URLSearchParams();
  body.set('grant_type', 'authorization_code');
  body.set('code', code);
  body.set('redirect_uri', KICK_REDIRECT_URI);
  body.set('client_id', KICK_CLIENT_ID);
  body.set('code_verifier', verifier);
  // Kick akceptuje client_secret w body dla confidential apps
  body.set('client_secret', KICK_CLIENT_SECRET);

  const r = await fetch('https://id.kick.com/oauth/token', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body
  });
  if (!r.ok) throw new Error(`token exchange ${r.status}`);
  return r.json();
}

async function refreshIfNeeded(tokens) {
  if (!tokens) return null;
  const expiresAt = (tokens.obtained_at || 0) + (tokens.expires_in || 0) - 60;
  const now = Math.floor(Date.now() / 1000);
  if (now < expiresAt) return tokens;

  if (!tokens.refresh_token) return tokens;

  const body = new URLSearchParams();
  body.set('grant_type', 'refresh_token');
  body.set('refresh_token', tokens.refresh_token);
  body.set('client_id', KICK_CLIENT_ID);
  body.set('client_secret', KICK_CLIENT_SECRET);

  const r = await fetch('https://id.kick.com/oauth/token', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body
  });
  if (!r.ok) throw new Error(`refresh ${r.status}`);
  const data = await r.json();
  const merged = {
    ...tokens,
    ...data,
    obtained_at: Math.floor(Date.now() / 1000)
  };
  await saveTokens(merged);
  return merged;
}

// ===== Kick helpers =====
async function fetchChannelMeta(slug) {
  // 1) override
  if (CHATROOM_ID_OVERRIDES[slug]) {
    return { slug, chatroom_id: CHATROOM_ID_OVERRIDES[slug] };
  }

  // 2) spróbuj API v2
  try {
    const r = await fetch(`https://kick.com/api/v2/channels/${encodeURIComponent(slug)}`);
    if (r.ok) {
      const j = await r.json();
      // w JSON często jest "chatroom" lub bezpośrednio "chatroom_id"
      const id =
        j?.chatroom_id ||
        j?.chatroom?.id ||
        j?.data?.chatroom_id ||
        j?.data?.chatroom?.id;
      if (id) return { slug, chatroom_id: String(id) };
    }
  } catch {}

  // 3) fallback: z HTML (view-source)
  try {
    const r = await fetch(`https://kick.com/${encodeURIComponent(slug)}`);
    if (r.ok) {
      const html = await r.text();
      const m = html.match(/"chatroom_id"\s*:\s*(\d+)/);
      if (m) return { slug, chatroom_id: m[1] };
    }
  } catch {}

  return null;
}

async function sendChatMessage(accessToken, chatroomId, text) {
  // najprostsze v2: /api/v2/chatrooms/{id}/messages
  const r = await fetch(`https://kick.com/api/v2/chatrooms/${chatroomId}/messages`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'authorization': `Bearer ${accessToken}`
    },
    body: JSON.stringify({ message: text })
  });
  if (r.ok) return { ok: true, status: r.status };
  const t = await r.text().catch(() => '');
  return { ok: false, status: r.status, body: t.slice(0, 400) };
}

// ===== ROUTES =====
app.get('/health', (_req, res) => res.type('text/plain').send('ok'));

// pokaż jaki URL generujemy (pomocne do debug)
app.get(`${OAUTH_PREFIX}/url`, (_req, res) => {
  const verifier = genCodeVerifier();
  const challenge = codeChallenge(verifier);
  const state = newState();
  pending.set(state, { verifier, createdAt: Date.now() });
  res.type('text/plain').send(authUrl(state, challenge));
});

app.get(`${OAUTH_PREFIX}/start`, (_req, res) => {
  const verifier = genCodeVerifier();
  const challenge = codeChallenge(verifier);
  const state = newState();
  pending.set(state, { verifier, createdAt: Date.now() });
  res.redirect(authUrl(state, challenge));
});

app.get(`${OAUTH_PREFIX}/callback`, async (req, res) => {
  try {
    const { code, state } = req.query;
    const stash = pending.get(state);
    pending.delete(state);
    if (!code || !stash) {
      return res.status(400).type('text/plain').send('Błędny stan albo brak code.');
    }
    const tok = await exchangeCodeForToken(String(code), stash.verifier);
    const normalized = {
      access_token: tok.access_token,
      refresh_token: tok.refresh_token,
      token_type: tok.token_type,
      expires_in: tok.expires_in,
      scope: tok.scope,
      obtained_at: Math.floor(Date.now() / 1000)
    };
    await saveTokens(normalized);
    res.type('text/plain').send(
      'Tokeny zapisane ✅. Możesz sprawdzić /tokens albo wysłać /chat/test'
    );
  } catch (e) {
    res
      .status(404)
      .type('text/plain')
      .send(`Błąd callback: ${e.message}`);
  }
});

app.get('/tokens', async (_req, res) => {
  const t = await loadTokens();
  if (!t) return res.json({ has_access_token: false, has_refresh_token: false });
  res.json({
    has_access_token: !!t.access_token,
    has_refresh_token: !!t.refresh_token,
    token_type: t.token_type,
    expires_in: t.expires_in,
    obtained_at: t.obtained_at,
    scope: t.scope || null
  });
});

// meta helper
app.get('/meta/:slug', async (req, res) => {
  const slug = String(req.params.slug || '').trim();
  const meta = await fetchChannelMeta(slug);
  if (!meta) return res.status(404).json({ ok: false, error: 'meta_not_found' });
  res.json({ ok: true, ...meta });
});

// test wysyłki: /chat/test?slug=holly-s&text=siema
app.get('/chat/test', async (req, res) => {
  try {
    const slug = String(req.query.slug || '').trim();
    const text = String(req.query.text || '').trim();
    if (!slug || !text) return res.status(400).json({ ok: false, error: 'slug_and_text_required' });

    if (ALLOWED_SLUGS.length && !ALLOWED_SLUGS.includes(slug)) {
      return res.status(403).json({ ok: false, error: 'slug_not_allowed' });
    }

    let tokens = await loadTokens();
    tokens = await refreshIfNeeded(tokens);
    if (!tokens?.access_token) {
      return res.status(401).json({ ok: false, error: 'no_access_token' });
    }

    const meta = await fetchChannelMeta(slug);
    if (!meta?.chatroom_id) {
      return res.status(404).json({ ok: false, error: 'no_chatroom_id' });
    }

    const resp = await sendChatMessage(tokens.access_token, meta.chatroom_id, text);
    if (resp.ok) return res.json({ ok: true, sent: { slug, chatroom_id: meta.chatroom_id } });

    return res.status(resp.status || 500).json({
      ok: false,
      error: resp.status || 'unknown',
      details: resp.body || null
    });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// (opcjonalny) webhook subscribe – zostawiam pod GET dla wygody
app.get('/subscribe', (_req, res) => {
  res.status(404).json({ ok: false, error: { status: 404, message: { message: 'Not Found' } } });
});

// start
app.listen(PORT, () => {
  console.log(`auth+bot app listening on :${PORT}`);
  console.log(`Using OAuth prefix: ${OAUTH_PREFIX} (authorize: https://id.kick.com/oauth/authorize)`);
});
