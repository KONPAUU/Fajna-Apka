// server.js — ESM, Kick echo bot (N powtórzeń !komendy -> echo)
// Wymagane "type":"module" w package.json

import "dotenv/config";
import express from "express";
import bodyParser from "body-parser";
import axios from "axios";
import crypto from "crypto";
import fs from "fs";
import path from "path";
import { io } from "socket.io-client";

/* ---------- Stałe / nagłówki ---------- */
const UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36";
const JSON_HEADERS = { "User-Agent": UA, Accept: "application/json, text/plain, */*", Referer: "https://kick.com/" };
const HTML_HEADERS = { "User-Agent": UA, Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", Referer: "https://kick.com/" };

/* ---------- ENV ---------- */
const {
  PORT = 3100,

  // OAuth
  KICK_CLIENT_ID = "",
  KICK_CLIENT_SECRET = "",
  KICK_REDIRECT_URI = "", // https://<twoja-apka>.onrender.com/callback
  AUTH_URL = "https://id.kick.com/oauth/authorize",
  TOKEN_URL = "https://id.kick.com/oauth/token",
  KICK_OAUTH_PREFIX = "/oauth",

  // Konfiguracja bota
  ALLOWED_SLUGS = "",                     // np. holly-s
  BOT_USERNAME = "",
  CHATROOM_ID_OVERRIDES = "",             // np. "holly-s:56494133"
  ADMIN_KEY = "",
  SUBSCRIBE_KEY = "",

  // Echo
  CMD_ECHO_ENABLED = "true",
  CMD_ECHO_MIN_RUN,
  ECHO_THRESHOLD,
  CMD_ECHO_COOLDOWN_SECONDS = "60",
  CMD_ECHO_EXCLUDE = "",
  IGNORE_EXACT = "",

  // Tokeny / dysk
  DATA_DIR = "/tmp",
  TOKENS_PATH = "/tmp/kick_tokens.json",
  KICK_REFRESH_TOKEN = "",

  // Polling
  POLL_SECONDS = "60",
} = process.env;

/* ---------- Helpers ---------- */
const allowedSlugs = String(ALLOWED_SLUGS || "")
  .split(",").map(s => s.trim().toLowerCase()).filter(Boolean);

const CHATROOM_OVERRIDES = String(CHATROOM_ID_OVERRIDES || "")
  .split(",").map(s => s.trim()).filter(Boolean)
  .reduce((acc, pair) => {
    const [slug, id] = pair.split(":").map(x => (x || "").trim());
    if (slug && id && /^\d+$/.test(id)) acc[slug.toLowerCase()] = Number(id);
    return acc;
  }, {});

const altSlugs = (s) => {
  const base = String(s || "").toLowerCase();
  const list = [base];
  if (base.includes("-")) list.push(base.replace(/-/g, "_"));
  if (base.includes("_")) list.push(base.replace(/_/g, "-"));
  return Array.from(new Set(list));
};

/* ---------- Pliki ---------- */
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
const TOKENS_FILE = TOKENS_PATH || path.join(DATA_DIR, "tokens.json");

/* ---------- Express ---------- */
const app = express();
app.use(bodyParser.json({ verify: (req, _res, buf) => (req.rawBody = buf) }));
app.use(bodyParser.urlencoded({ extended: true, verify: (req, _res, buf) => (req.rawBody = buf) }));

const mountGet = (p, h) => (Array.isArray(p) ? p : [p]).forEach(x => app.get(x, h));
const mountPost = (p, h) => (Array.isArray(p) ? p : [p]).forEach(x => app.post(x, h));

/* ---------- Tokeny użytkownika ---------- */
let tokens = { access_token: null, refresh_token: null, expires_at: 0 };
const saveTokens = () => { try { fs.writeFileSync(TOKENS_FILE, JSON.stringify(tokens, null, 2)); } catch {} };
(function loadTokens() {
  try {
    if (fs.existsSync(TOKENS_FILE)) {
      const t = JSON.parse(fs.readFileSync(TOKENS_FILE, "utf-8"));
      if (t?.refresh_token) tokens = t;
    }
  } catch {}
  if (!tokens.refresh_token && KICK_REFRESH_TOKEN) tokens.refresh_token = KICK_REFRESH_TOKEN.trim();
})();

async function refreshIfNeeded() {
  const now = Math.floor(Date.now() / 1000);
  if (tokens.access_token && now < Number(tokens.expires_at || 0) - 60) return tokens.access_token;
  if (!tokens.refresh_token) throw new Error("Brak refresh_token – przejdź /auth/start");

  const params = new URLSearchParams();
  params.append("grant_type", "refresh_token");
  params.append("client_id", KICK_CLIENT_ID);
  params.append("client_secret", KICK_CLIENT_SECRET);
  params.append("refresh_token", tokens.refresh_token);

  const { data } = await axios.post(TOKEN_URL, params, { headers: { "Content-Type": "application/x-www-form-urlencoded" }, timeout: 15000 });
  tokens.access_token = data.access_token;
  tokens.refresh_token = data.refresh_token;
  tokens.expires_at = Math.floor(Date.now() / 1000) + (data.expires_in || 3600);
  saveTokens();
  return tokens.access_token;
}

/* ---------- App token ---------- */
let appToken = { token: null, expires_at: 0 };
async function getAppToken() {
  const now = Math.floor(Date.now() / 1000);
  if (appToken.token && now < Number(appToken.expires_at || 0) - 60) return appToken.token;

  const params = new URLSearchParams();
  params.append("grant_type", "client_credentials");
  params.append("client_id", KICK_CLIENT_ID);
  params.append("client_secret", KICK_CLIENT_SECRET);

  const { data } = await axios.post(TOKEN_URL, params, { headers: { "Content-Type": "application/x-www-form-urlencoded" }, timeout: 15000 });
  appToken.token = data.access_token;
  appToken.expires_at = now + (data.expires_in || 3600);
  return appToken.token;
}

/* ---------- Kanały ---------- */
const channelIdCache = new Map(); // slug -> broadcaster_user_id

async function getChannelsBySlugs(slugs) {
  const base = (Array.isArray(slugs) ? slugs : [slugs]).map(s => String(s || "").trim().toLowerCase()).filter(Boolean);
  if (!base.length) return [];
  const list = Array.from(new Set(base.flatMap(altSlugs)));

  const token = await getAppToken();
  const baseUrl = "https://api.kick.com/public/v1/channels";
  const headers = { Authorization: `Bearer ${token}` };
  const timeout = 15000;

  // /channels/:slug
  if (list.length === 1) {
    try {
      const { data } = await axios.get(`${baseUrl}/${encodeURIComponent(list[0])}`, { headers, timeout });
      const ch = data?.data || data;
      if (ch) {
        if (ch.slug) channelIdCache.set(ch.slug, ch.broadcaster_user_id);
        return [ch];
      }
    } catch (e) {
      if (e?.response?.status && e.response.status !== 404) throw e;
    }
  }
  // ?slug=a&slug=b
  try {
    const qs = list.map(s => `slug=${encodeURIComponent(s)}`).join("&");
    const { data } = await axios.get(`${baseUrl}?${qs}`, { headers, timeout });
    if (Array.isArray(data?.data) && data.data.length) {
      for (const ch of data.data) channelIdCache.set(ch.slug, ch.broadcaster_user_id);
      return data.data;
    }
  } catch {}
  // ?slug[]=a&slug[]=b
  try {
    const qs = list.map(s => `slug[]=${encodeURIComponent(s)}`).join("&");
    const { data } = await axios.get(`${baseUrl}?${qs}`, { headers, timeout });
    if (Array.isArray(data?.data) && data.data.length) {
      for (const ch of data.data) channelIdCache.set(ch.slug, ch.broadcaster_user_id);
      return data.data;
    }
  } catch {}
  return [];
}

/* ---------- Wysyłanie na czat ---------- */
async function sendChatMessage({ broadcaster_user_id, content, type = "user" }) {
  const token = await refreshIfNeeded();
  await axios.post("https://api.kick.com/public/v1/chat", { broadcaster_user_id, content, type }, { headers: { Authorization: `Bearer ${token}` }, timeout: 15000 });
  markEchoSent(broadcaster_user_id, content);
}

/* ---------- ECHO ---------- */
const echoEnabled = String(CMD_ECHO_ENABLED).toLowerCase() === "true";
const echoMinRun = Math.max(2, Number(CMD_ECHO_MIN_RUN ?? ECHO_THRESHOLD ?? 5));
const echoCooldownMs = Math.max(5, Number(CMD_ECHO_COOLDOWN_SECONDS) || 60) * 1000;
const echoExclude = new Set((CMD_ECHO_EXCLUDE || IGNORE_EXACT || "").split(",").map(s => s.trim().toLowerCase()).filter(Boolean));

const echoStateByChannel = new Map(); // id -> { current, count, lastSentAt }
const echoRecentSent = new Map();     // id -> Map<content, ts>
function markEchoSent(id, content) {
  const m = echoRecentSent.get(id) || new Map();
  m.set(content, Date.now());
  for (const [msg, ts] of m) if (Date.now() - ts > 30_000) m.delete(msg);
  echoRecentSent.set(id, m);
}
const wasEchoSentRecently = (id, content) => {
  const m = echoRecentSent.get(id);
  const ts = m?.get(content);
  return Boolean(ts && Date.now() - ts < 30_000);
};

/* ---------- WebSocket + pobieranie chatroom_id i user_id (oba warianty slugów) ---------- */
const wsBySlug = new Map();
const missingChatLogOnce = new Set();

async function getChannelWithChatroom(slugRaw) {
  const variants = altSlugs(slugRaw);
  let ch = null;
  let chatroom_id = null;
  let usedSlug = variants[0];

  // 0) override
  for (const v of variants) {
    if (CHATROOM_OVERRIDES[v]) {
      usedSlug = v;
      const byV1 = (await getChannelsBySlugs([v]))?.[0] || null;
      ch = byV1 || { slug: v, broadcaster_user_id: channelIdCache.get(v) ?? null };
      chatroom_id = CHATROOM_OVERRIDES[v];
      if (ch?.broadcaster_user_id) channelIdCache.set(v, ch.broadcaster_user_id);
      return { usedSlug, ch, chatroom_id };
    }
  }

  // 1) public/v1
  for (const v of variants) {
    try {
      const byV1 = (await getChannelsBySlugs([v]))?.[0] || null;
      if (byV1) {
        usedSlug = v;
        ch = byV1;
        chatroom_id = ch?.chatroom?.id ?? ch?.chatroom_id ?? null;
        if (ch?.broadcaster_user_id) channelIdCache.set(v, ch.broadcaster_user_id);
        if (chatroom_id) return { usedSlug, ch, chatroom_id };
      }
    } catch {}
  }

  // 2) api/v2 JSON
  for (const v of variants) {
    try {
      const { data } = await axios.get(`https://kick.com/api/v2/channels/${encodeURIComponent(v)}`, { timeout: 15000, headers: JSON_HEADERS });
      if (data) {
        usedSlug = v;
        chatroom_id = data?.chatroom?.id ?? data?.data?.chatroom?.id ?? null;
        const uid = data?.user_id ?? data?.data?.user_id ?? null;
        if (!ch) ch = { slug: v, broadcaster_user_id: uid ?? channelIdCache.get(v) ?? null };
        if (uid) channelIdCache.set(v, uid);
        if (chatroom_id) return { usedSlug, ch, chatroom_id };
      }
    } catch {}
  }

  // 3) api/v2 HTML jako tekst
  for (const v of variants) {
    try {
      const { data: raw } = await axios.get(`https://kick.com/api/v2/channels/${encodeURIComponent(v)}`, { timeout: 15000, headers: HTML_HEADERS, responseType: "text" });
      let m = /"chatroom"\s*:\s*\{\s*"id"\s*:\s*(\d+)/.exec(raw) || /"chatroom_id"\s*:\s*(\d+)/.exec(raw);
      if (m) { usedSlug = v; chatroom_id = Number(m[1]); if (chatroom_id) return { usedSlug, ch, chatroom_id }; }
    } catch {}
  }

  // 4) /chatroom
  for (const v of variants) {
    try {
      const { data } = await axios.get(`https://kick.com/api/v2/channels/${encodeURIComponent(v)}/chatroom`, { timeout: 15000, headers: JSON_HEADERS });
      if (data?.id) { usedSlug = v; chatroom_id = data.id; return { usedSlug, ch, chatroom_id }; }
    } catch {}
  }

  // 5) strona kanału (HTML) — dodatkowo spróbuj wyciągnąć user_id
  for (const v of variants) {
    try {
      const { data: html } = await axios.get(`https://kick.com/${encodeURIComponent(v)}`, { timeout: 15000, headers: HTML_HEADERS, responseType: "text" });
      let m = /"chatroom"\s*:\s*\{\s*"id"\s*:\s*(\d+)/.exec(html) || /"chatroom_id"\s*:\s*(\d+)/.exec(html);
      const u = /"user_id"\s*:\s*(\d+)/.exec(html);
      if (u) channelIdCache.set(v, Number(u[1]));
      if (m) { usedSlug = v; chatroom_id = Number(m[1]); return { usedSlug, ch, chatroom_id }; }
    } catch {}
  }

  return { usedSlug, ch, chatroom_id };
}

function ensureWsListener(slugRaw, broadcaster_user_id_hint) {
  if (!echoEnabled) return;
  const slug = String(slugRaw || "").toLowerCase();
  if (wsBySlug.has(slug)) return;

  getChannelWithChatroom(slug).then(({ usedSlug, ch, chatroom_id }) => {
    if (!chatroom_id) {
      if (!missingChatLogOnce.has(slug)) { console.warn(`Brak chatroom_id dla ${slug}`); missingChatLogOnce.add(slug); }
      setTimeout(() => { wsBySlug.delete(slug); ensureWsListener(slug, broadcaster_user_id_hint); }, 60_000);
      return;
    }

    // upewnij się, że mamy broadcaster_user_id
    const broadcaster_user_id =
      ch?.broadcaster_user_id ||
      channelIdCache.get(usedSlug) ||
      channelIdCache.get(slug) ||
      broadcaster_user_id_hint ||
      0;

    if (!broadcaster_user_id) {
      console.warn(`Brak broadcaster_user_id dla ${slug} — echo nie wyśle wiadomości`);
    } else {
      channelIdCache.set(slug, broadcaster_user_id);
      channelIdCache.set(usedSlug, broadcaster_user_id);
    }

    const socket = io("https://chat.kick.com", {
      transports: ["websocket"],
      forceNew: true,
      reconnection: true,
      reconnectionDelayMax: 15000,
    });
    wsBySlug.set(slug, socket);

    socket.on("connect", () => {
      try { socket.emit("SUBSCRIBE", { room: `chatrooms:${chatroom_id}` }); } catch {}
      console.log(`WS connected for ${slug} -> room chatrooms:${chatroom_id} (uid=${broadcaster_user_id || "?"})`);
    });
    socket.on("disconnect", () => console.log(`WS disconnected for ${slug}`));

    const onMsg = async (payload) => {
      try {
        const raw = payload?.content ?? payload?.message?.content ?? "";
        const content = String(raw || "").trim();
        if (!content) return;

        const lower = content.toLowerCase();
        if (!lower.startsWith("!")) return;
        if (echoExclude.has(lower)) return;
        if (wasEchoSentRecently(broadcaster_user_id, content)) return;

        const id = broadcaster_user_id || channelIdCache.get(slug) || channelIdCache.get(usedSlug) || 0;
        const st = echoStateByChannel.get(id) || { current: "", count: 0, lastSentAt: 0 };

        if (st.current === lower) st.count += 1;
        else { st.current = lower; st.count = 1; }

        const now = Date.now();
        if (st.count >= echoMinRun && now - st.lastSentAt > echoCooldownMs && id) {
          console.log(`Echo TRIGGER for ${slug} (uid=${id}):`, content);
          try {
            await sendChatMessage({ broadcaster_user_id: id, content, type: "user" });
            st.lastSentAt = now;
            st.count = 0;
          } catch (e) {
            console.warn("Echo send error:", e?.response?.status || e?.message);
          }
        }
        echoStateByChannel.set(id, st);
      } catch {}
    };

    socket.on("message", onMsg);
    socket.on("chat_message", onMsg);
  }).catch(() => {});
}

/* ---------- Polling: odpala WS gdy LIVE ---------- */
const pollMs = Math.max(30, Number(POLL_SECONDS) || 60) * 1000;
async function pollingTick() {
  try {
    if (!allowedSlugs.length) return;
    const chans = await getChannelsBySlugs(allowedSlugs);
    for (const ch of chans) {
      const id = ch.broadcaster_user_id;
      const slug = String(ch.slug || "").toLowerCase();
      if (id) channelIdCache.set(slug, id);
      const isLive = ch.stream?.is_live === true; // nie zawsze dostępne
      if (isLive || true) {                        // wymuś próbę WS nawet gdy API nie podaje stream
        ensureWsListener(slug, id || 0);
      }
    }
  } catch (e) {
    console.error("Polling error:", e.message);
  }
}

/* ---------- OAuth: START/CALLBACK (PKCE w state) ---------- */
const b64 = (obj) => Buffer.from(JSON.stringify(obj)).toString("base64url");
const unb64 = (s) => { try { return JSON.parse(Buffer.from(String(s), "base64url").toString("utf8")); } catch { return null; } };

function buildAuthorizeURL(stateB64, codeChallenge) {
  const p = new URLSearchParams({
    response_type: "code",
    client_id: KICK_CLIENT_ID,
    redirect_uri: KICK_REDIRECT_URI || "",
    scope: "user:read channel:read chat:write events:subscribe",
    code_challenge: codeChallenge,
    code_challenge_method: "S256",
    state: stateB64,
  });
  return `${AUTH_URL}?${p.toString()}`;
}

const startPaths = [ `${KICK_OAUTH_PREFIX}/start`, "/oauth/start", "/auth/start", "/start" ];
const callbackPaths = [ `${KICK_OAUTH_PREFIX}/callback`, "/oauth/callback", "/auth/callback", "/callback" ];

mountGet(startPaths, (_req, res) => {
  if (!KICK_CLIENT_ID) return res.status(400).send("Missing KICK_CLIENT_ID");
  const verifier = crypto.randomBytes(32).toString("base64url");
  const challenge = crypto.createHash("sha256").update(verifier).digest().toString("base64url");
  const stateB64 = b64({ s: crypto.randomBytes(8).toString("hex"), v: verifier });
  res.redirect(buildAuthorizeURL(stateB64, challenge));
});

mountGet(callbackPaths, async (req, res) => {
  try {
    const { code, state, error, error_description } = req.query;
    if (error) return res.status(400).send(`OAuth error: ${error} ${error_description || ""}`);
    if (!code || !state) return res.status(400).send("Brak code/state – odpal /auth/start ponownie.");

    const verifier = unb64(state)?.v || null;
    if (!verifier) return res.status(400).send("Brak code_verifier – uruchom /auth/start ponownie.");

    const params = new URLSearchParams({
      grant_type: "authorization_code",
      client_id: KICK_CLIENT_ID,
      client_secret: KICK_CLIENT_SECRET,
      redirect_uri: KICK_REDIRECT_URI || "",
      code_verifier: verifier,
      code: String(code),
    });

    const { data } = await axios.post(TOKEN_URL, params, { headers: { "Content-Type": "application/x-www-form-urlencoded" }, timeout: 15000 });
    tokens.access_token = data.access_token;
    tokens.refresh_token = data.refresh_token;
    tokens.expires_at = Math.floor(Date.now() / 1000) + (data.expires_in || 3600);
    saveTokens();
    res.send("OK – tokeny zapisane. Możesz zamknąć kartę. Sprawdź /tokens lub /chat/test.");
  } catch (e) {
    console.error("Callback error:", e.response?.data || e.message);
    res.status(500).send("Błąd callback: " + (e.response?.data?.error_description || e.message));
  }
});

/* ---------- REST pomocnicze ---------- */
app.get("/health", (_req, res) => res.send("ok"));

app.get("/tokens", (_req, res) => {
  const has_access_token = Boolean(tokens?.access_token);
  const has_refresh_token = Boolean(tokens?.refresh_token);
  const token_type = has_access_token ? "Bearer" : null;
  const expires_in = has_access_token ? Math.max(0, Number(tokens.expires_at || 0) - Math.floor(Date.now() / 1000)) : null;
  res.json({ has_access_token, has_refresh_token, token_type, expires_in, scope: "user:read chat:write" });
});

/* Admin: ręczne wysłanie */
app.get("/admin/send", async (req, res) => {
  try {
    const key = req.query.key || req.get("X-Admin-Key");
    if (!ADMIN_KEY || key !== ADMIN_KEY) return res.status(403).send("Forbidden");

    const slug = String(req.query.slug || allowedSlugs[0] || "").toLowerCase();
    const msg = String(req.query.msg || "TEST").slice(0, 280);
    if (!slug) return res.status(400).json({ error: "Brak slug" });

    const chans = await getChannelsBySlugs([slug]);
    const id = chans?.[0]?.broadcaster_user_id || channelIdCache.get(slug) || 0;
    if (!id) return res.status(404).json({ error: `Kanał ${slug} nie znaleziony` });

    await sendChatMessage({ broadcaster_user_id: id, content: msg, type: "user" });
    return res.json({ ok: true, sent_to: { slug, id }, msg });
  } catch (e) {
    return res.status(e?.response?.status || 500).json({ ok: false, status: e?.response?.status, data: e?.response?.data || e.message });
  }
});

/* Admin: wymuś WS nasłuch (offline OK) */
app.get("/admin/ws-listen", async (req, res) => {
  try {
    const key = req.query.key || req.get("X-Admin-Key");
    if (!ADMIN_KEY || key !== ADMIN_KEY) return res.status(403).send("Forbidden");

    const slug = String(req.query.slug || allowedSlugs[0] || "").toLowerCase();
    if (!slug) return res.status(400).json({ error: "missing slug" });

    const chans = await getChannelsBySlugs([slug]);
    const id = chans?.[0]?.broadcaster_user_id || channelIdCache.get(slug) || 0;

    ensureWsListener(slug, id);
    return res.json({ ok: true, listening: true, slug, id });
  } catch (e) {
    return res.status(500).json({ ok: false, error: e.message });
  }
});

/* Admin: debug (sprawdź rozwiązywanie id/chatroom) */
app.get("/admin/debug", async (req, res) => {
  try {
    const key = req.query.key || req.get("X-Admin-Key");
    if (!ADMIN_KEY || key !== ADMIN_KEY) return res.status(403).send("Forbidden");
    const slug = String(req.query.slug || allowedSlugs[0] || "").toLowerCase();
    const { usedSlug, ch, chatroom_id } = await getChannelWithChatroom(slug);
    const cacheId = channelIdCache.get(slug) || channelIdCache.get(usedSlug) || null;
    res.json({ usedSlug, chatroom_id, ch, cacheId });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

/* Chat test – GET i POST */
mountGet("/chat/test", async (req, res) => {
  try {
    const slug = String(req.query.slug || allowedSlugs[0] || "").toLowerCase();
    const text = String(req.query.text || req.query.msg || "siema").slice(0, 280);
    if (!slug) return res.json({ ok: false, error: "missing slug" });

    const chans = await getChannelsBySlugs([slug]);
    const id = chans?.[0]?.broadcaster_user_id || channelIdCache.get(slug) || 0;
    if (!id) return res.json({ ok: false, error: `channel ${slug} not found` });

    await sendChatMessage({ broadcaster_user_id: id, content: text, type: "user" });
    res.json({ ok: true, sent_to: { slug, id }, text });
  } catch (e) {
    res.json({ ok: false, error: e?.response?.data || e.message });
  }
});
mountPost("/chat/test", async (req, res) => {
  try {
    const body = req.body || {};
    const slug = String(body.slug || allowedSlugs[0] || "").toLowerCase();
    const text = String(body.text || body.msg || "siema").slice(0, 280);
    if (!slug) return res.json({ ok: false, error: "missing slug" });

    const chans = await getChannelsBySlugs([slug]);
    const id = chans?.[0]?.broadcaster_user_id || channelIdCache.get(slug) || 0;
    if (!id) return res.json({ ok: false, error: `channel ${slug} not found` });

    await sendChatMessage({ broadcaster_user_id: id, content: text, type: "user" });
    res.json({ ok: true, sent_to: { slug, id }, text });
  } catch (e) {
    res.json({ ok: false, error: e?.response?.data || e.message });
  }
});

/* Subskrypcje (opcjonalne) */
mountPost("/subscribe", async (_req, res) => {
  try {
    const token = await refreshIfNeeded();
    const { data } = await axios.post(
      "https://api.kick.com/public/v1/events/subscriptions",
      { events: [{ name: "livestream.status.updated", version: 1 }], method: "webhook" },
      { headers: { Authorization: `Bearer ${token}` }, timeout: 15000 }
    );
    res.json({ ok: true, created: data?.data || null });
  } catch (e) {
    res.status(e?.response?.status || 500).json({ ok: false, error: e?.response?.data || e.message });
  }
});
mountGet("/subscribe", async (req, res) => {
  try {
    if (SUBSCRIBE_KEY) {
      if (req.query.key !== SUBSCRIBE_KEY) return res.status(403).send("Forbidden");
    } else {
      return res.status(405).send("Use POST /subscribe or set SUBSCRIBE_KEY to enable GET.");
    }
    const token = await refreshIfNeeded();
    const { data } = await axios.post(
      "https://api.kick.com/public/v1/events/subscriptions",
      { events: [{ name: "livestream.status.updated", version: 1 }], method: "webhook" },
      { headers: { Authorization: `Bearer ${token}` }, timeout: 15000 }
    );
    res.json({ ok: true, created: data?.data || null });
  } catch (e) {
    res.status(e?.response?.status || 500).json({ ok: false, error: e?.response?.data || e.message });
  }
});

/* ---------- Start ---------- */
app.listen(PORT, () => {
  console.log(`auth+bot app listening on :${PORT}`);
  console.log(`Using OAuth prefix: ${KICK_OAUTH_PREFIX} (authorize: ${AUTH_URL})`);
  setInterval(pollingTick, pollMs);
  pollingTick();
});
