// server.js  (ESM) — Kick echo bot + OAuth
// Logika bez zmian: OAuth, /chat/test, echo po X powtórzeniach, polling live.
// Zmiany: stabilniejsze WS (kilka hostów), lepsze nagłówki i logi, aliasy /auth/*.

/* ---------- importy ---------- */
import "dotenv/config";
import express from "express";
import bodyParser from "body-parser";
import axios from "axios";
import crypto from "crypto";
import fs from "fs";
import path from "path";
import { io } from "socket.io-client";

/* ---------- stałe/nagłówki ---------- */
const UA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36";
const JSON_HEADERS = { "User-Agent": UA, Accept: "application/json, text/plain, */*", Referer: "https://kick.com/" };
const HTML_HEADERS = { "User-Agent": UA, Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", Referer: "https://kick.com/" };

/* ---------- ENV ---------- */
const {
  PORT = 3100,

  // OAuth / Kick
  KICK_CLIENT_ID = "",
  KICK_CLIENT_SECRET = "",
  KICK_REDIRECT_URI = "",
  AUTH_URL = "https://id.kick.com/oauth/authorize",
  TOKEN_URL = "https://id.kick.com/oauth/token",
  KICK_OAUTH_PREFIX = "/oauth",

  // Kanały / bot
  ALLOWED_SLUGS = "",
  BOT_USERNAME = "",
  CHATROOM_ID_OVERRIDES = "",
  ADMIN_KEY = "",
  SUBSCRIBE_KEY = "",

  // Echo
  CMD_ECHO_ENABLED = "true",
  CMD_ECHO_MIN_RUN,
  ECHO_THRESHOLD,
  CMD_ECHO_COOLDOWN_SECONDS = "60",
  IGNORE_EXACT = "",
  CMD_ECHO_EXCLUDE = "",

  // pliki/tokeny
  TOKENS_PATH = "/tmp/kick_tokens.json",
  DATA_DIR = "/tmp",
  KICK_REFRESH_TOKEN = "",

  // harmonogram „polling” (live on/off)
  RAND_MIN_MINUTES = "",
  RAND_MAX_MINUTES = "",
  INTERVAL_MINUTES = "5",
  JITTER_SECONDS = "30,60",
  POLL_SECONDS = "60",

  // WebSocket: można narzucić konkretny URL albo listę (próby po kolei)
  KICK_WS_URL = "",
  KICK_WS_URLS = "wss://ws2.chat.kick.com,wss://ws1.chat.kick.com,wss://chat.kick.com",
  // Ostateczna deska ratunku (nie używać, chyba że Cloudflare/TLS bruździ):
  WS_INSECURE = "false",
} = process.env;

/* ---------- parse ENV ---------- */
const allowedSlugs = String(ALLOWED_SLUGS || "")
  .split(",")
  .map((s) => s.trim().toLowerCase())
  .filter(Boolean);

const CHATROOM_OVERRIDES = String(CHATROOM_ID_OVERRIDES || "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean)
  .reduce((acc, pair) => {
    const [slug, id] = pair.split(":").map((x) => (x || "").trim());
    if (slug && id && /^\d+$/.test(id)) acc[slug.toLowerCase()] = Number(id);
    return acc;
  }, {});

const WS_CANDIDATES = [
  ...String(KICK_WS_URL ? KICK_WS_URL : "").split(","),
  ...String(KICK_WS_URLS || "").split(","),
]
  .map((s) => s.trim())
  .filter(Boolean);

/* ---------- pliki ---------- */
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
const TOKENS_FILE = TOKENS_PATH || path.join(DATA_DIR, "tokens.json");
const PKCE_FILE = path.join(DATA_DIR, "pkce.json");

/* ---------- express ---------- */
const app = express();
app.use(
  bodyParser.json({
    verify: (req, _res, buf) => (req.rawBody = buf),
  })
);
app.use(
  bodyParser.urlencoded({
    extended: true,
    verify: (req, _res, buf) => (req.rawBody = buf),
  })
);

/* ---------- mount helpers ---------- */
function mountGet(paths, handler) {
  (Array.isArray(paths) ? paths : [paths]).forEach((p) => app.get(p, handler));
}
function mountPost(paths, handler) {
  (Array.isArray(paths) ? paths : [paths]).forEach((p) => app.post(p, handler));
}

/* ---------- tokeny ---------- */
let tokens = { access_token: null, refresh_token: null, expires_at: 0 };

function saveTokens() {
  try {
    fs.writeFileSync(TOKENS_FILE, JSON.stringify(tokens, null, 2));
  } catch {}
}
function loadTokens() {
  try {
    if (fs.existsSync(TOKENS_FILE)) {
      const t = JSON.parse(fs.readFileSync(TOKENS_FILE, "utf-8"));
      if (t?.refresh_token) tokens = t;
    }
  } catch {}
  if (!tokens.refresh_token && KICK_REFRESH_TOKEN) tokens.refresh_token = KICK_REFRESH_TOKEN.trim();
}
async function refreshIfNeeded() {
  const now = Math.floor(Date.now() / 1000);
  if (tokens.access_token && now < Number(tokens.expires_at || 0) - 60) return tokens.access_token;
  if (!tokens.refresh_token) throw new Error("Brak refresh_token – zrób /oauth/start (lub /auth/start)");

  const params = new URLSearchParams();
  params.append("grant_type", "refresh_token");
  params.append("client_id", KICK_CLIENT_ID);
  params.append("client_secret", KICK_CLIENT_SECRET);
  params.append("refresh_token", tokens.refresh_token);

  const { data } = await axios.post(TOKEN_URL, params, {
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    timeout: 15000,
  });

  tokens.access_token = data.access_token;
  tokens.refresh_token = data.refresh_token;
  tokens.expires_at = Math.floor(Date.now() / 1000) + (data.expires_in || 3600);
  saveTokens();
  return tokens.access_token;
}

/* ---------- app token do public API ---------- */
let appToken = { token: null, expires_at: 0 };
async function getAppToken() {
  const now = Math.floor(Date.now() / 1000);
  if (appToken.token && now < Number(appToken.expires_at || 0) - 60) return appToken.token;
  const params = new URLSearchParams();
  params.append("grant_type", "client_credentials");
  params.append("client_id", KICK_CLIENT_ID);
  params.append("client_secret", KICK_CLIENT_SECRET);
  const { data } = await axios.post(TOKEN_URL, params, {
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    timeout: 15000,
  });
  appToken.token = data.access_token;
  appToken.expires_at = now + (data.expires_in || 3600);
  return appToken.token;
}

/* ---------- kanały ---------- */
const channelIdCache = new Map(); // slug -> broadcaster_user_id

async function getChannelsBySlugs(slugs) {
  const list = (Array.isArray(slugs) ? slugs : [slugs])
    .map((s) => String(s || "").trim().toLowerCase())
    .filter(Boolean);
  if (!list.length) return [];
  const token = await getAppToken();
  const base = "https://api.kick.com/public/v1/channels";
  const headers = { Authorization: `Bearer ${token}` };
  const timeout = 15000;

  if (list.length === 1) {
    const slug = encodeURIComponent(list[0]);
    try {
      const { data } = await axios.get(`${base}/${slug}`, { headers, timeout });
      const ch = data?.data || data;
      if (ch) {
        if (ch.slug) channelIdCache.set(ch.slug, ch.broadcaster_user_id);
        return [ch];
      }
    } catch (e) {
      if (e?.response?.status && e.response.status !== 404) throw e;
    }
  }

  try {
    const qs = list.map((s) => `slug=${encodeURIComponent(s)}`).join("&");
    const { data } = await axios.get(`${base}?${qs}`, { headers, timeout });
    if (Array.isArray(data?.data) && data.data.length) {
      for (const ch of data.data) channelIdCache.set(ch.slug, ch.broadcaster_user_id);
      return data.data;
    }
  } catch {}
  try {
    const qs = list.map((s) => `slug[]=${encodeURIComponent(s)}`).join("&");
    const { data } = await axios.get(`${base}?${qs}`, { headers, timeout });
    if (Array.isArray(data?.data) && data.data.length) {
      for (const ch of data.data) channelIdCache.set(ch.slug, ch.broadcaster_user_id);
      return data.data;
    }
  } catch {}
  return [];
}

/* ---------- wysyłanie wiadomości ---------- */
async function sendChatMessage({ broadcaster_user_id, content, type = "user" }) {
  const token = await refreshIfNeeded();
  await axios.post(
    "https://api.kick.com/public/v1/chat",
    { broadcaster_user_id, content, type },
    { headers: { Authorization: `Bearer ${token}` }, timeout: 15000 }
  );
  markEchoSent(broadcaster_user_id, content);
}

/* ---------- echo ---------- */
const echoEnabled = String(CMD_ECHO_ENABLED).toLowerCase() === "true";
const echoMinRun = Math.max(2, Number(CMD_ECHO_MIN_RUN ?? ECHO_THRESHOLD ?? 5));
const echoCooldownMs = Math.max(5, Number(CMD_ECHO_COOLDOWN_SECONDS) || 60) * 1000;
const echoExclude = new Set(
  (CMD_ECHO_EXCLUDE || IGNORE_EXACT || "")
    .split(",")
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean)
);

const echoStateByChannel = new Map(); // id -> { current, count, lastSentAt }
const echoRecentSent = new Map(); // id -> Map<content, ts>
function markEchoSent(id, content) {
  const m = echoRecentSent.get(id) || new Map();
  m.set(content, Date.now());
  for (const [msg, ts] of m) if (Date.now() - ts > 30_000) m.delete(msg);
  echoRecentSent.set(id, m);
}
function wasEchoSentRecently(id, content) {
  const m = echoRecentSent.get(id);
  if (!m) return false;
  const ts = m.get(content);
  return Boolean(ts && Date.now() - ts < 30_000);
}

/* ---------- WS czatu ---------- */
const wsBySlug = new Map(); // slug -> socket
const missingChatLogOnce = new Set();

async function getChannelWithChatroom(slug) {
  const ov = CHATROOM_OVERRIDES[slug];
  let ch = null;
  let chatroom_id = null;

  if (ov) {
    ch = (await getChannelsBySlugs([slug]))?.[0] || { slug, broadcaster_user_id: channelIdCache.get(slug) ?? null };
    return { ch, chatroom_id: ov };
  }

  try {
    ch = (await getChannelsBySlugs([slug]))?.[0] || null;
    chatroom_id = ch?.chatroom?.id ?? ch?.chatroom_id ?? null;
  } catch {}

  if (!chatroom_id) {
    try {
      const { data } = await axios.get(`https://kick.com/api/v2/channels/${encodeURIComponent(slug)}`, {
        timeout: 15000,
        headers: JSON_HEADERS,
      });
      chatroom_id = data?.chatroom?.id ?? data?.data?.chatroom?.id ?? null;
      if (!ch && data) {
        ch = {
          slug,
          broadcaster_user_id: data?.user_id ?? data?.data?.user_id ?? channelIdCache.get(slug) ?? null,
        };
      }
    } catch {}
  }

  if (!chatroom_id) {
    try {
      const { data: raw } = await axios.get(`https://kick.com/api/v2/channels/${encodeURIComponent(slug)}`, {
        timeout: 15000,
        headers: HTML_HEADERS,
        responseType: "text",
      });
      let m = /"chatroom"\s*:\s*\{\s*"id"\s*:\s*(\d+)/.exec(raw);
      if (!m) m = /"chatroom_id"\s*:\s*(\d+)/.exec(raw);
      if (m) chatroom_id = Number(m[1]);
    } catch {}
  }

  if (!chatroom_id) {
    try {
      const { data } = await axios.get(
        `https://kick.com/api/v2/channels/${encodeURIComponent(slug)}/chatroom`,
        { timeout: 15000, headers: JSON_HEADERS }
      );
      chatroom_id = data?.id ?? null;
    } catch {}
  }

  if (!chatroom_id) {
    try {
      const { data: html } = await axios.get(`https://kick.com/${encodeURIComponent(slug)}`, {
        timeout: 15000,
        headers: HTML_HEADERS,
        responseType: "text",
      });
      let m = /"chatroom"\s*:\s*\{\s*"id"\s*:\s*(\d+)/.exec(html);
      if (!m) m = /"chatroom_id"\s*:\s*(\d+)/.exec(html);
      if (m) chatroom_id = Number(m[1]);
      if (!ch) {
        const u = /"user_id"\s*:\s*(\d+)/.exec(html);
        ch = { slug, broadcaster_user_id: u ? Number(u[1]) : channelIdCache.get(slug) ?? null };
      }
    } catch {}
  }

  return { ch, chatroom_id };
}

function ensureWsListener(slugRaw, broadcaster_user_id) {
  if (!echoEnabled) return;
  const slug = String(slugRaw || "").toLowerCase();
  if (wsBySlug.has(slug)) return;

  getChannelWithChatroom(slug)
    .then(({ chatroom_id }) => {
      if (!chatroom_id) {
        if (!missingChatLogOnce.has(slug)) {
          console.warn(`Brak chatroom_id dla ${slug}`);
          missingChatLogOnce.add(slug);
        }
        setTimeout(() => {
          wsBySlug.delete(slug);
          ensureWsListener(slug, broadcaster_user_id);
        }, 60_000);
        return;
      }

      const urls = WS_CANDIDATES.length ? WS_CANDIDATES : ["wss://ws2.chat.kick.com", "wss://ws1.chat.kick.com", "wss://chat.kick.com"];
      let idx = 0;
      let socket = null;

      const connect = () => {
        const url = urls[idx % urls.length];
        const headers = {
          "User-Agent": UA,
          // ważne: Origin/Referer konkretnie do kanału
          Origin: `https://kick.com/${slug}`,
          Referer: `https://kick.com/${slug}`,
        };

        socket = io(url, {
          transports: ["websocket"],
          path: "/socket.io",
          forceNew: true,
          reconnection: true,
          reconnectionDelayMax: 15000,
          timeout: 15000,
          withCredentials: true,
          extraHeaders: headers,
          rejectUnauthorized: String(WS_INSECURE).toLowerCase() === "true" ? false : true,
        });

        wsBySlug.set(slug, socket);

        socket.on("connect", () => {
          try {
            socket.emit("SUBSCRIBE", { room: `chatrooms:${chatroom_id}` });
            console.log(`WS connected for ${slug} via ${url} -> chatrooms:${chatroom_id}`);
          } catch (e) {
            console.warn("WS subscribe error:", e?.message || e);
          }
        });

        socket.on("connect_error", (err) => {
          const msg =
            err?.message ||
            err?.data ||
            (typeof err === "string" ? err : JSON.stringify(err || {}));
          console.error("WS connect_error", slug, msg);
          // spróbuj następnego hosta po chwili
          try {
            socket?.close?.();
          } catch {}
          idx += 1;
          setTimeout(connect, 2000);
        });

        socket.on("error", (err) => {
          const msg = err?.message || (typeof err === "string" ? err : JSON.stringify(err || {}));
          console.error("WS error", slug, msg);
        });

        socket.on("disconnect", (reason) => {
          console.warn(`WS disconnected for ${slug}: ${reason}`);
          // pozwalamy socket.io samemu się połączyć, a jeśli cyklicznie błądzi — przeskoczymy na inny host
        });

        const onMsg = async (payload) => {
          try {
            const raw = payload?.content ?? payload?.message?.content ?? "";
            const content = String(raw || "").trim();
            if (!content) return;

            const lower = content.toLowerCase();
            if (!lower.startsWith("!")) return;
            if (echoExclude.has(lower)) return;
            if (wasEchoSentRecently(broadcaster_user_id, content)) return;

            const st = echoStateByChannel.get(broadcaster_user_id) || { current: "", count: 0, lastSentAt: 0 };
            if (st.current === lower) st.count += 1;
            else {
              st.current = lower;
              st.count = 1;
            }

            const now = Date.now();
            if (st.count >= echoMinRun && now - st.lastSentAt > echoCooldownMs) {
              try {
                await sendChatMessage({ broadcaster_user_id, content, type: "user" });
                st.lastSentAt = now;
                st.count = 0;
              } catch (e) {
                console.warn("sendChatMessage error:", e?.response?.data || e?.message || e);
              }
            }
            echoStateByChannel.set(broadcaster_user_id, st);
          } catch {}
        };

        socket.on("message", onMsg);
        socket.on("chat_message", onMsg);
      };

      connect();
    })
    .catch((e) => console.error("ensureWsListener error:", e?.message || e));
}

/* ---------- polling live on/off ---------- */
const pollMs = Math.max(30, Number(POLL_SECONDS) || 60) * 1000;
async function pollingTick() {
  try {
    if (!allowedSlugs.length) return;
    const chans = await getChannelsBySlugs(allowedSlugs);
    for (const ch of chans) {
      const id = ch.broadcaster_user_id;
      const slug = String(ch.slug || "").toLowerCase();
      const isLive = ch.stream?.is_live === true || ch?.is_live === true;
      if (isLive) {
        channelIdCache.set(slug, id);
        ensureWsListener(slug, id);
      }
    }
  } catch (e) {
    console.error("Polling error:", e?.message || e);
  }
}

/* ---------- OAuth START / CALLBACK (obsługujemy /oauth/*, /auth/* i bez prefixu) ---------- */
function buildAuthorizeURL(state, codeChallenge) {
  const params = new URLSearchParams({
    response_type: "code",
    client_id: KICK_CLIENT_ID,
    redirect_uri: KICK_REDIRECT_URI || "",
    scope: "user:read channel:read chat:write events:subscribe",
    code_challenge: codeChallenge,
    code_challenge_method: "S256",
    state,
  });
  return `${AUTH_URL}?${params.toString()}`;
}

const startPaths = [
  `${KICK_OAUTH_PREFIX}/start`,
  "/oauth/start",
  "/auth/start",
  "/start",
];
const callbackPaths = [
  `${KICK_OAUTH_PREFIX}/callback`,
  "/oauth/callback",
  "/auth/callback",
  "/callback",
];

mountGet(startPaths, (req, res) => {
  if (!KICK_CLIENT_ID) return res.status(400).send("Missing KICK_CLIENT_ID");
  const codeVerifier = crypto.randomBytes(32).toString("base64url");
  const hash = crypto.createHash("sha256").update(codeVerifier).digest();
  const codeChallenge = Buffer.from(hash).toString("base64url");
  const state = crypto.randomBytes(8).toString("hex");
  let store = {};
  try {
    if (fs.existsSync(PKCE_FILE)) store = JSON.parse(fs.readFileSync(PKCE_FILE, "utf-8"));
  } catch {}
  store[state] = { verifier: codeVerifier, ts: Date.now() };
  try {
    fs.writeFileSync(PKCE_FILE, JSON.stringify(store, null, 2));
  } catch {}
  res.redirect(buildAuthorizeURL(state, codeChallenge));
});

mountGet(callbackPaths, async (req, res) => {
  try {
    const { code, state, error, error_description } = req.query;
    if (error) return res.status(400).send(`OAuth error: ${error} ${error_description || ""}`);

    if (!code || !state) return res.status(400).send("Brak code/state – uruchom /oauth/start jeszcze raz.");
    let store = {};
    try {
      if (fs.existsSync(PKCE_FILE)) store = JSON.parse(fs.readFileSync(PKCE_FILE, "utf-8"));
    } catch {}
    const codeVerifier = store?.[String(state)]?.verifier;
    if (!codeVerifier) return res.status(400).send("Brak code_verifier – odpal /oauth/start ponownie.");

    const params = new URLSearchParams({
      grant_type: "authorization_code",
      client_id: KICK_CLIENT_ID,
      client_secret: KICK_CLIENT_SECRET,
      redirect_uri: KICK_REDIRECT_URI || "",
      code_verifier: codeVerifier,
      code: String(code),
    });

    const { data } = await axios.post(TOKEN_URL, params, {
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      timeout: 15000,
    });

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
  res.json({ has_access_token, has_refresh_token, token_type, expires_in, obtained_at: tokens?.obtained_at, scope: "user:read chat:write" });
});

/* Admin: ręczne wysłanie (GET) */
app.get("/admin/send", async (req, res) => {
  try {
    const key = req.query.key || req.get("X-Admin-Key");
    if (!ADMIN_KEY || key !== ADMIN_KEY) return res.status(403).send("Forbidden");

    const slug = String(req.query.slug || allowedSlugs[0] || "").toLowerCase();
    const msg = String(req.query.msg || "TEST").slice(0, 280);
    if (!slug) return res.status(400).json({ error: "Brak slug" });
    if (!allowedSlugs.includes(slug)) return res.status(403).json({ error: "Slug poza ALLOWED_SLUGS" });

    const chans = await getChannelsBySlugs([slug]);
    const id = chans?.[0]?.broadcaster_user_id;
    if (!id) return res.status(404).json({ error: `Kanał ${slug} nie znaleziony` });

    await sendChatMessage({ broadcaster_user_id: id, content: msg, type: "user" });
    return res.json({ ok: true, sent_to: { slug, id }, msg });
  } catch (e) {
    return res.status(e?.response?.status || 500).json({ ok: false, status: e?.response?.status, data: e?.response?.data || e.message });
  }
});

/* Admin: wymuś WS nasłuch */
app.get("/admin/ws-listen", async (req, res) => {
  try {
    const key = req.query.key || req.get("X-Admin-Key");
    if (!ADMIN_KEY || key !== ADMIN_KEY) return res.status(403).send("Forbidden");

    const slug = String(req.query.slug || allowedSlugs[0] || "").toLowerCase();
    if (!slug) return res.status(400).json({ error: "missing slug" });

    const chans = await getChannelsBySlugs([slug]);
    const id = chans?.[0]?.broadcaster_user_id || 0;
    ensureWsListener(slug, id);
    return res.json({ ok: true, listening: true, slug, id });
  } catch (e) {
    return res.status(500).json({ ok: false, error: e.message });
  }
});

/* Admin: szybki debug (chatroom_id, is_live itp.) */
app.get("/admin/debug", async (req, res) => {
  try {
    const slug = String(req.query.slug || allowedSlugs[0] || "").toLowerCase();
    const { ch, chatroom_id } = await getChannelWithChatroom(slug);
    res.json({ usedSlug: slug, chatroom_id, ch });
  } catch (e) {
    res.status(500).json({ error: e?.message || e });
  }
});

/* Chat test – GET i POST */
mountGet("/chat/test", async (req, res) => {
  try {
    const slug = String(req.query.slug || allowedSlugs[0] || "").toLowerCase();
    const text = String(req.query.text || req.query.msg || "siema").slice(0, 280);
    if (!slug) return res.json({ ok: false, error: "missing slug" });

    const chans = await getChannelsBySlugs([slug]);
    const id = chans?.[0]?.broadcaster_user_id;
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
    const id = chans?.[0]?.broadcaster_user_id;
    if (!id) return res.json({ ok: false, error: `channel ${slug} not found` });

    await sendChatMessage({ broadcaster_user_id: id, content: text, type: "user" });
    res.json({ ok: true, sent_to: { slug, id }, text });
  } catch (e) {
    res.json({ ok: false, error: e?.response?.data || e.message });
  }
});

/* Subskrypcje (opcjonalnie) */
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

/* ---------- start ---------- */
loadTokens();

app.listen(PORT, () => {
  console.log(`auth+bot app listening on :${PORT}`);
  console.log(`Using OAuth prefix: ${KICK_OAUTH_PREFIX} (authorize: ${AUTH_URL})`);
  setInterval(pollingTick, pollMs);
  pollingTick();
});
