import "dotenv/config";
import express from "express";
import bodyParser from "body-parser";
import axios from "axios";
import crypto from "crypto";
import fs from "fs";
import path from "path";
import { io } from "socket.io-client";

/* ===== UA ===== */
const UA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36";
const JSON_HEADERS = {
  "User-Agent": UA,
  Accept: "application/json, text/plain, */*",
  Referer: "https://kick.com/",
};
const HTML_HEADERS = {
  "User-Agent": UA,
  Accept:
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
  Referer: "https://kick.com/",
};

/* ===== ENV ===== */
const {
  PORT = 3100,

  KICK_CLIENT_ID,
  KICK_CLIENT_SECRET,
  KICK_REDIRECT_URI,

  ALLOWED_SLUGS = "",
  BOT_USERNAME = "",

  // wiadomości planowane – zostawiamy (nie przeszkadzają)
  CHAT_MESSAGE = "Cześć czacie!",
  CHAT_MESSAGES_JSON = "",
  CHAT_MESSAGES_B64 = "",
  MSG_NO_REPEAT_COUNT = "8",
  INTERVAL_MINUTES = "5",
  JITTER_SECONDS = "30,60",
  POLL_SECONDS = "60",
  RAND_MIN_MINUTES = "",
  RAND_MAX_MINUTES = "",

  // Echo spamu
  CMD_ECHO_ENABLED = "true",
  CMD_ECHO_MIN_RUN = "", // stara nazwa – jak ktoś używa
  ECHO_THRESHOLD = "",   // nowa, czytelna nazwa
  CMD_ECHO_COOLDOWN_SECONDS = "60",
  CMD_ECHO_EXCLUDE = "",
  IGNORE_EXACT = "",     // alias dla wygody

  // Webhook signature (opcjonalnie)
  VERIFY_WEBHOOK_SIGNATURE = "false",

  // Admin / zapisy
  ADMIN_KEY = "",
  SUBSCRIBE_KEY = "",
  DATA_DIR = ".",

  // KV (opcjonalnie)
  UPSTASH_REDIS_REST_URL = "",
  UPSTASH_REDIS_REST_TOKEN = "",

  // Awaryjny refresh
  KICK_REFRESH_TOKEN = "",

  // ręczne nadpisanie chatroom_id
  CHATROOM_ID_OVERRIDES = "",

  // test offline
  OFFLINE_MOCK_ALLOWED = "true",

  // (opcjonalnie) prefiks do OAuth
  KICK_OAUTH_PREFIX = "/oauth",
} = process.env;

/* ===== Overrides chatroom_id ===== */
const CHATROOM_OVERRIDES = String(CHATROOM_ID_OVERRIDES || "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean)
  .reduce((acc, pair) => {
    const [slug, id] = pair.split(":").map((x) => (x || "").trim());
    if (slug && id && /^\d+$/.test(id)) acc[slug.toLowerCase()] = Number(id);
    return acc;
  }, {});

/* ===== storage ===== */
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
const TOKENS_FILE = path.join(DATA_DIR, "tokens.json");
const PKCE_FILE = path.join(DATA_DIR, "pkce.json");

/* ===== listy ===== */
const allowedSlugs = ALLOWED_SLUGS.split(",")
  .map((s) => s.trim().toLowerCase())
  .filter(Boolean);

/* ===== planowanie wiadomości (bez zmian istotnych) ===== */
const intervalMs = Math.max(1, Number(INTERVAL_MINUTES)) * 60_000;
const [jMinRaw, jMaxRaw] = (JITTER_SECONDS || "30,60").split(",");
const jMin = Math.abs(Number(jMinRaw || 30));
const jMax = Math.abs(Number(jMaxRaw || 60));
const jitterMs = () =>
  (Math.floor(Math.random() * (Math.max(jMin, jMax) - Math.min(jMin, jMax) + 1)) +
    Math.min(jMin, jMax)) *
  1000;

const useRandInterval =
  String(RAND_MIN_MINUTES).trim() !== "" &&
  String(RAND_MAX_MINUTES).trim() !== "";
function nextDelayMs() {
  if (useRandInterval) {
    const lo = Math.min(
      Number(RAND_MIN_MINUTES) || 0,
      Number(RAND_MAX_MINUTES) || 0
    );
    const hi = Math.max(
      Number(RAND_MIN_MINUTES) || 0,
      Number(RAND_MAX_MINUTES) || 0
    );
    const secs =
      Math.floor(Math.random() * (hi * 60 - lo * 60 + 1)) + lo * 60;
    const ms = secs * 1000;
    console.log(`Next message in ~${(ms / 60000).toFixed(1)} min`);
    return ms;
  }
  const ms = intervalMs + jitterMs();
  console.log(
    `Next message in ~${(ms / 60000).toFixed(1)} min (fallback interval+jitter)`
  );
  return ms;
}
const pollMs = Math.max(30, Number(POLL_SECONDS)) * 1000;

/* ===== utils wiadomości planowanych (skrócone) ===== */
function decodeB64Lines(b64) {
  try {
    const raw = Buffer.from(b64, "base64").toString("utf-8");
    return raw.split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
  } catch {
    return [];
  }
}
let baseMessages = [];
if (CHAT_MESSAGES_B64) baseMessages = decodeB64Lines(CHAT_MESSAGES_B64);
if (!baseMessages.length && CHAT_MESSAGES_JSON) {
  try {
    const arr = JSON.parse(CHAT_MESSAGES_JSON);
    if (Array.isArray(arr) && arr.length) baseMessages = arr.map(String);
  } catch {}
}
if (!baseMessages.length) baseMessages = [String(CHAT_MESSAGE)];

/* ===== KV (opcjonalnie) ===== */
const TOKENS_KV_KEY = "kick_tokens_v1";
async function kvGet(key) {
  if (!UPSTASH_REDIS_REST_URL || !UPSTASH_REDIS_REST_TOKEN) return null;
  const r = await fetch(
    `${UPSTASH_REDIS_REST_URL}/get/${encodeURIComponent(key)}`,
    { headers: { Authorization: `Bearer ${UPSTASH_REDIS_REST_TOKEN}` } }
  );
  if (!r.ok) return null;
  const j = await r.json();
  try {
    return j?.result ? JSON.parse(j.result) : null;
  } catch {
    return null;
  }
}
async function kvSet(key, obj) {
  if (!UPSTASH_REDIS_REST_URL || !UPSTASH_REDIS_REST_TOKEN) return;
  const val = encodeURIComponent(JSON.stringify(obj));
  await fetch(
    `${UPSTASH_REDIS_REST_URL}/set/${encodeURIComponent(key)}/${val}`,
    { method: "POST", headers: { Authorization: `Bearer ${UPSTASH_REDIS_REST_TOKEN}` } }
  ).catch(() => {});
}

/* ===== tokeny ===== */
let tokens = { access_token: null, refresh_token: null, expires_at: 0 };
function saveTokensToFile() {
  try { fs.writeFileSync(TOKENS_FILE, JSON.stringify(tokens, null, 2)); } catch {}
}
async function saveTokensEverywhere() { saveTokensToFile(); await kvSet(TOKENS_KV_KEY, tokens); }
async function loadTokensOnBoot() {
  const kv = await kvGet(TOKENS_KV_KEY);
  if (kv?.refresh_token) { tokens = kv; return; }
  if (fs.existsSync(TOKENS_FILE)) {
    try { const f = JSON.parse(fs.readFileSync(TOKENS_FILE, "utf-8")); if (f?.refresh_token) tokens = f; } catch {}
  }
  if (!tokens.refresh_token && KICK_REFRESH_TOKEN) tokens.refresh_token = KICK_REFRESH_TOKEN.trim();
}

async function refreshIfNeeded() {
  const now = Math.floor(Date.now() / 1000);
  if (tokens.access_token && now < Number(tokens.expires_at || 0) - 60)
    return tokens.access_token;
  if (!tokens.refresh_token) throw new Error("Brak refresh_token – uruchom /auth/start lub /oauth/start");

  const params = new URLSearchParams();
  params.append("grant_type", "refresh_token");
  params.append("client_id", KICK_CLIENT_ID);
  params.append("client_secret", KICK_CLIENT_SECRET);
  params.append("refresh_token", tokens.refresh_token);

  const { data } = await axios.post("https://id.kick.com/oauth/token", params, {
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    timeout: 15000,
  });

  tokens.access_token = data.access_token;
  tokens.refresh_token = data.refresh_token;
  tokens.expires_at = Math.floor(Date.now() / 1000) + (data.expires_in || 3600);
  await saveTokensEverywhere();
  return tokens.access_token;
}

let appToken = { token: null, expires_at: 0 };
async function getAppToken() {
  const now = Math.floor(Date.now() / 1000);
  if (appToken.token && now < Number(appToken.expires_at || 0) - 60) return appToken.token;

  const params = new URLSearchParams();
  params.append("grant_type", "client_credentials");
  params.append("client_id", KICK_CLIENT_ID);
  params.append("client_secret", KICK_CLIENT_SECRET);

  const { data } = await axios.post("https://id.kick.com/oauth/token", params, {
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    timeout: 15000,
  });

  appToken.token = data.access_token;
  appToken.expires_at = now + (data.expires_in || 3600);
  return appToken.token;
}

/* ===== API helpers ===== */
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
        channelIdCache.set(ch.slug || list[0], ch.broadcaster_user_id);
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
      for (const ch of data.data)
        channelIdCache.set(ch.slug, ch.broadcaster_user_id);
      return data.data;
    }
  } catch {}

  try {
    const qs = list.map((s) => `slug[]=${encodeURIComponent(s)}`).join("&");
    const { data } = await axios.get(`${base}?${qs}`, { headers, timeout });
    if (Array.isArray(data?.data) && data.data.length) {
      for (const ch of data.data)
        channelIdCache.set(ch.slug, ch.broadcaster_user_id);
      return data.data;
    }
  } catch {}

  return [];
}

async function sendChatMessage({ broadcaster_user_id, content, type = "user" }) {
  const token = await refreshIfNeeded();
  await axios.post(
    "https://api.kick.com/public/v1/chat",
    { broadcaster_user_id, content, type },
    { headers: { Authorization: `Bearer ${token}` }, timeout: 15000 }
  );
  markEchoSent(broadcaster_user_id, content);
}

/* ===== ECHO: parametry ===== */
const echoEnabled = String(CMD_ECHO_ENABLED).toLowerCase() === "true";
// priorytet ma ECHO_THRESHOLD; jeśli puste – użyj starego CMD_ECHO_MIN_RUN albo 5
const echoMinRun = Math.max(
  2,
  Number(ECHO_THRESHOLD || CMD_ECHO_MIN_RUN || 5) || 5
);
const echoCooldownMs =
  Math.max(5, Number(CMD_ECHO_COOLDOWN_SECONDS) || 60) * 1000;

const excludeExact = new Set(
  (CMD_ECHO_EXCLUDE || IGNORE_EXACT || "")
    .split(",")
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean)
);

const echoStateByChannel = new Map(); // id -> { current, count, lastSentAt }
const echoRecentSent = new Map(); // id -> Map<content, ts>
function markEchoSent(id, content) {
  const m = echoRecentSent.get(id) || new Map();
  m.set((content || "").toLowerCase(), Date.now());
  for (const [msg, ts] of m)
    if (Date.now() - ts > 30_000) m.delete(msg);
  echoRecentSent.set(id, m);
}
function wasEchoSentRecently(id, content) {
  const m = echoRecentSent.get(id);
  if (!m) return false;
  const ts = m.get((content || "").toLowerCase());
  return Boolean(ts && Date.now() - ts < 30_000);
}

/** Normalizacja tylko do porównania */
function norm(s) {
  return String(s || "")
    .trim()
    .toLowerCase()
    .replace(/\s+/g, " ");
}

/** Główny silnik echo – używany przez WS i tryb offline */
async function processIncomingChat({ slug, broadcaster_user_id, content, sender }) {
  if (!echoEnabled) return;
  const txt = String(content || "").trim();
  if (!txt) return;

  // nie powtarzaj własnych
  const isSelf =
    (sender && BOT_USERNAME && String(sender).toLowerCase() === BOT_USERNAME.toLowerCase()) ||
    false;
  if (isSelf) return;

  // proste wykluczenie dokładnych fraz
  if (excludeExact.has(txt.toLowerCase())) return;

  const id = broadcaster_user_id;
  if (!id) return;

  // zapobieganie pętli
  if (wasEchoSentRecently(id, txt)) return;

  const state = echoStateByChannel.get(id) || {
    current: "",
    count: 0,
    lastSentAt: 0,
  };

  const n = norm(txt);
  if (state.current === n) state.count += 1;
  else {
    state.current = n;
    state.count = 1;
  }

  const now = Date.now();
  if (state.count >= echoMinRun && now - state.lastSentAt > echoCooldownMs) {
    try {
      await sendChatMessage({ broadcaster_user_id: id, content: txt, type: "user" });
      state.lastSentAt = now;
      state.count = 0; // wyzeruj licznik dla tej frazy
    } catch (e) {
      // nic – pokaż w logu
      console.warn("echo send error:", e?.response?.status || e.message);
    }
  }

  echoStateByChannel.set(id, state);
}

/* ===== WS czatu ===== */
const wsBySlug = new Map();
const missingChatLogOnce = new Set();

async function getChannelWithChatroom(slug) {
  // override – najpierw
  const ov = CHATROOM_OVERRIDES[slug];
  let ch = null, chatroom_id = null;

  try { ch = (await getChannelsBySlugs([slug]))?.[0] || null; } catch {}
  if (ov) return { ch: ch || { slug, broadcaster_user_id: channelIdCache.get(slug) ?? null }, chatroom_id: ov };

  // próby wyciągnięcia chatroom_id różnymi drogami
  try {
    const { data } = await axios.get(
      `https://kick.com/api/v2/channels/${encodeURIComponent(slug)}`, { headers: JSON_HEADERS, timeout: 15000 }
    );
    chatroom_id = data?.chatroom?.id ?? data?.data?.chatroom?.id ?? null;
    if (!ch && data) ch = { slug, broadcaster_user_id: data?.user_id ?? data?.data?.user_id ?? null };
  } catch {}

  if (!chatroom_id) {
    try {
      const { data } = await axios.get(
        `https://kick.com/api/v2/channels/${encodeURIComponent(slug)}/chatroom`, { headers: JSON_HEADERS, timeout: 15000 }
      );
      chatroom_id = data?.id ?? null;
    } catch {}
  }

  if (!chatroom_id) {
    try {
      const { data: html } = await axios.get(`https://kick.com/${encodeURIComponent(slug)}`, {
        timeout: 15000, headers: HTML_HEADERS, responseType: "text",
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
          console.warn(`[warn] Brak chatroom_id dla ${slug}. Ustaw CHATROOM_ID_OVERRIDES lub sprawdź slug.`);
          missingChatLogOnce.add(slug);
        }
        setTimeout(() => {
          wsBySlug.delete(slug);
          ensureWsListener(slug, broadcaster_user_id);
        }, 60_000);
        return;
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
        console.log(`WS connected for ${slug} (chatrooms:${chatroom_id})`);
      });

      socket.on("disconnect", () => console.log(`WS disconnected for ${slug}`));

      const handle = async (payload) => {
        try {
          const raw =
            payload?.content ??
            payload?.message?.content ??
            payload?.data?.content ??
            "";
          const user =
            payload?.sender?.username ??
            payload?.message?.sender?.username ??
            payload?.data?.sender?.username ??
            "";
          await processIncomingChat({
            slug, broadcaster_user_id, content: raw, sender: user,
          });
        } catch {}
      };

      socket.on("message", handle);
      socket.on("chat_message", handle);
    })
    .catch(() => {});
}

/* ===== planowane wysyłanie – (opcjonalnie) ===== */
const postingLoops = new Map();
function startPostingLoop(broadcaster_user_id) {
  if (postingLoops.has(broadcaster_user_id)) return;
  let cancelled = false;
  const tick = async () => {
    if (cancelled) return;
    try {
      // tu możesz wstawiać swoje planowane teksty – nie dotyczy echa
      await sendChatMessage({ broadcaster_user_id, content: baseMessages[0], type: "user" });
    } catch (e) {
      const status = e?.response?.status;
      if (status === 401 || status === 403) {
        stopPostingLoop(broadcaster_user_id);
        return;
      }
    } finally {
      if (!cancelled) setTimeout(tick, nextDelayMs());
    }
  };
  postingLoops.set(broadcaster_user_id, { cancel: () => (cancelled = true) });
  setTimeout(tick, nextDelayMs());
}
function stopPostingLoop(broadcaster_user_id) {
  const c = postingLoops.get(broadcaster_user_id);
  if (c) { c.cancel(); postingLoops.delete(broadcaster_user_id); }
}

/* ===== express ===== */
const app = express();
app.use(bodyParser.json({ verify: (req, _res, buf) => (req.rawBody = buf) }));
app.use(bodyParser.urlencoded({ extended: true, verify: (req, _res, buf) => (req.rawBody = buf) }));

/* ===== OAuth ===== */
function addOAuthRoutes(prefix) {
  app.get(`${prefix}/start`, (req, res) => {
    if (!KICK_CLIENT_ID || !KICK_REDIRECT_URI)
      return res.status(400).send("Missing OAuth envs");
    const codeVerifier = crypto.randomBytes(32).toString("base64url");
    const hash = crypto.createHash("sha256").update(codeVerifier).digest();
    const codeChallenge = Buffer.from(hash).toString("base64url");
    const state = crypto.randomBytes(8).toString("hex");
    const store = fs.existsSync(PKCE_FILE)
      ? JSON.parse(fs.readFileSync(PKCE_FILE, "utf-8"))
      : {};
    store[state] = { verifier: codeVerifier, ts: Date.now() };
    fs.writeFileSync(PKCE_FILE, JSON.stringify(store, null, 2));

    const params = new URLSearchParams({
      response_type: "code",
      client_id: KICK_CLIENT_ID,
      redirect_uri: KICK_REDIRECT_URI,
      scope: "user:read channel:read chat:write events:subscribe",
      code_challenge: codeChallenge,
      code_challenge_method: "S256",
      state,
    });
    res.redirect(`https://id.kick.com/oauth/authorize?${params.toString()}`);
  });

  app.get(`${prefix}/callback`, async (req, res) => {
    try {
      const { code, state } = req.query;
      const store = fs.existsSync(PKCE_FILE)
        ? JSON.parse(fs.readFileSync(PKCE_FILE, "utf-8"))
        : {};
      const codeVerifier = state ? store[String(state)]?.verifier : null;
      if (!code || !codeVerifier)
        return res.status(400).send("Brak code/code_verifier – odpal start ponownie.");

      const params = new URLSearchParams({
        grant_type: "authorization_code",
        client_id: KICK_CLIENT_ID,
        client_secret: KICK_CLIENT_SECRET,
        redirect_uri: KICK_REDIRECT_URI,
        code_verifier: codeVerifier,
        code: String(code),
      });

      const { data } = await axios.post(
        "https://id.kick.com/oauth/token",
        params,
        { headers: { "Content-Type": "application/x-www-form-urlencoded" }, timeout: 15000 }
      );

      tokens.access_token = data.access_token;
      tokens.refresh_token = data.refresh_token;
      tokens.expires_at =
        Math.floor(Date.now() / 1000) + (data.expires_in || 3600);
      await saveTokensEverywhere();

      res.send("Tokeny zapisane ✅. /tokens pokaże stan. Możesz testować echo.");
    } catch (e) {
      res
        .status(500)
        .send("Błąd callback: " + (e?.response?.data?.error_description || e.message));
    }
  });
}
addOAuthRoutes("/auth");
addOAuthRoutes(KICK_OAUTH_PREFIX);

/* ===== webhook (tylko status live) – opcjonalnie ===== */
app.post("/webhook", async (req, res) => {
  try {
    if (String(VERIFY_WEBHOOK_SIGNATURE).toLowerCase() === "true") {
      // (pomijam pełną weryfikację dla zwięzłości)
    }
    const eventType = req.get("Kick-Event-Type");
    if (eventType === "livestream.status.updated") {
      const { broadcaster, is_live } = req.body || {};
      const id = broadcaster?.user_id;
      const slug = String(broadcaster?.channel_slug || "").toLowerCase();
      if (id && allowedSlugs.includes(slug)) {
        if (is_live) startPostingLoop(id);
        else stopPostingLoop(id);
      }
    }
    res.sendStatus(200);
  } catch {
    res.sendStatus(500);
  }
});

/* ===== polling ===== */
async function pollingTick() {
  try {
    if (!allowedSlugs.length) return;
    const chans = await getChannelsBySlugs(allowedSlugs);
    for (const ch of chans) {
      const id = ch.broadcaster_user_id;
      const slug = String(ch.slug || "").toLowerCase();
      const isLive = ch.stream?.is_live === true;
      if (isLive) {
        channelIdCache.set(slug, id);
        ensureWsListener(slug, id);
        // startPostingLoop(id); // jeśli chcesz planowe – odkomentuj
      } else {
        // echo z WS nadal działa, jeśli Kick puszcza czat offline – zostawiamy sam WS
        ensureWsListener(slug, id);
      }
    }
  } catch (e) {
    console.error("Polling error:", e.message);
  }
}

/* ===== admin / diagnostyka ===== */
app.get("/health", (_req, res) => res.send("ok"));
app.get("/tokens", (_req, res) => {
  const has_access_token = Boolean(tokens.access_token);
  const has_refresh_token = Boolean(tokens.refresh_token);
  res.json({
    has_access_token,
    has_refresh_token,
    token_type: "Bearer",
    expires_in: tokens.expires_at ? tokens.expires_at - Math.floor(Date.now() / 1000) : null,
    obtained_at: tokens.expires_at ? tokens.expires_at - (tokens.expires_at - 3600) : null,
    scope: "user:read chat:write",
  });
});

/* Wymuszone wysłanie – szybki test */
app.get("/admin/send", async (req, res) => {
  try {
    const key = req.query.key || req.get("X-Admin-Key");
    if (!ADMIN_KEY || key !== ADMIN_KEY) return res.status(403).send("Forbidden");
    const slug = String(req.query.slug || allowedSlugs[0] || "").toLowerCase();
    const msg = String(req.query.msg || "TEST").slice(0, 280);
    const chans = await getChannelsBySlugs([slug]);
    const id = chans?.[0]?.broadcaster_user_id;
    if (!id) return res.status(404).json({ error: `Kanał ${slug} nie znaleziony` });
    await sendChatMessage({ broadcaster_user_id: id, content: msg, type: "user" });
    res.json({ ok: true, sent_to: { slug, id }, msg });
  } catch (e) {
    res
      .status(e?.response?.status || 500)
      .json({ ok: false, error: e?.response?.data || e.message });
  }
});

/* ======== TRYB OFFLINE: mock echo ======== */
/**
 * POST /dev/echo/mock
 * body: { slug: "holly-s", text: "siema", times: 5, dryRun: false }
 * - times: ile razy „udajemy”, że ktoś napisał to samo (domyślnie 1)
 * - dryRun=true -> nie wysyła na Kick, tylko liczy i zwraca co by zrobił
 */
app.post("/dev/echo/mock", async (req, res) => {
  try {
    if (String(OFFLINE_MOCK_ALLOWED).toLowerCase() !== "true")
      return res.status(403).json({ ok: false, error: "mock disabled" });

    const slug = String(req.body?.slug || allowedSlugs[0] || "").toLowerCase();
    const text = String(req.body?.text || "").trim();
    const times = Math.max(1, Number(req.body?.times) || 1);
    const dryRun = String(req.body?.dryRun).toLowerCase() === "true";

    if (!slug || !text) return res.status(400).json({ ok: false, error: "slug/text required" });

    const chans = await getChannelsBySlugs([slug]);
    const id = chans?.[0]?.broadcaster_user_id || channelIdCache.get(slug);
    if (!id) return res.status(404).json({ ok: false, error: "channel not found" });

    let wouldSend = false;
    for (let i = 0; i < times; i++) {
      // symulujemy wiadomość od innego usera
      await processIncomingChat({ slug, broadcaster_user_id: id, content: text, sender: "mock_user" });

      const st = echoStateByChannel.get(id) || { current: "", count: 0, lastSentAt: 0 };
      const n = norm(text);
      if (st.current === n && st.count === 0) {
        // oznacza, że właśnie „wystrzeliło” i licznik został wyzerowany
        wouldSend = true;
      }
    }

    if (!dryRun && wouldSend) {
      // jeśli w pętli wcześniej poszło realnie, to tutaj i tak nic – processIncomingChat już wysłał
    }

    const state = echoStateByChannel.get(id) || { current: "", count: 0, lastSentAt: 0 };
    res.json({
      ok: true,
      slug,
      broadcaster_user_id: id,
      echo_threshold: echoMinRun,
      cooldown_ms: echoCooldownMs,
      wouldSend,
      state,
    });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

/** Podgląd licznika */
app.get("/dev/echo/state", async (req, res) => {
  const slug = String(req.query.slug || allowedSlugs[0] || "").toLowerCase();
  const chans = await getChannelsBySlugs([slug]);
  const id = chans?.[0]?.broadcaster_user_id || channelIdCache.get(slug);
  const st = (id && echoStateByChannel.get(id)) || { current: "", count: 0, lastSentAt: 0 };
  res.json({ ok: true, slug, broadcaster_user_id: id || null, state: st });
});

/* ===== start ===== */
await loadTokensOnBoot();

app.listen(PORT, () => {
  console.log(`auth+bot app listening on :${PORT}`);
  console.log(`Using OAuth prefixes: /auth and ${KICK_OAUTH_PREFIX}`);
  setInterval(pollingTick, pollMs);
  pollingTick();
});
