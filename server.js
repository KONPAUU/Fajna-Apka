import "dotenv/config";
import express from "express";
import bodyParser from "body-parser";
import axios from "axios";
import { io } from "socket.io-client";
import crypto from "crypto";

/* ================== ENV ================== */
const {
  PORT = 3100,

  // Slugi kanałów (CSV, małe litery)
  ALLOWED_SLUGS = "",

  // (opcjonalnie) login Twojego bota, żeby nie liczyć jego wiadomości
  BOT_USERNAME = "",

  // Ile identycznych komend pod rząd, by zareagować
  ECHO_THRESHOLD = "5",

  // Cooldown na komendę (sekundy)
  ECHO_COOLDOWN_SECONDS = "120",

  // Komendy do zignorowania (pełna treść, lowercase, CSV)
  IGNORE_EXACT = "!points",

  // ===== OAuth Kick =====
  KICK_CLIENT_ID = "",
  KICK_CLIENT_SECRET = "",
  KICK_REDIRECT_URI = "",

  // (opcjonalnie) override chatroom_id jeśli API nie wykryje
  // np. "rybsonlol:2968509,drugi:12345"
  CHATROOM_ID_OVERRIDES = "",

  // logowanie: info | silent
  LOG_LEVEL = "info"
} = process.env;

const allowedSlugs = ALLOWED_SLUGS.split(",").map(s => s.trim().toLowerCase()).filter(Boolean);
const ignoreExact = new Set(
  (IGNORE_EXACT || "")
    .toLowerCase()
    .split(",")
    .map(s => s.trim())
    .filter(Boolean)
);
const echoThreshold = Math.max(2, Number(ECHO_THRESHOLD) || 5);
const echoCooldownMs = Math.max(0, Number(ECHO_COOLDOWN_SECONDS) || 120) * 1000;

const UA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36";
const JSON_HEADERS = { "User-Agent": UA, "Accept": "application/json, text/plain, */*", "Referer": "https://kick.com/" };
const HTML_HEADERS = { "User-Agent": UA, "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "Referer": "https://kick.com/" };

const log = (...a) => { if (LOG_LEVEL !== "silent") console.log(...a); };

/* ================== Tokeny (pamięć procesu) ================== */
let TOKENS = {
  access_token: process.env.KICK_ACCESS_TOKEN || "",
  refresh_token: process.env.KICK_REFRESH_TOKEN || "",
  expires_at: 0
};

function setTokens(t) {
  if (t?.access_token) TOKENS.access_token = t.access_token;
  if (t?.refresh_token) TOKENS.refresh_token = t.refresh_token;
  if (t?.expires_in) TOKENS.expires_at = Date.now() + t.expires_in * 1000 - 10_000;
}

async function ensureToken() {
  if (TOKENS.access_token && Date.now() < TOKENS.expires_at) return TOKENS.access_token;
  if (!TOKENS.refresh_token) throw new Error("Brak refresh_token – uruchom /auth/start i dokończ logowanie.");
  const url = "https://id.kick.com/oauth2/token";
  const params = new URLSearchParams({
    grant_type: "refresh_token",
    refresh_token: TOKENS.refresh_token,
    client_id: KICK_CLIENT_ID,
    client_secret: KICK_CLIENT_SECRET,
    redirect_uri: KICK_REDIRECT_URI
  });
  const { data } = await axios.post(url, params, { headers: { "Content-Type": "application/x-www-form-urlencoded" }, timeout: 15000 });
  setTokens(data);
  return TOKENS.access_token;
}

/* ================== Utils ================== */
function normalizeRaw(s) {
  return String(s || "").trim().toLowerCase();
}
function isCommand(s) {
  return String(s || "").trim().startsWith("!");
}

/* ================== Kick API helpers ================== */
const chatroomOverrideMap = String(CHATROOM_ID_OVERRIDES || "")
  .split(",")
  .map(s => s.trim())
  .filter(Boolean)
  .reduce((acc, pair) => {
    const [slug, id] = pair.split(":").map(x => (x || "").trim());
    if (slug && /^\d+$/.test(id)) acc[slug.toLowerCase()] = Number(id);
    return acc;
  }, {});

async function getChannelMeta(slug) {
  // Zwraca { chatroom_id, broadcaster_user_id }
  // 1) v2/channels
  try {
    const { data } = await axios.get(`https://kick.com/api/v2/channels/${encodeURIComponent(slug)}`, {
      timeout: 12000, headers: JSON_HEADERS
    });
    const chatroom_id = data?.chatroom?.id ?? data?.data?.chatroom?.id ?? null;
    const broadcaster_user_id =
      data?.id ?? data?.user_id ?? data?.user?.id ?? data?.data?.id ?? null;
    if (chatroom_id && broadcaster_user_id) return { chatroom_id, broadcaster_user_id };
  } catch {}

  // 2) v2/chatroom + ponowny channels
  try {
    const { data } = await axios.get(`https://kick.com/api/v2/channels/${encodeURIComponent(slug)}/chatroom`, {
      timeout: 12000, headers: JSON_HEADERS
    });
    const chatroom_id = data?.id ?? null;
    const d2 = await axios.get(`https://kick.com/api/v2/channels/${encodeURIComponent(slug)}`, {
      timeout: 12000, headers: JSON_HEADERS
    }).then(r => r.data).catch(() => null);
    const broadcaster_user_id =
      d2?.id ?? d2?.user_id ?? d2?.user?.id ?? d2?.data?.id ?? null;
    if (chatroom_id && broadcaster_user_id) return { chatroom_id, broadcaster_user_id };
  } catch {}

  // 3) HTML fallback
  try {
    const { data: html } = await axios.get(`https://kick.com/${encodeURIComponent(slug)}`, {
      timeout: 12000, headers: HTML_HEADERS, responseType: "text"
    });
    let m = /"chatroom"\s*:\s*\{\s*"id"\s*:\s*(\d+)/.exec(html) || /"chatroom_id"\s*:\s*(\d+)/.exec(html);
    const chatroom_id = m ? Number(m[1]) : null;
    let u = /"user_id"\s*:\s*(\d+)/.exec(html) || /"id"\s*:\s*(\d+)/.exec(html);
    const broadcaster_user_id = u ? Number(u[1]) : null;
    if (chatroom_id && broadcaster_user_id) return { chatroom_id, broadcaster_user_id };
  } catch {}

  // 4) Ręczny override
  if (chatroomOverrideMap[slug]) {
    try {
      const { data } = await axios.get(`https://kick.com/api/v2/channels/${encodeURIComponent(slug)}`, {
        timeout: 12000, headers: JSON_HEADERS
      });
      const broadcaster_user_id =
        data?.id ?? data?.user_id ?? data?.user?.id ?? data?.data?.id ?? null;
      if (broadcaster_user_id) return { chatroom_id: chatroomOverrideMap[slug], broadcaster_user_id };
    } catch {}
  }
  return { chatroom_id: null, broadcaster_user_id: null };
}

async function sendChatMessage(broadcaster_user_id, content) {
  const token = await ensureToken();
  const url = "https://kick.com/api/v2/chats/send";
  await axios.post(url, { broadcaster_user_id, content }, {
    headers: { Authorization: `Bearer ${token}` },
    timeout: 15000
  });
}

/* ================== Echo-detekcja ================== */
const wsBySlug = new Map();
const metaBySlug = new Map();                // slug -> { chatroom_id, broadcaster_user_id }
const lastCmdsBySlug = new Map();            // slug -> array of {raw, norm, user, t}
const lastEchoAt = new Map();                // key `${slug}|${cmdNorm}` -> ts

function pushCmd(slug, item, limit = 12) {
  const arr = lastCmdsBySlug.get(slug) || [];
  arr.push(item);
  if (arr.length > limit) arr.splice(0, arr.length - limit);
  lastCmdsBySlug.set(slug, arr);
}

function shouldEcho(slug) {
  const arr = lastCmdsBySlug.get(slug) || [];
  if (arr.length < echoThreshold) return null;
  const tail = arr.slice(-echoThreshold);
  const firstNorm = tail[0].norm;
  if (!tail.every(x => x.norm === firstNorm)) return null;

  const rawToEcho = tail[tail.length - 1].raw;
  const cmdNorm = firstNorm;
  const key = `${slug}|${cmdNorm}`;
  const last = lastEchoAt.get(key) || 0;
  if (Date.now() - last < echoCooldownMs) return null;
  if (ignoreExact.has(cmdNorm)) return null;
  return { rawToEcho, key };
}

/* ================== WS nasłuch ================== */
async function ensureWs(slug) {
  if (wsBySlug.has(slug)) return;

  const meta = await getChannelMeta(slug);
  if (!meta.chatroom_id || !meta.broadcaster_user_id) {
    log(`[warn] Brak meta dla ${slug}. Ustaw CHATROOM_ID_OVERRIDES albo sprawdź slug.`);
    setTimeout(() => ensureWs(slug), 60000);
    return;
  }
  metaBySlug.set(slug, meta);

  const socket = io("https://chat.kick.com", {
    transports: ["websocket"],
    reconnection: true,
    reconnectionDelayMax: 15000,
    forceNew: true
  });

  socket.on("connect", () => {
    try { socket.emit("SUBSCRIBE", { room: `chatrooms:${meta.chatroom_id}` }); } catch {}
    log(`WS connected for ${slug} (chatrooms:${meta.chatroom_id})`);
  });

  const handler = (payload) => {
    // wyciąganie nicka i treści
    const username =
      payload?.username || payload?.user?.username || payload?.sender?.username ||
      payload?.author?.username || payload?.message?.sender?.username || "";

    if (BOT_USERNAME && username && username.toLowerCase() === BOT_USERNAME.toLowerCase()) {
      return;
    }

    const raw =
      String(payload?.content ?? payload?.message?.content ?? "").trim();
    if (!raw) return;
    if (!isCommand(raw)) return;

    const norm = normalizeRaw(raw);
    pushCmd(slug, { raw, norm, user: username || "unknown", t: Date.now() });

    const decision = shouldEcho(slug);
    if (decision) {
      const { rawToEcho, key } = decision;
      const meta = metaBySlug.get(slug);
      if (!meta?.broadcaster_user_id) return;
      sendChatMessage(meta.broadcaster_user_id, rawToEcho)
        .then(() => {
          lastEchoAt.set(key, Date.now());
          log(`[ECHO] ${slug} → "${rawToEcho}"`);
        })
        .catch(e => {
          const st = e?.response?.status;
          log("Echo send error", st || "", e?.response?.data || e.message);
        });
    }
  };

  socket.on("message", handler);
  socket.on("chat_message", handler);
  socket.on("disconnect", () => log(`WS disconnected for ${slug}`));
  wsBySlug.set(slug, socket);
}

/* ================== HTTP ================== */
const app = express();
app.use(bodyParser.json());

app.get("/health", (_req, res) => res.send("ok"));

app.get("/stats", (req, res) => {
  const out = {};
  for (const slug of allowedSlugs) {
    const meta = metaBySlug.get(slug) || {};
    const arr = (lastCmdsBySlug.get(slug) || []).slice(-10);
    out[slug] = {
      chatroom_id: meta.chatroom_id || null,
      broadcaster_user_id: meta.broadcaster_user_id || null,
      last_commands: arr
    };
  }
  res.json(out);
});

/* ===== OAuth ===== */
const pkceByState = new Map();
function sha256(buffer) { return crypto.createHash("sha256").update(buffer).digest(); }
function base64urlencode(b) { return b.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); }
function genPKCE() {
  const code_verifier = base64urlencode(crypto.randomBytes(32));
  const code_challenge = base64urlencode(sha256(code_verifier));
  return { code_verifier, code_challenge };
}

app.get("/auth/start", (_req, res) => {
  if (!KICK_CLIENT_ID || !KICK_REDIRECT_URI) {
    return res.status(500).send("Missing OAuth envs");
  }
  const { code_verifier, code_challenge } = genPKCE();
  const state = crypto.randomBytes(8).toString("hex");
  pkceByState.set(state, code_verifier);

  const scope = ["user:read", "chat:write"].join(" ");

  const url = new URL("https://id.kick.com/oauth2/authorize");
  url.searchParams.set("response_type", "code");
  url.searchParams.set("client_id", KICK_CLIENT_ID);
  url.searchParams.set("redirect_uri", KICK_REDIRECT_URI);
  url.searchParams.set("scope", scope);
  url.searchParams.set("state", state);
  url.searchParams.set("code_challenge", code_challenge);
  url.searchParams.set("code_challenge_method", "S256");

  res.redirect(url.toString());
});

// pomocniczo – zobacz dokładnie jaki URL generuje (diagnostyka 404)
app.get("/auth/url", (_req, res) => {
  if (!KICK_CLIENT_ID || !KICK_REDIRECT_URI) {
    return res.status(500).send("Brak KICK_CLIENT_ID/KICK_REDIRECT_URI");
  }
  const { code_verifier, code_challenge } = genPKCE();
  const state = "dbg" + Date.now();
  pkceByState.set(state, code_verifier);

  const scope = ["user:read", "chat:write"].join(" ");
  const url = new URL("https://id.kick.com/oauth2/authorize");
  url.searchParams.set("response_type", "code");
  url.searchParams.set("client_id", KICK_CLIENT_ID);
  url.searchParams.set("redirect_uri", KICK_REDIRECT_URI);
  url.searchParams.set("scope", scope);
  url.searchParams.set("state", state);
  url.searchParams.set("code_challenge", code_challenge);
  url.searchParams.set("code_challenge_method", "S256");

  res.type("text/plain").send(url.toString());
});

app.get("/callback", async (req, res) => {
  try {
    const { code, state } = req.query;
    if (!code || !state) return res.status(400).send("Brak code/state (uruchom /auth/start).");
    const code_verifier = pkceByState.get(String(state));
    if (!code_verifier) return res.status(400).send("Brak code_verifier (wygaśnięty state, uruchom /auth/start ponownie).");

    const tokenUrl = "https://id.kick.com/oauth2/token";
    const params = new URLSearchParams({
      grant_type: "authorization_code",
      code: String(code),
      code_verifier,
      client_id: KICK_CLIENT_ID,
      client_secret: KICK_CLIENT_SECRET,
      redirect_uri: KICK_REDIRECT_URI
    });
    const { data } = await axios.post(tokenUrl, params, {
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      timeout: 15000
    });
    setTokens(data);
    return res.send("Tokeny zapisane ✔ – możesz zamknąć okno.");
  } catch (e) {
    return res.status(400).send(`Błąd callback: ${e.message}`);
  }
});

/* ================== START ================== */
const appStart = async () => {
  const srv = app.listen(PORT, () => {
    log(`kick-echo-cmd listening on :${PORT}`);
  });

  if (!allowedSlugs.length) {
    log("Ustaw ALLOWED_SLUGS w .env (np. rybsonlol,drugi)");
    return;
  }
  for (const slug of allowedSlugs) {
    try { await ensureWs(slug); } catch {}
  }
};
appStart();
