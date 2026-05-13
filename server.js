const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { URL } = require("url");

const ROOT = __dirname;
const DATA_DIR = path.join(ROOT, "data");
const AUTH_FILE = path.join(DATA_DIR, "admin-auth.json");
const EVENTS_FILE = path.join(DATA_DIR, "usage-events.jsonl");
const COUNTS_FILE = path.join(DATA_DIR, "usage-counts.json");
const PORT = Number(process.env.PORT || 4173);
const HOST = process.env.HOST || "127.0.0.1";
const SESSION_TTL_MS = 1000 * 60 * 60 * 8;
const COOKIE_NAME = "lexa_admin_session";
const PUBLIC_INDEX = path.join(ROOT, "index.html");

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".webmanifest": "application/manifest+json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".ico": "image/x-icon",
  ".txt": "text/plain; charset=utf-8"
};

const ALLOWED_REDIRECT_HOSTS = new Set([
  "store.steampowered.com",
  "steamdb.info",
  "store.epicgames.com",
  "www.gog.com",
  "gog.com",
  "itch.io",
  "isthereanydeal.com",
  "www.pcgamingwiki.com",
  "pcgamingwiki.com",
  "www.protondb.com",
  "protondb.com"
]);

fs.mkdirSync(DATA_DIR, { recursive: true });

function json(res, code, payload) {
  const body = JSON.stringify(payload);
  res.writeHead(code, {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": Buffer.byteLength(body),
    "Cache-Control": "no-store",
    ...securityHeaders()
  });
  res.end(body);
}

function securityHeaders(extra = {}) {
  return {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    ...extra
  };
}

function send(res, code, body, type = "text/plain; charset=utf-8", headers = {}) {
  res.writeHead(code, {
    "Content-Type": type,
    "Content-Length": Buffer.byteLength(body),
    ...securityHeaders(headers)
  });
  res.end(body);
}

function notFound(res) { send(res, 404, "404 - Page introuvable"); }
function badRequest(res, msg = "Requête invalide") { send(res, 400, msg); }

function safePath(urlPath) {
  const decoded = decodeURIComponent(urlPath.split("?")[0]);
  const normalized = path.normalize(decoded).replace(/^(\.\.[/\\])+/, "");
  const file = path.join(ROOT, normalized);
  if (!file.startsWith(ROOT)) return null;
  return file;
}

function serveFile(res, file, cache = true) {
  if (!file || !fs.existsSync(file) || !fs.statSync(file).isFile()) return notFound(res);
  const ext = path.extname(file).toLowerCase();
  const headers = cache ? { "Cache-Control": "public, max-age=900" } : { "Cache-Control": "no-store" };
  const stream = fs.createReadStream(file);
  res.writeHead(200, { "Content-Type": MIME[ext] || "application/octet-stream", ...securityHeaders(headers) });
  stream.pipe(res);
}

function readBody(req, limit = 64 * 1024) {
  return new Promise((resolve, reject) => {
    let body = "";
    req.on("data", chunk => {
      body += chunk;
      if (body.length > limit) {
        reject(new Error("Payload too large"));
        req.destroy();
      }
    });
    req.on("end", () => resolve(body));
    req.on("error", reject);
  });
}

function parseCookies(req) {
  const raw = req.headers.cookie || "";
  return Object.fromEntries(raw.split(";").map(part => part.trim()).filter(Boolean).map(part => {
    const index = part.indexOf("=");
    return [part.slice(0, index), decodeURIComponent(part.slice(index + 1))];
  }));
}

function secret() {
  const fromEnv = process.env.LEXA_SESSION_SECRET;
  if (fromEnv && fromEnv.length >= 32) return fromEnv;
  const secretFile = path.join(DATA_DIR, "session-secret.txt");
  if (!fs.existsSync(secretFile)) fs.writeFileSync(secretFile, crypto.randomBytes(48).toString("hex"));
  return fs.readFileSync(secretFile, "utf8").trim();
}

function sign(value) {
  return crypto.createHmac("sha256", secret()).update(value).digest("base64url");
}

function makeSession(username) {
  const payload = JSON.stringify({ username, exp: Date.now() + SESSION_TTL_MS, nonce: crypto.randomBytes(12).toString("hex") });
  const data = Buffer.from(payload).toString("base64url");
  return data + "." + sign(data);
}

function verifySession(token) {
  if (!token || !token.includes(".")) return null;
  const [data, mac] = token.split(".");
  if (!crypto.timingSafeEqual(Buffer.from(mac), Buffer.from(sign(data)))) return null;
  const payload = JSON.parse(Buffer.from(data, "base64url").toString("utf8"));
  if (!payload.exp || payload.exp < Date.now()) return null;
  return payload;
}

function isAuthed(req) {
  try { return verifySession(parseCookies(req)[COOKIE_NAME]); }
  catch (_) { return null; }
}

function setSessionCookie(res, username, secure) {
  const token = makeSession(username);
  const cookie = COOKIE_NAME + "=" + encodeURIComponent(token) + "; Path=/; HttpOnly; SameSite=Strict; Max-Age=" + Math.floor(SESSION_TTL_MS / 1000) + (secure ? "; Secure" : "");
  res.setHeader("Set-Cookie", cookie);
}

function clearSessionCookie(res) {
  res.setHeader("Set-Cookie", COOKIE_NAME + "=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0");
}

function hashPassword(password, salt = crypto.randomBytes(16).toString("hex")) {
  const hash = crypto.scryptSync(password, salt, 64).toString("hex");
  return { salt, hash };
}

function loadAuth() {
  if (!fs.existsSync(AUTH_FILE)) {
    const envPassword = process.env.LEXA_ADMIN_PASSWORD;
    if (!envPassword || envPassword.length < 10) {
      throw new Error("Admin non configure. Lance: npm run admin:setup");
    }
    const record = { username: process.env.LEXA_ADMIN_USER || "admin", ...hashPassword(envPassword), createdAt: new Date().toISOString() };
    fs.writeFileSync(AUTH_FILE, JSON.stringify(record, null, 2));
  }
  return JSON.parse(fs.readFileSync(AUTH_FILE, "utf8"));
}

function saveAuth(username, password) {
  fs.writeFileSync(AUTH_FILE, JSON.stringify({ username, ...hashPassword(password), updatedAt: new Date().toISOString() }, null, 2));
}

function verifyPassword(password, record) {
  const attempted = hashPassword(password, record.salt).hash;
  return crypto.timingSafeEqual(Buffer.from(attempted, "hex"), Buffer.from(record.hash, "hex"));
}

const attempts = new Map();
function canTry(ip) {
  const now = Date.now();
  const item = attempts.get(ip) || { count: 0, until: 0 };
  if (item.until > now) return false;
  return true;
}
function noteFailure(ip) {
  const item = attempts.get(ip) || { count: 0, until: 0 };
  item.count += 1;
  if (item.count >= 5) {
    item.until = Date.now() + Math.min(15 * 60 * 1000, item.count * 30 * 1000);
  }
  attempts.set(ip, item);
}
function clearFailures(ip) { attempts.delete(ip); }

function loadCounts() {
  try { return JSON.parse(fs.readFileSync(COUNTS_FILE, "utf8")); }
  catch (_) { return { total: 0, byProvider: {}, byApp: {}, byService: {} }; }
}
function saveCounts(counts) { fs.writeFileSync(COUNTS_FILE, JSON.stringify(counts, null, 2)); }
function recordEvent(type, payload, req) {
  const event = {
    type,
    at: new Date().toISOString(),
    ip: (req.headers["x-forwarded-for"] || req.socket.remoteAddress || "").split(",")[0],
    ua: req.headers["user-agent"] || "",
    ...payload
  };
  fs.appendFileSync(EVENTS_FILE, JSON.stringify(event) + "\n");
  const counts = loadCounts();
  counts.total = (counts.total || 0) + 1;
  if (event.provider) counts.byProvider[event.provider] = (counts.byProvider[event.provider] || 0) + 1;
  if (event.appid) counts.byApp[event.appid] = (counts.byApp[event.appid] || 0) + 1;
  if (event.service) counts.byService[event.service] = (counts.byService[event.service] || 0) + 1;
  saveCounts(counts);
}

function redirect(res, location, code = 302) {
  res.writeHead(code, { Location: location, ...securityHeaders({ "Cache-Control": "no-store" }) });
  res.end();
}

async function handleApi(req, res, url) {
  if (url.pathname === "/api/admin/session" && req.method === "GET") {
    const session = isAuthed(req);
    return json(res, session ? 200 : 401, { authenticated: Boolean(session), user: session?.username || null });
  }

  if (url.pathname === "/api/admin/login" && req.method === "POST") {
    const ip = req.socket.remoteAddress || "local";
    if (!canTry(ip)) return json(res, 429, { ok: false, error: "Trop de tentatives. Attends quelques minutes." });
    const body = JSON.parse(await readBody(req) || "{}");
    const record = loadAuth();
    if (String(body.username || "") === record.username && verifyPassword(String(body.password || ""), record)) {
      clearFailures(ip);
      setSessionCookie(res, record.username, req.headers["x-forwarded-proto"] === "https");
      recordEvent("admin-login", { service: "admin" }, req);
      return json(res, 200, { ok: true });
    }
    noteFailure(ip);
    recordEvent("admin-login-failed", { service: "admin" }, req);
    return json(res, 401, { ok: false, error: "Identifiants incorrects." });
  }

  if (url.pathname === "/api/admin/logout" && req.method === "POST") {
    clearSessionCookie(res);
    return json(res, 200, { ok: true });
  }

  if (!isAuthed(req)) return json(res, 401, { ok: false, error: "Admin requis." });

  if (url.pathname === "/api/admin/change-password" && req.method === "POST") {
    const body = JSON.parse(await readBody(req) || "{}");
    const username = String(body.username || "").trim();
    const password = String(body.password || "");
    if (username.length < 3 || password.length < 10) return json(res, 400, { ok: false, error: "Identifiant min. 3 caractères, mot de passe min. 10 caractères." });
    saveAuth(username, password);
    recordEvent("admin-credentials-updated", { service: "admin" }, req);
    return json(res, 200, { ok: true });
  }

  if (url.pathname === "/api/admin/usage" && req.method === "GET") {
    return json(res, 200, loadCounts());
  }

  return json(res, 404, { ok: false, error: "API introuvable." });
}

function handleGo(req, res, url) {
  const target = url.searchParams.get("url");
  const provider = String(url.searchParams.get("provider") || "unknown").slice(0, 60);
  const appid = String(url.searchParams.get("appid") || "").slice(0, 20);
  if (!target) return badRequest(res, "URL manquante");
  let parsed;
  try { parsed = new URL(target); }
  catch (_) { return badRequest(res, "URL invalide"); }
  if (parsed.protocol !== "https:" || !ALLOWED_REDIRECT_HOSTS.has(parsed.hostname)) return badRequest(res, "Source non autorisée");
  recordEvent("download-click", { provider, appid, target: parsed.origin + parsed.pathname }, req);
  redirect(res, parsed.toString(), 302);
}

function handleAdmin(req, res, url) {
  const session = isAuthed(req);
  if (url.pathname === "/admin-login.html") return serveFile(res, path.join(ROOT, "admin-login.html"), false);
  if (!session) return serveFile(res, path.join(ROOT, "admin-login.html"), false);
  if (url.pathname === "/admin" || url.pathname === "/admin/") return serveFile(res, path.join(ROOT, "admin", "index.html"), false);
  const file = safePath(url.pathname.slice(1));
  return serveFile(res, file, false);
}

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, "http://" + req.headers.host);
    if (url.pathname.startsWith("/api/")) return await handleApi(req, res, url);
    if (url.pathname === "/go") return handleGo(req, res, url);
    if (url.pathname === "/admin" || url.pathname.startsWith("/admin/") || url.pathname === "/admin-login.html") return handleAdmin(req, res, url);
    if (url.pathname === "/admin.html") return redirect(res, "/admin", 302);
    const requested = url.pathname === "/" ? PUBLIC_INDEX : safePath(url.pathname.slice(1));
    return serveFile(res, requested, true);
  } catch (error) {
    console.error(error);
    return json(res, 500, { ok: false, error: "Erreur serveur." });
  }
});

try {
  loadAuth();
} catch (error) {
  console.error(error.message);
  console.error("Astuce: lance start-lexa-server.ps1 ou npm run admin:setup avant npm start.");
  process.exit(1);
}

server.listen(PORT, HOST, () => {
  console.log("Lexa server running on http://" + HOST + ":" + PORT);
  console.log("Admin: http://" + HOST + ":" + PORT + "/admin");
});
