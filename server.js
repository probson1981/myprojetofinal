import express from "express";
import mqtt from "mqtt";
import crypto from "crypto";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

/**
 * =========================
 * CONFIG (Render -> Environment Variables)
 * =========================
 * MQTT_URL     = mqtt://broker.hivemq.com:1883  (funciona com seu Pico atual)
 * MQTT_USER    = (opcional)
 * MQTT_PASS    = (opcional)
 *
 * TOPIC_PREFIX = embarcatech   (deve bater com seu firmware)
 *
 * DASH_USER    = admin
 * DASH_PASS    = uma_senha_forte
 * AUTH_SECRET  = uma string longa aleatória (>= 32 chars)
 */

const MQTT_URL = process.env.MQTT_URL || "mqtt://broker.hivemq.com:1883";
const MQTT_USER = process.env.MQTT_USER || "";
const MQTT_PASS = process.env.MQTT_PASS || "";
const TOPIC_PREFIX = process.env.TOPIC_PREFIX || "embarcatech";

const DASH_USER = process.env.DASH_USER || "admin";
const DASH_PASS = process.env.DASH_PASS || "admin123";
const AUTH_SECRET = process.env.AUTH_SECRET || "CHANGE_ME_TO_A_LONG_RANDOM_SECRET_32+";

const COOKIE_NAME = "auth";

/**
 * =========================
 * AUTH (cookie assinado)
 * =========================
 */
function b64url(str) {
  return Buffer.from(str, "utf8").toString("base64url");
}

function signToken(payloadObj) {
  const payload = b64url(JSON.stringify(payloadObj));
  const sig = crypto.createHmac("sha256", AUTH_SECRET).update(payload).digest("base64url");
  return `${payload}.${sig}`;
}

function verifyToken(token) {
  if (!token || typeof token !== "string") return null;
  const parts = token.split(".");
  if (parts.length !== 2) return null;

  const [payload, sig] = parts;
  const expected = crypto.createHmac("sha256", AUTH_SECRET).update(payload).digest("base64url");

  const a = Buffer.from(sig);
  const b = Buffer.from(expected);
  if (a.length !== b.length) return null;
  if (!crypto.timingSafeEqual(a, b)) return null;

  try {
    const obj = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
    if (!obj.exp || Date.now() > obj.exp) return null;
    return obj;
  } catch {
    return null;
  }
}

function getCookie(req, name) {
  const raw = req.headers.cookie || "";
  const parts = raw.split(";").map((s) => s.trim());
  for (const p of parts) {
    const [k, ...rest] = p.split("=");
    if (k === name) return decodeURIComponent(rest.join("=") || "");
  }
  return "";
}

function requireAuth(req, res, next) {
  const token = getCookie(req, COOKIE_NAME);
  const data = verifyToken(token);
  if (!data) {
    if (req.path.startsWith("/api/")) return res.status(401).json({ error: "unauthorized" });
    return res.redirect("/login");
  }
  req.user = data;
  next();
}

/**
 * =========================
 * Páginas: login / logout
 * =========================
 */
app.get("/login", (req, res) => {
  const hasErr = !!req.query.e;
  res.type("html").send(`<!doctype html>
<html lang="pt-BR">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>Login</title>
  <style>
    body{font-family:system-ui,Segoe UI,Roboto,Arial; background:#f2f2f2; margin:0; min-height:100vh; display:flex; align-items:center; justify-content:center; padding:16px;}
    .box{background:#fff; border:1px solid #ddd; border-radius:12px; padding:18px; width:100%; max-width:360px; box-shadow:0 8px 24px rgba(0,0,0,.08);}
    h3{margin:0 0 10px;}
    input,button{width:100%; padding:10px 12px; border-radius:10px; border:1px solid #ccc; font-size:1rem;}
    button{background:#4caf50; color:#fff; border:none; font-weight:700; cursor:pointer;}
    .hint{font-size:.85rem; color:#666; margin-top:10px;}
    .err{color:#c62828; font-size:.9rem; margin:10px 0;}
  </style>
</head>
<body>
  <form class="box" method="post" action="/login">
    <h3>Dashboard — Login</h3>
    ${hasErr ? `<div class="err">Usuário/senha inválidos.</div>` : ``}
    <input name="user" placeholder="Usuário" autocomplete="username" required />
    <div style="height:10px"></div>
    <input name="pass" type="password" placeholder="Senha" autocomplete="current-password" required />
    <div style="height:12px"></div>
    <button type="submit">Entrar</button>
    <div class="hint">O navegador não acessa MQTT direto. Tudo passa pelo servidor.</div>
  </form>
</body>
</html>`);
});

app.post("/login", (req, res) => {
  const user = String(req.body.user || "");
  const pass = String(req.body.pass || "");

  if (user === DASH_USER && pass === DASH_PASS) {
    const token = signToken({
      u: user,
      exp: Date.now() + 12 * 60 * 60 * 1000 // 12 horas
    });

    // cookie seguro (Render usa HTTPS no domínio onrender.com)
    res.setHeader(
      "Set-Cookie",
      `${COOKIE_NAME}=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Lax; Secure; Max-Age=${12 * 60 * 60}`
    );
    return res.redirect("/");
  }
  return res.redirect("/login?e=1");
});

app.get("/logout", (req, res) => {
  res.setHeader(
    "Set-Cookie",
    `${COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Lax; Secure; Max-Age=0`
  );
  res.redirect("/login");
});

/**
 * =========================
 * Health check (Render)
 * =========================
 */
app.get("/health", (req, res) => res.status(200).send("ok"));

/**
 * =========================
 * Static (dashboard) protegido
 * =========================
 */
app.use("/", requireAuth, express.static(path.join(__dirname, "public")));

/**
 * =========================
 * MQTT Bridge
 * Espera tópicos:
 *   TOPIC_PREFIX/<device_id>/telemetry  (seu Pico publica aqui)
 *   TOPIC_PREFIX/<device_id>/cmd        (servidor publica comando aqui)
 * =========================
 */
const latestByDevice = new Map();     // device -> {ts, topic, raw, parsed}
const sseByDevice = new Map();        // device -> Set(res)

function getDeviceFromTopic(topic) {
  const parts = topic.split("/");
  if (parts.length < 3) return null;
  if (parts[0] !== TOPIC_PREFIX) return null;
  return parts[1];
}

function sseSend(res, event, obj) {
  res.write(`event: ${event}\n`);
  res.write(`data: ${JSON.stringify(obj)}\n\n`);
}

const mqttOpts = {
  keepalive: 30,
  reconnectPeriod: 2000,
  connectTimeout: 20000,
  protocolVersion: 4
};
if (MQTT_USER) mqttOpts.username = MQTT_USER;
if (MQTT_PASS) mqttOpts.password = MQTT_PASS;

const mqttClient = mqtt.connect(MQTT_URL, mqttOpts);

mqttClient.on("connect", () => {
  console.log("[MQTT] connected:", MQTT_URL);

  const subTopic = `${TOPIC_PREFIX}/+/telemetry`;
  mqttClient.subscribe(subTopic, { qos: 1 }, (err) => {
    if (err) console.error("[MQTT] subscribe error:", err);
    else console.log("[MQTT] subscribed:", subTopic);
  });
});

mqttClient.on("reconnect", () => console.log("[MQTT] reconnecting..."));
mqttClient.on("close", () => console.log("[MQTT] closed"));
mqttClient.on("error", (e) => console.error("[MQTT] error:", e?.message || e));

mqttClient.on("message", (topic, payloadBuf) => {
  const device = getDeviceFromTopic(topic);
  if (!device) return;

  const raw = payloadBuf.toString("utf8");
  let parsed = null;
  try { parsed = JSON.parse(raw); } catch {}

  const record = { ts: Date.now(), topic, raw, parsed };
  latestByDevice.set(device, record);

  const clients = sseByDevice.get(device);
  if (clients) {
    for (const res of clients) sseSend(res, "telemetry", record);
  }
});

/**
 * =========================
 * API (protegida)
 * =========================
 */
app.get("/api/devices", requireAuth, (req, res) => {
  res.json({ devices: Array.from(latestByDevice.keys()).sort() });
});

app.get("/api/state", requireAuth, (req, res) => {
  res.json({
    mqtt: { url: MQTT_URL, connected: !!mqttClient.connected },
    prefix: TOPIC_PREFIX,
    devices: Array.from(latestByDevice.keys())
  });
});

app.get("/api/stream/:device", requireAuth, (req, res) => {
  const device = String(req.params.device || "").trim();
  if (!device) return res.status(400).json({ error: "device required" });

  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");

  const last = latestByDevice.get(device) || null;
  sseSend(res, "hello", { device, hasLast: !!last, last });

  if (!sseByDevice.has(device)) sseByDevice.set(device, new Set());
  sseByDevice.get(device).add(res);

  req.on("close", () => {
    const set = sseByDevice.get(device);
    if (set) {
      set.delete(res);
      if (set.size === 0) sseByDevice.delete(device);
    }
  });
});

app.post("/api/device/:device/cmd", requireAuth, (req, res) => {
  const device = String(req.params.device || "").trim();
  if (!device) return res.status(400).json({ error: "device required" });

  const topic = `${TOPIC_PREFIX}/${device}/cmd`;
  const payload = JSON.stringify(req.body || {});

  mqttClient.publish(topic, payload, { qos: 1, retain: false }, (err) => {
    if (err) return res.status(500).json({ ok: false, error: "publish_failed" });
    res.json({ ok: true, topic });
  });
});

/**
 * =========================
 * Listen (Render usa PORT)
 * =========================
 */
const PORT = process.env.PORT || 3000;
app.listen(PORT, "0.0.0.0", () => {
  console.log("[HTTP] listening on", PORT);
  console.log("[CFG] TOPIC_PREFIX =", TOPIC_PREFIX);
});
