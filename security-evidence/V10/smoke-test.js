const path = require("path");
// V10 post-upgrade smoke test: starts the real server.js with the upgraded dependencies and checks
// server startup, authentication, uploads (cloudinary 2.x + the V8 checks) and email (nodemailer 9.x).
// Usage (from repo root, after `npm install` in server/): node security-evidence/V10/smoke-test.js
// Writes smoke-test-results.json next to this file.
// Everything runs locally: in-memory MongoDB, a local stand-in for the Cloudinary upload API
// (via CLOUDINARY_URL upload_prefix) and a local stand-in SMTP server. No real account is contacted.
const S = path.resolve(__dirname, "../../server");
const r = (p) => require(`${S}/${p}`);
const { MongoMemoryServer } = r("node_modules/mongodb-memory-server");
const { spawn } = require("child_process");
const http = require("http");
const net = require("net");
const fs = require("fs");

const results = [];
const check = (name, pass, detail) => {
  results.push({ check: name, pass: !!pass, detail });
  console.log(`${pass ? "PASS" : "FAIL"}  ${name}${detail ? "  — " + JSON.stringify(detail) : ""}`);
};

// ── Local Cloudinary upload API stand-in ──────────────────────────────────────
const cloudinaryHits = [];
const cloudinaryStub = http.createServer((req, res) => {
  let size = 0;
  req.on("data", (c) => (size += c.length));
  req.on("end", () => {
    cloudinaryHits.push({ method: req.method, url: req.url, bytes: size });
    const folder = req.url.includes("/image/") ? "careline360/avatars" : "careline360/documents";
    res.setHeader("content-type", "application/json");
    res.end(JSON.stringify({
      public_id: `${folder}/smoke`, version: 1, format: "bin", resource_type: "image", bytes: size,
      url: `http://res.cloudinary.com/smoke/${folder}/smoke`,
      secure_url: `https://res.cloudinary.com/smoke/${folder}/smoke`,
    }));
  });
});

// ── Local SMTP stand-in (enough of RFC 5321 for nodemailer) ────────────────────
const smtpMessages = [];
const smtpStub = net.createServer((sock) => {
  let inData = false, data = "";
  sock.write("220 smoke ESMTP\r\n");
  sock.on("data", (buf) => {
    for (const line of buf.toString().split("\r\n")) {
      if (inData) {
        if (line === ".") { inData = false; smtpMessages.push(data); data = ""; sock.write("250 queued\r\n"); }
        else data += line + "\n";
        continue;
      }
      if (!line) continue;
      const cmd = line.slice(0, 4).toUpperCase();
      if (cmd === "EHLO") sock.write("250-smoke\r\n250 AUTH PLAIN LOGIN\r\n");
      else if (cmd === "AUTH") sock.write("235 ok\r\n");
      else if (cmd === "DATA") { inData = true; sock.write("354 go\r\n"); }
      else if (cmd === "QUIT") { sock.write("221 bye\r\n"); sock.end(); }
      else sock.write("250 ok\r\n");
    }
  });
});

const listen = (srv) => new Promise((ok) => srv.listen(0, "127.0.0.1", () => ok(srv.address().port)));

async function api(base, method, url, { token, json, form } = {}) {
  const headers = token ? { authorization: `Bearer ${token}` } : {};
  let body;
  if (json) { headers["content-type"] = "application/json"; body = JSON.stringify(json); }
  if (form) body = form;
  const res = await fetch(base + url, { method, headers, body });
  const text = await res.text();
  let parsed; try { parsed = JSON.parse(text); } catch { parsed = text; }
  return { status: res.status, body: parsed };
}

const file = (field, bytes, name, type) => {
  const fd = new FormData();
  fd.append(field, new Blob([bytes], { type }), name);
  return fd;
};

(async () => {
  const mongo = await MongoMemoryServer.create();
  const cPort = await listen(cloudinaryStub);
  const sPort = await listen(smtpStub);
  const probe = net.createServer(); const port = await listen(probe); probe.close();

  const env = {
    ...process.env,
    NODE_ENV: "development",
    PORT: String(port),
    MONGO_URI: mongo.getUri("careline360-smoke"),
    JWT_ACCESS_SECRET: "smoke-access-secret",
    JWT_REFRESH_SECRET: "smoke-refresh-secret",
    CLOUDINARY_URL: `cloudinary://smokekey:smokesecret@smoke?upload_prefix=http://127.0.0.1:${cPort}`,
    CLOUDINARY_CLOUD_NAME: "smoke",
    CLOUDINARY_API_KEY: "smokekey",
    CLOUDINARY_API_SECRET: "smokesecret",
    SMTP_HOST: "127.0.0.1",
    SMTP_PORT: String(sPort),
    SMTP_USER: "smoke@careline360.test",
    SMTP_PASS: "smoke",
    EMAIL_FROM: "smoke@careline360.test",
  };

  // 1. Server startup
  const server = spawn(process.execPath, ["server.js"], { cwd: S, env });
  let log = "";
  server.stdout.on("data", (d) => (log += d));
  server.stderr.on("data", (d) => (log += d));
  const started = await new Promise((ok) => {
    const t = setTimeout(() => ok(false), 30000);
    const iv = setInterval(() => {
      if (/running on port/.test(log) && /MongoDB Connected/.test(log)) { clearTimeout(t); clearInterval(iv); ok(true); }
      if (server.exitCode !== null) { clearTimeout(t); clearInterval(iv); ok(false); }
    }, 200);
  });
  check("server.js starts and connects to MongoDB", started, started ? undefined : log.slice(-500));
  const base = `http://127.0.0.1:${port}`;

  try {
    const root = await api(base, "GET", "/");
    check("GET / responds", root.status === 200, { status: root.status });

    // 2. Authentication
    const email = `smoke_${Date.now()}@careline360.test`;
    const password = "Smoke@12345";
    const reg = await api(base, "POST", "/api/auth/register", { json: { role: "patient", fullName: "Smoke Patient", identifier: email, password } });
    check("register patient", reg.status === 201, { status: reg.status });
    const login = await api(base, "POST", "/api/auth/login", { json: { identifier: email, password } });
    const token = login.body && login.body.accessToken;
    check("login returns access token", login.status === 200 && !!token, { status: login.status });
    const me = await api(base, "GET", "/api/auth/me", { token });
    check("authenticated /api/auth/me", me.status === 200, { status: me.status });
    const noAuth = await api(base, "GET", "/api/auth/me");
    check("unauthenticated /api/auth/me rejected", noAuth.status === 401, { status: noAuth.status });

    // 3. Uploads through cloudinary 2.x (V8 validation must still apply)
    const PDF = Buffer.from("%PDF-1.4\n%smoke\n");
    const PNG = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 0x0d, 0x49, 0x48, 0x44, 0x52]);

    let before = cloudinaryHits.length;
    const doc = await api(base, "POST", "/api/documents", { token, form: file("document", PDF, "report.pdf", "application/pdf") });
    check("genuine PDF document upload succeeds via cloudinary 2.x", doc.status === 201 && cloudinaryHits.length === before + 1,
      { status: doc.status, cloudinaryRequest: cloudinaryHits[before] });

    before = cloudinaryHits.length;
    const spoof = await api(base, "POST", "/api/documents", { token, form: file("document", Buffer.from("not a pdf"), "report.pdf", "application/pdf") });
    check("spoofed PDF still rejected before Cloudinary (V8 intact)", spoof.status === 400 && cloudinaryHits.length === before, { status: spoof.status });

    before = cloudinaryHits.length;
    const avatar = await api(base, "PATCH", "/api/patients/me/avatar", { token, form: file("avatar", PNG, "me.png", "image/png") });
    check("genuine PNG avatar reaches cloudinary 2.x image upload", cloudinaryHits.length === before + 1 && /\/image\/upload/.test(cloudinaryHits[before]?.url || ""),
      { status: avatar.status, cloudinaryRequest: cloudinaryHits[before] });

    // 4. Email through nodemailer 9.x (the same emailService the app uses)
    Object.assign(process.env, { SMTP_HOST: env.SMTP_HOST, SMTP_PORT: env.SMTP_PORT, SMTP_USER: env.SMTP_USER, SMTP_PASS: env.SMTP_PASS, EMAIL_FROM: env.EMAIL_FROM });
    const { sendEmail } = r("services/emailService");
    const info = await sendEmail({ to: "patient@careline360.test", subject: "V10 smoke", html: "<p>hello</p>" });
    const delivered = smtpMessages.find((m) => /Subject: V10 smoke/.test(m));
    check("emailService sends via nodemailer 9.x SMTP", !!(info && info.messageId && delivered), { messageId: info && info.messageId });
  } finally {
    server.kill();
    await mongo.stop();
    cloudinaryStub.close();
    smtpStub.close();
  }

  const versions = {};
  for (const p of ["nodemailer", "cloudinary", "mongoose", "mongodb", "express", "multer", "socket.io"]) {
    versions[p] = r(`node_modules/${p}/package.json`).version;
  }
  const out = { generatedAt: new Date().toISOString(), node: process.version, versions, results };
  fs.writeFileSync(path.join(__dirname, "smoke-test-results.json"), JSON.stringify(out, null, 2));
  const failed = results.filter((x) => !x.pass).length;
  console.log(`\n${results.length - failed}/${results.length} checks passed`);
  process.exit(failed ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
