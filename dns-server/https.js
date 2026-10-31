#!/usr/bin/env node
/* HTTPS/HTTP doorman for the PS5 User's Guide hijack. Node stdlib only.
 *
 *   sudo node https.js [options]
 *
 * The console's User's Guide page is hard-coded to https://manuals.playstation.net
 * on port 443; DNS alone can never send it to a chosen port. This server takes the
 * knock on 443 (self-signed cert: once per console, the PS5 shows a certificate
 * warning to accept) and on 80, then immediately hands the browser to the real
 * exploit site: http://<ip>:<target-port>/ which is "node api/serve.js <target-port>".
 *
 * Appcache manifest requests are answered 404: with a self-signed cert the appcache
 * cannot pass its update check after a console reboot and a stale cache would keep
 * showing the old page instead of following the redirect.
 *
 * Options:
 *   --ip <addr>           LAN address to advertise (default: auto-detect)
 *   --port <n>            HTTPS port (default: 443, needs root)
 *   --http-port <n>       HTTP port (default: 80, needs root; 0 disables)
 *   --target-port <n>     api/serve.js port to hand off to (default: 8080)
 *   --cert <p> --key <p>  TLS cert/key paths (default: cert.pem/key.pem next to this script)
 *   --help
 */
"use strict";
const https = require("https"), http = require("http"), fs = require("fs"),
      path = require("path"), net = require("net"), os = require("os"),
      spawnSync = require("child_process").spawnSync;

function usage() {
    console.log("usage: node https.js [--ip <addr>] [--port <n>] [--http-port <n>] [--target-port <n>] [--cert <p>] [--key <p>] [--help]");
}

const args = process.argv.slice(2);
let IP = null, PORT = 443, HTTP_PORT = 80, TARGET = 8080, CERT = null, KEY = null;
for (let i = 0; i < args.length; i++) {
    if (args[i] === "--help") { usage(); process.exit(0); }
    else if (args[i] === "--ip") IP = args[++i];
    else if (args[i] === "--port") PORT = parseInt(args[++i], 10);
    else if (args[i] === "--http-port") HTTP_PORT = parseInt(args[++i], 10);
    else if (args[i] === "--target-port") TARGET = parseInt(args[++i], 10);
    else if (args[i] === "--cert") CERT = args[++i];
    else if (args[i] === "--key") KEY = args[++i];
    else { console.error("unknown argument: " + args[i]); usage(); process.exit(1); }
}

function detectIP() {
    for (const list of Object.values(os.networkInterfaces()))
        for (const f of list || [])
            if (f.family === "IPv4" && !f.internal) return f.address;
    return "127.0.0.1";
}
IP = IP || detectIP();

CERT = CERT || path.join(__dirname, "cert.pem");
KEY = KEY || path.join(__dirname, "key.pem");

function ensureCert() {
    if (fs.existsSync(CERT) && fs.existsSync(KEY)) return true;
    console.log(`[cert] ${CERT} missing - generating self-signed cert for manuals.playstation.net (${IP}) ...`);
    const base = ["req", "-x509", "-newkey", "rsa:4096", "-nodes", "-days", "3650",
        "-keyout", KEY, "-out", CERT, "-subj", "/CN=manuals.playstation.net"];
    const SAN = ["-addext", `subjectAltName=DNS:manuals.playstation.net,DNS:manuals.playstation.sony.com,DNS:*.playstation.net,DNS:localhost,IP:${IP}`];
    let r = spawnSync("openssl", [...base, ...SAN], { stdio: "pipe" });
    if (r.status !== 0) r = spawnSync("openssl", base, { stdio: "pipe" });
    if (r.status !== 0 || !fs.existsSync(CERT)) {
        console.error(`[cert] auto-generation failed (is openssl installed?). Create the pair yourself:
  openssl req -x509 -newkey rsa:4096 -nodes -days 3650 \\
    -keyout ${KEY} -out ${CERT} \\
    -subj "/CN=manuals.playstation.net" \\
    -addext "subjectAltName=DNS:manuals.playstation.net,IP:${IP}"
  chmod 600 ${KEY}`);
        return false;
    }
    try { fs.chmodSync(KEY, 0o600); } catch {}
    console.log(`[cert] wrote ${CERT} and ${KEY} (valid 10 years)`);
    return true;
}

const banner = () => {
    const loc = TARGET === 80 ? `http://${IP}/` : `http://${IP}:${TARGET}/`;
    const ports = TARGET === 80 ? "port 80" : `port ${TARGET}`;
    console.log(`[door] https://${IP}:${PORT} + ${HTTP_PORT ? `http://${IP}:${HTTP_PORT} ` : ""}-> redirecting everything to ${loc}`);
    console.log(`[door] PS5 flow: Settings > Network > manual DNS ${IP} -> User's Guide -> accept certificate warning`);
    net.connect({ port: TARGET, host: "127.0.0.1", timeout: 2000 })
        .on("connect", function f() { this.end(); console.log(`[door] api/serve.js is listening locally on ${ports} - good`); })
        .on("timeout", function t() { this.destroy(); })
        .on("error", () => console.log(`[door] nothing on local port ${TARGET} yet - start the real site now:  node api/serve.js ${TARGET}`));
};
    
function handler(req, res) {
    const accept = String(req.headers.accept || "");
    if (accept.indexOf("text/cache-manifest") >= 0 || /\.appcache$/i.test(req.url || "")) {
        res.writeHead(404, { "Cache-Control": "no-store" });
        return res.end();
    }
    res.writeHead(302, {
        "Location": TARGET === 80 ? `http://${IP}/` : `http://${IP}:${TARGET}/`,
        "Cache-Control": "no-store"
    });
    res.end();
}

function listen(srv, port, label) {
    if (!port) return;
    srv.on("error", (e) => {
        if (e.code === "EACCES") console.error(`cannot bind ${label} ${port} - retry with: sudo node ${process.argv[1]} ${args.join(" ")}`);
        else if (e.code === "EADDRINUSE") console.error(`${label}/${port} already in use`);
        else console.error(e);
        process.exit(1);
    });
    srv.listen(port);
}

if (!ensureCert()) process.exit(1);

const tlsOpts = { key: fs.readFileSync(KEY), cert: fs.readFileSync(CERT) };
listen(https.createServer(tlsOpts, handler), PORT, "https");
listen(http.createServer(handler), HTTP_PORT, "http");
banner();

process.on("SIGINT", () => process.exit(0));
