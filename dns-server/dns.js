#!/usr/bin/env node
/* Fake DNS server for PS5 exploit hosting. Node stdlib only.
 *
 *   sudo node dns.js [options]
 *
 * The allowlisted exploit-host domains (manuals.playstation.net) are answered
 * with this machine's LAN IP (where api/serve.js and the 443 doorman run).
 * PlayStation/Sony domains are NXDOMAINed to stop updates and PSN traffic.
 * Everything else is forwarded verbatim to an upstream resolver so the console
 * can reach the real internet (catalogue art, provider pages) while the
 * Sony blocklist stays intact.
 *
 * Options:
 *   --ip <addr>        answer with this address  (default: auto-detect LAN IP)
 *   --port <n>         UDP port to bind          (default: 53, needs root)
 *   --upstream <addr>  resolver to forward to    (default: 8.8.8.8)
 *   --no-block-psn     answer PlayStation/Sony domains with the IP instead of NXDOMAIN
 *   --help
 */
"use strict";
const dgram = require("dgram"), os = require("os");

const BLOCK_PATTERNS = ["playstation", "sonyentertainmentnetwork", "sony.com"];
const ALLOWED_HOSTS = new Set(["manuals.playstation.net", "manuals.playstation.sony.com"]);

function matchesPattern(name, pattern) {
    const labels = name.split("."), pat = pattern.split(".");
    if (pat.length > labels.length) return false;
    for (let i = 0; i + pat.length <= labels.length; i++)
        if (pat.every((l, j) => labels[i + j] === l)) return true;
    return false;
}

function usage() {
    console.log("usage: node dns.js [--ip <addr>] [--port <n>] [--upstream <addr>] [--no-block-psn] [--help]");
}

const args = process.argv.slice(2);
let PORT = 53, FIX_IP = null, BLOCK = true, UPSTREAM = "8.8.8.8";
for (let i = 0; i < args.length; i++) {
    if (args[i] === "--help") { usage(); process.exit(0); }
    else if (args[i] === "--ip") FIX_IP = args[++i];
    else if (args[i] === "--port") PORT = parseInt(args[++i], 10);
    else if (args[i] === "--upstream") UPSTREAM = args[++i];
    else if (args[i] === "--no-block-psn") BLOCK = false;
    else { console.error("unknown argument: " + args[i]); usage(); process.exit(1); }
}

function detectIP() {
    for (const list of Object.values(os.networkInterfaces()))
        for (const f of list || [])
            if (f.family === "IPv4" && !f.internal) return f.address;
    return "127.0.0.1";
}
const IP = FIX_IP || detectIP();

function parseName(buf, off) {
    const parts = [];
    for (;;) {
        if (off >= buf.length) return null;
        const len = buf[off++];
        if (len === 0) return { name: parts.join("."), end: off };
        if (len > 63) {
            if ((len & 0xC0) !== 0xC0 || off >= buf.length) return null;
            const tail = parseName(buf, ((len & 0x3F) << 8) | buf[off]);
            if (!tail) return null;
            if (tail.name) parts.push(tail.name);
            return { name: parts.join("."), end: off + 1 };
        }
        if (off + len > buf.length) return null;
        parts.push(buf.toString("latin1", off, off + len).toLowerCase());
        off += len;
    }
}

function parseQuery(msg) {
    if (msg.length < 12 || (msg.readUInt16BE(2) & 0x8000)) return null;
    const qd = msg.readUInt16BE(4);
    let off = 12;
    const questions = [];
    for (let i = 0; i < qd; i++) {
        const n = parseName(msg, off);
        if (!n || n.end + 4 > msg.length) return null;
        const cls = msg.readUInt16BE(n.end + 2);
        if (cls !== 1) return null;
        questions.push({ name: n.name, type: msg.readUInt16BE(n.end) });
        off = n.end + 4;
    }
    return { id: msg.readUInt16BE(0), flags: msg.readUInt16BE(2), questions, end: off };
}

function headerFor(q, rcode, an, ns) {
    const h = Buffer.alloc(12);
    h.writeUInt16BE(q.id, 0);
    h.writeUInt16BE(0x8000 | (q.flags & 0x7900) | 0x0080 | (rcode & 0xF), 2);
    h.writeUInt16BE(q.questions.length, 4);
    h.writeUInt16BE(an, 6);
    h.writeUInt16BE(ns, 8);
    return h;
}

function encName(name) {
    const parts = [];
    for (const label of name.split(".")) {
        if (label) parts.push(Buffer.concat([Buffer.from([label.length]), Buffer.from(label, "latin1")]));
    }
    parts.push(Buffer.from([0]));
    return Buffer.concat(parts);
}

function rrPrefix(name, type, rdlength, ttl) {
    const p = Buffer.alloc(10);
    p.writeUInt16BE(type, 0);
    p.writeUInt16BE(1, 2);
    p.writeUInt32BE(ttl, 4);
    p.writeUInt16BE(rdlength, 8);
    return Buffer.concat([encName(name), p]);
}

function aRecord(name) {
    const ip = IP.split(".").map(Number);
    return Buffer.concat([rrPrefix(name, 1, 4, 60), Buffer.from(ip)]);
}

const UP_TIMEOUT = 3000;

function skipName(buf, off) {
    for (;;) {
        if (off >= buf.length) return null;
        const len = buf[off++];
        if (len === 0) return off;
        if ((len & 0xC0) === 0xC0) return off + 1;
        off += len;
    }
}

function firstAnswerIP(buf) {
    try {
        const qd = buf.readUInt16BE(4), an = buf.readUInt16BE(6);
        let off = 12;
        for (let i = 0; i < qd; i++) {
            off = skipName(buf, off);
            if (off === null || off + 4 > buf.length) return null;
            off += 4;
        }
        for (let i = 0; i < an; i++) {
            off = skipName(buf, off);
            if (off === null || off + 10 > buf.length) return null;
            const type = buf.readUInt16BE(off), rdlength = buf.readUInt16BE(off + 8);
            off += 10;
            if (type === 1 && rdlength === 4 && off + 4 <= buf.length)
                return Array.from(buf.subarray(off, off + 4)).join(".");
            off += rdlength;
        }
    } catch (e) {}
    return null;
}

function forwardQuery(q, req, rinfo) {
    const servfail = (verdict) => {
        finish(Buffer.concat([headerFor(q, 2, 0, 0), req.subarray(12, q.end)]), verdict);
    };
    const finish = (out, verdict) => {
        if (up.done) return;
        up.done = true;
        clearTimeout(up.timer);
        try { up.close(); } catch (e) {}
        sock.send(out, rinfo.port, rinfo.address);
        console.log(`[dns] ${rinfo.address} ${q.questions[0].name} type=${q.questions[0].type} -> ${verdict}`);
    };
    const up = dgram.createSocket("udp4");
    up.done = false;
    up.timer = setTimeout(() => servfail(`TIMEOUT(${UPSTREAM})`), UP_TIMEOUT);
    up.on("message", (res) => {
        const ip = firstAnswerIP(res);
        finish(res, ip ? `${ip} (forwarded via ${UPSTREAM})` : `forwarded via ${UPSTREAM}, no A record`);
    });
    up.on("error", () => servfail(`ERROR(${UPSTREAM})`));
    up.send(req, 53, UPSTREAM, (err) => { if (err) servfail(`ERROR(${UPSTREAM})`); });
}

function soaRecord(name) {
    const fields = Buffer.alloc(20);
    fields.writeUInt32BE(1, 0);
    fields.writeUInt32BE(600, 4);
    fields.writeUInt32BE(600, 8);
    fields.writeUInt32BE(86400, 12);
    fields.writeUInt32BE(60, 16);
    return Buffer.concat([
        rrPrefix(name, 6, encName("ns." + name).length + encName("root." + name).length + 20, 60),
        encName("ns." + name),
        encName("root." + name),
        fields
    ]);
}

const sock = dgram.createSocket({ type: "udp4", reuseAddr: true });
sock.on("message", (msg, rinfo) => {
    const q = parseQuery(msg);
    if (!q) return;
    const first = q.questions[0];
    const local = first.name in ALLOWED_HOSTS ? true : ALLOWED_HOSTS.has(first.name)
        || (!BLOCK && BLOCK_PATTERNS.some(p => matchesPattern(first.name, p)));
    const blocked = BLOCK && !local && BLOCK_PATTERNS.some(p => matchesPattern(first.name, p));
    let out, verdict;
    if (blocked) {
        out = Buffer.concat([headerFor(q, 3, 0, 1), msg.subarray(12, q.end), soaRecord(first.name)]);
        verdict = "NXDOMAIN";
    } else if (local && first.type === 1) {
        out = Buffer.concat([headerFor(q, 0, 1, 0), msg.subarray(12, q.end), aRecord(first.name)]);
        verdict = IP;
    } else if (local) {
        out = Buffer.concat([headerFor(q, 0, 0, 0), msg.subarray(12, q.end)]);
        verdict = "NODATA";
    } else {
        return forwardQuery(q, msg, rinfo);
    }
    sock.send(out, rinfo.port, rinfo.address);
    console.log(`[dns] ${rinfo.address} ${first.name} type=${first.type} -> ${verdict}`);
});

sock.on("error", (e) => {
    if (e.code === "EACCES") console.error(`cannot bind udp/${PORT} - retry with: sudo node ${process.argv[1]} ${args.join(" ")}`);
    else console.error(e);
    process.exit(1);
});

sock.bind(PORT, () => {
    console.log(`[dns] udp/${PORT} allow ${ALLOWED_HOSTS.size} host(s) -> ${IP}, sony blocked ${BLOCK ? "on" : "off"}, forwarding to ${UPSTREAM}`);
});

process.on("SIGINT", () => process.exit(0));
