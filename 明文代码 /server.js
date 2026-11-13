#!/usr/bin/env node
'use strict';

const http = require('http');
const fs = require('fs');
const path = require('path');
const net = require('net');
const crypto = require('crypto');
const { WebSocketServer } = require('ws');

// ============ 环境变量 ============
const UUID = process.env.UUID || 'a552c0ed-df68-11f1-881c-29ce776070aa'; // 节点UUID
const DOMAIN = process.env.DOMAIN || '';                                 // 项目域名,不包含https://前缀
const SUB_PATH = process.env.SUB_PATH || 'sub';                          // 节点订阅token
const NAME = process.env.NAME || '';                                     // 节点名称
const WSPATH = process.env.WSPATH || UUID.slice(0, 8);                   // 节点路径
const PORT = parseInt(process.env.SERVER_PORT || process.env.PORT || '80', 10); // http和ws端口
const DEBUG = (process.env.DEBUG || '').toLowerCase() === 'true';        // 调试日志

// ============ 全局变量 ============
let CurrentDomain = DOMAIN;
let CurrentPort = 443;
let Tls = 'tls';
let ISP = '';

const BLOCKED_DOMAINS = [
  'speedtest.net', 'fast.com', 'speedtest.cn', 'speed.cloudflare.com', 'speedof.me',
  'testmy.net', 'bandwidth.place', 'speed.io', 'librespeed.org', 'speedcheck.org',
];

// ============ 首页 ============
let INDEX_HTML = 'Hello world!';
try {
  INDEX_HTML = fs.readFileSync(path.join(__dirname, 'index.html'), 'utf8');
} catch (_) { /* 缺少 index.html 时回退 */ }

function log(message) {
  console.log(`${new Date().toISOString()} - INFO - ${message}`);
}

function errorLog(message) {
  console.error(`${new Date().toISOString()} - ERROR - ${message}`);
}

function isBlockedDomain(host) {
  if (!host) return false;
  const lower = host.toLowerCase();
  return BLOCKED_DOMAINS.some((blocked) => lower === blocked || lower.endsWith(`.${blocked}`));
}

function fetchWithTimeout(url, options = {}, ms = 5000) {
  return fetch(url, { ...options, signal: AbortSignal.timeout(ms) });
}

async function getISP() {
  try {
    const resp = await fetchWithTimeout('https://api.ip.sb/geoip',
      { headers: { 'User-Agent': 'Mozilla/5.0' } }, 3000);
    if (resp.ok) {
      const data = await resp.json();
      ISP = `${data.country_code || ''}-${data.isp || ''}`.replace(/ /g, '_');
      return;
    }
  } catch (_) { /* ignore */ }

  try {
    const resp = await fetchWithTimeout('http://ip-api.com/json',
      { headers: { 'User-Agent': 'Mozilla/5.0' } }, 3000);
    if (resp.ok) {
      const data = await resp.json();
      ISP = `${data.countryCode || ''}-${data.org || ''}`.replace(/ /g, '_');
      return;
    }
  } catch (_) { /* ignore */ }

  ISP = 'Unknown';
}

async function getIP() {
  if (!DOMAIN || DOMAIN === 'your-domain.com') {
    try {
      const resp = await fetchWithTimeout('https://api-ipv4.ip.sb/ip', {}, 5000);
      if (resp.ok) {
        const ip = (await resp.text()).trim();
        CurrentDomain = ip;
        Tls = 'none';
        CurrentPort = PORT;
        return;
      }
    } catch (e) {
      errorLog(`Failed to get IP: ${e.message}`);
    }
    CurrentDomain = 'change-your-domain.com';
    Tls = 'tls';
    CurrentPort = 443;
    return;
  }

  CurrentDomain = DOMAIN;
  Tls = 'tls';
  CurrentPort = 443;
}

async function resolveHost(host) {
  if (net.isIP(host)) return host;

  try {
    const resp = await fetchWithTimeout(
      `https://dns.google/resolve?name=${encodeURIComponent(host)}&type=A`, {}, 5000);
    if (resp.ok) {
      const data = await resp.json();
      if (data.Status === 0 && Array.isArray(data.Answer)) {
        const answer = data.Answer.find((item) => item.type === 1);
        if (answer) return answer.data;
      }
    }
  } catch (_) { /* ignore */ }

  return host; // 解析失败则返回原始域名
}

// 解析地址，返回 { host, offset }，失败返回 null
function readAddress(buf, offset, atyp, domainAtyp, ipv6Atyp) {
  let host;

  if (atyp === 1) { // IPv4
    if (offset + 4 > buf.length) return null;
    host = `${buf[offset]}.${buf[offset + 1]}.${buf[offset + 2]}.${buf[offset + 3]}`;
    offset += 4;
  } else if (atyp === domainAtyp) { // 域名
    if (offset >= buf.length) return null;
    const hostLen = buf[offset];
    offset += 1;
    if (offset + hostLen > buf.length) return null;
    host = buf.subarray(offset, offset + hostLen).toString('utf8');
    offset += hostLen;
  } else if (atyp === ipv6Atyp) { // IPv6
    if (offset + 16 > buf.length) return null;
    const parts = [];
    for (let j = offset; j < offset + 16; j += 2) {
      parts.push(((buf[j] << 8) | buf[j + 1]).toString(16).padStart(4, '0'));
    }
    host = parts.join(':');
    offset += 16;
  } else {
    return null;
  }

  return { host, offset };
}

const sha224Hex = (text) => crypto.createHash('sha224').update(text).digest('hex');

class ProxyHandler {
  constructor(uuid) {
    this.uuid = uuid; // 无短横线
    this.uuidBytes = Buffer.from(uuid, 'hex');
  }

  async handleVLESS(ws, ctx, msg) {
    try {
      if (msg.length < 18 || msg[0] !== 0) return false;

      // 验证UUID
      if (!msg.subarray(1, 17).equals(this.uuidBytes)) return false;

      let i = msg[17] + 19;
      if (i + 3 > msg.length) return false;

      const port = msg.readUInt16BE(i);
      i += 2;
      const atyp = msg[i];
      i += 1;

      const parsed = readAddress(msg, i, atyp, 2, 3);
      if (!parsed) return false;
      i = parsed.offset;
      const host = parsed.host;

      if (isBlockedDomain(host)) {
        ws.close();
        return false;
      }

      ws.send(Buffer.from([0, 0]));

      const resolvedHost = await resolveHost(host);
      await this.relay(ws, ctx, resolvedHost, port, msg.subarray(i));
      return true;
    } catch (e) {
      if (DEBUG) errorLog(`VLESS handler error: ${e.message}`);
      return false;
    }
  }

  async handleTrojan(ws, ctx, msg) {
    try {
      if (msg.length < 58) return false;

      // 验证密码 - 支持标准UUID和无短横线UUID
      const receivedHash = msg.subarray(0, 56).toString('latin1');
      if (receivedHash !== sha224Hex(this.uuid) && receivedHash !== sha224Hex(UUID)) {
        return false;
      }

      let offset = 56;
      if (msg[offset] === 13 && msg[offset + 1] === 10) offset += 2;

      const cmd = msg[offset];
      if (cmd !== 1) return false;
      offset += 1;

      const atyp = msg[offset];
      offset += 1;

      const parsed = readAddress(msg, offset, atyp, 3, 4);
      if (!parsed) return false;
      offset = parsed.offset;
      const host = parsed.host;

      if (offset + 2 > msg.length) return false;
      const port = msg.readUInt16BE(offset);
      offset += 2;

      if (msg[offset] === 13 && msg[offset + 1] === 10) offset += 2;

      if (isBlockedDomain(host)) {
        ws.close();
        return false;
      }

      const resolvedHost = await resolveHost(host);
      await this.relay(ws, ctx, resolvedHost, port, msg.subarray(offset));
      return true;
    } catch (e) {
      if (DEBUG) errorLog(`Trojan handler error: ${e.message}`);
      return false;
    }
  }

  async handleShadowsocks(ws, ctx, msg) {
    try {
      if (msg.length < 7) return false;

      let offset = 0;
      const atyp = msg[offset];
      offset += 1;

      const parsed = readAddress(msg, offset, atyp, 3, 4);
      if (!parsed) return false;
      offset = parsed.offset;
      const host = parsed.host;

      if (offset + 2 > msg.length) return false;
      const port = msg.readUInt16BE(offset);
      offset += 2;

      if (isBlockedDomain(host)) {
        ws.close();
        return false;
      }

      const resolvedHost = await resolveHost(host);
      await this.relay(ws, ctx, resolvedHost, port, msg.subarray(offset));
      return true;
    } catch (e) {
      if (DEBUG) errorLog(`Shadowsocks handler error: ${e.message}`);
      return false;
    }
  }

  relay(ws, ctx, host, port, initial) {
    return new Promise((resolve) => {
      const socket = net.connect({ host, port });
      let finished = false;
      const finish = () => {
        if (finished) return;
        finished = true;
        resolve();
      };

      socket.on('connect', () => {
        if (initial && initial.length) socket.write(initial);
        ctx.sink = (chunk) => {
          if (!socket.destroyed) socket.write(chunk);
        };
        for (const chunk of ctx.buffered) socket.write(chunk);
        ctx.buffered.length = 0;
        finish();
      });

      socket.on('data', (chunk) => {
        if (ws.readyState === 1) ws.send(chunk); // 1 = OPEN
      });

      socket.on('error', (e) => {
        if (DEBUG) errorLog(`Connection error: ${e.message}`);
        try { ws.close(); } catch (_) { /* ignore */ }
        finish();
      });

      socket.on('close', () => {
        try { ws.close(); } catch (_) { /* ignore */ }
        finish();
      });

      ws.on('close', () => {
        socket.destroy();
        finish();
      });
    });
  }
}

// ============ WebSocket 处理 ============
const wss = new WebSocketServer({ noServer: true });

wss.on('connection', (ws) => {
  const proxy = new ProxyHandler(UUID.replace(/-/g, ''));
  const ctx = { sink: null, buffered: [] };

  let gotFirst = false;
  let firstResolve;
  const firstPromise = new Promise((resolve) => { firstResolve = resolve; });

  const timer = setTimeout(() => {
    if (gotFirst) return;
    gotFirst = true;
    firstResolve(null);
    try { ws.close(); } catch (_) { /* ignore */ }
  }, 5000);

  ws.on('error', () => { /* ignore */ });

  ws.on('message', (data, isBinary) => {
    const buf = Buffer.isBuffer(data) ? data : Buffer.from(data);

    if (!gotFirst) {
      gotFirst = true;
      clearTimeout(timer);
      if (!isBinary) {
        firstResolve(null);
        try { ws.close(); } catch (_) { /* ignore */ }
        return;
      }
      firstResolve(buf);
      return;
    }

    if (!isBinary) return;
    if (ctx.sink) ctx.sink(buf);
    else ctx.buffered.push(buf);
  });

  (async () => {
    const msg = await firstPromise;

    if (msg && msg.length > 17 && msg[0] === 0) {
      if (await proxy.handleVLESS(ws, ctx, msg)) return;
    }

    if (msg && msg.length >= 58) {
      if (await proxy.handleTrojan(ws, ctx, msg)) return;
    }

    if (msg && msg.length > 0 && [1, 3, 4].includes(msg[0])) {
      if (await proxy.handleShadowsocks(ws, ctx, msg)) return;
    }

    try { ws.close(); } catch (_) { /* ignore */ }
  })();
});

// ============ HTTP 处理 ============
async function httpHandler(req, res) {
  const pathname = new URL(req.url, 'http://localhost').pathname;

  if (pathname === '/') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(INDEX_HTML);
    return;
  }

  if (pathname === `/${SUB_PATH}` || pathname === '/ip') {
    await getISP();
    await getIP();

    const namePart = NAME ? `${NAME}-${ISP}` : ISP;
    const tlsParam = Tls === 'tls' ? 'tls' : 'none';
    const ssTlsParam = Tls === 'tls' ? 'tls;' : '';

    const vlessUrl = `vless://${UUID}@${CurrentDomain}:${CurrentPort}?encryption=none&security=${tlsParam}&sni=${CurrentDomain}&fp=chrome&type=ws&host=${CurrentDomain}&path=%2F${WSPATH}#${namePart}`;
    const trojanUrl = `trojan://${UUID}@${CurrentDomain}:${CurrentPort}?security=${tlsParam}&sni=${CurrentDomain}&fp=chrome&type=ws&host=${CurrentDomain}&path=%2F${WSPATH}#${namePart}`;

    const ssMethodPassword = Buffer.from(`none:${UUID}`, 'utf8').toString('base64');
    const ssUrl = `ss://${ssMethodPassword}@${CurrentDomain}:${CurrentPort}?plugin=v2ray-plugin;mode%3Dwebsocket;host%3D${CurrentDomain};path%3D%2F${WSPATH};${ssTlsParam}sni%3D${CurrentDomain};skip-cert-verify%3Dtrue;mux%3D0#${namePart}`;

    const subscription = `${vlessUrl}\n${trojanUrl}\n${ssUrl}`;
    const base64Content = Buffer.from(subscription, 'utf8').toString('base64');

    // /ip 返回明文订阅，/sub 返回 base64 订阅
    res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end(pathname === '/ip' ? `${subscription}\n` : `${base64Content}\n`);
    return;
  }

  res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
  res.end('Not Found\n');
}

// ============ 启动 ============
const server = http.createServer((req, res) => {
  httpHandler(req, res).catch((e) => {
    if (DEBUG) errorLog(`HTTP handler error: ${e.message}`);
    if (!res.headersSent) res.writeHead(500);
    res.end();
  });
});

server.on('upgrade', (req, socket, head) => {
  const pathname = new URL(req.url, 'http://localhost').pathname;
  if (!pathname.includes(`/${WSPATH}`)) {
    socket.destroy();
    return;
  }
  wss.handleUpgrade(req, socket, head, (ws) => {
    wss.emit('connection', ws, req);
  });
});

function start(port, attempts) {
  server.once('error', (err) => {
    if (err.code === 'EADDRINUSE' && attempts > 0) {
      log(`Port ${port} is already in use, finding available port...`);
      start(port + 1, attempts - 1);
      return;
    }
    errorLog('No available ports found');
    process.exit(1);
  });

  server.listen(port, '0.0.0.0', () => {
    log(`✅ server is running on port ${port}`);
  });
}

start(PORT, 100);

process.on('SIGINT', () => {
  console.log('\nServer stopped by user');
  server.close(() => process.exit(0));
});
