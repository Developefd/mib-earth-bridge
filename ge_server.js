#!/usr/bin/env node
'use strict';
/*
 * Reverse proxy for a MIB2 head unit whose /etc/hosts points kh.google.com here.
 *
 * The car resolves kh.google.com to this machine and sends ordinary HTTP
 * requests to port 80 with `Host: kh.google.com`. This server rewrites the
 * User-Agent, forwards upstream to the real kh.google.com, and caches the
 * response.
 *
 * The rewrite that matters is the literal token `QNX`, which Google 403s. The
 * car sends:
 *   GoogleEarth/7.1.0003.0000(MIB;QNX (0.0.0.0);fr;kml:2.2;client:Free;type:default)
 * Bumping the version alone is NOT enough. See GOOGLE_EARTH_FINDINGS.md §3.
 *
 *     sudo node ge_server.js --port 80
 *
 * Node built-ins only, no npm install.
 *
 * Upstream addresses are found with dns.resolve4(), which queries DNS directly
 * and ignores /etc/hosts -- so this box cannot proxy to itself even if someone
 * adds the redirect here too. Requests then connect straight to those IPs.
 *
 * Caching matters: /flatfile URLs embed the tile epoch, so they are immutable
 * and cached indefinitely; /dbRoot.v5 has no epoch and gets a short TTL, or the
 * car would pin itself to a stale epoch. On-disk format is byte-compatible with
 * ge_server.py, so the two can share a cache directory.
 */

const http = require('http');
const dns = require('dns').promises;
const fs = require('fs');
const fsp = fs.promises;
const path = require('path');
const crypto = require('crypto');

const UPSTREAM_HOST = 'kh.google.com';
const UA_RE = /GoogleEarth\/\d+\.\d+\.\d+\.\d+/;

// Google 403s any User-Agent containing the literal token QNX. This -- not the
// client version -- is what actually blocks the car; bumping the version alone
// still gets 403 while QNX is present. The match is case-sensitive ("qnx" is
// served), but replacing the token outright is the sturdier fix.
const QNX_RE = /\bQNX\b/g;

// Hop-by-hop headers must not be forwarded in either direction (RFC 7230 6.1).
const HOP_BY_HOP = new Set([
  'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
  'te', 'trailers', 'transfer-encoding', 'upgrade', 'proxy-connection',
]);

// ---------------------------------------------------------------------------
// args
// ---------------------------------------------------------------------------
function parseArgs(argv) {
  const cfg = {
    port: 80,
    bind: '0.0.0.0',
    version: '7.1.8.3036',
    osToken: 'Linux',
    cacheDir: 'ge_cache',
    cacheMaxMb: 2048,
    dbrootTtl: 86400,
    timeout: 30000,
    upstreamIp: null,
    forceUa: false,
    debug: false,
  };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    const next = () => argv[++i];
    switch (a) {
      case '--port': cfg.port = Number(next()); break;
      case '--bind': cfg.bind = next(); break;
      case '--version': cfg.version = next(); break;
      case '--os-token': cfg.osToken = next(); break;
      case '--cache-dir': cfg.cacheDir = next(); break;
      case '--cache-max-mb': cfg.cacheMaxMb = Number(next()); break;
      case '--dbroot-ttl': cfg.dbrootTtl = Number(next()); break;
      case '--timeout': cfg.timeout = Number(next()) * 1000; break;
      case '--upstream-ip': cfg.upstreamIp = next(); break;
      case '--force-ua': cfg.forceUa = true; break;
      case '--no-cache': cfg.cacheDir = ''; break;
      case '--debug': cfg.debug = true; break;
      case '-h': case '--help':
        console.log(`Usage: node ge_server.js [options]

  --port N            listen port (default 80; the car will use 80)
  --bind ADDR         default 0.0.0.0
  --version V         client version to advertise (default 7.1.8.3036)
  --os-token T        replaces the literal "QNX" in the UA, which Google 403s
                      (default Linux) -- this is the rewrite that matters
  --force-ua          also set a User-Agent when the client sends none
  --upstream-ip IP    pin the real kh.google.com IP instead of resolving
  --cache-dir DIR     default ge_cache
  --no-cache          disable caching
  --cache-max-mb N    0 for unlimited (default 2048)
  --dbroot-ttl SEC    seconds to cache dbRoot; 0 = never cache (default 86400)
  --timeout SEC       upstream timeout, default 30
  --debug             on any non-200 upstream reply, dump the full outgoing
                      request headers and a preview of the response body
`);
        process.exit(0);
        break;
      default:
        console.error(`unknown option: ${a} (try --help)`);
        process.exit(1);
    }
  }
  return cfg;
}

const cfg = parseArgs(process.argv);

// ---------------------------------------------------------------------------
// logging + stats
// ---------------------------------------------------------------------------
function log(msg) {
  process.stdout.write(`[${new Date().toTimeString().slice(0, 8)}] ${msg}\n`);
}

const stats = {
  started: Date.now(),
  requests: 0,
  hits: 0,
  misses: 0,
  coalesced: 0,
  errors: 0,
  blocked: 0,       // upstream 403s -- means the rewrite is not applying
  bytesOut: 0,
  clientUserAgents: Object.create(null),
};

function snapshot() {
  return {
    uptime_s: Math.round((Date.now() - stats.started) / 100) / 10,
    requests: stats.requests,
    cache_hits: stats.hits,
    cache_misses: stats.misses,
    coalesced: stats.coalesced,
    upstream_errors: stats.errors,
    upstream_403: stats.blocked,
    bytes_served: stats.bytesOut,
    client_user_agents: { ...stats.clientUserAgents },
  };
}

// ---------------------------------------------------------------------------
// disk cache -- one file per entry: JSON metadata line, newline, then body
// ---------------------------------------------------------------------------
class DiskCache {
  constructor(dir, maxMb) {
    this.dir = dir;
    this.maxBytes = maxMb ? maxMb * 1024 * 1024 : 0;
    fs.mkdirSync(this.dir, { recursive: true });
  }

  _path(key) {
    const h = crypto.createHash('sha256').update(key).digest('hex');
    return path.join(this.dir, h.slice(0, 2), `${h.slice(2)}.ge`);
  }

  async get(key, ttlSec) {
    const p = this._path(key);
    let buf;
    try {
      buf = await fsp.readFile(p);
    } catch {
      return null;
    }
    const nl = buf.indexOf(0x0a);
    if (nl < 0) return null;
    let meta;
    try {
      meta = JSON.parse(buf.subarray(0, nl).toString('utf8'));
    } catch {
      return null;
    }
    if (ttlSec && Date.now() / 1000 - (meta.t || 0) > ttlSec) return null;
    fsp.utimes(p, new Date(), new Date()).catch(() => {});  // keep LRU honest
    return { status: meta.status || 200, headers: meta.headers || [], body: buf.subarray(nl + 1) };
  }

  async put(key, status, headers, body) {
    const p = this._path(key);
    const meta = { t: Date.now() / 1000, status, headers, url: key };
    const tmp = `${p}.${process.pid}.${Math.random().toString(36).slice(2)}.tmp`;
    try {
      await fsp.mkdir(path.dirname(p), { recursive: true });
      await fsp.writeFile(tmp, Buffer.concat([
        Buffer.from(`${JSON.stringify(meta)}\n`, 'utf8'), body,
      ]));
      await fsp.rename(tmp, p);
    } catch {
      fsp.unlink(tmp).catch(() => {});
    }
  }

  /** Evict oldest entries until the cache is under 90% of its limit. */
  async sweep() {
    if (!this.maxBytes) return;
    const entries = [];
    let total = 0;
    const walk = async (d) => {
      let items;
      try {
        items = await fsp.readdir(d, { withFileTypes: true });
      } catch { return; }
      for (const it of items) {
        const fp = path.join(d, it.name);
        if (it.isDirectory()) { await walk(fp); continue; }
        if (!it.name.endsWith('.ge')) continue;
        try {
          const st = await fsp.stat(fp);
          entries.push({ mtime: st.mtimeMs, size: st.size, fp });
          total += st.size;
        } catch { /* raced with eviction */ }
      }
    };
    await walk(this.dir);
    if (total <= this.maxBytes) return;

    const target = this.maxBytes * 0.9;
    entries.sort((a, b) => a.mtime - b.mtime);
    let freed = 0;
    for (const e of entries) {
      if (total - freed <= target) break;
      try { await fsp.unlink(e.fp); freed += e.size; } catch { /* already gone */ }
    }
    log(`cache sweep: freed ${(freed / 1e6).toFixed(1)} MB `
      + `(${(total / 1e6).toFixed(1)} -> ${((total - freed) / 1e6).toFixed(1)} MB)`);
  }
}

const cache = cfg.cacheDir ? new DiskCache(cfg.cacheDir, cfg.cacheMaxMb) : null;

// ---------------------------------------------------------------------------
// upstream
// ---------------------------------------------------------------------------
let upstreamIps = [];
let ipCursor = 0;

const agent = new http.Agent({
  keepAlive: true,
  keepAliveMsecs: 30000,
  maxSockets: 32,
});

async function resolveUpstream() {
  if (cfg.upstreamIp) return [cfg.upstreamIp];
  // resolve4 talks to DNS directly and ignores /etc/hosts, unlike dns.lookup
  const ips = await dns.resolve4(UPSTREAM_HOST);
  if (!ips.length) throw new Error(`could not resolve ${UPSTREAM_HOST}`);
  return ips.sort();
}

function fetchOnce(method, urlPath, headers, ip, body) {
  return new Promise((resolve, reject) => {
    const req = http.request({
      host: ip, port: 80, method, path: urlPath, headers, agent,
    }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const out = [];
        for (const [k, v] of Object.entries(res.headers)) {
          if (HOP_BY_HOP.has(k.toLowerCase()) || k.toLowerCase() === 'content-length') continue;
          out.push([k, v]);
        }
        resolve({ status: res.statusCode, headers: out, body: Buffer.concat(chunks), ip });
      });
      res.on('error', reject);
    });
    req.setTimeout(cfg.timeout, () => req.destroy(new Error('upstream timeout')));
    req.on('error', reject);
    if (body && body.length) req.write(body);
    req.end();
  });
}

/** Try the next upstream IP on failure; one retry. */
async function upstreamFetch(method, urlPath, headers, body) {
  let lastErr;
  for (let attempt = 0; attempt < 2; attempt++) {
    const ip = upstreamIps[(ipCursor + attempt) % upstreamIps.length];
    try {
      return await fetchOnce(method, urlPath, headers, ip, body);
    } catch (e) {
      lastErr = e;
      ipCursor = (ipCursor + 1) % upstreamIps.length;
    }
  }
  throw lastErr;
}

// ---------------------------------------------------------------------------
// request handling
// ---------------------------------------------------------------------------
/*
 * The car asks for dbRoot with `type=embedded`, the embedded/automotive dbRoot
 * variant. Google has decommissioned it and answers 404 NOT_FOUND; the same
 * request without that parameter returns a normal dbRoot. `cobrand=AUDI`, which
 * the car also sends, is harmless -- it is ignored and the response is
 * byte-identical with or without it, so it is left alone.
 */
let loggedRewrite = false;

function stripEmbedded(urlPath) {
  const i = urlPath.indexOf('?');
  if (i < 0) return urlPath;
  const base = urlPath.slice(0, i);
  const kept = urlPath.slice(i + 1).split('&').filter((kv) => kv !== 'type=embedded');
  const out = kept.length ? `${base}?${kept.join('&')}` : base;
  if (out !== urlPath && !loggedRewrite) {
    loggedRewrite = true;
    log('query rewrite active: dropping "type=embedded" (Google 404s that dbRoot variant)');
  }
  return out;
}

function cachePolicy(urlPath) {
  if (!cache) return { cacheable: false, ttl: 0 };
  if (urlPath.startsWith('/flatfile')) return { cacheable: true, ttl: 0 };   // epoch in URL
  // dbRootTtl <= 0 means never cache. Serving a stale or inconsistent dbRoot makes
  // the client raise OnNewDatabaseVersion and restart gemib mid-session.
  if (urlPath.startsWith('/dbRoot')) {
    return { cacheable: cfg.dbrootTtl > 0, ttl: cfg.dbrootTtl };
  }
  return { cacheable: false, ttl: 0 };
}

function buildUpstreamHeaders(req) {
  const headers = {};
  for (const [k, v] of Object.entries(req.headers)) {
    if (HOP_BY_HOP.has(k.toLowerCase()) || k.toLowerCase() === 'host') continue;
    headers[k] = v;
  }
  headers.host = UPSTREAM_HOST;

  const ua = req.headers['user-agent'] || '';
  if (ua) {
    if (!(ua in stats.clientUserAgents)) log(`client User-Agent seen: ${JSON.stringify(ua)}`);
    stats.clientUserAgents[ua] = (stats.clientUserAgents[ua] || 0) + 1;
  }
  if (ua) {
    let out = ua.replace(UA_RE, `GoogleEarth/${cfg.version}`).replace(QNX_RE, cfg.osToken);
    if (out !== ua) headers['user-agent'] = out;
  } else if (cfg.forceUa) {
    headers['user-agent'] = `GoogleEarth/${cfg.version}(MIB;${cfg.osToken};)`;
  }
  return headers;
}

function send(res, status, headers, body, sendBody = true) {
  const h = {};
  for (const [k, v] of headers) h[k] = v;
  h['Content-Length'] = String(body.length);
  try {
    res.writeHead(status, h);
    res.end(sendBody ? body : undefined);
  } catch { /* client already gone */ }
}

// Collapse concurrent requests for the same uncached URL into one upstream fetch.
const inflight = new Map();

async function handle(req, res) {
  const urlPath = stripEmbedded(req.url);
  const sendBody = req.method !== 'HEAD';
  stats.requests++;

  if (urlPath.startsWith('/_ge')) {
    const payload = Buffer.from(`${JSON.stringify(snapshot(), null, 2)}\n`);
    send(res, 200, [['Content-Type', 'application/json']], payload, sendBody);
    return;
  }

  if (req.method !== 'GET' && req.method !== 'HEAD' && req.method !== 'POST') {
    send(res, 405, [['Content-Type', 'text/plain']], Buffer.from('method not allowed\n'), sendBody);
    return;
  }

  let body = null;
  if (req.method === 'POST') {
    const chunks = [];
    for await (const c of req) chunks.push(c);
    body = Buffer.concat(chunks);
  }

  const { cacheable, ttl } = cachePolicy(urlPath);

  if (cacheable) {
    const hit = await cache.get(urlPath, ttl);
    if (hit) {
      stats.hits++;
      stats.bytesOut += hit.body.length;
      send(res, hit.status, hit.headers, hit.body, sendBody);
      log(`HIT  ${hit.status} ${String(hit.body.length).padStart(7)}B ${urlPath}`);
      return;
    }
  }

  const t0 = Date.now();
  const key = `${req.method} ${urlPath}`;
  let promise = inflight.get(key);
  const coalesced = Boolean(promise);
  if (coalesced) stats.coalesced++;

  let outHeaders = null;
  if (!promise) {
    outHeaders = buildUpstreamHeaders(req);
    promise = upstreamFetch(req.method, urlPath, outHeaders, body)
      .finally(() => inflight.delete(key));
    inflight.set(key, promise);
  }

  let up;
  try {
    up = await promise;
  } catch (e) {
    stats.errors++;
    log(`ERR  upstream ${e.message} for ${urlPath}`);
    send(res, 502, [['Content-Type', 'text/plain']], Buffer.from('upstream fetch failed\n'), sendBody);
    return;
  }

  if (up.status === 403) {
    stats.blocked++;
    log('403  Google refused this request. Check the outgoing User-Agent still '
      + `contains no literal "QNX" token. ${urlPath}`);
  }

  // Anything other than 200/304 is worth explaining, since the useful evidence is
  // what we *sent*, which is otherwise invisible.
  if (up.status !== 200 && up.status !== 304) {
    log(`     upstream ${up.status} via ${up.ip}; UA sent: `
      + `${outHeaders ? outHeaders['user-agent'] : '(coalesced request)'}`);
    if (cfg.debug && outHeaders) {
      log(`     > ${req.method} ${urlPath}`);
      for (const [k, v] of Object.entries(outHeaders)) log(`     > ${k}: ${v}`);
      const preview = up.body.subarray(0, 300).toString('utf8').replace(/\s+/g, ' ').trim();
      log(`     < ${up.status} body: ${preview}`);
    } else if (!cfg.debug) {
      log('     re-run with --debug to dump the full outgoing request');
    }
  }

  if (cacheable && up.status === 200 && !coalesced) {
    cache.put(urlPath, up.status, up.headers, up.body).catch(() => {});
  }

  stats.misses++;
  stats.bytesOut += up.body.length;
  send(res, up.status, up.headers, up.body, sendBody);
  log(`${coalesced ? 'COAL' : 'MISS'} ${up.status} ${String(up.body.length).padStart(7)}B `
    + `${String(Date.now() - t0).padStart(5)}ms ${urlPath}`);
}

// ---------------------------------------------------------------------------
async function main() {
  try {
    upstreamIps = await resolveUpstream();
  } catch (e) {
    console.error(`fatal: ${e.message}`);
    process.exit(1);
  }

  const server = http.createServer((req, res) => {
    handle(req, res).catch((e) => {
      stats.errors++;
      log(`ERR  handler ${e.stack || e.message}`);
      try { res.writeHead(500); res.end('internal error\n'); } catch { /* gone */ }
    });
  });
  server.keepAliveTimeout = 65000;
  server.headersTimeout = 70000;
  server.on('clientError', (err, socket) => {
    if (socket.writable) socket.end('HTTP/1.1 400 Bad Request\r\n\r\n');
  });

  log(`upstream ${UPSTREAM_HOST} -> ${upstreamIps.join(', ')} (by IP, /etc/hosts bypassed)`);
  log(`advertising GoogleEarth/${cfg.version}, replacing UA token QNX -> ${cfg.osToken}`);
  log(`cache: ${cfg.cacheDir || 'disabled'}`
    + (cfg.cacheDir && cfg.cacheMaxMb ? ` (max ${cfg.cacheMaxMb} MB)` : ''));

  if (cache) setInterval(() => cache.sweep().catch(() => {}), 300000).unref();

  server.listen(cfg.port, cfg.bind, () => {
    log(`listening on ${cfg.bind}:${cfg.port} -- point the car's /etc/hosts here`);
    if (cfg.port === 80 && typeof process.getuid === 'function' && process.getuid() !== 0) {
      log('warning: port 80 usually needs root');
    }
  });
  server.on('error', (e) => {
    console.error(`fatal: ${e.message}`);
    process.exit(1);
  });

  process.on('SIGINT', () => {
    const s = snapshot();
    log('shutting down');
    log(`served ${s.requests} requests, ${s.cache_hits} hits / ${s.cache_misses} misses, `
      + `${(s.bytes_served / 1e6).toFixed(1)} MB, ${s.upstream_403} upstream 403s`);
    process.exit(0);
  });
}

main();
