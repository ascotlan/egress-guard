// The egress guard: an HTTP forward proxy that sits between an agent and the
// network. Every request passes three checks, in order:
//   1. method      (CONNECT is refused: an HTTPS tunnel cannot be inspected)
//   2. host        (must be on the allowlist)
//   3. content     (no field may match an injection rule)
// Every decision is appended to a JSONL log.

import http from 'node:http';
import fs from 'node:fs';
import { extractFields } from './canonicalize.mjs';

const ALLOWED_METHODS = new Set(['GET', 'HEAD', 'POST']);
const MAX_BODY_BYTES = 1_000_000;

/** Split an absolute-form request target into host and the raw path+query. */
export function parseTarget(target) {
  const m = /^http:\/\/([^\/?#]*)(.*)$/i.exec(target);
  if (!m) return null;
  // "http://archive.test@outside.test/" is a request to outside.test.
  const authority = m[1].split('@').pop().toLowerCase();
  const host = authority.replace(/:80$/, '');
  let rest = m[2] || '/';
  if (rest.startsWith('?')) rest = '/' + rest;
  const hash = rest.indexOf('#');
  if (hash !== -1) rest = rest.slice(0, hash);
  return { host, rawTarget: rest };
}

/** Check one request against the rules. Returns { allowed, rule, field }. */
export function inspect({ rawTarget, body, contentType }, rules) {
  for (const field of extractFields({ rawTarget, body, contentType })) {
    for (const rule of rules) {
      if (rule.where && !rule.where.includes(field.where)) continue;
      if (rule.re.test(field.value)) {
        return { allowed: false, rule: rule.id, field: { where: field.where, name: field.name, value: field.value.slice(0, 200) } };
      }
    }
  }
  return { allowed: true };
}

/**
 * Create the guard.
 *   allowlist: hosts that may be reached, for example ['archive.test']
 *   resolve:   host -> { host, port } for the upstream, or null. In this test
 *              harness only the two local test sites resolve, so a request can
 *              never reach a real website even if a check fails.
 *   rules:     array from a rules-vN.mjs file
 *   logPath:   JSONL file, opened in append mode
 */
export function createGuard({ allowlist, resolve, rules, rulesVersion, logPath }) {
  const allowed = new Set(allowlist.map((h) => h.toLowerCase()));
  const log = fs.createWriteStream(logPath, { flags: 'a' });
  const write = (entry) => log.write(JSON.stringify({ ts: new Date().toISOString(), rules: rulesVersion, ...entry }) + '\n');

  const deny = (res, status, reason, meta, extra = {}) => {
    write({ ...meta, decision: 'block', status, reason, ...extra });
    res.writeHead(status, { 'content-type': 'application/json', 'x-guard-decision': 'block', 'x-guard-reason': reason });
    res.end(JSON.stringify({ blocked: true, reason, ...extra }));
  };

  const server = http.createServer((req, res) => {
    const meta = {
      testId: req.headers['x-test-id'] ?? null,
      runId: req.headers['x-run-id'] ?? null,
      method: req.method,
      target: req.url,
    };

    if (!ALLOWED_METHODS.has(req.method)) return deny(res, 405, 'method-not-allowed', meta);

    const parsed = parseTarget(req.url);
    if (!parsed) return deny(res, 400, 'not-a-proxy-request', meta);
    meta.host = parsed.host;
    if (!allowed.has(parsed.host)) return deny(res, 403, 'host-not-allowlisted', meta);

    const chunks = [];
    let size = 0;
    req.on('data', (c) => {
      size += c.length;
      if (size <= MAX_BODY_BYTES) chunks.push(c);
    });
    req.on('end', () => {
      if (size > MAX_BODY_BYTES) return deny(res, 413, 'body-too-large', meta);
      const body = Buffer.concat(chunks).toString('utf8');
      const verdict = inspect({ rawTarget: parsed.rawTarget, body, contentType: req.headers['content-type'] ?? '' }, rules);
      if (!verdict.allowed) return deny(res, 403, 'pattern-match', meta, { rule: verdict.rule, field: verdict.field });

      const upstream = resolve(parsed.host);
      if (!upstream) return deny(res, 502, 'unresolvable-host', meta);

      const headers = { ...req.headers, host: parsed.host };
      delete headers['proxy-connection'];
      if (body) headers['content-length'] = Buffer.byteLength(body);

      const up = http.request({ host: upstream.host, port: upstream.port, method: req.method, path: parsed.rawTarget, headers }, (upRes) => {
        write({ ...meta, decision: 'allow', status: upRes.statusCode });
        res.writeHead(upRes.statusCode, { ...upRes.headers, 'x-guard-decision': 'allow' });
        upRes.pipe(res);
      });
      up.on('error', (err) => deny(res, 502, 'upstream-error', meta, { error: err.code ?? String(err) }));
      up.end(body || undefined);
    });
  });

  // CONNECT never reaches the request handler; refuse it here.
  server.on('connect', (req, socket) => {
    write({ testId: req.headers['x-test-id'] ?? null, runId: req.headers['x-run-id'] ?? null, method: 'CONNECT', target: req.url, decision: 'block', status: 405, reason: 'tls-tunnel-not-inspectable' });
    socket.end('HTTP/1.1 405 Method Not Allowed\r\nx-guard-reason: tls-tunnel-not-inspectable\r\n\r\n');
  });

  const close = () => new Promise((r) => server.close(() => log.end(r)));
  return { server, close };
}
