// Unit tests for the decoding and the guard's checks. These use hand-written
// examples only, never the tuning or held-out sets.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { canonicalize } from '../guard/canonicalize.mjs';
import { parseTarget, inspect, createGuard } from '../guard/guard.mjs';
import { rules } from '../guard/rules-v0.mjs';

test('decodes double encoding, as in the %253C probe Transluce reported', () => {
  assert.equal(canonicalize('%253Cscript%253E').value, '<script>');
});

test('folds full-width look-alikes and HTML entities', () => {
  assert.equal(canonicalize('＜script＞').value, '<script>');
  assert.equal(canonicalize('&lt;svg&#x3e;').value, '<svg>');
});

test('leaves invalid percent sequences visible instead of failing', () => {
  assert.equal(canonicalize('100%zz').value, '100%zz');
});

test('parseTarget finds the real host behind a userinfo trick', () => {
  assert.equal(parseTarget('http://archive.test@outside.test/x').host, 'outside.test');
  assert.equal(parseTarget('http://ARCHIVE.test:80/Search?q=a').host, 'archive.test');
  assert.equal(parseTarget('http://archive.test?q=a').rawTarget, '/?q=a');
});

test('v0 rules block classic payloads and pass a plain search', () => {
  const check = (rawTarget) => inspect({ rawTarget }, rules).allowed;
  assert.equal(check('/Record?IdNumber=1%20OR%201%3D1'), false);
  assert.equal(check("/Search?q=x'%20or%20'1'='1"), false);
  assert.equal(check('/files/..%2F..%2Fetc%2Fpasswd'), false);
  assert.equal(check('/Search?q=Halifax+1905'), true);
});

test('guard refuses hosts off the allowlist and HTTPS tunnels', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'egress-guard-'));
  const guard = createGuard({ allowlist: ['archive.test'], resolve: () => null, rules, rulesVersion: 'v0', logPath: path.join(dir, 'guard.jsonl') });
  await new Promise((r) => guard.server.listen(0, '127.0.0.1', r));
  const port = guard.server.address().port;

  const status = await new Promise((done) => {
    http.get({ host: '127.0.0.1', port, path: 'http://outside.test/', headers: { host: 'outside.test' }, agent: false }, (res) => {
      res.resume();
      done(res.headers['x-guard-reason']);
    });
  });
  assert.equal(status, 'host-not-allowlisted');

  const tunnel = await new Promise((done) => {
    const req = http.request({ host: '127.0.0.1', port, method: 'CONNECT', path: 'archive.test:443', agent: false });
    req.on('connect', (res, socket) => {
      socket.destroy();
      done(res.statusCode);
    });
    req.on('error', () => done('error'));
    req.end();
  });
  assert.equal(tunnel, 405);

  await guard.close();
});
