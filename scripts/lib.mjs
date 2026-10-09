import fs from 'node:fs';
import crypto from 'node:crypto';

export const CATEGORIES = ['benign', 'injection', 'probe', 'off-allowlist'];

/** SHA-256 of a text file with line endings normalized to LF. */
export function sha256File(path) {
  const text = fs.readFileSync(path, 'utf8').replace(/\r\n/g, '\n');
  return crypto.createHash('sha256').update(text).digest('hex');
}

export function readJsonl(path) {
  return fs
    .readFileSync(path, 'utf8')
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter(Boolean)
    .map((l, i) => {
      try {
        return JSON.parse(l);
      } catch (e) {
        throw new Error(`${path} line ${i + 1}: ${e.message}`);
      }
    });
}

export function writeJsonl(path, rows) {
  fs.writeFileSync(path, rows.map((r) => JSON.stringify(r)).join('\n') + '\n');
}

/** Check that a request list is well formed. Returns a list of problems. */
export function validateRequests(rows) {
  const problems = [];
  const ids = new Set();
  for (const r of rows) {
    const where = `request ${r.id ?? '(no id)'}`;
    if (!r.id || typeof r.id !== 'string') problems.push(`${where}: missing id`);
    else if (ids.has(r.id)) problems.push(`${where}: duplicate id`);
    else ids.add(r.id);
    if (!CATEGORIES.includes(r.category)) problems.push(`${where}: unknown category ${r.category}`);
    if (!['GET', 'HEAD', 'POST'].includes(r.method)) problems.push(`${where}: method must be GET, HEAD or POST`);
    if (typeof r.url !== 'string' || !/^http:\/\/[\x21-\x7e]+$/.test(r.url)) problems.push(`${where}: url must start with http:// and use only printable ASCII (percent-encode everything else)`);
    if (r.body != null && typeof r.body !== 'string') problems.push(`${where}: body must be a string or null`);
    if (r.method !== 'POST' && r.body) problems.push(`${where}: only POST requests may have a body`);
  }
  return problems;
}

/** Seeded PRNG (mulberry32) so the split can be reproduced exactly. */
export function prng(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

export function timestamp(d = new Date()) {
  const p = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}${p(d.getMonth() + 1)}${p(d.getDate())}-${p(d.getHours())}${p(d.getMinutes())}${p(d.getSeconds())}`;
}
