// Run one request set through the guard and score it against the
// preregistered criteria.
//
//   node scripts/eval.mjs --set tuning --rules v0
//   node scripts/eval.mjs --set heldout --rules v1
//
// Starts both test sites and the guard on local ports, sends every request
// through the guard, then scores what each site's own log says it received.
// Results go to results/<run-id>/.
//
// The held-out set can be scored once. A second held-out run is refused unless
// --posthoc is passed, and is then labelled post-hoc everywhere.

import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { createGuard, parseTarget } from '../guard/guard.mjs';
import { createArchiveSite, createOutsideSite } from '../sites/sites.mjs';
import { CATEGORIES, readJsonl, validateRequests, sha256File, timestamp } from './lib.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const args = process.argv.slice(2);
const arg = (name, fallback) => (args.includes(name) ? args[args.indexOf(name) + 1] : fallback);
const setName = arg('--set');
const rulesVersion = arg('--rules', 'v0');
const posthoc = args.includes('--posthoc');

// Preregistered thresholds (held-out set). See PREREGISTRATION.md.
const CRITERIA = {
  injectionReached: { max: 0, label: 'injection requests that reached archive.test' },
  offAllowlistReached: { max: 0, label: 'off-allowlist requests that reached outside.test' },
  benignBlockedRate: { max: 0.05, label: 'share of benign requests blocked' },
};

if (!setName) {
  console.error('Usage: node scripts/eval.mjs --set <smoke|tuning|heldout> [--rules v0] [--posthoc]');
  process.exit(1);
}

const requestsPath = path.join(root, 'requests', `${setName}.jsonl`);
const rulesPath = path.join(root, 'guard', `rules-${rulesVersion}.mjs`);
for (const p of [requestsPath, rulesPath]) {
  if (!fs.existsSync(p)) {
    console.error(`Not found: ${path.relative(root, p)}`);
    process.exit(1);
  }
}

const resultsDir = path.join(root, 'results');
fs.mkdirSync(resultsDir, { recursive: true });

if (setName === 'heldout') {
  const prior = fs
    .readdirSync(resultsDir)
    .map((d) => path.join(resultsDir, d, 'meta.json'))
    .filter((p) => fs.existsSync(p))
    .map((p) => JSON.parse(fs.readFileSync(p, 'utf8')))
    .filter((m) => m.set === 'heldout');
  if (prior.length && !posthoc) {
    console.error(`The held-out set was already scored (run ${prior[0].runId}). A second run must be labelled: add --posthoc.`);
    process.exit(1);
  }
}

const requests = readJsonl(requestsPath);
const problems = validateRequests(requests);
if (problems.length) {
  console.error(problems.join('\n'));
  process.exit(1);
}

const { rules } = await import(pathToFileURL(rulesPath).href);
const runId = `${timestamp()}-${setName}-${rulesVersion}${posthoc ? '-posthoc' : ''}`;
const runDir = path.join(resultsDir, runId);
const logDir = path.join(runDir, 'logs');
fs.mkdirSync(logDir, { recursive: true });

// ---- start the sites and the guard -------------------------------------
const listen = (server) => new Promise((r) => server.listen(0, '127.0.0.1', () => r(server.address().port)));

const archive = createArchiveSite({ logPath: path.join(logDir, 'archive.jsonl') });
const outside = createOutsideSite({ logPath: path.join(logDir, 'outside.jsonl') });
const archivePort = await listen(archive.server);
const outsidePort = await listen(outside.server);

// Test-only resolver: the two fictional sites are the only names that resolve.
// Anything ending in outside.test goes to the outside site, so tricks such as
// archive.test.outside.test are caught by that site's log if the guard lets them out.
const resolve = (host) => {
  const h = host.replace(/:\d+$/, '');
  if (h === 'archive.test') return { host: '127.0.0.1', port: archivePort };
  if (h === 'outside.test' || h.endsWith('.outside.test')) return { host: '127.0.0.1', port: outsidePort };
  return null;
};

const guard = createGuard({ allowlist: ['archive.test'], resolve, rules, rulesVersion, logPath: path.join(logDir, 'guard.jsonl') });
const guardPort = await listen(guard.server);

// ---- send every request through the guard -------------------------------
function send(r) {
  return new Promise((done) => {
    const target = parseTarget(r.url);
    const headers = { host: target?.host ?? 'unknown', 'x-test-id': r.id, 'x-run-id': runId };
    if (r.body) {
      headers['content-type'] = r.contentType ?? 'application/x-www-form-urlencoded';
      headers['content-length'] = Buffer.byteLength(r.body);
    }
    const req = http.request({ host: '127.0.0.1', port: guardPort, method: r.method, path: r.url, headers, agent: false, timeout: 5000 }, (res) => {
      res.resume();
      res.on('end', () => done({ status: res.statusCode, guardDecision: res.headers['x-guard-decision'] ?? null }));
    });
    req.on('timeout', () => req.destroy(new Error('timeout')));
    req.on('error', (err) => done({ status: null, error: err.message }));
    req.end(r.body || undefined);
  });
}

const client = new Map();
for (const r of requests) client.set(r.id, await send(r));

await guard.close();
await archive.close();
await outside.close();

// ---- score from the sites' own logs -------------------------------------
const readLog = (name) => (fs.existsSync(path.join(logDir, name)) ? readJsonl(path.join(logDir, name)).filter((e) => e.runId === runId) : []);
const archiveSeen = new Set(readLog('archive.jsonl').map((e) => e.testId));
const outsideSeen = new Set(readLog('outside.jsonl').map((e) => e.testId));
const guardLog = new Map(readLog('guard.jsonl').map((e) => [e.testId, e]));

const rows = requests.map((r) => {
  const g = guardLog.get(r.id) ?? {};
  const reachedArchive = archiveSeen.has(r.id);
  const reachedOutside = outsideSeen.has(r.id);
  let outcome;
  if (r.category === 'benign') outcome = reachedArchive ? 'ok' : 'false-block';
  else if (r.category === 'injection') outcome = reachedArchive ? 'miss' : 'ok';
  else if (r.category === 'off-allowlist') outcome = reachedOutside ? 'miss' : 'ok';
  else outcome = reachedArchive ? 'reached' : 'blocked';
  return {
    id: r.id,
    category: r.category,
    method: r.method,
    url: r.url,
    outcome,
    reachedArchive,
    reachedOutside,
    guardDecision: g.decision ?? null,
    reason: g.reason ?? null,
    rule: g.rule ?? null,
    field: g.field ? `${g.field.where}${g.field.name ? ':' + g.field.name : ''}` : null,
    status: client.get(r.id)?.status ?? null,
    error: client.get(r.id)?.error ?? null,
    note: r.note ?? '',
  };
});

const by = (cat) => rows.filter((r) => r.category === cat);
const benign = by('benign');
const metrics = {
  injectionReached: by('injection').filter((r) => r.outcome === 'miss').length,
  offAllowlistReached: by('off-allowlist').filter((r) => r.outcome === 'miss').length,
  benignBlockedRate: benign.length ? benign.filter((r) => r.outcome === 'false-block').length / benign.length : 0,
};
const checks = Object.entries(CRITERIA).map(([k, c]) => ({ key: k, ...c, value: metrics[k], pass: metrics[k] <= c.max }));
const pass = checks.every((c) => c.pass);

// ---- write results -------------------------------------------------------
const meta = {
  runId,
  set: setName,
  rules: rulesVersion,
  posthoc,
  rulesSha256: sha256File(rulesPath),
  requestsSha256: sha256File(requestsPath),
  node: process.version,
  finishedAt: new Date().toISOString(),
  counts: Object.fromEntries(CATEGORIES.map((c) => [c, by(c).length])),
  metrics,
  pass,
};
fs.writeFileSync(path.join(runDir, 'meta.json'), JSON.stringify(meta, null, 2) + '\n');

const csvCell = (v) => (v == null ? '' : /[",\n]/.test(String(v)) ? `"${String(v).replace(/"/g, '""')}"` : String(v));
const cols = ['id', 'category', 'outcome', 'reason', 'rule', 'field', 'status', 'method', 'url', 'note'];
fs.writeFileSync(path.join(runDir, 'decisions.csv'), [cols.join(','), ...rows.map((r) => cols.map((c) => csvCell(r[c])).join(','))].join('\n') + '\n');

const pct = (x) => `${(x * 100).toFixed(1)}%`;
const fmt = (c) => (c.key === 'benignBlockedRate' ? `${pct(c.value)} (${benign.filter((r) => r.outcome === 'false-block').length} of ${benign.length})` : String(c.value));
const fmtMax = (c) => (c.key === 'benignBlockedRate' ? `at most ${pct(c.max)}` : `at most ${c.max}`);
const md = (s) => String(s ?? '').replace(/\|/g, '\\|');
const list = (items) => (items.length ? items.map((r) => `| ${r.id} | ${md(r.rule ?? r.reason ?? r.error ?? '')} | ${md(r.field ?? '')} | \`${md(r.url)}\` | ${md(r.note)} |`).join('\n') : '| none | | | | |');

const ruleCounts = {};
for (const r of rows.filter((x) => x.rule)) {
  ruleCounts[r.rule] ??= Object.fromEntries(CATEGORIES.map((c) => [c, 0]));
  ruleCounts[r.rule][r.category]++;
}

const label = setName === 'heldout' ? (posthoc ? 'held-out set, POST-HOC re-run (not the headline result)' : 'held-out set (headline result)') : `${setName} set (not the headline result)`;
const summary = `# ${runId}

- Set: ${label}
- Rules: ${rulesVersion} (SHA-256 ${meta.rulesSha256.slice(0, 16)}...)
- Requests: ${requests.length} (${CATEGORIES.map((c) => `${c} ${meta.counts[c]}`).join(', ')}), SHA-256 ${meta.requestsSha256.slice(0, 16)}...
- Measured from each site's own request log.

## Preregistered criteria

| Criterion | Result | Threshold | |
| --- | --- | --- | --- |
${checks.map((c) => `| ${c.label} | ${fmt(c)} | ${fmtMax(c)} | ${c.pass ? 'pass' : 'FAIL'} |`).join('\n')}

**Overall: ${pass ? 'PASS' : 'FAIL'}**${setName === 'heldout' && !posthoc ? '' : ' (only the first held-out run counts as the result)'}

## False blocks (benign requests that did not reach the site)

| id | rule or reason | field | url | note |
| --- | --- | --- | --- | --- |
${list(rows.filter((r) => r.outcome === 'false-block'))}

## Misses (attack-like requests that got through)

| id | rule or reason | field | url | note |
| --- | --- | --- | --- | --- |
${list(rows.filter((r) => r.outcome === 'miss'))}

## Probes (reported, not scored)

Reached the site: ${by('probe').filter((r) => r.outcome === 'reached').length} of ${by('probe').length}

| id | outcome | rule or reason | url | note |
| --- | --- | --- | --- | --- |
${by('probe').length ? by('probe').map((r) => `| ${r.id} | ${r.outcome} | ${md(r.rule ?? r.reason ?? '')} | \`${md(r.url)}\` | ${md(r.note)} |`).join('\n') : '| none | | | | |'}

## Blocks by rule

| rule | ${CATEGORIES.join(' | ')} |
| --- | ${CATEGORIES.map(() => '---').join(' | ')} |
${Object.keys(ruleCounts).length ? Object.entries(ruleCounts).map(([rule, c]) => `| ${rule} | ${CATEGORIES.map((k) => c[k]).join(' | ')} |`).join('\n') : `| none | ${CATEGORIES.map(() => '').join(' | ')} |`}
`;
fs.writeFileSync(path.join(runDir, 'summary.md'), summary);

console.log(`Run ${runId}: ${pass ? 'PASS' : 'FAIL'}`);
for (const c of checks) console.log(`  ${c.pass ? 'pass' : 'FAIL'}  ${c.label}: ${fmt(c)} (${fmtMax(c)})`);
console.log(`  probes that reached the site: ${by('probe').filter((r) => r.outcome === 'reached').length} of ${by('probe').length}`);
console.log(`Details: ${path.relative(root, path.join(runDir, 'summary.md'))}`);
