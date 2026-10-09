// Split requests/all.jsonl into requests/tuning.jsonl and requests/heldout.jsonl,
// half of each category in each, using a fixed seed.
//
//   node scripts/split.mjs --seed 20261010
//
// Refuses to overwrite an existing split, so the held-out set cannot be
// reshuffled by accident after tuning has started.

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { CATEGORIES, readJsonl, writeJsonl, validateRequests, prng, sha256File } from './lib.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const args = process.argv.slice(2);
const seedArg = args[args.indexOf('--seed') + 1];
const seed = Number.parseInt(seedArg, 10);
if (!args.includes('--seed') || !Number.isFinite(seed)) {
  console.error('Usage: node scripts/split.mjs --seed <integer>');
  process.exit(1);
}

const allPath = path.join(root, 'requests', 'all.jsonl');
const tuningPath = path.join(root, 'requests', 'tuning.jsonl');
const heldoutPath = path.join(root, 'requests', 'heldout.jsonl');

if ((fs.existsSync(tuningPath) || fs.existsSync(heldoutPath)) && !args.includes('--force')) {
  console.error('A split already exists. Refusing to overwrite it. (Use --force only if no scored run has happened yet.)');
  process.exit(1);
}

const rows = readJsonl(allPath);
const problems = validateRequests(rows);
if (problems.length) {
  console.error(problems.join('\n'));
  process.exit(1);
}

const rand = prng(seed);
const tuning = [];
const heldout = [];
for (const cat of CATEGORIES) {
  const group = rows.filter((r) => r.category === cat);
  // Fisher-Yates shuffle with the seeded PRNG.
  for (let i = group.length - 1; i > 0; i--) {
    const j = Math.floor(rand() * (i + 1));
    [group[i], group[j]] = [group[j], group[i]];
  }
  const half = Math.ceil(group.length / 2);
  tuning.push(...group.slice(0, half));
  heldout.push(...group.slice(half));
}

writeJsonl(tuningPath, tuning);
writeJsonl(heldoutPath, heldout);

const count = (set) => CATEGORIES.map((c) => `${c}=${set.filter((r) => r.category === c).length}`).join(', ');
console.log(`Seed: ${seed}`);
console.log(`Tuning:   ${tuning.length} requests (${count(tuning)})`);
console.log(`Held-out: ${heldout.length} requests (${count(heldout)})`);
console.log(`requests/all.jsonl     SHA-256: ${sha256File(allPath)}`);
console.log(`requests/tuning.jsonl  SHA-256: ${sha256File(tuningPath)}`);
console.log(`requests/heldout.jsonl SHA-256: ${sha256File(heldoutPath)}`);
console.log('Copy the seed and the hashes into PREREGISTRATION.md, then commit before any scored run.');
