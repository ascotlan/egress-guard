# egress-guard

A small egress guard for AI agents, and a preregistered test of how well it works.

The guard is an HTTP forward proxy that sits between an agent and the network. Each request passes three checks:

1. **Method.** `CONNECT` is refused, because an HTTPS tunnel cannot be inspected without terminating TLS.
2. **Host.** The destination must be on an allowlist.
3. **Content.** No field in the path, query or body may match an injection rule, after repeated decoding.

Every decision is appended to a JSONL log.

The test runs entirely on your machine. Two fictional sites, `archive.test` and `outside.test`, listen on `127.0.0.1`, and the guard can resolve only those two names, so no request can reach a real website.

## Requirements

Node.js 20 or later. There are no dependencies to install.

## Layout

```
guard/       canonicalize.mjs, guard.mjs, rules-v0.mjs (frozen), rules-v1.mjs (tuned, once it exists)
sites/       the two local test sites; each logs every request it receives
requests/    smoke.jsonl, all.jsonl, and the tuning.jsonl / heldout.jsonl split
scripts/     eval.mjs (run and score), split.mjs (seeded split), lib.mjs
results/     one folder per scored run: summary.md, decisions.csv, meta.json, logs/
test/        unit tests with hand-written examples
```

## Running it

```
npm test                                      # unit tests
npm run smoke                                 # plumbing check, not evidence
node scripts/split.mjs --seed 20261010        # once, after all.jsonl is final
node scripts/eval.mjs --set tuning --rules v0 # baseline on the tuning set
node scripts/eval.mjs --set tuning --rules v1 # after tuning (copy v0 to v1 first)
node scripts/eval.mjs --set heldout --rules v1 # once: the headline result
```

"Reached the site" is scored from each site's own log, not from the guard's log. A second held-out run is refused unless you pass `--posthoc`, and it is then labelled post-hoc in its results.

## Method

See [PREREGISTRATION.md](PREREGISTRATION.md) for the pass criteria, the split and the limits, all written before the first scored run.
