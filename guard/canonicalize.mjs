// Turn a raw request into the fields the rules inspect.
//
// Attackers (and agents retrying after a failure) change encodings, so every
// field is decoded repeatedly until it stops changing. Transluce's report
// includes a double-encoded "<" (%253C), which a single decode would miss.

const MAX_DECODE_PASSES = 4;

const NAMED_ENTITIES = { lt: '<', gt: '>', quot: '"', apos: "'", amp: '&', sol: '/', colon: ':' };

/** Decode %XX sequences once. Invalid sequences are left as they are. */
function percentDecodeOnce(s) {
  return s.replace(/(?:%[0-9a-fA-F]{2})+/g, (run) => {
    try {
      return decodeURIComponent(run);
    } catch {
      // Not valid UTF-8: decode byte by byte as Latin-1 so nothing is hidden.
      return run.replace(/%([0-9a-fA-F]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));
    }
  });
}

/** Decode a few HTML entities: &lt; &#60; &#x3c; and similar. */
function entityDecodeOnce(s) {
  return s
    .replace(/&#x([0-9a-f]+);?/gi, (_, h) => String.fromCodePoint(parseInt(h, 16)))
    .replace(/&#([0-9]+);?/g, (_, d) => String.fromCodePoint(parseInt(d, 10)))
    .replace(/&([a-z]+);/gi, (m, name) => NAMED_ENTITIES[name.toLowerCase()] ?? m);
}

/**
 * Fully decode one field and normalize it for matching.
 * Returns { value, passes } where passes is how many decode rounds changed it.
 */
export function canonicalize(raw, { plusIsSpace = false } = {}) {
  let s = String(raw ?? '');
  if (plusIsSpace) s = s.replace(/\+/g, ' ');
  let passes = 0;
  for (let i = 0; i < MAX_DECODE_PASSES; i++) {
    const next = entityDecodeOnce(percentDecodeOnce(s));
    if (next === s) break;
    s = next;
    passes++;
  }
  // NFKC folds look-alike characters, for example a full-width "＜" into "<".
  s = s.normalize('NFKC').toLowerCase();
  return { value: s, passes };
}

/** Split "a=1&b=2" into [{name, value}], keeping raw (undecoded) text. */
function splitPairs(qs) {
  if (!qs) return [];
  return qs.split('&').filter(Boolean).map((pair) => {
    const i = pair.indexOf('=');
    return i === -1 ? { name: pair, value: '' } : { name: pair.slice(0, i), value: pair.slice(i + 1) };
  });
}

/**
 * Break a request into named fields for inspection.
 * rawTarget is the path and query exactly as sent, for example "/Search?q=O%27Brien".
 */
export function extractFields({ rawTarget, body = '', contentType = '' }) {
  const fields = [];
  const q = rawTarget.indexOf('?');
  const rawPath = q === -1 ? rawTarget : rawTarget.slice(0, q);
  const rawQuery = q === -1 ? '' : rawTarget.slice(q + 1);

  fields.push({ where: 'path', name: '', raw: rawPath, ...canonicalize(rawPath) });
  for (const p of splitPairs(rawQuery)) {
    fields.push({ where: 'query-name', name: p.name, raw: p.name, ...canonicalize(p.name, { plusIsSpace: true }) });
    fields.push({ where: 'query', name: p.name, raw: p.value, ...canonicalize(p.value, { plusIsSpace: true }) });
  }
  if (body) {
    if (/application\/x-www-form-urlencoded/i.test(contentType)) {
      for (const p of splitPairs(body)) {
        fields.push({ where: 'body-name', name: p.name, raw: p.name, ...canonicalize(p.name, { plusIsSpace: true }) });
        fields.push({ where: 'body', name: p.name, raw: p.value, ...canonicalize(p.value, { plusIsSpace: true }) });
      }
    } else {
      fields.push({ where: 'body', name: '', raw: body, ...canonicalize(body) });
    }
  }
  return fields;
}
