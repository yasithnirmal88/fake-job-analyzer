// tests/providers-http-coverage.test.mjs — every provider talks to the network
// through the SSRF-guarded transport in providers/_http.mjs, never through the
// global fetch() (Node's undici) or an imported http/net module.
//
// Why this is a scan rule and not a review rule: providers/_ip-guard.mjs's
// address guard is *scoped*, not global. It runs inside a providerFetchContext
// established by _http.mjs's fetch helpers (fetchJson / fetchText /
// fetchResponse / the *WithRetry variants) — and scan.mjs hands every provider
// a ctx object built from those helpers (makeHttpCtx) so `ctx.fetchJson(url, …)`
// is guarded without the provider importing _http.mjs at all. A provider that
// calls the GLOBAL fetch bypasses that context entirely: the guard never runs,
// and the blocklist in _ip-guard.mjs is dead. The guard is deliberately
// scoped rather than global because _dns-cache.mjs patches node:dns
// process-wide, and loopback has to keep working for everything that is not a
// provider fetch (_http.mjs header). So a single raw fetch() call is a real
// SSRF hole, not a style mismatch — it is exactly the "scrape a job listing"
// line that resolves to 169.254.169.254 or ::1 and exfiltrates the metadata
// endpoint the guard exists to block.
//
// Why not an import check: `from './_http.mjs'` is not proof of a guarded
// transport. consider.mjs imports only BROWSER_LIKE_USER_AGENT from _http.mjs
// and still calls the global fetch() in its CSRF handshake — the import is for
// a constant, not for the transport, and the raw call is unflagged by any
// import-based rule. The converse is the norm: greenhouse.mjs imports nothing
// from _http.mjs and is fully guarded because every request goes through
// ctx.fetchJson(…). The rule is therefore about the CALL, with an import being
// neither necessary nor sufficient.
//
// What gets scanned: providers/*.mjs whose name does NOT begin with an
// underscore — the repo's documented provider/helper boundary ("Files prefixed
// with _ are never loaded as providers by scan.mjs", _http.mjs header). The
// underscore files are the guard itself and its shared pieces; _http.mjs's own
// raw fetch (line ~126) is the guarded transport, not a bypass in a provider.
//
// Current findings (2026-10-07): 104 providers scanned, of which 1 call the
// global fetch() — consider.mjs:96. The suite FAILS until that call is routed
// through the guarded transport; migrators please read providers/ADDING_A_PROVIDER.md
// and tests/providers/ats-ssrf-hardening.test.mjs.
//
// Deliberately a pass/fail suite (not node:test, no framework, no network, no
// process.exit): test-all.mjs discovers tests/**/*.test.mjs by glob and runs
// the file in-process, sharing the counters from ./helpers.mjs.
import { readdirSync, readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { pass, fail, codeMask } from './helpers.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const PROVIDERS_DIR = join(ROOT, 'providers');

// The guarded transport lives at providers/_http.mjs. Its helpers are fetched
// through ctx (fetchJson / fetchText / fetchResponse / fetchTextHead and the
// *WithRetry variants) or imported directly from _http.mjs; either way the call
// runs inside the providerFetchContext that arms providers/_ip-guard.mjs.
const HTTP_GUARD_MODULE = './_http.mjs';

// The documented convention: a leading underscore marks a shared helper, not a
// provider, and scan.mjs never loads those as providers (_http.mjs header).
const isScannedProviderFile = (name) => name.endsWith('.mjs') && !name.startsWith('_');

// Global fetch reachable as `globalThis.fetch(…)` (or cheap aliases) is the
// same bypass as a bare `fetch(…)` — still no providerFetchContext. Anything
// else reached through `.fetch(…)` is a method on some object (ctx, this, a
// Response-like body) and is not a raw transport call.
const GLOBAL_FETCH_RECEIVERS = new Set(['globalThis', 'self', 'global', 'window']);

// Importing undici's fetch, or a raw node:http(s) client, opens a second
// channel past the guard even if no call site spells it `fetch(`.
const RAW_TRANSPORT_IMPORTS = [
  /import\s*\{[^}]*\bfetch\b[^}]*\}\s*from\s*['"]undici['"]/,
  /import\s*['"][^'"]*node:https?['"]/, /import\s*['"][^'"]*node:net['"]/,
];

/**
 * Classify the `fetch(` tokens in `src` that are code (not comment / string /
 * template text) and return the raw global-fetch call sites.
 *
 * Excluded by construction:
 *  - the provider's own entry point: `async fetch(entry, ctx) {` / `fetch(…) {`
 *    / `fetch(…) =>` — the method scan.mjs calls, which is not a network call;
 *  - property dispatch `obj.fetch(…)` unless the receiver is a documented
 *    global alias of the global fetch (globalThis/self/global/window);
 *  - everything inside comments, string literals and template text, via the
 *    shared codeMask (tests/helpers.mjs).
 *
 * A lone `fetch(url)` (or `await fetch(url)`, `return fetch(url)`,
 * `globalThis.fetch(url)`) therefore survives as a violation.
 *
 * @param {string} src - Provider source text.
 * @param {boolean[]} mask - codeMask(src); true means code.
 * @returns {number[]} 1-based line numbers of raw global fetch() calls.
 */
function rawFetchCallLines(src, mask) {
  const lines = [];
  const re = /\bfetch\s*\(/g;
  let m;
  while ((m = re.exec(src))) {
    const at = m.index;
    const width = m[0].length;
    if (!mask.slice(at, at + width).every(Boolean)) continue;
    // Property dispatch? Walk back over `fetch` to see what precedes it.
    let back = at - 1;
    while (back >= 0 && /[\s]/.test(src[back])) back--;
    if (back >= 0 && src[back] === '.') {
      let receiverEnd = back - 1;
      if (receiverEnd >= 0 && src[receiverEnd] === '?') receiverEnd--; // `?.fetch`
      let receiverStart = receiverEnd;
      while (receiverStart >= 0 && /[A-Za-z0-9_$]/.test(src[receiverStart])) receiverStart--;
      const receiver = src.slice(receiverStart + 1, receiverEnd + 1);
      if (GLOBAL_FETCH_RECEIVERS.has(receiver)) lines.push(src.slice(0, at).split('\n').length);
      continue;
    }
    // Method/function definition? Advance to the matching close paren; a
    // definition is the one shape whose next token after it is `{` or `=>`.
    let k = at + width;
    let depth = 1;
    while (k < src.length && depth > 0) {
      const c = src[k];
      if (c === '(' || c === '[' || c === '{') depth++;
      else if (c === ')' || c === ']' || c === '}') depth--;
      k++;
    }
    while (k < src.length && /\s/.test(src[k])) k++;
    if (src[k] === '{' || src.slice(k, k + 2) === '=>') continue;
    lines.push(src.slice(0, at).split('\n').length);
  }
  return lines;
}

// ── self-test controls ──────────────────────────────────────────────────────
// Without these, a regression in rawFetchCallLines could report zero offenders
// on an offending tree and the suite would pass on a silent absence — the same
// vacuum this file exists to close. Each fixture uses the real detector.
function classify(...snippets) {
  const src = snippets.join('\n');
  const fires = [];
  for (const re of RAW_TRANSPORT_IMPORTS) if (re.test(src)) fires.push(`raw transport import (${re})`);
  return [...fires, ...rawFetchCallLines(src, codeMask(src))];
}

const controlCases = [
  ['const res = await fetch(url, { redirect: "error" });', 1, 'a plain global fetch() call'],
  ['return fetch(url).then(r => r.json());', 1, 'a fetch() call in an expression'],
  ['async fetch(entry, ctx) {', 0, 'the provider entry-point method definition'],
  ['fetch(entry, ctx) {', 0, 'a non-async method definition'],
  ['ctx.fetchJson(url, { redirect: "error" });', 0, 'the guarded ctx transport'],
  ['ctx.fetchText(url);', 0, 'the guarded ctx transport (text)'],
  ['ctx.fetch(url);', 0, 'property dispatch through ctx (no such helper today, but not global)'],
  ['throw new Error(`fetch(${url})`);', 0, 'fetch inside a template literal'],
  ['// fetch(url) must stay untouched\nconst a = 1;', 0, 'fetch mentioned in a comment'],
  ['await globalThis.fetch(url);', 1, 'globalThis.fetch bypass'],
];
for (const [fixture, expected, what] of controlCases) {
  const found = classify(fixture);
  found.length === expected
    ? pass(`provider-http-coverage control: ${what}`)
    : fail(`provider-http-coverage control broke: expected ${expected} raw fetch for \`${fixture.trim()}\`, got ${found.length}`);
}
{
  const found = classify(`import { fetch } from 'undici';`);
  found.length === 1
    ? pass('provider-http-coverage control: undici fetch binding is a raw transport')
    : fail(`provider-http-coverage control broke: undici fetch expected 1 raw transport, got ${found.length}`);
}

// ── the scan ────────────────────────────────────────────────────────────────
const providerFiles = readdirSync(PROVIDERS_DIR).filter(isScannedProviderFile).sort();
if (providerFiles.length < 50) {
  fail(`provider-http-coverage: expected to scan the provider tree, found only ${providerFiles.length} provider files`);
} else {
  const offenders = []; // {file, lines, why}
  let guardedImporters = 0;
  let ctxRouted = 0;
  for (const file of providerFiles) {
    const src = readFileSync(join(PROVIDERS_DIR, file), 'utf8');
    const lines = rawFetchCallLines(src, codeMask(src));
    const fires = [];
    for (const re of RAW_TRANSPORT_IMPORTS) if (re.test(src)) fires.push(`raw transport import ${re}`);
    if (/from\s*['"]\.\/_http\.mjs['"]/.test(src)) guardedImporters++;
    else if (/ctx\.fetch[A-Za-z]*\(/.test(src)) ctxRouted++;
    if (lines.length > 0 || fires.length > 0) {
      offenders.push({ file, lines, fires });
    }
  }
  for (const o of offenders) {
    for (const n of o.lines) {
      fail(`${o.file}:${n} calls the global fetch() — route it through ctx.fetchJson/ctx.fetchText (providers/_http.mjs guarded transport) or import a fetch helper from ./_http.mjs`);
    }
    for (const why of o.fires) {
      fail(`${o.file} uses ${why} — same SSRF gap as a raw global fetch(); use the guarded transport in providers/_http.mjs`);
    }
  }
  if (offenders.length === 0) {
    pass(`all ${providerFiles.length} providers route network calls through the ${HTTP_GUARD_MODULE} guarded transport`);
  } else {
    const names = offenders.map((o) => `${o.file}:${o.lines.join(',')}`).join(', ');
    fail(`providers-http-coverage: ${offenders.length} provider file(s) bypass the SSRF guard — ${names}. Migrate them through providers/_http.mjs (see providers/ADDING_A_PROVIDER.md); the suite stays red until the raw fetch() is gone.`);
  }
  console.log(`  — scanned ${providerFiles.length} providers: ${guardedImporters} import ${HTTP_GUARD_MODULE}, ${ctxRouted} route via the ctx transport, ${offenders.length} call the global fetch(); ${providerFiles.length - guardedImporters - ctxRouted - offenders.length} make no guarded HTTP call in their own file`);
}