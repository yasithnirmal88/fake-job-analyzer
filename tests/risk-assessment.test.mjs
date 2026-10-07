// tests/risk-assessment.test.mjs — structural pins for the Risk Assessment
// feature layer (Risk Assessment → Employer Verification → Recommended
// Actions → Risk Summary).
//
// The feature lives entirely in prose files that an AI reads at evaluation
// time (modes/_shared.md, modes/oferta.md, batch/batch-prompt.md) — there is
// no code path to unit-test, so the drift hazard
// pipeline-output-format-parity.test.mjs documents for cv.output_format
// applies here in full: files that must agree, and nothing but this check
// keeping them aligned. Six contracts are pinned:
//
//   1. Report order — the report template in modes/oferta.md and the heading
//      list in batch/batch-prompt.md must both present G → Risk Assessment →
//      Employer Verification → Recommended Actions → Risk Summary, adjacent
//      and in that order. Batch workers append sections by that list; a
//      reordered or missing heading makes batch reports read differently
//      from interactive ones.
//   2. Indicator tables — the 16 severity-graded IDs (C1–C4, H1–H5, M1–M4,
//      L1–L3), each under its severity heading with an indicator, an evidence
//      source, and valid category cells. H6 (WhatsApp/Telegram move-to-channel)
//      was explicitly deferred and must not appear, in tables or prose.
//   3. Determination rules — the ordered, first-match-wins ladder that turns
//      fired indicators into the Overall Risk Level. Pinned as text (so a
//      rule edit fails here first) AND re-executed below over synthetic
//      fired sets: determineLevel() mirrors _shared.md's seven rules, and
//      the two must change together.
//   4. Employer Verification — the four template fields with their enums,
//      the declared placement, and the never-invent rule.
//   5. Recommended Actions — the max-5-bullets length rule and the
//      safety-first ordering that keeps money/personal-data warnings ahead
//      of verification steps at 🔴/🚨.
//   6. Block contract — the Risk Assessment output fields and enums, the
//      mandatory language discipline, and the Machine Summary
//      risk_assessment schema (the schema must stay stable for downstream
//      parsers).
//
// Pure file reading + string/regex assertions: no AI calls, no network.

import { readFileSync } from 'fs';
import { join } from 'path';
import { pass, fail, warn, ROOT } from './helpers.mjs';

console.log('\nrisk assessment feature layer');

// Normalized to LF: the heading/bullet parsers below are $-anchored and
// `.` does not match \r, so a CRLF checkout would silently drop every match
// and the suite would fail everywhere for a line-ending reason.
const read = (rel) => readFileSync(join(ROOT, rel), 'utf8').replace(/\r\n/g, '\n');

const oferta = read('modes/oferta.md');
const shared = read('modes/_shared.md');
const batch = read('batch/batch-prompt.md');

/**
 * Section text from a line-start heading to the next `---` rule.
 *
 * The `\n…\n` anchors keep an inline mention in prose
 * (`… under \`## Recommended Actions\``) from being mistaken for the section
 * itself.
 *
 * @param {string} src - File content (LF).
 * @param {string} heading - Heading text without `##` prefix handling, e.g. `## Risk Assessment`.
 * @returns {string|null} Section body, or null when the heading is absent.
 */
const sectionFrom = (src, heading) => {
  const at = src.indexOf(`\n${heading}\n`);
  if (at === -1) return null;
  const end = src.indexOf('\n---\n', at);
  return src.slice(at + 1, end === -1 ? src.length : end);
};

/**
 * The ```markdown fence that follows `marker`.
 *
 * @param {string} src - File content (LF).
 * @param {string} marker - Text the section containing the fence starts from.
 * @returns {string|null} Fence body (including the opening fence line), or null.
 */
const fenceAfter = (src, marker) => {
  const at = src.indexOf(marker);
  if (at === -1) return null;
  const open = src.indexOf('```markdown', at);
  if (open === -1) return null;
  const close = src.indexOf('```', open + '```markdown'.length);
  return close === -1 ? null : src.slice(open, close);
};

// ── §1 Report order parity ────────────────────────────────────────────────

console.log('\n1. Report order parity (oferta report template vs batch heading list)');

// The contract: these five sections, in this order, adjacent. Prompts 1–4
// all edited this chain; nothing in the repo re-derives it, so both files
// are pinned against it directly.
const CHAIN = [
  '## G) Posting Legitimacy',
  '## Risk Assessment',
  '## Employer Verification',
  '## Recommended Actions',
  '## Risk Summary',
];

/**
 * Assert one heading sequence carries the full chain, in order, adjacent.
 *
 * @param {string} label - File/section name for failure messages.
 * @param {string[]} headings - Headings in document order.
 * @returns {void}
 */
const checkChain = (label, headings) => {
  const missing = CHAIN.filter((h) => !headings.includes(h));
  if (missing.length) {
    fail(`${label}: required report-order heading(s) missing: ${missing.join(', ')}`);
    return;
  }
  // All occurrences of chain headings, in document order — a duplicated or
  // reordered section shows up as a sequence that differs from CHAIN.
  const found = headings.filter((h) => CHAIN.includes(h));
  const expected = CHAIN.join(' → ');
  const actual = found.join(' → ');
  if (actual !== expected) {
    fail(`${label}: report order diverges — expected [${expected}], found [${actual}]`);
  } else {
    pass(`${label}: report order is ${expected}`);
  }
  const pos = CHAIN.map((h) => headings.indexOf(h));
  const broken = pos
    .map((p, i) => (i > 0 && p !== pos[i - 1] + 1 ? `${CHAIN[i - 1]} ⟂ ${CHAIN[i]}` : null))
    .filter(Boolean);
  if (broken.length) {
    fail(`${label}: chain sections are no longer adjacent — something now sits between ${broken.join(', ')}`);
  } else {
    pass(`${label}: the five chain sections are adjacent`);
  }
};

const template = oferta.includes('**Report format:**')
  ? fenceAfter(oferta, '**Report format:**')
  : null;
if (template) {
  pass('modes/oferta.md has a **Report format:** template');
} else {
  fail('modes/oferta.md lost its **Report format:** section — report-order parity has no anchor');
}

const templateHeadings = template ? [...template.matchAll(/^## .+$/gm)].map((m) => m[0].trim()) : [];
const batchHeadings = [...batch.matchAll(/^- `(##[^`]+)`$/gm)].map((m) => m[1].trim());

if (batchHeadings.length > 0) {
  pass(`batch/batch-prompt.md heading list has ${batchHeadings.length} entries`);
} else {
  fail('batch/batch-prompt.md has no `- ## …` heading list — batch workers no longer know what to append');
}

checkChain('modes/oferta.md report template', templateHeadings);
checkChain('batch/batch-prompt.md heading list', batchHeadings);

// ── §2 Indicator table integrity ──────────────────────────────────────────

console.log('\n2. Risk indicator tables (modes/_shared.md)');

const EXPECTED_SEVERITY = {
  C1: 'Critical', C2: 'Critical', C3: 'Critical', C4: 'Critical',
  H1: 'High', H2: 'High', H3: 'High', H4: 'High', H5: 'High',
  M1: 'Medium', M2: 'Medium', M3: 'Medium', M4: 'Medium',
  L1: 'Low', L2: 'Low', L3: 'Low',
};
// Likely Genuine is an outcome, never an indicator family — only these three
// may appear in an indicator's Categories cell.
const KNOWN_CATEGORIES = new Set(['Scam Indicators', 'Ghost/Stale', 'Suspicious']);

const indicatorsAt = shared.indexOf('### Risk Indicators');
const rulesAt = shared.indexOf('### Determination rules');
const categoryRulesAt = shared.indexOf('### Risk Category assignment');

if (indicatorsAt === -1 || rulesAt === -1 || rulesAt <= indicatorsAt) {
  fail('modes/_shared.md lost the ### Risk Indicators … ### Determination rules section — indicator integrity has no anchor');
} else {
  const region = shared.slice(indicatorsAt, rulesAt);
  const rows = [];
  let severity = null;
  for (const line of region.split('\n')) {
    const head = /^#### (\w+) severity$/.exec(line);
    if (head) { severity = head[1]; continue; }
    const row = /^\| ([CHML]\d) \| (.+?) \| (.+?) \| (.+?) \|$/.exec(line);
    if (row) {
      rows.push({
        id: row[1],
        indicator: row[2].trim(),
        evidence: row[3].trim(),
        categories: row[4].trim(),
        severity,
      });
    }
  }

  if (rows.length === 16) {
    pass('the indicator tables hold exactly 16 rows');
  } else {
    fail(`expected 16 indicator rows (C1–C4, H1–H5, M1–M4, L1–L3), found ${rows.length}`);
  }

  const gotIds = rows.map((r) => r.id);
  const expectedIds = Object.keys(EXPECTED_SEVERITY);
  const missing = expectedIds.filter((id) => !gotIds.includes(id));
  const extra = gotIds.filter((id) => !expectedIds.includes(id));
  const dupes = [...new Set(gotIds.filter((id, i) => gotIds.indexOf(id) !== i))];
  if (missing.length) fail(`indicator ID(s) missing: ${missing.join(', ')}`);
  if (extra.length) {
    fail(`unexpected indicator ID(s): ${extra.join(', ')} — H6 (WhatsApp/Telegram move-to-channel) was explicitly deferred; any new ID needs _shared.md, oferta.md and this test updated together`);
  }
  if (dupes.length) fail(`duplicate indicator ID(s): ${dupes.join(', ')}`);
  if (!missing.length && !extra.length && !dupes.length) {
    pass('indicator IDs are exactly C1–C4, H1–H5, M1–M4, L1–L3');
  }

  // Severity comes from the `#### … severity` heading each row sits under.
  const misfiled = rows
    .filter((r) => r.id in EXPECTED_SEVERITY && EXPECTED_SEVERITY[r.id] !== r.severity)
    .map((r) => `${r.id} filed under "${r.severity}" (expected ${EXPECTED_SEVERITY[r.id]})`);
  if (misfiled.length) fail(`indicator severity misfiled: ${misfiled.join('; ')}`);
  else pass('every indicator sits under its matching severity heading');

  const emptyCells = rows
    .filter((r) => !r.indicator || !r.evidence || !r.categories)
    .map((r) => r.id);
  if (emptyCells.length) {
    fail(`indicator row(s) missing an indicator/evidence/categories cell: ${emptyCells.join(', ')}`);
  } else {
    pass('every indicator row carries an indicator, an evidence source, and a categories cell');
  }

  const badCategories = rows.flatMap((r) => {
    if (r.categories === '—') {
      // L2 (benefits not mentioned) maps to no category family — the table
      // documents that placeholder for it alone.
      return r.id === 'L2'
        ? []
        : [`${r.id} uses the empty "—" categories placeholder (only L2 may: it maps to no category family)`];
    }
    const unknown = r.categories.split(',').map((c) => c.trim()).filter((c) => !KNOWN_CATEGORIES.has(c));
    return unknown.length ? [`${r.id} → unknown categor${unknown.length > 1 ? 'ies' : 'y'}: ${unknown.join(', ')}`] : [];
  });
  if (badCategories.length) fail(`risk-category cell problem: ${badCategories.join('; ')}`);
  else pass('categories cells name only Scam Indicators / Ghost/Stale / Suspicious (L2 may use "—")');
}

// H6 was deliberately deferred (prompt 2). The ID-set check above catches it
// as a table row; this catches it surfacing in prose too.
const riskSectionAt = shared.indexOf('## Risk Assessment');
const companyTypeAt = shared.indexOf('## Company Type and Compensation Reliability');
const riskSection = (riskSectionAt !== -1 && companyTypeAt > riskSectionAt)
  ? shared.slice(riskSectionAt, companyTypeAt)
  : '';
if (/\bH6\b/.test(riskSection)) {
  fail('modes/_shared.md mentions H6 — that indicator was explicitly deferred and must stay out');
} else {
  pass('no H6 reference anywhere in the Risk Assessment section (deferred indicator stays out)');
}

// ── §3 Determination rules ────────────────────────────────────────────────

console.log('\n3. Determination rules (ordered, first match wins)');

if (rulesAt === -1 || categoryRulesAt === -1 || categoryRulesAt <= rulesAt) {
  fail('modes/_shared.md lost the ### Determination rules section — the risk-level ladder has no anchor');
} else {
  const rulesRegion = shared.slice(rulesAt, categoryRulesAt);

  if (/Apply these rules in order\. The first matching rule wins\./.test(rulesRegion)) {
    pass('rules declare "Apply these rules in order. The first matching rule wins."');
  } else {
    fail('modes/_shared.md no longer declares the determination rules ordered with first-match-wins');
  }

  const parsed = [...rulesRegion.matchAll(/^(\d+)\. \*\*(.+?)\*\* → `(.+?)`$/gm)]
    .map((m) => ({ n: Number(m[1]), condition: m[2], outcome: m[3] }));

  // The pinned ladder: outcome + a fragment that must appear in each rule's
  // condition. Editing any rule in _shared.md reddens here first.
  const EXPECTED_RULES = [
    ['🚨 Critical', 'C1–C4'],
    ['🔴 High', 'H1–H5'],
    ['🔴 High', 'One High indicator + two or more Medium'],
    ['🟡 Medium', 'One High indicator fired (alone)'],
    ['🟡 Medium', 'Two or more Medium indicators'],
    ['🟡 Medium', '(H5) fired alone'],
    ['🟢 Low', 'L1–L3'],
  ];

  if (parsed.length !== EXPECTED_RULES.length) {
    fail(`expected ${EXPECTED_RULES.length} determination rules, parsed ${parsed.length} — a rule was added or removed; update EXPECTED_RULES and determineLevel() together`);
  } else {
    const drift = parsed.flatMap((rule, i) => {
      const [outcome, fragment] = EXPECTED_RULES[i];
      const problems = [];
      if (rule.n !== i + 1) problems.push(`rule at position ${i + 1} is numbered ${rule.n}`);
      if (rule.outcome !== outcome) problems.push(`rule ${i + 1} → "${rule.outcome}" (expected "${outcome}")`);
      if (!rule.condition.includes(fragment)) {
        problems.push(`rule ${i + 1} condition lacks "${fragment}" (is "${rule.condition}")`);
      }
      return problems;
    });
    if (drift.length) fail(`determination rules drifted from the pinned ladder: ${drift.join('; ')}`);
    else pass('7 ordered rules match the pinned ladder (Critical → High ×2 → Medium ×3 → Low)');
  }
}

// determineLevel() mirrors the seven rules above under first-match-wins.
// The text pins fail when _shared.md's rules change; this keeps the EXECUTED
// ordering honest for synthetic inputs, so both must move together.
//
// Note: rule 6 (H5 alone) is unreachable under first-match-wins — ['H5'] is
// already caught by rule 4 (one High alone) — but both say Medium, so the
// disagreement the redundancy could cause does not exist. Asserted below
// against the shared outcome.
const determineLevel = (fired) => {
  const count = (re) => fired.filter((id) => re.test(id)).length;
  const C = count(/^C[1-4]$/);
  const H = count(/^H[1-5]$/);
  const M = count(/^M[1-4]$/);
  const L = count(/^L[1-3]$/);
  if (C >= 1) return '🚨 Critical';                                   // rule 1
  if (H >= 2) return '🔴 High';                                       // rule 2
  if (H >= 1 && M >= 2) return '🔴 High';                             // rule 3
  if (H === 1 && M === 0 && L === 0) return '🟡 Medium';              // rule 4 ("alone")
  if (M >= 2) return '🟡 Medium';                                     // rule 5
  if (fired.length === 1 && fired[0] === 'H5') return '🟡 Medium';    // rule 6 (subsumed by rule 4)
  if (H === 0 && M === 0) return '🟢 Low';                            // rule 7: only Ls / none
  return null;                                                        // no documented rule matched
};

const CASES = [
  // The five shapes the feature spec calls out explicitly.
  [['C1'], '🚨 Critical', 'any Critical (C1–C4) forces Critical'],
  [['H1', 'H2'], '🔴 High', 'two High force High'],
  [['H1', 'M1', 'M2'], '🔴 High', 'one High + two Medium force High'],
  [['M1', 'M2'], '🟡 Medium', 'only Mediums force Medium'],
  [['L1', 'L2', 'L3'], '🟢 Low', 'only Low force Low'],
  [[], '🟢 Low', 'no indicators → Low'],
  // First-match-wins: earlier rules must preempt later ones, or a Critical
  // posting could render as High and a ghost listing as Low.
  [['C1', 'H1', 'H2', 'M1', 'M2'], '🚨 Critical', 'rule 1 preempts rules 2/3/5'],
  [['H1', 'H2', 'M1', 'M2'], '🔴 High', 'rule 2 preempts rules 3/5'],
  [['M1', 'M2', 'L1'], '🟡 Medium', 'rule 5 preempts rule 7'],
  [['H5'], '🟡 Medium', 'H5 alone → Medium (rules 4 and 6 agree)'],
  [['L2'], '🟢 Low', 'L2 alone stays Low'],
];

for (const [fired, expected, why] of CASES) {
  const got = determineLevel(fired);
  const label = `[${fired.join(', ') || 'none'}]`;
  if (got === expected) pass(`${label} → ${expected} — ${why}`);
  else fail(`${label} → ${got ?? 'no rule matched'}, expected ${expected} — ${why}`);
}

// Shapes no documented rule matches: rule 3 needs ≥2 Medium, rule 4's
// "alone" excludes any companion, rule 5 needs ≥2 Medium, and rule 7
// forbids High/Medium entirely. The ladder declares first-match-wins, which
// implies every input matches SOMETHING — so these are documentation gaps.
// Surfaced as one warning (visible in the summary line) rather than a hard
// failure: the five specified behaviours above all pass, and a fix to the
// rules reddens the text pins and these asserts together.
const GAP_CASES = [
  [['M1'], 'a single Medium alone'],
  [['H1', 'M1'], 'one High + one Medium'],
  [['M1', 'L1'], 'one Medium + one Low'],
];
const unresolved = GAP_CASES.filter(([fired]) => determineLevel(fired) === null);
if (unresolved.length > 0) {
  warn(`modes/_shared.md determination rules leave ${unresolved.length} fired-indicator shape(s) unmatched (first-match-wins falls through): ${unresolved.map(([fired, shape]) => `[${fired.join(', ')}] = ${shape}`).join('; ')} — add a rule, or narrow rule 4's "alone"`);
}
for (const [fired, shape] of GAP_CASES) {
  const got = determineLevel(fired);
  const label = `[${fired.join(', ')}] (${shape})`;
  if (got === null) pass(`${label} falls through as documented — gap surfaced in the warning above`);
  else fail(`${label} resolved to ${got} but no rule text covers it — update determineLevel() and the text pins together`);
}

// ── §4 Employer Verification template ─────────────────────────────────────

console.log('\n4. Employer Verification template');

const evSection = sectionFrom(oferta, '## Employer Verification');
if (!evSection) {
  fail('modes/oferta.md lost its ## Employer Verification section');
} else {
  const FIELDS = [
    '- **Company website:** {Found | Not found | Could not check}',
    '- **Email domain matches claimed company:** {Yes | No | N/A}',
    '- **Role found on official careers page:** {Yes | No | Unknown}',
    '- **Additional notes:** {short free text, or —}',
  ];
  const missingFields = FIELDS.filter((f) => !evSection.includes(f));
  if (missingFields.length) {
    fail(`Employer Verification template missing field line(s): ${missingFields.join(' | ')}`);
  } else {
    pass('Employer Verification template carries all four fields with their enums');
  }

  if (evSection.includes('immediately after `## Risk Assessment` and before `## Risk Summary`')) {
    pass('Employer Verification declares its placement between Risk Assessment and Risk Summary');
  } else {
    fail('Employer Verification no longer declares placement immediately after Risk Assessment / before Risk Summary');
  }

  if (evSection.includes('Never invent results.')) {
    pass('Employer Verification keeps the never-invent rule');
  } else {
    fail('Employer Verification lost "Never invent results." — unknown checks could be fabricated');
  }
}

// ── §5 Recommended Actions rules ──────────────────────────────────────────

console.log('\n5. Recommended Actions rules');

const recSection = sectionFrom(oferta, '## Recommended Actions');
if (!recSection) {
  fail('modes/oferta.md lost its ## Recommended Actions section');
} else {
  const LENGTH_PINS = ['maximum 5 bullets; prefer 3–4', 'Order bullets by severity'];
  const missingLength = LENGTH_PINS.filter((s) => !recSection.includes(s));
  if (missingLength.length) {
    fail(`Recommended Actions length/order rule(s) missing: ${missingLength.join(' | ')}`);
  } else {
    pass('Recommended Actions caps at 5 bullets (prefer 3–4) and orders them by severity');
  }

  const SAFETY_PINS = [
    'Safety first at high risk',
    '🚨 Critical or 🔴 High',
    'the first actions must address money and personal data',
    'before any verification or research steps',
  ];
  const missingSafety = SAFETY_PINS.filter((s) => !recSection.includes(s));
  if (missingSafety.length) {
    fail(`Recommended Actions safety-first rule(s) missing: ${missingSafety.join(' | ')}`);
  } else {
    pass('safety-first rule puts money/personal-data actions before verification steps at 🔴/🚨');
  }

  if (recSection.includes('immediately after `## Employer Verification` and before `## Risk Summary`')) {
    pass('Recommended Actions declares its placement between Employer Verification and Risk Summary');
  } else {
    fail('Recommended Actions no longer declares placement after Employer Verification / before Risk Summary');
  }
}

// ── §6 Block contract (output fields, language, Machine Summary schema) ───

console.log('\n6. Risk Assessment block contract');

const raSection = sectionFrom(oferta, '## Risk Assessment');
if (!raSection) {
  fail('modes/oferta.md lost its ## Risk Assessment section');
} else {
  const RA_FIELDS = [
    '- **Overall Risk Level:** {🟢 Low | 🟡 Medium | 🔴 High | 🚨 Critical}',
    '- **Risk Categories:** {Scam Indicators | Ghost/Stale | Suspicious | Likely Genuine}',
    '- **Confidence:** {High | Medium | Low}',
    '- **Summary:** {1-2 sentences explaining the verdict}',
  ];
  const missingRa = RA_FIELDS.filter((f) => !raSection.includes(f));
  if (missingRa.length) {
    fail(`Risk Assessment output format missing line(s): ${missingRa.join(' | ')}`);
  } else {
    pass('Risk Assessment output format keeps all four fields and their enums');
  }

  if (raSection.includes('**Never** state "this is a scam"')) {
    pass('mandatory language discipline forbids absolute scam/ghost conclusions');
  } else {
    fail('Risk Assessment lost the mandatory "Never state this is a scam" language discipline');
  }
}

// The Machine Summary schema is the feature's machine-readable contract —
// downstream scripts parse it. It must stay put: keys, enums, no-invention.
const raSchemaLine = batch.split('\n').find((l) => l.includes('`risk_assessment` mirrors')) ?? '';
const SCHEMA_PINS = [
  '`level`',
  '`categories`',
  '`confidence`',
  '`summary`',
  '`low` / `medium` / `high` / `critical`',
  'Never invent a value the block does not show',
];
if (!raSchemaLine) {
  fail('batch/batch-prompt.md no longer defines `risk_assessment` in the Machine Summary schema');
} else {
  const missingSchema = SCHEMA_PINS.filter((s) => !raSchemaLine.includes(s));
  if (missingSchema.length) {
    fail(`risk_assessment schema drift — missing: ${missingSchema.join(' | ')}`);
  } else {
    pass('Machine Summary risk_assessment keeps level/categories/confidence/summary + enums + no-invent rule');
  }
}
