#!/usr/bin/env node
/**
 * verify-risk.mjs — Deterministic post-evaluation audit of the Risk
 * Assessment layer for career-ops.
 *
 * The Risk Assessment verdict chain (## Risk Assessment → ## Employer
 * Verification → ## Recommended Actions → ## Risk Summary, sitting between
 * Block G and the Risk Summary) is produced by an LLM from prompt-only
 * instructions in modes/_shared.md and modes/oferta.md. That has one
 * structural weakness a prompt cannot police: the model can silently SKIP the
 * layer, write the sections out of the mandated order, under-detect the
 * fired indicators (a 🟢 Low with an email-domain mismatch or a fired
 * Critical standing in the Key Indicators), or drop the Machine Summary
 * `risk_assessment` mirror downstream scripts read. Nothing in the file
 * system failed when that happened — the report renders fine, the risk just
 * reads wrong.
 *
 * This script is that watchdog. It is a SAFETY NET, not a replacement for
 * producing the Risk Assessment correctly in-prompt: it can only ever
 * re-derive a verdict from what the report itself states (the fired
 * indicator IDs it lists, the Employer Verification field it recorded, the
 * Machine Summary it mirrored), so an indicator that never fired in the
 * report is invisible to it. Missing content is not proof of safety — which
 * is why the block-missing and unparseable shapes stay soft warnings, and a
 * 🔴 High report that simply omitted the Key Indicators subsection is not
 * flagged (no fired set to contradict the level with). It flags, never
 * fixes: zero LLM, zero network, zero writes.
 *
 * Checks, per report:
 *   risk-blocks-missing           (soft)  any of the four risk sections absent —
 *                                         legacy reports predate them and stay valid
 *   risk-order-error              (hard)  the chain is reordered or non-adjacent
 *   risk-assessment-unparseable   (soft)  Risk Assessment present but no usable
 *                                         "**Overall Risk Level:**" value
 *   ev-domain-unreadable          (soft)  EV block present but the domain field
 *                                         is missing or not Yes/No/N/A
 *   domain-mismatch-with-low      (hard)  EV says email domain mismatch (H4)
 *                                         while the level is 🟢 Low
 *   indicator-level-contradiction (hard)  the report's OWN fired Key Indicators
 *                                         re-derive to a level that contradicts
 *                                         the stated one (via _shared.md's
 *                                         seven determination rules)
 *   machine-summary-risk-missing  (hard)  Risk Assessment present but Machine
 *                                         Summary has no `risk_assessment:` map
 *   risk-summary-drift            (soft)  prose level differs from Machine
 *                                         Summary risk_assessment.level
 *
 * Run: node verify-risk.mjs                        (JSON to stdout)
 *      node verify-risk.mjs --summary               (human-readable table)
 *      node verify-risk.mjs --reports-dir path/to    (override reports/, for testing)
 *      node verify-risk.mjs --self-test              (run the in-memory test suite)
 *      node verify-risk.mjs --help                   (print usage and exit)
 *
 * Exit codes: 1 if any hard finding, 0 otherwise (including the empty-repo
 * case — reports/*.md is gitignored, so a fresh checkout has nothing to scan;
 * a report missing only soft findings never fails the run). Wired into
 * verify-pipeline.mjs Check 18 and test-all.mjs's --self-test invocation.
 */

import { readFileSync, readdirSync, existsSync, mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'fs';
import { join, dirname } from 'path';
import { tmpdir } from 'os';
import { fileURLToPath } from 'url';
import { flagValue } from './lib/cli-flags.mjs';
import { getCareerOpsRoot } from './path-resolver.mjs';
import { isMainModule } from './lib/is-main-module.mjs';

const CAREER_OPS = dirname(fileURLToPath(import.meta.url));
const DATA_ROOT = getCareerOpsRoot();
const DEFAULT_REPORTS_DIR = join(DATA_ROOT, 'reports');

// reports/{###}-{company-slug}-{YYYY-MM-DD}.md — same convention as
// check-jd-archive.mjs's parseReportFilename. The company slug may itself
// contain hyphens, so only the numeric prefix and trailing date are anchored.
const REPORT_FILENAME_RE = /^(\d+)-(.+)-(\d{4}-\d{2}-\d{2})\.md$/;
const RESERVED_FILENAME_RE = /^\d+-RESERVED\.md$/;

// The five-section report-order contract, identical to the CHAIN pinned in
// tests/risk-assessment.test.mjs §1 (oferta.md report template and
// batch/batch-prompt.md heading list must both present it, adjacent, in
// order). Block G always anchors the chain when present.
const G_HEADING = '## G) Posting Legitimacy';
const RISK_CHAIN = [
  '## Risk Assessment',
  '## Employer Verification',
  '## Recommended Actions',
  '## Risk Summary',
];
const CHAIN = [G_HEADING, ...RISK_CHAIN];

// Emoji label order runs Critical (most severe) → Low (least severe).
const LEVEL_LABELS = ['🚨 Critical', '🔴 High', '🟡 Medium', '🟢 Low'];
const SEVERITY = new Map([['🚨 Critical', 4], ['🔴 High', 3], ['🟡 Medium', 2], ['🟢 Low', 1]]);

const OVERALL_RISK_LINE_RE = /-\s*\*\*Overall Risk Level:\*\*\s*([^\n]+)/;
const LEVEL_RE = /(🚨\s*Critical|🔴\s*High|🟡\s*Medium|🟢\s*Low)/;
const EMAIL_DOMAIN_LINE_RE = /-\s*\*\*Email domain matches claimed company:\*\*\s*([^\n]+)/;
const INDICATOR_RE = /\b(C[1-4]|H[1-5]|M[1-4]|L[1-3])\b/g;

// Hard findings fail the run (exit 1); everything else is a visible soft
// warning that never sets a non-zero exit — mirrors check-jd-archive.mjs's
// missing-jd-archive vs jd-archive-review-due severity split.
export const HARD_FINDING_TYPES = new Set([
  'risk-order-error',
  'domain-mismatch-with-low',
  'indicator-level-contradiction',
  'machine-summary-risk-missing',
]);

export const hasHardFindings = (findings) => findings.some((f) => HARD_FINDING_TYPES.has(f.type));

const USAGE = `Usage:
  node verify-risk.mjs                      # full JSON findings to stdout
  node verify-risk.mjs --summary             # human-readable table
  node verify-risk.mjs --reports-dir <path>  # override reports/ (testing)
  node verify-risk.mjs --self-test           # run the in-memory test suite
  node verify-risk.mjs --help                # print this usage block and exit`;

// --- CLI args ---
const args = process.argv.slice(2);
const summaryMode = args.includes('--summary');
const selfTestMode = args.includes('--self-test');
const reportsDirArg = flagValue(args, '--reports-dir') ?? null;

/**
 * Line-start level-2 headings of a report, in document order.
 * @param {string} content - Report text (LF or CRLF, both handled).
 * @returns {string[]}
 */
export function extractHeadings(content) {
  return [...String(content ?? '').matchAll(/^## .+$/gm)].map((m) => m[0].trim());
}

/**
 * Section text under a line-start heading, up to the next level-2 heading
 * (a `### ` Key Indicators subsection stays inside the Risk Assessment
 * section; the next `## ` ends it).
 * @param {string} content - Report text.
 * @param {RegExp} headingRe - /m-anchored heading regex, e.g. /^## Risk Assessment\b/m.
 * @returns {string|null} Trimmed section text, or null when the heading is absent.
 */
export function sectionText(content, headingRe) {
  const text = String(content ?? '');
  const m = headingRe.exec(text);
  if (!m) return null;
  const rest = text.slice(m.index + m[0].length);
  const next = rest.search(/^## /m);
  const section = next === -1 ? rest : rest.slice(0, next);
  return section.trim();
}

/**
 * Normalize a raw "**Overall Risk Level:**" value to one of the four emoji
 * labels, or null when it carries none.
 * @param {string} raw - The text after the field marker.
 * @returns {string|null}
 */
export function parseLevel(raw) {
  const m = LEVEL_RE.exec(String(raw ?? ''));
  return m ? m[1].replace(/\s+/g, ' ') : null;
}

/**
 * The fired indicator IDs a Risk Assessment section declares in its
 * `### Key Indicators` subsection (the doc's contract is "only include
 * indicators that actually fired"). Empty when the subsection is absent or
 * lists none — which is a legitimate Low-report shape, never a contradiction.
 * @param {string|null} raSection - The Risk Assessment section text.
 * @returns {string[]}
 */
export function parseKeyIndicatorIds(raSection) {
  const text = String(raSection ?? '');
  const at = text.search(/^###\s+Key Indicators\b/m);
  if (at === -1) return [];
  return [...text.slice(at).matchAll(INDICATOR_RE)].map((m) => m[1]);
}

/**
 * Mirrors modes/_shared.md's seven ordered, first-match-wins determination
 * rules (the same ladder tests/risk-assessment.test.mjs §3 re-executes over
 * synthetic fired sets — this must change together with those pins). Returns
 * the emoji level, or null when no documented rule matches (the [M1],
 * [H1,M1], [M1,L1] gap shapes).
 * @param {string[]} firedIds - Indicator IDs declared in Key Indicators.
 * @returns {string|null}
 */
export function expectedLevelFor(firedIds) {
  const count = (re) => firedIds.filter((id) => re.test(id)).length;
  const C = count(/^C[1-4]$/);
  const H = count(/^H[1-5]$/);
  const M = count(/^M[1-4]$/);
  const L = count(/^L[1-3]$/);
  if (C >= 1) return '🚨 Critical';                                   // rule 1
  if (H >= 2) return '🔴 High';                                       // rule 2
  if (H >= 1 && M >= 2) return '🔴 High';                             // rule 3
  if (H === 1 && M === 0 && L === 0) return '🟡 Medium';              // rule 4 ("alone")
  if (M >= 2) return '🟡 Medium';                                     // rule 5
  if (firedIds.length === 1 && firedIds[0] === 'H5') return '🟡 Medium'; // rule 6 (subsumed by rule 4)
  if (H === 0 && M === 0) return '🟢 Low';                            // rule 7: only Ls / none
  return null;                                                        // no documented rule matched
}

/**
 * The Machine Summary `risk_assessment` contract (batch/batch-prompt.md is
 * the schema source of truth): a `risk_assessment:` map carrying a `level`
 * enum of `low`/`medium`/`high`/`critical`.
 * @param {string} content - Report text.
 * @returns {{ present: boolean, level: string|null }}
 */
export function machineRiskAssessment(content) {
  const region = sectionText(content, /^## Machine Summary\b/m);
  if (region === null) return { present: false, level: null };
  const at = region.search(/\brisk_assessment\s*:/);
  if (at === -1) return { present: false, level: null };
  const after = region.slice(at);
  const end = after.search(/\n[^\s#|]/); // next non-indented line = next top-level key or fence end
  const block = end === -1 ? after : after.slice(0, end);
  const lm = /level\s*:\s*['"]?([A-Za-z]+)['"]?/.exec(block);
  if (!lm) return { present: true, level: null };
  const MAP = { low: '🟢 Low', medium: '🟡 Medium', high: '🔴 High', critical: '🚨 Critical' };
  return { present: true, level: MAP[lm[1].toLowerCase()] ?? null };
}

/**
 * One report's findings. Pure over the report text — no fs access — so the
 * suite can run it on inline fixtures and the scanner only adds file/report
 * identity.
 * @param {string} content - Report text.
 * @param {{ filename?: string|null }} [opts]
 * @returns {{ findings: Array<{ type: string, file: string|null, detail: string }> }}
 */
export function checkRiskReport(content, { filename = null } = {}) {
  const findings = [];
  const text = String(content ?? '');
  const headings = extractHeadings(text);

  // --- Section presence / order ---
  const present = CHAIN.filter((h) => headings.includes(h));
  const missingRisk = RISK_CHAIN.filter((h) => !present.includes(h));
  if (missingRisk.length) {
    // Additive feature: reports written before the risk layer are valid, so
    // this is soft — old reports just don't get the consistency checks below.
    findings.push({
      type: 'risk-blocks-missing',
      file: filename,
      detail: `missing ${missingRisk.join(' and ')} — report predates the risk layer (or skipped it), so no risk checks apply`,
    });
  } else {
    const found = headings.filter((h) => CHAIN.includes(h));
    const expectedSeq = CHAIN.join(' → ');
    const actualSeq = found.join(' → ');
    const pos = CHAIN.map((h) => headings.indexOf(h));
    const nonAdjacent = pos
      .slice(1)
      .map((p, i) => (p !== pos[i] + 1 ? `${CHAIN[i]} ⟂ ${CHAIN[i + 1]}` : null))
      .filter(Boolean);
    const divergence = actualSeq !== expectedSeq
      ? `risk chain is out of order — expected [${expectedSeq}], found [${actualSeq}]`
      : (nonAdjacent.length
        ? `risk chain sections are no longer adjacent — something sits between ${nonAdjacent.join(', ')}`
        : null);
    if (divergence) {
      findings.push({ type: 'risk-order-error', file: filename, detail: divergence });
    }
  }

  const raSection = sectionText(text, /^## Risk Assessment\b/m);
  const overallLine = OVERALL_RISK_LINE_RE.exec(raSection ?? '');
  const statedLevel = overallLine ? parseLevel(overallLine[1]) : null;

  // --- Risk Assessment parseability (soft — a value variant is style, not
  // evidence of a wrong verdict; the hard rules below never run on it). ---
  if (raSection !== null && !statedLevel) {
    findings.push({
      type: 'risk-assessment-unparseable',
      file: filename,
      detail: `Risk Assessment is present but its "**Overall Risk Level:**" does not carry one of ${LEVEL_LABELS.join(' | ')} — the deterministic checks can't apply`,
    });
  }

  // --- Employer Verification domain field ---
  const evSection = sectionText(text, /^## Employer Verification\b/m);
  const domainLine = EMAIL_DOMAIN_LINE_RE.exec(evSection ?? '');
  const domainRaw = domainLine ? domainLine[1].trim() : null;
  const domainMatch = domainRaw && /^(yes|no|n\/a)$/i.test(domainRaw) ? domainRaw.toLowerCase() : null;
  if (evSection !== null && domainLine && !domainMatch) {
    findings.push({
      type: 'ev-domain-unreadable',
      file: filename,
      detail: `"**Email domain matches claimed company:**" value "${domainRaw}" is not one of Yes | No | N/A — the domain-mismatch rule can't apply`,
    });
  } else if (evSection !== null && !domainLine) {
    findings.push({
      type: 'ev-domain-unreadable',
      file: filename,
      detail: 'Employer Verification block lacks the "**Email domain matches claimed company:**" field — the domain-mismatch rule can\'t apply',
    });
  } else if (domainMatch === 'no' && statedLevel === '🟢 Low') {
    // The explicit user rule: an email-domain mismatch is H4, and H4 alone
    // ladders to Medium (rule 4) — it can never coexist with a Low verdict.
    findings.push({
      type: 'domain-mismatch-with-low',
      file: filename,
      detail: 'Employer Verification records an email domain that does not match the claimed company (H4) while the Risk Assessment states 🟢 Low — an email-domain mismatch cannot sit under a Low risk level',
    });
  }

  // --- Indicator/level contradiction (only against the report's OWN fired
  // set, so a bare 🟡/🔴/🚨 with no Key Indicators subsection is never a
  // false positive). ---
  const firedIds = parseKeyIndicatorIds(raSection);
  if (firedIds.length > 0 && statedLevel) {
    const expected = expectedLevelFor(firedIds);
    if (expected !== null && expected !== statedLevel) {
      const direction = SEVERITY.get(expected) > SEVERITY.get(statedLevel)
        ? 'the fired indicators force a HIGHER risk level than stated (under-detection)'
        : 'the stated risk level is stricter than the fired indicators determine';
      findings.push({
        type: 'indicator-level-contradiction',
        file: filename,
        detail: `Key Indicators fire [${firedIds.join(', ')}], which the determination rules resolve to ${expected}, but the block states ${statedLevel} — ${direction}`,
      });
    }
  }

  // --- Machine Summary `risk_assessment` mirror ---
  const machine = machineRiskAssessment(text);
  if (raSection !== null && !machine.present) {
    findings.push({
      type: 'machine-summary-risk-missing',
      file: filename,
      detail: 'Risk Assessment is present but the Machine Summary carries no `risk_assessment:` map — downstream scripts read the level from there',
    });
  } else if (raSection !== null && machine.present && machine.level !== null && statedLevel && statedLevel !== machine.level) {
    findings.push({
      type: 'risk-summary-drift',
      file: filename,
      detail: `prose "**Overall Risk Level:**" is ${statedLevel} but Machine Summary risk_assessment.level is ${machine.level}`,
    });
  }

  return { findings };
}

/**
 * Scan a reports/ directory. Same contract as check-jd-archive.mjs:
 * findings are decorated with {type, file, report, detail}, unreadable
 * files become warnings, and a missing reports dir is a clean empty result.
 * @param {string} reportsDir
 * @returns {{ reportsScanned: number, findings: Array, warnings: Array }}
 */
export function checkRiskReports(reportsDir) {
  const findings = [];
  const warnings = [];
  let reportsScanned = 0;

  if (!existsSync(reportsDir)) {
    return { reportsScanned, findings, warnings };
  }

  const files = readdirSync(reportsDir)
    .filter((f) => f.endsWith('.md') && !RESERVED_FILENAME_RE.test(f))
    .sort();

  for (const file of files) {
    reportsScanned += 1;
    let content;
    try {
      content = readFileSync(join(reportsDir, file), 'utf-8');
    } catch (e) {
      warnings.push({ type: 'warning', file, detail: `could not read file: ${e.message.split('\n')[0]}` });
      continue;
    }
    const meta = REPORT_FILENAME_RE.exec(file);
    const report = meta ? parseInt(meta[1], 10) : null;
    const { findings: reportFindings } = checkRiskReport(content, { filename: file });
    for (const f of reportFindings) findings.push({ report, ...f });
  }

  return { reportsScanned, findings, warnings };
}

// --- Summary mode ---
function printSummary(result) {
  const { reportsScanned, findings, warnings } = result;
  console.log(`\n${'='.repeat(78)}`);
  console.log('  Risk Verification — career-ops');
  console.log(`  reports scanned: ${reportsScanned}`);
  console.log(`${'='.repeat(78)}\n`);

  if (findings.length === 0) {
    console.log(reportsScanned === 0
      ? '  No report files found under reports/.\n'
      : '  Every report passes the deterministic risk-consistency checks.\n');
  } else {
    console.log('  ' + 'Type'.padEnd(30) + 'Report'.padEnd(8) + 'File'.padEnd(30) + 'Detail');
    console.log('  ' + '-'.repeat(96));
    for (const f of findings) {
      const hard = HARD_FINDING_TYPES.has(f.type) ? '!' : ' ';
      console.log('  '
        + `${hard}${f.type}`.padEnd(30)
        + (f.report !== null ? String(f.report) : '?').padEnd(8)
        + f.file.substring(0, 28).padEnd(30)
        + f.detail);
    }
    console.log(`\n  (${findings.filter((f) => HARD_FINDING_TYPES.has(f.type)).length} hard — set exit 1; `
      + `${findings.length - findings.filter((f) => HARD_FINDING_TYPES.has(f.type)).length} soft — visible, never blocking)\n`);
  }

  if (warnings.length) {
    console.log(`  ${warnings.length} warning${warnings.length === 1 ? '' : 's'} (files skipped, never fatal):`);
    for (const w of warnings) console.log(`    ${w.file}: ${w.detail}`);
    console.log('');
  }
}

// --- Self-test (fixtures only — never reads the real reports/ for findings) ---
function runSelfTest() {
  let pass = 0;
  let fail = 0;
  const check = (cond, label) => {
    if (cond) { pass += 1; } else { fail += 1; console.error(`  FAIL: ${label}`); }
  };

  // --- Unit-level checks on the pure functions ---
  check(expectedLevelFor(['C1']) === '🚨 Critical', 'any Critical forces Critical (rule 1)');
  check(expectedLevelFor(['H1', 'H2']) === '🔴 High', 'two High force High (rule 2)');
  check(expectedLevelFor(['H1', 'M1', 'M2']) === '🔴 High', 'one High + two Medium force High (rule 3)');
  check(expectedLevelFor(['H1']) === '🟡 Medium', 'one High alone is Medium (rule 4)');
  check(expectedLevelFor(['M1', 'M2']) === '🟡 Medium', 'two Medium force Medium (rule 5)');
  check(expectedLevelFor(['H5']) === '🟡 Medium', 'H5 alone is Medium (rules 4/6 agree)');
  check(expectedLevelFor(['L1', 'L2', 'L3']) === '🟢 Low', 'only Low force Low (rule 7)');
  check(expectedLevelFor([]) === '🟢 Low', 'no indicators is Low (rule 7)');
  check(expectedLevelFor(['C1', 'H1', 'M1']) === '🚨 Critical', 'rule 1 preempts later rules');
  check(expectedLevelFor(['M1']) === null, 'single Medium alone is an undocumented gap — no assertion');
  check(expectedLevelFor(['H1', 'M1']) === null, 'one High + one Medium is an undocumented gap — no assertion');
  check(expectedLevelFor(['M1', 'L1']) === null, 'one Medium + one Low is an undocumented gap — no assertion');

  check(parseLevel('🟢 Low') === '🟢 Low', 'parseLevel normalizes the Low label');
  check(parseLevel('- **Overall Risk Level:** 🔴 High') === '🔴 High', 'parseLevel extracts the level from the full field line');
  check(parseLevel('Moderate') === null, 'parseLevel rejects a non-enum value');

  check(JSON.stringify(parseKeyIndicatorIds('### Key Indicators\n\n- 🚨 C1 (Critical): advance fee requested\n- 🔴 H2 (High): urgency pressure')) === JSON.stringify(['C1', 'H2']),
    'parseKeyIndicatorIds extracts fired IDs from Key Indicators bullets');

  check(sectionText('## Risk Assessment\n\n- **Overall Risk Level:** 🟢 Low\n\n### Key Indicators\n- 🟢 L1 (Low): title\n\n## Employer Verification\nx', /^## Risk Assessment\b/m)
    .includes('### Key Indicators'), 'sectionText keeps the Key Indicators subsection inside Risk Assessment');
  check(sectionText('## Risk Assessment\nbody\n## Employer Verification\nx', /^## Risk Assessment\b/m) === 'body',
    'sectionText truncates at the next level-2 heading');

  const machineLevel = machineRiskAssessment([
    '## Machine Summary',
    '```yaml',
    'score: 4.0',
    'risk_assessment:',
    '  level: low',
    '  categories: [Ghost/Stale]',
    '```',
    '## G) Posting Legitimacy',
  ].join('\n'));
  check(machineLevel.present === true && machineLevel.level === '🟢 Low', 'machineRiskAssessment reads level from a block-form risk_assessment map');
  check(machineRiskAssessment('## Machine Summary\n```yaml\nscore: 4.0\n```').present === false,
    'machineRiskAssessment reports absent when no risk_assessment key exists');

  // --- Fixture directory tree (mkdtempSync, mirrors the repo's own test convention) ---
  const tmpDir = mkdtempSync(join(tmpdir(), 'verify-risk-test-'));
  const reportsDir = join(tmpDir, 'reports');
  mkdirSync(reportsDir, { recursive: true });

  const write = (file, lines) => writeFileSync(join(reportsDir, file), lines.join('\n') + '\n');

  const MACHINE = (level) => [
    '## Machine Summary',
    '```yaml',
    'score: 4.0',
    'risk_assessment:',
    `  level: ${level}`,
    '  categories: [suspicious]',
    '  confidence: Medium',
    '  summary: "fixture"',
    '```',
  ];

  // Fixture 1: clean report — full chain in order, Low, domain Yes, no fired
  // indicators, Machine Summary mirror present and agreeing. Expect 0 findings.
  write('001-acme-2026-01-15.md', [
    '# Evaluation: Acme — Analyst',
    '',
    ...MACHINE('low'),
    '',
    '## G) Posting Legitimacy',
    '**Legitimacy:** High Confidence',
    '',
    '## Risk Assessment',
    '',
    '- **Overall Risk Level:** 🟢 Low',
    '- **Risk Categories:** Likely Genuine',
    '- **Confidence:** High',
    '- **Summary:** No notable signals.',
    '',
    '## Employer Verification',
    '',
    '- **Company website:** Found',
    '- **Email domain matches claimed company:** Yes',
    '- **Role found on official careers page:** Yes',
    '- **Additional notes:** —',
    '',
    '## Recommended Actions',
    '',
    '- No notable risk signals found — proceed with your normal application checks.',
    '',
    '## Risk Summary',
    '',
    '| Signal | Status |',
    '|--------|--------|',
    '| Posting legitimacy | ✅ High Confidence |',
  ]);

  // Fixture 2: no risk sections at all (legacy report). Expect risk-blocks-missing only.
  write('002-globex-2026-01-16.md', [
    '# Evaluation: Globex — Analyst',
    '',
    ...MACHINE('low'),
    '',
    '## G) Posting Legitimacy',
    '**Legitimacy:** High Confidence',
  ]);

  // Fixture 3: reordered chain (Employer Verification before Risk Assessment).
  // Expect risk-order-error (hard).
  write('003-initech-2026-01-17.md', [
    '# Evaluation: Initech — Analyst',
    '',
    ...MACHINE('low'),
    '',
    '## G) Posting Legitimacy',
    '**Legitimacy:** High Confidence',
    '',
    '## Employer Verification',
    '',
    '- **Email domain matches claimed company:** Yes',
    '',
    '## Risk Assessment',
    '',
    '- **Overall Risk Level:** 🟢 Low',
    '- **Risk Categories:** Likely Genuine',
    '- **Confidence:** High',
    '- **Summary:** No notable signals.',
    '',
    '## Recommended Actions',
    '',
    '- Fine.',
    '',
    '## Risk Summary',
    '',
    '| Signal | Status |',
    '|--------|--------|',
    '| Posting legitimacy | ✅ High Confidence |',
  ]);

  // Fixture 4: email domain mismatch ("No") alongside 🟢 Low. Expect
  // domain-mismatch-with-low (hard).
  write('004-umbrella-2026-01-18.md', [
    '# Evaluation: Umbrella Corp — Analyst',
    '',
    ...MACHINE('low'),
    '',
    '## G) Posting Legitimacy',
    '**Legitimacy:** Proceed with Caution',
    '',
    '## Risk Assessment',
    '',
    '- **Overall Risk Level:** 🟢 Low',
    '- **Risk Categories:** Suspicious',
    '- **Confidence:** Low',
    '- **Summary:** Minor concerns.',
    '',
    '## Employer Verification',
    '',
    '- **Company website:** Not found',
    '- **Email domain matches claimed company:** No',
    '- **Role found on official careers page:** Unknown',
    '- **Additional notes:** —',
    '',
    '## Recommended Actions',
    '',
    '- Verify the company website.',
    '',
    '## Risk Summary',
    '',
    '| Signal | Status |',
    '|--------|--------|',
    '| Posting legitimacy | ⚠️ Proceed with Caution — mixed signals |',
  ]);

  // Fixture 5: fired C1 in Key Indicators but prose states 🟢 Low. Expect
  // indicator-level-contradiction (hard).
  write('005-oscorp-2026-01-19.md', [
    '# Evaluation: Oscorp — Analyst',
    '',
    ...MACHINE('low'),
    '',
    '## G) Posting Legitimacy',
    '**Legitimacy:** Suspicious',
    '',
    '## Risk Assessment',
    '',
    '- **Overall Risk Level:** 🟢 Low',
    '- **Risk Categories:** Scam Indicators',
    '- **Confidence:** Low',
    '- **Summary:** No major concerns.',
    '',
    '### Key Indicators',
    '',
    '- 🚨 C1 (Critical): advance fee requested — "pay 99 EUR to unlock the role"',
    '',
    '## Employer Verification',
    '',
    '- **Email domain matches claimed company:** N/A',
    '',
    '## Recommended Actions',
    '',
    '- Fine.',
    '',
    '## Risk Summary',
    '',
    '| Signal | Status |',
    '|--------|--------|',
    '| Posting legitimacy | ⚠️ Suspicious |',
  ]);

  // Fixture 6: Risk Assessment present but Machine Summary has no
  // risk_assessment map. Expect machine-summary-risk-missing (hard).
  write('006-wayne-2026-01-20.md', [
    '# Evaluation: Wayne Enterprises — Analyst',
    '',
    '## Machine Summary',
    '```yaml',
    'score: 4.0',
    '```',
    '',
    '## G) Posting Legitimacy',
    '**Legitimacy:** High Confidence',
    '',
    '## Risk Assessment',
    '',
    '- **Overall Risk Level:** 🟢 Low',
    '- **Risk Categories:** Likely Genuine',
    '- **Confidence:** High',
    '- **Summary:** No notable signals.',
    '',
    '## Employer Verification',
    '',
    '- **Email domain matches claimed company:** Yes',
    '',
    '## Recommended Actions',
    '',
    '- Fine.',
    '',
    '## Risk Summary',
    '',
    '| Signal | Status |',
    '|--------|--------|',
    '| Posting legitimacy | ✅ High Confidence |',
  ]);

  // Fixture 7: prose Low vs Machine Summary level high. Expect
  // risk-summary-drift (soft).
  write('007-stark-2026-01-21.md', [
    '# Evaluation: Stark Industries — Analyst',
    '',
    ...MACHINE('high'),
    '',
    '## G) Posting Legitimacy',
    '**Legitimacy:** Proceed with Caution',
    '',
    '## Risk Assessment',
    '',
    '- **Overall Risk Level:** 🟢 Low',
    '- **Risk Categories:** Suspicious',
    '- **Confidence:** Low',
    '- **Summary:** Minor concerns.',
    '',
    '## Employer Verification',
    '',
    '- **Email domain matches claimed company:** Yes',
    '',
    '## Recommended Actions',
    '',
    '- Fine.',
    '',
    '## Risk Summary',
    '',
    '| Signal | Status |',
    '|--------|--------|',
    '| Posting legitimacy | ⚠️ Proceed with Caution |',
  ]);

  // Fixture 8: Risk Assessment present but no Overall Risk Level line.
  // Expect risk-assessment-unparseable (soft).
  write('008-lexcorp-2026-01-22.md', [
    '# Evaluation: LexCorp — Analyst',
    '',
    ...MACHINE('low'),
    '',
    '## G) Posting Legitimacy',
    '**Legitimacy:** High Confidence',
    '',
    '## Risk Assessment',
    '',
    '- **Risk Categories:** Likely Genuine',
    '- **Confidence:** High',
    '- **Summary:** No notable signals.',
    '',
    '## Employer Verification',
    '',
    '- **Email domain matches claimed company:** Yes',
    '',
    '## Recommended Actions',
    '',
    '- Fine.',
    '',
    '## Risk Summary',
    '',
    '| Signal | Status |',
    '|--------|--------|',
    '| Posting legitimacy | ✅ High Confidence |',
  ]);

  // Fixture 9: EV block present but the domain field is absent. Expect
  // ev-domain-unreadable (soft).
  write('009-roxton-2026-01-23.md', [
    '# Evaluation: Roxton — Analyst',
    '',
    ...MACHINE('low'),
    '',
    '## G) Posting Legitimacy',
    '**Legitimacy:** High Confidence',
    '',
    '## Risk Assessment',
    '',
    '- **Overall Risk Level:** 🟢 Low',
    '- **Risk Categories:** Likely Genuine',
    '- **Confidence:** High',
    '- **Summary:** No notable signals.',
    '',
    '## Employer Verification',
    '',
    '- **Company website:** Found',
    '- **Additional notes:** —',
    '',
    '## Recommended Actions',
    '',
    '- Fine.',
    '',
    '## Risk Summary',
    '',
    '| Signal | Status |',
    '|--------|--------|',
    '| Posting legitimacy | ✅ High Confidence |',
  ]);

  // Fixture 10: a genuinely High report — fired H1+H2, stated 🔴 High, domain
  // No (but not Low, so the domain rule doesn't apply), Machine Summary high,
  // consistent. Expect ZERO findings — proves no over-flagging of a correct
  // High report and that the domain rule is scoped to 🟢 Low.
  write('010-triad-2026-01-24.md', [
    '# Evaluation: Triad — Analyst',
    '',
    ...MACHINE('high'),
    '',
    '## G) Posting Legitimacy',
    '**Legitimacy:** Proceed with Caution',
    '',
    '## Risk Assessment',
    '',
    '- **Overall Risk Level:** 🔴 High',
    '- **Risk Categories:** Scam Indicators, Suspicious',
    '- **Confidence:** Medium',
    '- **Summary:** Multiple strong indicators suggest caution.',
    '',
    '### Key Indicators',
    '',
    '- 🔴 H1 (High): free email domain — "recruiter@outlook.com"',
    '- 🔴 H2 (High): urgency pressure — "must apply in 24 hours"',
    '',
    '## Employer Verification',
    '',
    '- **Company website:** Found',
    '- **Email domain matches claimed company:** No',
    '- **Role found on official careers page:** Yes',
    '- **Additional notes:** —',
    '',
    '## Recommended Actions',
    '',
    '- Verify the company website and confirm the email domain matches.',
    '',
    '## Risk Summary',
    '',
    '| Signal | Status |',
    '|--------|--------|',
    '| Posting legitimacy | ⚠️ Proceed with Caution |',
  ]);

  // Fixture 11: Low report firing a gap shape ([M1]) — no documented rule,
  // so no contradiction can be asserted. Expect ZERO findings.
  write('011-cyberdyne-2026-01-25.md', [
    '# Evaluation: Cyberdyne — Analyst',
    '',
    ...MACHINE('low'),
    '',
    '## G) Posting Legitimacy',
    '**Legitimacy:** High Confidence',
    '',
    '## Risk Assessment',
    '',
    '- **Overall Risk Level:** 🟢 Low',
    '- **Risk Categories:** Suspicious',
    '- **Confidence:** Medium',
    '- **Summary:** Vague JD but no strong signals.',
    '',
    '### Key Indicators',
    '',
    '- 🟡 M1 (Medium): vague role description — "generalist role"',
    '',
    '## Employer Verification',
    '',
    '- **Email domain matches claimed company:** Yes',
    '',
    '## Recommended Actions',
    '',
    '- Fine.',
    '',
    '## Risk Summary',
    '',
    '| Signal | Status |',
    '|--------|--------|',
    '| Posting legitimacy | ✅ High Confidence |',
  ]);

  // Fixture 12: a numeric reservation sentinel must be skipped (mirrors
  // check-jd-archive-reserved.test.mjs; the real allocator writes these).
  write('042-RESERVED.md', ['{"pid": 1, "token": "fixture", "created_at": "2026-01-01"}']);

  // Fixture 13: a non-conforming filename with a clean full report chain must
  // not crash the scan (report identity stays null, no findings).
  write('hand-named-report.md', [
    '# Evaluation: Weyland — Analyst',
    '',
    ...MACHINE('low'),
    '',
    '## G) Posting Legitimacy',
    '**Legitimacy:** High Confidence',
    '',
    '## Risk Assessment',
    '',
    '- **Overall Risk Level:** 🟢 Low',
    '- **Risk Categories:** Likely Genuine',
    '- **Confidence:** High',
    '- **Summary:** No notable signals.',
    '',
    '## Employer Verification',
    '',
    '- **Email domain matches claimed company:** Yes',
    '',
    '## Recommended Actions',
    '',
    '- Fine.',
    '',
    '## Risk Summary',
    '',
    '| Signal | Status |',
    '|--------|--------|',
    '| Posting legitimacy | ✅ High Confidence |',
  ]);

  const result = checkRiskReports(reportsDir);

  check(result.reportsScanned === 12, `all 12 fixture reports scanned (got ${result.reportsScanned})`);

  const types = (file) => result.findings.filter((f) => f.file === file).map((f) => f.type);
  check(types('001-acme-2026-01-15.md').length === 0, 'clean report produces zero findings');
  check(types('002-globex-2026-01-16.md').includes('risk-blocks-missing'), 'legacy report missing all risk sections is a soft risk-blocks-missing');
  check(types('003-initech-2026-01-17.md').includes('risk-order-error'), 'reordered chain is a risk-order-error');
  check(types('004-umbrella-2026-01-18.md').includes('domain-mismatch-with-low'), 'email-domain mismatch alongside 🟢 Low is a domain-mismatch-with-low');
  check(types('005-oscorp-2026-01-19.md').includes('indicator-level-contradiction'), 'fired C1 alongside 🟢 Low is an indicator-level-contradiction');
  check(types('006-wayne-2026-01-20.md').includes('machine-summary-risk-missing'), 'Risk Assessment without a Machine Summary risk_assessment map is flagged');
  check(types('007-stark-2026-01-21.md').includes('risk-summary-drift'), 'prose vs Machine Summary level mismatch is a soft risk-summary-drift');
  check(types('008-lexcorp-2026-01-22.md').includes('risk-assessment-unparseable'), 'Risk Assessment with no Overall Risk Level line is soft-unparseable');
  check(types('009-roxton-2026-01-23.md').includes('ev-domain-unreadable'), 'EV block without the domain field is soft ev-domain-unreadable');
  check(types('010-triad-2026-01-24.md').length === 0, 'a consistent High report with fired H1+H2 is not flagged');
  check(types('011-cyberdyne-2026-01-25.md').length === 0, 'a gap-shape fired set is never asserted (no documented rule to contradict with)');
  check(!result.findings.some((f) => f.file === '042-RESERVED.md'), 'numeric reservation sentinel is skipped');
  check(!result.findings.some((f) => f.file === 'hand-named-report.md'), 'hand-named clean report scans without crashing or finding');
  check(result.findings.some((f) => f.type === 'risk-order-error' && HARD_FINDING_TYPES.has(f.type)), 'risk-order-error is a hard finding');
  check(hasHardFindings(result.findings) === true, 'hasHardFindings is true when any hard finding is present');

  const emptyDir = join(tmpDir, 'reports-empty');
  mkdirSync(emptyDir, { recursive: true });
  const emptyResult = checkRiskReports(emptyDir);
  check(emptyResult.reportsScanned === 0 && emptyResult.findings.length === 0 && !hasHardFindings(emptyResult.findings),
    'empty reports dir -> clean result, exit 0');
  const neverCreated = checkRiskReports(join(tmpDir, 'does-not-exist'));
  check(neverCreated.reportsScanned === 0 && neverCreated.findings.length === 0, 'missing reports dir -> clean result, no crash');

  rmSync(tmpDir, { recursive: true, force: true });
  console.log(`\nverify-risk.mjs --self-test: ${pass} passed, ${fail} failed`);
  return fail > 0 ? 1 : 0;
}

if (isMainModule(import.meta.url)) {
  if (selfTestMode) {
    process.exitCode = runSelfTest();
  } else if (args.includes('--help')) {
    console.log(USAGE);
  } else {
    const reportsDir = reportsDirArg ?? DEFAULT_REPORTS_DIR;
    const result = checkRiskReports(reportsDir);
    if (summaryMode) {
      printSummary(result);
    } else {
      console.log(JSON.stringify(result, null, 2));
    }
    process.exitCode = hasHardFindings(result.findings) ? 1 : 0;
  }
}