/**
 * tests/risk-consistency.test.mjs — Risk Verification validator: behavior,
 * wiring, and read-only boundary.
 *
 * verify-risk.mjs is the deterministic post-evaluation safety net over the
 * Risk Assessment layer: it re-checks every reports/*.md for the mandated
 * risk-chain order, the Machine Summary `risk_assessment` mirror, and the
 * two under-detection shapes that matter — an Employer Verification email
 * domain mismatch recorded alongside a 🟢 Low verdict, and a fired Critical /
 * High indicator in the report's OWN Key Indicators whose re-derived level
 * contradicts the stated one. Its own --self-test (invoked via test-all.mjs's
 * CLI table) covers the finding logic on synthetic fixtures. This suite pins
 * behavior against inline report strings, the determination-rule ladder it
 * shares with tests/risk-assessment.test.mjs §3, and the wiring the script
 * needs to actually ship and run: SYSTEM_PATHS, the npm script, SCRIPTS.md,
 * AGENTS.md, verify-pipeline.mjs Check 18, and the read-only import boundary
 * (it reports risk inconsistencies; it must never be able to "fix" a report
 * by writing one).
 *
 * Safety-net framing is pinned here explicitly: the validator is documented
 * as a safety net, never a replacement for producing the Risk Assessment
 * correctly in-prompt.
 *
 * Run: node test-all.mjs --only risk-consistency
 */

import { readFileSync } from 'fs';
import { join } from 'path';
import { pass, fail, ROOT } from './helpers.mjs';
import { checkRiskReports, checkRiskReport, expectedLevelFor } from '../verify-risk.mjs';

function readFile(path) {
  return readFileSync(join(ROOT, path), 'utf-8');
}

console.log('\nRisk verification validator: behavior + wiring + read-only boundary');

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

// --- Behavior via the pure checkRiskReport (inline strings, no fs) ---
// The same shapes the --self-test fixtures assert on disk, kept in the suite
// so a regression is caught by the repo's normal test runner even when nobody
// ran the CLI self-test.
const typeSet = (content) => new Set(checkRiskReport(content).findings.map((f) => f.type));

const CLEAN = [
  '# Evaluation: Acme — Analyst',
  '',
  ...MACHINE('low'),
  '',
  '## G) Posting Legitimacy',
  '**Legitimacy:** High Confidence',
  '',
  '## Risk Assessment',
  '- **Overall Risk Level:** 🟢 Low',
  '- **Risk Categories:** Likely Genuine',
  '- **Confidence:** High',
  '- **Summary:** No notable signals.',
  '',
  '## Employer Verification',
  '- **Email domain matches claimed company:** Yes',
  '',
  '## Recommended Actions',
  '- Fine.',
  '',
  '## Risk Summary',
  '| Signal | Status |',
  '|--------|--------|',
  '| Posting legitimacy | ✅ High Confidence |',
].join('\n');

if (typeSet(CLEAN).size === 0) pass('a clean report (full chain, Low, domain Yes, no fired indicators, Machine Summary agreed) produces no findings');
else fail(`clean report produced findings: ${[...typeSet(CLEAN)].join(', ')}`);

const DOMAIN_LOW = CLEAN.replace('- **Email domain matches claimed company:** Yes', '- **Email domain matches claimed company:** No');
if (typeSet(DOMAIN_LOW).has('domain-mismatch-with-low')) pass('"Email domain matches claimed company: No" alongside 🟢 Low is flagged hard (the under-detection rule)');
else fail('email-domain-mismatch-with-Low was not flagged');

const FIRED_C1_LOW = CLEAN.replace(
  '- **Summary:** No notable signals.',
  '- **Summary:** No notable signals.\n\n### Key Indicators\n\n- 🚨 C1 (Critical): advance fee requested — "pay 99 EUR"',
);
if (typeSet(FIRED_C1_LOW).has('indicator-level-contradiction')) pass('a fired Critical indicator next to 🟢 Low is flagged hard');
else fail('fired-C1-with-Low was not flagged');

const FIRED_H4_LOW = CLEAN.replace(
  '- **Summary:** No notable signals.',
  '- **Summary:** No notable signals.\n\n### Key Indicators\n\n- 🔴 H4 (High): domain mismatch — "recruiter@outlook.com"',
);
if (typeSet(FIRED_H4_LOW).has('indicator-level-contradiction')) pass('a fired H4 indicator next to 🟢 Low is flagged hard via the ladder');
else fail('fired-H4-with-Low was not flagged');

const NOT_LOW_DOMAIN = CLEAN
  .replace('- **Overall Risk Level:** 🟢 Low', '- **Overall Risk Level:** 🔴 High')
  .replace('- **Email domain matches claimed company:** Yes', '- **Email domain matches claimed company:** No');
if (!typeSet(NOT_LOW_DOMAIN).has('domain-mismatch-with-low')) pass('a domain mismatch on a 🔴 High report is NOT flagged by the Low-only rule (scoped to the actual contradiction)');
else fail('domain-mismatch rule fired on a report that is already High');

const NO_DOMAIN_FIELD = CLEAN.replace('- **Email domain matches claimed company:** Yes\n', '');
if (typeSet(NO_DOMAIN_FIELD).has('ev-domain-unreadable')) pass('an Employer Verification block missing the domain field is soft ev-domain-unreadable');
else fail('missing EV domain field was not flagged');

const NO_RISK_BLOCKS = '# Evaluation: Acme — Analyst\n\n## G) Posting Legitimacy\n**Legitimacy:** High Confidence\n';
if (typeSet(NO_RISK_BLOCKS).has('risk-blocks-missing')) pass('a legacy report with no risk sections is a soft risk-blocks-missing, never an error');
else fail('legacy report was not flagged risk-blocks-missing');

// Build the reorder deterministically: swap the section bodies so Employer
// Verification lands before Risk Assessment.
const REORDERED_BODY = [
  '# Evaluation: Acme — Analyst',
  '',
  ...MACHINE('low'),
  '',
  '## G) Posting Legitimacy',
  '**Legitimacy:** High Confidence',
  '',
  '## Employer Verification',
  '- **Email domain matches claimed company:** Yes',
  '',
  '## Risk Assessment',
  '- **Overall Risk Level:** 🟢 Low',
  '- **Risk Categories:** Likely Genuine',
  '- **Confidence:** High',
  '- **Summary:** No notable signals.',
  '',
  '## Recommended Actions',
  '- Fine.',
  '',
  '## Risk Summary',
  '| Signal | Status |',
  '|--------|--------|',
  '| Posting legitimacy | ✅ High Confidence |',
].join('\n');
if (typeSet(REORDERED_BODY).has('risk-order-error')) pass('a reordered risk chain is flagged hard (risk-order-error)');
else fail('reordered risk chain was not flagged');

const MACHINE_NO_RA = CLEAN.replace(
  [
    '## Machine Summary',
    '```yaml',
    'score: 4.0',
    'risk_assessment:',
    '  level: low',
    '  categories: [suspicious]',
    '  confidence: Medium',
    '  summary: "fixture"',
    '```',
  ].join('\n'),
  ['## Machine Summary', '```yaml', 'score: 4.0', '```'].join('\n'),
);
if (typeSet(MACHINE_NO_RA).has('machine-summary-risk-missing')) pass('Risk Assessment present but no Machine Summary risk_assessment map is flagged hard');
else fail('missing Machine Summary risk_assessment was not flagged');

const DRIFT = CLEAN.replace('  level: low', '  level: high');
if (typeSet(DRIFT).has('risk-summary-drift')) pass('prose Low vs Machine Summary high is a soft risk-summary-drift');
else fail('prose/machine drift was not flagged');

// --- Ladder parity with tests/risk-assessment.test.mjs §3 ---
const CASES = [
  [['C1'], '🚨 Critical'],
  [['H1', 'H2'], '🔴 High'],
  [['H1', 'M1', 'M2'], '🔴 High'],
  [['M1', 'M2'], '🟡 Medium'],
  [['L1', 'L2', 'L3'], '🟢 Low'],
  [[], '🟢 Low'],
  [['C1', 'H1', 'H2', 'M1', 'M2'], '🚨 Critical'],
  [['H1', 'H2', 'M1', 'M2'], '🔴 High'],
  [['H5'], '🟡 Medium'],
  [['L2'], '🟢 Low'],
];
const ladderDrift = CASES.filter(([fired, expected]) => expectedLevelFor(fired) !== expected)
  .map(([fired]) => `[${fired.join(',')}]`);
if (ladderDrift.length === 0) pass(`expectedLevelFor mirrors the determination ladder on ${CASES.length} shapes`);
else fail(`expectedLevelFor diverges from the determination ladder on: ${ladderDrift.join('; ')}`);

const GAPS = [['M1'], ['H1', 'M1'], ['M1', 'L1']];
if (GAPS.every((fired) => expectedLevelFor(fired) === null)) pass('gap shapes ([M1], [H1,M1], [M1,L1]) resolve to null — no rule text, so no contradiction is ever asserted on them');
else fail('a gap shape resolved to a level despite having no documented determination rule');

// --- Wiring pins (mirrors tests/jd-archive-wiring.test.mjs) ---
try {
  const src = readFile('verify-risk.mjs');

  const updaterSrc = readFile('update-system.mjs');
  const sysBlock = (updaterSrc.match(/SYSTEM_PATHS\s*=\s*\[([\s\S]*?)\]/) || [, ''])[1];
  if (sysBlock.includes("'verify-risk.mjs'")) {
    pass('verify-risk.mjs is in update-system.mjs SYSTEM_PATHS (shipped + updatable)');
  } else {
    fail('verify-risk.mjs is NOT in SYSTEM_PATHS — updates would never deliver it');
  }

  const pkg = JSON.parse(readFile('package.json'));
  if (pkg.scripts && pkg.scripts['risk-verify'] === 'node verify-risk.mjs') {
    pass('package.json exposes npm run risk-verify');
  } else {
    fail('package.json missing the risk-verify script entry');
  }

  const scriptsDoc = readFile('docs/SCRIPTS.md');
  if (scriptsDoc.includes('## verify-risk') && scriptsDoc.includes('domain-mismatch-with-low')) {
    pass('docs/SCRIPTS.md documents verify-risk (section + a finding type)');
  } else {
    fail('docs/SCRIPTS.md missing the verify-risk section');
  }

  const agentsDoc = readFile('AGENTS.md');
  if (agentsDoc.includes('`verify-risk.mjs`')) {
    pass('AGENTS.md Main Files table lists verify-risk.mjs');
  } else {
    fail('AGENTS.md Main Files table missing verify-risk.mjs');
  }

  const vpSrc = readFile('verify-pipeline.mjs');
  if (vpSrc.includes('checkRiskReports') && /Check 18/.test(vpSrc)) {
    pass('verify-pipeline.mjs runs the risk check (Check 18)');
  } else {
    fail('verify-pipeline.mjs does not wire the risk check as Check 18');
  }

  // Read-only boundary, compact replica of the jd-archive check: the fs
  // import whitelist, write APIs only inside runSelfTest, no fs/promises, no
  // require() escape hatch.
  const SELF_TEST_ONLY_FS = new Set(['mkdtempSync', 'mkdirSync', 'writeFileSync', 'rmSync']);
  const READ_ONLY_FS = new Set(['readFileSync', 'readdirSync', 'existsSync']);
  const fsImportMatch = src.match(/import\s*\{([^}]*)\}\s*from\s*['"](?:node:)?fs['"]/);
  const fsNames = fsImportMatch ? fsImportMatch[1].split(',').map(s => s.trim()).filter(Boolean) : [];
  const unexpected = fsNames.filter(n => !READ_ONLY_FS.has(n) && !SELF_TEST_ONLY_FS.has(n));
  if (fsNames.length > 0 && unexpected.length === 0) {
    pass('verify-risk.mjs fs imports are read-only scanning APIs plus self-test-fixture builders');
  } else {
    fail(`verify-risk.mjs fs import boundary violated: ${unexpected.join(', ') || 'no fs import matched'}`);
  }

  const start = src.indexOf('function runSelfTest()');
  let selfTestBody = '';
  if (start !== -1) {
    const openBrace = src.indexOf('{', start);
    let depth = 0;
    let i = openBrace;
    for (; i < src.length; i += 1) {
      if (src[i] === '{') depth += 1;
      else if (src[i] === '}') {
        depth -= 1;
        if (depth === 0) break;
      }
    }
    selfTestBody = src.slice(openBrace, i + 1);
  }
  const codeOutsideSelfTest = src.replace(selfTestBody, '');
  const outsideSelfTest = codeOutsideSelfTest
    .split('\n')
    .filter(line => [...SELF_TEST_ONLY_FS].some(fn => line.includes(`${fn}(`)) && !/^\s*import\b/.test(line));
  if (outsideSelfTest.length === 0) {
    pass('verify-risk.mjs never calls a write-capable fs API outside its own self-test fixtures');
  } else {
    fail(`verify-risk.mjs calls a write-capable fs API outside runSelfTest: ${outsideSelfTest.join(' | ')}`);
  }

  if (!/from\s*['"](?:node:)?fs\/promises['"]/.test(src)) {
    pass('verify-risk.mjs does not import fs/promises');
  } else {
    fail('verify-risk.mjs imports fs/promises — write-capable API surface');
  }
  if (!/\brequire\s*\(/.test(src)) {
    pass('verify-risk.mjs has no require() escape hatch');
  } else {
    fail('verify-risk.mjs uses require() — bypasses the import whitelist');
  }

  if (/import\s*\{[^}]*fetch[^}]*\}|from\s*['"](?:node:)?https?['"]/.test(src)) {
    fail('verify-risk.mjs imports a network capability — it must be zero-network');
  } else {
    pass('verify-risk.mjs imports no network capability (zero LLM, zero network)');
  }
} catch (e) {
  fail(`risk-consistency wiring check: ${e.message}`);
}