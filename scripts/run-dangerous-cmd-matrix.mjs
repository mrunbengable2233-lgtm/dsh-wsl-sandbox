#!/usr/bin/env node
// Zero-execution Red-Team Dangerous Command Batch Verifier (`dsh-wsl-sandbox`).
// Evaluates AI-generated JSON or NDJSON dangerous/benign command matrices purely against
// the deterministic guard engines (`evaluatePwshCommand`, `evaluateBashCommand`,
// `evaluateHostPosixBashOnWindows`, `validateShareEntry`, `validateDeviceNode`) WITHOUT
// ever executing destructive commands on the host machine!
//
// Usage:
//   node scripts/run-dangerous-cmd-matrix.mjs [--input path/to/batch.json] [--json]
import fs from 'node:fs';
import path from 'node:path';

const ROOT = path.resolve(import.meta.dirname, '..');
const DEFAULT_SEED = path.join(ROOT, 'tests', 'fixtures', 'dangerous-commands-seed.json');

const coreIndex = path.join(ROOT, 'dist', 'packages', 'core', 'src', 'index.js');
const pwshHook = path.join(ROOT, 'dist', 'packages', 'dsh-plugin', 'src', 'pwsh-hook.js');

if (!fs.existsSync(coreIndex) || !fs.existsSync(pwshHook)) {
  const { spawnSync } = await import('node:child_process');
  const buildRes = spawnSync(process.execPath, [path.join(ROOT, 'scripts', 'build.mjs')], {
    cwd: ROOT,
    stdio: 'inherit',
  });
  if (buildRes.status !== 0) process.exit(buildRes.status ?? 1);
}

const {
  evaluateBashCommand,
  evaluatePwshCommand,
  validateDeviceNode,
  validateShareEntry,
} = await import('../dist/packages/core/src/index.js');
const { evaluateHostPosixBashOnWindows } = await import('../dist/packages/dsh-plugin/src/pwsh-hook.js');

function parseInputFile(filePath) {
  const raw = fs.readFileSync(filePath, 'utf8').trim();
  if (!raw) return [];
  if (raw.startsWith('[')) {
    return JSON.parse(raw);
  }
  if (raw.startsWith('{') && !raw.includes('\n{')) {
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed.cases)) return parsed.cases;
    return [parsed];
  }
  // NDJSON (one JSON object per line)
  return raw
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0 && !line.startsWith('#') && !line.startsWith('//'))
    .map((line) => JSON.parse(line));
}

function decisionSatisfies(actual, expected) {
  if (Array.isArray(expected)) {
    return expected.includes(actual);
  }
  if (expected === 'intercept') {
    // Either hard-denied (L0) or forced into human approval (L2/L3) — never silently allowed!
    return actual === 'deny' || actual === 'ask';
  }
  return actual === expected;
}

export function runDangerousCommandMatrix(cases) {
  const results = [];
  let passed = 0;
  let falseNegatives = 0;
  let falsePositives = 0;
  let otherMismatches = 0;

  for (let i = 0; i < cases.length; i++) {
    const tc = cases[i];
    const id = tc.id || `CASE-${String(i + 1).padStart(3, '0')}`;
    const surface = tc.surface || 'pwsh';
    const expectedDecision = tc.expectedDecision;

    let actualDecision = 'allow';
    let touchesPhysicalDevice = false;
    let requiresSessionRuleBlocked = false;
    let reasons = [];

    if (surface === 'pwsh') {
      const res = evaluatePwshCommand(String(tc.command ?? ''));
      actualDecision = res.decision;
      touchesPhysicalDevice = res.touchesPhysicalDevice;
      requiresSessionRuleBlocked = res.requiresSessionRuleBlocked;
      reasons = [...res.reasons];
    } else if (surface === 'bash') {
      const workspaceRoot = tc.workspaceRoot || '/home/dev/project';
      const res = evaluateBashCommand(String(tc.command ?? ''), {
        workspaceRoot,
        cwd: tc.cwd || workspaceRoot,
      });
      actualDecision = res.decision;
      touchesPhysicalDevice = res.touchesPhysicalDevice;
      requiresSessionRuleBlocked = res.requiresSessionRuleBlocked;
      reasons = [...res.reasons];
    } else if (surface === 'host-posix') {
      const res = evaluateHostPosixBashOnWindows(String(tc.command ?? ''));
      actualDecision = res.decision;
      touchesPhysicalDevice = res.touchesPhysicalDevice;
      requiresSessionRuleBlocked = res.requiresSessionRuleBlocked;
      reasons = [...res.reasons];
    } else if (surface === 'share') {
      try {
        validateShareEntry({
          id: 'fuzz-sh',
          alias: tc.alias || '',
          sourceLinuxPath: String(tc.path ?? tc.command ?? ''),
          mode: tc.mode || 'ro',
          oneShot: false,
        });
        actualDecision = 'allow';
      } catch (err) {
        actualDecision = 'deny';
        requiresSessionRuleBlocked = true;
        reasons = [err instanceof Error ? err.message : String(err)];
      }
    } else if (surface === 'device') {
      try {
        validateDeviceNode({
          id: 'fuzz-dev',
          path: String(tc.path ?? tc.command ?? ''),
          mode: tc.mode || 'rw',
        });
        actualDecision = 'allow';
        touchesPhysicalDevice = true;
        requiresSessionRuleBlocked = true;
      } catch (err) {
        actualDecision = 'deny';
        requiresSessionRuleBlocked = true;
        reasons = [err instanceof Error ? err.message : String(err)];
      }
    } else {
      throw new Error(`Unsupported surface '${surface}' in case ${id}`);
    }

    let ok = decisionSatisfies(actualDecision, expectedDecision);
    let mismatchKind = null;

    if (!ok) {
      if (actualDecision === 'allow' && expectedDecision !== 'allow') {
        mismatchKind = 'FALSE_NEGATIVE_BYPASS';
        falseNegatives++;
      } else if (expectedDecision === 'allow' && actualDecision !== 'allow') {
        mismatchKind = 'FALSE_POSITIVE_OVERBLOCK';
        falsePositives++;
      } else {
        mismatchKind = 'TIER_MISMATCH';
        otherMismatches++;
      }
    } else if (tc.expectSingleShotLock === true && !requiresSessionRuleBlocked) {
      ok = false;
      mismatchKind = 'MISSING_SINGLE_SHOT_LOCK';
      falseNegatives++;
    } else if (tc.expectPhysicalFlag === true && !touchesPhysicalDevice) {
      ok = false;
      mismatchKind = 'MISSING_PHYSICAL_DEVICE_FLAG';
      otherMismatches++;
    }

    if (ok) passed++;

    results.push({
      id,
      category: tc.category || 'uncategorized',
      surface,
      input: tc.command ?? tc.path,
      expectedDecision,
      actualDecision,
      requiresSessionRuleBlocked,
      touchesPhysicalDevice,
      ok,
      mismatchKind,
      reasons,
    });
  }

  return {
    total: cases.length,
    passed,
    failed: cases.length - passed,
    falseNegatives,
    falsePositives,
    otherMismatches,
    results,
  };
}

const isMain =
  process.argv[1] &&
  path.resolve(process.argv[1]) === path.resolve(import.meta.filename);

if (isMain) {
  const args = process.argv.slice(2);
  let inputPath = DEFAULT_SEED;
  let asJson = false;

  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--input' && args[i + 1]) {
      inputPath = path.resolve(args[++i]);
    } else if (args[i].startsWith('--input=')) {
      inputPath = path.resolve(args[i].slice('--input='.length));
    } else if (args[i] === '--json') {
      asJson = true;
    } else if (!args[i].startsWith('-')) {
      inputPath = path.resolve(args[i]);
    }
  }

  const cases = parseInputFile(inputPath);
  const report = runDangerousCommandMatrix(cases);

  if (asJson) {
    console.log(JSON.stringify(report, null, 2));
  } else {
    console.log('====================================================================');
    console.log(` dsh-wsl-sandbox Red-Team Matrix  |  Total: ${report.total}  |  Pass: ${report.passed}  |  Fail: ${report.failed}`);
    console.log(` False-Negative Bypasses: ${report.falseNegatives}  |  False-Positives: ${report.falsePositives}`);
    console.log('====================================================================');
    for (const r of report.results) {
      const tag = r.ok ? '[PASS]' : `[FAIL:${r.mismatchKind}]`;
      console.log(
        `${tag.padEnd(32)} ${r.id.padEnd(14)} [${r.surface}] expected=${JSON.stringify(r.expectedDecision)} actual=${r.actualDecision}`,
      );
      if (!r.ok) {
        console.log(`    Input  : ${r.input}`);
        console.log(`    Reasons: ${r.reasons.join(' | ') || '(none)'}`);
      }
    }
  }

  process.exit(report.failed === 0 ? 0 : 1);
}
