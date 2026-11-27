#!/usr/bin/env node
// Universal `node test` AND bare `node --test` entrypoint.
// - When invoked as `node test` (or `node test.js`): `process.env.NODE_TEST_CONTEXT` is undefined,
//   so we delegate directly to `scripts/run-tests.mjs`.
// - When discovered automatically by bare `node --test`: `process.env.NODE_TEST_CONTEXT` is set
//   by Node's test runner, so we build `.cache/compiled-tests/test-env.mjs` if missing and
//   dynamically import it without recursively spawning `node --test`.
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const ROOT = import.meta.dirname;

if (!process.env.NODE_TEST_CONTEXT) {
  const { runTestSuites } = await import('./scripts/run-tests.mjs');
  await runTestSuites(process.argv.slice(2));
} else {
  const compiledTestEnv = path.join(ROOT, '.cache', 'compiled-tests', 'test-env.mjs');
  if (!fs.existsSync(compiledTestEnv)) {
    const buildEnv = { ...process.env };
    delete buildEnv.NODE_OPTIONS;
    if (process.versions && process.versions.electron) {
      buildEnv.ELECTRON_RUN_AS_NODE = '1';
    }
    const res = spawnSync(process.execPath, [path.join(ROOT, 'scripts', 'build.mjs')], {
      cwd: ROOT,
      stdio: 'inherit',
      env: buildEnv,
      windowsHide: true,
    });
    if (res.status !== 0) {
      throw new Error(`Failed building test artifacts via scripts/build.mjs (exit ${res.status ?? 1})`);
    }
  }
  const { BUILT_CLIENT_PATH, BUILT_RUNNER_PATH, ensureArtifactsBuilt } = await import(
    pathToFileURL(compiledTestEnv).href
  );
  ensureArtifactsBuilt();
  const { test } = await import('node:test');
  const assert = await import('node:assert/strict');
  test('build artifacts (dist/ & client.js) are present and up to date', () => {
    assert.equal(fs.existsSync(BUILT_RUNNER_PATH), true);
    assert.equal(fs.existsSync(BUILT_CLIENT_PATH), true);
    assert.equal(fs.existsSync(path.join(ROOT, 'package.json')), true);
  });
}
