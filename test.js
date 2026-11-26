#!/usr/bin/env node
// Universal `node test` AND bare `node --test` entrypoint.
// - When invoked as `node test` (or `node test.js`): `process.env.NODE_TEST_CONTEXT` is undefined,
//   so we delegate directly to `scripts/run-tests.mjs`.
// - When discovered automatically by bare `node --test`: `process.env.NODE_TEST_CONTEXT` is set
//   by Node's test runner, so we reuse `tests/test-env.ts`'s lock-protected `ensureArtifactsBuilt()`
//   without recursively spawning `node --test`.
import fs from 'node:fs';
import path from 'node:path';

const ROOT = import.meta.dirname;

if (!process.env.NODE_TEST_CONTEXT) {
  const { runTestSuites } = await import('./scripts/run-tests.mjs');
  await runTestSuites(process.argv.slice(2));
} else {
  const { BUILT_CLIENT_PATH, BUILT_RUNNER_PATH, ensureArtifactsBuilt } = await import('./tests/test-env.ts');
  ensureArtifactsBuilt();
  const { test } = await import('node:test');
  const assert = await import('node:assert/strict');
  test('build artifacts (dist/ & client.js) are present and up to date', () => {
    assert.equal(fs.existsSync(BUILT_RUNNER_PATH), true);
    assert.equal(fs.existsSync(BUILT_CLIENT_PATH), true);
    assert.equal(fs.existsSync(path.join(ROOT, 'package.json')), true);
  });
}
