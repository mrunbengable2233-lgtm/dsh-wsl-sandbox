#!/usr/bin/env node
// 通用 `node test` 与直接 `node --test` 兼容入口：
// - 直接运行 `node test` / `node test.js` 时，`process.env.NODE_TEST_CONTEXT` 未设置，
//   将直接转交 `scripts/run-tests.mjs` 执行全套测试（Windows 默认启用 `DSH_WSL_NO_HOST_SPAWN=1`）。
// - 通过 `node --test` 自动发现本文件时，`NODE_TEST_CONTEXT` 已由 Node 测试器注入，
//   此时仅按需预编译并检查 `dist/` 与 `client.js` 产物就绪，避免递归套娃拉起 `node --test`。
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
