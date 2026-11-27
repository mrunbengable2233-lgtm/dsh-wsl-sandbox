#!/usr/bin/env node
// `dsh-wsl-sandbox` 跨平台自动化测试编排脚本：
// 1. 自动先运行 `scripts/build.mjs`，确保 `dist/` 与 `client.js` 始终保持最新构建状态。
// 2. 使用纯 Node 遍历测试文件（不依赖在 Windows `cmd.exe` 下易失效的 Bash 通配符展开）。
// 3. 运行 `.cache/compiled-tests/` 中的预编译 JS 测试（兼容 Node 24 LTS、Node 22.x 及 Node 20+，
//    并自动复用当前 DSH/Node 载体进程及 `ELECTRON_RUN_AS_NODE=1`；Win32 下自动注入 `DSH_WSL_NO_HOST_SPAWN=1` 隔离锁）。
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const ROOT = path.resolve(import.meta.dirname, '..');

function collectFiles(dir, suffix, out = []) {
  if (!fs.existsSync(dir)) return out;
  for (const ent of fs.readdirSync(dir, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
    const full = path.join(dir, ent.name);
    if (ent.isDirectory()) {
      collectFiles(full, suffix, out);
    } else if (ent.isFile() && ent.name.endsWith(suffix)) {
      out.push(full);
    }
  }
  return out;
}

export async function runTestSuites(cliArgs = process.argv.slice(2)) {
  let suite = 'all';
  const extraTestArgs = [];

  for (let i = 0; i < cliArgs.length; i++) {
    const arg = cliArgs[i];
    if (arg === '--suite' && cliArgs[i + 1]) {
      suite = cliArgs[++i];
    } else if (arg.startsWith('--suite=')) {
      suite = arg.slice('--suite='.length);
    } else {
      extraTestArgs.push(arg);
    }
  }

  const childEnv = { ...process.env };
  delete childEnv.NODE_OPTIONS;
  if (childEnv.DSH_STRICT_KERNEL_TESTS !== '1') {
    childEnv.DSH_WSL_NO_HOST_SPAWN = '1';
  }
  if (process.versions && process.versions.electron) {
    childEnv.ELECTRON_RUN_AS_NODE = '1';
  }

  // 1. Always ensure dist/ and client.js are built first
  const buildScript = path.join(ROOT, 'scripts', 'build.mjs');
  const buildRes = spawnSync(process.execPath, [buildScript], {
    cwd: ROOT,
    stdio: 'inherit',
    env: childEnv,
    windowsHide: true,
  });
  if (buildRes.status !== 0) {
    process.exit(buildRes.status ?? 1);
  }

  // 2. Resolve suite directories from compiled JS tests (or fallback to .ts if compiled dir absent)
  const compiledRoot = path.join(ROOT, '.cache', 'compiled-tests');
  const useCompiled = fs.existsSync(compiledRoot);
  const baseDir = useCompiled ? compiledRoot : path.join(ROOT, 'tests');
  const suffix = useCompiled ? '.compiled.mjs' : '.test.ts';

  const suiteDirs = {
    unit: [path.join(baseDir, 'unit')],
    coexistence: [path.join(baseDir, 'plugin-coexistence')],
    'linux-sandbox': [path.join(baseDir, 'linux-sandbox')],
    all: [
      path.join(baseDir, 'unit'),
      path.join(baseDir, 'plugin-coexistence'),
      path.join(baseDir, 'linux-sandbox'),
    ],
  };

  const selectedDirs = suiteDirs[suite];
  if (!selectedDirs) {
    console.error(`[test] Unknown --suite '${suite}'. Expected: all | unit | coexistence | linux-sandbox`);
    process.exit(2);
  }

  const files = [];
  for (const d of selectedDirs) {
    collectFiles(d, suffix, files);
  }

  if (files.length === 0) {
    console.error(`[test] No test files found for suite '${suite}' under ${baseDir}`);
    process.exit(1);
  }

  const nodeArgs = ['--test', ...extraTestArgs, ...files];
  const testRes = spawnSync(process.execPath, nodeArgs, {
    cwd: ROOT,
    stdio: 'inherit',
    env: childEnv,
    windowsHide: true,
  });

  if (testRes.error) {
    console.error(`[test] Failed to launch node --test: ${testRes.error.message}`);
    process.exit(1);
  }
  process.exit(testRes.status ?? 1);
}

const isMain =
  process.argv[1] &&
  import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href;

if (isMain) {
  await runTestSuites();
}
