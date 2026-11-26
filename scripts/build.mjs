#!/usr/bin/env node
// Zero-dependency ESM + DSH Client Bundle build script.
// 1. Dynamically loads Node built-in `stripTypeScriptTypes` (falls back gracefully to prebuilt `dist/`
//    when running on an older Node runtime if `dist/` + `client.js` are already present).
// 2. Compiles `packages/**.ts` -> `dist/packages/**.js` AND `tests/**.ts` -> `dist/.compiled-tests/**.mjs`
//    so the test suite can run even on Node runtimes without native `.ts` execution.
// 3. Emits normalized root `client.js` with single-line `window.__ModuleLoader__.load(...)` header.
import fs from 'node:fs';
import path from 'node:path';

const ROOT = path.resolve(import.meta.dirname, '..');
const PACKAGES_DIR = path.join(ROOT, 'packages');
const TESTS_DIR = path.join(ROOT, 'tests');
const DIST_DIR = path.join(ROOT, 'dist');
const COMPILED_TESTS_DIR = path.join(DIST_DIR, '.compiled-tests');
const CLIENT_SRC = path.join(ROOT, 'packages', 'dsh-plugin', 'client-src.js');
const CLIENT_OUT = path.join(ROOT, 'client.js');

function walkTs(dir, out = []) {
  if (!fs.existsSync(dir)) return out;
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      walkTs(full, out);
    } else if (entry.isFile() && entry.name.endsWith('.ts') && !entry.name.endsWith('.d.ts')) {
      out.push(full);
    }
  }
  return out;
}

function rewriteTsSpecifiers(jsCode, isCompiledTest = false) {
  let out = jsCode
    .replace(/(from\s+['"])(\.[^'"]+)\.test\.ts(['"])/g, '$1$2.compiled.mjs$3')
    .replace(/(import\s*\(\s*['"])(\.[^'"]+)\.test\.ts(['"]\s*\))/g, '$1$2.compiled.mjs$3')
    .replace(/(from\s+['"])(\.[^'"]+)\.ts(['"])/g, (_, p1, spec, p3) => {
      if (isCompiledTest && (spec === './test-env' || spec === '../test-env')) {
        return `${p1}${spec}.mjs${p3}`;
      }
      return `${p1}${spec}.js${p3}`;
    })
    .replace(/(import\s*\(\s*['"])(\.[^'"]+)\.ts(['"]\s*\))/g, (_, p1, spec, p3) => {
      if (isCompiledTest && (spec === './test-env' || spec === '../test-env')) {
        return `${p1}${spec}.mjs${p3}`;
      }
      return `${p1}${spec}.js${p3}`;
    });

  if (isCompiledTest) {
    // Adjust `<root>/tests/<subDir>/` -> `../../scripts/*` to `<root>/dist/.compiled-tests/<subDir>/` -> `../../../scripts/*`
    out = out
      .replace(/(from\s+['"])\.\.\/\.\.\/scripts\//g, '$1../../../scripts/')
      .replace(/(import\s*\(\s*['"])\.\.\/\.\.\/scripts\//g, '$1../../../scripts/');
  }
  return out;
}

const pkgFiles = walkTs(PACKAGES_DIR);
const prebuiltMain = path.join(DIST_DIR, 'packages', 'dsh-plugin', 'src', 'index.js');

const nodeMod = await import('node:module');
const stripTypeScriptTypes = nodeMod.stripTypeScriptTypes;

if (typeof stripTypeScriptTypes !== 'function' || pkgFiles.length === 0 || !fs.existsSync(CLIENT_SRC)) {
  if (fs.existsSync(prebuiltMain) && fs.existsSync(CLIENT_OUT)) {
    console.log('[build] Using prebuilt dist/ and client.js artifacts.');
    process.exit(0);
  }
  throw new Error(
    'Cannot build from TypeScript sources: requires Node.js >=22.18 / 24 LTS stripTypeScriptTypes (or prebuilt dist/ + client.js).',
  );
}

fs.rmSync(DIST_DIR, { recursive: true, force: true });

let compiled = 0;

for (const file of pkgFiles) {
  const rel = path.relative(ROOT, file);
  const outPath = path.join(DIST_DIR, rel.replace(/\.ts$/, '.js'));
  fs.mkdirSync(path.dirname(outPath), { recursive: true });
  const source = fs.readFileSync(file, 'utf8');
  const stripped = stripTypeScriptTypes(source, { mode: 'strip' });
  const finalCode = rewriteTsSpecifiers(stripped, false);
  fs.writeFileSync(outPath, finalCode, 'utf8');
  if (source.startsWith('#!')) {
    try { fs.chmodSync(outPath, 0o755); } catch { /* ignore on win32 */ }
  }
  compiled++;
}

const testFiles = walkTs(TESTS_DIR);
let compiledTests = 0;
for (const file of testFiles) {
  const relFromTests = path.relative(TESTS_DIR, file);
  const outName = relFromTests.endsWith('.test.ts')
    ? relFromTests.replace(/\.test\.ts$/, '.compiled.mjs')
    : relFromTests.replace(/\.ts$/, '.mjs');
  const outPath = path.join(COMPILED_TESTS_DIR, outName);
  fs.mkdirSync(path.dirname(outPath), { recursive: true });
  const source = fs.readFileSync(file, 'utf8');
  const stripped = stripTypeScriptTypes(source, { mode: 'strip' });
  const finalCode = rewriteTsSpecifiers(stripped, true);
  fs.writeFileSync(outPath, finalCode, 'utf8');
  compiledTests++;
}

const clientCode = fs.readFileSync(CLIENT_SRC, 'utf8').trimStart();
if (!clientCode.startsWith('window.__ModuleLoader__.load(')) {
  throw new Error('client-src.js must begin with window.__ModuleLoader__.load(');
}
fs.writeFileSync(CLIENT_OUT, clientCode + '\n', 'utf8');

console.log(
  `[build] Compiled ${compiled} package files + ${compiledTests} test files into dist/ and emitted client.js`,
);
