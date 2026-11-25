#!/usr/bin/env node
// Zero-dependency ESM + DSH Client Bundle build script using Node 22+ built-in stripTypeScriptTypes.
// 1. Compiles packages/**.ts -> dist/packages/**.js with .ts import specifiers rewritten to .js.
// 2. Emits normalized root client.js with single-line window.__ModuleLoader__.load(...) header.
import fs from 'node:fs';
import path from 'node:path';
import { stripTypeScriptTypes } from 'node:module';

const ROOT = path.resolve(import.meta.dirname, '..');
const PACKAGES_DIR = path.join(ROOT, 'packages');
const DIST_DIR = path.join(ROOT, 'dist');
const CLIENT_SRC = path.join(ROOT, 'packages', 'dsh-plugin', 'client-src.js');
const CLIENT_OUT = path.join(ROOT, 'client.js');

function walk(dir, out = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      walk(full, out);
    } else if (entry.isFile() && entry.name.endsWith('.ts') && !entry.name.endsWith('.d.ts')) {
      out.push(full);
    }
  }
  return out;
}

function rewriteTsSpecifiers(jsCode) {
  return jsCode
    .replace(/(from\s+['"])(\.[^'"]+)\.ts(['"])/g, '$1$2.js$3')
    .replace(/(import\s*\(\s*['"])(\.[^'"]+)\.ts(['"]\s*\))/g, '$1$2.js$3');
}

fs.rmSync(DIST_DIR, { recursive: true, force: true });

const files = walk(PACKAGES_DIR);
let compiled = 0;

for (const file of files) {
  const rel = path.relative(ROOT, file);
  const outPath = path.join(DIST_DIR, rel.replace(/\.ts$/, '.js'));
  fs.mkdirSync(path.dirname(outPath), { recursive: true });
  const source = fs.readFileSync(file, 'utf8');
  const stripped = stripTypeScriptTypes(source, { mode: 'strip' });
  const finalCode = rewriteTsSpecifiers(stripped);
  fs.writeFileSync(outPath, finalCode, 'utf8');
  if (source.startsWith('#!')) {
    fs.chmodSync(outPath, 0o755);
  }
  compiled++;
}

const clientCode = fs.readFileSync(CLIENT_SRC, 'utf8').trimStart();
if (!clientCode.startsWith('window.__ModuleLoader__.load(')) {
  throw new Error('client-src.js must begin with window.__ModuleLoader__.load(');
}
fs.writeFileSync(CLIENT_OUT, clientCode + '\n', 'utf8');

console.log(`[build] Compiled ${compiled} TypeScript files into dist/ and emitted client.js`);
