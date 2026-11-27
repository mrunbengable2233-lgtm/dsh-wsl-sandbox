#!/usr/bin/env node
// Zero-dependency ESM + DSH Client Bundle build script.
// 1. Dynamically loads Node built-in `stripTypeScriptTypes` (falls back gracefully to prebuilt `dist/`
//    when running on an older Node runtime if `dist/` + `client.js` are already present).
// 2. Compiles `packages/**.ts` -> `dist/packages/**.js` AND `tests/**.ts` -> `.cache/compiled-tests/**.mjs`
//    so the test suite can run even on Node runtimes without native `.ts` execution.
// 3. Emits normalized root `client.js` with single-line `window.__ModuleLoader__.load(...)` header.
import fs from 'node:fs';
import path from 'node:path';

const ROOT = path.resolve(import.meta.dirname, '..');
const PACKAGES_DIR = path.join(ROOT, 'packages');
const TESTS_DIR = path.join(ROOT, 'tests');
const DIST_DIR = path.join(ROOT, 'dist');
const COMPILED_TESTS_DIR = path.join(ROOT, '.cache', 'compiled-tests');
const CLIENT_SRC = path.join(ROOT, 'packages', 'dsh-plugin', 'client-src.js');
const CLIENT_OUT = path.join(ROOT, 'client.js');

function toPosixPath(p) {
  return p.replace(/\\/g, '/');
}

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

function mapCompiledTarget(absTarget) {
  const relPkg = path.relative(PACKAGES_DIR, absTarget);
  if (relPkg && !relPkg.startsWith('..') && !path.isAbsolute(relPkg) && absTarget.endsWith('.ts')) {
    return path.join(DIST_DIR, 'packages', relPkg.replace(/\.ts$/, '.js'));
  }
  const relTest = path.relative(TESTS_DIR, absTarget);
  if (relTest && !relTest.startsWith('..') && !path.isAbsolute(relTest) && absTarget.endsWith('.ts')) {
    const outName = relTest.endsWith('.test.ts')
      ? relTest.replace(/\.test\.ts$/, '.compiled.mjs')
      : relTest.replace(/\.ts$/, '.mjs');
    return path.join(COMPILED_TESTS_DIR, outName);
  }
  return absTarget;
}

export function resolveCompiledSpecifier(spec, sourceFile, outFile, isCompiledTest) {
  if (!spec.startsWith('./') && !spec.startsWith('../')) return spec;
  if (!isCompiledTest && !spec.endsWith('.ts')) return spec;
  if (isCompiledTest && !/\.(?:ts|js|mjs|cjs|json)$/.test(spec)) return spec;
  const absTarget = path.resolve(path.dirname(sourceFile), spec);
  const mappedOut = mapCompiledTarget(absTarget);
  let rel = path.posix.relative(toPosixPath(path.dirname(outFile)), toPosixPath(mappedOut));
  if (!rel.startsWith('.')) {
    rel = './' + rel;
  }
  return rel;
}

function skipWsAndComments(code, pos) {
  let i = pos;
  while (i < code.length) {
    const ch = code[i];
    if (ch === ' ' || ch === '\t' || ch === '\r' || ch === '\n') {
      i++;
      continue;
    }
    if (ch === '/' && code[i + 1] === '/') {
      i += 2;
      while (i < code.length && code[i] !== '\n') i++;
      continue;
    }
    if (ch === '/' && code[i + 1] === '*') {
      const end = code.indexOf('*/', i + 2);
      i = end === -1 ? code.length : end + 2;
      continue;
    }
    break;
  }
  return i;
}

function readQuotedLiteral(code, quoteStart) {
  const quote = code[quoteStart];
  if (quote !== "'" && quote !== '"') return null;
  let i = quoteStart + 1;
  while (i < code.length) {
    const ch = code[i];
    if (ch === '\\') {
      i += 2;
      continue;
    }
    if (ch === '\n' || ch === '\r') return null;
    if (ch === quote) {
      return {
        quote,
        value: code.slice(quoteStart + 1, i),
        endIdx: i + 1,
      };
    }
    i++;
  }
  return null;
}

function readRegexLiteral(code, slashStart) {
  if (code[slashStart] !== '/') return null;
  let i = slashStart + 1;
  let inCharClass = false;
  while (i < code.length) {
    const ch = code[i];
    if (ch === '\\') {
      if (i + 1 >= code.length || code[i + 1] === '\n' || code[i + 1] === '\r') {
        return null;
      }
      i += 2;
      continue;
    }
    if (ch === '\n' || ch === '\r') {
      return null;
    }
    if (ch === '[') {
      inCharClass = true;
      i++;
      continue;
    }
    if (ch === ']' && inCharClass) {
      inCharClass = false;
      i++;
      continue;
    }
    if (ch === '/' && !inCharClass) {
      i++;
      while (i < code.length && /[A-Za-z0-9_$]/.test(code[i])) i++;
      return { endIdx: i };
    }
    i++;
  }
  return null;
}

const REGEX_PREFIX_KEYWORDS = new Set([
  'return',
  'throw',
  'case',
  'default',
  'typeof',
  'void',
  'delete',
  'in',
  'instanceof',
  'new',
  'await',
  'yield',
  'else',
  'do',
  'export',
  'of',
]);

const REGEX_PREFIX_CHARS = new Set([
  '(',
  '[',
  '{',
  '}',
  ',',
  ';',
  ':',
  '?',
  '=',
  '!',
  '&',
  '|',
  '^',
  '~',
  '+',
  '-',
  '*',
  '/',
  '%',
  '<',
  '>',
  '\n',
]);

/**
 * Lexically rewrites ESM `from '...'`, dynamic `import('...')`, and side-effect `import '...'`
 * relative specifiers without ever altering `.ts` inside comments or arbitrary prose string literals.
 */
export function rewriteTsSpecifiers(jsCode, sourceFile, outFile, isCompiledTest = false) {
  let out = '';
  let lastCopied = 0;
  let i = 0;
  let prevNonWsChar = '';
  let regexAllowed = true;
  let templateDepth = 0;
  const exprBraceStack = [];

  const flushThrough = (endIdx) => {
    out += jsCode.slice(lastCopied, endIdx);
    lastCopied = endIdx;
  };

  const scanTemplateSegment = (startIdx) => {
    let pos = startIdx;
    while (pos < jsCode.length) {
      const tc = jsCode[pos];
      if (tc === '\\') {
        pos += 2;
        continue;
      }
      if (tc === '$' && jsCode[pos + 1] === '{') {
        exprBraceStack.push(1);
        pos += 2;
        regexAllowed = true;
        prevNonWsChar = '{';
        return pos;
      }
      if (tc === '`') {
        templateDepth--;
        pos++;
        regexAllowed = false;
        prevNonWsChar = '`';
        return pos;
      }
      pos++;
    }
    return pos;
  };

  while (i < jsCode.length) {
    const ch = jsCode[i];
    const next = jsCode[i + 1] ?? '';

    // Line comment
    if (ch === '/' && next === '/') {
      i += 2;
      while (i < jsCode.length && jsCode[i] !== '\n') i++;
      continue;
    }
    // Block comment
    if (ch === '/' && next === '*') {
      const end = jsCode.indexOf('*/', i + 2);
      i = end === -1 ? jsCode.length : end + 2;
      continue;
    }
    // RegExp literal when `/` follows an expression-start token
    if (ch === '/' && regexAllowed) {
      const reLit = readRegexLiteral(jsCode, i);
      if (reLit) {
        i = reLit.endIdx;
        prevNonWsChar = '/';
        regexAllowed = false;
        continue;
      }
    }
    // Regular string literal (prose strings stay untouched!)
    if (ch === "'" || ch === '"') {
      const lit = readQuotedLiteral(jsCode, i);
      if (lit) {
        i = lit.endIdx;
        prevNonWsChar = ch;
        regexAllowed = false;
        continue;
      }
      i++;
      continue;
    }
    // Template literal
    if (ch === '`') {
      templateDepth++;
      i = scanTemplateSegment(i + 1);
      continue;
    }

    // Track braces inside template `${...}` expressions
    if (exprBraceStack.length > 0) {
      if (ch === '{') {
        exprBraceStack[exprBraceStack.length - 1]++;
      } else if (ch === '}') {
        exprBraceStack[exprBraceStack.length - 1]--;
        if (exprBraceStack[exprBraceStack.length - 1] === 0) {
          exprBraceStack.pop();
          i = scanTemplateSegment(i + 1);
          continue;
        }
      }
    }

    if ((ch === '+' && next === '+') || (ch === '-' && next === '-')) {
      i += 2;
      prevNonWsChar = ch;
      regexAllowed = false;
      continue;
    }

    if (/[A-Za-z_$]/.test(ch)) {
      const idStart = i;
      const beforeIdentChar = prevNonWsChar;
      i++;
      while (i < jsCode.length && /[A-Za-z0-9_$]/.test(jsCode[i])) i++;
      const ident = jsCode.slice(idStart, i);

      if (beforeIdentChar !== '.' && (ident === 'from' || ident === 'import')) {
        let pos = skipWsAndComments(jsCode, i);
        if (ident === 'import' && jsCode[pos] === '(') {
          pos = skipWsAndComments(jsCode, pos + 1);
        }
        const lit = readQuotedLiteral(jsCode, pos);
        if (lit) {
          const rewritten = resolveCompiledSpecifier(lit.value, sourceFile, outFile, isCompiledTest);
          if (rewritten !== lit.value) {
            flushThrough(pos + 1);
            out += rewritten;
            lastCopied = lit.endIdx - 1;
          }
          i = lit.endIdx;
          prevNonWsChar = lit.quote;
          regexAllowed = false;
          continue;
        }
      }
      prevNonWsChar = jsCode[i - 1];
      regexAllowed = beforeIdentChar !== '.' && REGEX_PREFIX_KEYWORDS.has(ident);
      continue;
    }

    if (/[0-9]/.test(ch)) {
      i++;
      while (i < jsCode.length && /[0-9A-Za-z_.]/.test(jsCode[i])) i++;
      prevNonWsChar = jsCode[i - 1];
      regexAllowed = false;
      continue;
    }

    if (ch === '\n') {
      regexAllowed = true;
      i++;
      continue;
    }

    if (ch !== ' ' && ch !== '\t' && ch !== '\r') {
      prevNonWsChar = ch;
      regexAllowed = REGEX_PREFIX_CHARS.has(ch);
    }
    i++;
  }

  flushThrough(jsCode.length);
  void templateDepth;
  return out;
}

export async function runBuild() {
  const pkgFiles = walkTs(PACKAGES_DIR);
  const prebuiltMain = path.join(DIST_DIR, 'packages', 'dsh-plugin', 'src', 'index.js');

  const nodeMod = await import('node:module');
  const stripTypeScriptTypes = nodeMod.stripTypeScriptTypes;

  if (typeof stripTypeScriptTypes !== 'function' || pkgFiles.length === 0 || !fs.existsSync(CLIENT_SRC)) {
    if (fs.existsSync(prebuiltMain) && fs.existsSync(CLIENT_OUT)) {
      console.log('[build] Using prebuilt dist/ and client.js artifacts.');
      return;
    }
    throw new Error(
      'Cannot build from TypeScript sources: requires Node.js >=22.18 / 24 LTS stripTypeScriptTypes (or prebuilt dist/ + client.js).',
    );
  }

  // Clean ONLY dist/ and .cache/compiled-tests/ (never touch .cache/tmp or .cache/ms-official-docs-notes.md!)
  fs.rmSync(DIST_DIR, { recursive: true, force: true });
  fs.rmSync(COMPILED_TESTS_DIR, { recursive: true, force: true });

  let compiled = 0;

  for (const file of pkgFiles) {
    const rel = path.relative(ROOT, file);
    const outPath = path.join(DIST_DIR, rel.replace(/\.ts$/, '.js'));
    fs.mkdirSync(path.dirname(outPath), { recursive: true });
    const source = fs.readFileSync(file, 'utf8');
    const stripped = stripTypeScriptTypes(source, { mode: 'strip' });
    const finalCode = rewriteTsSpecifiers(stripped, file, outPath, false);
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
    const finalCode = rewriteTsSpecifiers(stripped, file, outPath, true);
    fs.writeFileSync(outPath, finalCode, 'utf8');
    compiledTests++;
  }

  const clientCode = fs.readFileSync(CLIENT_SRC, 'utf8').trimStart();
  if (!clientCode.startsWith('window.__ModuleLoader__.load(')) {
    throw new Error('client-src.js must begin with window.__ModuleLoader__.load(');
  }
  fs.writeFileSync(CLIENT_OUT, clientCode + '\n', 'utf8');

  console.log(
    `[build] Compiled ${compiled} package files into dist/ + ${compiledTests} test files into .cache/compiled-tests/ and emitted client.js`,
  );
}

const isDirectRun = process.argv[1] && path.resolve(process.argv[1]) === path.resolve(import.meta.filename);
if (isDirectRun) {
  await runBuild();
}
