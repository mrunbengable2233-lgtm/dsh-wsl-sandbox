import fs from 'node:fs';
import { posix } from 'node:path';

/**
 * Checklist B: Workspace-internal read-only protected files & directories.
 * Sourced from Anthropic sandbox-runtime, OpenAI Codex, Google Gemini CLI, and DSH itself.
 */
export const DANGEROUS_FILES = [
  '.gitconfig',
  '.gitmodules',
  '.bashrc',
  '.bash_profile',
  '.zshrc',
  '.zprofile',
  '.profile',
  '.ripgreprc',
  '.mcp.json',
  '.envrc',
  '.ignore',
  '.rgignore',
] as const;

export const DANGEROUS_DIRECTORIES = [
  '.git/hooks',
  '.git/config',
  '.git/HEAD',
  '.vscode',
  '.idea',
  '.claude/commands',
  '.claude/agents',
  '.claude/settings.json',
  '.claude/settings.local.json',
  '.cursor/mcp.json',
  '.agents',
  '.codex',
  '.gemini',
  '.dsh',
] as const;

export const ENV_SCAN_SKIP_DIRS = new Set([
  '.git',
  'node_modules',
  '.venv',
  'venv',
  '__pycache__',
  'dist',
  'build',
  'target',
  '.next',
  '.cache',
]);

const ENV_ALLOWLIST_SUFFIXES = new Set([
  '.env.example',
  '.env.sample',
  '.env.template',
  '.env.dist',
]);

export function isEnvSecretFilename(basename: string): boolean {
  if (ENV_ALLOWLIST_SUFFIXES.has(basename)) return false;
  return basename === '.env' || basename.startsWith('.env.');
}

export function isProtectedWorkspaceWrite(
  workspaceRoot: string,
  candidatePath: string,
): { blocked: boolean; reason?: string; matchedRule?: string } {
  const root = posix.normalize(workspaceRoot);
  const target = posix.normalize(candidatePath);

  if (target !== root && !target.startsWith(root + '/')) {
    return { blocked: true, reason: `Path is outside workspaceRoot (${root})`, matchedRule: 'outside-workspace' };
  }

  const rel = target === root ? '' : target.slice(root.length + 1);
  if (!rel) return { blocked: false };

  for (const file of DANGEROUS_FILES) {
    if (rel === file || rel.endsWith('/' + file)) {
      return {
        blocked: true,
        reason: `Protected configuration file cannot be modified inside sandbox: ${file}`,
        matchedRule: file,
      };
    }
  }

  for (const dirOrMeta of DANGEROUS_DIRECTORIES) {
    if (rel === dirOrMeta || rel.startsWith(dirOrMeta + '/')) {
      return {
        blocked: true,
        reason: `Protected metadata/config path cannot be modified inside sandbox: ${dirOrMeta}`,
        matchedRule: dirOrMeta,
      };
    }
  }

  return { blocked: false };
}

export function isMaskedEnvRead(
  workspaceRoot: string,
  candidatePath: string,
  maskEnvSecrets: boolean,
): boolean {
  if (!maskEnvSecrets) return false;
  const root = posix.normalize(workspaceRoot);
  const target = posix.normalize(candidatePath);
  if (!target.startsWith(root + '/')) return false;
  const rel = target.slice(root.length + 1);
  const base = posix.basename(rel);
  return isEnvSecretFilename(base);
}

/**
 * Scan workspace up to maxDepth (default 8) for .env / .env.* secret files,
 * safely following symlinks with cycle detection via visited realpaths.
 * Returns paths sorted by ascending length so shallow bindings apply first.
 */
export function scanEnvSecretFiles(workspaceRoot: string, maxDepth = 8): string[] {
  const found: string[] = [];
  const visitedDirs = new Set<string>();

  function walk(currentDir: string, depth: number): void {
    if (depth > maxDepth) return;
    let realDir: string;
    try {
      realDir = fs.realpathSync(currentDir);
    } catch {
      return;
    }
    if (visitedDirs.has(realDir)) return;
    visitedDirs.add(realDir);

    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(currentDir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      const fullPath = posix.join(currentDir, entry.name);
      let st: fs.Stats;
      try {
        st = fs.statSync(fullPath);
      } catch {
        continue; // Broken symlink or inaccessible entry
      }
      if (st.isDirectory()) {
        if (ENV_SCAN_SKIP_DIRS.has(entry.name)) continue;
        walk(fullPath, depth + 1);
      } else if (st.isFile() && isEnvSecretFilename(entry.name)) {
        found.push(fullPath);
      }
    }
  }

  walk(posix.normalize(workspaceRoot), 0);
  found.sort((a, b) => a.length - b.length || a.localeCompare(b));
  return found;
}
