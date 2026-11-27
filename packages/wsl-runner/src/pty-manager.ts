import { randomUUID } from 'node:crypto';
import fs from 'node:fs';
import { posix } from 'node:path';
import {
  isPathInside,
  type SessionBinding,
  type TerminalExecParams,
  type TerminalExecResult,
} from '../../core/src/index.ts';
import type { ConfinedProcManager } from './proc-manager.ts';

interface TerminalSessionState {
  readonly sessionId: string;
  readonly terminalId: string;
  cwd: string;
  readonly env: Record<string, string>;
}

function makeKey(sessionId: string, terminalId: string): string {
  return `${sessionId}::${terminalId}`;
}

function toPosixPath(p: string): string {
  return p.replace(/\\/g, '/');
}

function isAllowedTerminalCwd(binding: SessionBinding, candidate: string): boolean {
  const norm = posix.normalize(toPosixPath(candidate));
  const wsRoot = posix.normalize(toPosixPath(binding.workspaceRoot));
  if (isPathInside(wsRoot, norm)) {
    return true;
  }
  try {
    const wsReal = toPosixPath(fs.realpathSync(binding.workspaceRoot));
    if (isPathInside(wsReal, norm)) {
      return true;
    }
  } catch {
    // ignore realpath lookup failure in mocked paths
  }
  if (norm === '/shares' || norm.startsWith('/shares/')) {
    const parts = norm.split('/').filter(Boolean);
    const alias = parts[1];
    if (alias && binding.authorizedShares.some((s) => s.alias === alias)) {
      return true;
    }
  }
  return false;
}

/**
 * Controlled stateful WSL terminal manager (`wsl_terminal`).
 * Isolates per-session & per-terminal state by `(sessionId, terminalId)` so invalidating
 * or resetting one session/terminal NEVER clobbers another session's CWD or processes.
 * Executes every command inside a fresh `bwrap + seccomp + prlimit` sandbox.
 */
export class ConfinedTerminalManager {
  private readonly procManager: ConfinedProcManager;
  private readonly sessions = new Map<string, TerminalSessionState>();

  constructor(procManager: ConfinedProcManager) {
    this.procManager = procManager;
  }

  async reset(terminalId: string, sessionId?: string): Promise<boolean> {
    let deleted = false;
    if (sessionId) {
      deleted = this.sessions.delete(makeKey(sessionId, terminalId));
      await this.procManager.killTerminal(sessionId, terminalId);
      return deleted;
    }
    for (const [key, st] of this.sessions) {
      if (st.terminalId === terminalId) {
        this.sessions.delete(key);
        await this.procManager.killTerminal(st.sessionId, st.terminalId);
        deleted = true;
      }
    }
    return deleted;
  }

  clearSession(sessionId: string, terminalId?: string): number {
    let cleared = 0;
    for (const [key, st] of this.sessions) {
      if (st.sessionId !== sessionId) continue;
      if (terminalId && st.terminalId !== terminalId) continue;
      this.sessions.delete(key);
      cleared += 1;
    }
    return cleared;
  }

  clearAll(): void {
    this.sessions.clear();
  }

  listSessions(sessionId?: string): Array<{ readonly sessionId: string; readonly terminalId: string; readonly cwd: string }> {
    return Array.from(this.sessions.values())
      .filter((s) => !sessionId || s.sessionId === sessionId)
      .map((s) => ({ sessionId: s.sessionId, terminalId: s.terminalId, cwd: s.cwd }));
  }

  async exec(params: TerminalExecParams): Promise<TerminalExecResult> {
    const key = makeKey(params.binding.sessionId, params.terminalId);
    const requestedCwd = params.cwd ? posix.normalize(toPosixPath(params.cwd)) : undefined;
    const bindingCwdNorm = posix.normalize(toPosixPath(params.binding.cwd));
    const shouldOverrideCwd =
      params.explicitCwd === true ||
      (params.explicitCwd !== false && Boolean(requestedCwd) && requestedCwd !== bindingCwdNorm);

    let state = this.sessions.get(key);
    if (!state) {
      const initialCwd =
        requestedCwd && isAllowedTerminalCwd(params.binding, requestedCwd)
          ? requestedCwd
          : params.binding.cwd;
      state = {
        sessionId: params.binding.sessionId,
        terminalId: params.terminalId,
        cwd: initialCwd,
        env: {},
      };
      this.sessions.set(key, state);
    } else if (shouldOverrideCwd && requestedCwd && isAllowedTerminalCwd(params.binding, requestedCwd)) {
      state.cwd = requestedCwd;
    }

    const effectiveCwd = isAllowedTerminalCwd(params.binding, state.cwd)
      ? state.cwd
      : params.binding.workspaceRoot;

    const cwdMarker = `__DSH_WSL_TERM_CWD_${randomUUID().replace(/-/g, '')}__=`;
    const rawCmd = params.command ?? '';
    const wrapped = [
      `__dsh_emit_cwd() { local __rc=$?; printf '\\n${cwdMarker}%s\\n' "$(pwd -P)"; exit $__rc; }`,
      'trap __dsh_emit_cwd EXIT',
      rawCmd,
    ].join('\n');

    const result = await this.procManager.exec({
      ...params,
      terminalId: params.terminalId,
      command: wrapped,
      argv: undefined,
      cwd: effectiveCwd,
      env: { ...state.env, ...(params.env ?? {}) },
    });

    // Extract updated cwd if it remained inside workspaceRoot or an authorized share
    let cleanText = result.stdout.text;
    const markerIdx = cleanText.lastIndexOf(cwdMarker);
    if (markerIdx !== -1) {
      const after = cleanText.slice(markerIdx + cwdMarker.length).split('\n')[0]?.trim();
      if (after && after.startsWith('/')) {
        const norm = posix.normalize(after);
        if (isAllowedTerminalCwd(params.binding, norm)) {
          state.cwd = norm;
        }
      }
      cleanText = cleanText.slice(0, markerIdx).replace(/\n$/, '');
    }

    return {
      ...result,
      stdout: {
        ...result.stdout,
        text: cleanText,
      },
      terminalId: params.terminalId,
      cwd: state.cwd,
    };
  }
}
