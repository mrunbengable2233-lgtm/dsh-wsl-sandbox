import { posix } from 'node:path';
import {
  isPathInside,
  type TerminalExecParams,
  type TerminalExecResult,
} from '../../core/src/index.ts';
import type { ConfinedProcManager } from './proc-manager.ts';

interface TerminalSessionState {
  readonly terminalId: string;
  cwd: string;
  readonly env: Record<string, string>;
}

const CWD_MARKER = '__DSH_WSL_TERM_CWD__=';

/**
 * Controlled stateful WSL terminal manager (`wsl_terminal`).
 * Keeps per-terminal working directory continuity strictly within `workspaceRoot`
 * while executing every single command inside a fresh `bwrap + seccomp + prlimit` sandbox.
 * Never exposes any human interactive terminal PTY or stdin to the model.
 */
export class ConfinedTerminalManager {
  private readonly procManager: ConfinedProcManager;
  private readonly sessions = new Map<string, TerminalSessionState>();

  constructor(procManager: ConfinedProcManager) {
    this.procManager = procManager;
  }

  reset(terminalId: string): boolean {
    return this.sessions.delete(terminalId);
  }

  clearAll(): void {
    this.sessions.clear();
  }

  async exec(params: TerminalExecParams): Promise<TerminalExecResult> {
    let state = this.sessions.get(params.terminalId);
    if (!state) {
      state = {
        terminalId: params.terminalId,
        cwd: params.cwd || params.binding.cwd,
        env: {},
      };
      this.sessions.set(params.terminalId, state);
    }

    const effectiveCwd = isPathInside(params.binding.workspaceRoot, state.cwd)
      ? state.cwd
      : params.binding.workspaceRoot;

    const rawCmd = params.command ?? '';
    const wrapped = [
      rawCmd,
      '__dsh_rc=$?',
      `printf '\\n${CWD_MARKER}%s\\n' "$(pwd -P)"`,
      'exit $__dsh_rc',
    ].join('\n');

    const result = await this.procManager.exec({
      ...params,
      command: wrapped,
      argv: undefined,
      cwd: effectiveCwd,
      env: { ...state.env, ...(params.env ?? {}) },
    });

    // Extract updated cwd if it remained inside workspaceRoot
    let cleanText = result.stdout.text;
    const markerIdx = cleanText.lastIndexOf(CWD_MARKER);
    if (markerIdx !== -1) {
      const after = cleanText.slice(markerIdx + CWD_MARKER.length).split('\n')[0]?.trim();
      if (after && after.startsWith('/')) {
        const norm = posix.normalize(after);
        if (isPathInside(params.binding.workspaceRoot, norm)) {
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
