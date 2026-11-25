import { posix } from 'node:path';
import {
  isPathInside,
                          
                          
} from '../../core/src/index.js';
                                                             

                                
                              
              
                                       
 

const CWD_MARKER = '__DSH_WSL_TERM_CWD__=';

/**
 * Controlled stateful WSL terminal manager (`wsl_terminal`).
 * Keeps per-terminal working directory continuity strictly within `workspaceRoot`
 * while executing every single command inside a fresh `bwrap + seccomp + prlimit` sandbox.
 * Never exposes any human interactive terminal PTY or stdin to the model.
 */
export class ConfinedTerminalManager {
                   procManager                     ;
                   sessions = new Map                              ();

  constructor(procManager                     ) {
    this.procManager = procManager;
  }

  reset(terminalId        )          {
    return this.sessions.delete(terminalId);
  }

  clearAll()       {
    this.sessions.clear();
  }

  async exec(params                    )                              {
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
      `__dsh_emit_cwd() { local __rc=$?; printf '\\n${CWD_MARKER}%s\\n' "$(pwd -P)"; exit $__rc; }`,
      'trap __dsh_emit_cwd EXIT',
      rawCmd,
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
