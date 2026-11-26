import { posix } from 'node:path';
import {
  isPathInside,
                          
                          
} from '../../core/src/index.js';
                                                             

                                
                             
                              
              
                                       
 

const CWD_MARKER = '__DSH_WSL_TERM_CWD__=';

function makeKey(sessionId        , terminalId        )         {
  return `${sessionId}::${terminalId}`;
}

/**
 * Controlled stateful WSL terminal manager (`wsl_terminal`).
 * Isolates per-session & per-terminal state by `(sessionId, terminalId)` so invalidating
 * or resetting one session/terminal NEVER clobbers another session's CWD or processes.
 * Executes every command inside a fresh `bwrap + seccomp + prlimit` sandbox.
 */
export class ConfinedTerminalManager {
                   procManager                     ;
                   sessions = new Map                              ();

  constructor(procManager                     ) {
    this.procManager = procManager;
  }

  async reset(terminalId        , sessionId         )                   {
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

  clearSession(sessionId        , terminalId         )         {
    let cleared = 0;
    for (const [key, st] of this.sessions) {
      if (st.sessionId !== sessionId) continue;
      if (terminalId && st.terminalId !== terminalId) continue;
      this.sessions.delete(key);
      cleared += 1;
    }
    return cleared;
  }

  clearAll()       {
    this.sessions.clear();
  }

  listSessions(sessionId         )                                                                                           {
    return Array.from(this.sessions.values())
      .filter((s) => !sessionId || s.sessionId === sessionId)
      .map((s) => ({ sessionId: s.sessionId, terminalId: s.terminalId, cwd: s.cwd }));
  }

  async exec(params                    )                              {
    const key = makeKey(params.binding.sessionId, params.terminalId);
    let state = this.sessions.get(key);
    if (!state) {
      state = {
        sessionId: params.binding.sessionId,
        terminalId: params.terminalId,
        cwd: params.cwd || params.binding.cwd,
        env: {},
      };
      this.sessions.set(key, state);
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
      terminalId: params.terminalId,
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
