import type {
  AuthorizedDeviceNode,
  AuthorizedShare,
  NetworkMode,
  SandboxMode,
  SessionBinding,
  WslProbeResult,
} from './binding.ts';
import type { RlimitConfig } from './bwrap-builder.ts';
import type { SandboxErrorCode } from './errors.ts';

export const MAX_RPC_FRAME_BYTES = 16 * 1024 * 1024; // 16 MiB

export interface RpcRequest<TParams = Record<string, unknown>> {
  readonly id: string;
  readonly method: string;
  readonly params: TParams;
}

export interface RpcErrorPayload {
  readonly code: SandboxErrorCode;
  readonly message: string;
  readonly details?: Record<string, unknown>;
}

export interface RpcResponse<TResult = unknown> {
  readonly id: string;
  readonly ok: boolean;
  readonly result?: TResult;
  readonly error?: RpcErrorPayload;
}

export interface RpcCallbackRequest {
  readonly kind: 'callback';
  readonly id: string;
  readonly method: 'proxy.authorizeHost';
  readonly params: { readonly host: string; readonly port: number };
}

export interface RpcCallbackResponse {
  readonly kind: 'callback-response';
  readonly id: string;
  readonly ok: boolean;
  readonly result?: { readonly allowed: boolean };
}

export interface ProxyConfigureParams {
  readonly enabled: boolean;
  readonly customAllowedDomains?: readonly string[];
  readonly upstreamProxy?: string;
  readonly localLabCidrs?: readonly string[];
  readonly localLabPorts?: readonly number[];
  readonly enableInteractiveApproval?: boolean;
}

export interface ProxyConfigureResult {
  readonly enabled: boolean;
  readonly socketPath?: string;
}

export interface ProbeParams {
  readonly sessionId: string;
  readonly distribution: string;
  readonly workspaceRoot: string;
  readonly cwd: string;
  readonly profile: SandboxMode;
  readonly revision: string;
  readonly allowLinuxDevMode?: boolean;
  readonly authorizedShares?: readonly AuthorizedShare[];
  readonly authorizedDevices?: readonly AuthorizedDeviceNode[];
}

export interface CollectedStream {
  readonly text: string;
  readonly truncated: boolean;
  readonly totalBytes: number;
  readonly spillPath?: string;
}

export interface ShellSandboxFacts {
  readonly mode: SandboxMode;
  readonly denied: boolean;
  readonly enforcement: 'full' | 'partial';
  readonly runnerFailed: boolean;
  readonly denialMatches: readonly string[];
}

export interface ProcExecParams {
  readonly execId?: string;
  readonly binding: SessionBinding;
  readonly command?: string;
  readonly argv?: readonly string[];
  readonly cwd: string;
  readonly mode: SandboxMode;
  readonly networkMode: NetworkMode;
  readonly env?: Readonly<Record<string, string | undefined>>;
  readonly dshEnv?: Readonly<Record<string, string>>;
  readonly stdin?: string;
  readonly timeoutMs?: number;
  readonly graceMs?: number;
  readonly maxOutputBytes?: number;
  readonly rlimits?: Partial<RlimitConfig>;
  readonly proxySocketHostPath?: string;
  readonly cacheDir?: string;
  readonly maskEnvSecrets?: boolean;
  readonly mirrorCn?: boolean;
}

export interface ProcExecResult {
  readonly exitCode: number | null;
  readonly signal: string | null;
  readonly timedOut: boolean;
  readonly aborted: boolean;
  readonly timeoutMs: number;
  readonly stdout: CollectedStream;
  readonly stderr: CollectedStream;
  readonly sandbox: ShellSandboxFacts;
}

export interface TerminalExecParams extends ProcExecParams {
  readonly terminalId: string;
}

export interface TerminalExecResult extends ProcExecResult {
  readonly terminalId: string;
  readonly cwd: string;
}

export interface FsDirEntry {
  readonly name: string;
  readonly kind: 'file' | 'dir' | 'symlink' | 'other';
  readonly size: number;
}

export interface GrepMatch {
  readonly file: string;
  readonly line: number;
  readonly text: string;
}

export type ProbeResponse = WslProbeResult;
