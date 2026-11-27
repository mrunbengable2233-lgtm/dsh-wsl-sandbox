import type { IncomingMessage, ServerResponse } from 'node:http';

/**
 * Structural TypeScript interfaces for the DeepSeek Harness (DSH) Cordis host context.
 * Supports BOTH real `@deepseek-ai/dsh` (>=0.2.1-rc.1 / 0.2.2-rc.5) services AND lightweight
 * standalone coexistence test harnesses, while keeping zero runtime npm dependencies.
 */

export type Disposer = () => void | Promise<void>;

export interface DshLogger {
  info(msg: string, ...args: unknown[]): void;
  warn(msg: string, ...args: unknown[]): void;
  error(msg: string, ...args: unknown[]): void;
  debug?(msg: string, ...args: unknown[]): void;
}

export type DshLoggerInput = Partial<DshLogger> | ((name: string) => Partial<DshLogger>);

export interface DshContentBlock {
  readonly type: 'text';
  readonly text: string;
}

export interface DshToolOutputDefinition {
  readonly schema: Readonly<Record<string, unknown>>;
  render(args: unknown, value: unknown): DshContentBlock[];
}

export interface DshToolCallMeta {
  readonly callId?: string;
  readonly sessionId?: string;
  readonly agent?: unknown;
  readonly signal?: AbortSignal;
}

export interface DshToolDefinition<TInput = Record<string, unknown>, TOutput = unknown> {
  readonly name: string;
  readonly description: string;
  readonly parameters: Readonly<Record<string, unknown>>;
  readonly output: DshToolOutputDefinition;
  readonly isConcurrencySafe?: (args: unknown) => boolean;
  readonly execute: (input: TInput, meta?: DshToolCallMeta) => Promise<TOutput>;
}

export interface DshRealToolExecution {
  readonly name: string;
  readonly arguments: unknown;
  readonly callId?: string;
  readonly agent?: unknown;
  readonly signal?: AbortSignal;
}

export interface DshToolGuardDenial {
  readonly reason: string;
  readonly info?: {
    readonly name: string;
    readonly code: string;
    readonly reason?: string;
  };
}

export type DshToolGuard = (
  execution: Readonly<DshRealToolExecution>,
) => string | DshToolGuardDenial | undefined;

export interface DshToolRegistry {
  register(tool: DshToolDefinition): (() => void) | void;
  guard?(fn: DshToolGuard): (() => void) | void;
  has?(name: string): boolean;
}

export interface DshSystemPromptSection {
  readonly id: string;
  readonly order: number;
  readonly content: string | (() => string | Promise<string>);
}

export interface DshRealPromptSection {
  readonly name: string;
  readonly order: number;
  readonly interpolate?: boolean;
  readonly text: string | ((context?: unknown) => string);
}

export interface DshSystemPromptService {
  /** Real `@deepseek-ai/dsh-system-prompt` API */
  section?(section: DshRealPromptSection): () => void;
  /** Fallback / standalone test harness API */
  register?(section: DshSystemPromptSection): Disposer | void;
}

export interface DshHostApprovalRequest {
  readonly source?: string;
  readonly requestId?: string;
  readonly kind?: string;
  readonly summary?: string;
  readonly command?: string;
  readonly reasons?: readonly string[];
  readonly touchesPhysicalDevice?: boolean;
  readonly allowSessionRule?: boolean;
  // Real `@deepseek-ai/dsh-user-approval` fields:
  readonly agent?: unknown;
  readonly toolName?: string;
  readonly callId?: string;
  readonly reason?: string;
  readonly signal?: AbortSignal;
}

export interface DshHostApprovalResult {
  readonly decision: 'allow-once' | 'allow-session-rule' | 'deny' | 'deny-with-guidance';
  readonly guidance?: string;
  readonly sessionPrefix?: readonly string[];
  readonly bypassed?: boolean;
  readonly hooksDenyBypass?: boolean;
  readonly humanVerified?: boolean;
  readonly source?: string;
}

export type DshRealApprovalOutcome =
  | 'allowed-once'
  | 'allowed-always'
  | 'allowed-session'
  | 'allow-once'
  | 'allow-session-rule'
  | 'allowed'
  | 'allow'
  | 'rejected'
  | 'cancelled'
  | 'unavailable';

export interface DshApprovalService {
  request(req: DshHostApprovalRequest): Promise<DshHostApprovalResult | DshRealApprovalOutcome | (string & {})>;
}

export interface DshHttpRequest {
  readonly method: string;
  readonly path: string;
  readonly params: Readonly<Record<string, string>>;
  readonly query: Readonly<Record<string, string>>;
  readonly body?: unknown;
  readonly headers: Readonly<Record<string, string | undefined>>;
}

export interface DshHttpResponse {
  status(code: number): DshHttpResponse;
  header(name: string, value: string): DshHttpResponse;
  json(payload: unknown): void;
  html(content: string): void;
  text(content: string): void;
}

export type DshHttpHandler = (req: DshHttpRequest, res: DshHttpResponse) => Promise<void> | void;

export interface DshHttpRouter {
  route(method: 'GET' | 'POST' | 'PUT' | 'DELETE', path: string, handler: DshHttpHandler): Disposer | void;
}

/** Real `@deepseek-ai/dsh-host-webserver` route contract */
export interface DshWebServerRoute {
  readonly kind: 'exact' | 'prefix';
  readonly path: string;
  readonly handler: (req: IncomingMessage, res: ServerResponse) => void | Promise<void>;
}

export interface DshWebServer {
  readonly host?: string;
  readonly port?: number;
  readonly protocol?: string;
  register(route: DshWebServerRoute): () => void;
}

export type DshConnectionAdmission =
  | { readonly peer: unknown }
  | { readonly rejection: number };

export interface DshConnectionService {
  readonly trustedHosts?: readonly string[];
  admit?(req: IncomingMessage): DshConnectionAdmission;
}

export interface DshToolPreExecutePayload {
  readonly toolName?: string;
  readonly input?: Record<string, unknown>;
  readonly sessionId?: string;
  readonly callId?: string;
  // Real `@deepseek-ai/dsh-tools` ToolExecution fields:
  readonly name?: string;
  readonly arguments?: unknown;
  readonly agent?: unknown;
  readonly signal?: AbortSignal;
}

export type DshPreToolDecision =
  | { readonly kind: 'allow' }
  | {
      readonly kind: 'deny';
      readonly reason: string;
      readonly info?: { readonly name: string; readonly code: string; readonly reason?: string };
    }
  | { readonly kind: 'cancel' }
  | { readonly kind: 'ask'; readonly reason?: string };

export type DshWaterfallListener<TPayload, TResult = unknown> = (
  payload: TPayload,
  next: () => Promise<TResult>,
) => Promise<TResult>;

export interface DshCordisContext {
  readonly tools?: DshToolRegistry;
  readonly systemPrompt?: DshSystemPromptService;
  readonly approval?: DshApprovalService;
  readonly webServer?: DshWebServer;
  readonly connection?: DshConnectionService;
  readonly http?: DshHttpRouter;
  readonly logger?: DshLoggerInput;
  get?(name: string): unknown;
  inject?(deps: readonly string[], callback: (ctx: DshCordisContext) => void): (() => void) | void;
  /** Cordis 4 瀑布流事件订阅接口（必须优先用 `ctx.on`，`ctx.waterfall` 为派发而非订阅！） */
  on?<TPayload = unknown, TResult = unknown>(
    event: string,
    listener: DshWaterfallListener<TPayload, TResult>,
  ): Disposer | (() => boolean) | void;
  /** 仅用于兼容早期独立测试桩；在真实 Cordis 宿主上请勿将其当成订阅函数调用 */
  waterfall?<TPayload = unknown, TResult = unknown>(
    event: string,
    listener: DshWaterfallListener<TPayload, TResult>,
  ): Disposer | void;
  effect?(setupOrDisposer: (() => Disposer | void) | Disposer, label?: string): void;
}

/**
 * 统一订阅 Cordis 瀑布流钩子：
 * - 在真实 `@deepseek-ai/dsh`（Cordis 4）中必须调用 `ctx.on(event, listener)`（若误调 `ctx.waterfall`
 *   会直接触发空事件派发导致 `TypeError: next is not a function`）。
 * - 仅当测试桩未实现 `ctx.on` 且显式提供 `ctx.waterfall` 注册方法时，兼容回退到 `ctx.waterfall`。
 */
export function subscribeCordisWaterfall<TPayload = unknown, TResult = unknown>(
  ctx: DshCordisContext,
  event: string,
  listener: DshWaterfallListener<TPayload, TResult>,
): (() => void) | undefined {
  if (typeof ctx.on === 'function') {
    const dispose = ctx.on(event, listener);
    return typeof dispose === 'function' ? () => { void dispose(); } : undefined;
  }
  if (typeof ctx.waterfall === 'function') {
    const dispose = ctx.waterfall(event, listener);
    return typeof dispose === 'function' ? () => { void dispose(); } : undefined;
  }
  return undefined;
}

export function getOptionalService<K extends keyof DshCordisContext & string>(
  ctx: DshCordisContext,
  key: K,
): DshCordisContext[K] | undefined {
  if (typeof ctx.get === 'function') {
    return ctx.get(key) as DshCordisContext[K] | undefined;
  }
  return ctx[key];
}
