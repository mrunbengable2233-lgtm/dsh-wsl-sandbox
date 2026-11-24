/**
 * Minimal structural TypeScript interfaces for the DeepSeek Harness (DSH) Cordis host context.
 * Keeps `dsh-wsl-sandbox` 100% decoupled from private `@deepseek-ai/*` internals while staying
 * compatible with DSH Desktop, `dsh web`, `dsh headless`, and coexistence test harnesses.
 */

export type Disposer = () => void | Promise<void>;

export interface DshLogger {
  info(msg: string, ...args: unknown[]): void;
  warn(msg: string, ...args: unknown[]): void;
  error(msg: string, ...args: unknown[]): void;
  debug?(msg: string, ...args: unknown[]): void;
}

export interface DshToolDefinition<TInput = Record<string, unknown>, TOutput = unknown> {
  readonly name: string;
  readonly description: string;
  readonly parameters: Readonly<Record<string, unknown>>;
  readonly execute: (input: TInput, meta?: DshToolCallMeta) => Promise<TOutput>;
}

export interface DshToolCallMeta {
  readonly callId?: string;
  readonly sessionId?: string;
  readonly signal?: AbortSignal;
}

export interface DshToolRegistry {
  register(tool: DshToolDefinition): Disposer | void;
  has?(name: string): boolean;
}

export interface DshSystemPromptSection {
  readonly id: string;
  readonly order: number;
  readonly content: string | (() => string | Promise<string>);
}

export interface DshSystemPromptService {
  register(section: DshSystemPromptSection): Disposer | void;
}

export interface DshHostApprovalRequest {
  readonly source: string;
  readonly requestId: string;
  readonly kind: string;
  readonly summary: string;
  readonly command?: string;
  readonly reasons?: readonly string[];
  readonly touchesPhysicalDevice?: boolean;
  readonly allowSessionRule?: boolean;
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

export interface DshApprovalService {
  request(req: DshHostApprovalRequest): Promise<DshHostApprovalResult>;
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

export interface DshToolPreExecutePayload {
  readonly toolName: string;
  readonly input: Record<string, unknown>;
  readonly sessionId?: string;
  readonly callId?: string;
}

export type DshWaterfallListener<TPayload, TResult = unknown> = (
  payload: TPayload,
  next: () => Promise<TResult>,
) => Promise<TResult>;

export interface DshCordisContext {
  readonly tools?: DshToolRegistry;
  readonly systemPrompt?: DshSystemPromptService;
  readonly approval?: DshApprovalService;
  readonly http?: DshHttpRouter;
  readonly logger?: DshLogger;
  waterfall?<TPayload = unknown, TResult = unknown>(
    event: string,
    listener: DshWaterfallListener<TPayload, TResult>,
  ): Disposer | void;
  effect?(disposer: Disposer): void;
}
