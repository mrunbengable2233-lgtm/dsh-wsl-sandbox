export type SandboxErrorCode =
  | 'INVALID_SETUP'
  | 'INVALID_ACTION'
  | 'BACKEND_UNAVAILABLE'
  | 'SANDBOX_UNAVAILABLE'
  | 'SANDBOX_PREPARATION_FAILED'
  | 'POLICY_BLOCK'
  | 'STALE_BINDING'
  | 'REVIEW_DENIED'
  | 'REVIEW_TIMEOUT'
  | 'REVIEW_CANCELLED'
  | 'REVIEW_UNAVAILABLE'
  | 'REVIEW_INVALID'
  | 'REVIEW_ERROR'
  | 'GRANT_CONSUMED'
  | 'COMMAND_NOT_FOUND'
  | 'PROCESS_EXIT'
  | 'TIMEOUT'
  | 'CANCELLED'
  | 'OUTPUT_LIMIT';

export interface SandboxErrorDetails {
  readonly [key: string]: unknown;
}

export class SandboxError extends Error {
  readonly code: SandboxErrorCode;
  readonly details?: SandboxErrorDetails;

  constructor(
    code: SandboxErrorCode,
    message?: string,
    details?: SandboxErrorDetails,
    options?: ErrorOptions,
  ) {
    super(message ?? code, options);
    this.name = 'SandboxError';
    this.code = code;
    if (details !== undefined) {
      this.details = details;
    }
    Error.captureStackTrace?.(this, SandboxError);
  }
}

export function failSandbox(
  code: SandboxErrorCode,
  message?: string,
  details?: SandboxErrorDetails,
  options?: ErrorOptions,
): never {
  throw new SandboxError(code, message, details, options);
}

export function isSandboxError(err: unknown): err is SandboxError {
  return err instanceof SandboxError;
}
