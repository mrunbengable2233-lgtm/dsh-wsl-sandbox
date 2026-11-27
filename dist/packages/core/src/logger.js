import fs from 'node:fs';
import path from 'node:path';

/**
 * SSD-Friendly, Zero-Lock End-to-End Structured Logging System for `dsh-wsl-sandbox`.
 *
 * Security, SSD longevity & operational invariants:
 * 1. Recursive secret redaction: scrubs credential keys (`API_KEY`, `TOKEN`, `SECRET`, `PASSWORD`,
 *    `AUTHORIZATION`, `COOKIE`, `PRIVATE_KEY`) and inline secret patterns (`Bearer ...`, `sk-...`,
 *    `ghp_...`, `github_pat_...`, `AKIA...`, URL `user:pass@host`) BEFORE storing in memory or disk.
 * 2. SSD-friendly write coalescing & rate limiting (`RotatingNdjsonSink` + `StructuredLogger`):
 *    - Buffers serialized NDJSON lines in memory and flushes in a SINGLE batched `writeSync` at most
 *      once every `flushIntervalMs` (default `2500ms`) or when `pendingBytes >= 64 KiB`, plus once
 *      on `flushSync()` / `dispose()` / `process.once('exit')`.
 *    - Suppresses duplicate log bursts within `dedupeWindowMs` (`3000ms`) and enforces a per-10s
 *      disk-write token bucket (`maxDiskEntriesPer10s = 120`) so runaway loops or `debug` storms
 *      NEVER cause SSD write amplification or wear out user drives.
 *    - Tracks `knownFileSize` in RAM to avoid repeated `statSync` metadata reads.
 * 3. Zero Windows NTFS handle lock & zero read I/O on queries:
 *    - Each batch flush uses short-lived `openSync` -> single `writeSync` -> `closeSync`, holding
 *      ZERO open file descriptors at idle.
 *    - `query()` serves 100% from the in-memory ring buffer (`0` disk reads); startup preload reads
 *      at most the final `64 KiB` tail (`readSync` with offset), never full-file `readFileSync`.
 * 4. Owner-only permissions (`0o700` dir, `0o600` file, `5 MiB x 3` bounded rotation).
 */

                                                           
                                                            

export const LOG_LEVEL_WEIGHT                                     = {
  debug: 10,
  info: 20,
  warn: 30,
  error: 40,
};

export const RUNNER_LOG_WIRE_PREFIX = '[DSH_RUNNER_LOG]';

export function isValidLogLevel(value         )                    {
  return value === 'debug' || value === 'info' || value === 'warn' || value === 'error';
}

export function normalizeLogLevel(value         , fallback           = 'info')           {
  if (typeof value === 'string') {
    const lower = value.trim().toLowerCase();
    if (isValidLogLevel(lower)) return lower;
  }
  return fallback;
}

                           
                       
                             
                           
                             
                             
                         
                           
                              
                        
                               
                                          
 

                                 
                               
                                      
                              
                              
                           
                             
                          
 

                                          
                          
                            
                             
                             
                                                                                                             
                                    
                                                                    
                                        
                                                                                                      
                                    
                                                                           
 

const SECRET_KEY_RE =
  /(?:api[_-]?key|secret|token|password|passwd|private[_-]?key|access[_-]?key|authorization|cookie|credential|client[_-]?secret)/i;

const MAX_STRING_LEN = 2048;
const MAX_OBJECT_DEPTH = 5;
const MAX_ARRAY_ITEMS = 40;
const TAIL_PRELOAD_MAX_BYTES = 64 * 1024;

/**
 * Redacts inline tokens, URL basic-auth credentials, JWT/Basic headers, PEM private keys,
 * and secret key-value assignments inside strings BEFORE truncating to MAX_STRING_LEN.
 */
export function redactSecretText(input        )         {
  let out = input;
  out = out.replace(/-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|$)/g, '[REDACTED PEM KEY]');
  out = out.replace(/([a-z][a-z0-9+.-]*:\/\/)([^/\s:@]+:[^/\s@]+)@/gi, '$1[REDACTED]@');
  out = out.replace(/\b(Bearer\s+)[A-Za-z0-9._~+/=-]{8,}/gi, '$1[REDACTED]');
  out = out.replace(/\b(Basic\s+)[A-Za-z0-9+/=]{8,}/gi, '$1[REDACTED]');
  out = out.replace(/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g, 'jwt_[REDACTED]');
  out = out.replace(/\bsk-[A-Za-z0-9_-]{12,}\b/g, 'sk-[REDACTED]');
  out = out.replace(/\bgh[pousr]_[A-Za-z0-9]{16,}\b/g, 'gh_[REDACTED]');
  out = out.replace(/\bgithub_pat_[A-Za-z0-9_]{20,}\b/g, 'github_pat_[REDACTED]');
  out = out.replace(/\bglpat-[A-Za-z0-9_-]{16,}\b/g, 'glpat-[REDACTED]');
  out = out.replace(/\bAIza[0-9A-Za-z_-]{20,}\b/g, 'AIza[REDACTED]');
  out = out.replace(/\bxox[baprs]-[A-Za-z0-9-]{12,}\b/g, 'xox-[REDACTED]');
  out = out.replace(/\bAKIA[0-9A-Z]{16}\b/g, 'AKIA[REDACTED]');
  out = out.replace(
    /\b([A-Za-z0-9_]*(?:API_KEY|SECRET|TOKEN|PASSWORD|PASSWD|PRIVATE_KEY|ACCESS_KEY)[A-Za-z0-9_]*)\s*=\s*([^\s"'`;&|]+|"[^"]*"|'[^']*')/gi,
    '$1=[REDACTED]',
  );
  if (out.length > MAX_STRING_LEN) {
    out = `${out.slice(0, MAX_STRING_LEN)}...[truncated ${out.length - MAX_STRING_LEN} chars]`;
  }
  return out;
}

/**
 * Recursively clones and redacts arbitrary structured metadata for safe logging.
 */
export function redactLogData(value         , depth = 0, seen = new WeakSet        ())          {
  if (value === null || value === undefined) return value;
  if (typeof value === 'string') return redactSecretText(value);
  if (typeof value === 'number' || typeof value === 'boolean') return value;
  if (typeof value === 'bigint') return value.toString();
  if (value instanceof Error) {
    return {
      name: value.name,
      message: redactSecretText(value.message),
      code: (value                      ).code,
    };
  }
  if (depth >= MAX_OBJECT_DEPTH) {
    return '[MaxDepth]';
  }
  if (typeof value === 'object') {
    if (seen.has(value)) return '[Circular]';
    seen.add(value);
  }
  if (Array.isArray(value)) {
    const sliced = value.slice(0, MAX_ARRAY_ITEMS).map((item) => redactLogData(item, depth + 1, seen));
    if (value.length > MAX_ARRAY_ITEMS) {
      sliced.push(`[+${value.length - MAX_ARRAY_ITEMS} more]`);
    }
    return sliced;
  }
  if (typeof value === 'object') {
    const out                          = {};
    try {
      for (const [k, v] of Object.entries(value                           )) {
        if (v === undefined) continue;
        if (SECRET_KEY_RE.test(k)) {
          out[k] = '[REDACTED]';
        } else {
          out[k] = redactLogData(v, depth + 1, seen);
        }
      }
    } catch {
      return '[UnreadableObject]';
    }
    return out;
  }
  return String(value);
}

/**
 * Coalesced, size-bounded NDJSON rotating file sink.
 * Batches multiple log lines into a single periodic write (`flushIntervalMs = 2500ms`) and
 * closes the file descriptor immediately after each batch so ZERO handles remain open at idle.
 */
export class RotatingNdjsonSink {
                   logDir        ;
                   filePath        ;
                   maxBytes        ;
                   maxFiles        ;
                   flushIntervalMs        ;
                   flushThresholdBytes        ;
                   maxPendingBytes        ;
                   hardenPath                                                     ;

          dirEnsured = false;
          knownFileSize                = null;
          pendingLines           = [];
          pendingBytes = 0;
          flushTimer                            ;
          exitHook                          ;
          diskFlushCount = 0;
          disposed = false;

  constructor(options                         ) {
    this.logDir = options.logDir;
    this.filePath = path.join(options.logDir, options.fileName);
    this.maxBytes = Math.max(8 * 1024, options.maxBytes ?? 5 * 1024 * 1024);
    this.maxFiles = Math.max(1, options.maxFiles ?? 3);
    this.flushIntervalMs = Math.max(0, options.flushIntervalMs ?? 2500);
    this.flushThresholdBytes = Math.max(4 * 1024, options.flushThresholdBytes ?? 64 * 1024);
    this.maxPendingBytes = Math.max(this.flushThresholdBytes, options.maxPendingBytes ?? 512 * 1024);
    this.hardenPath = options.hardenPath;

    const onExit = ()       => {
      this.flushSync();
    };
    this.exitHook = onExit;
    process.once('exit', onExit);
  }

  getLogDir()         {
    return this.logDir;
  }

  getFilePath()         {
    return this.filePath;
  }

  getDiskFlushCount()         {
    return this.diskFlushCount;
  }

  getPendingByteCount()         {
    return this.pendingBytes;
  }

          ensureDir()       {
    if (this.dirEnsured && fs.existsSync(this.logDir)) return;
    const existed = fs.existsSync(this.logDir);
    fs.mkdirSync(this.logDir, { recursive: true, mode: 0o700 });
    if (!existed) {
      try {
        fs.chmodSync(this.logDir, 0o700);
      } catch {
        // ignore
      }
      this.hardenPath?.(this.logDir, 'dir');
    }
    this.dirEnsured = true;
  }

          getCurrentSize()         {
    if (this.knownFileSize !== null) return this.knownFileSize;
    try {
      if (fs.existsSync(this.filePath)) {
        this.knownFileSize = fs.statSync(this.filePath).size;
      } else {
        this.knownFileSize = 0;
      }
    } catch {
      this.knownFileSize = 0;
    }
    return this.knownFileSize;
  }

          rotateFiles()       {
    try {
      const oldest = `${this.filePath}.${this.maxFiles}`;
      if (fs.existsSync(oldest)) {
        fs.rmSync(oldest, { force: true });
      }
      for (let i = this.maxFiles - 1; i >= 1; i--) {
        const src = `${this.filePath}.${i}`;
        const dst = `${this.filePath}.${i + 1}`;
        if (fs.existsSync(src)) {
          fs.renameSync(src, dst);
        }
      }
      if (fs.existsSync(this.filePath)) {
        fs.renameSync(this.filePath, `${this.filePath}.1`);
      }
      this.knownFileSize = 0;
    } catch {
      this.knownFileSize = null;
    }
  }

  append(entry          )       {
    if (this.disposed) return;
    const line = JSON.stringify(entry) + '\n';
    const byteLen = Buffer.byteLength(line, 'utf8');

    // Protect RAM if disk is stalled or huge burst arrives before flush
    while (this.pendingLines.length > 0 && this.pendingBytes + byteLen > this.maxPendingBytes) {
      const dropped = this.pendingLines.shift() ;
      this.pendingBytes -= Buffer.byteLength(dropped, 'utf8');
    }

    this.pendingLines.push(line);
    this.pendingBytes += byteLen;

    if (this.flushIntervalMs === 0 || this.pendingBytes >= this.flushThresholdBytes) {
      this.flushSync();
      return;
    }

    if (!this.flushTimer) {
      this.flushTimer = setTimeout(() => {
        this.flushTimer = undefined;
        this.flushSync();
      }, this.flushIntervalMs);
      this.flushTimer.unref();
    }
  }

  /**
   * Writes all buffered log lines in a single coalesced syscall batch and closes FD immediately.
   */
  flushSync()       {
    if (this.flushTimer) {
      clearTimeout(this.flushTimer);
      this.flushTimer = undefined;
    }
    if (this.pendingLines.length === 0) return;

    const linesToFlush = this.pendingLines;
    const bytesToFlush = this.pendingBytes;
    const batchText = linesToFlush.join('');
    this.pendingLines = [];
    this.pendingBytes = 0;

    try {
      this.ensureDir();
      const buf = Buffer.from(batchText, 'utf8');
      const currentSize = this.getCurrentSize();

      if (currentSize > 0 && currentSize + buf.length > this.maxBytes) {
        this.rotateFiles();
      }

      const isNew = this.getCurrentSize() === 0 && !fs.existsSync(this.filePath);
      const fd = fs.openSync(
        this.filePath,
        fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_APPEND,
        0o600,
      );
      try {
        fs.writeSync(fd, buf, 0, buf.length);
        this.knownFileSize = (this.knownFileSize ?? 0) + buf.length;
        this.diskFlushCount += 1;
      } finally {
        fs.closeSync(fd);
      }

      if (isNew) {
        try {
          fs.chmodSync(this.filePath, 0o600);
        } catch {
          // ignore
        }
        this.hardenPath?.(this.filePath, 'file');
      }

      // If single huge batch itself exceeded maxBytes, rotate cleanly for next batch
      if ((this.knownFileSize ?? 0) > this.maxBytes) {
        this.rotateFiles();
      }
    } catch (err) {
      this.knownFileSize = null;
      const code = (err                         ).code;
      if (code === 'EBUSY' || code === 'EPERM' || code === 'EAGAIN') {
        this.pendingLines = [...linesToFlush, ...this.pendingLines];
        this.pendingBytes += bytesToFlush;
        while (this.pendingLines.length > 0 && this.pendingBytes > this.maxPendingBytes) {
          const dropped = this.pendingLines.shift() ;
          this.pendingBytes -= Buffer.byteLength(dropped, 'utf8');
        }
        if (!this.disposed && this.flushIntervalMs > 0 && !this.flushTimer && this.pendingLines.length > 0) {
          this.flushTimer = setTimeout(() => {
            this.flushTimer = undefined;
            this.flushSync();
          }, this.flushIntervalMs);
          this.flushTimer.unref();
        }
      }
    }
  }

  /**
   * Reads ONLY the last `64 KiB` tail of the log file once on startup (never full-file read).
   */
  readRecent(maxEntries = 200)             {
    try {
      if (!fs.existsSync(this.filePath)) return [];
      const st = fs.statSync(this.filePath);
      this.knownFileSize = st.size;
      if (st.size === 0) return [];

      const readLen = Math.min(st.size, TAIL_PRELOAD_MAX_BYTES);
      const offset = st.size - readLen;
      const buf = Buffer.alloc(readLen);
      const fd = fs.openSync(this.filePath, fs.constants.O_RDONLY);
      let bytesRead = 0;
      try {
        bytesRead = fs.readSync(fd, buf, 0, readLen, offset);
      } finally {
        fs.closeSync(fd);
      }

      let slice = buf.subarray(0, bytesRead);
      // If we started mid-file, discard up through the first LF byte so UTF-8 boundaries and JSON stay valid
      if (offset > 0) {
        const firstNl = slice.indexOf(0x0a);
        if (firstNl === -1) return [];
        slice = slice.subarray(firstNl + 1);
      }
      const lines = slice.toString('utf8').split(/\r?\n/);
      const nonEmpty = lines.filter(Boolean).slice(-maxEntries);
      const parsed             = [];
      for (const line of nonEmpty) {
        try {
          const obj = JSON.parse(line)            ;
          if (obj && typeof obj.timestamp === 'string' && isValidLogLevel(obj.level)) {
            parsed.push(obj);
          }
        } catch {
          // skip partial/corrupt line
        }
      }
      return parsed;
    } catch {
      return [];
    }
  }

  clear()         {
    if (this.flushTimer) {
      clearTimeout(this.flushTimer);
      this.flushTimer = undefined;
    }
    this.pendingLines = [];
    this.pendingBytes = 0;
    this.knownFileSize = 0;

    let removed = 0;
    try {
      const candidates = [this.filePath];
      for (let i = 1; i <= this.maxFiles; i++) {
        candidates.push(`${this.filePath}.${i}`);
      }
      for (const file of candidates) {
        if (fs.existsSync(file)) {
          fs.rmSync(file, { force: true });
          removed += 1;
        }
      }
    } catch {
      // ignore
    }
    return removed;
  }

  dispose()       {
    if (this.disposed) return;
    this.flushSync();
    this.disposed = true;
    if (this.exitHook) {
      process.off('exit', this.exitHook);
      this.exitHook = undefined;
    }
  }
}

                                          
                             
                            
                                     
                                         
                                     
                                                                    
                                   
                                                                                                       
                                         
                                               
 

                                 
                             
                         
                           
                              
                        
                               
                                          
 

                                  
                                                                                                                                   
                                                                                                                                  
                                                                                                                                  
                                                                                                                                   
 

                       
              
                  
                    
                     
                    
                
                  
                              
                
 

export class StructuredLogger {
                   source           ;
          level          ;
                   maxMemoryEntries        ;
                   fileSink                     ;
                   dedupeWindowMs        ;
                   maxDiskEntriesPer10s        ;
                   onEntry                            ;
                   buffer             = [];
          seq = 0;

          lastDedupe                         ;
          rateWindowStartMs = Date.now();
          rateWindowDiskWrites = 0;
          rateDroppedCount = 0;

  constructor(options                         ) {
    this.source = options.source;
    this.level = options.level ?? 'info';
    this.maxMemoryEntries = Math.max(50, options.maxMemoryEntries ?? 600);
    this.fileSink = options.fileSink;
    this.dedupeWindowMs = Math.max(0, options.dedupeWindowMs ?? 3000);
    this.maxDiskEntriesPer10s = Math.max(10, options.maxDiskEntriesPer10s ?? 120);
    this.onEntry = options.onEntry;

    if (options.preloadFromDisk !== false && this.fileSink) {
      const historical = this.fileSink.readRecent(Math.min(150, this.maxMemoryEntries));
      for (const item of historical) {
        this.seq += 1;
        this.pushToMemory({ ...item, seq: this.seq });
      }
    }
  }

  getLevel()           {
    return this.level;
  }

  setLevel(level          )       {
    if (isValidLogLevel(level)) {
      this.level = level;
    }
  }

  getLogFilePath()                     {
    return this.fileSink?.getFilePath();
  }

  getLogDir()                     {
    return this.fileSink?.getLogDir();
  }

  getBufferedCount()         {
    return this.buffer.length;
  }

  getDiskStats()                                                                             {
    return {
      diskFlushCount: this.fileSink?.getDiskFlushCount() ?? 0,
      pendingBytes: this.fileSink?.getPendingByteCount() ?? 0,
      rateDroppedCount: this.rateDroppedCount,
    };
  }

          pushToMemory(entry          )       {
    this.buffer.push(entry);
    if (this.buffer.length > this.maxMemoryEntries) {
      this.buffer.splice(0, this.buffer.length - this.maxMemoryEntries);
    }
  }

          allowDiskPersistence(level          , nowMs        )          {
    if (!this.fileSink) return false;
    if (nowMs - this.rateWindowStartMs >= 10_000) {
      this.rateWindowStartMs = nowMs;
      this.rateWindowDiskWrites = 0;
    }
    // Warn/error get 2x headroom so security alerts aren't silenced, while still hard-capped to protect SSD
    const cap = level === 'warn' || level === 'error' ? this.maxDiskEntriesPer10s * 2 : this.maxDiskEntriesPer10s;
    if (this.rateWindowDiskWrites >= cap) {
      this.rateDroppedCount += 1;
      return false;
    }
    this.rateWindowDiskWrites += 1;
    return true;
  }

          emitSummaryForSuppressedDuplicates()       {
    const state = this.lastDedupe;
    if (!state || state.count === 0) return;
    const suppressedCount = state.count;
    state.count = 0;

    this.seq += 1;
    const summaryEntry           = {
      seq: this.seq,
      timestamp: new Date().toISOString(),
      level: state.level,
      source: state.source,
      component: state.component,
      event: `${state.event}.coalesced`,
      message: `${state.message} (coalesced ${suppressedCount} identical repeats)`,
      ...(state.sessionId ? { sessionId: state.sessionId } : {}),
      pid: process.pid,
      data: { suppressedDuplicates: suppressedCount },
    };
    this.pushToMemory(summaryEntry);
    if (this.allowDiskPersistence(state.level, Date.now())) {
      this.fileSink?.append(summaryEntry);
    }
    this.onEntry?.(summaryEntry);
  }

          recordInternal(
    level          ,
    source           ,
    fields                                                  ,
  )                       {
    if (!this.shouldLog(level)) return undefined;

    const nowMs = Date.now();
    const cleanMessage = redactSecretText(fields.message);
    const dedupeKey = `${level}|${source}|${fields.sessionId ?? ''}|${fields.component}|${fields.event}|${cleanMessage}`;

    if (this.dedupeWindowMs > 0 && this.lastDedupe) {
      if (
        this.lastDedupe.key === dedupeKey &&
        nowMs - this.lastDedupe.firstSuppressedAtMs <= this.dedupeWindowMs
      ) {
        this.lastDedupe.count += 1;
        return undefined;
      }
      if (this.lastDedupe.count > 0) {
        this.emitSummaryForSuppressedDuplicates();
      }
    }

    this.lastDedupe = {
      key: dedupeKey,
      level,
      source,
      ...(fields.sessionId ? { sessionId: fields.sessionId } : {}),
      component: fields.component,
      event: fields.event,
      message: cleanMessage,
      firstSuppressedAtMs: nowMs,
      count: 0,
    };

    this.seq += 1;
    const redactedData = fields.data
      ? (redactLogData(fields.data)                           )
      : undefined;

    const entry           = {
      seq: this.seq,
      timestamp: fields.timestamp ?? new Date(nowMs).toISOString(),
      level,
      source,
      component: fields.component,
      event: fields.event,
      message: cleanMessage,
      ...(fields.sessionId ? { sessionId: fields.sessionId } : {}),
      pid: fields.pid ?? process.pid,
      ...(fields.durationMs !== undefined ? { durationMs: Math.round(fields.durationMs) } : {}),
      ...(redactedData && Object.keys(redactedData).length > 0 ? { data: redactedData } : {}),
    };

    this.pushToMemory(entry);
    if (this.allowDiskPersistence(level, nowMs)) {
      this.fileSink?.append(entry);
    }
    this.onEntry?.(entry);
    return entry;
  }

  shouldLog(level          )          {
    return LOG_LEVEL_WEIGHT[level] >= LOG_LEVEL_WEIGHT[this.level];
  }

  log(level          , fields                )                       {
    return this.recordInternal(level, this.source, fields);
  }

  /**
   * Ingests a structured log entry forwarded from `wsl-runner` stderr (`[DSH_RUNNER_LOG]{...}`)
   * into the unified host ring buffer and coalesced NDJSON log file.
   */
  ingestExternal(raw                   )                       {
    const level = normalizeLogLevel(raw.level, 'info');
    const source            =
      raw.source === 'wsl-runner' || raw.source === 'bootstrap' ? raw.source : 'wsl-runner';
    return this.recordInternal(level, source, {
      timestamp: typeof raw.timestamp === 'string' && raw.timestamp ? raw.timestamp : undefined,
      component: typeof raw.component === 'string' && raw.component ? raw.component : 'runner',
      event: typeof raw.event === 'string' && raw.event ? raw.event : 'runner.log',
      message: typeof raw.message === 'string' ? raw.message : '',
      sessionId: typeof raw.sessionId === 'string' && raw.sessionId ? raw.sessionId : undefined,
      pid: typeof raw.pid === 'number' ? raw.pid : undefined,
      durationMs: typeof raw.durationMs === 'number' ? raw.durationMs : undefined,
      data: raw.data,
    });
  }

  child(component        , defaults                                  )                  {
    return {
      debug: (event, message, data, extra) => {
        this.log('debug', {
          component,
          event,
          message,
          sessionId: extra?.sessionId ?? defaults?.sessionId,
          durationMs: extra?.durationMs,
          data,
        });
      },
      info: (event, message, data, extra) => {
        this.log('info', {
          component,
          event,
          message,
          sessionId: extra?.sessionId ?? defaults?.sessionId,
          durationMs: extra?.durationMs,
          data,
        });
      },
      warn: (event, message, data, extra) => {
        this.log('warn', {
          component,
          event,
          message,
          sessionId: extra?.sessionId ?? defaults?.sessionId,
          durationMs: extra?.durationMs,
          data,
        });
      },
      error: (event, message, data, extra) => {
        this.log('error', {
          component,
          event,
          message,
          sessionId: extra?.sessionId ?? defaults?.sessionId,
          durationMs: extra?.durationMs,
          data,
        });
      },
    };
  }

  /**
   * Pure in-memory query (ZERO disk reads).
   */
  query(filter                 = {})             {
    const minWeight = filter.minLevel ? LOG_LEVEL_WEIGHT[filter.minLevel] : 0;
    const sourceFilter = filter.source && filter.source !== 'all' ? filter.source : undefined;
    const compFilter = filter.component?.trim().toLowerCase();
    const sessionFilter = filter.sessionId?.trim();
    const searchLower = filter.search?.trim().toLowerCase();
    const sinceSeq = filter.sinceSeq ?? 0;
    const limit = Math.min(1000, Math.max(1, filter.limit ?? 200));

    const matched             = [];
    for (let i = this.buffer.length - 1; i >= 0; i--) {
      const e = this.buffer[i] ;
      if (e.seq <= sinceSeq) continue;
      if (LOG_LEVEL_WEIGHT[e.level] < minWeight) continue;
      if (sourceFilter && e.source !== sourceFilter) continue;
      if (compFilter && e.component.toLowerCase() !== compFilter) continue;
      if (sessionFilter && e.sessionId !== sessionFilter) continue;
      if (searchLower) {
        const hay = `${e.component} ${e.event} ${e.message} ${e.data ? JSON.stringify(e.data) : ''}`.toLowerCase();
        if (!hay.includes(searchLower)) continue;
      }
      matched.push(e);
      if (matched.length >= limit) break;
    }
    return matched.reverse();
  }

  exportNdjson(filter                 = {})         {
    const entries = this.query({ ...filter, limit: filter.limit ?? 1000 });
    if (entries.length === 0) return '';
    return entries.map((e) => JSON.stringify(e)).join('\n') + '\n';
  }

  flushSync()       {
    if (this.lastDedupe && this.lastDedupe.count > 0) {
      this.emitSummaryForSuppressedDuplicates();
    }
    this.fileSink?.flushSync();
  }

  clear()                                                  {
    if (this.lastDedupe) {
      this.lastDedupe.count = 0;
    }
    const clearedMemory = this.buffer.length;
    this.buffer.length = 0;
    const removedFiles = this.fileSink?.clear() ?? 0;
    return { clearedMemory, removedFiles };
  }

  dispose()       {
    this.flushSync();
    this.fileSink?.dispose();
  }
}

export function formatRunnerWireLog(entry          )         {
  return `${RUNNER_LOG_WIRE_PREFIX}${JSON.stringify(entry)}\n`;
}

export function parseRunnerWireLog(line        )                           {
  const trimmed = line.trim();
  if (!trimmed.startsWith(RUNNER_LOG_WIRE_PREFIX)) return null;
  const payload = trimmed.slice(RUNNER_LOG_WIRE_PREFIX.length).trim();
  if (!payload) return null;
  try {
    const parsed = JSON.parse(payload)                     ;
    if (parsed && typeof parsed === 'object') return parsed;
    return null;
  } catch {
    return null;
  }
}
