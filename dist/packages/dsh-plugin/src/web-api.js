import { spawn, spawnSync } from 'node:child_process';
import fs from 'node:fs';
                                                                 
import os from 'node:os';
import path from 'node:path';
import {
                            
                            
                       
  failSandbox,
  isSandboxError,
} from '../../core/src/index.js';
                                                           
import {
                        
                   
  getDefaultBackupDir,
  validateBackupDirPath,
} from './config-store.js';
import {
                        
                      
                      
                       
  getOptionalService,
} from './cordis-types.js';
import { upsertAgentsMdWslSection } from './prompt-injector.js';
                                                           
import { renderWslSandboxUiHtml } from './web-ui-entry.js';

                             
                                    
                                                    
                                          
 

                      
                                                     
                           
                         
                                         
                                   
 

function compilePattern(pattern        )                                          {
  const paramNames           = [];
  const escaped = pattern
    .split('/')
    .map((seg) => {
      if (seg.startsWith(':')) {
        paramNames.push(seg.slice(1));
        return '([^/]+)';
      }
      return seg.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    })
    .join('/');
  return { regex: new RegExp(`^${escaped}$`), paramNames };
}

function sendError(res                 , err         )       {
  if (isSandboxError(err)) {
    res.status(err.code === 'POLICY_BLOCK' ? 403 : 400).json({
      ok: false,
      error: { code: err.code, message: err.message, details: err.details },
    });
    return;
  }
  res.status(500).json({
    ok: false,
    error: { code: 'INTERNAL', message: err instanceof Error ? err.message : String(err) },
  });
}

function safe(handler                )                 {
  return async (req, res) => {
    try {
      await handler(req, res);
    } catch (err) {
      sendError(res, err);
    }
  };
}

function isSameOriginOrLoopback(req                 )          {
  const origin = req.headers.origin;
  const host = req.headers.host;
  if (!origin) return true;
  if (origin === 'null') {
    // Electron file:// origin allowed ONLY when explicit custom client header is present
    return req.headers['x-dsh-wsl-client'] === '1';
  }
  try {
    const parsed = new URL(origin);
    if (host && parsed.host === host) return true;
    return parsed.hostname === '127.0.0.1' || parsed.hostname === 'localhost' || parsed.hostname === '[::1]';
  } catch {
    return false;
  }
}

async function readJsonBody(req                 , maxBytes = 256 * 1024)                   {
  const method = (req.method ?? 'GET').toUpperCase();
  if (method === 'GET' || method === 'HEAD') return undefined;
  const chunks           = [];
  let total = 0;
  for await (const chunk of req) {
    const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk));
    total += buf.length;
    if (total > maxBytes) {
      throw new Error(`Request body exceeds ${maxBytes} bytes`);
    }
    chunks.push(buf);
  }
  if (chunks.length === 0) return {};
  const raw = Buffer.concat(chunks).toString('utf8').trim();
  if (!raw) return {};
  return JSON.parse(raw);
}

function wrapNodeResponse(res                )                  {
  let code = 200;
  const headers                         = {
    'Cache-Control': 'no-store',
  };
  const wrapper                  = {
    status(c        ) {
      code = c;
      return wrapper;
    },
    header(name        , value        ) {
      headers[name] = value;
      return wrapper;
    },
    json(payload         ) {
      const body = JSON.stringify(payload);
      res.writeHead(code, {
        ...headers,
        'Content-Type': 'application/json; charset=utf-8',
        'Content-Length': String(Buffer.byteLength(body, 'utf8')),
      });
      res.end(body);
    },
    html(content        ) {
      res.writeHead(code, {
        ...headers,
        'Content-Type': 'text/html; charset=utf-8',
        'Content-Length': String(Buffer.byteLength(content, 'utf8')),
      });
      res.end(content);
    },
    text(content        ) {
      res.writeHead(code, {
        ...headers,
        'Content-Type': 'text/plain; charset=utf-8',
        'Content-Length': String(Buffer.byteLength(content, 'utf8')),
      });
      res.end(content);
    },
  };
  return wrapper;
}

/**
 * Registers strictly namespaced human-only HTTP routes under `/wsl-sandbox/api/*` and `/wsl-sandbox/ui`
 * on BOTH real `@deepseek-ai/dsh-host-webserver` (`ctx.webServer`) AND generic `ctx.http` test routers.
 */
export function registerWslSandboxWebApi(ctx                  , deps            )                 {
  const disposers                 = [];
  const table               = [];
  const httpRouter = getOptionalService(ctx, 'http');
  const webServer = getOptionalService(ctx, 'webServer');

  const add = (
    method                                   ,
    routePath        ,
    handler                ,
  )       => {
    const wrapped = safe(handler);
    const { regex, paramNames } = compilePattern(routePath);
    table.push({ method, pattern: routePath, regex, paramNames, handler: wrapped });
    if (httpRouter) {
      const dispose = httpRouter.route(method, routePath, wrapped);
      if (typeof dispose === 'function') disposers.push(() => void dispose());
    }
  };

  add('GET', '/wsl-sandbox/ui', (_req, res) => {
    res.status(200).html(renderWslSandboxUiHtml());
  });

  add('GET', '/wsl-sandbox/api/status', (_req, res) => {
    const binding = deps.sessionManager.getBindingSnapshot();
    res.status(200).json({
      ok: true,
      bound: Boolean(binding),
      generation: deps.sessionManager.getGeneration(),
      binding: binding ?? null,
      config: deps.configStore.get(),
      pendingApprovals: deps.approvalBridge.listPending().length,
      sessionRules: deps.approvalBridge.getSessionRules(),
    });
  });

  add('GET', '/wsl-sandbox/api/config', (_req, res) => {
    res.status(200).json(deps.configStore.get());
  });

  add('PUT', '/wsl-sandbox/api/config', (req, res) => {
    const body = (req.body ?? {})                                              ;
    const updated = deps.configStore.updateBasic(body);
    res.status(200).json({ ok: true, config: updated });
  });

  add('POST', '/wsl-sandbox/api/env-unmask', (req, res) => {
    const body = (req.body ?? {})                                                  ;
    const ws = String(body.workspaceRoot ?? '').trim();
    const cur = deps.configStore.get().unmaskedEnvWorkspaces;
    const next = body.unmasked ? [...new Set([...cur, ws])] : cur.filter((x) => x !== ws);
    const updated = deps.configStore.updateBasic({ unmaskedEnvWorkspaces: next });
    res.status(200).json({ ok: true, config: updated });
  });

  add('POST', '/wsl-sandbox/api/advanced/shares', (req, res) => {
    const raw = (req.body ?? {})                                                ;
    const share                  = {
      id: raw.id ?? `sh-${Date.now().toString(36)}`,
      alias: raw.alias ?? '',
      sourceLinuxPath: String(raw.sourceLinuxPath ?? raw.path ?? ''),
      mode: raw.mode === 'rw' ? 'rw' : 'ro',
      oneShot: Boolean(raw.oneShot),
    };
    const updated = deps.configStore.addShare(share);
    const added = updated.advanced.shares[updated.advanced.shares.length - 1] ?? null;
    res.status(200).json({ ok: true, share: added, config: updated });
  });

  add('DELETE', '/wsl-sandbox/api/advanced/shares/:id', async (req, res) => {
    const shareId = req.params.id ?? '';
    const updated = deps.configStore.removeShare(shareId);
    const killedCount = await deps.sessionManager.invalidateNow(`Share '${shareId}' revoked`);
    res.status(200).json({ ok: true, revokedShareId: shareId, killedCount, config: updated });
  });

                            
                          
                              
                                  
                               
                               
                                                          
   

  const SAFE_BACKUP_FILE_RE = /\.(?:orig|bak|ini|txt|absent|conf)$/i;
  const BLOCKED_EXEC_EXT_RE = /\.(?:exe|com|bat|cmd|ps1|vbs|js|jse|wsf|wsh|msi|msp|scr|pif|lnk|hta)$/i;

  function resolveEffectiveBackupDir(customInput         )         {
    const cfg = deps.configStore.get();
    const candidate = customInput !== undefined && customInput.trim() !== ''
      ? validateBackupDirPath(customInput)
      : cfg.backupDir;
    return path.resolve(candidate ?? getDefaultBackupDir());
  }

  function collectHostBackupItems(
    resolvedBackupDir        ,
    distro        ,
    wslInternalDir         ,
    wslEntries                    ,
  )                   {
    const items                   = [];
    if (fs.existsSync(resolvedBackupDir)) {
      for (const entry of fs.readdirSync(resolvedBackupDir).sort()) {
        if (BLOCKED_EXEC_EXT_RE.test(entry)) continue;
        const full = path.join(resolvedBackupDir, entry);
        try {
          const st = fs.lstatSync(full);
          if (!st.isFile()) continue;
          items.push({
            name: entry,
            fullPath: full,
            explorerPath: full,
            sizeBytes: st.size,
            updatedAt: new Date(st.mtimeMs).toISOString().replace('T', ' ').slice(0, 19),
            source: 'custom-backup-dir',
          });
        } catch {
          // ignore unreadable item
        }
      }
    }

    if (wslInternalDir && wslEntries && wslEntries.length > 0) {
      const seenNames = new Set(items.map((i) => i.name));
      for (const name of wslEntries) {
        if (seenNames.has(name) || BLOCKED_EXEC_EXT_RE.test(name)) continue;
        const linuxFull = path.posix.join(wslInternalDir, name);
        const explorerPath =
          process.platform === 'win32'
            ? `\\\\wsl.localhost\\${distro}${linuxFull.replace(/\//g, '\\')}`
            : linuxFull;
        if (process.platform !== 'win32' && path.resolve(linuxFull) === path.join(resolvedBackupDir, name)) {
          continue;
        }
        items.push({
          name: `[WSL 内置] ${name}`,
          fullPath: linuxFull,
          explorerPath,
          sizeBytes: 0,
          updatedAt: '-',
          source: 'wsl-internal',
        });
      }
    }
    return items;
  }

  add('GET', '/wsl-sandbox/api/wsl-config/backups', async (req, res) => {
    const cfg = deps.configStore.get();
    const resolvedBackupDir = resolveEffectiveBackupDir(req.query.backupDir);
    let wslInternalDir                    ;
    let wslEntries           = [];
    let automountDisabledInWslConf = false;
    try {
      const info = (await deps.sessionManager.callRpc('wsl.listBackups', {}, 8_000))     
                           
                           
                                             
       ;
      wslInternalDir = info.backupDir;
      wslEntries = info.entries ?? [];
      automountDisabledInWslConf = Boolean(info.automountDisabledInWslConf);
    } catch {
      // Runner not spawned yet; still serve host backup directory items
    }
    const items = collectHostBackupItems(resolvedBackupDir, cfg.distro, wslInternalDir, wslEntries);
    res.status(200).json({
      ok: true,
      backupDir: resolvedBackupDir,
      items,
      entries: items.map((i) => i.name),
      sandboxTmpfsMntLocked: true,
      automountDisabledInWslConf,
    });
  });

  add('POST', '/wsl-sandbox/api/wsl-config/backup', async (req, res) => {
    const body = (req.body ?? {})                          ;
    const resolvedBackupDir = resolveEffectiveBackupDir(body.backupDir);
    if (body.backupDir && body.backupDir.trim() !== '' && body.backupDir.trim() !== deps.configStore.get().backupDir) {
      deps.configStore.updateBasic({ backupDir: resolvedBackupDir });
    }
    const cfg = deps.configStore.get();
    fs.mkdirSync(resolvedBackupDir, { recursive: true, mode: 0o700 });

    const savedFiles           = [];
    const ts = new Date().toISOString().replace(/[:.]/g, '-');
    const wslCfg = path.join(os.homedir(), '.wslconfig');
    const origHostCfg = path.join(resolvedBackupDir, '.wslconfig.orig');
    const absentHostMarker = path.join(resolvedBackupDir, '.wslconfig.orig.absent');

    if (fs.existsSync(wslCfg)) {
      if (!fs.existsSync(origHostCfg) && !fs.existsSync(absentHostMarker)) {
        fs.copyFileSync(wslCfg, origHostCfg);
        savedFiles.push(origHostCfg);
      }
      const snap = path.join(resolvedBackupDir, `.wslconfig.${ts}.bak`);
      fs.copyFileSync(wslCfg, snap);
      savedFiles.push(snap);
    } else if (!fs.existsSync(origHostCfg) && !fs.existsSync(absentHostMarker)) {
      fs.writeFileSync(absentHostMarker, `# Host had no %USERPROFILE%\\.wslconfig at initial backup (${ts})\n`, {
        mode: 0o600,
      });
      savedFiles.push(absentHostMarker);
    }

    let wslInternalDir                    ;
    try {
      const wslResult = (await deps.sessionManager.callRpc('wsl.backupConfigs', {}, 12_000))     
                                      
                                       
                                     
                                           
       ;
      wslInternalDir = wslResult.wslInternalBackupDir;
      if (typeof wslResult.wslConfContent === 'string') {
        const distroOrig = path.join(resolvedBackupDir, `wsl.conf.${cfg.distro}.orig`);
        if (!fs.existsSync(distroOrig)) {
          fs.writeFileSync(distroOrig, wslResult.wslConfContent, { mode: 0o600 });
          savedFiles.push(distroOrig);
        }
        const distroSnap = path.join(resolvedBackupDir, `wsl.conf.${cfg.distro}.${ts}.bak`);
        fs.writeFileSync(distroSnap, wslResult.wslConfContent, { mode: 0o600 });
        savedFiles.push(distroSnap);
      } else {
        const distroAbsent = path.join(resolvedBackupDir, `wsl.conf.${cfg.distro}.orig.absent`);
        if (!fs.existsSync(distroAbsent)) {
          fs.writeFileSync(distroAbsent, `# ${cfg.distro} had no /etc/wsl.conf at initial backup (${ts})\n`, {
            mode: 0o600,
          });
          savedFiles.push(distroAbsent);
        }
      }
      if (typeof wslResult.fstabContent === 'string') {
        const fstabOrig = path.join(resolvedBackupDir, `fstab.${cfg.distro}.orig`);
        if (!fs.existsSync(fstabOrig)) {
          fs.writeFileSync(fstabOrig, wslResult.fstabContent, { mode: 0o600 });
          savedFiles.push(fstabOrig);
        }
      }
      if (typeof wslResult.drvfsMountsContent === 'string') {
        const mountsSnap = path.join(resolvedBackupDir, `drvfs-mounts.${cfg.distro}.${ts}.txt`);
        fs.writeFileSync(mountsSnap, wslResult.drvfsMountsContent + '\n', { mode: 0o600 });
        savedFiles.push(mountsSnap);
      }
    } catch {
      // Runner offline; host backup still succeeded
    }

    const items = collectHostBackupItems(resolvedBackupDir, cfg.distro, wslInternalDir, []);
    res.status(200).json({
      ok: true,
      backupDir: resolvedBackupDir,
      hostBackupDir: resolvedBackupDir,
      savedFiles,
      items,
      sandboxTmpfsMntLocked: true,
    });
  });

  add('POST', '/wsl-sandbox/api/wsl-config/open-explorer', (req, res) => {
    const body = (req.body ?? {})                                                                     ;
    const resolvedBackupDir = resolveEffectiveBackupDir(body.backupDir);
    const cfg = deps.configStore.get();
    const rawTarget = String(body.targetPath ?? resolvedBackupDir).trim();
    if (!rawTarget || rawTarget.includes('\0')) {
      failSandbox('POLICY_BLOCK', 'Invalid explorer target path');
    }
    if (BLOCKED_EXEC_EXT_RE.test(rawTarget)) {
      failSandbox('POLICY_BLOCK', `Refusing to pass executable file extension to Explorer: ${rawTarget}`);
    }

    const wslUncPrefix = `\\\\wsl.localhost\\${cfg.distro}\\`;
    const isWslInternalBackup =
      rawTarget.toLowerCase().startsWith(wslUncPrefix.toLowerCase()) &&
      rawTarget.replace(/\\/g, '/').includes('/.config/dsh-wsl-sandbox/backups/');

    let finalTarget        ;
    let isFileTarget = Boolean(body.selectFile);

    if (isWslInternalBackup) {
      const baseName = rawTarget.split(/[\\/]/).pop() ?? '';
      if (baseName && !SAFE_BACKUP_FILE_RE.test(baseName)) {
        failSandbox('POLICY_BLOCK', `Refusing to highlight non-backup file in WSL UNC path: ${baseName}`);
      }
      finalTarget = rawTarget;
      isFileTarget = Boolean(body.selectFile);
    } else {
      const resolvedTarget = path.resolve(rawTarget);
      const normDir = resolvedBackupDir.endsWith(path.sep) ? resolvedBackupDir : resolvedBackupDir + path.sep;
      const isDirItself = resolvedTarget === resolvedBackupDir;
      const isChildOfBackupDir = resolvedTarget.startsWith(normDir);
      if (!isDirItself && !isChildOfBackupDir) {
        failSandbox(
          'POLICY_BLOCK',
          `Explorer open is strictly confined to the configured backup directory (${resolvedBackupDir}); rejected: ${resolvedTarget}`,
        );
      }
      if (isDirItself) {
        fs.mkdirSync(resolvedBackupDir, { recursive: true, mode: 0o700 });
        isFileTarget = false;
      } else {
        if (!SAFE_BACKUP_FILE_RE.test(path.basename(resolvedTarget)) || !fs.existsSync(resolvedTarget)) {
          failSandbox('POLICY_BLOCK', `Backup item does not exist or has disallowed extension: ${resolvedTarget}`);
        }
        const st = fs.lstatSync(resolvedTarget);
        if (st.isSymbolicLink() || !st.isFile()) {
          failSandbox('POLICY_BLOCK', `Refusing to highlight symlink or non-regular file: ${resolvedTarget}`);
        }
        isFileTarget = body.selectFile !== false;
      }
      finalTarget = resolvedTarget;
    }

    const explorerArgs = isFileTarget ? [`/select,${finalTarget}`] : [finalTarget];
    let launched = false;
    if (process.platform === 'win32') {
      const child = spawn('explorer.exe', explorerArgs, {
        shell: false,
        detached: true,
        stdio: 'ignore',
      });
      child.unref();
      launched = true;
    } else if (process.platform === 'darwin') {
      const child = spawn('open', isFileTarget ? ['-R', finalTarget] : [finalTarget], {
        shell: false,
        detached: true,
        stdio: 'ignore',
      });
      child.unref();
      launched = true;
    } else if (process.env.WSL_DISTRO_NAME) {
      // Running inside WSL Linux dev mode: convert path via wslpath -w and launch Windows explorer.exe
      const wp = spawnSync('wslpath', ['-w', finalTarget], { encoding: 'utf8' });
      const winPath = wp.status === 0 ? wp.stdout.trim() : finalTarget;
      const child = spawn('explorer.exe', isFileTarget ? [`/select,${winPath}`] : [winPath], {
        shell: false,
        detached: true,
        stdio: 'ignore',
      });
      child.on('error', () => {});
      child.unref();
      launched = true;
    }

    res.status(200).json({
      ok: true,
      launched,
      platform: process.platform,
      targetPath: finalTarget,
      explorerArgs,
    });
  });

  add('POST', '/wsl-sandbox/api/wsl-config/pick-dir', (_req, res) => {
    if (process.platform !== 'win32') {
      res.status(200).json({
        ok: true,
        supported: false,
        selectedDir: null,
        message: '非 Windows 宿主环境请直接在备份路径输入框中粘贴或填写任意目录路径。',
      });
      return;
    }
    const psScript = [
      'Add-Type -AssemblyName System.Windows.Forms;',
      '$dlg = New-Object System.Windows.Forms.FolderBrowserDialog;',
      '$dlg.Description = "选择原始 WSL 配置文件备份保存目录";',
      '$dlg.ShowNewFolderButton = $true;',
      'if ($dlg.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8; Write-Output $dlg.SelectedPath }',
    ].join(' ');
    const proc = spawnSync('powershell.exe', ['-NoProfile', '-Sta', '-Command', psScript], {
      encoding: 'utf8',
      timeout: 120_000,
      windowsHide: false,
    });
    const chosen = (proc.stdout ?? '').trim();
    if (chosen) {
      const updated = deps.configStore.updateBasic({ backupDir: chosen });
      res.status(200).json({ ok: true, supported: true, selectedDir: updated.backupDir, config: updated });
      return;
    }
    res.status(200).json({ ok: true, supported: true, selectedDir: null });
  });

  add('PUT', '/wsl-sandbox/api/advanced/devices', async (req, res) => {
    const body = (req.body ?? {})                                            ;
    const updated = deps.configStore.setDeviceNodes(body.deviceNodes ?? []);
    const killedCount = await deps.sessionManager.invalidateNow('Device whitelist updated');
    res.status(200).json({ ok: true, killedCount, config: updated });
  });

  add('PUT', '/wsl-sandbox/api/advanced/network', (req, res) => {
    const body = (req.body ?? {})     
                               
                               
                                      
     ;
    const updated = deps.configStore.updateAdvancedNetwork(body);
    res.status(200).json({ ok: true, config: updated });
  });

  add('GET', '/wsl-sandbox/api/approvals', (_req, res) => {
    res.status(200).json({
      ok: true,
      pending: deps.approvalBridge.listPending(),
      sessionRules: deps.approvalBridge.getSessionRules(),
    });
  });

  add('POST', '/wsl-sandbox/api/approvals/:id/decide', (req, res) => {
    const requestId = req.params.id ?? '';
    const body = (req.body ?? {})     
                                      
                        
                               
     ;
    if (!body.decision) {
      res.status(400).json({ ok: false, error: { code: 'INVALID_ACTION', message: 'Missing decision field' } });
      return;
    }
    const found = deps.approvalBridge.decidePending(requestId, body.decision, {
      guidance: body.guidance,
      sessionPrefix: body.sessionPrefix,
    });
    if (!found) {
      res.status(404).json({ ok: false, error: { code: 'NOT_FOUND', message: `Approval '${requestId}' not pending` } });
      return;
    }
    res.status(200).json({ ok: true, requestId, decision: body.decision });
  });

  add('GET', '/wsl-sandbox/api/session-rules', (_req, res) => {
    res.status(200).json({ ok: true, rules: deps.approvalBridge.getSessionRules() });
  });

  add('DELETE', '/wsl-sandbox/api/session-rules', (_req, res) => {
    deps.approvalBridge.clearSessionRules();
    res.status(200).json({ ok: true, rules: [] });
  });

  add('POST', '/wsl-sandbox/api/session/invalidate', async (_req, res) => {
    const killedCount = await deps.sessionManager.invalidateNow('Emergency manual invalidation');
    res.status(200).json({ ok: true, killedCount });
  });

  add('POST', '/wsl-sandbox/api/cache/clear', async (_req, res) => {
    const result = await deps.sessionManager.callRpc('cache.clear', {}, 15_000);
    res.status(200).json({ ok: true, ...(typeof result === 'object' && result ? result : {}) });
  });

  add('GET', '/wsl-sandbox/api/doctor', async (_req, res) => {
    const cfg = deps.configStore.get();
    try {
      const report = await deps.sessionManager.callRpc(
        'env.doctor',
        { upstreamProxy: cfg.upstreamProxy },
        25_000,
      );
      res.status(200).json({ ok: true, report });
    } catch {
      const { runDoctor } = await import('../../bootstrap/src/doctor.js');
      const report = await runDoctor({ upstreamProxy: cfg.upstreamProxy || undefined });
      res.status(200).json({ ok: true, report });
    }
  });

  add('GET', '/wsl-sandbox/api/audit', (_req, res) => {
    res.status(200).json({
      ok: true,
      records: deps.approvalBridge.getAuditLog(),
    });
  });

  add('POST', '/wsl-sandbox/api/agents-md', (req, res) => {
    const body = (req.body ?? {})                            ;
    const cfg = deps.configStore.get();
    const targetDir = body.projectRoot?.trim() || cfg.workspaceRoot;
    const result = upsertAgentsMdWslSection(targetDir, {
      distro: cfg.distro,
      workspaceRoot: cfg.workspaceRoot,
    });
    res.status(200).json({ ok: true, ...result });
  });

  // Real `@deepseek-ai/dsh-host-webserver` (`ctx.webServer`) carrier
  if (webServer && typeof webServer.register === 'function') {
    const dispatchRaw = async (req                 , res                )                => {
      const method = (req.method ?? 'GET').toUpperCase();
      const urlObj = new URL(req.url ?? '/', 'http://127.0.0.1');
      const pathname = urlObj.pathname.replace(/\/+$/, '') || '/';

      if (method !== 'GET' && method !== 'HEAD') {
        if (!isSameOriginOrLoopback(req)) {
          wrapNodeResponse(res).status(403).json({
            ok: false,
            error: { code: 'FORBIDDEN_ORIGIN', message: 'Cross-origin mutation rejected' },
          });
          return;
        }
      }

      const matched = table.find((r) => r.method === method && r.regex.test(pathname));
      if (!matched) {
        wrapNodeResponse(res).status(404).json({
          ok: false,
          error: { code: 'NOT_FOUND', message: `No route for ${method} ${pathname}` },
        });
        return;
      }

      const m = matched.regex.exec(pathname) ;
      const params                         = {};
      matched.paramNames.forEach((name, idx) => {
        params[name] = decodeURIComponent(m[idx + 1] ?? '');
      });

      const query                         = {};
      for (const [k, v] of urlObj.searchParams.entries()) {
        query[k] = v;
      }

      const headers                                     = {};
      for (const [k, v] of Object.entries(req.headers)) {
        headers[k.toLowerCase()] = Array.isArray(v) ? v.join(', ') : v;
      }

      let body         ;
      try {
        body = await readJsonBody(req);
      } catch (err) {
        wrapNodeResponse(res).status(400).json({
          ok: false,
          error: { code: 'INVALID_JSON', message: err instanceof Error ? err.message : String(err) },
        });
        return;
      }

      const dshReq                 = {
        method,
        path: pathname,
        params,
        query,
        body,
        headers,
      };
      await matched.handler(dshReq, wrapNodeResponse(res));
    };

    const disposeUi = webServer.register({
      kind: 'exact',
      path: '/wsl-sandbox/ui',
      handler: dispatchRaw,
    });
    const disposeApi = webServer.register({
      kind: 'prefix',
      path: '/wsl-sandbox/api',
      handler: dispatchRaw,
    });
    disposers.push(disposeUi, disposeApi);
  }

  return disposers;
}
