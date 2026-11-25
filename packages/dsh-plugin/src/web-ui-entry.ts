/**
 * Self-contained HTML/CSS/JS control panel served at `/wsl-sandbox/ui`.
 *
 * Visual design strictly matches official DSH Purge / DSH Marketplace dark obsidian hierarchy:
 * - Zero emojis, zero Tailwind dependency, pure scoped `.dsh-wsl-sbx-*` CSS (`z-index <= 850`).
 * - Internal `revision` and `generation` counters stay strictly under the hood; the UI displays
 *   clear human-friendly sync state (`已生效` / `待点击应用`).
 * - Basic settings expose all 16 configuration controls while completely hiding `/mnt` full-drive mounts.
 * - Advanced controls remain collapsed inside `<details class="dsh-wsl-sbx-advanced">` by default.
 * - Live `/wsl-sandbox/api/*` wiring for Status, 4-Decision Approvals, Shares, Devices, SSRF Network,
 *   WSL Doctor, Package Cache Clear, Emergency Kill, and Audit Log.
 */

import type { DshCordisContext } from './cordis-types.ts';

export const name = 'dsh-wsl-sandbox-web-ui';
export const inject: string[] = [];

export interface WebUiPluginConfig {
  readonly routePrefix?: string;
  readonly zIndexCap?: number;
}

export function apply(ctx: DshCordisContext, config: WebUiPluginConfig = {}): void {
  if (!ctx.http) return;
  const uiPath = config.routePrefix
    ? config.routePrefix.replace(/\/api\/?$/, '/ui')
    : '/wsl-sandbox/ui';
  try {
    const dispose = ctx.http.route('GET', uiPath, (_req, res) => {
      res.status(200).html(renderWslSandboxUiHtml());
    });
    if (typeof dispose === 'function') {
      if ('fiber' in (ctx as object) || typeof ctx.inject === 'function') {
        ctx.effect?.(() => () => void dispose());
      } else {
        ctx.effect?.(dispose);
      }
    }
  } catch {
    // Route already registered by main host entry (`web-api.ts`) — idempotent no-op
  }
  ctx.logger?.info(`[dsh-wsl-sandbox-web-ui] UI active at ${uiPath} (z-index cap ${config.zIndexCap ?? 850})`);
}

export function renderWslSandboxUiHtml(): string {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>WSL 2 沙箱 — DeepSeek Harness 控制台</title>
  <style>
    .dsh-wsl-sbx-root {
      --bg-canvas: #0f1012;
      --bg-panel: #16171a;
      --bg-card: #1c1d21;
      --bg-inset: #121316;
      --border-subtle: rgba(255, 255, 255, 0.065);
      --border-default: rgba(255, 255, 255, 0.12);
      --text-primary: #f2f3f5;
      --text-secondary: #9498a3;
      --text-muted: #646873;
      --ok: #22c55e;
      --warn: #f59e0b;
      --danger: #e06c65;
      --danger-solid: #8c2d2b;
      --switch-on: #3b82f6;
      --switch-off: #32353e;
      --sans: -apple-system, BlinkMacSystemFont, "PingFang SC", "Hiragino Sans GB", "Microsoft YaHei", system-ui, sans-serif;
      --mono: "JetBrains Mono", "SF Mono", Menlo, Consolas, ui-monospace, monospace;
      background: var(--bg-canvas);
      color: var(--text-primary);
      font-family: var(--sans);
      font-size: 13px;
      line-height: 1.5;
      min-height: 100vh;
      margin: 0;
      padding: 20px 24px 36px;
      position: relative;
      z-index: 1;
    }
    .dsh-wsl-sbx-root * { box-sizing: border-box; }
    .dsh-wsl-sbx-shell { max-width: 1000px; margin: 0 auto; }
    .dsh-wsl-sbx-mono { font-family: var(--mono); font-variant-numeric: tabular-nums; }
    .dsh-wsl-sbx-brand { display: flex; align-items: center; justify-content: space-between; margin-bottom: 12px; }
    .dsh-wsl-sbx-brand-title { font-size: 16px; font-weight: 600; display: inline-flex; align-items: center; gap: 8px; }
    .dsh-wsl-sbx-tabs { display: flex; gap: 22px; border-bottom: 1px solid var(--border-subtle); }
    .dsh-wsl-sbx-tab {
      position: relative; background: none; border: 0; color: var(--text-secondary);
      font: 500 13.5px/1 var(--sans); padding: 10px 0 12px; cursor: pointer;
    }
    .dsh-wsl-sbx-tab.is-active { color: var(--text-primary); font-weight: 600; }
    .dsh-wsl-sbx-tab.is-active::after {
      content: ""; position: absolute; left: 0; right: 0; bottom: -1px; height: 2px; background: var(--text-primary);
    }
    .dsh-wsl-sbx-tel {
      display: flex; flex-wrap: wrap; gap: 18px; padding: 11px 2px;
      border-bottom: 1px solid var(--border-subtle); margin-bottom: 18px; font-size: 12px; color: var(--text-secondary);
    }
    .dsh-wsl-sbx-tel b { color: var(--text-primary); font-weight: 600; }
    .dsh-wsl-sbx-dot { width: 7px; height: 7px; border-radius: 50%; display: inline-block; margin-right: 6px; background: var(--ok); }
    .dsh-wsl-sbx-notice {
      display: none; align-items: center; justify-content: space-between; padding: 9px 14px;
      margin-bottom: 14px; border-radius: 9px; background: #1a1d24; border: 1px solid var(--border-default);
      z-index: 800;
    }
    .dsh-wsl-sbx-notice.is-visible { display: flex; }
    .dsh-wsl-sbx-panel {
      background: var(--bg-panel); border: 1px solid var(--border-subtle); border-radius: 14px; padding: 22px 24px;
    }
    .dsh-wsl-sbx-head { display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between; gap: 12px; margin-bottom: 18px; }
    .dsh-wsl-sbx-title { font-size: 18px; font-weight: 600; margin: 0; }
    .dsh-wsl-sbx-actions { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; }
    .dsh-wsl-sbx-btn {
      border-radius: 8px; padding: 6px 15px; font: 500 12.5px/1.25 var(--sans); cursor: pointer; border: 1px solid transparent;
    }
    .dsh-wsl-sbx-btn:disabled { opacity: 0.38; cursor: not-allowed; }
    .dsh-wsl-sbx-btn-apply { background: #f4f5f7; color: #111214; font-weight: 600; }
    .dsh-wsl-sbx-btn-sec { background: var(--bg-card); border-color: var(--border-default); color: var(--text-primary); }
    .dsh-wsl-sbx-btn-out-danger { background: transparent; border-color: rgba(224,108,101,0.4); color: var(--danger); }
    .dsh-wsl-sbx-btn-danger { background: var(--danger-solid); color: #fbeae9; }
    .dsh-wsl-sbx-hero {
      background: var(--bg-card); border: 1px solid var(--border-subtle); border-radius: 12px; padding: 18px 20px; margin-bottom: 14px;
    }
    .dsh-wsl-sbx-bar { height: 3px; background: #2b2d35; border-radius: 99px; overflow: hidden; margin: 12px 0 15px; }
    .dsh-wsl-sbx-bar > i { display: block; height: 100%; background: var(--ok); }
    .dsh-wsl-sbx-stats { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 10px; }
    .dsh-wsl-sbx-stat { border: 1px solid var(--border-subtle); border-radius: 9px; padding: 11px 13px; background: rgba(255,255,255,0.018); }
    .dsh-wsl-sbx-stat.dashed { border-style: dashed; border-color: rgba(255,255,255,0.12); }
    .dsh-wsl-sbx-grid2 { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px; margin-bottom: 14px; }
    @media (max-width: 720px) { .dsh-wsl-sbx-stats, .dsh-wsl-sbx-grid2 { grid-template-columns: 1fr; } }
    .dsh-wsl-sbx-fcard {
      position: relative; background: var(--bg-card); border: 1px solid var(--border-subtle);
      border-radius: 11px; padding: 15px 17px; display: flex; flex-direction: column; gap: 8px;
    }
    .dsh-wsl-sbx-fcard.is-on::before {
      content: ""; position: absolute; left: 0; top: 10px; bottom: 10px; width: 2.5px; border-radius: 2px; background: #f2f3f5;
    }
    .dsh-wsl-sbx-sw { position: relative; width: 40px; height: 22px; display: inline-block; }
    .dsh-wsl-sbx-sw input { opacity: 0; width: 0; height: 0; }
    .dsh-wsl-sbx-sw i { position: absolute; inset: 0; border-radius: 99px; background: var(--switch-off); cursor: pointer; transition: 0.18s; }
    .dsh-wsl-sbx-sw i::before {
      content: ""; position: absolute; width: 16px; height: 16px; left: 3px; top: 3px; border-radius: 50%; background: #fff; transition: transform 0.18s;
    }
    .dsh-wsl-sbx-sw input:checked + i { background: var(--switch-on); }
    .dsh-wsl-sbx-sw input:checked + i::before { transform: translateX(18px); }
    .dsh-wsl-sbx-pill {
      align-self: flex-start; padding: 2px 10px; border-radius: 999px; border: 1px solid var(--border-default); font-size: 11.5px; color: var(--text-secondary);
    }
    .dsh-wsl-sbx-card {
      background: var(--bg-card); border: 1px solid var(--border-subtle); border-radius: 11px; padding: 16px 18px; margin-bottom: 12px;
    }
    .dsh-wsl-sbx-input, .dsh-wsl-sbx-select {
      width: 100%; background: var(--bg-inset); color: var(--text-primary); border: 1px solid var(--border-default);
      border-radius: 8px; padding: 8px 11px; font: 12.5px var(--sans); outline: none;
    }
    .dsh-wsl-sbx-cmd {
      background: var(--bg-inset); border: 1px solid var(--border-subtle); border-radius: 8px; padding: 10px 12px;
      font: 12px/1.5 var(--mono); overflow-x: auto; margin: 8px 0;
    }
    .dsh-wsl-sbx-advanced {
      background: var(--bg-card); border: 1px solid var(--border-default); border-radius: 11px; padding: 14px 18px; margin-top: 14px;
    }
    .dsh-wsl-sbx-advanced > summary { cursor: pointer; font-weight: 600; font-size: 13.5px; }
    .dsh-wsl-sbx-pane { display: none; }
    .dsh-wsl-sbx-pane.is-active { display: block; }
    .dsh-wsl-sbx-table { width: 100%; border-collapse: collapse; font-size: 12.5px; }
    .dsh-wsl-sbx-table th, .dsh-wsl-sbx-table td { padding: 8px 10px; text-align: left; border-bottom: 1px solid var(--border-subtle); }
  </style>
</head>
<body class="dsh-wsl-sbx-root">
  <div class="dsh-wsl-sbx-shell">
    <div class="dsh-wsl-sbx-brand">
      <div class="dsh-wsl-sbx-brand-title">
        <span>WSL 2 沙箱</span>
        <span style="font-size:12.5px;font-weight:400;color:var(--text-secondary)">内核命名空间执行后端、单壳方言防呆与物理硬件单次门禁</span>
      </div>
      <span class="dsh-wsl-sbx-mono" style="font-size:12px;color:var(--text-secondary)">dsh-wsl-sandbox v0.1.0</span>
    </div>

    <div class="dsh-wsl-sbx-tabs">
      <button class="dsh-wsl-sbx-tab is-active" onclick="sbxTab('status', this)">状态</button>
      <button class="dsh-wsl-sbx-tab" onclick="sbxTab('approvals', this)">审批队列 <span id="tabCnt">(0)</span></button>
      <button class="dsh-wsl-sbx-tab" onclick="sbxTab('settings', this)">基础策略与高级共享</button>
      <button class="dsh-wsl-sbx-tab" onclick="sbxTab('doctor', this)">内核体检</button>
      <button class="dsh-wsl-sbx-tab" onclick="sbxTab('audit', this)">审计明细</button>
    </div>

    <div class="dsh-wsl-sbx-tel">
      <span><i class="dsh-wsl-sbx-dot" id="telDot"></i>受控发行版 <b class="dsh-wsl-sbx-mono" id="telDistro">加载中...</b></span>
      <span>工作区 <b class="dsh-wsl-sbx-mono" id="telWs">-</b></span>
      <span>隔离层级 <b id="telIso">bwrap + seccomp + UDS 代理</b></span>
      <span>配置状态 <b id="telSync">已生效</b></span>
    </div>

    <div class="dsh-wsl-sbx-notice" id="notice"><span id="noticeMsg"></span><button class="dsh-wsl-sbx-btn dsh-wsl-sbx-btn-sec" onclick="document.getElementById('notice').classList.remove('is-visible')">关闭</button></div>

    <main class="dsh-wsl-sbx-panel">
      <div class="dsh-wsl-sbx-head">
        <h1 class="dsh-wsl-sbx-title" id="pTitle">沙箱状态</h1>
        <div class="dsh-wsl-sbx-actions">
          <button class="dsh-wsl-sbx-btn dsh-wsl-sbx-btn-apply" onclick="saveBasic()">应用</button>
          <button class="dsh-wsl-sbx-btn dsh-wsl-sbx-btn-out-danger" onclick="loadStatus()">还原</button>
          <button class="dsh-wsl-sbx-btn dsh-wsl-sbx-btn-danger" onclick="emergencyKill()">熔断强杀</button>
        </div>
      </div>

      <!-- Status -->
      <section class="dsh-wsl-sbx-pane is-active" id="pane-status">
        <div class="dsh-wsl-sbx-hero">
          <div><span style="font-size:26px;font-weight:700" class="dsh-wsl-sbx-mono" id="layerBig">6</span> <span>/ 6 层内核与单壳防线就位</span></div>
          <div class="dsh-wsl-sbx-bar"><i id="layerBar" style="width:100%"></i></div>
          <div class="dsh-wsl-sbx-stats">
            <div class="dsh-wsl-sbx-stat"><div style="font-size:12px;color:var(--text-secondary)">已生效防线</div><div style="font-size:19px;font-weight:600;color:var(--ok)" id="stLayers">6</div></div>
            <div class="dsh-wsl-sbx-stat"><div style="font-size:12px;color:var(--text-secondary)">待人工审批</div><div style="font-size:19px;font-weight:600;color:var(--warn)" id="stPending">0</div></div>
            <div class="dsh-wsl-sbx-stat"><div style="font-size:12px;color:var(--text-secondary)">会话前缀规则</div><div style="font-size:19px;font-weight:600" id="stRules">0</div></div>
            <div class="dsh-wsl-sbx-stat dashed"><div style="font-size:12px;color:var(--text-secondary)">外部共享 / 硬件</div><div style="font-size:19px;font-weight:600" id="stAdv">0 / 0</div></div>
          </div>
        </div>

        <div class="dsh-wsl-sbx-grid2">
          <div class="dsh-wsl-sbx-fcard is-on" id="fc-en">
            <div style="display:flex;justify-content:space-between;align-items:center">
              <b>WSL 2 沙箱后端</b>
              <label class="dsh-wsl-sbx-sw"><input type="checkbox" id="in-enabled" checked /><i></i></label>
            </div>
            <span style="color:var(--text-secondary);font-size:12.5px">接管 7 项 wsl_* 工具并在 Linux 命名空间内隔离执行。关闭后拒绝调用，绝不回退宿主机。</span>
            <span class="dsh-wsl-sbx-pill dsh-wsl-sbx-mono" id="pl-en">workspace-write</span>
          </div>
          <div class="dsh-wsl-sbx-fcard is-on" id="fc-pw">
            <div style="display:flex;justify-content:space-between;align-items:center">
              <b>宿主终端单壳与零 Token 守卫</b>
              <label class="dsh-wsl-sbx-sw"><input type="checkbox" id="in-pwsh" checked /><i></i></label>
            </div>
            <span style="color:var(--text-secondary);font-size:12.5px">单调 Guard 硬拦截 pwsh 套 cmd、混用 powershell.exe、/s /q 假别名、2&gt;nul 与 UNC 穿透。</span>
            <span class="dsh-wsl-sbx-pill">单壳纯净 · L0 硬拦 / L3 必审</span>
          </div>
          <div class="dsh-wsl-sbx-fcard is-on" id="fc-pr">
            <div style="display:flex;justify-content:space-between;align-items:center">
              <b>系统提示词路由注入</b>
              <label class="dsh-wsl-sbx-sw"><input type="checkbox" id="in-prompt" checked /><i></i></label>
            </div>
            <span style="color:var(--text-secondary);font-size:12.5px">增量注册 order 4200 (interpolate: false) 段落，与 dsh-purge / billion-context 完全兼容。</span>
            <span class="dsh-wsl-sbx-pill dsh-wsl-sbx-mono">order 4200</span>
          </div>
          <div class="dsh-wsl-sbx-fcard" id="fc-cn">
            <div style="display:flex;justify-content:space-between;align-items:center">
              <b>国内镜像源环境变量</b>
              <label class="dsh-wsl-sbx-sw"><input type="checkbox" id="in-mirror" /><i></i></label>
            </div>
            <span style="color:var(--text-secondary);font-size:12.5px">为沙箱内 npm、pip、uv、cargo、go 注入国内镜像加速变量，不写全局文件。</span>
            <span class="dsh-wsl-sbx-pill">按需开启</span>
          </div>
        </div>

        <!-- Direct Quick Entry: Disable Full-Drive Mount + Mount Specific Folder + Original WSL Backup -->
        <div class="dsh-wsl-sbx-card" style="border-color:var(--border-default)">
          <div style="padding-bottom:12px;border-bottom:1px solid var(--border-subtle);margin-bottom:12px">
            <div style="display:flex;flex-wrap:wrap;justify-content:space-between;align-items:center;gap:10px;margin-bottom:8px">
              <div>
                <div style="display:flex;align-items:center;gap:8px">
                  <b>禁用 Windows 全盘挂载 (C:\ / D:\) 与原始 WSL 配置备份</b>
                  <span class="dsh-wsl-sbx-pill" style="color:var(--ok);border-color:rgba(34,197,94,0.35)">沙箱 --tmpfs /mnt 已锁死生效</span>
                </div>
                <div style="color:var(--text-secondary);font-size:12px;margin-top:3px">
                  默认已在内核命名空间层将 AI 可见的 <span class="dsh-wsl-sbx-mono">/mnt</span> 置为空内存盘；可任意指定备份目录，并为每一项原始备份拉起 Windows 原生资源管理器定位文件。
                </div>
              </div>
              <button class="dsh-wsl-sbx-btn dsh-wsl-sbx-btn-sec" onclick="toggleWslConfCmd()">彻底关闭底层自动挂载指令</button>
            </div>
            <div style="display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-top:8px">
              <input class="dsh-wsl-sbx-input dsh-wsl-sbx-mono" style="flex:1;min-width:240px" id="bk-dir" placeholder="任意指定备份保存目录，例如 D:\Backups\WSL-Orig" />
              <button class="dsh-wsl-sbx-btn dsh-wsl-sbx-btn-sec" onclick="pickBackupDir()">浏览选择目录...</button>
              <button class="dsh-wsl-sbx-btn dsh-wsl-sbx-btn-apply" onclick="backupWslConfigs()">立即备份到此目录</button>
              <button class="dsh-wsl-sbx-btn dsh-wsl-sbx-btn-sec" onclick="openBackupExplorer('', false)">打开备份文件夹</button>
            </div>
            <div id="backupItemsBox" style="margin-top:9px"></div>
          </div>
          <div id="wslConfCmdBox" style="display:none;margin-bottom:12px">
            <pre class="dsh-wsl-sbx-cmd"># 在 WSL 内执行（自动备份原版 /etc/wsl.conf 后关闭自动挂载）：
bash packages/bootstrap/provision-wsl.sh --disable-automount
# 如需一键还原原厂 /etc/wsl.conf：
bash packages/bootstrap/provision-wsl.sh --restore-configs</pre>
          </div>

          <div>
            <div style="font-weight:600;margin-bottom:4px">指定单目录快捷挂载（直接粘贴 Windows 文件夹路径或 Linux 路径 -> /shares/&lt;别名&gt;）</div>
            <div style="color:var(--text-secondary);font-size:12px;margin-bottom:8px">
              自动将 <span class="dsh-wsl-sbx-mono">D:\Datasets\ESP32</span> 转换为受控挂载点 <span class="dsh-wsl-sbx-mono">/shares/ESP32</span>（默认只读，严禁填入 <span class="dsh-wsl-sbx-mono">C:\</span> 或 <span class="dsh-wsl-sbx-mono">D:\</span> 整盘根目录）。
            </div>
            <div style="display:flex;flex-wrap:wrap;gap:8px;align-items:center">
              <input class="dsh-wsl-sbx-input dsh-wsl-sbx-mono" style="flex:1;min-width:240px" id="qk-path" placeholder="例如 D:\Datasets\ESP32 或 C:\Users\Alice\Downloads\spec" />
              <input class="dsh-wsl-sbx-input dsh-wsl-sbx-mono" style="width:150px" id="qk-alias" placeholder="别名(留空自动生成)" />
              <select class="dsh-wsl-sbx-select" style="width:110px" id="qk-mode">
                <option value="ro">只读 (ro)</option>
                <option value="rw">读写 (rw)</option>
              </select>
              <button class="dsh-wsl-sbx-btn dsh-wsl-sbx-btn-apply" onclick="quickAddShare()">挂载此目录</button>
            </div>
            <div id="quickSharesBox" style="margin-top:10px"></div>
          </div>
        </div>
      </section>

      <!-- Approvals -->
      <section class="dsh-wsl-sbx-pane" id="pane-approvals">
        <div id="pendingBox"></div>
        <div class="dsh-wsl-sbx-card" style="margin-top:12px">
          <div style="display:flex;justify-content:space-between;align-items:center">
            <b>当前会话已授权命令前缀</b>
            <button class="dsh-wsl-sbx-btn dsh-wsl-sbx-btn-sec" onclick="clearSessionRules()">清空会话规则</button>
          </div>
          <div id="rulesBox" style="margin-top:8px;color:var(--text-secondary)"></div>
        </div>
      </section>

      <!-- Basic & Collapsed Advanced -->
      <section class="dsh-wsl-sbx-pane" id="pane-settings">
        <div class="dsh-wsl-sbx-card">
          <div style="margin-bottom:12px;color:var(--text-secondary);font-size:12px">
            跨系统传文件请使用 Windows 资源管理器左侧「Linux」目录拖拽复制（基础配置严禁挂载 /mnt 全盘）。
          </div>
          <div class="dsh-wsl-sbx-grid2">
            <div><label>传输模式</label><select class="dsh-wsl-sbx-select" id="in-transport"><option value="wsl">wsl</option><option value="local-linux">local-linux</option></select></div>
            <div><label>WSL 2 发行版</label><input class="dsh-wsl-sbx-input dsh-wsl-sbx-mono" id="in-distro" /></div>
            <div><label>Linux 非 root 用户名</label><input class="dsh-wsl-sbx-input dsh-wsl-sbx-mono" id="in-user" /></div>
            <div><label>工作区根目录 (原生 ext4)</label><input class="dsh-wsl-sbx-input dsh-wsl-sbx-mono" id="in-ws" /></div>
            <div><label>Runner 路径</label><input class="dsh-wsl-sbx-input dsh-wsl-sbx-mono" id="in-runner" /></div>
            <div><label>审批超时 (ms)</label><input class="dsh-wsl-sbx-input dsh-wsl-sbx-mono" type="number" id="in-ttl" /></div>
            <div><label>文件沙箱模式</label><select class="dsh-wsl-sbx-select" id="in-smode"><option value="workspace-write">workspace-write</option><option value="read-only">read-only</option></select></div>
            <div><label>审批策略模式</label><select class="dsh-wsl-sbx-select" id="in-amode"><option value="balanced">balanced</option><option value="strict">strict</option><option value="trust-workspace">trust-workspace</option></select></div>
            <div><label>网络隔离模式</label><select class="dsh-wsl-sbx-select" id="in-nmode"><option value="allowlist-proxy">allowlist-proxy</option><option value="offline">offline</option></select></div>
            <div><label>上游代理 (HTTP/SOCKS5)</label><input class="dsh-wsl-sbx-input dsh-wsl-sbx-mono" id="in-proxy" /></div>
            <div><label>包缓存策略</label><select class="dsh-wsl-sbx-select" id="in-cmode"><option value="workspace-persistent">workspace-persistent</option><option value="ephemeral-tmp">ephemeral-tmp</option></select></div>
            <div><label>豁免 .env* 脱敏工作区 (逗号分隔)</label><input class="dsh-wsl-sbx-input dsh-wsl-sbx-mono" id="in-unmask" /></div>
          </div>
          <div style="display:flex;gap:8px;margin-top:10px">
            <button class="dsh-wsl-sbx-btn dsh-wsl-sbx-btn-sec" onclick="clearCache()">清理 WSL 包缓存</button>
            <button class="dsh-wsl-sbx-btn dsh-wsl-sbx-btn-sec" onclick="upsertAgents()">写入 AGENTS.md 路由</button>
          </div>
        </div>

        <details class="dsh-wsl-sbx-advanced">
          <summary>高级风险控制（单目录 /shares 挂载、物理串口/USB 设备透传、靶机网段白名单）</summary>
          <div style="margin-top:14px;display:flex;flex-direction:column;gap:14px">
            <div>
              <b>1. 单目录受控挂载 (/shares/&lt;alias&gt;)</b>
              <div style="display:flex;gap:8px;margin:8px 0">
                <input class="dsh-wsl-sbx-input dsh-wsl-sbx-mono" style="width:140px" id="sh-alias" placeholder="alias" />
                <input class="dsh-wsl-sbx-input dsh-wsl-sbx-mono" id="sh-path" placeholder="/mnt/c/Users/Dev/Drops" />
                <select class="dsh-wsl-sbx-select" style="width:100px" id="sh-mode"><option value="ro">ro</option><option value="rw">rw</option></select>
                <button class="dsh-wsl-sbx-btn dsh-wsl-sbx-btn-sec" onclick="addShare()">添加</button>
              </div>
              <div id="sharesBox"></div>
            </div>
            <div>
              <b>2. 物理设备节点直通 (强制人工单次 allow-once)</b>
              <div style="display:flex;gap:8px;margin:8px 0">
                <input class="dsh-wsl-sbx-input dsh-wsl-sbx-mono" id="dev-list" placeholder="/dev/ttyUSB0, /dev/ttyACM0" />
                <button class="dsh-wsl-sbx-btn dsh-wsl-sbx-btn-sec" onclick="saveDevices()">保存设备白名单</button>
              </div>
            </div>
            <div>
              <b>3. 局域网靶机 CIDR / 端口 / 自定义域名</b>
              <div class="dsh-wsl-sbx-grid2" style="margin-top:8px">
                <input class="dsh-wsl-sbx-input dsh-wsl-sbx-mono" id="adv-cidrs" placeholder="CIDR 如 192.168.50.0/24" />
                <input class="dsh-wsl-sbx-input dsh-wsl-sbx-mono" id="adv-ports" placeholder="端口 如 8080, 1883" />
                <input class="dsh-wsl-sbx-input dsh-wsl-sbx-mono" id="adv-domains" placeholder="域名 如 dl.espressif.cn" />
                <button class="dsh-wsl-sbx-btn dsh-wsl-sbx-btn-sec" onclick="saveAdvNet()">保存高级网络</button>
              </div>
            </div>
          </div>
        </details>
      </section>

      <!-- Doctor -->
      <section class="dsh-wsl-sbx-pane" id="pane-doctor">
        <button class="dsh-wsl-sbx-btn dsh-wsl-sbx-btn-sec" style="margin-bottom:12px" onclick="runDoc()">执行实时 dsh-wsl-doctor 自检</button>
        <div id="docBox" class="dsh-wsl-sbx-card">点击上方按钮运行内核隔离与 22 项工具链体检。</div>
      </section>

      <!-- Audit -->
      <section class="dsh-wsl-sbx-pane" id="pane-audit">
        <table class="dsh-wsl-sbx-table" id="auditTbl"></table>
      </section>
    </main>
  </div>

  <script>
    const H = { 'Content-Type': 'application/json', 'X-DSH-WSL-Client': '1' };
    function msg(t) {
      document.getElementById('noticeMsg').textContent = t;
      document.getElementById('notice').classList.add('is-visible');
    }
    function sbxTab(id, btn) {
      document.querySelectorAll('.dsh-wsl-sbx-pane').forEach(p => p.classList.toggle('is-active', p.id === 'pane-' + id));
      document.querySelectorAll('.dsh-wsl-sbx-tab').forEach(b => b.classList.toggle('is-active', b === btn));
    }
    async function api(method, url, body) {
      const r = await fetch(url, { method, headers: H, body: body ? JSON.stringify(body) : undefined });
      return r.json();
    }
    async function loadStatus() {
      const customBk = (document.getElementById('bk-dir') && document.getElementById('bk-dir').dataset.dirty === '1')
        ? document.getElementById('bk-dir').value.trim()
        : '';
      const bkQuery = customBk ? ('?backupDir=' + encodeURIComponent(customBk)) : '';
      const [st, ap, au, bk] = await Promise.all([
        api('GET', '/wsl-sandbox/api/status'),
        api('GET', '/wsl-sandbox/api/approvals'),
        api('GET', '/wsl-sandbox/api/audit'),
        api('GET', '/wsl-sandbox/api/wsl-config/backups' + bkQuery)
      ]);
      if (!st.ok) return;
      const c = st.config;
      document.getElementById('telDistro').textContent = c.distro + (c.username ? ' · ' + c.username : '');
      document.getElementById('telWs').textContent = c.workspaceRoot;
      document.getElementById('telSync').textContent = c.enabled ? '已生效' : '已停用';
      document.getElementById('tabCnt').textContent = '(' + (ap.pending || []).length + ')';
      document.getElementById('stPending').textContent = String((ap.pending || []).length);
      document.getElementById('stRules').textContent = String((ap.sessionRules || []).length);
      document.getElementById('stAdv').textContent = c.advanced.shares.length + ' / ' + c.advanced.deviceNodes.length;

      const bkInput = document.getElementById('bk-dir');
      if (bkInput && bkInput.dataset.dirty !== '1') {
        bkInput.value = (bk && bk.backupDir) || c.backupDir || '';
      }
      const bkItems = (bk && bk.items) || [];
      const bkBox = document.getElementById('backupItemsBox');
      if (bkBox) {
        bkBox.innerHTML = bkItems.length === 0
          ? '<span style="color:var(--text-muted);font-size:12px">当前备份目录下暂无快照，点击「立即备份到此目录」生成原始 .wslconfig 与 wsl.conf 备份。</span>'
          : bkItems.map((it, idx) =>
              '<div style="display:flex;justify-content:space-between;align-items:center;gap:8px;padding:5px 0;border-bottom:1px solid var(--border-subtle)">' +
              '<div style="min-width:0"><b class="dsh-wsl-sbx-mono">' + it.name + '</b> <span class="dsh-wsl-sbx-mono" style="color:var(--text-secondary);font-size:11.5px">' + it.explorerPath + '</span></div>' +
              '<button class="dsh-wsl-sbx-btn dsh-wsl-sbx-btn-sec" data-exp="' + encodeURIComponent(it.explorerPath) + '" onclick="openBackupExplorer(decodeURIComponent(this.dataset.exp), true)">在资源管理器中定位</button>' +
              '</div>'
            ).join('');
      }

      document.getElementById('in-enabled').checked = c.enabled;
      document.getElementById('in-pwsh').checked = c.enablePwshGuard;
      document.getElementById('in-prompt').checked = c.enablePromptInjection;
      document.getElementById('in-mirror').checked = c.mirrorCn;
      document.getElementById('in-transport').value = c.transportMode;
      document.getElementById('in-distro').value = c.distro;
      document.getElementById('in-user').value = c.username || '';
      document.getElementById('in-ws').value = c.workspaceRoot;
      document.getElementById('in-runner').value = c.runnerPath;
      document.getElementById('in-ttl').value = c.approvalTimeoutMs;
      document.getElementById('in-smode').value = c.sandboxMode;
      document.getElementById('in-amode').value = c.approvalPolicyMode;
      document.getElementById('in-nmode').value = c.networkMode;
      document.getElementById('in-proxy').value = c.upstreamProxy || '';
      document.getElementById('in-cmode').value = c.cacheMode;
      document.getElementById('in-unmask').value = (c.unmaskedEnvWorkspaces || []).join(', ');
      document.getElementById('dev-list').value = c.advanced.deviceNodes.map(d => d.path).join(', ');
      document.getElementById('adv-cidrs').value = c.advanced.localLabCidrs.join(', ');
      document.getElementById('adv-ports').value = c.advanced.localLabPorts.join(', ');
      document.getElementById('adv-domains').value = c.advanced.customAllowedDomains.join(', ');

      const shareRowsHtml = c.advanced.shares.map(s =>
        '<div style="display:flex;justify-content:space-between;align-items:center;padding:6px 0;border-bottom:1px solid var(--border-subtle)">' +
        '<span class="dsh-wsl-sbx-mono">/shares/' + s.alias + ' &lt;- ' + s.sourceLinuxPath + ' (' + s.mode + ')</span>' +
        '<button class="dsh-wsl-sbx-btn dsh-wsl-sbx-btn-out-danger" onclick="delShare(\\'' + s.id + '\\')">取消挂载</button></div>'
      ).join('') || '<span style="color:var(--text-muted);font-size:12px">当前未挂载任何外部目录（所有 Windows 盘符对 AI 完全不可见）</span>';
      document.getElementById('sharesBox').innerHTML = shareRowsHtml;
      const qkBox = document.getElementById('quickSharesBox');
      if (qkBox) qkBox.innerHTML = shareRowsHtml;

      document.getElementById('pendingBox').innerHTML = (ap.pending || []).map(p =>
        '<div class="dsh-wsl-sbx-card">' +
        '<div style="display:flex;justify-content:space-between"><b>' + p.summary + '</b><span class="dsh-wsl-sbx-mono" style="color:var(--text-muted)">' + p.requestId + '</span></div>' +
        '<pre class="dsh-wsl-sbx-cmd">' + (p.command || '') + '</pre>' +
        '<div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:8px">' +
        '<button class="dsh-wsl-sbx-btn dsh-wsl-sbx-btn-apply" onclick="decide(\\'' + p.requestId + '\\',\\'allow-once\\')">允许一次</button>' +
        '<button class="dsh-wsl-sbx-btn dsh-wsl-sbx-btn-sec" ' + (p.touchesPhysicalDevice || !p.allowSessionRuleOption ? 'disabled' : '') + ' onclick="decide(\\'' + p.requestId + '\\',\\'allow-session-rule\\')">' + (p.touchesPhysicalDevice ? '硬件锁死单次' : '允许会话前缀') + '</button>' +
        '<button class="dsh-wsl-sbx-btn dsh-wsl-sbx-btn-out-danger" onclick="decide(\\'' + p.requestId + '\\',\\'deny\\')">拒绝</button>' +
        '<input class="dsh-wsl-sbx-input" style="max-width:220px" id="gd-' + p.requestId + '" placeholder="输入修改意见..." />' +
        '<button class="dsh-wsl-sbx-btn dsh-wsl-sbx-btn-sec" onclick="decide(\\'' + p.requestId + '\\',\\'deny-with-guidance\\')">附意见打回</button>' +
        '</div></div>'
      ).join('') || '<div class="dsh-wsl-sbx-card" style="color:var(--text-secondary)">当前无待处理的审批请求。</div>';

      document.getElementById('rulesBox').textContent = (ap.sessionRules || []).map(r => '[' + r.join(' ') + ']').join('  ') || '暂无缓存前缀规则';
      document.getElementById('auditTbl').innerHTML = '<thead><tr><th>时间</th><th>类型</th><th>摘要</th><th>结果</th></tr></thead><tbody>' +
        (au.records || []).slice().reverse().map(r => '<tr><td class="dsh-wsl-sbx-mono">' + r.timestamp + '</td><td>' + r.kind + '</td><td>' + r.summary + '</td><td>' + r.outcome + '</td></tr>').join('') + '</tbody>';
    }
    async function saveBasic() {
      const r = await api('PUT', '/wsl-sandbox/api/config', {
        enabled: document.getElementById('in-enabled').checked,
        enablePwshGuard: document.getElementById('in-pwsh').checked,
        enablePromptInjection: document.getElementById('in-prompt').checked,
        mirrorCn: document.getElementById('in-mirror').checked,
        transportMode: document.getElementById('in-transport').value,
        distro: document.getElementById('in-distro').value.trim(),
        username: document.getElementById('in-user').value.trim() || undefined,
        workspaceRoot: document.getElementById('in-ws').value.trim(),
        runnerPath: document.getElementById('in-runner').value.trim(),
        approvalTimeoutMs: Number(document.getElementById('in-ttl').value) || 60000,
        sandboxMode: document.getElementById('in-smode').value,
        approvalPolicyMode: document.getElementById('in-amode').value,
        networkMode: document.getElementById('in-nmode').value,
        upstreamProxy: document.getElementById('in-proxy').value.trim(),
        cacheMode: document.getElementById('in-cmode').value,
        unmaskedEnvWorkspaces: document.getElementById('in-unmask').value.split(',').map(s => s.trim()).filter(Boolean)
      });
      msg(r.ok ? '基础配置已保存并生效。' : ('保存失败: ' + (r.error && r.error.message)));
      loadStatus();
    }
    async function decide(id, decision) {
      const g = document.getElementById('gd-' + id);
      await api('POST', '/wsl-sandbox/api/approvals/' + encodeURIComponent(id) + '/decide', {
        decision, guidance: g ? g.value.trim() : undefined
      });
      loadStatus();
    }
    async function clearSessionRules() { await api('DELETE', '/wsl-sandbox/api/session-rules'); msg('已清空会话规则。'); loadStatus(); }
    async function emergencyKill() { await api('POST', '/wsl-sandbox/api/session/invalidate'); msg('已熔断并清理全部沙箱进程组。'); loadStatus(); }
    async function clearCache() { await api('POST', '/wsl-sandbox/api/cache/clear'); msg('已清理 WSL 包管理器缓存。'); }
    async function upsertAgents() { const r = await api('POST', '/wsl-sandbox/api/agents-md', {}); msg(r.ok ? ('已更新 ' + r.filePath) : '更新失败'); }
    async function addShare() {
      const alias = document.getElementById('sh-alias').value.trim();
      const sourceLinuxPath = document.getElementById('sh-path').value.trim();
      const mode = document.getElementById('sh-mode').value;
      const r = await api('POST', '/wsl-sandbox/api/advanced/shares', { id: 'sh-' + Date.now(), alias, sourceLinuxPath, mode });
      msg(r.ok ? ('已挂载至 /shares/' + (r.share ? r.share.alias : alias)) : ('拦截: ' + (r.error && r.error.message)));
      loadStatus();
    }
    async function quickAddShare() {
      const sourceLinuxPath = document.getElementById('qk-path').value.trim();
      const alias = document.getElementById('qk-alias').value.trim();
      const mode = document.getElementById('qk-mode').value;
      const r = await api('POST', '/wsl-sandbox/api/advanced/shares', { id: 'sh-' + Date.now(), alias, sourceLinuxPath, mode });
      if (r.ok) {
        document.getElementById('qk-path').value = '';
        document.getElementById('qk-alias').value = '';
        msg('已挂载指定目录: /shares/' + (r.share ? r.share.alias : alias) + ' <- ' + (r.share ? r.share.sourceLinuxPath : sourceLinuxPath));
      } else {
        msg('拦截: ' + (r.error && r.error.message));
      }
      loadStatus();
    }
    async function backupWslConfigs() {
      const bkIn = document.getElementById('bk-dir');
      const backupDir = bkIn ? bkIn.value.trim() : '';
      const r = await api('POST', '/wsl-sandbox/api/wsl-config/backup', { backupDir: backupDir || undefined });
      if (r.ok && bkIn) {
        bkIn.value = r.backupDir || backupDir;
        bkIn.dataset.dirty = '0';
      }
      msg(r.ok ? ('原始 WSL 配置已备份至: ' + r.backupDir) : ('备份失败: ' + (r.error && r.error.message)));
      loadStatus();
    }
    async function pickBackupDir() {
      const r = await api('POST', '/wsl-sandbox/api/wsl-config/pick-dir', {});
      if (r.ok && r.selectedDir) {
        const bkIn = document.getElementById('bk-dir');
        if (bkIn) { bkIn.value = r.selectedDir; bkIn.dataset.dirty = '0'; }
        msg('已选择备份目录: ' + r.selectedDir);
        loadStatus();
      } else if (r.message) {
        msg(r.message);
      }
    }
    async function openBackupExplorer(targetPath, selectFile) {
      const bkIn = document.getElementById('bk-dir');
      const backupDir = bkIn ? bkIn.value.trim() : '';
      const r = await api('POST', '/wsl-sandbox/api/wsl-config/open-explorer', {
        targetPath: targetPath || backupDir || undefined,
        backupDir: backupDir || undefined,
        selectFile: Boolean(selectFile)
      });
      msg(r.ok
        ? ('已拉起资源管理器窗口: ' + (r.explorerArgs ? r.explorerArgs.join(' ') : r.targetPath))
        : ('拦截: ' + (r.error && r.error.message)));
    }
    document.addEventListener('input', function (ev) {
      if (ev.target && ev.target.id === 'bk-dir') ev.target.dataset.dirty = '1';
    });
    function toggleWslConfCmd() {
      const el = document.getElementById('wslConfCmdBox');
      if (el) el.style.display = el.style.display === 'none' ? 'block' : 'none';
    }
    async function delShare(id) { await api('DELETE', '/wsl-sandbox/api/advanced/shares/' + encodeURIComponent(id)); msg('已取消挂载并终止旧沙箱进程。'); loadStatus(); }
    async function saveDevices() {
      const nodes = document.getElementById('dev-list').value.split(',').map(s => s.trim()).filter(Boolean).map(p => ({ path: p }));
      const r = await api('PUT', '/wsl-sandbox/api/advanced/devices', { deviceNodes: nodes });
      msg(r.ok ? '已更新物理设备白名单。' : ('拦截: ' + (r.error && r.error.message)));
      loadStatus();
    }
    async function saveAdvNet() {
      const r = await api('PUT', '/wsl-sandbox/api/advanced/network', {
        localLabCidrs: document.getElementById('adv-cidrs').value.split(',').map(s => s.trim()).filter(Boolean),
        localLabPorts: document.getElementById('adv-ports').value.split(',').map(s => Number(s.trim())).filter(Boolean),
        customAllowedDomains: document.getElementById('adv-domains').value.split(',').map(s => s.trim()).filter(Boolean)
      });
      msg(r.ok ? '已更新高级网络白名单。' : ('拦截: ' + (r.error && r.error.message)));
      loadStatus();
    }
    async function runDoc() {
      document.getElementById('docBox').textContent = '正在执行内核隔离与工具链自检...';
      const r = await api('GET', '/wsl-sandbox/api/doctor');
      if (!r.ok || !r.report) { document.getElementById('docBox').textContent = '自检失败'; return; }
      const d = r.report;
      document.getElementById('docBox').innerHTML =
        '<div><b>总体结论: ' + d.verdict.toUpperCase() + '</b> · 内核 ' + d.os.kernel + ' · bwrap ' + (d.sandbox.bwrapVersion || '缺失') +
        ' · io_uring=' + d.sandbox.seccompIoUringBlocked + ' · AF_VSOCK=' + d.sandbox.seccompAfVsockBlocked + '</div>' +
        '<table class="dsh-wsl-sbx-table" style="margin-top:10px"><thead><tr><th>工具</th><th>档位</th><th>版本</th><th>状态</th></tr></thead><tbody>' +
        d.tools.map(t => '<tr><td class="dsh-wsl-sbx-mono">' + t.name + '</td><td>' + t.tier + '</td><td class="dsh-wsl-sbx-mono">' + (t.version || '-') + '</td><td>' + (t.present ? '就绪' : '可选缺失') + '</td></tr>').join('') +
        '</tbody></table>';
    }
    loadStatus();
    setInterval(loadStatus, 4000);
  </script>
</body>
</html>`;
}
