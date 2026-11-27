/**
 * `/wsl-sandbox/ui` 独立 HTML/CSS/JS 控制面板。
 *
 * 视觉规范严格对齐 DSH Purge / DSH Marketplace 暗色层级：
 * - 零 Emoji、零 Tailwind 外部依赖，全局部隔离 `.dsh-wsl-sbx-*` 样式类（`z-index <= 850`）。
 * - 内部 `revision` 与 `generation` 计数器严格收拢在后端，主界面仅展示友好同步状态（`已生效` / `待点击应用`）。
 * - 基础策略页暴露全部基础开关，但彻底隐藏 `/mnt` 全盘挂载入口。
 * - 高级共享与物理硬件控制默认折叠于 `<details class="dsh-wsl-sbx-advanced">` 内部。
 * - 内置 **简体中文 | English** 界面概览与主导航一键切换，实时联动 `/wsl-sandbox/api/*`。
 */

                                                          

export const name = 'dsh-wsl-sandbox-web-ui';
export const inject           = [];

                                    
                                
                              
 

export function apply(ctx                  , config                    = {})       {
  if (!ctx.http) return;
  const uiPath = config.routePrefix
    ? config.routePrefix.replace(/\/api\/?$/, '/ui')
    : '/wsl-sandbox/ui';
  try {
    const dispose = ctx.http.route('GET', uiPath, (_req, res) => {
      res.status(200).html(renderWslSandboxUiHtml());
    });
    if (typeof dispose === 'function') {
      if ('fiber' in (ctx          ) || typeof ctx.inject === 'function') {
        ctx.effect?.(() => () => void dispose());
      } else {
        ctx.effect?.(dispose);
      }
    }
  } catch {
    // 路由已由主宿主入口（`web-api.ts`）注册，此处保持幂等跳过
  }
  const rawLogger = ctx.logger           ;
  const scopedLogger =
    typeof rawLogger === 'function'
      ? (rawLogger                                                 )('dsh-wsl-sandbox-web-ui')
      : (rawLogger                                              );
  if (typeof scopedLogger?.info === 'function') {
    scopedLogger.info(`[dsh-wsl-sandbox-web-ui] UI active at ${uiPath} (z-index cap ${config.zIndexCap ?? 850})`);
  }
}

export function renderWslSandboxUiHtml()         {
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
        <span id="brandTitle">WSL 2 沙箱</span>
        <span id="brandSub" style="font-size:12.5px;font-weight:400;color:var(--text-secondary)">内核命名空间执行后端、单壳方言防呆与物理硬件单次门禁</span>
      </div>
      <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">
        <span class="dsh-wsl-sbx-mono" style="font-size:12px;color:var(--text-secondary)">dsh-wsl-sandbox v0.3.0</span>
        <button class="dsh-wsl-sbx-btn dsh-wsl-sbx-btn-sec" id="btn-oobe-reopen" style="padding:3px 9px;font-size:11.5px" onclick="reopenOobeHint()">OOBE 初始化向导说明</button>
        <button class="dsh-wsl-sbx-btn dsh-wsl-sbx-btn-apply" id="langBtn-zh" style="padding:3px 9px;font-size:11.5px" onclick="setUiLang('zh')">简体中文</button>
        <button class="dsh-wsl-sbx-btn dsh-wsl-sbx-btn-sec" id="langBtn-en" style="padding:3px 9px;font-size:11.5px" onclick="setUiLang('en')">English</button>
      </div>
    </div>

    <div class="dsh-wsl-sbx-tabs">
      <button class="dsh-wsl-sbx-tab is-active" onclick="sbxTab('status', this)"><span id="tabLbl-status">状态</span></button>
      <button class="dsh-wsl-sbx-tab" onclick="sbxTab('approvals', this)"><span id="tabLbl-approvals">审批队列</span> <span id="tabCnt">(0)</span></button>
      <button class="dsh-wsl-sbx-tab" onclick="sbxTab('settings', this)"><span id="tabLbl-settings">基础策略与高级共享</span></button>
      <button class="dsh-wsl-sbx-tab" onclick="sbxTab('doctor', this)"><span id="tabLbl-doctor">内核体检</span></button>
      <button class="dsh-wsl-sbx-tab" onclick="sbxTab('logs', this)"><span id="tabLbl-logs">运行日志</span></button>
      <button class="dsh-wsl-sbx-tab" onclick="sbxTab('audit', this)"><span id="tabLbl-audit">审计明细</span></button>
    </div>

    <div class="dsh-wsl-sbx-tel">
      <span><i class="dsh-wsl-sbx-dot" id="telDot"></i>受控发行版 <b class="dsh-wsl-sbx-mono" id="telDistro">加载中...</b></span>
      <span>工作区 <b class="dsh-wsl-sbx-mono" id="telWs">-</b></span>
      <span>共用 Node <b class="dsh-wsl-sbx-mono" id="telNode">-</b></span>
      <span>隔离层级 <b id="telIso">bwrap + seccomp + UDS 代理</b></span>
      <span>配置状态 <b id="telSync">已生效</b></span>
    </div>

    <div class="dsh-wsl-sbx-notice" id="notice"><span id="noticeMsg"></span><button class="dsh-wsl-sbx-btn dsh-wsl-sbx-btn-sec" id="btn-notice-close" onclick="document.getElementById('notice').classList.remove('is-visible')">关闭</button></div>

    <main class="dsh-wsl-sbx-panel">
      <div class="dsh-wsl-sbx-head">
        <h1 class="dsh-wsl-sbx-title" id="pTitle">沙箱状态</h1>
        <div class="dsh-wsl-sbx-actions">
          <button class="dsh-wsl-sbx-btn dsh-wsl-sbx-btn-apply" id="btn-apply" onclick="saveBasic()">应用</button>
          <button class="dsh-wsl-sbx-btn dsh-wsl-sbx-btn-out-danger" id="btn-reset" onclick="loadStatus(true)">还原</button>
          <button class="dsh-wsl-sbx-btn dsh-wsl-sbx-btn-danger" id="btn-kill" onclick="emergencyKill()">熔断强杀</button>
        </div>
      </div>

      <!-- Status -->
      <section class="dsh-wsl-sbx-pane is-active" id="pane-status">
        <div class="dsh-wsl-sbx-card" id="sbxIntroBanner" style="border-color:var(--border-default);margin-bottom:14px">
          <div style="font-weight:600;margin-bottom:4px" id="introTitle">WSL 2 沙箱后端概览 (v0.3.0)</div>
          <div style="color:var(--text-secondary);font-size:12.5px;line-height:1.55" id="introBody">
            将 AI 的文件读写、构建与终端执行统一收敛到 WSL 2 原生 Linux 命名空间内（bubblewrap + seccomp-bpf + UDS 白名单代理），自动遮蔽 Windows 全盘（/mnt）与敏感配置目录（~/.dsh / ~/.ssh），并在宿主侧挂载微软官方 PowerShell AST 单壳防呆守卫与物理硬件/驱动单次人工审批锁。右上角可切换简体中文与英文说明。
          </div>
        </div>
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
                  默认已在内核命名空间层将 AI 可见的 <span class="dsh-wsl-sbx-mono">/mnt</span> 及 <span class="dsh-wsl-sbx-mono">~/.dsh</span>/<span class="dsh-wsl-sbx-mono">~/.ssh</span> 等配置目录彻底遮蔽；可任意指定备份目录（只读快照），并为每一项备份拉起 Windows 原生资源管理器定位文件。
                </div>
                <div style="color:var(--text-muted);font-size:11.5px;margin-top:3px">
                  说明：Windows 官方 WSL Settings 与 WSL Manager 均共享同一套 <span class="dsh-wsl-sbx-mono">%USERPROFILE%\.wslconfig</span> 与 <span class="dsh-wsl-sbx-mono">/etc/wsl.conf</span> 路径；本插件默认绝不自动修改原配置，且配置/备份目录仅限当前用户访问。
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
            <pre class="dsh-wsl-sbx-cmd" id="wslConfCmdPre"># 在 WSL 内执行（只读备份原版 /etc/wsl.conf 后关闭自动挂载）：
bash ~/.local/share/dsh-wsl-sandbox/runner/packages/bootstrap/provision-wsl.sh --disable-automount
# 如需一键还原原厂 /etc/wsl.conf：
bash ~/.local/share/dsh-wsl-sandbox/runner/packages/bootstrap/provision-wsl.sh --restore-configs
# 在 Windows PowerShell 中仅重启当前发行版（切勿用 wsl --shutdown 以免关掉其他 WSL 会话）：
wsl.exe --terminate &lt;当前发行版&gt;</pre>
          </div>

          <div>
            <div style="font-weight:600;margin-bottom:4px">指定单目录快捷挂载（直接粘贴 Windows 文件夹路径或 Linux 路径 -> /shares/&lt;别名&gt;）</div>
            <div style="color:var(--text-secondary);font-size:12px;margin-bottom:8px">
              自动将 <span class="dsh-wsl-sbx-mono">D:\Datasets\Project</span> 转换为受控挂载点 <span class="dsh-wsl-sbx-mono">/shares/Project</span>（默认只读，严禁填入 <span class="dsh-wsl-sbx-mono">C:\</span>、整盘根目录或配置/凭证目录）。
            </div>
            <div style="display:flex;flex-wrap:wrap;gap:8px;align-items:center">
              <input class="dsh-wsl-sbx-input dsh-wsl-sbx-mono" style="flex:1;min-width:240px" id="qk-path" placeholder="例如 D:\Datasets\Project 或 C:\Users\Alice\Downloads\spec" />
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

        <!-- Controlled AI Bootstrap Channel + Script Preview (Eliminates dual-entry conflict) -->
        <div class="dsh-wsl-sbx-card" id="bootstrapCard" style="border-color:var(--border-default)">
          <div style="display:flex;flex-wrap:wrap;justify-content:space-between;align-items:center;gap:10px;margin-bottom:8px">
            <div>
              <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">
                <b id="bsCardTitle">受控 AI 初始化引导与安装脚本预览</b>
                <span class="dsh-wsl-sbx-pill" id="bsPhasePill">已锁定关闭（仅授权人工手动或先开闸）</span>
              </div>
              <div style="color:var(--text-secondary);font-size:12px;margin-top:4px" id="bsCardDesc">
                彻底消除「人工脚本 vs AI Skill」冲突：默认态 L0 机械锁定安装脚本（<code>install-dsh-plugin.ps1</code> / <code>provision-wsl.sh</code>）；点击下方按钮可先审阅完整安装脚本与 SHA-256 哈希，再开启限时 20 分钟「受控引导通道」（严格强制 1 探测 -&gt; 2 <code>-DryRun</code> 预览确认卡 -&gt; 3 单次审批安装 -&gt; 4 <code>doctor</code> 闭环自动关闸）。常规测试与 USB 联调推荐保持 WSL 2 默认 <b>NAT</b> 网络模式。
              </div>
            </div>
            <div style="display:flex;flex-wrap:wrap;gap:8px;align-items:center">
              <button class="dsh-wsl-sbx-btn dsh-wsl-sbx-btn-sec" id="bsBtnPreview" onclick="loadBootstrapPreview(true)">预览安装脚本与 SHA-256</button>
              <button class="dsh-wsl-sbx-btn dsh-wsl-sbx-btn-apply" id="bsBtnOpen" onclick="toggleBootstrapChannel(true)">开启受控引导通道并复制会话指令</button>
              <button class="dsh-wsl-sbx-btn dsh-wsl-sbx-btn-out-danger" id="bsBtnClose" style="display:none" onclick="toggleBootstrapChannel(false)">关闭引导通道</button>
            </div>
          </div>
          <div style="display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-bottom:8px">
            <span style="font-size:12px;color:var(--text-secondary)">锁定目标发行版（留空则探测后再确认）:</span>
            <input class="dsh-wsl-sbx-input dsh-wsl-sbx-mono" style="max-width:260px" id="bs-target-distro" placeholder="如 Ubuntu-26.04 / Debian" />
            <span class="dsh-wsl-sbx-mono" id="bsTimerHint" style="font-size:11.5px;color:var(--text-secondary)"></span>
          </div>
          <div id="bsPreviewWrap" style="display:none;border-top:1px solid var(--border-subtle);padding-top:10px;margin-top:8px">
            <div style="display:flex;flex-wrap:wrap;gap:6px;margin-bottom:8px" id="bsScriptTabs"></div>
            <div class="dsh-wsl-sbx-mono" id="bsScriptMeta" style="font-size:11.5px;color:var(--text-secondary);margin-bottom:6px"></div>
            <pre class="dsh-wsl-sbx-cmd" id="bsScriptCode" style="max-height:260px;overflow:auto;white-space:pre"></pre>
            <div style="font-size:11.5px;color:var(--text-secondary);margin-top:6px">可直接复制给 AI 会话的受控初始化指令：</div>
            <pre class="dsh-wsl-sbx-cmd" id="bsPromptBox" style="white-space:pre-wrap"></pre>
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
            支持任意已注册的 WSL 2 发行版（Ubuntu 26.04/24.04、Debian、Fedora、Arch 或经 WSL Manager 导入/迁移磁盘的自定义实例）。即便实例从资源管理器左侧「Linux」消失，仍可通过 <span class="dsh-wsl-sbx-mono">wsl.exe</span> 与原生 ext4 Runner 正常运行（基础配置严禁挂载 <span class="dsh-wsl-sbx-mono">/mnt</span> 全盘或配置目录）。
          </div>
          <div style="display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-bottom:12px;padding:10px 12px;background:var(--bg-inset);border:1px solid var(--border-subtle);border-radius:9px">
            <span style="font-size:12px;color:var(--text-secondary)">已发现的 WSL 2 实例:</span>
            <select class="dsh-wsl-sbx-select dsh-wsl-sbx-mono" style="flex:1;min-width:240px" id="in-distro-select" onchange="pickDiscoveredDistro()">
              <option value="">点击右侧「刷新实例」探测已安装/已迁移的 WSL 2 发行版...</option>
            </select>
            <button class="dsh-wsl-sbx-btn dsh-wsl-sbx-btn-sec" onclick="refreshDistros(true)">刷新实例</button>
          </div>
          <div id="distroMetaHint" style="display:none;margin-bottom:12px;font-size:12px;color:var(--text-secondary)"></div>
          <div class="dsh-wsl-sbx-grid2">
            <div><label>传输模式</label><select class="dsh-wsl-sbx-select" id="in-transport"><option value="wsl">wsl</option><option value="local-linux">local-linux</option></select></div>
            <div><label>WSL 2 发行版名称</label><input class="dsh-wsl-sbx-input dsh-wsl-sbx-mono" id="in-distro" placeholder="如 Ubuntu-26.04 / Debian / 自定义导入名" /></div>
            <div><label>工具链环境档位 (provision / doctor)</label>
              <select class="dsh-wsl-sbx-select" id="in-profile">
                <option value="core">core (~350MB: 沙箱基础 + Codex CLI + C/C++ + python3 + Node 24 LTS 共用)</option>
                <option value="standard">standard (~1.2GB 推荐: + mise/uv/pnpm/yarn/bun/Go/golangci-lint/Rust)</option>
                <option value="universal">universal (~3.5GB: + clang/bazelisk/Node 22&amp;24/JDK21/Gradle/Ruby/PHP)</option>
              </select>
            </div>
            <div><label>Linux 非 root 用户名</label><input class="dsh-wsl-sbx-input dsh-wsl-sbx-mono" id="in-user" /></div>
            <div><label>工作区根目录 (原生 ext4)</label><input class="dsh-wsl-sbx-input dsh-wsl-sbx-mono" id="in-ws" /></div>
            <div><label>Runner 路径 (原生 ext4，零 /mnt 占用)</label><input class="dsh-wsl-sbx-input dsh-wsl-sbx-mono" id="in-runner" /></div>
            <div><label>审批超时 (ms)</label><input class="dsh-wsl-sbx-input dsh-wsl-sbx-mono" type="number" id="in-ttl" /></div>
            <div><label>文件沙箱模式</label><select class="dsh-wsl-sbx-select" id="in-smode"><option value="workspace-write">workspace-write</option><option value="read-only">read-only</option></select></div>
            <div><label>审批策略模式</label><select class="dsh-wsl-sbx-select" id="in-amode"><option value="balanced">balanced</option><option value="strict">strict</option><option value="trust-workspace">trust-workspace</option></select></div>
            <div><label>网络隔离模式</label><select class="dsh-wsl-sbx-select" id="in-nmode"><option value="allowlist-proxy">allowlist-proxy</option><option value="offline">offline</option></select></div>
            <div><label>上游代理 (HTTP/SOCKS5)</label><input class="dsh-wsl-sbx-input dsh-wsl-sbx-mono" id="in-proxy" /></div>
            <div><label>包缓存策略</label><select class="dsh-wsl-sbx-select" id="in-cmode"><option value="workspace-persistent">workspace-persistent</option><option value="ephemeral-tmp">ephemeral-tmp</option></select></div>
            <div><label>运行日志级别 (自动脱敏 · 2.5s 合并写盘)</label>
              <select class="dsh-wsl-sbx-select" id="in-loglevel">
                <option value="info">info (默认推荐)</option>
                <option value="warn">warn (仅告警与错误)</option>
                <option value="error">error (仅错误)</option>
                <option value="debug">debug (详细排障)</option>
              </select>
            </div>
            <div style="grid-column:1 / -1"><label>豁免 .env* 脱敏工作区 (逗号分隔)</label><input class="dsh-wsl-sbx-input dsh-wsl-sbx-mono" id="in-unmask" /></div>
          </div>
          <div style="display:flex;gap:8px;margin-top:10px">
            <button class="dsh-wsl-sbx-btn dsh-wsl-sbx-btn-sec" onclick="clearCache()">清理 WSL 包缓存</button>
            <button class="dsh-wsl-sbx-btn dsh-wsl-sbx-btn-sec" onclick="upsertAgents()">写入 AGENTS.md 路由</button>
          </div>
        </div>

        <details class="dsh-wsl-sbx-advanced">
          <summary>高级风险控制（单目录 /shares 挂载、物理 USB/串口/HID 设备透传、靶机网段白名单）</summary>
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
              <div style="color:var(--text-secondary);font-size:11.5px;margin-top:4px">
                支持 <span class="dsh-wsl-sbx-mono">/dev/bus/usb/NNN/NNN</span>（手机 ADB/Fastboot/EDL、libusb）、<span class="dsh-wsl-sbx-mono">/dev/hidraw*</span>、<span class="dsh-wsl-sbx-mono">/dev/cdc-wdm*</span>、<span class="dsh-wsl-sbx-mono">/dev/video*</span>、<span class="dsh-wsl-sbx-mono">/dev/ttyUSB*</span>、<span class="dsh-wsl-sbx-mono">/dev/ttyACM*</span>。注意：Windows 免驱网卡或依赖原厂 OEM 驱动的手机 BL 解锁工具若 WSL 2 默认内核无对应驱动模块，建议留在 Windows 侧按单次审批调用原厂驱动。
              </div>
              <div style="display:flex;gap:8px;margin:8px 0">
                <input class="dsh-wsl-sbx-input dsh-wsl-sbx-mono" id="dev-list" placeholder="/dev/bus/usb/001/002, /dev/ttyUSB0, /dev/hidraw0" />
                <button class="dsh-wsl-sbx-btn dsh-wsl-sbx-btn-sec" onclick="saveDevices()">保存设备白名单</button>
              </div>
            </div>
            <div>
              <b>3. 局域网靶机 CIDR / 端口 / 自定义域名</b>
              <div class="dsh-wsl-sbx-grid2" style="margin-top:8px">
                <input class="dsh-wsl-sbx-input dsh-wsl-sbx-mono" id="adv-cidrs" placeholder="CIDR 如 192.168.50.0/24" />
                <input class="dsh-wsl-sbx-input dsh-wsl-sbx-mono" id="adv-ports" placeholder="端口 如 8080, 1883" />
                <input class="dsh-wsl-sbx-input dsh-wsl-sbx-mono" id="adv-domains" placeholder="自定义域名 如 mirrors.example.com" />
                <button class="dsh-wsl-sbx-btn dsh-wsl-sbx-btn-sec" onclick="saveAdvNet()">保存高级网络</button>
              </div>
            </div>
            <div>
              <b>4. 落盘足迹清单、包缓存清理与一键可逆卸载</b>
              <div style="font-size:12px;color:var(--text-secondary);margin-top:4px">
                无需翻查安装日志，实时查看宿主与 WSL 2 侧全部落盘目录体积，一键清空 <span class="dsh-wsl-sbx-mono">~/.cache/dsh-wsl-sandbox</span> 工作区包缓存或移除 <span class="dsh-wsl-sbx-mono">AGENTS.md</span> 注入块。彻底卸载请运行：<span class="dsh-wsl-sbx-mono">.\\packages\\bootstrap\\uninstall-dsh-plugin.ps1 [-DryRun] [-PurgeToolchains]</span>
              </div>
              <div style="display:flex;flex-wrap:wrap;gap:8px;margin-top:8px">
                <button class="dsh-wsl-sbx-btn dsh-wsl-sbx-btn-sec" onclick="loadFootprint()">查看落盘足迹清单</button>
                <button class="dsh-wsl-sbx-btn dsh-wsl-sbx-btn-sec" onclick="purgeSandboxCache()">清空沙箱包缓存与残留临时目录</button>
                <button class="dsh-wsl-sbx-btn dsh-wsl-sbx-btn-out-danger" onclick="removeAgentsMdBlock()">移除工作区 AGENTS.md 注入块</button>
              </div>
              <pre id="footprintBox" class="dsh-wsl-sbx-mono" style="display:none;margin-top:8px;padding:10px;background:#0f1012;border:1px solid var(--border-subtle);border-radius:6px;font-size:11.5px;white-space:pre-wrap;max-height:220px;overflow:auto"></pre>
            </div>
          </div>
        </details>
      </section>

      <!-- Doctor -->
      <section class="dsh-wsl-sbx-pane" id="pane-doctor">
        <button class="dsh-wsl-sbx-btn dsh-wsl-sbx-btn-sec" style="margin-bottom:12px" onclick="runDoc()">按当前配置档位执行 dsh-wsl-doctor 自检</button>
        <div id="docBox" class="dsh-wsl-sbx-card">点击上方按钮按所选环境档位（core / standard / universal）运行内核隔离与 Codex 工具链体检。</div>
      </section>

      <!-- Structured Logs -->
      <section class="dsh-wsl-sbx-pane" id="pane-logs">
        <div class="dsh-wsl-sbx-card" style="margin-bottom:12px">
          <div style="display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-bottom:8px">
            <select class="dsh-wsl-sbx-select" style="width:130px" id="log-lvl" onchange="loadLogs()">
              <option value="debug">全部级别</option>
              <option value="info" selected>INFO 及以上</option>
              <option value="warn">WARN 及以上</option>
              <option value="error">仅 ERROR</option>
            </select>
            <select class="dsh-wsl-sbx-select" style="width:145px" id="log-src" onchange="loadLogs()">
              <option value="all">全部来源</option>
              <option value="host">宿主机 Host</option>
              <option value="wsl-runner">WSL Runner</option>
            </select>
            <input class="dsh-wsl-sbx-input dsh-wsl-sbx-mono" style="flex:1;min-width:180px" id="log-q" placeholder="搜索事件名、组件或关键字..." onkeydown="if(event.key==='Enter')loadLogs()" />
            <button class="dsh-wsl-sbx-btn dsh-wsl-sbx-btn-sec" onclick="loadLogs()">刷新</button>
            <button class="dsh-wsl-sbx-btn dsh-wsl-sbx-btn-sec" onclick="exportLogsNdjson()">导出 NDJSON</button>
            <button class="dsh-wsl-sbx-btn dsh-wsl-sbx-btn-out-danger" onclick="clearLogs()">清空日志</button>
          </div>
          <div style="font-size:11.5px;color:var(--text-secondary)" class="dsh-wsl-sbx-mono" id="logStatsBar">
            纯内存环形缓冲读取（零读盘开销） · 2.5s 合并批量落盘 + 重复风暴折叠（保护 SSD 寿命）
          </div>
        </div>
        <div class="dsh-wsl-sbx-card" style="padding:0;overflow-x:auto">
          <table class="dsh-wsl-sbx-table" id="logsTbl"></table>
        </div>
      </section>

      <!-- Audit -->
      <section class="dsh-wsl-sbx-pane" id="pane-audit">
        <table class="dsh-wsl-sbx-table" id="auditTbl"></table>
      </section>
    </main>
  </div>

  <script>
    const H = { 'Content-Type': 'application/json', 'X-DSH-WSL-Client': '1' };
    let discoveredDistros = [];
    let currentTab = 'status';
    let uiLang = 'zh';
    let formDirty = false;
    const UI_I18N = {
      zh: {
        brandTitle: 'WSL 2 沙箱',
        brandSub: '内核命名空间执行后端、单壳方言防呆与物理硬件单次门禁',
        introTitle: 'WSL 2 沙箱后端概览 (v0.3.0)',
        introBody: '将 AI 的文件读写、构建与终端执行统一收敛到 WSL 2 原生 Linux 命名空间内（bubblewrap + seccomp-bpf + UDS 白名单代理），自动遮蔽 Windows 全盘（/mnt）与敏感配置目录（~/.dsh / ~/.ssh），并在宿主侧挂载微软官方 PowerShell AST 单壳防呆守卫与物理硬件/驱动单次人工审批锁。右上角可切换简体中文与英文说明。',
        apply: '应用',
        reset: '还原',
        kill: '熔断强杀',
        close: '关闭',
        tabs: {
          status: '状态',
          approvals: '审批队列',
          settings: '基础策略与高级共享',
          doctor: '内核体检',
          logs: '运行日志',
          audit: '审计明细'
        },
        titles: {
          status: '沙箱状态',
          approvals: '审批队列',
          settings: '基础策略与高级共享',
          doctor: '内核体检',
          logs: '运行日志',
          audit: '审计明细'
        },
        bsTitle: '受控 AI 初始化引导与安装脚本预览',
        bsPreviewBtn: '预览安装脚本与 SHA-256',
        bsOpenBtn: '开启受控引导通道并复制会话指令',
        bsCloseBtn: '关闭引导通道'
      },
      en: {
        brandTitle: 'WSL 2 Sandbox',
        brandSub: 'Linux namespace execution backend, single-shell AST dialect guard & single-shot hardware approval',
        introTitle: 'WSL 2 Sandbox Overview (v0.3.0)',
        introBody: 'Confines agent file operations, builds, and shell execution inside a WSL 2 Linux namespace (bubblewrap + seccomp-bpf + UDS allowlist proxy), masks Windows drives (/mnt) and sensitive directories (~/.dsh / ~/.ssh), and enforces official Microsoft PowerShell AST guards plus physical hardware single-shot approvals.',
        apply: 'Apply',
        reset: 'Reset',
        kill: 'Emergency Kill',
        close: 'Close',
        tabs: {
          status: 'Status',
          approvals: 'Approvals',
          settings: 'Policy & Shares',
          doctor: 'WSL Doctor',
          logs: 'Logs',
          audit: 'Audit Log'
        },
        titles: {
          status: 'Sandbox Status',
          approvals: 'Approval Queue',
          settings: 'Basic Policy & Advanced Shares',
          doctor: 'Kernel & Toolchain Doctor',
          logs: 'Runtime Logs',
          audit: 'Audit Records'
        },
        bsTitle: 'Controlled AI Bootstrap Channel & Script Preview',
        bsPreviewBtn: 'Preview Installer Scripts & SHA-256',
        bsOpenBtn: 'Open Bootstrap Channel & Copy Session Prompt',
        bsCloseBtn: 'Close Bootstrap Channel'
      }
    };
    let bootstrapPreviewData = null;
    let activePreviewIdx = 0;
    function setUiLang(lang) {
      uiLang = lang === 'en' ? 'en' : 'zh';
      const d = UI_I18N[uiLang];
      const byId = (id) => document.getElementById(id);
      if (byId('brandTitle')) byId('brandTitle').textContent = d.brandTitle;
      if (byId('brandSub')) byId('brandSub').textContent = d.brandSub;
      if (byId('introTitle')) byId('introTitle').textContent = d.introTitle;
      if (byId('introBody')) byId('introBody').textContent = d.introBody;
      if (byId('btn-apply')) byId('btn-apply').textContent = d.apply;
      if (byId('btn-reset')) byId('btn-reset').textContent = d.reset;
      if (byId('btn-kill')) byId('btn-kill').textContent = d.kill;
      if (byId('btn-notice-close')) byId('btn-notice-close').textContent = d.close;
      if (byId('bsCardTitle')) byId('bsCardTitle').textContent = d.bsTitle;
      if (byId('bsBtnPreview')) byId('bsBtnPreview').textContent = d.bsPreviewBtn;
      if (byId('bsBtnOpen')) byId('bsBtnOpen').textContent = d.bsOpenBtn;
      if (byId('bsBtnClose')) byId('bsBtnClose').textContent = d.bsCloseBtn;
      for (const k of ['status', 'approvals', 'settings', 'doctor', 'logs', 'audit']) {
        const el = byId('tabLbl-' + k);
        if (el) el.textContent = d.tabs[k];
      }
      if (byId('pTitle')) byId('pTitle').textContent = d.titles[currentTab] || d.titles.status;
      if (byId('langBtn-zh')) {
        byId('langBtn-zh').className = 'dsh-wsl-sbx-btn ' + (uiLang === 'zh' ? 'dsh-wsl-sbx-btn-apply' : 'dsh-wsl-sbx-btn-sec');
      }
      if (byId('langBtn-en')) {
        byId('langBtn-en').className = 'dsh-wsl-sbx-btn ' + (uiLang === 'en' ? 'dsh-wsl-sbx-btn-apply' : 'dsh-wsl-sbx-btn-sec');
      }
    }
    function esc(s) {
      return String(s == null ? '' : s)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
    }
    function msg(t) {
      document.getElementById('noticeMsg').textContent = t;
      document.getElementById('notice').classList.add('is-visible');
    }
    function sbxTab(id, btn) {
      currentTab = id;
      const d = UI_I18N[uiLang] || UI_I18N.zh;
      const titleEl = document.getElementById('pTitle');
      if (titleEl) titleEl.textContent = d.titles[id] || d.titles.status;
      document.querySelectorAll('.dsh-wsl-sbx-pane').forEach(p => p.classList.toggle('is-active', p.id === 'pane-' + id));
      document.querySelectorAll('.dsh-wsl-sbx-tab').forEach(b => b.classList.toggle('is-active', b === btn));
      if (id === 'logs') loadLogs();
    }
    async function api(method, url, body) {
      const r = await fetch(url, { method, headers: H, body: body ? JSON.stringify(body) : undefined });
      const text = await r.text();
      let data;
      try {
        data = text ? JSON.parse(text) : {};
      } catch {
        data = { ok: false, error: { message: text || ('HTTP ' + r.status) } };
      }
      if (!r.ok && data && data.ok !== false) {
        return { ok: false, error: data.error || { message: 'HTTP ' + r.status } };
      }
      return data;
    }
    async function refreshDistros(notify) {
      const r = await api('GET', '/wsl-sandbox/api/distros');
      if (!r.ok) return;
      discoveredDistros = (r.distros || []).filter(d => !d.isInternalContainer);
      const sel = document.getElementById('in-distro-select');
      if (!sel) return;
      if (discoveredDistros.length === 0) {
        sel.innerHTML = '<option value="">未探测到 Windows WSL 实例（如在纯 Linux 开发模式请直接填写下方名称）</option>';
      } else {
        const cur = document.getElementById('in-distro').value.trim();
        sel.innerHTML = '<option value="">-- 选择已发现的 WSL 发行版 --</option>' + discoveredDistros.map(d => {
          const tags = ['WSL ' + d.wslVersion, d.state];
          if (d.isDefault) tags.push('默认');
          if (d.isCustomDiskLocation) tags.push('已迁移/WSL Manager: ' + d.basePath);
          const selected = d.name === cur ? ' selected' : '';
          return '<option value="' + esc(d.name) + '"' + selected + '>' + esc(d.name) + ' (' + esc(tags.join(' · ')) + ')</option>';
        }).join('');
      }
      if (notify) msg('已探测到 ' + discoveredDistros.length + ' 个 WSL 发行版。');
    }
    async function pickDiscoveredDistro() {
      const sel = document.getElementById('in-distro-select');
      const name = sel ? sel.value : '';
      if (!name) return;
      formDirty = true;
      document.getElementById('in-distro').value = name;
      const meta = discoveredDistros.find(d => d.name === name);
      const hint = document.getElementById('distroMetaHint');
      if (meta && hint) {
        hint.style.display = 'block';
        hint.textContent = meta.isCustomDiskLocation
          ? '检测到 WSL Manager / 自定义迁移磁盘路径: ' + meta.basePath + '（即便在 Windows 资源管理器左侧不可见，沙箱依然通过 wsl.exe 与原生 ext4 Runner 正常运行）'
          : (meta.basePath ? ('磁盘路径: ' + meta.basePath) : '');
      }
      const probed = await api('GET', '/wsl-sandbox/api/distros?probeDistro=' + encodeURIComponent(name));
      if (probed.ok && probed.probedUser) {
        if (probed.probedUser.uid === 0) {
          msg('警告: 发行版 ' + name + ' 默认用户为 root (UID 0)，沙箱将拒绝运行，请先配置非 root 用户。');
        } else {
          document.getElementById('in-user').value = probed.probedUser.username;
          document.getElementById('in-ws').value = probed.probedUser.homeDir + '/workspace';
          document.getElementById('in-runner').value = probed.probedUser.homeDir + '/.local/share/dsh-wsl-sandbox/runner/dist/packages/wsl-runner/src/main.js';
          msg('已自动探测 ' + name + ' 非 root 用户: ' + probed.probedUser.username + '（点击右上角「应用」保存）。');
        }
      }
    }
    async function refreshBackups() {
      const bkInput = document.getElementById('bk-dir');
      const customBk = (bkInput && bkInput.dataset.dirty === '1') ? bkInput.value.trim() : '';
      const bkQuery = customBk ? ('?backupDir=' + encodeURIComponent(customBk)) : '';
      const bk = await api('GET', '/wsl-sandbox/api/wsl-config/backups' + bkQuery);
      if (!bk || !bk.ok) return;
      if (bkInput && bkInput.dataset.dirty !== '1' && bk.backupDir) {
        bkInput.value = bk.backupDir;
      }
      const bkItems = bk.items || [];
      const bkBox = document.getElementById('backupItemsBox');
      if (bkBox) {
        bkBox.innerHTML = bkItems.length === 0
          ? '<span style="color:var(--text-muted);font-size:12px">当前备份目录下暂无快照，点击「立即备份到此目录」生成只读原始 .wslconfig 与 wsl.conf 备份。</span>'
          : bkItems.map((it) =>
              '<div style="display:flex;justify-content:space-between;align-items:center;gap:8px;padding:5px 0;border-bottom:1px solid var(--border-subtle)">' +
              '<div style="min-width:0"><b class="dsh-wsl-sbx-mono">' + esc(it.name) + '</b> <span class="dsh-wsl-sbx-mono" style="color:var(--text-secondary);font-size:11.5px">' + esc(it.explorerPath) + '</span></div>' +
              '<button class="dsh-wsl-sbx-btn dsh-wsl-sbx-btn-sec" data-exp="' + encodeURIComponent(it.explorerPath) + '" onclick="openBackupExplorer(decodeURIComponent(this.dataset.exp), true)">在资源管理器中定位</button>' +
              '</div>'
            ).join('');
      }
    }
    async function loadLogs() {
      const lvl = document.getElementById('log-lvl').value;
      const src = document.getElementById('log-src').value;
      const q = document.getElementById('log-q').value.trim();
      const qs = '?level=' + encodeURIComponent(lvl) + '&source=' + encodeURIComponent(src) + (q ? '&search=' + encodeURIComponent(q) : '') + '&limit=180';
      const r = await api('GET', '/wsl-sandbox/api/logs' + qs);
      if (!r.ok) return;
      const st = r.stats || {};
      document.getElementById('logStatsBar').textContent =
        '日志文件: ' + (st.logFilePath || '仅内存模式') +
        ' · 内存缓存: ' + (st.bufferedCount || 0) + ' 条' +
        ' · 累计合并落盘: ' + (st.diskFlushCount || 0) + ' 次 (2.5s 批处理防磨损)';
      const rows = (r.entries || []).slice().reverse();
      const colorOf = (l) => l === 'error' ? 'var(--danger)' : (l === 'warn' ? 'var(--warn)' : (l === 'info' ? '#60a5fa' : 'var(--text-muted)'));
      document.getElementById('logsTbl').innerHTML =
        '<thead><tr><th style="width:155px">时间</th><th style="width:68px">级别</th><th style="width:130px">来源 / 组件</th><th style="width:160px">事件</th><th>详情</th></tr></thead><tbody>' +
        (rows.length === 0
          ? '<tr><td colspan="5" style="color:var(--text-secondary);padding:14px">当前筛选条件下暂无运行日志。</td></tr>'
          : rows.map(e =>
              '<tr>' +
              '<td class="dsh-wsl-sbx-mono" style="color:var(--text-secondary);font-size:11.5px">' + esc(String(e.timestamp || '').replace('T', ' ').slice(0, 19)) + '</td>' +
              '<td class="dsh-wsl-sbx-mono" style="font-weight:600;color:' + colorOf(e.level) + '">' + esc(String(e.level || '').toUpperCase()) + '</td>' +
              '<td class="dsh-wsl-sbx-mono" style="font-size:11.5px">' + esc(e.source + ':' + e.component) + '</td>' +
              '<td class="dsh-wsl-sbx-mono" style="font-size:11.5px">' + esc(e.event) + (e.durationMs != null ? ' (' + e.durationMs + 'ms)' : '') + '</td>' +
              '<td style="word-break:break-word">' + esc(e.message) + (e.data ? ' <span class="dsh-wsl-sbx-mono" style="color:var(--text-muted);font-size:11.5px">' + esc(JSON.stringify(e.data)) + '</span>' : '') + '</td>' +
              '</tr>'
            ).join('')) +
        '</tbody>';
    }
    async function clearLogs() {
      await api('DELETE', '/wsl-sandbox/api/logs');
      msg('已清空内存与本地轮转日志。');
      loadLogs();
    }
    async function loadStatus(forceSync) {
      const [st, ap, au] = await Promise.all([
        api('GET', '/wsl-sandbox/api/status'),
        api('GET', '/wsl-sandbox/api/approvals'),
        api('GET', '/wsl-sandbox/api/audit')
      ]);
      if (!st.ok) return;
      if (forceSync) formDirty = false;
      const c = st.config;
      const nr = st.nodeRuntime || {};
      document.getElementById('telDistro').textContent = c.distro + (c.username ? ' · ' + c.username : '') + ' · ' + (c.environmentProfile || 'standard');
      document.getElementById('telWs').textContent = c.workspaceRoot;
      document.getElementById('telNode').textContent = 'Host ' + (nr.hostNodeVersion || '-') + (nr.wslNodeVersion ? (' / WSL ' + nr.wslNodeVersion) : ' (DSH 进程共用)');
      document.getElementById('telSync').textContent = formDirty ? '待点击应用' : (c.enabled ? '已生效' : '已停用');
      document.getElementById('tabCnt').textContent = '(' + (ap.pending || []).length + ')';
      document.getElementById('stPending').textContent = String((ap.pending || []).length);
      document.getElementById('stRules').textContent = String((ap.sessionRules || []).length);
      document.getElementById('stAdv').textContent = c.advanced.shares.length + ' / ' + c.advanced.deviceNodes.length;
      renderBootstrapStatus(st.bootstrap, c);

      const cmdPre = document.getElementById('wslConfCmdPre');
      if (cmdPre) {
        cmdPre.textContent =
          '# 在 WSL 内执行（只读备份原版 /etc/wsl.conf 后关闭自动挂载）：\\n' +
          'bash ~/.local/share/dsh-wsl-sandbox/runner/packages/bootstrap/provision-wsl.sh --disable-automount\\n' +
          '# 如需一键还原原厂 /etc/wsl.conf：\\n' +
          'bash ~/.local/share/dsh-wsl-sandbox/runner/packages/bootstrap/provision-wsl.sh --restore-configs\\n' +
          '# 在 Windows PowerShell 中仅重启当前发行版（切勿用 wsl --shutdown 以免关掉其他 WSL 会话）：\\n' +
          'wsl.exe --terminate ' + c.distro;
      }

      const bkInput = document.getElementById('bk-dir');
      if (bkInput && bkInput.dataset.dirty !== '1' && !bkInput.value) {
        bkInput.value = c.backupDir || '';
      }

      if (forceSync || !formDirty) {
        document.getElementById('in-enabled').checked = c.enabled;
        document.getElementById('in-pwsh').checked = c.enablePwshGuard;
        document.getElementById('in-prompt').checked = c.enablePromptInjection;
        document.getElementById('in-mirror').checked = c.mirrorCn;
        document.getElementById('in-transport').value = c.transportMode;
        document.getElementById('in-distro').value = c.distro;
        document.getElementById('in-profile').value = c.environmentProfile || 'standard';
        document.getElementById('in-user').value = c.username || '';
        document.getElementById('in-ws').value = c.workspaceRoot;
        document.getElementById('in-runner').value = c.runnerPath;
        document.getElementById('in-ttl').value = c.approvalTimeoutMs;
        document.getElementById('in-smode').value = c.sandboxMode;
        document.getElementById('in-amode').value = c.approvalPolicyMode;
        document.getElementById('in-nmode').value = c.networkMode;
        document.getElementById('in-proxy').value = c.upstreamProxy || '';
        document.getElementById('in-cmode').value = c.cacheMode;
        document.getElementById('in-loglevel').value = c.logLevel || 'info';
        document.getElementById('in-unmask').value = (c.unmaskedEnvWorkspaces || []).join(', ');
        document.getElementById('dev-list').value = c.advanced.deviceNodes.map(d => d.path).join(', ');
        document.getElementById('adv-cidrs').value = c.advanced.localLabCidrs.join(', ');
        document.getElementById('adv-ports').value = c.advanced.localLabPorts.join(', ');
        document.getElementById('adv-domains').value = c.advanced.customAllowedDomains.join(', ');
      }

      const shareRowsHtml = c.advanced.shares.map(s =>
        '<div style="display:flex;justify-content:space-between;align-items:center;padding:6px 0;border-bottom:1px solid var(--border-subtle)">' +
        '<span class="dsh-wsl-sbx-mono">/shares/' + esc(s.alias) + ' &lt;- ' + esc(s.sourceLinuxPath) + ' (' + esc(s.mode) + ')</span>' +
        '<button class="dsh-wsl-sbx-btn dsh-wsl-sbx-btn-out-danger" data-share-id="' + esc(s.id) + '" onclick="delShare(this.dataset.shareId)">取消挂载</button></div>'
      ).join('') || '<span style="color:var(--text-muted);font-size:12px">当前未挂载任何外部目录（所有 Windows 盘符对 AI 完全不可见）</span>';
      document.getElementById('sharesBox').innerHTML = shareRowsHtml;
      const qkBox = document.getElementById('quickSharesBox');
      if (qkBox) qkBox.innerHTML = shareRowsHtml;

      document.getElementById('pendingBox').innerHTML = (ap.pending || []).map(p =>
        '<div class="dsh-wsl-sbx-card" data-req-id="' + esc(p.requestId) + '">' +
        '<div style="display:flex;justify-content:space-between"><b>' + esc(p.summary) + '</b><span class="dsh-wsl-sbx-mono" style="color:var(--text-muted)">' + esc(p.requestId) + '</span></div>' +
        '<pre class="dsh-wsl-sbx-cmd">' + esc(p.command || '') + '</pre>' +
        '<div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:8px">' +
        '<button class="dsh-wsl-sbx-btn dsh-wsl-sbx-btn-apply" data-decision="allow-once" onclick="decideFromBtn(this)">允许一次</button>' +
        '<button class="dsh-wsl-sbx-btn dsh-wsl-sbx-btn-sec" ' + (p.touchesPhysicalDevice || !p.allowSessionRuleOption ? 'disabled' : '') + ' data-decision="allow-session-rule" onclick="decideFromBtn(this)">' + (p.touchesPhysicalDevice ? '硬件锁死单次' : '允许会话前缀') + '</button>' +
        '<button class="dsh-wsl-sbx-btn dsh-wsl-sbx-btn-out-danger" data-decision="deny" onclick="decideFromBtn(this)">拒绝</button>' +
        '<input class="dsh-wsl-sbx-input" style="max-width:220px" data-role="guidance" placeholder="输入修改意见..." />' +
        '<button class="dsh-wsl-sbx-btn dsh-wsl-sbx-btn-sec" data-decision="deny-with-guidance" onclick="decideFromBtn(this)">附意见打回</button>' +
        '</div></div>'
      ).join('') || '<div class="dsh-wsl-sbx-card" style="color:var(--text-secondary)">当前无待处理的审批请求。</div>';

      document.getElementById('rulesBox').textContent = (ap.sessionRules || []).map(r => '[' + r.join(' ') + ']').join('  ') || '暂无缓存前缀规则';
      document.getElementById('auditTbl').innerHTML = '<thead><tr><th>时间</th><th>类型</th><th>摘要</th><th>结果</th></tr></thead><tbody>' +
        (au.records || []).slice().reverse().map(r => '<tr><td class="dsh-wsl-sbx-mono">' + esc(r.timestamp) + '</td><td>' + esc(r.kind) + '</td><td>' + esc(r.summary) + '</td><td>' + esc(r.outcome) + '</td></tr>').join('') + '</tbody>';
    }
    async function saveBasic() {
      const r = await api('PUT', '/wsl-sandbox/api/config', {
        enabled: document.getElementById('in-enabled').checked,
        enablePwshGuard: document.getElementById('in-pwsh').checked,
        enablePromptInjection: document.getElementById('in-prompt').checked,
        mirrorCn: document.getElementById('in-mirror').checked,
        transportMode: document.getElementById('in-transport').value,
        distro: document.getElementById('in-distro').value.trim(),
        environmentProfile: document.getElementById('in-profile').value,
        username: document.getElementById('in-user').value.trim() || undefined,
        workspaceRoot: document.getElementById('in-ws').value.trim(),
        runnerPath: document.getElementById('in-runner').value.trim(),
        approvalTimeoutMs: Number(document.getElementById('in-ttl').value) || 60000,
        sandboxMode: document.getElementById('in-smode').value,
        approvalPolicyMode: document.getElementById('in-amode').value,
        networkMode: document.getElementById('in-nmode').value,
        upstreamProxy: document.getElementById('in-proxy').value.trim(),
        cacheMode: document.getElementById('in-cmode').value,
        logLevel: document.getElementById('in-loglevel').value,
        unmaskedEnvWorkspaces: document.getElementById('in-unmask').value.split(',').map(s => s.trim()).filter(Boolean)
      });
      msg(r.ok ? '基础配置已保存并生效。' : ('保存失败: ' + (r.error && r.error.message)));
      loadStatus(Boolean(r.ok));
    }
    function decideFromBtn(btn) {
      const card = btn && btn.closest ? btn.closest('[data-req-id]') : null;
      if (!card) return;
      const id = card.getAttribute('data-req-id') || '';
      const decision = btn.getAttribute('data-decision') || '';
      const g = card.querySelector('[data-role="guidance"]');
      return decide(id, decision, g ? g.value.trim() : undefined);
    }
    async function decide(id, decision, guidance) {
      await api('POST', '/wsl-sandbox/api/approvals/' + encodeURIComponent(id) + '/decide', {
        decision, guidance
      });
      loadStatus(false);
    }
    async function clearSessionRules() { await api('DELETE', '/wsl-sandbox/api/session-rules'); msg('已清空会话规则。'); loadStatus(); }
    async function emergencyKill() { await api('POST', '/wsl-sandbox/api/session/invalidate'); msg('已仅熔断当前 DSH 会话内的沙箱进程组（不影响其他会话或人工 WSL 终端）。'); loadStatus(); }
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
      msg(r.ok ? ('只读原始 WSL 配置快照已保存至: ' + r.backupDir) : ('备份失败: ' + (r.error && r.error.message)));
      await refreshBackups();
      loadStatus();
    }
    async function pickBackupDir() {
      const r = await api('POST', '/wsl-sandbox/api/wsl-config/pick-dir', {});
      if (r.ok && r.selectedDir) {
        const bkIn = document.getElementById('bk-dir');
        if (bkIn) { bkIn.value = r.selectedDir; bkIn.dataset.dirty = '0'; }
        msg('已选择备份目录: ' + r.selectedDir);
        await refreshBackups();
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
      if (!ev.target) return;
      if (ev.target.id === 'bk-dir') ev.target.dataset.dirty = '1';
      if (/^(?:in-|dev-list$|adv-)/.test(ev.target.id || '')) {
        formDirty = true;
        const syncEl = document.getElementById('telSync');
        if (syncEl) syncEl.textContent = '待点击应用';
      }
    });
    document.addEventListener('change', function (ev) {
      if (ev.target && /^(?:in-|dev-list$|adv-)/.test(ev.target.id || '')) {
        formDirty = true;
        const syncEl = document.getElementById('telSync');
        if (syncEl) syncEl.textContent = '待点击应用';
      }
    });
    function toggleWslConfCmd() {
      const el = document.getElementById('wslConfCmdBox');
      if (el) el.style.display = el.style.display === 'none' ? 'block' : 'none';
    }
    function renderBootstrapStatus(bs, cfg) {
      const pill = document.getElementById('bsPhasePill');
      const closeBtn = document.getElementById('bsBtnClose');
      const timerHint = document.getElementById('bsTimerHint');
      const distroIn = document.getElementById('bs-target-distro');
      if (distroIn && !distroIn.dataset.dirty && !distroIn.value && cfg && cfg.distro) {
        distroIn.value = cfg.distro;
      }
      if (!pill) return;
      if (!bs || !bs.active) {
        pill.textContent = '已锁定关闭（常态 L0 禁用 AI 自主运行安装脚本）';
        pill.style.color = 'var(--text-secondary)';
        if (closeBtn) closeBtn.style.display = 'none';
        if (timerHint) timerHint.textContent = '';
        return;
      }
      const phaseNames = {
        '1-probe': '步骤 1/4: 探测就绪 · 等待 -DryRun 预览',
        '2-previewed': '步骤 2/4: 已预览 -DryRun · 可申请单次安装审批',
        '3-installing': '步骤 3/4: 受控单次安装确认'
      };
      pill.textContent = (phaseNames[bs.phase] || bs.phase) + (bs.targetDistro ? (' [' + bs.targetDistro + ']') : '');
      pill.style.color = 'var(--ok)';
      if (closeBtn) closeBtn.style.display = 'inline-block';
      if (timerHint) {
        const mins = Math.max(0, Math.ceil((bs.remainingMs || 0) / 60000));
        timerHint.textContent = '限时通道剩余 ' + mins + ' 分钟（首次绑定就绪后自动关闭）';
      }
    }
    function selectPreviewScript(idx) {
      activePreviewIdx = idx;
      if (!bootstrapPreviewData || !bootstrapPreviewData.scripts) return;
      const list = bootstrapPreviewData.scripts;
      const tabs = document.getElementById('bsScriptTabs');
      const meta = document.getElementById('bsScriptMeta');
      const code = document.getElementById('bsScriptCode');
      const cur = list[idx] || list[0];
      if (tabs) {
        tabs.innerHTML = list.map((s, i) =>
          '<button class="dsh-wsl-sbx-btn ' + (i === idx ? 'dsh-wsl-sbx-btn-apply' : 'dsh-wsl-sbx-btn-sec') + '" onclick="selectPreviewScript(' + i + ')">' + esc(s.relPath) + '</button>'
        ).join('');
      }
      if (cur && meta && code) {
        meta.textContent = cur.title + ' · SHA-256: ' + (cur.sha256 || 'N/A') + ' · ' + cur.lines + ' 行 (' + cur.bytes + ' 字节) · 路径: ' + cur.fullPath;
        code.textContent = cur.content || '';
      }
    }
    async function loadBootstrapPreview(showNotice) {
      const d = (document.getElementById('bs-target-distro').value || '').trim();
      const qs = d ? ('?distro=' + encodeURIComponent(d)) : '';
      const r = await api('GET', '/wsl-sandbox/api/bootstrap-preview' + qs);
      if (!r.ok) { msg('加载脚本预览失败'); return; }
      bootstrapPreviewData = r;
      const wrap = document.getElementById('bsPreviewWrap');
      if (wrap) wrap.style.display = 'block';
      selectPreviewScript(activePreviewIdx);
      const pbox = document.getElementById('bsPromptBox');
      if (pbox) pbox.textContent = r.recommendedSessionPrompt || '';
      if (showNotice) msg('已加载安装脚本源码与 SHA-256 摘要（零宿主进程执行）。');
    }
    async function toggleBootstrapChannel(open) {
      const targetDistro = (document.getElementById('bs-target-distro').value || '').trim() || undefined;
      const r = await api('POST', '/wsl-sandbox/api/bootstrap-session', {
        action: open ? 'open' : 'close',
        targetDistro
      });
      if (!r.ok) {
        msg('操作失败: ' + (r.error && r.error.message));
        return;
      }
      if (open) {
        await loadBootstrapPreview(false);
        const promptText = (bootstrapPreviewData && bootstrapPreviewData.recommendedSessionPrompt) || '';
        if (promptText && navigator.clipboard && navigator.clipboard.writeText) {
          try { await navigator.clipboard.writeText(promptText); } catch {}
        }
        msg('已开启 20 分钟受控引导通道并复制初始化会话指令（仍强制先 -DryRun 预览 + 单次审批）。');
      } else {
        msg('已关闭受控 AI 初始化引导通道。');
      }
      loadStatus(false);
    }
    async function delShare(id) { await api('DELETE', '/wsl-sandbox/api/advanced/shares/' + encodeURIComponent(id)); msg('已取消挂载并仅终止当前会话的旧沙箱进程。'); loadStatus(false); }
    async function saveDevices() {
      const nodes = document.getElementById('dev-list').value.split(',').map(s => s.trim()).filter(Boolean).map(p => ({ path: p }));
      const r = await api('PUT', '/wsl-sandbox/api/advanced/devices', { deviceNodes: nodes });
      msg(r.ok ? '已更新物理设备白名单。' : ('拦截: ' + (r.error && r.error.message)));
      loadStatus(Boolean(r.ok));
    }
    async function saveAdvNet() {
      const r = await api('PUT', '/wsl-sandbox/api/advanced/network', {
        localLabCidrs: document.getElementById('adv-cidrs').value.split(',').map(s => s.trim()).filter(Boolean),
        localLabPorts: document.getElementById('adv-ports').value.split(',').map(s => Number(s.trim())).filter(Boolean),
        customAllowedDomains: document.getElementById('adv-domains').value.split(',').map(s => s.trim()).filter(Boolean)
      });
      msg(r.ok ? '已更新高级网络白名单。' : ('拦截: ' + (r.error && r.error.message)));
      loadStatus(Boolean(r.ok));
    }
    async function loadFootprint() {
      const box = document.getElementById('footprintBox');
      box.style.display = 'block';
      box.textContent = '正在扫描宿主机与 WSL 2 落盘足迹...';
      const r = await api('GET', '/wsl-sandbox/api/footprint');
      box.textContent = r.ok ? JSON.stringify({ host: r.host, wsl: r.wsl, uninstallCommands: r.uninstallCommands }, null, 2) : ('读取失败: ' + (r.error && r.error.message));
    }
    async function purgeSandboxCache() {
      const r = await api('POST', '/wsl-sandbox/api/cache/purge', {});
      msg(r.ok ? ('已清理沙箱缓存目录 (' + (r.clearedEntries || 0) + ' 项) 与孤儿临时目录 (' + ((r.sweptTempDirs && r.sweptTempDirs.length) || 0) + ' 项)。') : ('清理失败: ' + (r.error && r.error.message)));
    }
    async function removeAgentsMdBlock() {
      const r = await api('DELETE', '/wsl-sandbox/api/agents-md', {});
      msg(r.ok ? ('AGENTS.md 处理结果: ' + r.action + ' (' + r.filePath + ')') : ('移除失败: ' + (r.error && r.error.message)));
    }
    async function reopenOobeHint() {
      const r = await api('POST', '/wsl-sandbox/api/oobe', { action: 'reopen' });
      msg(r.ok
        ? '已重置 OOBE 首次安装向导标志：切回 DeepSeek Harness 主界面即会自动弹出交互式三步安装向导（也可直接在下方「受控 AI 初始化引导」卡片开启通道）。'
        : ('操作失败: ' + (r.error && r.error.message)));
    }
    async function exportLogsNdjson() {
      const res = await fetch('/wsl-sandbox/api/logs/export', { headers: { 'X-DSH-WSL-Client': '1' } });
      if (!res.ok) { msg('导出日志失败: HTTP ' + res.status); return; }
      const text = await res.text();
      const blob = new Blob([text], { type: 'application/x-ndjson;charset=utf-8' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'dsh-wsl-sandbox-logs.ndjson';
      document.body.appendChild(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    }
    async function runDoc() {
      document.getElementById('docBox').textContent = '正在执行内核隔离与当前档位工具链自检...';
      const r = await api('GET', '/wsl-sandbox/api/doctor');
      if (!r.ok || !r.report) { document.getElementById('docBox').textContent = '自检失败'; return; }
      const d = r.report;
      document.getElementById('docBox').innerHTML =
        '<div><b>总体结论: ' + esc(d.verdict.toUpperCase()) + '</b> · 档位 <span class="dsh-wsl-sbx-mono">' + esc(d.selectedProfile || 'standard') + '</span> · 发行版 ' + esc(d.os.distroPrettyName || d.os.platform) +
        ' · 内核 ' + esc(d.os.kernel) + ' · bwrap ' + esc(d.sandbox.bwrapVersion || '缺失') +
        ' · io_uring=' + d.sandbox.seccompIoUringBlocked + ' · AF_VSOCK=' + d.sandbox.seccompAfVsockBlocked + '</div>' +
        '<table class="dsh-wsl-sbx-table" style="margin-top:10px"><thead><tr><th>工具</th><th>档位</th><th>版本</th><th>状态</th></tr></thead><tbody>' +
        d.tools.map(t => '<tr><td class="dsh-wsl-sbx-mono">' + esc(t.name) + '</td><td>' + esc(t.tier) + '</td><td class="dsh-wsl-sbx-mono">' + esc(t.version || '-') + '</td><td>' + (t.present ? '就绪' : '未安装') + '</td></tr>').join('') +
        '</tbody></table>';
    }
    loadStatus(true).then(() => { refreshBackups(); refreshDistros(false); });
    setInterval(function () {
      if (document.hidden) return;
      loadStatus(false);
      if (currentTab === 'logs') loadLogs();
    }, 5000);
  </script>
</body>
</html>`;
}
