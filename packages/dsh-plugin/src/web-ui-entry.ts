/**
 * Self-contained HTML/CSS/JS control panel served at `/wsl-sandbox/ui`.
 *
 * Coexistence & UI invariants:
 * - All CSS classes prefixed `.dsh-wsl-sbx-*`, `z-index <= 850` (never overlaps DSH modals at 1000 or dsh-purge buttons at 900/950).
 * - Basic panel completely HIDES Windows `/mnt` full-drive mounting (Q8); notes Windows Explorer Linux sidebar for drag/copy.
 * - Advanced panel is collapsed (`<details>`) by default and holds single-directory `/shares/<alias>` (`ro` default + instant revoke),
 *   single-device passthrough nodes (Q13), and local lab CIDRs/ports (Q16).
 * - Live approval queue supports 4 actions (`allow-once`, `allow-session-rule`, `deny`, `deny-with-guidance`) and disables
 *   `allow-session-rule` automatically whenever `touchesPhysicalDevice` is true or prefix is banned.
 */

import type { DshCordisContext } from './cordis-types.ts';

export const name = 'dsh-wsl-sandbox-web-ui';
export const inject = { optional: ['http', 'logger'] } as const;

export interface WebUiPluginConfig {
  readonly routePrefix?: string;
  readonly zIndexCap?: number;
}

export function apply(ctx: DshCordisContext, config: WebUiPluginConfig = {}): void {
  if (!ctx.http) return;
  const uiPath = config.routePrefix ? config.routePrefix.replace(/\/api\/?$/, '/ui') : '/wsl-sandbox/ui';
  const dispose = ctx.http.route('GET', uiPath, (_req, res) => {
    res.status(200).html(renderWslSandboxUiHtml());
  });
  if (typeof dispose === 'function') {
    ctx.effect?.(dispose);
  }
  ctx.logger?.info(`[dsh-wsl-sandbox-web-ui] UI mounted at ${uiPath} (z-index cap ${config.zIndexCap ?? 850})`);
}

export function renderWslSandboxUiHtml(): string {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>DSH WSL 2 Sandbox Console</title>
  <style>
    :root {
      --bg: #0f1419;
      --panel: #171e26;
      --border: #2a3441;
      --text: #e6edf3;
      --muted: #8b949e;
      --accent: #3b82f6;
      --ok: #22c55e;
      --warn: #f59e0b;
      --danger: #ef4444;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.5;
    }
    .dsh-wsl-sbx-root {
      max-width: 980px;
      margin: 0 auto;
      padding: 20px;
      position: relative;
      z-index: 800;
    }
    .dsh-wsl-sbx-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      border-bottom: 1px solid var(--border);
      padding-bottom: 12px;
      margin-bottom: 18px;
    }
    .dsh-wsl-sbx-badge {
      display: inline-block;
      padding: 2px 10px;
      border-radius: 999px;
      font-size: 12px;
      background: #1e293b;
      border: 1px solid var(--border);
    }
    .dsh-wsl-sbx-badge-ok { border-color: var(--ok); color: var(--ok); }
    .dsh-wsl-sbx-badge-warn { border-color: var(--warn); color: var(--warn); }
    .dsh-wsl-sbx-card {
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 16px;
      margin-bottom: 16px;
    }
    .dsh-wsl-sbx-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 12px;
    }
    .dsh-wsl-sbx-field label {
      display: block;
      font-size: 12px;
      color: var(--muted);
      margin-bottom: 4px;
    }
    .dsh-wsl-sbx-field input,
    .dsh-wsl-sbx-field select {
      width: 100%;
      padding: 8px 10px;
      border-radius: 6px;
      border: 1px solid var(--border);
      background: #0d1117;
      color: var(--text);
      font-size: 13px;
    }
    .dsh-wsl-sbx-btn {
      padding: 7px 13px;
      border-radius: 6px;
      border: 1px solid var(--border);
      background: #21262d;
      color: var(--text);
      cursor: pointer;
      font-size: 13px;
    }
    .dsh-wsl-sbx-btn-primary { background: var(--accent); border-color: var(--accent); }
    .dsh-wsl-sbx-btn-danger { background: #7f1d1d; border-color: var(--danger); }
    .dsh-wsl-sbx-btn:disabled { opacity: 0.45; cursor: not-allowed; }
    .dsh-wsl-sbx-note {
      font-size: 12px;
      color: var(--muted);
      margin-top: 8px;
    }
    .dsh-wsl-sbx-approval {
      border: 1px solid var(--warn);
      border-radius: 8px;
      padding: 12px;
      margin-bottom: 10px;
      background: #1c1917;
    }
    .dsh-wsl-sbx-code {
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
      background: #0d1117;
      padding: 8px;
      border-radius: 6px;
      overflow-x: auto;
      font-size: 12px;
      margin: 8px 0;
    }
    .dsh-wsl-sbx-actions {
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
      margin-top: 8px;
    }
    details.dsh-wsl-sbx-advanced summary {
      cursor: pointer;
      font-weight: 600;
      color: var(--warn);
      list-style: none;
    }
    .dsh-wsl-sbx-list {
      margin: 10px 0 0;
      padding: 0;
      list-style: none;
    }
    .dsh-wsl-sbx-list li {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 6px 8px;
      border-bottom: 1px solid var(--border);
      font-size: 13px;
    }
  </style>
</head>
<body>
  <div class="dsh-wsl-sbx-root">
    <div class="dsh-wsl-sbx-header">
      <div>
        <h2 style="margin:0;">DSH WSL 2 Sandbox</h2>
        <div class="dsh-wsl-sbx-note">Zero-Token Command Approval · bwrap + seccomp-bpf + UDS Allowlist Proxy · Coexists with dsh-purge</div>
      </div>
      <span id="statusBadge" class="dsh-wsl-sbx-badge">Loading...</span>
    </div>

    <div class="dsh-wsl-sbx-card">
      <h3 style="margin-top:0;">Pending Approvals</h3>
      <div id="approvalsList" class="dsh-wsl-sbx-note">No pending approval requests.</div>
    </div>

    <div class="dsh-wsl-sbx-card">
      <h3 style="margin-top:0;">Basic Sandbox Settings</h3>
      <div class="dsh-wsl-sbx-grid">
        <div class="dsh-wsl-sbx-field">
          <label>WSL 2 Distro</label>
          <input id="distro" type="text" placeholder="Ubuntu-24.04" />
        </div>
        <div class="dsh-wsl-sbx-field">
          <label>Workspace Root (Linux ext4)</label>
          <input id="workspaceRoot" type="text" placeholder="/home/dev/workspace" />
        </div>
        <div class="dsh-wsl-sbx-field">
          <label>Sandbox Mode</label>
          <select id="sandboxMode">
            <option value="workspace-write">workspace-write (default)</option>
            <option value="read-only">read-only</option>
          </select>
        </div>
        <div class="dsh-wsl-sbx-field">
          <label>Approval Policy (dsh-purge coexistence)</label>
          <select id="approvalPolicyMode">
            <option value="balanced">balanced (default — L3 fallback protected)</option>
            <option value="strict">strict (always independent queue)</option>
            <option value="trust-workspace">trust-workspace (in-workspace fast path)</option>
          </select>
        </div>
        <div class="dsh-wsl-sbx-field">
          <label>Network Mode (--unshare-net always ON)</label>
          <select id="networkMode">
            <option value="allowlist-proxy">allowlist-proxy (dev registries + UDS)</option>
            <option value="offline">offline (100% air-gapped)</option>
          </select>
        </div>
        <div class="dsh-wsl-sbx-field">
          <label>Upstream Proxy (Clash/Mihomo/v2rayN)</label>
          <input id="upstreamProxy" type="text" placeholder="http://127.0.0.1:7890 or socks5://..." />
        </div>
        <div class="dsh-wsl-sbx-field">
          <label>Package Cache Mode</label>
          <select id="cacheMode">
            <option value="workspace-persistent">workspace-persistent</option>
            <option value="ephemeral-tmp">ephemeral-tmp</option>
          </select>
        </div>
        <div class="dsh-wsl-sbx-field">
          <label>China Mirrors (TUNA / npmmirror / goproxy.cn)</label>
          <select id="mirrorCn">
            <option value="false">Off</option>
            <option value="true">On (--mirror cn)</option>
          </select>
        </div>
      </div>
      <div class="dsh-wsl-sbx-actions" style="margin-top:14px;">
        <button class="dsh-wsl-sbx-btn dsh-wsl-sbx-btn-primary" onclick="saveBasic()">Save Basic Config</button>
        <button class="dsh-wsl-sbx-btn" onclick="injectAgentsMd()">Upsert AGENTS.md WSL-First Block</button>
      </div>
      <div class="dsh-wsl-sbx-note">
        Windows /mnt full-drive mounting is hidden &amp; disabled by default. To copy files between Windows and WSL, use the <strong>Windows Explorer &rarr; Linux</strong> sidebar, or authorize a single directory temporarily under <strong>Advanced</strong> below.
      </div>
    </div>

    <div class="dsh-wsl-sbx-card">
      <details class="dsh-wsl-sbx-advanced">
        <summary>&#9888; Advanced Controls (Collapsed by Default — Single-Dir Shares, Physical Devices, Local Lab Network)</summary>
        <div style="margin-top:14px;">
          <h4 style="margin:6px 0;">1. Per-Use Single-Directory Share (/shares/&lt;alias&gt;, default read-only)</h4>
          <div class="dsh-wsl-sbx-grid">
            <div class="dsh-wsl-sbx-field"><label>Alias</label><input id="shareAlias" placeholder="firmware-assets" /></div>
            <div class="dsh-wsl-sbx-field"><label>Linux Source Path</label><input id="sharePath" placeholder="/home/dev/shared-dir" /></div>
            <div class="dsh-wsl-sbx-field">
              <label>Mode</label>
              <select id="shareMode"><option value="ro">ro (recommended)</option><option value="rw">rw</option></select>
            </div>
          </div>
          <div class="dsh-wsl-sbx-actions"><button class="dsh-wsl-sbx-btn" onclick="addShare()">Add Share</button></div>
          <ul id="sharesList" class="dsh-wsl-sbx-list"></ul>

          <h4 style="margin:16px 0 6px;">2. Physical Device Nodes (ESP32 / USBIP — Auto-Downgrades to Manual Allow-Once)</h4>
          <div class="dsh-wsl-sbx-field">
            <label>Comma-separated device paths (e.g. /dev/ttyUSB0, /dev/ttyACM0)</label>
            <input id="deviceNodes" placeholder="/dev/ttyUSB0" />
          </div>
          <div class="dsh-wsl-sbx-actions"><button class="dsh-wsl-sbx-btn" onclick="saveDevices()">Update Devices</button></div>

          <h4 style="margin:16px 0 6px;">3. Local Lab Network Allowlist &amp; Custom Domains (SSRF-Safe)</h4>
          <div class="dsh-wsl-sbx-grid">
            <div class="dsh-wsl-sbx-field"><label>Local Lab CIDRs</label><input id="localLabCidrs" placeholder="192.168.56.0/24" /></div>
            <div class="dsh-wsl-sbx-field"><label>Local Lab Ports</label><input id="localLabPorts" placeholder="3000, 8080" /></div>
            <div class="dsh-wsl-sbx-field"><label>Custom Allowed Domains</label><input id="customDomains" placeholder="example.org" /></div>
          </div>
          <div class="dsh-wsl-sbx-actions"><button class="dsh-wsl-sbx-btn" onclick="saveAdvancedNet()">Update Network Policy</button></div>
        </div>
      </details>
    </div>
  </div>

  <script>
    async function api(path, opts) {
      const r = await fetch('/wsl-sandbox/api' + path, Object.assign({ headers: { 'Content-Type': 'application/json' } }, opts));
      return r.json();
    }
    async function refresh() {
      const [status, cfg, approvals] = await Promise.all([api('/status'), api('/config'), api('/approvals')]);
      const badge = document.getElementById('statusBadge');
      badge.textContent = status.bound ? ('Bound: ' + status.binding.distribution + ' (' + status.config.revision + ')') : ('Standby (' + status.config.revision + ')');
      badge.className = 'dsh-wsl-sbx-badge ' + (status.bound ? 'dsh-wsl-sbx-badge-ok' : 'dsh-wsl-sbx-badge-warn');
      document.getElementById('distro').value = cfg.distro || '';
      document.getElementById('workspaceRoot').value = cfg.workspaceRoot || '';
      document.getElementById('sandboxMode').value = cfg.sandboxMode || 'workspace-write';
      document.getElementById('approvalPolicyMode').value = cfg.approvalPolicyMode || 'balanced';
      document.getElementById('networkMode').value = cfg.networkMode || 'allowlist-proxy';
      document.getElementById('upstreamProxy').value = cfg.upstreamProxy || '';
      document.getElementById('cacheMode').value = cfg.cacheMode || 'workspace-persistent';
      document.getElementById('mirrorCn').value = String(Boolean(cfg.mirrorCn));
      document.getElementById('deviceNodes').value = (cfg.advanced.deviceNodes || []).map(d => d.path).join(', ');
      document.getElementById('localLabCidrs').value = (cfg.advanced.localLabCidrs || []).join(', ');
      document.getElementById('localLabPorts').value = (cfg.advanced.localLabPorts || []).join(', ');
      document.getElementById('customDomains').value = (cfg.advanced.customAllowedDomains || []).join(', ');

      const sharesList = document.getElementById('sharesList');
      sharesList.innerHTML = (cfg.advanced.shares || []).map(s =>
        '<li><span><code>/shares/' + s.alias + '</code> &larr; ' + s.sourceLinuxPath + ' (' + s.mode + ')</span>' +
        '<button class="dsh-wsl-sbx-btn dsh-wsl-sbx-btn-danger" onclick="revokeShare(\\'' + s.id + '\\')">Revoke &amp; Kill</button></li>'
      ).join('') || '<li class="dsh-wsl-sbx-note">No active directory shares.</li>';

      const appEl = document.getElementById('approvalsList');
      if (!approvals.pending || approvals.pending.length === 0) {
        appEl.innerHTML = 'No pending approval requests.';
      } else {
        appEl.innerHTML = approvals.pending.map(p =>
          '<div class="dsh-wsl-sbx-approval">' +
          '<div><strong>' + p.summary + '</strong>' + (p.touchesPhysicalDevice ? ' <span class="dsh-wsl-sbx-badge dsh-wsl-sbx-badge-warn">Physical Device: Allow-Once Only</span>' : '') + '</div>' +
          (p.command ? '<div class="dsh-wsl-sbx-code">' + p.command.replace(/</g, '&lt;') + '</div>' : '') +
          '<div class="dsh-wsl-sbx-note">' + (p.reasons || []).join(' | ') + '</div>' +
          '<div class="dsh-wsl-sbx-actions">' +
          '<button class="dsh-wsl-sbx-btn dsh-wsl-sbx-btn-primary" onclick="decide(\\'' + p.requestId + '\\', \\'allow-once\\')">Allow Once</button>' +
          '<button class="dsh-wsl-sbx-btn" ' + (!p.allowSessionRuleOption ? 'disabled' : '') + ' onclick="decide(\\'' + p.requestId + '\\', \\'allow-session-rule\\')">Allow Prefix (Session)</button>' +
          '<button class="dsh-wsl-sbx-btn dsh-wsl-sbx-btn-danger" onclick="decide(\\'' + p.requestId + '\\', \\'deny\\')">Deny</button>' +
          '</div></div>'
        ).join('');
      }
    }
    async function saveBasic() {
      await api('/config', { method: 'PUT', body: JSON.stringify({
        distro: document.getElementById('distro').value,
        workspaceRoot: document.getElementById('workspaceRoot').value,
        sandboxMode: document.getElementById('sandboxMode').value,
        approvalPolicyMode: document.getElementById('approvalPolicyMode').value,
        networkMode: document.getElementById('networkMode').value,
        upstreamProxy: document.getElementById('upstreamProxy').value,
        cacheMode: document.getElementById('cacheMode').value,
        mirrorCn: document.getElementById('mirrorCn').value === 'true',
      })});
      await refresh();
    }
    async function addShare() {
      const alias = document.getElementById('shareAlias').value.trim();
      const sourceLinuxPath = document.getElementById('sharePath').value.trim();
      const mode = document.getElementById('shareMode').value;
      if (!alias || !sourceLinuxPath) return;
      await api('/advanced/shares', { method: 'POST', body: JSON.stringify({ id: 'share-' + alias, alias, sourceLinuxPath, mode }) });
      await refresh();
    }
    async function revokeShare(id) {
      await api('/advanced/shares/' + encodeURIComponent(id), { method: 'DELETE' });
      await refresh();
    }
    async function saveDevices() {
      const nodes = document.getElementById('deviceNodes').value.split(',').map(s => s.trim()).filter(Boolean).map(path => ({ path }));
      await api('/advanced/devices', { method: 'PUT', body: JSON.stringify({ deviceNodes: nodes }) });
      await refresh();
    }
    async function saveAdvancedNet() {
      const localLabCidrs = document.getElementById('localLabCidrs').value.split(',').map(s => s.trim()).filter(Boolean);
      const localLabPorts = document.getElementById('localLabPorts').value.split(',').map(s => Number(s.trim())).filter(n => Number.isInteger(n) && n > 0);
      const customAllowedDomains = document.getElementById('customDomains').value.split(',').map(s => s.trim()).filter(Boolean);
      await api('/advanced/network', { method: 'PUT', body: JSON.stringify({ localLabCidrs, localLabPorts, customAllowedDomains }) });
      await refresh();
    }
    async function decide(id, decision) {
      await api('/approvals/' + encodeURIComponent(id) + '/decide', { method: 'POST', body: JSON.stringify({ decision }) });
      await refresh();
    }
    async function injectAgentsMd() {
      await api('/agents-md', { method: 'POST', body: JSON.stringify({}) });
      alert('AGENTS.md updated with WSL-first routing section.');
    }
    refresh();
    setInterval(refresh, 3000);
  </script>
</body>
</html>`;
}
