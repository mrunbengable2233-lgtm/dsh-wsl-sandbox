window.__ModuleLoader__.load({ id: "dsh-wsl-sandbox", factory: (require) => {
  var module = { exports: {} };
  var exports = module.exports;
  Object.defineProperty(exports, Symbol.toStringTag, { value: "Module" });

  var React = require("react");
  var h = React.createElement;
  var useState = React.useState;
  var useEffect = React.useEffect;
  var useCallback = React.useCallback;

  var NS = "settings.wsl-sandbox";
  var STYLE_ATTR = "data-dsh-wsl-sandbox-style";

  var zh = {
    navTitle: "WSL 2 沙箱",
    panelTitle: "沙箱状态",
    apply: "应用",
    reset: "还原",
    kill: "熔断强杀",
    openStandalone: "打开独立控制台",
    tabStatus: "状态",
    tabApprovals: "审批队列",
    tabBasic: "基础策略",
    tabAdvanced: "共享与硬件",
    tabDoctor: "内核体检",
    tabAudit: "审计明细",
    offlineHint: "当前宿主未挂载 HTTP 控制面（如纯离线 Desktop 模式），配置存储于 ~/.dsh/dsh-wsl-sandbox/config.json。"
  };

  var en = {
    navTitle: "WSL 2 Sandbox",
    panelTitle: "Sandbox Status",
    apply: "Apply",
    reset: "Reset",
    kill: "Emergency Kill",
    openStandalone: "Open Full Console",
    tabStatus: "Status",
    tabApprovals: "Approvals",
    tabBasic: "Basic Policy",
    tabAdvanced: "Shares & Hardware",
    tabDoctor: "WSL Doctor",
    tabAudit: "Audit Log",
    offlineHint: "HTTP control surface not mounted on this host; config is persisted at ~/.dsh/dsh-wsl-sandbox/config.json."
  };

  var CSS_TEXT = [
    ".dsh-wsl-native { color: var(--dsw-alias-label-primary, #f2f3f5); font-size: 13px; line-height: 1.5; max-width: 920px; position: relative; z-index: 1; }",
    ".dsh-wsl-native * { box-sizing: border-box; }",
    ".dsh-wsl-native-mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-variant-numeric: tabular-nums; }",
    ".dsh-wsl-native-tabs { display: flex; gap: 20px; border-bottom: 1px solid rgba(255,255,255,0.08); margin-bottom: 12px; }",
    ".dsh-wsl-native-tab { position: relative; background: none; border: 0; color: #9498a3; padding: 8px 0 10px; font: 500 13px/1 inherit; cursor: pointer; }",
    ".dsh-wsl-native-tab.is-on { color: #f2f3f5; font-weight: 600; }",
    ".dsh-wsl-native-tab.is-on::after { content: ''; position: absolute; left: 0; right: 0; bottom: -1px; height: 2px; background: #f2f3f5; }",
    ".dsh-wsl-native-tel { display: flex; flex-wrap: wrap; gap: 16px; padding-bottom: 10px; margin-bottom: 14px; border-bottom: 1px solid rgba(255,255,255,0.07); font-size: 12px; color: #9498a3; }",
    ".dsh-wsl-native-tel b { color: #f2f3f5; font-weight: 600; }",
    ".dsh-wsl-native-panel { background: #16171a; border: 1px solid rgba(255,255,255,0.07); border-radius: 14px; padding: 18px 20px; }",
    ".dsh-wsl-native-head { display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between; gap: 10px; margin-bottom: 14px; }",
    ".dsh-wsl-native-btn { border-radius: 8px; padding: 6px 14px; font: 500 12.5px/1.2 inherit; cursor: pointer; border: 1px solid rgba(255,255,255,0.12); background: #1c1d21; color: #f2f3f5; }",
    ".dsh-wsl-native-btn:disabled { opacity: 0.38; cursor: not-allowed; }",
    ".dsh-wsl-native-btn-pri { background: #f4f5f7; color: #111214; border-color: transparent; font-weight: 600; }",
    ".dsh-wsl-native-btn-out-red { background: transparent; border-color: rgba(224,108,101,0.4); color: #e06c65; }",
    ".dsh-wsl-native-btn-red { background: #8c2d2b; border-color: transparent; color: #fbeae9; }",
    ".dsh-wsl-native-card { background: #1c1d21; border: 1px solid rgba(255,255,255,0.065); border-radius: 11px; padding: 14px 16px; margin-bottom: 12px; position: relative; }",
    ".dsh-wsl-native-card.accent::before { content: ''; position: absolute; left: 0; top: 10px; bottom: 10px; width: 2.5px; border-radius: 2px; background: #f2f3f5; }",
    ".dsh-wsl-native-grid2 { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 10px; }",
    ".dsh-wsl-native-stats { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 8px; margin-top: 12px; }",
    ".dsh-wsl-native-stat { border: 1px solid rgba(255,255,255,0.07); border-radius: 8px; padding: 10px 12px; }",
    ".dsh-wsl-native-in { width: 100%; background: #121316; color: #f2f3f5; border: 1px solid rgba(255,255,255,0.12); border-radius: 7px; padding: 7px 10px; font-size: 12.5px; outline: none; }"
  ].join("\n");

  function SectionIcon(props) {
    var sz = (props && props.size) || 16;
    return h(
      "svg",
      {
        width: sz,
        height: sz,
        viewBox: "0 0 24 24",
        fill: "none",
        stroke: "currentColor",
        strokeWidth: 1.9,
        strokeLinecap: "round",
        strokeLinejoin: "round"
      },
      h("rect", { x: 3, y: 4, width: 18, height: 16, rx: 3 }),
      h("polyline", { points: "8 10 11 13 8 16" }),
      h("line", { x1: 13, y1: 16, x2: 17, y2: 16 })
    );
  }

  function apiFetch(method, path, body) {
    return fetch(path, {
      method: method,
      headers: {
        "Content-Type": "application/json",
        "X-DSH-WSL-Client": "1"
      },
      body: body !== undefined ? JSON.stringify(body) : undefined
    }).then(function (r) {
      return r.json();
    });
  }

  function WslSandboxSection() {
    var _tab = useState("status"), tab = _tab[0], setTab = _tab[1];
    var _cfg = useState(null), cfg = _cfg[0], setCfg = _cfg[1];
    var _pending = useState([]), pending = _pending[0], setPending = _pending[1];
    var _rules = useState([]), rules = _rules[0], setRules = _rules[1];
    var _audit = useState([]), audit = _audit[0], setAudit = _audit[1];
    var _doc = useState(null), doc = _doc[0], setDoc = _doc[1];
    var _notice = useState(""), notice = _notice[0], setNotice = _notice[1];
    var _unavail = useState(false), unavail = _unavail[0], setUnavail = _unavail[1];
    var _qPath = useState(""), qPath = _qPath[0], setQPath = _qPath[1];
    var _qAlias = useState(""), qAlias = _qAlias[0], setQAlias = _qAlias[1];
    var _qMode = useState("ro"), qMode = _qMode[0], setQMode = _qMode[1];
    var _bkDir = useState(""), bkDir = _bkDir[0], setBkDir = _bkDir[1];
    var _bkDirty = useState(false), bkDirty = _bkDirty[0], setBkDirty = _bkDirty[1];
    var _bkItems = useState([]), bkItems = _bkItems[0], setBkItems = _bkItems[1];

    var reload = useCallback(function () {
      Promise.all([
        apiFetch("GET", "/wsl-sandbox/api/status"),
        apiFetch("GET", "/wsl-sandbox/api/approvals"),
        apiFetch("GET", "/wsl-sandbox/api/audit"),
        apiFetch("GET", "/wsl-sandbox/api/wsl-config/backups")
      ])
        .then(function (res) {
          if (res[0] && res[0].ok) {
            setUnavail(false);
            setCfg(res[0].config);
            setPending((res[1] && res[1].pending) || []);
            setRules((res[1] && res[1].sessionRules) || []);
            setAudit((res[2] && res[2].records) || []);
            if (res[3] && res[3].ok) {
              setBkItems(res[3].items || []);
              if (!bkDirty) setBkDir(res[3].backupDir || res[0].config.backupDir || "");
            }
          } else {
            setUnavail(true);
          }
        })
        .catch(function () {
          setUnavail(true);
        });
    }, [bkDirty]);

    useEffect(function () {
      reload();
      var timer = setInterval(reload, 4000);
      return function () {
        clearInterval(timer);
      };
    }, [reload]);

    function updateField(k, v) {
      if (!cfg) return;
      var next = Object.assign({}, cfg);
      next[k] = v;
      setCfg(next);
    }

    function saveConfig() {
      if (!cfg) return;
      apiFetch("PUT", "/wsl-sandbox/api/config", {
        enabled: cfg.enabled,
        transportMode: cfg.transportMode,
        distro: cfg.distro,
        username: cfg.username || undefined,
        workspaceRoot: cfg.workspaceRoot,
        runnerPath: cfg.runnerPath,
        sandboxMode: cfg.sandboxMode,
        approvalPolicyMode: cfg.approvalPolicyMode,
        approvalTimeoutMs: Number(cfg.approvalTimeoutMs) || 60000,
        networkMode: cfg.networkMode,
        upstreamProxy: cfg.upstreamProxy || "",
        mirrorCn: Boolean(cfg.mirrorCn),
        cacheMode: cfg.cacheMode,
        enablePwshGuard: Boolean(cfg.enablePwshGuard),
        enablePromptInjection: Boolean(cfg.enablePromptInjection),
        unmaskedEnvWorkspaces: cfg.unmaskedEnvWorkspaces || [],
        backupDir: bkDir || cfg.backupDir
      }).then(function (r) {
        setBkDirty(false);
        setNotice(r && r.ok ? "配置已原子保存并生效。" : "保存失败: " + ((r && r.error && r.error.message) || ""));
        reload();
      });
    }

    function killAll() {
      apiFetch("POST", "/wsl-sandbox/api/session/invalidate", {}).then(function () {
        setNotice("已熔断强杀全部沙箱进程组并清空待审队列。");
        reload();
      });
    }

    function decide(id, decision, guidance) {
      apiFetch("POST", "/wsl-sandbox/api/approvals/" + encodeURIComponent(id) + "/decide", {
        decision: decision,
        guidance: guidance
      }).then(function () {
        reload();
      });
    }

    function runDoctor() {
      setNotice("正在执行 WSL 内核与 22 项工具链自检...");
      apiFetch("GET", "/wsl-sandbox/api/doctor").then(function (r) {
        if (r && r.ok) {
          setDoc(r.report);
          setNotice("内核体检已完成: " + String(r.report.verdict || "").toUpperCase());
        }
      });
    }

    function quickMountShare() {
      apiFetch("POST", "/wsl-sandbox/api/advanced/shares", {
        path: qPath,
        alias: qAlias,
        mode: qMode
      }).then(function (r) {
        if (r && r.ok) {
          setQPath("");
          setQAlias("");
          setNotice("已挂载指定目录 -> /shares/" + (r.share ? r.share.alias : qAlias));
          reload();
        } else {
          setNotice("挂载拦截: " + ((r && r.error && r.error.message) || ""));
        }
      });
    }

    function revokeShare(id) {
      apiFetch("DELETE", "/wsl-sandbox/api/advanced/shares/" + encodeURIComponent(id)).then(function () {
        setNotice("已取消挂载并清理旧沙箱进程。");
        reload();
      });
    }

    function backupWslConfigs() {
      apiFetch("POST", "/wsl-sandbox/api/wsl-config/backup", { backupDir: bkDir || undefined }).then(function (r) {
        if (r && r.ok) {
          setBkDirty(false);
          setBkDir(r.backupDir || bkDir);
          setBkItems(r.items || []);
          setNotice("原始 WSL 配置已备份至: " + r.backupDir);
        } else {
          setNotice("备份失败: " + ((r && r.error && r.error.message) || ""));
        }
      });
    }

    function pickBackupDir() {
      apiFetch("POST", "/wsl-sandbox/api/wsl-config/pick-dir", {}).then(function (r) {
        if (r && r.ok && r.selectedDir) {
          setBkDirty(false);
          setBkDir(r.selectedDir);
          setNotice("已选择自定义备份目录: " + r.selectedDir);
          reload();
        } else if (r && r.message) {
          setNotice(r.message);
        }
      });
    }

    function openInExplorer(targetPath, selectFile) {
      apiFetch("POST", "/wsl-sandbox/api/wsl-config/open-explorer", {
        targetPath: targetPath || bkDir || undefined,
        backupDir: bkDir || undefined,
        selectFile: Boolean(selectFile)
      }).then(function (r) {
        setNotice(r && r.ok ? "已拉起资源管理器: " + (r.explorerArgs ? r.explorerArgs.join(" ") : r.targetPath) : "打开失败");
      });
    }

    if (unavail || !cfg) {
      return h(
        "div",
        { className: "dsh-wsl-native" },
        h(
          "div",
          { className: "dsh-wsl-native-panel" },
          h("div", { style: { fontWeight: 600, fontSize: "15px", marginBottom: "8px" } }, "WSL 2 沙箱 (dsh-wsl-sandbox)"),
          h("div", { style: { color: "#9498a3" } }, zh.offlineHint)
        )
      );
    }

    var layers = cfg.enabled ? (cfg.enablePwshGuard ? 6 : 5) : 0;

    return h(
      "div",
      { className: "dsh-wsl-native" },
      h(
        "div",
        { className: "dsh-wsl-native-tabs" },
        [
          ["status", "状态"],
          ["approvals", "审批队列 (" + pending.length + ")"],
          ["basic", "基础策略"],
          ["advanced", "共享与硬件"],
          ["doctor", "内核体检"],
          ["audit", "审计明细"]
        ].map(function (pair) {
          return h(
            "button",
            {
              key: pair[0],
              className: "dsh-wsl-native-tab" + (tab === pair[0] ? " is-on" : ""),
              onClick: function () { setTab(pair[0]); }
            },
            pair[1]
          );
        })
      ),
      h(
        "div",
        { className: "dsh-wsl-native-tel" },
        h("span", null, "受控发行版 ", h("b", { className: "dsh-wsl-native-mono" }, cfg.distro)),
        h("span", null, "工作区 ", h("b", { className: "dsh-wsl-native-mono" }, cfg.workspaceRoot)),
        h("span", null, "隔离层级 ", h("b", null, cfg.enabled ? "bwrap + seccomp + 单壳防呆" : "已停用")),
        h("span", null, "配置状态 ", h("b", null, "已生效"))
      ),
      notice
        ? h(
            "div",
            { className: "dsh-wsl-native-card", style: { padding: "9px 14px", color: "#e5e7eb" } },
            notice
          )
        : null,
      h(
        "div",
        { className: "dsh-wsl-native-panel" },
        h(
          "div",
          { className: "dsh-wsl-native-head" },
          h("div", { style: { fontSize: "17px", fontWeight: 600 } }, "WSL 2 沙箱控制面"),
          h(
            "div",
            { style: { display: "flex", gap: "8px", flexWrap: "wrap" } },
            h("button", { className: "dsh-wsl-native-btn dsh-wsl-native-btn-pri", onClick: saveConfig }, "应用"),
            h("button", { className: "dsh-wsl-native-btn dsh-wsl-native-btn-out-red", onClick: reload }, "还原"),
            h("button", { className: "dsh-wsl-native-btn dsh-wsl-native-btn-red", onClick: killAll }, "熔断强杀"),
            h(
              "a",
              {
                href: "/wsl-sandbox/ui",
                target: "_blank",
                rel: "noreferrer",
                style: { color: "#9498a3", fontSize: "12px", alignSelf: "center", marginLeft: "4px" }
              },
              "独立窗口"
            )
          )
        ),
        tab === "status"
          ? h(
              "div",
              null,
              h(
                "div",
                { className: "dsh-wsl-native-card" },
                h(
                  "div",
                  null,
                  h("span", { className: "dsh-wsl-native-mono", style: { fontSize: "24px", fontWeight: 700 } }, String(layers)),
                  " / 6 层内核与单壳防线就位"
                ),
                h(
                  "div",
                  { style: { height: "3px", background: "#2b2d35", borderRadius: "99px", margin: "10px 0" } },
                  h("div", { style: { height: "100%", width: Math.round((layers / 6) * 100) + "%", background: "#22c55e", borderRadius: "99px" } })
                ),
                h(
                  "div",
                  { className: "dsh-wsl-native-stats" },
                  h("div", { className: "dsh-wsl-native-stat" }, h("div", { style: { color: "#9498a3", fontSize: "11.5px" } }, "生效防线"), h("div", { style: { fontSize: "18px", fontWeight: 600, color: "#22c55e" } }, String(layers))),
                  h("div", { className: "dsh-wsl-native-stat" }, h("div", { style: { color: "#9498a3", fontSize: "11.5px" } }, "待人工审批"), h("div", { style: { fontSize: "18px", fontWeight: 600, color: "#f59e0b" } }, String(pending.length))),
                  h("div", { className: "dsh-wsl-native-stat" }, h("div", { style: { color: "#9498a3", fontSize: "11.5px" } }, "会话前缀"), h("div", { style: { fontSize: "18px", fontWeight: 600 } }, String(rules.length))),
                  h("div", { className: "dsh-wsl-native-stat" }, h("div", { style: { color: "#9498a3", fontSize: "11.5px" } }, "共享 / 硬件"), h("div", { style: { fontSize: "18px", fontWeight: 600 } }, cfg.advanced.shares.length + " / " + cfg.advanced.deviceNodes.length))
                )
              ),
              h(
                "div",
                { className: "dsh-wsl-native-grid2" },
                [
                  ["enabled", "WSL 2 沙箱后端", "接管 wsl_* 工具并在 Linux 内核命名空间内隔离执行。"],
                  ["enablePwshGuard", "宿主终端单壳与方言守卫", "硬拦截 pwsh 套 cmd、混用 powershell.exe、/s /q、2>nul 与 UNC 越界。"],
                  ["enablePromptInjection", "系统提示词路由注入", "以 order 4200 (interpolate: false) 引导优先使用 wsl_*。"],
                  ["mirrorCn", "国内镜像源环境变量", "为沙箱内 npm/pip/uv/cargo/go 自动注入加速镜像源。"]
                ].map(function (row) {
                  var on = Boolean(cfg[row[0]]);
                  return h(
                    "div",
                    { key: row[0], className: "dsh-wsl-native-card" + (on ? " accent" : "") },
                    h(
                      "div",
                      { style: { display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "6px" } },
                      h("b", null, row[1]),
                      h("input", {
                        type: "checkbox",
                        checked: on,
                        onChange: function (e) { updateField(row[0], e.target.checked); }
                      })
                    ),
                    h("div", { style: { color: "#9498a3", fontSize: "12px" } }, row[2])
                  );
                })
              ),
              h(
                "div",
                { className: "dsh-wsl-native-card", style: { marginTop: "2px", borderColor: "rgba(255,255,255,0.12)" } },
                h(
                  "div",
                  { style: { paddingBottom: "10px", marginBottom: "10px", borderBottom: "1px solid rgba(255,255,255,0.07)" } },
                  h(
                    "div",
                    { style: { marginBottom: "8px" } },
                    h("b", null, "禁用 Windows 全盘挂载 (C:\\ / D:\\) 与原始 WSL 配置备份 · "),
                    h("span", { style: { color: "#22c55e", fontSize: "12px" } }, "沙箱 --tmpfs /mnt 已锁死开启")
                  ),
                  h(
                    "div",
                    { style: { display: "flex", gap: "8px", flexWrap: "wrap", marginBottom: "8px" } },
                    h("input", {
                      className: "dsh-wsl-native-in dsh-wsl-native-mono",
                      style: { flex: "1", minWidth: "200px" },
                      placeholder: "任意指定备份目录，如 D:\\Backups\\WSL-Orig",
                      value: bkDir,
                      onChange: function (e) { setBkDirty(true); setBkDir(e.target.value); }
                    }),
                    h("button", { className: "dsh-wsl-native-btn", onClick: pickBackupDir }, "选择目录..."),
                    h("button", { className: "dsh-wsl-native-btn dsh-wsl-native-btn-pri", onClick: backupWslConfigs }, "立即备份"),
                    h("button", { className: "dsh-wsl-native-btn", onClick: function () { openInExplorer(bkDir, false); } }, "打开备份目录")
                  ),
                  bkItems.length === 0
                    ? h("div", { style: { color: "#9498a3", fontSize: "12px" } }, "暂无原始配置快照，点击「立即备份」保存到上方自定义目录。")
                    : bkItems.map(function (it) {
                        return h(
                          "div",
                          { key: it.explorerPath, style: { display: "flex", justifyContent: "space-between", alignItems: "center", gap: "8px", padding: "4px 0", borderTop: "1px solid rgba(255,255,255,0.05)" } },
                          h("span", { className: "dsh-wsl-native-mono", style: { fontSize: "12px" } }, it.name + "  (" + it.explorerPath + ")"),
                          h("button", { className: "dsh-wsl-native-btn", style: { padding: "3px 10px" }, onClick: function () { openInExplorer(it.explorerPath, true); } }, "在资源管理器中定位")
                        );
                      })
                ),
                h("div", { style: { fontWeight: 600, marginBottom: "6px" } }, "指定单目录快捷挂载（直接粘贴 Windows 文件夹如 D:\\Datasets\\ESP32）"),
                h(
                  "div",
                  { style: { display: "flex", gap: "8px", flexWrap: "wrap", marginBottom: "8px" } },
                  h("input", {
                    className: "dsh-wsl-native-in dsh-wsl-native-mono",
                    style: { flex: "1", minWidth: "200px" },
                    placeholder: "D:\\Datasets\\ESP32 或 /mnt/d/...",
                    value: qPath,
                    onChange: function (e) { setQPath(e.target.value); }
                  }),
                  h("input", {
                    className: "dsh-wsl-native-in dsh-wsl-native-mono",
                    style: { width: "130px" },
                    placeholder: "别名(可选)",
                    value: qAlias,
                    onChange: function (e) { setQAlias(e.target.value); }
                  }),
                  h(
                    "select",
                    {
                      className: "dsh-wsl-native-in",
                      style: { width: "100px" },
                      value: qMode,
                      onChange: function (e) { setQMode(e.target.value); }
                    },
                    h("option", { value: "ro" }, "只读 (ro)"),
                    h("option", { value: "rw" }, "读写 (rw)")
                  ),
                  h("button", { className: "dsh-wsl-native-btn dsh-wsl-native-btn-pri", onClick: quickMountShare }, "挂载此目录")
                ),
                cfg.advanced.shares.length === 0
                  ? h("div", { style: { color: "#9498a3", fontSize: "12px" } }, "当前无挂载目录（Windows 各盘符全盘已对 AI 遮蔽）。")
                  : cfg.advanced.shares.map(function (s) {
                      return h(
                        "div",
                        { key: s.id, style: { display: "flex", justifyContent: "space-between", alignItems: "center", padding: "5px 0", borderTop: "1px solid rgba(255,255,255,0.05)" } },
                        h("span", { className: "dsh-wsl-native-mono", style: { fontSize: "12px" } }, "/shares/" + s.alias + " <- " + s.sourceLinuxPath + " (" + s.mode + ")"),
                        h("button", { className: "dsh-wsl-native-btn dsh-wsl-native-btn-out-red", style: { padding: "3px 10px" }, onClick: function () { revokeShare(s.id); } }, "取消挂载")
                      );
                    })
              )
            )
          : null,
        tab === "approvals"
          ? h(
              "div",
              null,
              pending.length === 0
                ? h("div", { className: "dsh-wsl-native-card", style: { color: "#9498a3" } }, "当前没有待处理的人工审批请求。")
                : pending.map(function (p) {
                    return h(
                      "div",
                      { key: p.requestId, className: "dsh-wsl-native-card" },
                      h("div", { style: { fontWeight: 600, marginBottom: "6px" } }, p.summary),
                      h("pre", { className: "dsh-wsl-native-in dsh-wsl-native-mono", style: { overflowX: "auto", marginBottom: "8px" } }, p.command || ""),
                      h(
                        "div",
                        { style: { display: "flex", gap: "8px", flexWrap: "wrap" } },
                        h("button", { className: "dsh-wsl-native-btn dsh-wsl-native-btn-pri", onClick: function () { decide(p.requestId, "allow-once"); } }, "允许一次"),
                        h(
                          "button",
                          {
                            className: "dsh-wsl-native-btn",
                            disabled: Boolean(p.touchesPhysicalDevice || !p.allowSessionRuleOption),
                            onClick: function () { decide(p.requestId, "allow-session-rule"); }
                          },
                          p.touchesPhysicalDevice ? "硬件强制单次锁" : "本会话允许前缀"
                        ),
                        h("button", { className: "dsh-wsl-native-btn dsh-wsl-native-btn-out-red", onClick: function () { decide(p.requestId, "deny"); } }, "拒绝")
                      )
                    );
                  })
            )
          : null,
        tab === "basic"
          ? h(
              "div",
              { className: "dsh-wsl-native-grid2" },
              h("div", null, h("div", null, "WSL 发行版"), h("input", { className: "dsh-wsl-native-in dsh-wsl-native-mono", value: cfg.distro, onChange: function (e) { updateField("distro", e.target.value); } })),
              h("div", null, h("div", null, "工作区根目录 (原生 ext4)"), h("input", { className: "dsh-wsl-native-in dsh-wsl-native-mono", value: cfg.workspaceRoot, onChange: function (e) { updateField("workspaceRoot", e.target.value); } })),
              h("div", null, h("div", null, "沙箱模式"), h("select", { className: "dsh-wsl-native-in", value: cfg.sandboxMode, onChange: function (e) { updateField("sandboxMode", e.target.value); } }, h("option", { value: "workspace-write" }, "workspace-write"), h("option", { value: "read-only" }, "read-only"))),
              h("div", null, h("div", null, "审批策略"), h("select", { className: "dsh-wsl-native-in", value: cfg.approvalPolicyMode, onChange: function (e) { updateField("approvalPolicyMode", e.target.value); } }, h("option", { value: "balanced" }, "balanced"), h("option", { value: "strict" }, "strict"), h("option", { value: "trust-workspace" }, "trust-workspace"))),
              h("div", null, h("div", null, "网络隔离模式"), h("select", { className: "dsh-wsl-native-in", value: cfg.networkMode, onChange: function (e) { updateField("networkMode", e.target.value); } }, h("option", { value: "allowlist-proxy" }, "allowlist-proxy"), h("option", { value: "offline" }, "offline"))),
              h("div", null, h("div", null, "上游代理"), h("input", { className: "dsh-wsl-native-in dsh-wsl-native-mono", value: cfg.upstreamProxy || "", onChange: function (e) { updateField("upstreamProxy", e.target.value); } }))
            )
          : null,
        tab === "advanced"
          ? h(
              "div",
              { className: "dsh-wsl-native-card" },
              h("div", { style: { marginBottom: "8px", color: "#9498a3" } }, "受控单目录挂载 (/shares) 与物理串口/USB 设备透传默认关闭；如需添加或立即吊销，请点击右上角「独立窗口」使用完整高级表格。"),
              h("div", { className: "dsh-wsl-native-mono" }, "当前共享数: " + cfg.advanced.shares.length + " · 当前物理设备数: " + cfg.advanced.deviceNodes.length)
            )
          : null,
        tab === "doctor"
          ? h(
              "div",
              null,
              h("button", { className: "dsh-wsl-native-btn", style: { marginBottom: "10px" }, onClick: runDoctor }, "运行 dsh-wsl-doctor 实时自检"),
              doc
                ? h("pre", { className: "dsh-wsl-native-in dsh-wsl-native-mono", style: { maxHeight: "300px", overflow: "auto" } }, JSON.stringify(doc, null, 2))
                : null
            )
          : null,
        tab === "audit"
          ? h(
              "div",
              { className: "dsh-wsl-native-card" },
              audit.length === 0
                ? h("div", { style: { color: "#9498a3" } }, "暂无审计记录。")
                : audit.slice(-15).reverse().map(function (r, idx) {
                    return h("div", { key: idx, className: "dsh-wsl-native-mono", style: { padding: "5px 0", borderBottom: "1px solid rgba(255,255,255,0.05)" } }, r.timestamp + " · " + r.kind + " -> " + r.outcome);
                  })
            )
          : null
      )
    );
  }

  var inject = ["slots", "locale"];

  function apply(ctx) {
    var t = ctx.locale.bind(NS);
    ctx.effect(function () {
      return ctx.locale.register(NS, { zh: zh, en: en });
    });

    ctx.effect(function () {
      if (typeof document === "undefined") return function () {};
      var existing = document.querySelector("style[" + STYLE_ATTR + "]");
      if (existing) return function () {};
      var styleEl = document.createElement("style");
      styleEl.setAttribute(STYLE_ATTR, "1");
      styleEl.textContent = CSS_TEXT;
      document.head.appendChild(styleEl);
      return function () {
        styleEl.remove();
      };
    });

    ctx.effect(function () {
      return ctx.slots.inject("settings.section", function () {
        var d1 = ctx.slots.register(
          {
            name: "settings.section",
            id: "dsh-wsl-sandbox",
            order: 45,
            label: function () { return t("navTitle"); },
            locale: NS
          },
          WslSandboxSection
        );
        var d2 = ctx.slots.register(
          {
            name: "settings.section.icon",
            id: "dsh-wsl-sandbox"
          },
          SectionIcon
        );
        return function () {
          if (typeof d1 === "function") d1();
          if (typeof d2 === "function") d2();
        };
      });
    });
  }

  exports.NS = NS;
  exports.inject = inject;
  exports.apply = apply;
  return module.exports;
} });

