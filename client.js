window.__ModuleLoader__.load({ id: "dsh-wsl-sandbox", factory: (require) => {
  var module = { exports: {} };
  var exports = module.exports;
  Object.defineProperty(exports, Symbol.toStringTag, { value: "Module" });

  var React = require("react");
  var ReactDOM = null;
  try {
    ReactDOM = require("react-dom");
  } catch (_e) {
    ReactDOM = null;
  }

  var h = React.createElement;
  var useState = React.useState;
  var useEffect = React.useEffect;
  var useCallback = React.useCallback;

  var NS = "settings.wsl-sandbox";
  var PANEL_ID = "wsl-sandbox";
  var PLUGIN_ID = "dsh-wsl-sandbox";
  var STYLE_ATTR = "data-dsh-wsl-sandbox-style";

  var zh = {
    navTitle: "WSL 2 沙箱",
    panelTitle: "WSL 2 沙箱控制台",
    rightTabTitle: "WSL 2 沙箱",
    guideTitle: "WSL 2 内核隔离与审批面板",
    guideDesc: "查看实时沙箱绑定状态、待处理人工审批队列，并按需扫描本机 WSL 2 发行版。",
    introTitle: "WSL 2 内核隔离执行后端 (v0.3.0)",
    introSummary: "默认将 AI 代码读写、构建与命令执行隔离在 WSL 2 原生 Linux 命名空间内（bwrap + seccomp-bpf + UDS 白名单代理），自动遮蔽 Windows 全盘 (/mnt) 与宿主机敏感凭证 (~/.dsh / ~/.ssh)，并在宿主 PowerShell/CMD 层提供基于微软官方 AST 的单壳防呆守卫与物理硬件单次人工审批锁。",
    apply: "应用",
    reset: "还原",
    kill: "熔断强杀",
    tabStatus: "状态",
    tabApprovals: "审批队列",
    tabBasic: "基础策略",
    tabAdvanced: "共享与硬件",
    tabDoctor: "内核体检",
    tabLogs: "运行日志",
    tabAudit: "审计明细",
    offlineHint: "当前宿主未挂载 HTTP 控制面（如纯离线或无 WebServer 模式），配置存储于 ~/.dsh/dsh-wsl-sandbox/config.json。"
  };

  var en = {
    navTitle: "WSL 2 Sandbox",
    panelTitle: "WSL 2 Sandbox Console",
    rightTabTitle: "WSL 2 Sandbox",
    guideTitle: "WSL 2 Sandbox & Approvals",
    guideDesc: "Inspect live sandbox binding, resolve pending human approvals, and trigger on-demand WSL distro discovery.",
    introTitle: "WSL 2 Kernel-Isolated Execution Backend (v0.3.0)",
    introSummary: "Confines agent code edits, builds, and shell commands inside a WSL 2 Linux namespace (bwrap + seccomp-bpf + UDS allowlist proxy), masks Windows drives (/mnt) and sensitive host credentials (~/.dsh / ~/.ssh), and enforces official Microsoft PowerShell AST dialect guards plus single-shot hardware approval locks.",
    apply: "Apply",
    reset: "Reset",
    kill: "Emergency Kill",
    tabStatus: "Status",
    tabApprovals: "Approvals",
    tabBasic: "Basic Policy",
    tabAdvanced: "Shares & Hardware",
    tabDoctor: "WSL Doctor",
    tabLogs: "Logs",
    tabAudit: "Audit Log",
    offlineHint: "HTTP control surface not mounted on this host; config is persisted at ~/.dsh/dsh-wsl-sandbox/config.json."
  };

  var CSS_TEXT = [
    ".dsh-wsl-main-wrap { flex: 1 1 auto; min-width: 0; min-height: 0; height: 100%; overflow-y: auto; padding: 22px 26px 42px; -webkit-app-region: no-drag; }",
    ".dsh-wsl-native { color: var(--dsw-alias-label-primary, #f2f3f5); font-size: 13px; line-height: 1.5; max-width: 960px; margin: 0 auto; position: relative; z-index: 1; }",
    ".dsh-wsl-native * , .dsh-wsl-oobe-backdrop * { box-sizing: border-box; }",
    ".dsh-wsl-native-mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-variant-numeric: tabular-nums; }",
    ".dsh-wsl-native-tabs { display: flex; flex-wrap: wrap; gap: 18px; border-bottom: 1px solid rgba(255,255,255,0.08); margin-bottom: 12px; }",
    ".dsh-wsl-native-tab { position: relative; background: none; border: 0; color: #9498a3; padding: 8px 0 10px; font: 500 13px/1 inherit; cursor: pointer; }",
    ".dsh-wsl-native-tab.is-on { color: #f2f3f5; font-weight: 600; }",
    ".dsh-wsl-native-tab.is-on::after { content: ''; position: absolute; left: 0; right: 0; bottom: -1px; height: 2px; background: #f2f3f5; }",
    ".dsh-wsl-native-tel { display: flex; flex-wrap: wrap; gap: 16px; padding-bottom: 10px; margin-bottom: 14px; border-bottom: 1px solid rgba(255,255,255,0.07); font-size: 12px; color: #9498a3; }",
    ".dsh-wsl-native-tel b { color: #f2f3f5; font-weight: 600; }",
    ".dsh-wsl-native-panel { background: #16171a; border: 1px solid rgba(255,255,255,0.08); border-radius: 14px; padding: 18px 20px; }",
    ".dsh-wsl-native-head { display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between; gap: 10px; margin-bottom: 14px; }",
    ".dsh-wsl-native-btn { border-radius: 8px; padding: 6px 14px; font: 500 12.5px/1.2 inherit; cursor: pointer; border: 1px solid rgba(255,255,255,0.14); background: #1c1d21; color: #f2f3f5; transition: background 0.14s, border-color 0.14s; -webkit-app-region: no-drag; }",
    ".dsh-wsl-native-btn:hover:not(:disabled) { border-color: rgba(255,255,255,0.28); background: #24262c; }",
    ".dsh-wsl-native-btn:disabled { opacity: 0.38; cursor: not-allowed; }",
    ".dsh-wsl-native-btn-pri { background: #f4f5f7; color: #111214; border-color: transparent; font-weight: 600; }",
    ".dsh-wsl-native-btn-pri:hover:not(:disabled) { background: #ffffff; border-color: transparent; }",
    ".dsh-wsl-native-btn-out-red { background: transparent; border-color: rgba(224,108,101,0.45); color: #e06c65; }",
    ".dsh-wsl-native-btn-red { background: #8c2d2b; border-color: transparent; color: #fbeae9; }",
    ".dsh-wsl-native-card { background: #1c1d21; border: 1px solid rgba(255,255,255,0.075); border-radius: 11px; padding: 14px 16px; margin-bottom: 12px; position: relative; }",
    ".dsh-wsl-native-card.accent::before { content: ''; position: absolute; left: 0; top: 10px; bottom: 10px; width: 2.5px; border-radius: 2px; background: #22c55e; }",
    ".dsh-wsl-native-card.warn { border-color: rgba(245,158,11,0.42); background: rgba(245,158,11,0.08); }",
    ".dsh-wsl-native-grid2 { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 10px; }",
    ".dsh-wsl-native-stats { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 8px; margin-top: 12px; }",
    ".dsh-wsl-native-stat { border: 1px solid rgba(255,255,255,0.07); border-radius: 8px; padding: 10px 12px; }",
    ".dsh-wsl-native-in { width: 100%; background: #121316; color: #f2f3f5; border: 1px solid rgba(255,255,255,0.14); border-radius: 7px; padding: 7px 10px; font-size: 12.5px; outline: none; }",
    ".dsh-wsl-native-pill { display: inline-flex; align-items: center; gap: 5px; padding: 2px 9px; border-radius: 999px; font-size: 11.5px; border: 1px solid rgba(255,255,255,0.14); color: #9498a3; }",
    ".dsh-wsl-oobe-backdrop { position: fixed; inset: 0; z-index: 9200; background: rgba(8, 9, 12, 0.72); backdrop-filter: blur(4px); display: flex; align-items: center; justify-content: center; padding: 20px; -webkit-app-region: no-drag; }",
    ".dsh-wsl-oobe-modal { width: min(760px, 100%); max-height: 90vh; overflow-y: auto; background: #16171a; color: #f2f3f5; border: 1px solid rgba(255,255,255,0.14); border-radius: 16px; padding: 22px 24px; box-shadow: 0 24px 64px rgba(0,0,0,0.58); font-size: 13px; line-height: 1.55; }",
    ".dsh-wsl-approval-toast { position: fixed; right: 20px; bottom: 20px; width: min(410px, calc(100vw - 32px)); z-index: 9100; background: #181a1f; color: #f2f3f5; border: 1px solid rgba(245,158,11,0.5); border-radius: 13px; padding: 14px 16px; box-shadow: 0 18px 48px rgba(0,0,0,0.55); font-size: 12.5px; line-height: 1.5; -webkit-app-region: no-drag; }"
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

  function apiFetch(method, urlPath, body) {
    return fetch(urlPath, {
      method: method,
      headers: {
        "Content-Type": "application/json",
        "X-DSH-WSL-Client": "1"
      },
      body: body !== undefined ? JSON.stringify(body) : undefined
    }).then(function (r) {
      return r.text().then(function (text) {
        var data;
        try {
          data = text ? JSON.parse(text) : {};
        } catch (_err) {
          data = { ok: false, error: { message: text || ("HTTP " + r.status) } };
        }
        if (!r.ok && data && data.ok !== false) {
          return { ok: false, error: data.error || { message: "HTTP " + r.status } };
        }
        return data;
      });
    });
  }

  function portalToBody(node) {
    if (ReactDOM && typeof ReactDOM.createPortal === "function" && typeof document !== "undefined" && document.body) {
      return ReactDOM.createPortal(node, document.body);
    }
    return node;
  }

  function copyClipboardText(text) {
    if (!text) return;
    if (typeof navigator !== "undefined" && navigator.clipboard && navigator.clipboard.writeText) {
      try {
        navigator.clipboard.writeText(text);
        return;
      } catch (_e) {}
    }
    if (typeof document !== "undefined" && document.body) {
      try {
        var ta = document.createElement("textarea");
        ta.value = text;
        ta.style.position = "fixed";
        ta.style.left = "-9999px";
        document.body.appendChild(ta);
        ta.select();
        document.execCommand("copy");
        ta.remove();
      } catch (_e2) {}
    }
  }

  function downloadNdjsonLogs(onResult) {
    fetch("/wsl-sandbox/api/logs/export", {
      method: "GET",
      headers: { "X-DSH-WSL-Client": "1" }
    })
      .then(function (r) {
        if (!r.ok) throw new Error("HTTP " + r.status);
        return r.text();
      })
      .then(function (txt) {
        if (typeof Blob !== "undefined" && typeof URL !== "undefined" && typeof document !== "undefined") {
          var blob = new Blob([txt], { type: "application/x-ndjson;charset=utf-8" });
          var url = URL.createObjectURL(blob);
          var a = document.createElement("a");
          a.href = url;
          a.download = "dsh-wsl-sandbox-logs.ndjson";
          document.body.appendChild(a);
          a.click();
          a.remove();
          setTimeout(function () {
            try { URL.revokeObjectURL(url); } catch (_e) {}
          }, 1000);
          if (onResult) onResult(true);
        }
      })
      .catch(function (err) {
        if (onResult) onResult(false, err && err.message ? err.message : String(err));
      });
  }

  function createSharedUiController(getActiveLang) {
    var oobeListeners = new Set();
    var oobeOpen = false;
    var activeTabOverride = null;
    var tabListeners = new Set();
    var langState = getActiveLang() === "en" ? "en" : "zh";
    var langListeners = new Set();
    var layoutService = null;
    var statusListeners = new Set();

    return {
      setLayoutService: function (svc) {
        layoutService = svc || null;
      },
      getLayoutService: function () {
        return layoutService;
      },
      openMainPanel: function (requestedTab) {
        if (requestedTab) {
          activeTabOverride = requestedTab;
          tabListeners.forEach(function (fn) { fn(requestedTab); });
        }
        if (layoutService && typeof layoutService.selectPanel === "function") {
          layoutService.selectPanel(PANEL_ID);
          return true;
        }
        return false;
      },
      backToChat: function () {
        if (layoutService && typeof layoutService.selectPanel === "function") {
          layoutService.selectPanel(null);
          return true;
        }
        return false;
      },
      getOobeOpen: function () {
        return oobeOpen;
      },
      setOobeOpen: function (next) {
        oobeOpen = Boolean(next);
        oobeListeners.forEach(function (fn) { fn(oobeOpen); });
      },
      subscribeOobe: function (fn) {
        oobeListeners.add(fn);
        return function () { oobeListeners.delete(fn); };
      },
      consumeTabOverride: function () {
        var cur = activeTabOverride;
        activeTabOverride = null;
        return cur;
      },
      subscribeTabOverride: function (fn) {
        tabListeners.add(fn);
        return function () { tabListeners.delete(fn); };
      },
      getLang: function () {
        return langState;
      },
      setLang: function (next) {
        langState = next === "en" ? "en" : "zh";
        langListeners.forEach(function (fn) { fn(langState); });
      },
      subscribeLang: function (fn) {
        langListeners.add(fn);
        return function () { langListeners.delete(fn); };
      },
      notifyStatusChanged: function () {
        statusListeners.forEach(function (fn) { fn(); });
      },
      subscribeStatusChanged: function (fn) {
        statusListeners.add(fn);
        return function () { statusListeners.delete(fn); };
      }
    };
  }

  function apply(ctx) {
    var t = ctx.locale.bind(NS);
    var uiCtrl = createSharedUiController(function () {
      try {
        var loc = ctx.locale.getLocale && ctx.locale.getLocale();
        return (loc && loc.active === "en") ? "en" : "zh";
      } catch (_e) {
        return "zh";
      }
    });

    function useUiLang() {
      var _s = useState(uiCtrl.getLang()), lang = _s[0], setLang = _s[1];
      useEffect(function () {
        return uiCtrl.subscribeLang(function (next) { setLang(next); });
      }, []);
      return [lang, function (v) { uiCtrl.setLang(v); }];
    }

    // 主设置 / 侧边栏面板完整控制台组件
    function WslSandboxSection(sectionProps) {
      var isMainPanel = Boolean(sectionProps && sectionProps.isMainPanel);
      var onCloseSettings = sectionProps && typeof sectionProps.close === "function" ? sectionProps.close : null;
      var _langPair = useUiLang(), introLang = _langPair[0], setIntroLang = _langPair[1];
      var isEn = introLang === "en";

      var _tab = useState(uiCtrl.consumeTabOverride() || "status"), tab = _tab[0], setTab = _tab[1];
      var _cfg = useState(null), cfg = _cfg[0], setCfg = _cfg[1];
      var _initialized = useState(true), initialized = _initialized[0], setInitialized = _initialized[1];
      var _cfgDirty = useState(false), cfgDirty = _cfgDirty[0], setCfgDirty = _cfgDirty[1];
      var _nodeRt = useState(null), nodeRt = _nodeRt[0], setNodeRt = _nodeRt[1];
      var _pending = useState([]), pending = _pending[0], setPending = _pending[1];
      var _rules = useState([]), rules = _rules[0], setRules = _rules[1];
      var _audit = useState([]), audit = _audit[0], setAudit = _audit[1];
      var _logs = useState([]), logs = _logs[0], setLogs = _logs[1];
      var _logStats = useState(null), logStats = _logStats[0], setLogStats = _logStats[1];
      var _logLvl = useState("info"), logLvl = _logLvl[0], setLogLvl = _logLvl[1];
      var _logQ = useState(""), logQ = _logQ[0], setLogQ = _logQ[1];
      var _doc = useState(null), doc = _doc[0], setDoc = _doc[1];
      var _notice = useState(""), notice = _notice[0], setNotice = _notice[1];
      var _unavail = useState(false), unavail = _unavail[0], setUnavail = _unavail[1];
      var _qPath = useState(""), qPath = _qPath[0], setQPath = _qPath[1];
      var _qAlias = useState(""), qAlias = _qAlias[0], setQAlias = _qAlias[1];
      var _qMode = useState("ro"), qMode = _qMode[0], setQMode = _qMode[1];
      var _bkDir = useState(""), bkDir = _bkDir[0], setBkDir = _bkDir[1];
      var _bkDirty = useState(false), bkDirty = _bkDirty[0], setBkDirty = _bkDirty[1];
      var _bkItems = useState([]), bkItems = _bkItems[0], setBkItems = _bkItems[1];
      var _distros = useState([]), distros = _distros[0], setDistros = _distros[1];
      var _bsState = useState(null), bsState = _bsState[0], setBsState = _bsState[1];
      var _bsDistro = useState(""), bsDistro = _bsDistro[0], setBsDistro = _bsDistro[1];
      var bsInitRef = useState({ synced: false })[0];
      var _bsPreview = useState(null), bsPreview = _bsPreview[0], setBsPreview = _bsPreview[1];
      var _bsScriptIdx = useState(0), bsScriptIdx = _bsScriptIdx[0], setBsScriptIdx = _bsScriptIdx[1];

      useEffect(function () {
        return uiCtrl.subscribeTabOverride(function (nextTab) {
          if (nextTab) setTab(nextTab);
        });
      }, []);

      var loadBackups = useCallback(function () {
        apiFetch("GET", "/wsl-sandbox/api/wsl-config/backups")
          .then(function (r) {
            if (r && r.ok) {
              setBkItems(r.items || []);
              if (!bkDirty && r.backupDir) setBkDir(r.backupDir);
            }
          })
          .catch(function () {});
      }, [bkDirty]);

      var loadLogs = useCallback(function () {
        var qs = "?level=" + encodeURIComponent(logLvl) + (logQ ? "&search=" + encodeURIComponent(logQ) : "") + "&limit=150";
        apiFetch("GET", "/wsl-sandbox/api/logs" + qs)
          .then(function (r) {
            if (r && r.ok) {
              setLogs(r.entries || []);
              setLogStats(r.stats || null);
            }
          })
          .catch(function () {});
      }, [logLvl, logQ]);

      var reload = useCallback(function (forceCfg) {
        var shouldSyncCfg = forceCfg === true || !cfgDirty;
        Promise.all([
          apiFetch("GET", "/wsl-sandbox/api/status"),
          apiFetch("GET", "/wsl-sandbox/api/approvals"),
          apiFetch("GET", "/wsl-sandbox/api/audit")
        ])
          .then(function (res) {
            if (res[0] && res[0].ok) {
              setUnavail(false);
              setInitialized(res[0].initialized !== false);
              if (shouldSyncCfg) {
                setCfg(res[0].config);
                if (forceCfg === true) setCfgDirty(false);
              }
              setNodeRt(res[0].nodeRuntime || null);
              setBsState(res[0].bootstrap || null);
              if (!bsInitRef.synced && res[0].config && res[0].config.distro) {
                bsInitRef.synced = true;
                setBsDistro(res[0].config.distro);
              }
              setPending((res[1] && res[1].pending) || []);
              setRules((res[1] && res[1].sessionRules) || []);
              setAudit((res[2] && res[2].records) || []);
              if (!bkDirty && !bkDir && res[0].config && res[0].config.backupDir) setBkDir(res[0].config.backupDir);
            } else {
              setUnavail(true);
            }
          })
          .catch(function () {
            setUnavail(true);
          });
      }, [bkDirty, bkDir, bsInitRef, cfgDirty]);

      var loadDistros = useCallback(function (notify) {
        apiFetch("GET", "/wsl-sandbox/api/distros")
          .then(function (r) {
            if (r && r.ok) {
              var usable = (r.distros || []).filter(function (d) { return !d.isInternalContainer; });
              setDistros(usable);
              if (notify) {
                setNotice(isEn ? ("Detected " + usable.length + " WSL distro(s).") : ("已探测到 " + usable.length + " 个 WSL 发行版（含 WSL Manager 迁移实例）。"));
              }
            }
          })
          .catch(function () {});
      }, [isEn]);

      useEffect(function () {
        reload();
        loadBackups();
        var unsub = uiCtrl.subscribeStatusChanged(function () { reload(true); });
        var timer = setInterval(function () {
          if (typeof document !== "undefined" && document.hidden) return;
          reload();
          if (tab === "logs") loadLogs();
        }, 5000);
        return function () {
          unsub();
          clearInterval(timer);
        };
      }, [reload, loadBackups, tab, loadLogs]);

      useEffect(function () {
        if (tab === "logs") loadLogs();
      }, [tab, loadLogs]);

      function updateField(k, v) {
        if (!cfg) return;
        setCfgDirty(true);
        var next = Object.assign({}, cfg);
        next[k] = v;
        setCfg(next);
      }

      function selectDiscoveredDistro(name) {
        if (!name || !cfg) return;
        updateField("distro", name);
        apiFetch("GET", "/wsl-sandbox/api/distros?probeDistro=" + encodeURIComponent(name))
          .then(function (r) {
            if (r && r.ok && r.probedUser) {
              if (r.probedUser.uid === 0) {
                setNotice("警告: " + name + " 默认用户为 root (UID 0)，请先配置非 root 用户。");
              } else {
                var next = Object.assign({}, cfg, {
                  distro: name,
                  username: r.probedUser.username,
                  workspaceRoot: r.probedUser.homeDir + "/workspace",
                  runnerPath: r.probedUser.homeDir + "/.local/share/dsh-wsl-sandbox/runner/dist/packages/wsl-runner/src/main.js"
                });
                setCfgDirty(true);
                setCfg(next);
                setNotice("已自动探测 " + name + " 非 root 用户: " + r.probedUser.username + "（点击「应用」生效）。");
              }
            }
          })
          .catch(function () {});
      }

      function saveConfig() {
        if (!cfg) return;
        apiFetch("PUT", "/wsl-sandbox/api/config", {
          enabled: cfg.enabled,
          transportMode: cfg.transportMode,
          distro: cfg.distro,
          environmentProfile: cfg.environmentProfile || "standard",
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
          logLevel: cfg.logLevel || "info",
          enablePwshGuard: Boolean(cfg.enablePwshGuard),
          enablePromptInjection: Boolean(cfg.enablePromptInjection),
          unmaskedEnvWorkspaces: cfg.unmaskedEnvWorkspaces || [],
          backupDir: bkDir || cfg.backupDir
        }).then(function (r) {
          if (r && r.ok) {
            setBkDirty(false);
            setCfgDirty(false);
            setNotice(isEn ? "Configuration saved atomically." : "配置已原子保存并生效。");
            uiCtrl.notifyStatusChanged();
            reload(true);
          } else {
            setNotice((isEn ? "Save failed: " : "保存失败: ") + ((r && r.error && r.error.message) || ""));
          }
        });
      }

      function killAll() {
        apiFetch("POST", "/wsl-sandbox/api/session/invalidate", {}).then(function () {
          setNotice(isEn ? "Terminated active DSH sandbox process group." : "已仅熔断当前 DSH 会话的沙箱进程组（不影响其他会话或人工 WSL 终端）。");
          reload();
        });
      }

      function decide(id, decision, guidance) {
        apiFetch("POST", "/wsl-sandbox/api/approvals/" + encodeURIComponent(id) + "/decide", {
          decision: decision,
          guidance: guidance
        }).then(function () {
          uiCtrl.notifyStatusChanged();
          reload();
        });
      }

      function runDoctor() {
        setNotice(isEn ? "Running WSL kernel & toolchain doctor..." : "正在按所选档位执行 WSL 内核与工具链自检...");
        apiFetch("GET", "/wsl-sandbox/api/doctor").then(function (r) {
          if (r && r.ok) {
            setDoc(r.report);
            setNotice((isEn ? "Doctor finished: " : "内核体检已完成 (") + (r.report.selectedProfile || "standard") + "): " + String(r.report.verdict || "").toUpperCase());
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
          setNotice("已取消挂载并仅清理当前会话的旧沙箱进程。");
          reload();
        });
      }

      function backupWslConfigs() {
        apiFetch("POST", "/wsl-sandbox/api/wsl-config/backup", { backupDir: bkDir || undefined }).then(function (r) {
          if (r && r.ok) {
            setBkDirty(false);
            setBkDir(r.backupDir || bkDir);
            setBkItems(r.items || []);
            setNotice("只读原始 WSL 配置快照已保存至: " + r.backupDir);
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
            loadBackups();
            reload();
          } else if (r && r.message) {
            setNotice(r.message);
          }
        });
      }

      function clearAllLogs() {
        apiFetch("DELETE", "/wsl-sandbox/api/logs").then(function () {
          setNotice(isEn ? "Logs cleared." : "已清空内存与本地轮转日志。");
          loadLogs();
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

      function fetchBootstrapPreview(notify) {
        var qs = bsDistro ? ("?distro=" + encodeURIComponent(bsDistro)) : "";
        return apiFetch("GET", "/wsl-sandbox/api/bootstrap-preview" + qs).then(function (r) {
          if (r && r.ok) {
            setBsPreview(r);
            if (notify) setNotice(isEn ? "Loaded script sources and SHA-256 checksums." : "已加载安装脚本源码与 SHA-256 哈希（零子进程调用）。");
          }
          return r;
        });
      }

      function toggleBootstrapChannel(open) {
        apiFetch("POST", "/wsl-sandbox/api/bootstrap-session", {
          action: open ? "open" : "close",
          targetDistro: bsDistro || undefined
        }).then(function (r) {
          if (r && r.ok) {
            setBsState(r.bootstrap || null);
            if (open) {
              fetchBootstrapPreview(false).then(function (prev) {
                var promptText = prev && prev.recommendedSessionPrompt;
                copyClipboardText(promptText);
              });
              setNotice(isEn
                ? "Opened 20m controlled AI bootstrap channel and copied prompt. Paste into chat!"
                : "已开启 20 分钟受控初始化引导通道并复制标准四步会话指令。请回到对话粘贴发给 AI。");
            } else {
              setNotice(isEn ? "Closed bootstrap channel." : "已关闭受控 AI 初始化引导通道。");
            }
            uiCtrl.notifyStatusChanged();
            reload();
          } else {
            setNotice((isEn ? "Failed: " : "引导通道操作失败: ") + ((r && r.error && r.error.message) || ""));
          }
        });
      }

      function triggerOpenOobe() {
        if (onCloseSettings) onCloseSettings();
        uiCtrl.setOobeOpen(true);
      }

      function renderIntroCard() {
        var dict = isEn ? en : zh;
        return h(
          "div",
          {
            className: "dsh-wsl-native-card",
            style: {
              display: "flex",
              justifyContent: "space-between",
              alignItems: "flex-start",
              gap: "12px",
              marginBottom: "12px"
            }
          },
          h(
            "div",
            { style: { flex: 1, minWidth: 0 } },
            h("div", { style: { fontWeight: 600, fontSize: "13.5px", marginBottom: "4px" } }, dict.introTitle),
            h("div", { style: { color: "#9498a3", fontSize: "12px", lineHeight: 1.55 } }, dict.introSummary)
          ),
          h(
            "div",
            { style: { display: "flex", gap: "6px", flexShrink: 0, flexWrap: "wrap" } },
            isMainPanel && uiCtrl.getLayoutService()
              ? h(
                  "button",
                  {
                    className: "dsh-wsl-native-btn",
                    style: { padding: "4px 10px", fontSize: "11.5px" },
                    onClick: function () { uiCtrl.backToChat(); }
                  },
                  isEn ? "Back to Chat" : "返回对话"
                )
              : null,
            h(
              "button",
              {
                className: "dsh-wsl-native-btn",
                style: { padding: "4px 10px", fontSize: "11.5px" },
                onClick: triggerOpenOobe
              },
              isEn ? "Setup Wizard (OOBE)" : "初始化向导 (OOBE)"
            ),
            h(
              "button",
              {
                className: "dsh-wsl-native-btn" + (!isEn ? " dsh-wsl-native-btn-pri" : ""),
                style: { padding: "4px 9px", fontSize: "11.5px" },
                onClick: function () { setIntroLang("zh"); }
              },
              "中文"
            ),
            h(
              "button",
              {
                className: "dsh-wsl-native-btn" + (isEn ? " dsh-wsl-native-btn-pri" : ""),
                style: { padding: "4px 9px", fontSize: "11.5px" },
                onClick: function () { setIntroLang("en"); }
              },
              "EN"
            )
          )
        );
      }

      if (unavail || !cfg) {
        var offlineDict = isEn ? en : zh;
        return h(
          "div",
          { className: "dsh-wsl-native" },
          renderIntroCard(),
          h(
            "div",
            { className: "dsh-wsl-native-panel" },
            h("div", { style: { fontWeight: 600, fontSize: "15px", marginBottom: "8px" } }, isEn ? "WSL 2 Sandbox (dsh-wsl-sandbox)" : "WSL 2 沙箱 (dsh-wsl-sandbox)"),
            h("div", { style: { color: "#9498a3", marginBottom: "10px" } }, offlineDict.offlineHint),
            h(
              "button",
              { className: "dsh-wsl-native-btn", onClick: function () { reload(true); } },
              isEn ? "Retry Connection" : "重试连接控制面"
            )
          )
        );
      }

      var layers = cfg.enabled ? (cfg.enablePwshGuard ? 6 : 5) : 0;

      return h(
        "div",
        { className: "dsh-wsl-native" },
        renderIntroCard(),
        !initialized
          ? h(
              "div",
              {
                className: "dsh-wsl-native-card warn",
                style: { display: "flex", justifyContent: "space-between", alignItems: "center", gap: "12px", flexWrap: "wrap" }
              },
              h(
                "div",
                { style: { flex: 1, minWidth: "240px" } },
                h("div", { style: { fontWeight: 600, color: "#fbbf24", marginBottom: "2px" } }, isEn ? "WSL 2 Environment Not Initialized" : "尚未完成 WSL 2 沙箱初始化"),
                h(
                  "div",
                  { style: { color: "#e5e7eb", fontSize: "12px" } },
                  isEn
                    ? "Sandbox execution stays safely disabled until a real WSL 2 distro is probed, previewed, and provisioned. Open the OOBE wizard to configure in 3 guided steps."
                    : "在探测并完成 WSL 2 发行版环境配置前，沙箱处于安全待就绪态，绝不会误写默认发行版。请点击右侧启动 OOBE 初始化向导。"
                )
              ),
              h(
                "button",
                { className: "dsh-wsl-native-btn dsh-wsl-native-btn-pri", onClick: triggerOpenOobe },
                isEn ? "Launch OOBE Wizard" : "启动 OOBE 初始化向导"
              )
            )
          : null,
        h(
          "div",
          { className: "dsh-wsl-native-tabs" },
          [
            ["status", isEn ? "Status" : "状态"],
            ["approvals", (isEn ? "Approvals (" : "审批队列 (") + pending.length + ")"],
            ["basic", isEn ? "Basic Policy" : "基础策略"],
            ["advanced", isEn ? "Shares & Hardware" : "共享与硬件"],
            ["doctor", isEn ? "WSL Doctor" : "内核体检"],
            ["logs", isEn ? "Runtime Logs" : "运行日志"],
            ["audit", isEn ? "Audit Log" : "审计明细"]
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
          h("span", null, (isEn ? "Distro " : "受控发行版 "), h("b", { className: "dsh-wsl-native-mono" }, cfg.distro + " · " + (cfg.environmentProfile || "standard"))),
          h("span", null, (isEn ? "Workspace " : "工作区 "), h("b", { className: "dsh-wsl-native-mono" }, cfg.workspaceRoot)),
          h("span", null, (isEn ? "Node " : "共用 Node "), h("b", { className: "dsh-wsl-native-mono" }, "Host " + ((nodeRt && nodeRt.hostNodeVersion) || "-") + ((nodeRt && nodeRt.wslNodeVersion) ? (" / WSL " + nodeRt.wslNodeVersion) : " (DSH 进程共用)"))),
          h("span", null, (isEn ? "Isolation " : "隔离层级 "), h("b", null, cfg.enabled ? (isEn ? "bwrap + seccomp + guard" : "bwrap + seccomp + 单壳防呆") : (initialized ? (isEn ? "Disabled" : "已停用") : (isEn ? "Uninitialized" : "待初始化")))),
          h("span", null, (isEn ? "State " : "配置状态 "), h("b", null, cfgDirty ? (isEn ? "Pending Apply" : "待点击应用") : (cfg.enabled ? (isEn ? "Active" : "已生效") : (isEn ? "Off" : "未开启"))))
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
            h("div", { style: { fontSize: "17px", fontWeight: 600 } }, isEn ? "WSL 2 Sandbox Control Surface" : "WSL 2 沙箱控制面"),
            h(
              "div",
              { style: { display: "flex", gap: "8px", flexWrap: "wrap" } },
              h("button", { className: "dsh-wsl-native-btn dsh-wsl-native-btn-pri", onClick: saveConfig }, isEn ? "Apply" : "应用"),
              h("button", { className: "dsh-wsl-native-btn dsh-wsl-native-btn-out-red", onClick: function () { setCfgDirty(false); setBkDirty(false); reload(true); } }, isEn ? "Reset" : "还原"),
              h("button", { className: "dsh-wsl-native-btn dsh-wsl-native-btn-red", onClick: killAll }, isEn ? "Emergency Kill" : "熔断强杀")
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
                    isEn ? " / 6 isolation & host shell defenses active" : " / 6 层内核与单壳防线就位"
                  ),
                  h(
                    "div",
                    { style: { height: "3px", background: "#2b2d35", borderRadius: "99px", margin: "10px 0" } },
                    h("div", { style: { height: "100%", width: Math.round((layers / 6) * 100) + "%", background: "#22c55e", borderRadius: "99px" } })
                  ),
                  h(
                    "div",
                    { className: "dsh-wsl-native-stats" },
                    h("div", { className: "dsh-wsl-native-stat" }, h("div", { style: { color: "#9498a3", fontSize: "11.5px" } }, isEn ? "Active Layers" : "生效防线"), h("div", { style: { fontSize: "18px", fontWeight: 600, color: "#22c55e" } }, String(layers))),
                    h("div", { className: "dsh-wsl-native-stat" }, h("div", { style: { color: "#9498a3", fontSize: "11.5px" } }, isEn ? "Pending Approvals" : "待人工审批"), h("div", { style: { fontSize: "18px", fontWeight: 600, color: "#f59e0b" } }, String(pending.length))),
                    h("div", { className: "dsh-wsl-native-stat" }, h("div", { style: { color: "#9498a3", fontSize: "11.5px" } }, isEn ? "Session Rules" : "会话前缀"), h("div", { style: { fontSize: "18px", fontWeight: 600 } }, String(rules.length))),
                    h("div", { className: "dsh-wsl-native-stat" }, h("div", { style: { color: "#9498a3", fontSize: "11.5px" } }, isEn ? "Shares / Devices" : "共享 / 硬件"), h("div", { style: { fontSize: "18px", fontWeight: 600 } }, cfg.advanced.shares.length + " / " + cfg.advanced.deviceNodes.length))
                  )
                ),
                h(
                  "div",
                  { className: "dsh-wsl-native-grid2" },
                  [
                    ["enabled", isEn ? "WSL 2 Sandbox Backend" : "WSL 2 沙箱后端", isEn ? "Routes wsl_* tools into Linux namespace execution." : "接管 wsl_* 工具并在 Linux 内核命名空间内隔离执行。"],
                    ["enablePwshGuard", isEn ? "Host Single-Shell AST Guard" : "宿主终端单壳与方言守卫", isEn ? "Blocks nested cmd inside pwsh, legacy aliases, 2>nul & UNC escapes." : "硬拦截 pwsh 套 cmd、混用 powershell.exe、/s /q、2>nul 与 UNC 越界。"],
                    ["enablePromptInjection", isEn ? "System Prompt Routing" : "系统提示词路由注入", isEn ? "Registers order 4200 (interpolate: false) WSL-first guidance." : "以 order 4200 (interpolate: false) 引导优先使用 wsl_*。"],
                    ["mirrorCn", isEn ? "CN Registry Mirror Env" : "国内镜像源环境变量", isEn ? "Injects npm/pip/uv/cargo/go CN mirror env inside sandbox." : "为沙箱内 npm/pip/uv/cargo/go 自动注入加速镜像源。"]
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
                      { style: { marginBottom: "4px" } },
                      h("b", null, isEn ? "Host Drive Masking (--tmpfs /mnt) & Read-Only WSL Config Backup · " : "禁用 Windows 全盘挂载 (C:\\ / D:\\) 与原始 WSL 配置备份 · "),
                      h("span", { style: { color: "#22c55e", fontSize: "12px" } }, isEn ? "Locked" : "沙箱 --tmpfs /mnt 与配置目录遮蔽已锁死")
                    ),
                    h(
                      "div",
                      { style: { color: "#9498a3", fontSize: "11.5px", marginBottom: "8px" } },
                      "WSL Settings 与 WSL Manager 共用 %USERPROFILE%\\.wslconfig 与 /etc/wsl.conf；本插件绝不自动改写原配置，备份以只读权限保存。"
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
                      h("button", { className: "dsh-wsl-native-btn", onClick: pickBackupDir }, isEn ? "Browse..." : "选择目录..."),
                      h("button", { className: "dsh-wsl-native-btn dsh-wsl-native-btn-pri", onClick: backupWslConfigs }, isEn ? "Backup Now" : "立即备份"),
                      h("button", { className: "dsh-wsl-native-btn", onClick: function () { openInExplorer(bkDir, false); } }, isEn ? "Open Folder" : "打开备份目录")
                    ),
                    bkItems.length === 0
                      ? h("div", { style: { color: "#9498a3", fontSize: "12px" } }, isEn ? "No backups yet." : "暂无原始配置快照，点击「立即备份」保存到上方自定义目录。")
                      : bkItems.map(function (it) {
                          return h(
                            "div",
                            { key: it.explorerPath, style: { display: "flex", justifyContent: "space-between", alignItems: "center", gap: "8px", padding: "4px 0", borderTop: "1px solid rgba(255,255,255,0.05)" } },
                            h("span", { className: "dsh-wsl-native-mono", style: { fontSize: "12px" } }, it.name + "  (" + it.explorerPath + ")"),
                            h("button", { className: "dsh-wsl-native-btn", style: { padding: "3px 10px" }, onClick: function () { openInExplorer(it.explorerPath, true); } }, isEn ? "Locate" : "在资源管理器中定位")
                          );
                        })
                  ),
                  h("div", { style: { fontWeight: 600, marginBottom: "6px" } }, isEn ? "Quick Single-Directory Mount (/shares/<alias>)" : "指定单目录快捷挂载（直接粘贴 Windows 文件夹如 D:\\Datasets\\Project）"),
                  h(
                    "div",
                    { style: { display: "flex", gap: "8px", flexWrap: "wrap", marginBottom: "8px" } },
                    h("input", {
                      className: "dsh-wsl-native-in dsh-wsl-native-mono",
                      style: { flex: "1", minWidth: "200px" },
                      placeholder: "D:\\Datasets\\Project 或 /mnt/d/...",
                      value: qPath,
                      onChange: function (e) { setQPath(e.target.value); }
                    }),
                    h("input", {
                      className: "dsh-wsl-native-in dsh-wsl-native-mono",
                      style: { width: "130px" },
                      placeholder: isEn ? "alias" : "别名(可选)",
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
                      h("option", { value: "ro" }, isEn ? "ro" : "只读 (ro)"),
                      h("option", { value: "rw" }, isEn ? "rw" : "读写 (rw)")
                    ),
                    h("button", { className: "dsh-wsl-native-btn dsh-wsl-native-btn-pri", onClick: quickMountShare }, isEn ? "Mount" : "挂载此目录")
                  ),
                  cfg.advanced.shares.length === 0
                    ? h("div", { style: { color: "#9498a3", fontSize: "12px" } }, isEn ? "No mounted shares (all Windows drives masked)." : "当前无挂载目录（Windows 各盘符全盘已对 AI 遮蔽）。")
                    : cfg.advanced.shares.map(function (s) {
                        return h(
                          "div",
                          { key: s.id, style: { display: "flex", justifyContent: "space-between", alignItems: "center", padding: "5px 0", borderTop: "1px solid rgba(255,255,255,0.05)" } },
                          h("span", { className: "dsh-wsl-native-mono", style: { fontSize: "12px" } }, "/shares/" + s.alias + " <- " + s.sourceLinuxPath + " (" + s.mode + ")"),
                          h("button", { className: "dsh-wsl-native-btn dsh-wsl-native-btn-out-red", style: { padding: "3px 10px" }, onClick: function () { revokeShare(s.id); } }, isEn ? "Revoke" : "取消挂载")
                        );
                      })
                ),
                h(
                  "div",
                  { className: "dsh-wsl-native-card", style: { marginTop: "2px", borderColor: "rgba(255,255,255,0.12)" } },
                  h(
                    "div",
                    { style: { display: "flex", justifyContent: "space-between", alignItems: "center", gap: "8px", flexWrap: "wrap", marginBottom: "6px" } },
                    h(
                      "div",
                      null,
                      h("b", null, isEn ? "Controlled AI Bootstrap Channel & Script Preview · " : "受控 AI 初始化引导与安装脚本预览 · "),
                      h(
                        "span",
                        { style: { color: (bsState && bsState.active) ? "#22c55e" : "#9498a3", fontSize: "12px" } },
                        (bsState && bsState.active)
                          ? ("已开启 [" + bsState.phase + (bsState.targetDistro ? (" · " + bsState.targetDistro) : "") + "]")
                          : (isEn ? "Locked (L0)" : "常态 L0 锁定关闭")
                      )
                    ),
                    h(
                      "div",
                      { style: { display: "flex", gap: "6px", flexWrap: "wrap" } },
                      h("button", { className: "dsh-wsl-native-btn", onClick: function () { fetchBootstrapPreview(true); } }, isEn ? "Preview Scripts & SHA-256" : "预览安装脚本"),
                      h("button", { className: "dsh-wsl-native-btn dsh-wsl-native-btn-pri", onClick: function () { toggleBootstrapChannel(true); } }, isEn ? "Open Channel & Copy Prompt" : "开启引导通道"),
                      (bsState && bsState.active)
                        ? h("button", { className: "dsh-wsl-native-btn dsh-wsl-native-btn-out-red", onClick: function () { toggleBootstrapChannel(false); } }, isEn ? "Close" : "关闭")
                        : null
                    )
                  ),
                  h(
                    "div",
                    { style: { color: "#9498a3", fontSize: "11.5px", marginBottom: "8px" } },
                    isEn
                      ? "Default L0 blocks autonomous installer execution. Opening the 20m bootstrap channel enforces: 1) Probe -> 2) -DryRun Preview Card -> 3) Single-Shot Install Approval -> 4) dsh-wsl-doctor. Recommended network mode: default WSL NAT."
                      : "默认常态 L0 禁止 AI 私自运行安装脚本；开启 20 分钟引导通道后强制按「1 只读探测 -> 2 -DryRun 预览卡片确认 -> 3 单次审批安装 -> 4 doctor 闭环自动关闸」推进，常规测试推荐保持 WSL 默认 NAT 网络。"
                  ),
                  h(
                    "div",
                    { style: { display: "flex", gap: "8px", flexWrap: "wrap", alignItems: "center", marginBottom: "6px" } },
                    h("input", {
                      className: "dsh-wsl-native-in dsh-wsl-native-mono",
                      style: { maxWidth: "240px" },
                      placeholder: "锁定目标发行版（如 Ubuntu-24.04）",
                      value: bsDistro,
                      onChange: function (e) { setBsDistro(e.target.value); }
                    })
                  ),
                  (bsPreview && bsPreview.scripts && bsPreview.scripts.length > 0)
                    ? h(
                        "div",
                        { style: { marginTop: "8px", borderTop: "1px solid rgba(255,255,255,0.08)", paddingTop: "8px" } },
                        h(
                          "div",
                          { style: { display: "flex", gap: "6px", flexWrap: "wrap", marginBottom: "6px" } },
                          bsPreview.scripts.map(function (sc, idx) {
                            return h(
                              "button",
                              {
                                key: sc.id,
                                className: "dsh-wsl-native-btn" + (bsScriptIdx === idx ? " dsh-wsl-native-btn-pri" : ""),
                                style: { padding: "3px 9px", fontSize: "11.5px" },
                                onClick: function () { setBsScriptIdx(idx); }
                              },
                              sc.relPath
                            );
                          })
                        ),
                        (function () {
                          var curSc = bsPreview.scripts[bsScriptIdx] || bsPreview.scripts[0];
                          return curSc
                            ? h(
                                "div",
                                null,
                                h("div", { className: "dsh-wsl-native-mono", style: { fontSize: "11px", color: "#9498a3", marginBottom: "4px" } }, curSc.title + " · SHA-256: " + (curSc.sha256 || "-") + " · " + curSc.lines + " 行"),
                                h("pre", { className: "dsh-wsl-native-in dsh-wsl-native-mono", style: { maxHeight: "200px", overflow: "auto", whiteSpace: "pre" } }, curSc.content || "")
                              )
                            : null;
                        })()
                      )
                    : null
                )
              )
            : null,
          tab === "approvals"
            ? h(
                "div",
                null,
                pending.length === 0
                  ? h("div", { className: "dsh-wsl-native-card", style: { color: "#9498a3" } }, isEn ? "No pending manual approvals." : "当前没有待处理的人工审批请求。")
                  : pending.map(function (p) {
                      return h(
                        "div",
                        { key: p.requestId, className: "dsh-wsl-native-card" },
                        h("div", { style: { fontWeight: 600, marginBottom: "6px" } }, p.summary),
                        h("pre", { className: "dsh-wsl-native-in dsh-wsl-native-mono", style: { overflowX: "auto", marginBottom: "8px" } }, p.command || ""),
                        h(
                          "div",
                          { style: { display: "flex", gap: "8px", flexWrap: "wrap" } },
                          h("button", { className: "dsh-wsl-native-btn dsh-wsl-native-btn-pri", onClick: function () { decide(p.requestId, "allow-once"); } }, isEn ? "Allow Once" : "允许一次"),
                          h(
                            "button",
                            {
                              className: "dsh-wsl-native-btn",
                              disabled: Boolean(p.touchesPhysicalDevice || !p.allowSessionRuleOption),
                              onClick: function () { decide(p.requestId, "allow-session-rule"); }
                            },
                            p.touchesPhysicalDevice ? (isEn ? "Hardware Single-Shot Locked" : "硬件强制单次锁") : (isEn ? "Allow Session Prefix" : "本会话允许前缀")
                          ),
                          h("button", { className: "dsh-wsl-native-btn dsh-wsl-native-btn-out-red", onClick: function () { decide(p.requestId, "deny"); } }, isEn ? "Deny" : "拒绝")
                        )
                      );
                    })
              )
            : null,
          tab === "basic"
            ? h(
                "div",
                null,
                h(
                  "div",
                  { className: "dsh-wsl-native-card", style: { marginBottom: "10px", padding: "10px 12px" } },
                  h("div", { style: { fontSize: "12px", color: "#9498a3", marginBottom: "6px" } }, isEn ? "On-demand scan (never auto-launches WSL on UI open). Supports standard & WSL Manager moved distros:" : "按需探测已注册的 WSL 2 发行版（绝不在打开界面时私自唤醒 WSL，支持 WSL Manager 迁移实例）："),
                  h(
                    "div",
                    { style: { display: "flex", gap: "8px", flexWrap: "wrap" } },
                    h(
                      "select",
                      {
                        className: "dsh-wsl-native-in dsh-wsl-native-mono",
                        style: { flex: "1", minWidth: "220px" },
                        value: distros.some(function (d) { return d.name === cfg.distro; }) ? cfg.distro : "",
                        onChange: function (e) { selectDiscoveredDistro(e.target.value); }
                      },
                      h("option", { value: "" }, distros.length ? "-- 选择已探测的 WSL 发行版 --" : (isEn ? "-- Click Scan Distros or enter manually below --" : "-- 点击右侧「扫描/刷新实例」或直接在下方手动填写 --")),
                      distros.map(function (d) {
                        var label = d.name + " (WSL " + d.wslVersion + " · " + d.state + (d.isDefault ? " · 默认" : "") + (d.isCustomDiskLocation ? " · 已迁移" : "") + ")";
                        return h("option", { key: d.name, value: d.name }, label);
                      })
                    ),
                    h("button", { className: "dsh-wsl-native-btn", onClick: function () { loadDistros(true); } }, isEn ? "Scan Distros" : "扫描/刷新实例")
                  )
                ),
                h(
                  "div",
                  { className: "dsh-wsl-native-grid2" },
                  h("div", null, h("div", null, isEn ? "WSL Distro" : "WSL 发行版"), h("input", { className: "dsh-wsl-native-in dsh-wsl-native-mono", value: cfg.distro, onChange: function (e) { updateField("distro", e.target.value); } })),
                  h(
                    "div",
                    null,
                    h("div", null, isEn ? "Toolchain Profile" : "工具链环境档位"),
                    h(
                      "select",
                      { className: "dsh-wsl-native-in", value: cfg.environmentProfile || "standard", onChange: function (e) { updateField("environmentProfile", e.target.value); } },
                      h("option", { value: "core" }, "core (~350MB 基础)"),
                      h("option", { value: "standard" }, "standard (~1.2GB 推荐)"),
                      h("option", { value: "universal" }, "universal (~3.5GB 全语言)")
                    )
                  ),
                  h("div", null, h("div", null, isEn ? "Workspace Root (ext4)" : "工作区根目录 (原生 ext4)"), h("input", { className: "dsh-wsl-native-in dsh-wsl-native-mono", value: cfg.workspaceRoot, onChange: function (e) { updateField("workspaceRoot", e.target.value); } })),
                  h("div", null, h("div", null, isEn ? "Sandbox Mode" : "沙箱模式"), h("select", { className: "dsh-wsl-native-in", value: cfg.sandboxMode, onChange: function (e) { updateField("sandboxMode", e.target.value); } }, h("option", { value: "workspace-write" }, "workspace-write"), h("option", { value: "read-only" }, "read-only"))),
                  h("div", null, h("div", null, isEn ? "Approval Policy" : "审批策略"), h("select", { className: "dsh-wsl-native-in", value: cfg.approvalPolicyMode, onChange: function (e) { updateField("approvalPolicyMode", e.target.value); } }, h("option", { value: "balanced" }, "balanced"), h("option", { value: "strict" }, "strict"), h("option", { value: "trust-workspace" }, "trust-workspace"))),
                  h("div", null, h("div", null, isEn ? "Network Isolation" : "网络隔离模式"), h("select", { className: "dsh-wsl-native-in", value: cfg.networkMode, onChange: function (e) { updateField("networkMode", e.target.value); } }, h("option", { value: "allowlist-proxy" }, "allowlist-proxy"), h("option", { value: "offline" }, "offline"))),
                  h(
                    "div",
                    null,
                    h("div", null, isEn ? "Log Level" : "运行日志级别 (2.5s 合并落盘)"),
                    h(
                      "select",
                      { className: "dsh-wsl-native-in", value: cfg.logLevel || "info", onChange: function (e) { updateField("logLevel", e.target.value); } },
                      h("option", { value: "info" }, "info (默认推荐)"),
                      h("option", { value: "warn" }, "warn (仅告警)"),
                      h("option", { value: "error" }, "error (仅错误)"),
                      h("option", { value: "debug" }, "debug (排障)")
                    )
                  ),
                  h("div", null, h("div", null, isEn ? "Upstream Proxy" : "上游代理"), h("input", { className: "dsh-wsl-native-in dsh-wsl-native-mono", value: cfg.upstreamProxy || "", onChange: function (e) { updateField("upstreamProxy", e.target.value); } }))
                )
              )
            : null,
          tab === "advanced"
            ? h(
                "div",
                { className: "dsh-wsl-native-card" },
                h("div", { style: { marginBottom: "8px", color: "#9498a3" } }, isEn ? "Authorized /shares and physical device passthrough are disabled by default. Manage single-directory mounts from the Status tab above." : "受控单目录挂载 (/shares) 与物理串口/USB 设备透传默认关闭；可在「状态」页快速授权或立即吊销单目录共享。"),
                h("div", { className: "dsh-wsl-native-mono" }, (isEn ? "Shares: " : "当前共享数: ") + cfg.advanced.shares.length + " · " + (isEn ? "Devices: " : "当前物理设备数: ") + cfg.advanced.deviceNodes.length)
              )
            : null,
          tab === "doctor"
            ? h(
                "div",
                null,
                h("button", { className: "dsh-wsl-native-btn", style: { marginBottom: "10px" }, onClick: runDoctor }, isEn ? "Run dsh-wsl-doctor" : "运行 dsh-wsl-doctor 实时自检"),
                doc
                  ? h("pre", { className: "dsh-wsl-native-in dsh-wsl-native-mono", style: { maxHeight: "300px", overflow: "auto" } }, JSON.stringify(doc, null, 2))
                  : null
              )
            : null,
          tab === "logs"
            ? h(
                "div",
                null,
                h(
                  "div",
                  { className: "dsh-wsl-native-card", style: { marginBottom: "10px" } },
                  h(
                    "div",
                    { style: { display: "flex", gap: "8px", flexWrap: "wrap", marginBottom: "8px" } },
                    h(
                      "select",
                      {
                        className: "dsh-wsl-native-in",
                        style: { width: "130px" },
                        value: logLvl,
                        onChange: function (e) { setLogLvl(e.target.value); }
                      },
                      h("option", { value: "debug" }, "全部级别"),
                      h("option", { value: "info" }, "INFO 及以上"),
                      h("option", { value: "warn" }, "WARN 及以上"),
                      h("option", { value: "error" }, "仅 ERROR")
                    ),
                    h("input", {
                      className: "dsh-wsl-native-in dsh-wsl-native-mono",
                      style: { flex: "1", minWidth: "180px" },
                      placeholder: isEn ? "Filter events or text..." : "过滤事件或关键字...",
                      value: logQ,
                      onChange: function (e) { setLogQ(e.target.value); }
                    }),
                    h("button", { className: "dsh-wsl-native-btn", onClick: loadLogs }, isEn ? "Refresh" : "刷新"),
                    h("button", {
                      className: "dsh-wsl-native-btn",
                      onClick: function () {
                        downloadNdjsonLogs(function (ok, errMsg) {
                          setNotice(ok ? (isEn ? "Downloaded NDJSON logs." : "已导出 NDJSON 日志文件。") : ("导出失败: " + errMsg));
                        });
                      }
                    }, isEn ? "Export NDJSON" : "导出 NDJSON"),
                    h("button", { className: "dsh-wsl-native-btn dsh-wsl-native-btn-out-red", onClick: clearAllLogs }, isEn ? "Clear" : "清空日志")
                  ),
                  h(
                    "div",
                    { className: "dsh-wsl-native-mono", style: { fontSize: "11.5px", color: "#9498a3" } },
                    "纯内存读取零读盘 · 累计合并落盘 " + ((logStats && logStats.diskFlushCount) || 0) + " 次 · 文件: " + ((logStats && logStats.logFilePath) || "内存模式")
                  )
                ),
                h(
                  "div",
                  { className: "dsh-wsl-native-card", style: { maxHeight: "340px", overflow: "auto" } },
                  logs.length === 0
                    ? h("div", { style: { color: "#9498a3" } }, isEn ? "No matching log entries." : "暂无匹配日志。")
                    : logs.slice().reverse().map(function (e) {
                        var col = e.level === "error" ? "#e06c65" : (e.level === "warn" ? "#f59e0b" : (e.level === "info" ? "#60a5fa" : "#9498a3"));
                        return h(
                          "div",
                          { key: e.seq, className: "dsh-wsl-native-mono", style: { padding: "5px 0", borderBottom: "1px solid rgba(255,255,255,0.05)", fontSize: "12px" } },
                          h("span", { style: { color: "#9498a3" } }, String(e.timestamp || "").replace("T", " ").slice(0, 19) + " "),
                          h("span", { style: { color: col, fontWeight: 600 } }, "[" + String(e.level || "").toUpperCase() + "] "),
                          h("span", { style: { color: "#9498a3" } }, e.source + ":" + e.component + " (" + e.event + ") "),
                          h("span", null, e.message)
                        );
                      })
                )
              )
            : null,
          tab === "audit"
            ? h(
                "div",
                { className: "dsh-wsl-native-card" },
                audit.length === 0
                  ? h("div", { style: { color: "#9498a3" } }, isEn ? "No audit records yet." : "暂无审计记录。")
                  : audit.slice(-15).reverse().map(function (r, idx) {
                      return h("div", { key: idx, className: "dsh-wsl-native-mono", style: { padding: "5px 0", borderBottom: "1px solid rgba(255,255,255,0.05)" } }, r.timestamp + " · " + r.kind + " -> " + r.outcome);
                    })
              )
            : null
        )
      );
    }

    // 左侧边栏主面板全屏滚动包装
    function WslSandboxMainPanel() {
      return h(
        "div",
        { className: "dsh-wsl-main-wrap" },
        h(WslSandboxSection, { isMainPanel: true })
      );
    }

    // 首次安装自动 OOBE 弹窗 + 全局待审批浮层（挂载在 root shell.overlay）
    function WslGlobalOverlay() {
      var _langPair = useUiLang(), lang = _langPair[0], setLang = _langPair[1];
      var isEn = lang === "en";
      var _open = useState(uiCtrl.getOobeOpen()), open = _open[0], setOpen = _open[1];
      var _step = useState(1), step = _step[0], setStep = _step[1];
      var _distro = useState(""), distro = _distro[0], setDistro = _distro[1];
      var _profile = useState("standard"), profile = _profile[0], setProfile = _profile[1];
      var _mirrorCn = useState(false), mirrorCn = _mirrorCn[0], setMirrorCn = _mirrorCn[1];
      var _proxy = useState(""), proxy = _proxy[0], setProxy = _proxy[1];
      var _distros = useState([]), distros = _distros[0], setDistros = _distros[1];
      var _scanning = useState(false), scanning = _scanning[0], setScanning = _scanning[1];
      var _preview = useState(null), preview = _preview[0], setPreview = _preview[1];
      var _scriptIdx = useState(0), scriptIdx = _scriptIdx[0], setScriptIdx = _scriptIdx[1];
      var _statusMsg = useState(""), statusMsg = _statusMsg[0], setStatusMsg = _statusMsg[1];
      var _initialized = useState(false), initialized = _initialized[0], setInitialized = _initialized[1];
      var _pending = useState([]), pending = _pending[0], setPending = _pending[1];
      var overlayInitRef = useState({ autoChecked: false, distroSynced: false })[0];

      useEffect(function () {
        return uiCtrl.subscribeOobe(function (v) {
          setOpen(v);
          if (v) {
            setStep(1);
            setStatusMsg("");
          }
        });
      }, []);

      var pollStatusAndApprovals = useCallback(function () {
        Promise.all([
          apiFetch("GET", "/wsl-sandbox/api/status"),
          apiFetch("GET", "/wsl-sandbox/api/approvals")
        ])
          .then(function (res) {
            var st = res[0];
            var ap = res[1];
            if (st && st.ok) {
              setInitialized(Boolean(st.initialized));
              if (st.config) {
                if (!overlayInitRef.distroSynced && st.config.distro) {
                  overlayInitRef.distroSynced = true;
                  setDistro(st.config.distro);
                }
                if (st.config.environmentProfile) setProfile(st.config.environmentProfile);
                if (st.config.mirrorCn !== undefined) setMirrorCn(Boolean(st.config.mirrorCn));
              }
              if (!overlayInitRef.autoChecked) {
                overlayInitRef.autoChecked = true;
                if (st.oobeNeeded === true) {
                  uiCtrl.setOobeOpen(true);
                }
              }
            }
            if (ap && ap.ok) {
              setPending(ap.pending || []);
            }
          })
          .catch(function () {});
      }, [overlayInitRef]);

      useEffect(function () {
        pollStatusAndApprovals();
        var unsub = uiCtrl.subscribeStatusChanged(pollStatusAndApprovals);
        var timer = setInterval(function () {
          if (typeof document !== "undefined" && document.hidden) return;
          pollStatusAndApprovals();
        }, 5000);
        return function () {
          unsub();
          clearInterval(timer);
        };
      }, [pollStatusAndApprovals]);

      function scanLocalDistros() {
        setScanning(true);
        setStatusMsg(isEn ? "Scanning registered WSL 2 distros..." : "正在按需扫描本机 WSL 2 发行版...");
        apiFetch("GET", "/wsl-sandbox/api/distros")
          .then(function (r) {
            setScanning(false);
            if (r && r.ok) {
              var list = (r.distros || []).filter(function (d) { return !d.isInternalContainer; });
              setDistros(list);
              if (r.recommendedDistro && (!distro || distro === "Ubuntu-26.04")) {
                setDistro(r.recommendedDistro);
              }
              setStatusMsg(
                list.length > 0
                  ? (isEn ? ("Found " + list.length + " WSL distro(s).") : ("已发现 " + list.length + " 个可用 WSL 实例，请确认目标发行版。"))
                  : (isEn ? "No WSL 2 distros found yet; you can install one via PowerShell 7 in Step 3." : "暂未发现已安装发行版，可在第 3 步通过 PowerShell 脚本自动拉起或手动指定名称。")
              );
            } else {
              setStatusMsg((isEn ? "Scan failed: " : "探测失败: ") + ((r && r.error && r.error.message) || ""));
            }
          })
          .catch(function (err) {
            setScanning(false);
            setStatusMsg((isEn ? "Scan error: " : "探测异常: ") + (err && err.message ? err.message : String(err)));
          });
      }

      function goToPreviewStep() {
        var mirror = mirrorCn ? "cn" : "global";
        var qs =
          "?distro=" + encodeURIComponent(distro || "Ubuntu-24.04") +
          "&profile=" + encodeURIComponent(profile || "standard") +
          "&mirror=" + encodeURIComponent(mirror);
        apiFetch("GET", "/wsl-sandbox/api/bootstrap-preview" + qs).then(function (r) {
          if (r && r.ok) {
            setPreview(r);
            setStep(2);
            setStatusMsg("");
          } else {
            setStatusMsg((isEn ? "Preview failed: " : "加载脚本预览失败: ") + ((r && r.error && r.error.message) || ""));
          }
        });
      }

      function startAiControlledBootstrap() {
        var target = (distro || "").trim() || undefined;
        apiFetch("POST", "/wsl-sandbox/api/bootstrap-session", {
          action: "open",
          targetDistro: target
        }).then(function (r) {
          if (!r || !r.ok) {
            setStatusMsg((isEn ? "Failed opening channel: " : "开启受控通道失败: ") + ((r && r.error && r.error.message) || ""));
            return;
          }
          apiFetch("POST", "/wsl-sandbox/api/oobe", {
            action: "complete",
            distro: target,
            environmentProfile: profile,
            mirrorCn: mirrorCn,
            upstreamProxy: proxy,
            enableNow: false
          }).then(function () {
            var promptTxt = (preview && preview.recommendedSessionPrompt) ||
              ("请按照 dsh-wsl-env-setup 四步安全协议协助完成目标 WSL 2 发行版「" + (target || "Ubuntu-24.04") + "」的环境初始化。");
            copyClipboardText(promptTxt);
            setStatusMsg(isEn
              ? "20m AI bootstrap channel opened & prompt copied! Switching to chat so you can paste."
              : "已开启 20 分钟 AI 受控引导通道并复制四步指令，正在关闭向导并返回对话，直接粘贴发送即可。");
            uiCtrl.notifyStatusChanged();
            setTimeout(function () {
              uiCtrl.setOobeOpen(false);
              uiCtrl.backToChat();
            }, 600);
          });
        });
      }

      function verifyManualReload() {
        apiFetch("POST", "/wsl-sandbox/api/bootstrap-session", { action: "reload" }).then(function () {
          apiFetch("GET", "/wsl-sandbox/api/status").then(function (st) {
            if (st && st.ok && st.initialized) {
              setInitialized(true);
              setStatusMsg(isEn ? "Detected completed setup! Sandbox is ready." : "已检测到落盘安装清单，WSL 2 沙箱配置已就绪！");
              uiCtrl.notifyStatusChanged();
            } else {
              setStatusMsg(isEn
                ? "install-manifest.json not detected yet. Finish running install-dsh-plugin.ps1 first."
                : "尚未检测到 install-manifest.json，请先在 PowerShell 7 终端执行上方安装命令后再点此校验。");
            }
          });
        });
      }

      function dismissOobe() {
        apiFetch("POST", "/wsl-sandbox/api/oobe", { action: "dismiss" }).then(function () {
          uiCtrl.setOobeOpen(false);
          uiCtrl.notifyStatusChanged();
        });
      }

      function decideToast(requestId, decision) {
        apiFetch("POST", "/wsl-sandbox/api/approvals/" + encodeURIComponent(requestId) + "/decide", {
          decision: decision
        }).then(function () {
          uiCtrl.notifyStatusChanged();
          pollStatusAndApprovals();
        });
      }

      var oobeNode = open
        ? h(
            "div",
            {
              className: "dsh-wsl-oobe-backdrop",
              role: "dialog",
              "aria-modal": "true"
            },
            h(
              "div",
              { className: "dsh-wsl-oobe-modal" },
              h(
                "div",
                { style: { display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: "12px", marginBottom: "14px" } },
                h(
                  "div",
                  null,
                  h("div", { style: { fontSize: "17px", fontWeight: 700 } }, isEn ? "WSL 2 Sandbox Setup Wizard (OOBE)" : "WSL 2 内核沙箱首次安装引导 (OOBE)"),
                  h("div", { style: { color: "#9498a3", fontSize: "12px", marginTop: "2px" } }, isEn ? "Safe 3-step initialization: Probe on-demand -> Preview Scripts -> Start Setup" : "安全三步初始化：按需探测发行版 -> 审阅脚本与 SHA-256 -> 选择 AI 引导或手动安装")
                ),
                h(
                  "div",
                  { style: { display: "flex", gap: "6px", flexShrink: 0 } },
                  h("button", { className: "dsh-wsl-native-btn" + (!isEn ? " dsh-wsl-native-btn-pri" : ""), style: { padding: "4px 9px", fontSize: "11.5px" }, onClick: function () { setLang("zh"); } }, "中文"),
                  h("button", { className: "dsh-wsl-native-btn" + (isEn ? " dsh-wsl-native-btn-pri" : ""), style: { padding: "4px 9px", fontSize: "11.5px" }, onClick: function () { setLang("en"); } }, "EN"),
                  h("button", { className: "dsh-wsl-native-btn", style: { padding: "4px 9px", fontSize: "11.5px" }, onClick: dismissOobe }, isEn ? "Close" : "关闭")
                )
              ),
              h(
                "div",
                { style: { display: "flex", gap: "8px", marginBottom: "16px", flexWrap: "wrap" } },
                [
                  [1, isEn ? "1. Distro & Profile" : "1. 探测与环境选型"],
                  [2, isEn ? "2. Script & SHA-256" : "2. 脚本与哈希预览"],
                  [3, isEn ? "3. Initialize" : "3. 启动安全安装"]
                ].map(function (it) {
                  var active = step === it[0];
                  return h(
                    "span",
                    {
                      key: it[0],
                      className: "dsh-wsl-native-pill",
                      style: {
                        background: active ? "#f4f5f7" : "transparent",
                        color: active ? "#111214" : "#9498a3",
                        fontWeight: active ? 600 : 400
                      }
                    },
                    it[1]
                  );
                })
              ),
              statusMsg
                ? h("div", { className: "dsh-wsl-native-card", style: { padding: "9px 12px", color: "#e5e7eb" } }, statusMsg)
                : null,
              step === 1
                ? h(
                    "div",
                    null,
                    h(
                      "div",
                      { className: "dsh-wsl-native-card" },
                      h("div", { style: { fontWeight: 600, marginBottom: "8px" } }, isEn ? "Target WSL 2 Distribution (On-Demand Scan)" : "目标 WSL 2 发行版（点击才扫描，绝不私自拉起 WSL）"),
                      h(
                        "div",
                        { style: { display: "flex", gap: "8px", flexWrap: "wrap", marginBottom: "8px" } },
                        h("input", {
                          className: "dsh-wsl-native-in dsh-wsl-native-mono",
                          style: { flex: "1", minWidth: "220px" },
                          placeholder: "例如 Ubuntu-24.04 / Debian / AI workspace",
                          value: distro,
                          onChange: function (e) { setDistro(e.target.value); }
                        }),
                        h("button", { className: "dsh-wsl-native-btn dsh-wsl-native-btn-pri", disabled: scanning, onClick: scanLocalDistros }, scanning ? (isEn ? "Scanning..." : "扫描中...") : (isEn ? "Scan WSL 2 Distros" : "扫描本机 WSL 发行版"))
                      ),
                      distros.length > 0
                        ? h(
                            "div",
                            { style: { display: "flex", gap: "6px", flexWrap: "wrap", marginTop: "6px" } },
                            distros.map(function (d) {
                              var sel = d.name === distro;
                              return h(
                                "button",
                                {
                                  key: d.name,
                                  className: "dsh-wsl-native-btn" + (sel ? " dsh-wsl-native-btn-pri" : ""),
                                  style: { padding: "4px 10px", fontSize: "12px" },
                                  onClick: function () { setDistro(d.name); }
                                },
                                d.name + " (WSL " + d.wslVersion + (d.isDefault ? " · 默认" : "") + ")"
                              );
                            })
                          )
                        : null
                    ),
                    h(
                      "div",
                      { className: "dsh-wsl-native-grid2", style: { marginBottom: "12px" } },
                      h(
                        "div",
                        null,
                        h("div", { style: { marginBottom: "4px", fontWeight: 600 } }, isEn ? "Toolchain Profile" : "工具链环境档位"),
                        h(
                          "select",
                          { className: "dsh-wsl-native-in", value: profile, onChange: function (e) { setProfile(e.target.value); } },
                          h("option", { value: "core" }, "core (~350MB: 沙箱核心 + Node 共用 + C/C++/Python)"),
                          h("option", { value: "standard" }, "standard (~1.2GB 推荐: + pnpm/uv/Go/Rust/golangci)"),
                          h("option", { value: "universal" }, "universal (~3.5GB 全语言: + clang/bazel/JDK/Ruby)")
                        )
                      ),
                      h(
                        "div",
                        null,
                        h("div", { style: { marginBottom: "4px", fontWeight: 600 } }, isEn ? "Upstream Proxy (Optional)" : "上游代理（可选 HTTP / SOCKS5）"),
                        h("input", {
                          className: "dsh-wsl-native-in dsh-wsl-native-mono",
                          placeholder: "http://127.0.0.1:7890 (留空则直连)",
                          value: proxy,
                          onChange: function (e) { setProxy(e.target.value); }
                        })
                      )
                    ),
                    h(
                      "label",
                      { style: { display: "flex", alignItems: "center", gap: "8px", marginBottom: "10px", cursor: "pointer" } },
                      h("input", { type: "checkbox", checked: mirrorCn, onChange: function (e) { setMirrorCn(e.target.checked); } }),
                      h("span", null, isEn ? "Use CN package mirrors (apt/npmmirror/tuna) during provisioning" : "初始化与沙箱运行时启用国内镜像源加速（npmmirror / tuna / ustc）")
                    ),
                    h(
                      "div",
                      { style: { color: "#9498a3", fontSize: "12px", marginBottom: "16px" } },
                      isEn
                        ? "Note: Default WSL 2 NAT networking is recommended for normal testing and USB/ADB debugging; mirrored networking is never forced."
                        : "网络说明：常规开发测试与手机/USB 硬件联调推荐保持 WSL 2 默认 NAT 网络模式，无需强制改为 mirrored，绝不自动篡改 %USERPROFILE%\\.wslconfig。"
                    ),
                    h(
                      "div",
                      { style: { display: "flex", justifyContent: "space-between", gap: "8px" } },
                      h("button", { className: "dsh-wsl-native-btn", onClick: dismissOobe }, isEn ? "Configure Later" : "稍后配置"),
                      h("button", { className: "dsh-wsl-native-btn dsh-wsl-native-btn-pri", onClick: goToPreviewStep }, isEn ? "Next: Preview Scripts & SHA-256 ->" : "下一步：预览安装脚本与 SHA-256 ->")
                    )
                  )
                : null,
              step === 2 && preview
                ? h(
                    "div",
                    null,
                    h(
                      "div",
                      { style: { display: "flex", gap: "6px", flexWrap: "wrap", marginBottom: "8px" } },
                      (preview.scripts || []).map(function (sc, idx) {
                        return h(
                          "button",
                          {
                            key: sc.id,
                            className: "dsh-wsl-native-btn" + (scriptIdx === idx ? " dsh-wsl-native-btn-pri" : ""),
                            style: { padding: "4px 10px", fontSize: "11.5px" },
                            onClick: function () { setScriptIdx(idx); }
                          },
                          sc.relPath
                        );
                      })
                    ),
                    (function () {
                      var sc = preview.scripts && (preview.scripts[scriptIdx] || preview.scripts[0]);
                      return sc
                        ? h(
                            "div",
                            null,
                            h("div", { className: "dsh-wsl-native-mono", style: { fontSize: "11px", color: "#9498a3", marginBottom: "5px" } }, sc.title + " · SHA-256: " + (sc.sha256 || "-") + " · " + sc.lines + " 行"),
                            h("pre", { className: "dsh-wsl-native-in dsh-wsl-native-mono", style: { maxHeight: "230px", overflow: "auto", whiteSpace: "pre", marginBottom: "10px" } }, sc.content || "")
                          )
                        : null;
                    })(),
                    h("div", { style: { fontSize: "12px", color: "#9498a3", marginBottom: "4px" } }, isEn ? "Dry-Run Preview Command:" : "步骤 2 强制执行的只读 -DryRun 预览命令："),
                    h("pre", { className: "dsh-wsl-native-in dsh-wsl-native-mono", style: { marginBottom: "14px", overflowX: "auto" } }, preview.dryRunCommand || ""),
                    h(
                      "div",
                      { style: { display: "flex", justifyContent: "space-between", gap: "8px" } },
                      h("button", { className: "dsh-wsl-native-btn", onClick: function () { setStep(1); } }, isEn ? "<- Back" : "<- 返回上一步"),
                      h("button", { className: "dsh-wsl-native-btn dsh-wsl-native-btn-pri", onClick: function () { setStep(3); } }, isEn ? "Next: Start Installation ->" : "下一步：选择安装方式 ->")
                    )
                  )
                : null,
              step === 3 && preview
                ? h(
                    "div",
                    null,
                    h(
                      "div",
                      { className: "dsh-wsl-native-card accent" },
                      h("div", { style: { fontWeight: 600, marginBottom: "4px" } }, isEn ? "Option A (Recommended): Controlled AI 4-Step Bootstrap" : "方式 A（推荐）：开启受控 AI 引导通道（严格 4 步：探测 -> -DryRun 预览卡 -> 单次审批 -> doctor）"),
                      h("div", { style: { fontSize: "12px", color: "#9498a3", marginBottom: "10px" } }, isEn ? "Opens a 20m time-limited channel, copies the standard prompt, and returns you to Chat so you can paste and supervise step by step." : "开启限时 20 分钟引导通道，自动复制标准化四步提示词并切回对话页，粘贴即可由 AI 带你在每次执行前人工审批安装。"),
                      h("button", { className: "dsh-wsl-native-btn dsh-wsl-native-btn-pri", onClick: startAiControlledBootstrap }, isEn ? "Open 20m Channel, Copy Prompt & Go to Chat" : "一键开启 20 分钟 AI 引导通道并复制四步指令")
                    ),
                    h(
                      "div",
                      { className: "dsh-wsl-native-card" },
                      h("div", { style: { fontWeight: 600, marginBottom: "4px" } }, isEn ? "Option B: Manual PowerShell 7 Execution" : "方式 B：本机 PowerShell 7 终端手动前置安装（零 AI 权限）"),
                      h("pre", { className: "dsh-wsl-native-in dsh-wsl-native-mono", style: { overflowX: "auto", marginBottom: "8px" } }, preview.installCommand || ""),
                      h(
                        "div",
                        { style: { display: "flex", gap: "8px", flexWrap: "wrap" } },
                        h("button", { className: "dsh-wsl-native-btn", onClick: function () { copyClipboardText(preview.installCommand || ""); setStatusMsg(isEn ? "Install command copied." : "已复制 PowerShell 7 安装命令。"); } }, isEn ? "Copy Command" : "复制安装命令"),
                        h("button", { className: "dsh-wsl-native-btn dsh-wsl-native-btn-pri", onClick: verifyManualReload }, isEn ? "I Finished Install — Verify & Reload" : "我已完成终端安装 — 立即检测生效")
                      )
                    ),
                    h(
                      "div",
                      { style: { display: "flex", justifyContent: "space-between", gap: "8px" } },
                      h("button", { className: "dsh-wsl-native-btn", onClick: function () { setStep(2); } }, isEn ? "<- Back" : "<- 返回脚本预览"),
                      h(
                        "div",
                        { style: { display: "flex", gap: "8px" } },
                        initialized
                          ? h("button", { className: "dsh-wsl-native-btn dsh-wsl-native-btn-pri", onClick: function () { uiCtrl.setOobeOpen(false); uiCtrl.openMainPanel("status"); } }, isEn ? "Open Sandbox Console" : "进入 WSL 2 沙箱控制台")
                          : h("button", { className: "dsh-wsl-native-btn", onClick: dismissOobe }, isEn ? "Configure Later" : "稍后配置")
                      )
                    )
                  )
                : null
            )
          )
        : null;

      var firstPending = pending.length > 0 ? pending[0] : null;
      var pendingToastNode = (!open && firstPending)
        ? h(
            "div",
            { className: "dsh-wsl-approval-toast" },
            h(
              "div",
              { style: { display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "6px" } },
              h("b", { style: { color: "#fbbf24" } }, (isEn ? "WSL Sandbox Approval (" : "WSL 沙箱待人工审批 (") + pending.length + ")"),
              firstPending.touchesPhysicalDevice
                ? h("span", { className: "dsh-wsl-native-pill", style: { color: "#f59e0b", borderColor: "rgba(245,158,11,0.4)" } }, isEn ? "Hardware Single-Shot" : "硬件单次锁")
                : null
            ),
            h("div", { style: { marginBottom: "4px" } }, firstPending.summary),
            firstPending.command
              ? h("pre", { className: "dsh-wsl-native-in dsh-wsl-native-mono", style: { maxHeight: "90px", overflow: "auto", marginBottom: "8px", fontSize: "11.5px" } }, firstPending.command)
              : null,
            h(
              "div",
              { style: { display: "flex", gap: "6px", flexWrap: "wrap" } },
              h("button", { className: "dsh-wsl-native-btn dsh-wsl-native-btn-pri", style: { padding: "4px 10px" }, onClick: function () { decideToast(firstPending.requestId, "allow-once"); } }, isEn ? "Allow Once" : "允许一次"),
              h("button", { className: "dsh-wsl-native-btn dsh-wsl-native-btn-out-red", style: { padding: "4px 10px" }, onClick: function () { decideToast(firstPending.requestId, "deny"); } }, isEn ? "Deny" : "拒绝"),
              h("button", { className: "dsh-wsl-native-btn", style: { padding: "4px 10px" }, onClick: function () { uiCtrl.openMainPanel("approvals"); } }, isEn ? "Open Queue" : "审批详情")
            )
          )
        : null;

      if (!oobeNode && !pendingToastNode) return null;
      return h(React.Fragment, null, oobeNode ? portalToBody(oobeNode) : null, pendingToastNode ? portalToBody(pendingToastNode) : null);
    }

    // 插件管理详情页 / 行配置 / 启用引导卡片（Plugins 面板联动）
    function WslPluginConfigCard(props) {
      var _langPair = useUiLang(), lang = _langPair[0];
      var isEn = lang === "en";
      var _st = useState(null), st = _st[0], setSt = _st[1];

      useEffect(function () {
        var mounted = true;
        var load = function () {
          apiFetch("GET", "/wsl-sandbox/api/status").then(function (r) {
            if (mounted && r && r.ok) setSt(r);
          }).catch(function () {});
        };
        load();
        var unsub = uiCtrl.subscribeStatusChanged(load);
        return function () { mounted = false; unsub(); };
      }, []);

      var cfg = st && st.config;
      var initialized = st ? st.initialized !== false : true;
      var onDismiss = props && typeof props.onDismiss === "function" ? props.onDismiss : null;

      return h(
        "div",
        { className: "dsh-wsl-native-card", style: { marginTop: "8px", marginBottom: "8px" } },
        h(
          "div",
          { style: { display: "flex", justifyContent: "space-between", alignItems: "center", gap: "10px", flexWrap: "wrap", marginBottom: "8px" } },
          h(
            "div",
            null,
            h("b", null, isEn ? "WSL 2 Sandbox Control & Setup" : "WSL 2 沙箱配置与初始化入口"),
            cfg
              ? h("div", { className: "dsh-wsl-native-mono", style: { fontSize: "12px", color: "#9498a3", marginTop: "3px" } },
                  (initialized ? (cfg.enabled ? (isEn ? "Active" : "已启用") : (isEn ? "Disabled" : "已停用")) : (isEn ? "Uninitialized" : "待初始化")) +
                  " · " + cfg.distro + " · " + (cfg.environmentProfile || "standard")
                )
              : null
          ),
          h(
            "div",
            { style: { display: "flex", gap: "8px", flexWrap: "wrap" } },
            h("button", {
              className: "dsh-wsl-native-btn dsh-wsl-native-btn-pri",
              onClick: function () { uiCtrl.setOobeOpen(true); }
            }, isEn ? "Open OOBE Setup Wizard" : "启动 OOBE 初始化向导"),
            h("button", {
              className: "dsh-wsl-native-btn",
              onClick: function () { uiCtrl.openMainPanel("status"); }
            }, isEn ? "Open Sidebar Console" : "打开左侧边栏控制台"),
            onDismiss
              ? h("button", { className: "dsh-wsl-native-btn", onClick: onDismiss }, isEn ? "Dismiss" : "收起")
              : null
          )
        )
      );
    }

    function WslPluginDetailSection(props) {
      var subject = props && props.subject;
      if (!subject || !subject.pkg || subject.pkg.name !== PLUGIN_ID) return null;
      return h(WslPluginConfigCard, null);
    }

    // 右侧边栏会话停靠标签页（精简状态与审批）
    function WslRightSidebarPane() {
      var _langPair = useUiLang(), lang = _langPair[0];
      var isEn = lang === "en";
      var _st = useState(null), st = _st[0], setSt = _st[1];
      var _pending = useState([]), pending = _pending[0], setPending = _pending[1];

      useEffect(function () {
        var mounted = true;
        var load = function () {
          Promise.all([
            apiFetch("GET", "/wsl-sandbox/api/status"),
            apiFetch("GET", "/wsl-sandbox/api/approvals")
          ]).then(function (res) {
            if (!mounted) return;
            if (res[0] && res[0].ok) setSt(res[0]);
            if (res[1] && res[1].ok) setPending(res[1].pending || []);
          }).catch(function () {});
        };
        load();
        var unsub = uiCtrl.subscribeStatusChanged(load);
        var timer = setInterval(load, 5000);
        return function () { mounted = false; unsub(); clearInterval(timer); };
      }, []);

      var cfg = st && st.config;
      return h(
        "div",
        { style: { padding: "14px", color: "#f2f3f5", fontSize: "12.5px", overflowY: "auto", height: "100%" } },
        h("div", { style: { fontWeight: 700, fontSize: "14px", marginBottom: "8px" } }, isEn ? "WSL 2 Sandbox Status" : "WSL 2 沙箱实时面板"),
        cfg
          ? h(
              "div",
              { className: "dsh-wsl-native-card" },
              h("div", { className: "dsh-wsl-native-mono", style: { marginBottom: "4px" } }, cfg.distro + " · " + (cfg.environmentProfile || "standard")),
              h("div", { style: { color: "#9498a3", fontSize: "11.5px" } }, (isEn ? "Workspace: " : "工作区: ") + cfg.workspaceRoot)
            )
          : null,
        h(
          "div",
          { style: { display: "flex", gap: "8px", flexWrap: "wrap", marginBottom: "12px" } },
          h("button", { className: "dsh-wsl-native-btn dsh-wsl-native-btn-pri", onClick: function () { uiCtrl.openMainPanel("status"); } }, isEn ? "Full Console" : "打开完整控制台"),
          h("button", { className: "dsh-wsl-native-btn", onClick: function () { uiCtrl.setOobeOpen(true); } }, "OOBE")
        ),
        pending.length > 0
          ? pending.map(function (p) {
              return h(
                "div",
                { key: p.requestId, className: "dsh-wsl-native-card warn" },
                h("div", { style: { fontWeight: 600, marginBottom: "4px" } }, p.summary),
                h("pre", { className: "dsh-wsl-native-in dsh-wsl-native-mono", style: { marginBottom: "6px", maxHeight: "90px", overflow: "auto" } }, p.command || ""),
                h(
                  "div",
                  { style: { display: "flex", gap: "6px" } },
                  h("button", { className: "dsh-wsl-native-btn dsh-wsl-native-btn-pri", onClick: function () { apiFetch("POST", "/wsl-sandbox/api/approvals/" + encodeURIComponent(p.requestId) + "/decide", { decision: "allow-once" }).then(function () { uiCtrl.notifyStatusChanged(); }); } }, isEn ? "Allow Once" : "允许一次"),
                  h("button", { className: "dsh-wsl-native-btn dsh-wsl-native-btn-out-red", onClick: function () { apiFetch("POST", "/wsl-sandbox/api/approvals/" + encodeURIComponent(p.requestId) + "/decide", { decision: "deny" }).then(function () { uiCtrl.notifyStatusChanged(); }); } }, isEn ? "Deny" : "拒绝")
                )
              );
            })
          : h("div", { style: { color: "#9498a3", fontSize: "12px" } }, isEn ? "No pending approvals." : "暂无待处理人工审批。")
      );
    }

    // 1. 注册中英双语字典
    ctx.effect(function () {
      return ctx.locale.register(NS, { zh: zh, en: en });
    });

    // 2. 注入隔离 CSS（附带 data-plugin 标记，方便 DSH HMR 自动回收）
    ctx.effect(function () {
      if (typeof document === "undefined") return function () {};
      var existing = document.querySelector("style[" + STYLE_ATTR + "]");
      if (existing) return function () {};
      var styleEl = document.createElement("style");
      styleEl.setAttribute("data-plugin", PLUGIN_ID);
      styleEl.setAttribute(STYLE_ATTR, "1");
      styleEl.textContent = CSS_TEXT;
      document.head.appendChild(styleEl);
      return function () {
        styleEl.remove();
      };
    });

    // 3. 绑定可选 layout 服务引用（不阻塞无 layout 的独立测试）
    if (typeof ctx.inject === "function") {
      ctx.inject(["layout"], function (lCtx) {
        uiCtrl.setLayoutService(lCtx.layout);
        if (typeof lCtx.effect === "function") {
          lCtx.effect(function () {
            return function () { uiCtrl.setLayoutService(null); };
          });
        }
      });
    } else if (typeof ctx.get === "function" && ctx.get("layout")) {
      uiCtrl.setLayoutService(ctx.get("layout"));
    }

    // 4. 注册左侧边栏全局入口（sidebar.panellist + main）
    ctx.effect(function () {
      return ctx.slots.inject("main", function () {
        return ctx.slots.register(
          {
            name: "main",
            key: PANEL_ID,
            locale: NS
          },
          WslSandboxMainPanel
        );
      });
    });

    ctx.effect(function () {
      return ctx.slots.inject("sidebar.panellist", function () {
        return ctx.slots.register(
          {
            name: "sidebar.panellist",
            id: PANEL_ID,
            order: 35,
            label: function () { return t("navTitle"); },
            locale: NS
          },
          SectionIcon
        );
      });
    });

    // 5. 注册根级 shell.overlay（首次未初始化自动弹出 OOBE 向导 + 全局审批浮层）
    ctx.effect(function () {
      return ctx.slots.inject("shell.overlay", function () {
        return ctx.slots.register(
          {
            name: "shell.overlay",
            id: PLUGIN_ID + ".overlay",
            locale: NS
          },
          WslGlobalOverlay
        );
      });
    });

    // 6. 注册插件管理页槽位（plugins.bundle.config / row.config / activation / detail.section）
    ctx.effect(function () {
      return ctx.slots.inject("plugins.bundle.activation", function () {
        return ctx.slots.register(
          {
            name: "plugins.bundle.activation",
            key: PLUGIN_ID,
            locale: NS
          },
          WslPluginConfigCard
        );
      });
    });

    ctx.effect(function () {
      return ctx.slots.inject("plugins.bundle.config", function () {
        return ctx.slots.register(
          {
            name: "plugins.bundle.config",
            key: PLUGIN_ID,
            locale: NS
          },
          WslPluginConfigCard
        );
      });
    });

    ctx.effect(function () {
      return ctx.slots.inject("plugins.row.config", function () {
        return ctx.slots.register(
          {
            name: "plugins.row.config",
            key: PLUGIN_ID + "#" + PLUGIN_ID,
            locale: NS
          },
          WslPluginConfigCard
        );
      });
    });

    ctx.effect(function () {
      return ctx.slots.inject("plugins.detail.section", function () {
        return ctx.slots.register(
          {
            name: "plugins.detail.section",
            id: PLUGIN_ID + ".detail",
            order: 10,
            locale: NS
          },
          WslPluginDetailSection
        );
      });
    });

    // 7. 保留左下角「设置 -> WSL 2 沙箱」完整设置页兼容注册
    ctx.effect(function () {
      return ctx.slots.inject("settings.section", function () {
        var d1 = ctx.slots.register(
          {
            name: "settings.section",
            id: PLUGIN_ID,
            order: 45,
            label: function () { return t("navTitle"); },
            locale: NS
          },
          WslSandboxSection
        );
        var d2 = null;
        try {
          d2 = ctx.slots.register(
            {
              name: "settings.section.icon",
              id: PLUGIN_ID
            },
            SectionIcon
          );
        } catch (_err) {
          d2 = null;
        }
        return function () {
          if (typeof d1 === "function") d1();
          if (typeof d2 === "function") d2();
        };
      });
    });

    // 8. 可选注册右侧边栏停靠标签页（仅当 DSH 挂载 sidebarRightTabs 时）
    if (typeof ctx.inject === "function") {
      ctx.inject(["sidebarRightTabs"], function (srCtx) {
        if (srCtx.sidebarRightTabs && typeof srCtx.sidebarRightTabs.register === "function") {
          var regDispose = srCtx.sidebarRightTabs.register({
            id: PLUGIN_ID,
            kind: "wsl-sandbox",
            priority: "extension",
            title: function () { return t("rightTabTitle"); },
            guide: [
              {
                id: "wsl-sandbox-guide",
                order: 45,
                title: function () { return t("guideTitle"); },
                description: function () { return t("guideDesc"); },
                icon: SectionIcon
              }
            ]
          });
          if (typeof srCtx.effect === "function") {
            srCtx.effect(function () {
              return function () { if (typeof regDispose === "function") regDispose(); };
            });
          }
        }
        if (srCtx.slots && typeof srCtx.slots.inject === "function" && typeof srCtx.effect === "function") {
          srCtx.effect(function () {
            return srCtx.slots.inject("sidebar.right.pane.tab", function () {
              return srCtx.slots.register(
                {
                  name: "sidebar.right.pane.tab",
                  key: PLUGIN_ID,
                  locale: NS
                },
                WslRightSidebarPane
              );
            });
          });
        }
      });
    }
  }

  exports.NS = NS;
  exports.PANEL_ID = PANEL_ID;
  exports.inject = ["slots", "locale"];
  exports.apply = apply;
  return module.exports;
} });

