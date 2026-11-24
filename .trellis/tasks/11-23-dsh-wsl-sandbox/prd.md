# DSH WSL 2 Sandbox Backend — Final Confirmed PRD (v2.0)

> **Status**: Final Spec Frozen (`grill-me` Q1–Q18 all settled; awaiting user sign-off on Complete Spec v2.0 before continuing implementation)

## Goal
为 Windows 下的 DeepSeek Harness (DSH) 构建完整的 **WSL 2 后端与 Codex 级 OS 命令沙盒**（`dsh-wsl-sandbox`），实现：
1. **Codex + Anthropic + Google + nsjail 级 Linux 内核硬隔离**（`bwrap` + 纯 TS `seccomp-bpf` + `prlimit` + WSL 2 全逃逸面遮蔽）；
2. **双引擎零 Token 命令审批体系**：WSL 侧完整 Bash AST 守卫 + Windows 宿主侧完整 PowerShell 高危守卫 + 并发单次动作绑定审批控制面 + 物理设备操作自动降级手动单次审批；
3. **笔记本零重构建的 Agent 引导式建环境方案（Q18）**：不跑本地 Docker 镜像构建、不做内核编译；提供专门注入给 Agent 的 **WSL 环境置备 Skill / 提示词（`dsh-wsl-env-setup`）** + 幂等分步脚本 + `dsh-wsl-doctor` 自检闭环，让 Agent 在人类确认下直接操作官方现成 WSL 发行版（`wsl --install` 或已有发行版）按需配齐对标 Codex (`core`/`standard`/`universal`) 且适配国内网络（`--mirror cn` + 上游代理）的开发环境；
4. **宿主机 DSH 插件（如 `dsh-purge` 等）100% 不冲突、不失效**：保留宿主机原生工具以支持 USBIP/ESP32/Kali 混合工作流，提供完整同底座 `wsl_*` 工具族与非侵入式 WSL 优先提示词引导。

## Complete Settled Decision Log (Q1–Q18)

| ID | 决策项 | 定稿结论 |
| :--- | :--- | :--- |
| **Q1** | 目标 DSH 运行形态 | **C** — 同时支持 Windows Electron Desktop (`desktop` profile) 与 CLI (`dsh web` / `dsh headless`)，标准 DSH Bundle 交付 |
| **Q2** | WSL 2 发行版承载策略 | **C** — 双模式：支持独立新建官方 WSL 2 发行版（如 `Ubuntu-24.04` / 克隆实例）或复用现有 WSL 2 发行版 |
| **Q3** | WSL 侧常驻 Runner 语言 | **A** — 纯 TypeScript / Node 22 ESM（零交叉编译，与内置环境和 DSH 统一） |
| **Q4** | 与 `dsh-purge` 共存的审批控制权 | **A (`balanced`)** — `dsh-purge` 提示词/技能/路由 100% 保留；内核硬隔离与 L0 永不可绕过；L3 优先走 DSH `ctx.approval`，检测到宿主钩子被跳过时由本插件独立高危闸门兜底（可切 `strict` / `trust-workspace`） |
| **Q5** | 结合国情的默认网络策略 | **B** — 沙盒保持 `--unshare-net` 禁直连与抽象 Unix Socket，默认常开 UDS 受控开发源白名单代理 + 自动/手动级联本机上游代理（Clash/Mihomo/v2rayN，兼容 NAT/mirrored）+ 国内镜像源 `--mirror cn`；白名单外域名走审批；可一键切纯断网 |
| **Q6** | 对标 Codex 的内置环境档位 | **可选三档** — `core` / `standard` / `universal` 任选（含 `--mirror cn` / `--proxy`） |
| **Q7** | `.env` / `.env.*` 密钥默认策略 | **A** — 默认深度 ≤ 3 自动遮蔽为空白只读（`wsl_bash` 与 `wsl_fs` 同步），人类 UI 可按项目放行 |
| **Q8** | Windows 跨盘共享策略 | **强收敛 + 高级按次开** — 基础设置页完全隐藏 `/mnt` 全盘挂载；单目录 `/shares/<alias>` 放进「高级选项」手动按次开启（默认只读、撤权即强杀）；保留 Windows Explorer「Linux」标签下手动复制粘贴 |
| **Q9** | 命令审批快捷决策与白名单 | **A** — 4 档决策（`allow-once` / `allow-session-rule` / `deny` / `deny-with-guidance`）+ POSIX & PowerShell 双黑名单禁用万能跳板沉淀 + 默认 60s 超时 fail-closed |
| **Q10** | AST 守卫依赖策略 | **A** — 纯 TS 零原生编译完整 Bash 词法/AST 解析引擎 + 可选 WASM 挂点（零 `node-gyp` / `pnpm allowBuilds` 冲突） |
| **Q11** | 沙盒内包管理器缓存策略 | **可选** — 支持「按工作区隔离持久化缓存卷（默认）」与「纯 `/tmp` 阅后即焚」可选，支持一键清理 |
| **Q12** | 工具接管形态 | **B + WSL 优先引导** — 保留宿主原生 Windows 工具（适配 USBIP/ESP32/Kali），新增全套同沙盒底座 `wsl_*` 工具族（`wsl_bash`/`wsl_read`/`wsl_write`/`wsl_edit`/`wsl_glob`/`wsl_grep`/`wsl_terminal`），引导模型默认优先用 WSL |
| **Q13** | 物理设备节点直通策略 | **A + 自动降级手动审批** — 默认关闭任何物理设备；高级选项支持精确单节点 `--dev-bind` 白名单（`/dev/ttyUSB*`、`/dev/ttyACM*`、`/dev/bus/usb/*`）；**凡涉及物理设备操作（含烧录工具与宿主 `usbipd bind/attach/detach`）一律强制降级为每次手动 `allow-once` 审批，禁止会话记忆放行** |
| **Q14** | 「优先用 WSL」提示词注入 | **A** — 非侵入式 `ctx.systemPrompt` 增量 section（零覆盖 `dsh-purge` 的 `id: system-prompt`）+ 一键写入/更新项目 `AGENTS.md` WSL 优先指引 |
| **Q15** | 宿主 PowerShell 完整高危守卫 | **A + 完整 `PwshGuard`** — 除精准拦截宿主 `pwsh` 偷调 `wsl.exe`/改 `.wslconfig` 绕过沙盒外，实现完整 PowerShell 静态守卫（含 Base64 `-EncodedCommand` 解码、反引号去混淆、L0 毁灭命令硬禁、L3 破坏/提权/下载执行/物理设备 `usbipd` 审批、禁用跳板白名单），对正常查询与 `dsh-purge` 透明无误杀 |
| **Q16** | UDS 代理私网/回环策略 | **A** — 默认严禁私网/回环 IP（防 SSRF）；高级选项支持人类手动配置本地实验 CIDR/端口白名单（供本地 Dev Server / 合法本地靶场调试，模型无权修改） |
| **Q17** | 交付范围与验证边界 | **A** — 本机 Linux x86_64 完成全量 4 包实现 + 真实内核 `bwrap+seccomp+prlimit+UDS代理` 正反集成测试 + 模拟 `dsh-purge` 共存测试 + 交付 Windows 真实 WSL 2 一键验收脚本与诚实分层验证报告 |
| **Q18** | **笔记本轻量化建环境策略** | **零 Docker / 零内核构建 + Agent 提示词驱动建环境** — 放弃重型本地 Docker 镜像构建与任何内核编译；交付专用 **Agent 建环境引导 Skill & 提示词（`dsh-wsl-env-setup`）** + 轻量幂等 `provision-wsl.sh` + `dsh-wsl-doctor` 自检工具，让用户在笔记本上由 Agent 引导操作官方现成 WSL 2 发行版按步配齐环境（每步可控、可断点续跑、零重负载构建） |

## Acceptance Criteria
- [ ] 完整版 Spec（[specification.md](file:///home/antigravity/.gemini/jetski/brain/v1/default/jetski_remote_agents_3p_devbox/5d04c271-d126-4358-9d3b-ff5a5e3911b6/specification.md) + `.trellis/spec/` 全部 5 层可执行代码规范 + `.agents/skills/` 10 个便携 Skill）交付并通过用户审阅。
- [ ] `packages/core`、`packages/wsl-runner`、`packages/dsh-plugin`、`packages/bootstrap` 全部无错构建（零原生 `node-gyp` 依赖）。
- [ ] 全量单元测试通过：`BashAstGuard`、`PwshGuard`（含 Base64 `-EncodedCommand` 解码与反引号去混淆）、`ApprovalController`（并发、防重放、篡改、TTL、撤权、跳板黑名单、物理设备自动降级）、`SeccompBpf`（`x86_64` + `aarch64`）、`BwrapBuilder`、`EnvSanitizer`、`UdsProxy`。
- [ ] 本机真实 Linux 内核 `bwrap --seccomp <fd>` + `prlimit` + `wsl-runner` + `UdsProxy` 集成测试全绿。
- [ ] 模拟 `dsh-purge` 同装共存测试全绿。
- [ ] `packages/bootstrap` 交付 `dsh-wsl-env-setup` Agent 提示词/Skill、轻量幂等 `provision-wsl.sh`（零 Docker / 零内核构建）、`dsh-wsl-doctor` 及 `tests/windows-wsl-verify/verify-wsl2.ps1`。
