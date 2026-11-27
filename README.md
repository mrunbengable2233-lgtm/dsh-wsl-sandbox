# `dsh-wsl-sandbox` — DeepSeek Harness (DSH) WSL 2 内核级沙箱与执行后端 (`v0.3.0`)

> **语言选择 / Language**: **简体中文** | [**English**](./README.en.md)

面向 **DeepSeek Harness (`@deepseek-ai/dsh@0.2.2-rc.5`)** 的 Codex 级 Linux 内核沙箱执行后端（`bubblewrap` + 原生 `seccomp-bpf` + `prlimit` + UDS 白名单代理），集成**宿主 / WSL 2 共用 Node 运行时**（`Node >=20.11.0`，推荐 `22.19+` / `24 LTS` + `ELECTRON_RUN_AS_NODE=1`）、**SSD 友好型合并刷盘结构化日志**（`2.5s`/`64 KiB` 批量落盘、空闲零文件句柄、内存直读）、**微软官方 PowerShell AST（`[Parser]::ParseInput` / `ParseFile`）与 8 层 Bash AST 单壳方言门禁**、**零 Token 人工单票审批与物理硬件/驱动单次锁**、**DIY/WSL Manager 迁移发行版自动发现与原生 `ext4` Runner 自动部署**、**只读配置备份还原与单目录快捷挂载**，并与 **Top-27 DSH 市场及 CLI 插件（含 `dsh-purge`、`dshmarket`、`cc-safety-net`、`dsh-win-bash`、`dsh-better-sidebar`）100% 无冲突共存**。

---

## 文档导航（Documentation Index）

- **小白零基础编译、测试与部署全攻略（含 PowerShell 7 + UTF-8 首选终端持久化）**：[`docs/BEGINNER-BUILD-AND-DEPLOY.zh.md`](./docs/BEGINNER-BUILD-AND-DEPLOY.zh.md)
- **简明中文安装、多发行版 / WSL Manager 兼容、配置备份还原与发布指南**：[`INSTALL.zh.md`](./INSTALL.zh.md)
- **危险命令红队对抗测试与 AI 批量生成指南（零执行纯内存压测）**：[`docs/AI-DANGEROUS-COMMAND-FUZZING-GUIDE.zh.md`](./docs/AI-DANGEROUS-COMMAND-FUZZING-GUIDE.zh.md)
- **Linux 内核隔离机制与安全审计交接白皮书（面向内核 / 系统安全工程师）**：[`docs/KERNEL-SECURITY-HANDOFF.zh.md`](./docs/KERNEL-SECURITY-HANDOFF.zh.md)
- **完整工程规格书（Q1–Q18 决策锁定与 v0.3.0 验收归档）**：[`docs/specification-v2.0.md`](./docs/specification-v2.0.md)
- **架构设计与开源方案对比归档**：[`docs/dsh-wsl-sandbox-architecture.md`](./docs/dsh-wsl-sandbox-architecture.md)
- **原始 WSL 配置参考备份模板**：[`packages/bootstrap/templates/`](./packages/bootstrap/templates/)
- **English Overview**：[`README.en.md`](./README.en.md)

---

## 核心架构（Core Architecture）

| 模块 | 职责与核心安全机制 |
| :--- | :--- |
| **`packages/core`** | 纯 TypeScript 实现（**零第三方 npm 运行时依赖**、零 `node-gyp`）：<br>- `node-runtime.ts`：Windows 侧复用 DSH `process.execPath`（支持 `ELECTRON_RUN_AS_NODE=1`），WSL 2 侧优先复用原生 Linux Node `>=22` / 24 LTS 并拦截 `/mnt/*` `.exe` 跨界回弹；<br>- `logger.ts`：SSD 友好 `2.5s`/`64 KiB` 合并 NDJSON 落盘（空闲 `0` FD、`3s` 风暴折叠、`120 条/10s` 限速、`5 MiB × 3` 滚动、`100%` 内存响应 UI 查询、递归密钥脱敏）；<br>- `binding.ts` & `env-sanitizer.ts` & `dangerous-paths.ts`：强会话绑定（WSL 2、`uid > 0`、支持带空格/中文 DIY 发行版名）、单目录共享校验（`/shares/<alias>`）、显式外设节点白名单、环境变量白名单清洗、工作区敏感路径只读锁与深度 `<= 3` `.env*` 归零遮蔽；<br>- `seccomp-bpf.ts` & `bwrap-builder.ts`：纯 TS `x86_64`/`aarch64` cBPF 编译（阻断 `io_uring_*`、`AF_VSOCK`、`AF_PACKET`、`ptrace`、`mount`、`bpf`、`x32` ABI）与 `bwrap` 挂载树（遮蔽 `/mnt`、`/run/WSL`、`~/.dsh`、`~/.config/dsh-wsl-sandbox`、`~/.ssh` 等）；<br>- `pwsh-system-parser.ts` & `pwsh-guard.ts` & `bash-ast-guard.ts`：集成**微软官方 PowerShell 系统 AST 解析器（`[System.Management.Automation.Language.Parser]` 持久只读 Worker）** 与 8 层 `BashAstGuard`，零 Token 拦截套壳混淆、方言误用、手机 Bootloader/ADB 与 Windows 驱动/网卡变更并强制单次锁；<br>- `approval-controller.ts` & `uds-proxy.ts`：`SHA-256` 动作绑定并发单票审批与 `AF_UNIX` 白名单代理（SSRF + DNS Rebinding 防御）。 |
| **`packages/wsl-runner`** | 部署于 WSL 原生 `ext4`（`~/.local/share/dsh-wsl-sandbox/runner/`，零 `/mnt` 依赖、零 Windows 文件夹占用锁）的常驻 NDJSON RPC Worker：通过内存管道回传结构化日志至宿主统一落盘、`probe`、防符号链接穿越与 `O_NOFOLLOW` 原子文件服务（`ConfinedFsService`）、`bwrap --seccomp 3` + `prlimit` + `(sessionId, terminalId)` 作用域 PGID 隔离回收（`ConfinedProcManager` / `ConfinedTerminalManager`）、`0400` 只读 `wsl.backupConfigs`、以及受管 `UdsAllowlistProxy` 租约看门狗。 |
| **`packages/dsh-plugin`** | 原生 `@deepseek-ai/dsh@0.2.2-rc.5` Cordis 插件（`cordis.patch.yml` 增量挂载 + 浏览器 `client.js` 原生 `settings.section`）：动态发现多发行版与 WSL Manager 迁移 VHDX、`ensureBound()` 单飞并发与缺失 Runner 自动原生 `ext4` 部署（`stageRunnerIntoWslAsync`）、7 个支持 `AbortController` 的 `wsl_*` 工具、非侵入 `ctx.systemPrompt` 路由（`order: 4200`）、宿主 `tools.guard` + `tools/pre-execute` 单调守卫、`ApprovalBridge`、`0600`+ACL `ConfigStore`、带 DNS Rebinding（`Host`）+ CSRF（`Origin` + `X-DSH-WSL-Client: 1`）防护的 `/wsl-sandbox/api/*` 及 `/wsl-sandbox/ui`（内置中文/英文控制台切换）。 |
| **`packages/bootstrap`** | 笔记本友好、**零 Docker、零内核编译、零源码编译 `pyenv`** 的多发行版引导套件（覆盖 Ubuntu 26.04/24.04/22.04、Debian、Kali、Fedora、Arch Linux / `archlinux`、openSUSE、Alpine）：<br>- `provision-wsl.sh`：`core`/`standard`/`universal` 三档幂等二进制安装（`profile.json` + 增量清单 `provision-manifest.json`）、`--mirror cn` 国内镜像与 `--proxy`、AppArmor `bwrap` 规则自配置、`--disable-automount`、单发行版 `--terminate` 指引及可逆 `--uninstall`；<br>- `scripts/stage-wsl-runner.mjs`：纯 Node POSIX ustar 流部署 Runner 至原生 `ext4`（带 `.staged-version` 校验）；<br>- `doctor.ts`（`dsh-wsl-doctor`）：实机内核 `seccomp`/配置遮蔽/USBIP 与分档位工具链自检；<br>- `install-dsh-plugin.ps1` / `uninstall-dsh-plugin.ps1`：UTF-8 BOM + CRLF 签名兼容安装与 13 项足迹一站式卸载。 |

---

## 快速开始（Windows 10/11 + WSL 2 · 两条自洽安装路径，二选一）

> **先预览、绝不「左右脑互搏」**：无论选择先命令行装环境再加插件，还是先加插件后由 AI 引导建环境，**插件在常态下通过宿主 `L0` 单调门禁机械锁死全部安装/置备/卸载脚本**；唯有在设置页点击开启限时「受控引导通道」并完成 `-DryRun` 预览确认卡片后，AI 才允许按步申请单次人工审批安装。详细教程见 [`docs/BEGINNER-BUILD-AND-DEPLOY.zh.md`](./docs/BEGINNER-BUILD-AND-DEPLOY.zh.md) 与 [`INSTALL.zh.md`](./INSTALL.zh.md)。

### 方式 A：先运行本地安装脚本，再注册插件（推荐日常用户）
```powershell
# 1. 在 Windows PowerShell 7 中预览（零写入，校验 SHA-256）：
.\packages\bootstrap\install-dsh-plugin.ps1 -Provision -Profile standard -Mirror cn -DryRun

# 2. 确认无误后正式置备环境、只读备份原配置并部署原生 ext4 Runner：
.\packages\bootstrap\install-dsh-plugin.ps1 -Provision -Profile standard -Mirror cn -UpsertAgentsMd

# 3. 注册插件到 DeepSeek Harness (DSH)：
dsh plugin --profile web add .\dsh-wsl-sandbox-0.3.0.tgz
dsh plugin --profile desktop add .\dsh-wsl-sandbox-0.3.0.tgz
```

### 方式 B：先安装插件 -> 控制台预览脚本 -> 开启「受控 AI 引导通道」
1. 先导入并启用 `dsh-wsl-sandbox-0.3.0.tgz` 插件（未配齐 WSL 前 `wsl_*` 工具安全处于待就绪态）；
2. 打开 DSH **设置 -> WSL 2 沙箱**（或 `/wsl-sandbox/ui`），点击 **「预览安装脚本与 SHA-256」**；
3. 点击 **「开启受控引导通道并复制会话指令」** 并发送给 AI——宿主门禁将严格按 **`1 只读探测 -> 2 -DryRun 预览卡片确认 -> 3 单次审批安装 -> 4 dsh-wsl-doctor 闭环验收（自动关闸）`** 顺序推进。

> **关于 WSL 2 网络模式与发行版兼容**：本插件完全**不强制**要求把 WSL 配成 `mirrored` 模式；日常开发及手机/USB 硬件测试**强烈建议保持 WSL 2 默认 `NAT` 模式**。全面保障主流发行版（Ubuntu 26.04/24.04/22.04、Debian、Kali、Fedora、Arch、openSUSE、Alpine）及 WSL Manager 迁移实例稳定可用，详情与低版本 WSL `< 2.4` / NixOS / 无 `systemd` 审计说明见 [`INSTALL.zh.md`](./INSTALL.zh.md)。

---

## 编译、自动化测试与红队验证（Development & Verification）

> **跨平台运行说明**：在 Windows 上运行 `npm test` / `node test` 时会自动启用 `DSH_WSL_NO_HOST_SPAWN=1`，绝不会私自拉起 `wsl.exe`、`explorer.exe` 或修改任何 WSL 实例；在指定 WSL 2 Linux 内核环境下可额外实测全部 `81` 项测试（含真实 `bwrap` + `seccomp-bpf` 逃逸拦截）。

```bash
# 编译全部 TypeScript 模块、测试预编译缓存与 DSH 原生前端 bundle client.js
npm run build

# 运行自动化测试套件（原生兼容 npm test、node test 与 node --test）
# Win32 宿主机：81 项共 71 通过、0 失败（自动跳过 10 项 Linux 内核态专项）；WSL 2：81 项全量实测
npm test
node test

# 运行零执行内存级危险命令红队矩阵校验（共 3 组内置集计 246 条向量：30 + 24 + 192）
npm run fuzz:check
node scripts/run-dangerous-cmd-matrix.mjs --input tests/fixtures/audit-redteam-cases.json
node scripts/run-dangerous-cmd-matrix.mjs --input tests/fixtures/redteam-v021.json

# 在目标 WSL 2 发行版内执行内核隔离、配置遮蔽、USB 驱动与工具链实机体检
npm run doctor -- --profile standard
```
