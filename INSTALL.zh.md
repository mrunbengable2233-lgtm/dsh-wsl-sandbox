# `dsh-wsl-sandbox` 本地安装、多发行版与 WSL Manager 兼容、配置备份与发布指南

> **如果你是第一次接触命令行、PowerShell 7 UTF-8 配置、WSL 2 或源码编译的新手**，请优先阅读保姆级教程：[`docs/BEGINNER-BUILD-AND-DEPLOY.zh.md`](./docs/BEGINNER-BUILD-AND-DEPLOY.zh.md)。  
> **如需让 AI 批量生成危险命令测试集进行门禁红队压测**，请参阅：[`docs/AI-DANGEROUS-COMMAND-FUZZING-GUIDE.zh.md`](./docs/AI-DANGEROUS-COMMAND-FUZZING-GUIDE.zh.md)。

本指南面向日常使用者与仓库维护者，提供 **零 Docker、零内核编译、零 `/mnt` 文件夹占用、与 DSH 共用 Node 运行时** 的本地安装流程，覆盖 **Ubuntu 26.04/24.04/Debian/Fedora/Arch 多发行版自动探测、WSL Manager 迁移磁盘兼容、三档环境配置（`core`/`standard`/`universal`）、只读配置备份还原、SSD 友好型合并刷盘日志** 以及发布到 **GitHub PR / npm** 的完整步骤。

---

## 一、Windows 10/11 + WSL 2 本地快速安装（2 步完成）

> **前置条件**：Windows 10 (21H2+) 或 Windows 11，推荐先安装 **PowerShell 7 (`pwsh.exe`)** 并持久化 UTF-8 编码为默认首选终端（见 [`docs/BEGINNER-BUILD-AND-DEPLOY.zh.md` 第二节](./docs/BEGINNER-BUILD-AND-DEPLOY.zh.md)），已启用 WSL 2（支持任意已注册的 WSL 2 发行版：默认推荐 `Ubuntu-26.04`，也完全支持 `Ubuntu-24.04`、`Debian`、`Fedora`、`Arch`、`kali-linux` 以及通过 **WSL Manager** 导入/迁移 VHDX 磁盘的自定义实例）。
>
> **关于 Node.js 版本（直接与 DSH 共用，无需重复安装）**：
> - 本插件声明 `"engines": { "node": "^22.19.0 || >=24.0.0" }`，与 `@deepseek-ai/dsh@0.2.2-rc.5`（内置 Node `>=24.9.0`）及其他现代 DSH 插件完全对齐。
> - **Windows 宿主侧**：插件直接在 DSH 进程内运行，子进程与安装脚本自动复用 DSH 自带的 Node 载体（`process.execPath` / Electron 下自动携带 `ELECTRON_RUN_AS_NODE=1`，若使用预编译包甚至可直接走 Windows 自带 `tar.exe` 零 Node 安装部署）。
> - **WSL 2 Linux 侧**：自动发现并共用 `~/.dsh/runtime/bin`、`mise`、`nvm`、`fnm`、`volta` 或 `/usr/bin` 下任意已安装的 Linux Node（`>=22`）；仅在全新无 Node 环境下自动安装预编译 **Node 24 Active LTS**（拒绝跨界调用 `/mnt/c/.../node.exe`）。

### 第 1 步：运行交互式 Windows 安装与环境建置向导（零硬编码）

在仓库根目录的 Windows PowerShell 中直接执行（无需手写发行版名或 Linux 用户名）：

```powershell
# 自动探测已注册的 WSL 2 实例（含 WSL Manager 迁移磁盘实例），先检测并补齐 bwrap/prlimit/socat/node，
# 自动只读备份原有 .wslconfig 与 /etc/wsl.conf，将 Runner 部署到 WSL 原生 ext4（零 /mnt 锁占用），
# 验证就绪后再写入 config.json 并执行 dsh-wsl-doctor 闭环体检：
.\packages\bootstrap\install-dsh-plugin.ps1 -Provision -Mirror cn -UpsertAgentsMd
```

> **支持哪些非交互 / 自定义参数？**
> - 指定已有发行版（包括 WSL Manager 自定义名称）：`-Distro MyMovedDebian`
> - 指定三档工具链配置（严格按 spec 生效并持久化到 `~/.config/dsh-wsl-sandbox/profile.json`）：
>   - `-Profile core`（~350MB，约 2 分钟）：`bwrap`/`prlimit`/`socat` + Codex 高频 CLI + C/C++ 基础 + `python3` + 共用 Linux Node `>=22`（全新环境默认安装 **Node 24 Active LTS**）
>   - `-Profile standard`（~1.2GB，默认推荐）：`core` + `ccache`/`protobuf`/`libpq`/`libxml2` + `mise` + `uv`/`pytest`/`ruff`/`mypy`/`pyright`/`black` + `pnpm`/`yarn`/`bun`/`typescript`/`eslint`/`prettier` + Go + `golangci-lint` + Rust 最小化套件
>   - `-Profile universal`（~3.5GB，纯预编译）：`standard` + `clang`/`bazelisk` + `mise` Node 22/24 LTS（默认 `node@24`）+ `poetry`/`isort` + OpenJDK 21 + `maven`/`gradle` + `ruby` + `php-cli`/`composer`
> - 使用上游代理：`-Proxy http://127.0.0.1:7890`
> - 仅备份原有 WSL 配置到任意自定义目录：`-BackupOnly -BackupDir "D:\Backups\WSL-Orig" -OpenBackupFolder`
> - 如尚未安装任何 WSL 2 发行版，向导会提示可选的官方发行版列表（默认推荐 `Ubuntu-26.04`，也可选择 `Ubuntu-24.04`、`Debian`、`FedoraLinux-42`、`Arch`、`kali-linux` 等）。

如果你已经在 WSL 内，也可以随时直接按需运行单步幂等脚本与体检：
```bash
# 支持 --step all|base|cli|node|python|go|rust|go-rust|extra （升级已有 Node 22 到 24 可加 --upgrade-node）
bash ~/.local/share/dsh-wsl-sandbox/runner/packages/bootstrap/provision-wsl.sh --profile standard --mirror cn
node ~/.local/share/dsh-wsl-sandbox/runner/dist/packages/bootstrap/src/doctor.js --strict-wsl2 --profile standard
```

### 第 2 步：在 DeepSeek Harness (DSH) 中注册插件

```powershell
# 注册到 DSH（按你使用的模式选择 web 或 desktop，也可直接在 DSH Desktop 插件设置中导入 .tgz 或源码目录）：
dsh plugin --profile web add .\dsh-wsl-sandbox-0.2.0.tgz
dsh plugin --profile desktop add .\dsh-wsl-sandbox-0.2.0.tgz
```

- 启动 DSH 后打开 **设置（Settings） -> WSL 2 沙箱**（原生挂载 `settings.section`，与 `dsh-purge`、`dshmarket`、`cc-safety-net` 等 Top 27 插件零冲突共存）。
- 在 DSH Web 服务运行期间也可直接打开同源完整控制台路由：`/wsl-sandbox/ui`。

---

## 二、WSL Manager 迁移实例、配置隔离、物理硬件驱动与 SSD 友好型日志系统

### 1. WSL Manager 导入/导出与磁盘迁移兼容（零资源管理器依赖、零文件夹占用）
- 使用 **WSL Manager** 等工具导入/导出并迁移 VHDX 磁盘到 `D:\WSL` / `E:\WSL` 后，该实例常会从 Windows 资源管理器左侧「Linux」导航栏消失，但仍正常注册在 `wsl.exe -l -v` 与 `HKCU\Software\Microsoft\Windows\CurrentVersion\Lxss` 注册表项下。
- 本插件通过 `wsl.exe -d <Distro> --cd ~` 与只读 `Lxss` 注册表发现这些实例，并通过纯 Node.js POSIX tar 流（`scripts/stage-wsl-runner.mjs`）将 Runner 部署至 WSL 原生 `ext4`（`$HOME/.local/share/dsh-wsl-sandbox/runner/`），**彻底不依赖 `/mnt/c` 或资源管理器左侧栏**。
- 正因不从 `/mnt/c` 运行代码且启动时固定 `--cd ~`，禁用插件、关闭 DSH 或卸载插件目录时**不会产生不可解除的 Windows 文件夹占用锁**。

### 2. 配置目录权限隔离与 WSL Settings / WSL Manager 共用路径保护
- **共用路径声明**：Windows 官方 **WSL Settings**、第三方 **WSL Manager** 与本插件读写的都是同一套配置文件（`%USERPROFILE%\.wslconfig` 与 `/etc/wsl.conf`）。本插件默认**绝不自动改写**它们。
- **配置与备份目录权限最小化**：
  - 宿主配置目录 `%USERPROFILE%\.dsh\dsh-wsl-sandbox` 与备份目录均自动应用仅当前用户与 SYSTEM 可访问的 ACL（Windows `icacls /inheritance:r`，Linux `0700`）；备份快照统一保存为**只读文件**（Linux `0400` / Windows `attrib +R`）。
  - 严禁将 `backupDir`、`workspaceRoot` 或 `/shares` 指向 `%USERPROFILE%`、`~/.dsh`、`~/.config/dsh-wsl-sandbox`、`~/.ssh`、`AppData\Local\Packages` 或任何 WSL 发行版的 VHDX `BasePath`。
  - 在 `bwrap` 沙箱内核层，所有私有配置与凭证目录（`~/.dsh`、`~/.config/dsh-wsl-sandbox`、`~/.ssh`、`~/.gnupg`、`~/.aws`、`~/.kube`、`~/.docker`）均被 `--tmpfs <dir> --remount-ro <dir>` 完全遮蔽，沙箱内 AI **零读/零写权限**。

### 3. 会话进程隔离与禁用全局 `wsl --shutdown`
- 每次沙箱执行绑定 `(sessionId, terminalId)` 与独立 PGID，且在发送 `kill(-pgid)` 前核对 `/proc/<pid>/stat` 进程组归属；点击「熔断强杀」、取消挂载或中止单次工具调用（`AbortController`）**只会终止当前 DSH 会话内的沙箱进程组，绝不会关掉其他 DSH 会话或你手动打开的 WSL 终端**。
- 当你在 opt-in 场景下修改或还原 `/etc/wsl.conf` 后，一律使用单发行版重启命令：
  ```powershell
  wsl.exe --terminate <当前发行版名称>
  ```
  **切勿使用 `wsl.exe --shutdown`**（它会瞬间终止宿主机上所有其他运行中的 WSL 发行版与终端会话）。

### 4. 原始 WSL 配置备份、资源管理器定位与单目录快捷挂载
- **双层禁用全盘挂载**：默认 `bwrap --tmpfs /mnt` 已在内核层完全隐藏 `C:\` / `D:\` 全盘；若需连 WSL 底层也关闭自动挂载，可在 WSL 内运行 `bash ~/.local/share/dsh-wsl-sandbox/runner/packages/bootstrap/provision-wsl.sh --disable-automount`，之后在 Windows 执行 `wsl.exe --terminate <当前发行版名称>`。
- **自定义目录只读备份与单文件定位**：控制台主界面支持任意指定备份路径（或点击「浏览选择目录...」），并为列表中的每一项原始备份提供「在资源管理器中定位」（无壳调用 `explorer.exe /select,<file>`，严格限制在 `backupDir` 内且阻断可执行后缀）。
- **指定单目录快捷挂载**：粘贴例如 `D:\Datasets\Project` 即可单目录映射至 `/shares/Project`（默认只读 `ro`，整盘根目录/系统目录/配置目录会被 `POLICY_BLOCK` 自动拒绝）。

### 5. 物理 USB 设备与驱动（手机解 BL / 免驱 USB 网卡 / HID / 串口）
- USBIP（`usbipd-win`）与物理设备门禁**不限于开发板**：支持 `/dev/bus/usb/NNN/NNN`（手机 ADB/Fastboot/EDL/DFU、`libusb`）、`/dev/hidraw*`、`/dev/cdc-wdm*`、`/dev/video*`、`/dev/ttyUSB*`、`/dev/ttyACM*`。
- **驱动注意事项**：WSL 2 默认微软内核仅内置极少数 USB 驱动模块。
  - 手机解 Bootloader / 原厂线刷工具（依赖 Windows WinUSB/OEM 驱动）或 Windows 免驱但缺少 Linux/WSL 2 `.ko` 驱动模块的 USB 网卡，建议直接留在 Windows 宿主侧调用原厂驱动（`fastboot`/`adb`/`pnputil`/`NetAdapter` 等变更操作均受本插件 L3 硬件单次审批锁保护，绝不自动放行）。
  - 仅依赖用户态 `libusb`（`/dev/bus/usb/NNN/NNN`）或内核已有驱动的设备，可通过 `usbipd attach --wsl` 挂载进 WSL 2 并按节点显式放行。

### 6. SSD 友好型合并刷盘结构化日志系统（保护固态硬盘寿命、零句柄锁）
- 日志位置：`%USERPROFILE%\.dsh\dsh-wsl-sandbox\logs\host.ndjson`（可在控制台 **「运行日志」** 标签页实时筛选、导出、清空或切换 `debug|info|warn|error` 级别）。
- **五大护盘设计**：
  1. **内存合并批量刷盘（`2.5s` / `64 KiB`）**：日志先进入内存缓冲区，最多每 `2.5 秒` 合并成单次 `open -> write -> close` 原子批量写入，杜绝每条日志触发一次小块随机写放大。
  2. **空闲零文件句柄占用**：平时不持有任何打开的文件描述符（`0` open FD），随时卸载插件或删除目录均不报 Windows 文件夹占用。
  3. **重复风暴折叠（`3s` 窗口）与写盘硬限流（`120 条/10s`）**：高频相同告警自动折叠为 1 条主记录 + 1 条汇总计数，极端 `debug` 洪峰下严格限制磁盘写入速率。
  4. **单边落盘 + 滚动限额（`5 MiB × 3`）**：WSL Runner 日志通过内存管道汇总至宿主统一落盘，不在 WSL `ext4.vhdx` 虚拟磁盘内二次写文件；总日志体积硬上限 `15 MiB`。
  5. **全内存查询与敏感信息脱敏**：Web UI 轮询 `/wsl-sandbox/api/logs` 100% 从内存环形缓冲区返回（**`0` 次磁盘读取**，切到后台标签页自动暂停轮询），并自动脱敏 `API_KEY`、`TOKEN`、`Bearer`、`sk-...`、`ghp_...` 等密钥。

### 7. 持久化落盘清单（13 项全透明对账）与一键可逆卸载

> **设计透明性说明**：`bwrap` 的 `--tmpfs` 内存盘仅用于遮蔽 `/tmp`、`/run`、`/mnt` 及 `$HOME` 敏感凭证目录；插件的安装配置、备份、工作区缓存与工具链属于明确的持久化落盘，全部记录在 `install-manifest.json` 与 `provision-manifest.json` 中，**绝不留隐蔽垃圾，也无需翻查安装日志**。

#### 一键可逆卸载命令（Windows PowerShell 7）
```powershell
# 1. 先预览将要还原和删除的全部 13 项路径（零修改安全演练）：
.\packages\bootstrap\uninstall-dsh-plugin.ps1 -DryRun

# 2. 标准卸载（从 DSH 移除插件、还原 /etc/wsl.conf 与 APT 源、剥离 AGENTS.md 块与 Shell 钩子、解锁 +R/0400 并删净宿主与 WSL 插件目录/缓存）：
.\packages\bootstrap\uninstall-dsh-plugin.ps1

# 3. 深度卸载（在标准卸载基础上，额外按 provision-manifest.json 增量清单卸载安装期新装的 apt/dnf 包、Node 24/Go/Rust/uv/mise/bun 等工具链，绝不误删你原本就有的环境）：
.\packages\bootstrap\uninstall-dsh-plugin.ps1 -PurgeToolchains
```

#### 全量 13 项落盘位置与回收机制对账表

| 侧 | 落盘产物 | 精确路径与权限 | 自动防护与卸载回收方式 |
| :--- | :--- | :--- | :--- |
| **Windows** | 1. 宿主配置、清单与日志 | `%DSH_HOME%\dsh-wsl-sandbox\{config.json, install-manifest.json, logs\}`（owner-only `icacls`） | `uninstall-dsh-plugin.ps1` 自动解锁并整目录移除 |
| **Windows** | 2. `.wslconfig` 滚动备份 | `%DSH_HOME%\dsh-wsl-sandbox\backups\.wslconfig.*.bak`（`attrib +R`） | **SHA-256 去重**（内容未变绝不重复生成 `.bak`，最多保留 5 份）；卸载自动去 `+R` 删除（加 `-KeepBackups` 可保留） |
| **Windows** | 3. 初始只读基准快照 | `backups\{.wslconfig.orig, .wslconfig.orig.absent, wsl.conf.<Distro>.orig}` | 可选 `-RestoreHostWslConfig` 还原后自动解锁删除 |
| **Windows** | 4. 项目 `AGENTS.md` 注入块 | `<!-- dsh-wsl-sandbox:start --> ... <!-- dsh-wsl-sandbox:end -->` | 路径自动记录于 `install-manifest.json`；卸载（或 `DELETE /wsl-sandbox/api/agents-md`）自动剥离标记块，若文件为插件新建空壳则直接删文件 |
| **Windows** | 5. 向导新装的 WSL 发行版 | `wsl.exe --install -d <Distro>`（可选） | 记录于 `install-manifest.json`；默认保留保护用户数据，传 `-UnregisterPluginDistro` 才注销 |
| **WSL 2** | 6. 原生 ext4 Runner 与独立 Node | `~/.local/share/dsh-wsl-sandbox/{runner, toolchains/node}`（`0700`） | 官方 `SHASUMS256.txt` 校验解压（**零 `curl \| sudo bash`、零第三方 APT 源污染**）；`--uninstall` 直接删除 |
| **WSL 2** | 7. 默认空工作区目录 | `~/workspace` | 卸载时仅当目录**完全为空**才 `rmdir`，非空自动保留 |
| **WSL 2** | 8. WSL 配置、增量清单与备份 | `~/.config/dsh-wsl-sandbox/{profile.json, provision-manifest.json, backups/}`（`0400` 备份） | 备份按 SHA-256 去重限 5 份；卸载先还原配置，再 `chmod -R u+w` 解锁删净 |
| **WSL 2** | 9. Shell 环境脚本与 RC 钩子 | `~/.dsh-wsl-env.sh` 及 `~/.bashrc`、`~/.profile` 单行引用 | `--uninstall` 自动精准剔除引用行并删除 `~/.dsh-wsl-env.sh` |
| **WSL 2** | 10. 工作区持久化包缓存 | `~/.cache/dsh-wsl-sandbox/<sha256-12>` | 超过 30 天未访问自动过期清理；支持 UI 一键清空；`--uninstall` 全量删除（设 `cacheMode=ephemeral` 则不落盘） |
| **WSL 2** | 11. 档位软件包与非 APT 工具链 | 新增系统包及 `/usr/local/go`、`~/.rustup`、`~/.cargo`、`~/.bun`、`~/.local/share/mise`、`uv` | 安装前比对记录增量至 `provision-manifest.json`；传 `-PurgeToolchains` / `--purge-toolchains` 精确回滚增量项 |
| **WSL 2** | 12. `/etc/wsl.conf` 与 APT 镜像源 | `/etc/wsl.conf`、`/etc/apt/sources.list.d/*.bak` | `--uninstall` 默认自动还原原始文件并清理 `.bak` |
| **WSL 2** | 13. Runner / UDS 代理运行期目录 | `dsh-wsl-runner-*`、`dsh-wsl-proxy-*`（含 `0444` `empty-mask`） | 优先建在内核真内存盘 `/run/user/<uid>` 或 `/dev/shm`（`tmpfs`，`wsl --terminate` 自动蒸发），并带 `owner.pid` 在每次启动及卸载时自动清扫 `kill -9` 残留 |

---

## 三、通过 GitHub Desktop 或命令行提交独立版本 PR（`release/v0.2.0` -> `main`）

### 方式 1：GitHub Desktop 零命令创建 PR（推荐）
1. 解压 `dsh-wsl-sandbox-github-desktop.zip` 到本地目录。
2. 打开 **GitHub Desktop** -> `File` -> `Add local repository...` -> 选择解压出来的 `dsh-wsl-sandbox` 文件夹。
3. 顶部当前分支已自动切好在独立分支 **`release/v0.2.0`**（基于线上 `origin/main` 分叉，无任何冲突）：
   - 点击顶部 **`Publish branch`** 推送 `release/v0.2.0` 分支；
   - 紧接着点击 **`Preview Pull Request` / `Create Pull Request`**，即可在 GitHub 网页一键发起 `release/v0.2.0 -> main` 的独立版本 PR。

### 方式 2：使用 `dsh-wsl-sandbox-v0.2.0.bundle` 命令行推送分支提 PR
```zsh
git clone dsh-wsl-sandbox-v0.2.0.bundle dsh-wsl-sandbox-pr
cd dsh-wsl-sandbox-pr
git checkout release/v0.2.0
git remote set-url origin https://github.com/mrunbengable2233-lgtm/dsh-wsl-sandbox.git
git push -u origin release/v0.2.0
# 推送后打开提示的 GitHub Pull Request 链接点击 Create pull request 即可
```

---

## 四、托管发布到 npm（以及接入 DSH 插件市场）

```zsh
npm login
npm test
npm pack --dry-run
npm publish --access public
```
发布后任何用户即可一行安装：
```powershell
dsh plugin --profile web add dsh-wsl-sandbox
dsh plugin --profile desktop add dsh-wsl-sandbox
```

