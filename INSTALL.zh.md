# `dsh-wsl-sandbox` 本地安装、多发行版与 WSL Manager 兼容、配置备份与 npm 托管指南

本指南面向日常使用者与仓库维护者，提供 **零 Docker、零内核编译、零 `/mnt` 文件夹占用** 的本地安装流程，覆盖 **Ubuntu 26.04/24.04/Debian/Fedora/Arch 多发行版自动探测、WSL Manager 迁移磁盘兼容、三档环境配置（`core`/`standard`/`universal`）、只读配置备份还原、单发行版 `--terminate` 隔离** 以及发布到 **npm / GitHub** 的完整步骤。

---

## 一、Windows 10/11 + WSL 2 本地快速安装（2 步完成）

> **前置条件**：Windows 10 (21H2+) 或 Windows 11，已启用 WSL 2（支持任意已注册的 WSL 2 发行版：默认推荐 `Ubuntu-26.04`，也完全支持 `Ubuntu-24.04`、`Debian`、`Fedora`、`Arch`、`kali-linux` 以及通过 **WSL Manager** 导入/迁移 VHDX 磁盘的自定义实例），宿主机 Node.js `>= 22.18.0`。

### 第 1 步：运行交互式 Windows 安装与环境建置向导（零硬编码）

在仓库根目录的 Windows PowerShell 中直接执行（无需手写发行版名或 Linux 用户名）：

```powershell
# 自动探测已注册的 WSL 2 实例（含 WSL Manager 迁移磁盘实例），引导选择 core/standard/universal 档位，
# 自动只读备份原有 .wslconfig 与 /etc/wsl.conf，将 Runner 部署到 WSL 原生 ext4（零 /mnt 锁占用），
# 并按所选档位执行 provision-wsl.sh + dsh-wsl-doctor 闭环体检：
.\packages\bootstrap\install-dsh-plugin.ps1 -Provision -Mirror cn -UpsertAgentsMd
```

> **支持哪些非交互 / 自定义参数？**
> - 指定已有发行版（包括 WSL Manager 自定义名称）：`-Distro MyMovedDebian`
> - 指定三档工具链配置（严格按 spec 生效并持久化到 `~/.config/dsh-wsl-sandbox/profile.json`）：
>   - `-Profile core`（~350MB，约 2 分钟）：`bwrap`/`prlimit`/`socat` + Codex 高频 CLI + C/C++ 基础 + `python3` + Node 22 LTS
>   - `-Profile standard`（~1.2GB，默认推荐）：`core` + `ccache`/`protobuf`/`libpq`/`libxml2` + `mise` + `uv`/`pytest`/`ruff`/`mypy`/`pyright`/`black` + `pnpm`/`yarn`/`bun`/`typescript`/`eslint`/`prettier` + Go + `golangci-lint` + Rust 最小化套件
>   - `-Profile universal`（~3.5GB，纯预编译）：`standard` + `clang`/`bazelisk` + `mise` Node 20/22/24 + `poetry`/`isort` + OpenJDK 21 + `maven`/`gradle` + `ruby` + `php-cli`/`composer`
> - 使用上游代理：`-Proxy http://127.0.0.1:7890`
> - 仅备份原有 WSL 配置到任意自定义目录：`-BackupOnly -BackupDir "D:\Backups\WSL-Orig" -OpenBackupFolder`
> - 如尚未安装任何 WSL 2 发行版，向导会提示可选的官方发行版列表（默认推荐 `Ubuntu-26.04`，也可选择 `Ubuntu-24.04`、`Debian`、`FedoraLinux-42`、`Arch`、`kali-linux` 等）。

如果你已经在 WSL 内，也可以随时直接按需运行单步幂等脚本与体检：
```bash
# 支持 --step all|base|cli|node|python|go|rust|go-rust|extra
bash ~/.local/share/dsh-wsl-sandbox/runner/packages/bootstrap/provision-wsl.sh --profile standard --mirror cn
node ~/.local/share/dsh-wsl-sandbox/runner/dist/packages/bootstrap/src/doctor.js --strict-wsl2 --profile standard
```

### 第 2 步：在 DeepSeek Harness (DSH) 中注册插件

```powershell
# 注册到 DSH（按你使用的模式选择 web 或 desktop）：
dsh plugin --profile web add .\dsh-wsl-sandbox-0.1.0.tgz
dsh plugin --profile desktop add .\dsh-wsl-sandbox-0.1.0.tgz
```

- 启动 DSH 后打开 **设置（Settings） -> WSL 2 沙箱**（原生挂载 `settings.section`，与 `dsh-purge`、`dshmarket`、`cc-safety-net` 等 Top 27 插件零冲突共存）。
- 在 DSH Web 服务运行期间也可直接打开同源完整控制台路由：`/wsl-sandbox/ui`。

---

## 二、WSL Manager 迁移实例、配置文件夹权限隔离与物理硬件/驱动说明

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

---

## 三、通过 GitHub Desktop 或命令行推送到 GitHub 公开仓库

### 方式 1：GitHub Desktop 零命令直接推送（推荐）
1. 解压 `dsh-wsl-sandbox-github-desktop.zip` 到本地目录。
2. 打开 **GitHub Desktop** -> `File` -> `Add local repository...` -> 选择解压出来的 `dsh-wsl-sandbox` 文件夹。
3. 确认顶部显示 `Push origin`（基于 `origin/main` 干净 fast-forward 提交），直接点击 **`Push origin`** 即可完成推送。

### 方式 2：使用 `dsh-wsl-sandbox-main.bundle`
```zsh
git clone dsh-wsl-sandbox-main.bundle dsh-wsl-sandbox
cd dsh-wsl-sandbox
git checkout -B main
git remote set-url origin https://github.com/mrunbengable2233-lgtm/dsh-wsl-sandbox.git
git push -u origin main
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
