# DSH WSL 2 沙盒环境建置引导提示词（笔记本轻量化 · 零 Docker / 零内核构建）

> 将本提示词注入或发送给宿主机上的 DSH Agent（或启用 `.agents/skills/dsh-wsl-env-setup/SKILL.md`），即可让 Agent 在你的审批下分步在 WSL 2 中配齐对标 Codex 的沙盒开发环境，**全程不跑 Docker 镜像构建、不编译 Linux 内核、不源码编译 Python**。

---

## 注入给 Agent 的标准执行指令

你现在负责在用户的 Windows 笔记本上，为 `dsh-wsl-sandbox` 插件配置一个安全、轻快、可验证的 WSL 2 沙盒环境。严格遵守以下 6 条红线：

1. **禁止重构建**：绝不在笔记本上构建 Docker 镜像、绝不编译 Linux 内核、绝不使用 `pyenv` 源码编译 Python。一律使用任意已注册的 WSL 2 发行版（Ubuntu 26.04/24.04/22.04、Debian、Fedora、Arch、openSUSE、Alpine，以及通过 WSL Manager 导入/迁移磁盘的自定义实例）+ 预编译二进制包（系统包管理器、预编译 Node 22、Astral `uv`、官方 Go tarball、`rustup --profile minimal`）。
2. **先探测、后确认、再安装**：先执行只读探测（同时检查 `wsl.exe -l -v` 与只读 `HKCU:\Software\Microsoft\Windows\CurrentVersion\Lxss\*`，确保能识别经 WSL Manager 导入/迁移 VHDX 且从资源管理器左侧消失的实例），向用户展示发现结果和计划安装的档位、体积与镜像/代理方案，**获得用户明确确认后**才执行安装命令。
3. **禁止私改共享系统配置 & 禁止使用 `wsl --shutdown`**：Windows 官方 **WSL Settings** 与第三方 **WSL Manager** 共享同一套 `/etc/wsl.conf` 与 `%USERPROFILE%\.wslconfig`。严禁自动修改它们；任何配置备份以只读权限 (`0400`/`+R`) 保存到受保护目录（严禁指向 `%USERPROFILE%`、`~/.dsh` 或 VHDX `BasePath`）。如确需重启目标发行版，一律只用 `wsl.exe --terminate <目标发行版>`，**严禁使用 `wsl.exe --shutdown`** 以免关掉其他 WSL 会话！
4. **原生 ext4 落地（零 `/mnt` 依赖、零 Windows 文件夹占用）**：使用 `node scripts/stage-wsl-runner.mjs --distro <目标发行版>` 将 Runner 与安装脚本部署到 WSL 原生 `$HOME/.local/share/dsh-wsl-sandbox/runner/`，既兼容 `[automount] enabled = false`，又避免卸载/禁用插件时出现不可解除的文件夹占用。
5. **必须非 root 运行**：确认目标发行版存在并默认使用非 root 普通用户（`uid > 0`），绝不以 `root` 作为日常沙盒执行身份。
6. **以 `dsh-wsl-doctor --profile <所选档位>` 实测为准**：安装完成后必须运行 `dsh-wsl-doctor --strict-wsl2 --profile <所选档位> --json`，逐项核验 `WSL 2`、`uid > 0`、`bwrap`、`unprivileged userns`、`seccomp`（`AF_VSOCK` & `io_uring` EPERM）、`/mnt` 与 `~/.dsh`/`~/.config/dsh-wsl-sandbox` 遮蔽自检全绿后才宣告完成；如遇 AppArmor 限制无特权 userns，禁止降级裸跑，给出精确修复命令请用户确认。

### 执行步骤

#### 第一步：只读探测（无需修改任何文件）
1. 在 Windows 宿主机运行 `wsl.exe -l -v`（以及只读查询 `HKCU:\Software\Microsoft\Windows\CurrentVersion\Lxss\*` 获取迁移后的 `BasePath`），过滤掉 `docker-desktop` / `docker-desktop-data` 等内部发行版。
2. 如果已有目标 WSL 2 发行版，执行只读探针（务必带 `--cd ~` 避免锁定当前 Windows 目录）：
   ```powershell
   wsl.exe -d <distro> --cd ~ -- sh -c 'id; cat /etc/os-release 2>/dev/null | head -n 3; uname -r; uname -m; command -v bwrap prlimit socat node python3 git rg fdfind fd jq uv go cargo mise || true'
   ```
3. 向用户确认 3 个选项：
   - **目标发行版**：复用现有任意 WSL 2 发行版（含 WSL Manager 迁移实例），还是安装干净的官方新发行版（默认推荐 `Ubuntu-26.04`，也可选 `Ubuntu-24.04`、`Debian`、`FedoraLinux-42`、`Arch`、`kali-linux` 等）？
   - **环境档位（真正按档位安装并持久化到 `profile.json`）**：
     - `core`（~350MB，约 2 分钟）：`bwrap` + `prlimit` + `socat` + Codex 高频 CLI（`git`/`rg`/`fd`/`jq`/`sqlite3`/`rsync`/`ctags` 等）+ C/C++ 基础 + `python3` + Node 22。
     - `standard`（~1.2GB，推荐）：`core` + `ccache`/`protobuf`/`libpq`/`libxml2` + `mise` + `uv`/`pytest`/`ruff`/`mypy`/`pyright`/`black` + `pnpm`/`yarn`/`bun`/`typescript`/`eslint`/`prettier` + Go/`golangci-lint` + Rust（`rustc`/`cargo`/`rustfmt`/`clippy`）。
     - `universal`（~3.5GB，纯预编译二进制）：`standard` + `clang`/`clang-format`/`clang-tidy` + `bazelisk` + `mise` Node 20/22/24 + `poetry`/`isort` + OpenJDK 21 + `maven`/`gradle` + `ruby` + `php-cli`/`composer`。
   - **国内网络加速**：是否开启 `--mirror cn`（清华 APT/PyPI、`UV_PYTHON_INSTALL_MIRROR`、`npmmirror`、`goproxy.cn`、`rsproxy.cn`），以及是否需要透传宿主机本地代理（例如 `http://127.0.0.1:7890`）？

#### 第二步：原生 ext4 部署与分步幂等安装（每步可断点续跑）
在 Windows PowerShell 一步完成动态探测、原生 ext4 分发（零 `/mnt` 锁定）与按档位安装：
```powershell
.\packages\bootstrap\install-dsh-plugin.ps1 -Distro <目标发行版> -Profile <core|standard|universal> -Mirror <global|cn> -Provision
```
或在 WSL 内直接调用分步脚本（支持 `--step all|base|cli|node|python|go|rust|go-rust|extra`）：
```bash
bash ~/.local/share/dsh-wsl-sandbox/runner/packages/bootstrap/provision-wsl.sh --profile <core|standard|universal> [--mirror cn] [--proxy <代理>] [--step all|base|cli|node|python|go|rust|extra]
```

#### 第三步：闭环验证
在目标 WSL 2 发行版内运行：
```bash
node ~/.local/share/dsh-wsl-sandbox/runner/dist/packages/bootstrap/src/doctor.js --strict-wsl2 --profile <所选档位> --json
```
汇总输出沙盒内核自检结果、配置目录遮蔽与 ACL 状态、USBIP/内核驱动提示（区分手机 ADB/Fastboot/EDL `libusb` 节点与依赖 Windows 驱动的网卡/OEM 工具）以及当前档位对应的工具链版本矩阵；如有任一安全红线未通过，明确标注 `blocked` 原因与最小修复命令。
