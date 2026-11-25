# DSH WSL 2 沙盒环境建置引导提示词（笔记本轻量化 · 零 Docker / 零内核构建）

> 将本提示词注入或发送给宿主机上的 DSH Agent（或启用 `.agents/skills/dsh-wsl-env-setup/SKILL.md`），即可让 Agent 在你的审批下分步在 WSL 2 中配齐对标 Codex 的沙盒开发环境，**全程不跑 Docker 镜像构建、不编译 Linux 内核、不源码编译 Python**。

---

## 注入给 Agent 的标准执行指令

你现在负责在用户的 Windows 笔记本上，为 `dsh-wsl-sandbox` 插件配置一个安全、轻快、可验证的 WSL 2 沙盒环境。严格遵守以下 5 条红线：

1. **禁止重构建**：绝不在笔记本上构建 Docker 镜像、绝不编译 Linux 内核、绝不使用 `pyenv` 源码编译 Python。一律使用官方现成 WSL 2 发行版（Ubuntu 24.04/22.04 或 Debian）+ 预编译二进制包（`apt`、预编译 Node 22、Astral `uv`、官方 Go tarball、`rustup --profile minimal`）。
2. **先探测、后确认、再安装**：先执行只读探测，向用户展示发现结果和计划安装的档位、体积与镜像/代理方案，**获得用户明确确认后**才执行安装命令。
3. **禁止私改系统配置**：严禁自动修改 `/etc/wsl.conf`、`/etc/fstab`、`%USERPROFILE%\.wslconfig`。如检测到 WSL 1 或配置隐患，只输出只读建议供用户自行决定。
4. **必须非 root 运行**：确认目标发行版存在并默认使用非 root 普通用户（`uid > 0`），绝不以 `root` 作为日常沙盒执行身份。
5. **以 `dsh-wsl-doctor` 实测为准**：安装完成后必须运行 `dsh-wsl-doctor --json`，逐项核验 `WSL 2`、`uid > 0`、`bwrap`、`unprivileged userns`、`seccomp`（`AF_VSOCK` & `io_uring` 拒绝探针）与逃逸面遮蔽全绿后才宣告完成；如遇 Ubuntu 24.04 AppArmor 限制无特权 userns，禁止降级裸跑，给出精确修复命令请用户确认。

### 执行步骤

#### 第一步：只读探测（无需修改任何文件）
1. 在 Windows 宿主机运行 `wsl.exe -l -v`，列出全部发行版与 WSL 版本（过滤掉 `docker-desktop` / `docker-desktop-data` 等内部发行版）。
2. 如果已有目标 WSL 2 发行版，执行只读探针查看已有工具：
   ```powershell
   wsl.exe -d <distro> -- sh -c 'id; uname -r; uname -m; command -v bwrap prlimit socat node python3 git rg fdfind fd jq uv go cargo mise || true'
   ```
3. 向用户确认 3 个选项：
   - **目标发行版**：复用现有 WSL 2 发行版，还是安装干净的官方新发行版（`wsl.exe --install Ubuntu-24.04 --name dsh-sandbox`，如 WSL 版本不支持 `--name` 则 `wsl.exe --install -d Ubuntu-24.04`）？
   - **环境档位**：
     - `core`（~350MB，约 2 分钟）：`bwrap` + `prlimit` + `socat` + Codex 高频 CLI（`git`/`rg`/`fd`/`jq`/`sqlite3`/`rsync`/`ctags` 等）+ C/C++ 基础 + `python3` + Node 22。
     - `standard`（~1.2GB，推荐）：`core` + `mise` + `uv`/`pytest`/`ruff`/`mypy`/`pyright`/`black` + `pnpm`/`yarn`/`bun`/`typescript`/`eslint`/`prettier` + Go/`golangci-lint` + Rust（`rustc`/`cargo`/`rustfmt`/`clippy`）。
     - `universal`（~3.5GB，纯预编译二进制）：`standard` + `clang`/`clang-format`/`clang-tidy` + `bazelisk` + OpenJDK 21 + `maven`/`gradle` + `ruby` + `php-cli`/`composer`。
   - **国内网络加速**：是否开启 `--mirror cn`（清华 APT/PyPI、`npmmirror`、`goproxy.cn`、`rsproxy.cn`），以及是否需要透传宿主机本地代理（例如 `http://127.0.0.1:7890`）？

#### 第二步：分步幂等安装（每步可断点续跑）
按用户确认的选项，分阶段执行（或直接调用项目内置的幂等脚本 `bash packages/bootstrap/provision-wsl.sh --profile <档位> [--mirror cn] [--proxy <代理>]`）：
- Stage 1 (`base`)：`bubblewrap`、`util-linux`、`socat`、Codex CLI、C/C++ 基础库、`fd` 软链。
- Stage 2 (`node`)：预编译 Node 22 LTS（`wsl-runner` 必需）及 `standard`/`universal` 下的 `pnpm`/`yarn`/`bun`/`typescript`/`eslint`/`prettier`。
- Stage 3 (`python`)：安装预编译 `uv` + `uv tool install ruff pytest mypy pyright black`。
- Stage 4 (`go-rust`)：安装官方预编译 Go + `golangci-lint`，`rustup --profile minimal` + `rustfmt`/`clippy`。
- Stage 5 (`extra`，仅 `universal`)：`apt` 预编译 Clang、OpenJDK 21、Maven/Gradle、Ruby、PHP/Composer、`bazelisk`。

#### 第三步：闭环验证
在目标 WSL 2 发行版内运行：
```bash
node packages/bootstrap/src/doctor.ts --json
```
汇总输出沙盒内核自检结果与 Codex 工具链版本矩阵；如有任一安全红线未通过，明确标注 `blocked` 原因与最小修复命令。
