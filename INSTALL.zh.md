# `dsh-wsl-sandbox` 本地安装、原始 WSL 配置备份与 npm 托管指南

本指南面向日常使用者与仓库维护者，提供 **零 Docker、零内核编译** 的三步本地安装流程、**禁用全盘挂载 / 指定单目录快捷挂载 / 原始 WSL 配置备份还原** 操作说明，以及后续发布托管到 **npm**（与 GitHub 公开仓库）的完整步骤。

---

## 一、Windows 10/11 + WSL 2 本地快速安装（3 步完成）

> **前置条件**：Windows 10 (21H2+) 或 Windows 11，已启用 WSL 2（推荐 `Ubuntu-24.04` 或 `Ubuntu-22.04`），宿主机 Node.js `>= 22.18.0`。

### 第 1 步：准备 WSL 2 工具链（零源码编译，自动备份原版配置）

如果没有安装 Ubuntu，先在 Windows PowerShell 中执行：
```powershell
wsl.exe --install -d Ubuntu-24.04
```

进入 WSL 2 终端（非 `root` 普通用户），在仓库目录下执行幂等安装脚本（脚本会在第一步**自动将你原有的 `/etc/wsl.conf` 与 `/etc/fstab` 备份到 `~/.config/dsh-wsl-sandbox/backups/`**）：

```bash
# 国内网络环境（自动配置清华镜像源与包管理器镜像）：
bash packages/bootstrap/provision-wsl.sh --profile standard --mirror cn

# 或使用本机代理（如 Clash / Mihomo / v2rayN）：
bash packages/bootstrap/provision-wsl.sh --profile standard --proxy http://127.0.0.1:7890
```

完成后运行内核隔离与工具链体检（确认 `bwrap`、`seccomp` 阻断 `io_uring` 与 `AF_VSOCK` 均显示 `READY`）：
```bash
node dist/packages/bootstrap/src/doctor.js
```

### 第 2 步：在 DeepSeek Harness (DSH) 中安装插件

#### 方式 A：直接通过本地 `.tgz` 包或目录安装（CLI / Web / Desktop 通用）
在 Windows PowerShell 中执行：
```powershell
# 1. 运行安装向导（会自动备份你原有的 C:\Users\<用户名>\.wslconfig，并生成 ~/.dsh/dsh-wsl-sandbox/config.json）
.\packages\bootstrap\install-dsh-plugin.ps1 -Distro Ubuntu-24.04 -WorkspaceRoot /home/<你的Linux用户名>/workspace -UpsertAgentsMd

# 2. 注册到 DSH（按你使用的模式选择 web 或 desktop）：
dsh plugin --profile web add .\dsh-wsl-sandbox-0.1.0.tgz
dsh plugin --profile desktop add .\dsh-wsl-sandbox-0.1.0.tgz
```

#### 方式 B：在 DSH 桌面端 / Web 设置页查看控制台
- 启动 DSH 后打开 **设置（Settings） -> WSL 2 沙箱**（已原生挂载 `settings.section`，与 `dsh-purge`、`dshmarket`、`cc-safety-net` 等 Top 20+ 插件 100% 零冲突共存）。
- 也可在 DSH Web 服务运行期间访问同源独立完整控制台路由：`/wsl-sandbox/ui`。

---

## 二、禁用全盘挂载、指定单目录快捷挂载与原始 WSL 配置备份

这两项高频入口已直接放置在控制台首页 **「状态」标签页正中央**（无需翻找折叠菜单）：

### 1. 禁用 Windows 全盘挂载（双层防护机制）
- **第一层（默认强制开启，无需重启 WSL）**：每次 AI 调用 `wsl_*` 工具时，`bwrap` 都会在内核挂载命名空间内执行 `--tmpfs /mnt`，将 AI 看到的 `/mnt` 替换为空内存盘。**AI 完全看不到 `C:\`、`D:\` 全盘**，而你自己的 Windows 与 WSL 终端不受影响。
- **第二层（可选：连 WSL 发行版底层也彻底关闭自动挂载）**：如果你希望 WSL 启动时根本不挂载 `C:\`、`D:\`，可在 WSL 内执行：
  ```bash
  bash packages/bootstrap/provision-wsl.sh --disable-automount
  ```
  然后在 Windows PowerShell 执行 `wsl.exe --shutdown` 重启生效。

### 2. 指定单目录快捷挂载（直接粘贴 Windows 路径）
1. 在主界面 **「指定单目录快捷挂载」** 输入框中，直接粘贴 Windows 文件夹路径（支持资源管理器直接复制带引号的路径），例如：
   - `D:\Datasets\ESP32`
   - `"C:\Users\Alice\Downloads\spec-v2"`
2. 选择 **`只读 (ro)`**（推荐默认）或 **`读写 (rw)`**，点击 **「挂载此目录」**。
3. 系统会自动将其规范化为 `/mnt/d/Datasets/ESP32` 并仅将该单目录挂载至沙箱内的 **`/shares/ESP32`**（整盘根目录如 `C:\`、`D:\`、`C:\Windows` 或整个用户主目录 `C:\Users\Alice` 会被 `POLICY_BLOCK` 自动拒绝）。
4. 用完后点击条目右侧的 **「取消挂载」**，后端会立即自增会话世代（`generation++`）并终止旧沙箱进程组。

> **日常零配置传文件小贴士**：也可以直接打开 Windows 资源管理器左侧边栏的 **「Linux -> Ubuntu-24.04 -> home -> <用户名> -> workspace」** 拖拽复制文件进工作区，全程无需开启任何跨盘挂载。

### 3. 原始 WSL 配置文件备份（支持任意自定义路径 + 资源管理器单文件定位）与一键还原
我们提供了可自选路径的多重备份保障，绝不破坏你原有的 WSL 环境：
1. **任意指定备份保存目录**：
   - 在控制台主界面 **「禁用 Windows 全盘挂载与原始 WSL 配置备份」** 卡片中，可直接粘贴任意目录路径（例如 `D:\Backups\WSL-Orig`），或点击 **「浏览选择目录...」** 拉起 Windows 原生文件夹选择对话框（`FolderBrowserDialog`），然后点击 **「立即备份到此目录」**。
   - 命令行安装同样支持 `-BackupDir` / `--backup-dir` 与自动拉起资源管理器：
     ```powershell
     .\packages\bootstrap\install-dsh-plugin.ps1 -Distro Ubuntu-24.04 -BackupDir "D:\Backups\WSL-Orig" -BackupOnly -OpenBackupFolder
     ```
     ```bash
     bash packages/bootstrap/provision-wsl.sh --backup-configs --backup-dir "D:\Backups\WSL-Orig" --open-backup-dir
     ```
2. **所有原始备份列表项一键拉起 Windows 原生资源管理器**：
   - 列表中的每一项备份（`.wslconfig.orig`、`wsl.conf.<Distro>.orig`、`fstab.<Distro>.orig` 等）右侧均提供 **「在资源管理器中定位」** 按钮，点击后通过无壳 `explorer.exe /select,"<完整文件路径>"` 直接打开 Windows 资源管理器并高亮选中该备份文件（后端严格校验备份目录边界并阻断 `.exe`/`.bat` 等可执行后缀，零命令注入风险）。
   - 仓库内同时附带原厂默认参考模板 [`packages/bootstrap/templates/`](./packages/bootstrap/templates/)。
3. **一键无损还原原厂配置**：
   ```bash
   # WSL 内还原 /etc/wsl.conf 与 APT 源：
   bash packages/bootstrap/provision-wsl.sh --restore-configs --backup-dir "D:\Backups\WSL-Orig"
   ```
   ```powershell
   # Windows PowerShell 还原 %USERPROFILE%\.wslconfig 并重启 WSL：
   .\packages\bootstrap\install-dsh-plugin.ps1 -Distro Ubuntu-24.04 -BackupDir "D:\Backups\WSL-Orig" -RestoreWslConfig
   wsl.exe --shutdown
   ```

---

## 三、在 macOS (`zsh`) 上解包推送到 GitHub 公开仓库

如果你从压缩包（`.zip`）或 `git bundle` 拉取到本地 Mac，执行以下命令即可完整推送到你的 GitHub 公开仓库：

### 方式 1：使用 `dsh-wsl-sandbox-main.bundle`（推荐，保留完整 Git 提交历史）
```zsh
git clone dsh-wsl-sandbox-main.bundle dsh-wsl-sandbox
cd dsh-wsl-sandbox
git checkout -B main
git remote set-url origin https://github.com/mrunbengable2233-lgtm/dsh-wsl-sandbox.git
git push -u origin main
```

### 方式 2：使用 `.zip` 压缩包
```zsh
unzip dsh-wsl-sandbox-complete-2026-11-25.zip -d dsh-wsl-sandbox-release
cd dsh-wsl-sandbox-release/dsh-wsl-sandbox
git remote set-url origin https://github.com/mrunbengable2233-lgtm/dsh-wsl-sandbox.git
git push -u origin main
```

---

## 四、托管发布到 npm（以及接入 DSH 插件市场）

本包已配置好完整的 `exports`、`files` 白名单、`dsh.bundle`、`dsh.client` 与 `prepare` 构建钩子，**零外部运行时依赖**，可直接发布到官方 npm 仓库：

### 1. 首次发布到 npm
在本地仓库根目录执行：
```zsh
# 1. 登录你的 npm 账号
npm login

# 2. 如果包名 dsh-wsl-sandbox 未被占用可直接用；若想挂在你的作用域下可改为 @你的用户名/dsh-wsl-sandbox
# 发布前先本地跑一遍全量测试与干跑预览打包清单：
npm test
npm pack --dry-run

# 3. 正式公开托管到 npm：
npm publish --access public
```

### 2. 发布到 npm 后用户的极简安装命令
一旦托管到 npm，任何人都只需一行命令即可安装：
```powershell
dsh plugin --profile web add dsh-wsl-sandbox
dsh plugin --profile desktop add dsh-wsl-sandbox
```

### 3. 后续版本升级流程
```zsh
npm version patch   # 自动升级版本号 (如 0.1.0 -> 0.1.1) 并打 Git tag
npm test
npm publish --access public
git push && git push --tags
```
