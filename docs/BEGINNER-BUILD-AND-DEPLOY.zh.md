# `dsh-wsl-sandbox` 小白零基础编译、测试与部署全攻略（保姆级手把手版）

哪怕你以前**从来没自己编译过 Node.js / TypeScript 项目、没配过终端编码、没用过 WSL 2，甚至刚装好 DeepSeek Harness (DSH)**，只要按顺序一步步复制粘贴命令，10 分钟内就能一次配齐、终身省心。

---

## 一、先用大白话搞懂：它到底是怎么工作的？

你可以把 `dsh-wsl-sandbox` 理解成给 DSH 装上的一个**「WSL 2 安全保险箱 + Windows 终端防呆器」**：

1. **平时 AI 改代码、跑脚本都在 WSL 2 的 Linux 保险箱里完成**，默认看不到你 Windows 上的 `C:\`、`D:\` 全盘私人文件，也改不了你的 `.ssh` 密钥或 `.git/hooks`。
2. **万一 AI 想在 Windows PowerShell 里乱敲高危命令、乱套壳（比如 PowerShell 里套 CMD）、或者动你的手机刷机/网卡驱动**，插件会在执行前拦下来，弹窗让你点「批准」或「拒绝」（而且不消耗大模型 Token）。
3. **不折腾电脑、不伤硬盘**：
   - **不用装 Docker Desktop**，**不用编译 Linux 内核或 C++**（纯 TypeScript，**0 个第三方运行时 npm 依赖**）；
   - **不用重复装多套 Node.js**：Windows 上直接共用 DSH 自带的 Node 运行时（DSH 内置 Node 24）；WSL 2 里自动复用已有 Node 22/24，没装过才自动装预编译 Node 24 LTS；
   - **不伤固态硬盘（SSD）**：日志在内存合并后最多每 `2.5 秒` 批量写盘一次，空闲 `0` 文件占用锁，重复日志自动折叠。

---

## 二、【必做第一步】安装 PowerShell 7，设为第一首选默认终端并永久开启 UTF-8

> **为什么所有小白都应该最先做这一步？**
> Windows 系统默认自带的蓝色图标「Windows PowerShell 5.1 (`powershell.exe`)」是十多年前的老版本，默认使用 **GBK (`CP936`) 编码**！AI 工具在里面跑命令时，极易出现**中文变乱码、引号被吞掉导致卡死在 `>>` 提示符、以及 `&&` 语法报错**。
>
> 只要花 **2 分钟** 装上微软官方新版 **PowerShell 7 (`pwsh.exe`，黑色图标)**，把它设成**第一首选终端**并**永久锁定 UTF-8 编码**，以后用 DSH、Claude Code、VS Code 再也不会踩乱码坑！

### 第 1 小步：一键安装 PowerShell 7 (`pwsh`)

1. 在键盘上按下 **`Win + X`**（或右键点击屏幕左下角 Windows 开始图标），点击 **「终端 (Terminal)」** 或 **「PowerShell」**。
2. 复制粘贴下面这行微软官方安装命令，按回车（如果弹出安装确认输入 `Y` 回车即可）：
   ```powershell
   winget install --id Microsoft.PowerShell --source winget
   ```
   > *备用方法：如果你的精简版系统没有 `winget`，打开自带的 **Microsoft Store（微软应用商店）**，搜索 **`PowerShell`**（认准黑色图标、发布者 Microsoft Corporation），直接点「获取/安装」即可。*
3. **安装完成后，把当前旧窗口关掉**，重新按 `Win + X` -> 打开「终端 (Terminal)」。

### 第 2 小步：把 PowerShell 7 设为「第一首选默认终端」并永久保存

下面提供**「鼠标点选法」**和**「一键自动脚本法」**，任选一种都会永久保存，以后开机或打开终端默认就是 PowerShell 7：

#### 方法 A：鼠标 3 秒设置法（最直观）
1. 打开 **Windows 终端 (Terminal)**，按键盘快捷键 **`Ctrl + ,`**（逗号）打开设置页面。
2. 在左侧 **「启动 (Startup)」** 页面修改两项：
   - **默认配置文件 (Default profile)**：下拉选择 **`PowerShell`**（**认准黑色图标的新版 PowerShell 7**，千万别选蓝色图标的旧版 `Windows PowerShell`！）；
   - **默认终端应用程序 (Default terminal application)**：下拉选择 **`Windows 终端 (Windows Terminal)`**。
3. 点击右下角蓝色的 **「保存 (Save)」** 按钮！
4. **关掉终端再重新打开**，现在你看到第一行写着 `PowerShell 7.x.x`，说明你已经跑在新版 PowerShell 7 里了！

#### 方法 B：在编辑器 / DSH 开发环境中同步锁定 PowerShell 7 为第一首选终端
如果你同时使用 **VS Code / Cursor** 或基于终端配置的 IDE，在设置 JSON 中加入下面这一行即可永久将 PowerShell 7 锁定为第一首选终端：
```json
"terminal.integrated.defaultProfile.windows": "PowerShell"
```
同时你也可以在刚才打开的 **PowerShell 7** 窗口里运行下面这段脚本，它会自动帮你检查并把 **Windows Terminal 的默认首选 Profile** 和 **当前用户 PATH 优先级** 一并持久化锁定到 PowerShell 7：
```powershell
# 自动将 Windows Terminal 的首选默认配置 (defaultProfile) 持久化锁定为 PowerShell 7 (pwsh.exe)
$wtSettingsPaths = @(
  "$env:LOCALAPPDATA\Packages\Microsoft.WindowsTerminal_8wekyb3d8bbwe\LocalState\settings.json",
  "$env:LOCALAPPDATA\Packages\Microsoft.WindowsTerminalPreview_8wekyb3d8bbwe\LocalState\settings.json",
  "$env:LOCALAPPDATA\Microsoft\Windows Terminal\settings.json"
)
foreach ($wtPath in $wtSettingsPaths) {
  if (Test-Path $wtPath) {
    Copy-Item $wtPath "$wtPath.bak" -Force
    $rawJson = Get-Content $wtPath -Raw -Encoding UTF8
    # PowerShell 7 在 Windows Terminal 中的官方固定 GUID 为 {574e775e-4f2a-5b96-ac1e-a2962a402336}
    if ($rawJson -match '574e775e-4f2a-5b96-ac1e-a2962a402336') {
      $updated = $rawJson -replace '"defaultProfile"\s*:\s*"\{?[0-9a-fA-F-]+\}?"', '"defaultProfile": "{574e775e-4f2a-5b96-ac1e-a2962a402336}"'
      Set-Content -Path $wtPath -Value $updated -Encoding utf8NoBOM
      Write-Host "已将 Windows Terminal 第一首选终端永久锁定为 PowerShell 7: $wtPath" -ForegroundColor Green
    }
  }
}
```

### 第 3 小步：永久持久化 UTF-8 编码（不影响国内老软件，每次启动自动生效！）

> **防坑提醒**：网上有些老教程让你去勾选「控制面板 -> 区域 -> Beta 版：使用 Unicode UTF-8 提供全球语言支持」，**千万不要勾那个全局 Beta 开关**，否则很多国内老软件会出现乱码！
>
> 最科学、最干净的做法是：**写入 PowerShell 7 个人启动配置文件（`$PROFILE`）+ 用户环境变量**，只让终端、AI 工具、Node、Python、Git 100% 永久走纯净无 BOM 的 UTF-8！

在已经打开的 **PowerShell 7（黑色图标，`pwsh`）** 窗口里，**整段复制粘贴**下面这段命令并按回车（无需管理员权限，重复执行也完全安全）：

```powershell
# 永久写入 PowerShell 7 全局个人配置文件 ($PROFILE.CurrentUserAllHosts) 与用户级 UTF-8 环境变量
$profilePath = $PROFILE.CurrentUserAllHosts
$profileDir  = Split-Path -Parent $profilePath
if (!(Test-Path $profileDir)) {
  New-Item -ItemType Directory -Path $profileDir -Force | Out-Null
}

$utf8InitBlock = @'
# >>> dsh-pwsh7-utf8-persist >>>
$__dshUtf8NoBom = [System.Text.UTF8Encoding]::new($false)
[Console]::InputEncoding  = $__dshUtf8NoBom
[Console]::OutputEncoding = $__dshUtf8NoBom
$OutputEncoding           = $__dshUtf8NoBom
$PSDefaultParameterValues['Out-File:Encoding']    = 'utf8NoBOM'
$PSDefaultParameterValues['Set-Content:Encoding'] = 'utf8NoBOM'
$PSDefaultParameterValues['Add-Content:Encoding'] = 'utf8NoBOM'
if ($IsWindows) { chcp 65001 > $null }
# <<< dsh-pwsh7-utf8-persist <<<
'@

$existingContent = if (Test-Path $profilePath) { Get-Content $profilePath -Raw -ErrorAction SilentlyContinue } else { '' }
if ($existingContent -notmatch 'dsh-pwsh7-utf8-persist') {
  Add-Content -Path $profilePath -Value "`n$utf8InitBlock" -Encoding utf8NoBOM
}

# 同步持久化 Python 与命令行分页器的 UTF-8 用户级环境变量（重启电脑也永久保留）
[Environment]::SetEnvironmentVariable('PYTHONUTF8', '1', 'User')
[Environment]::SetEnvironmentVariable('PYTHONIOENCODING', 'utf-8', 'User')
[Environment]::SetEnvironmentVariable('LESSCHARSET', 'utf-8', 'User')

# 立即在当前窗口加载生效
. $profilePath
Write-Host "成功！PowerShell 7 已永久持久化 UTF-8 编码 -> $profilePath" -ForegroundColor Green
```

#### 10 秒验证是否全部持久化成功
关掉终端再重新打开一个新的终端窗口，输入下面这行检查命令：
```powershell
"当前版本: PowerShell $($PSVersionTable.PSVersion) | 控制台编码: $([Console]::OutputEncoding.BodyName) | 代码页: $(chcp)"
```
只要看到输出包含 **`PowerShell 7.`**、**`utf-8`** 和 **`65001`**，你的 Windows 终端底座就已经达到完美状态了！

---

## 三、【准备工作第二步】检查电脑里有没有 WSL 2

在刚才配好的 **PowerShell 7** 窗口里输入：

```powershell
wsl.exe -l -v
```

- **情况 A（已经装好了）**：列表里出现了比如 `Ubuntu-24.04`、`Ubuntu-26.04`、`Debian` 等名字，且右边 `VERSION` 列写着 **`2`**。直接进入第四节或第五节！
  > *小贴士：就算你以前用 **WSL Manager** 把虚拟磁盘迁移到了 D 盘/E 盘，导致资源管理器左边看不到 Linux 企鹅图标，只要 `wsl.exe -l -v` 能看到，本插件就能 100% 自动识别！*
- **情况 B（还没装 WSL 2 或没有任何发行版）**：复制下面这行命令一键安装官方 Ubuntu LTS（装完按提示重启一次电脑，并设置一个普通的英文用户名和密码，**注意不要用 `root` 当日常用户**）：
  ```powershell
  wsl.exe --install -d Ubuntu-26.04
  ```

---

## 四、路线 A：纯小白直接安装部署（不改源码，最快 2 步搞定）

如果你只是想把插件装进 DSH 里用起来，拿到解压后的插件文件夹（或 `.tgz` 安装包）后，在 **PowerShell 7** 里按下面两步走：

### 第 1 步：进入插件文件夹，一键配好 WSL 2 沙箱环境

假设你把插件解压到了 `D:\Plugins\dsh-wsl-sandbox`：

```powershell
# 1. 进入插件所在文件夹（把路径换成你实际解压的位置）
Set-Location "D:\Plugins\dsh-wsl-sandbox"

# 2. 临时允许当前窗口运行本地安装脚本（关掉窗口自动恢复默认，很安全）
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force

# 3. 运行一键安装向导（国内网络推荐加上 -Mirror cn 走清华/阿里镜像加速）
.\packages\bootstrap\install-dsh-plugin.ps1 -Provision -Profile standard -Mirror cn
```

**运行过程中会发生什么？**
1. 自动找到你电脑里的 WSL 2 发行版（有多个会列出序号让你选）。
2. 自动把你原有的 `.wslconfig` 和 `/etc/wsl.conf` **以只读方式备份**好（绝不偷偷乱改你的系统配置）。
3. 把沙箱运行器部署进 WSL 2 内部原生 `ext4`（不会锁死你 Windows 上的文件夹）。
4. 先在 WSL 2 里检测并补齐沙箱必需组件（`bubblewrap`、`socat`、`prlimit` 及开发工具链，首次 `sudo apt` 安装软件包时会提示输入一次你的 Linux 密码）：
   - `-Profile core`（约 350MB，最快，2 分钟）：沙箱核心 + 基础命令行 + Python3 + Node（复用已有 Node 22/24 或装 Node 24 LTS）。
   - `-Profile standard`（约 1.2GB，**最推荐**）：配齐 Python `uv`/测试工具、前端 `pnpm`/`bun`/`ts`、Go、Rust 常用开发套件。
   - `-Profile universal`（约 3.5GB，全能包）：再额外装上 Java 21、Clang、Maven/Gradle、Ruby、PHP。
5. 验证通过后才写入启用配置，并自动跑一遍 `dsh-wsl-doctor` 体检，看到 **`Verdict: READY`** 即完全就绪！

### 第 2 步：把插件注册进 DeepSeek Harness (DSH)

任选**图形界面**或**命令行**其中一种：

- **方法 1：DSH 桌面版（图形界面导入，最适合小白）**
  打开 **DSH Desktop** -> 左下角 **设置（Settings） -> 插件（Plugins）** -> 导入本地插件 -> 选择 **`dsh-wsl-sandbox-0.2.0.tgz`** 压缩包（或直接选 `D:\Plugins\dsh-wsl-sandbox` 文件夹），启用即可。

- **方法 2：DSH 命令行一键添加**
  ```powershell
  # 如果你用 DSH 桌面版：
  dsh plugin --profile desktop add .\dsh-wsl-sandbox-0.2.0.tgz

  # 如果你用 DSH 网页版 / CLI：
  dsh plugin --profile web add .\dsh-wsl-sandbox-0.2.0.tgz
  ```

### 第 3 步：确认插件已经生效
打开 DSH 的 **「设置 -> WSL 2 沙箱」** 页面：
- 顶部状态栏会显示绿点、**受控发行版名称** 以及 **共用 Node 版本**；
- 切到 **「内核体检」** 标签页可查看内核隔离状态，切到 **「运行日志」** 可实时查看或导出日志。

---

## 五、路线 B：从零下载源码、自己编译、跑单元测试与打包

如果你想自己拉取 GitHub 源码、修改代码、编译并跑通全套单元测试，下面是完整步骤。

### 先搞懂：在 Windows PowerShell 7 跑编译/测试，还是在 WSL 2 里跑？

| 操作 | 在 Windows PowerShell 7 跑 | 在 WSL 2 (Ubuntu) 终端里跑 |
| :--- | :--- | :--- |
| **`npm run build`（编译源码）** | 完全支持 | 完全支持 |
| **`node test` 或 `npm test`（跑单测）** | 支持！自动跑核心逻辑、红队门禁与插件兼容测试，并**自动跳过**仅 Linux 内核才有的 `bwrap` 测试项 | **最推荐！** 60 项测试（含真 Linux 内核命名空间、`seccomp-bpf` 系统调用拦截、进程防泄漏）**100% 全量真跑** |
| **`npm run fuzz:check`（危险命令红队校验）** | 完全支持（零执行纯内存校验，绝对安全） | 完全支持 |
| **`npm pack`（生成 `.tgz` 安装包）** | 完全支持 | 完全支持 |

> **需要提前装 `npm install` 吗？**
> 本项目**零第三方运行时依赖**！只要有 Node.js（`>= 22.19` 或 `Node 24 LTS`），连 `npm install` 都不需要下载任何外部包，断网离线都能 1 秒完成编译！

### 手把手 4 步完成编译、全量单测与打包（推荐在 WSL 2 终端执行）

在 PowerShell 7 里输入 `wsl` 进入你的 WSL 2 Linux 环境（或者直接在 PowerShell 7 里跑，命令完全通用）：

#### 1. 克隆源码仓库并进入目录
```bash
git clone https://github.com/mrunbengable2233-lgtm/dsh-wsl-sandbox.git
cd dsh-wsl-sandbox
```

#### 2. 编译全部 TypeScript 源码与前端界面
```bash
npm run build
```

#### 3. 运行自动化单元测试（3 种写法任选其一，全部原生兼容）
```bash
# 写法 1（标准 npm 命令）：
npm test

# 写法 2（顺手敲的 node test）：
node test

# 写法 3（Node 原生测试运行器）：
node --test
```
> **进阶玩法**：如果你想让 AI 帮你批量生成几百条混淆危险命令来压测沙箱门禁，请直接参考配套红队文档：[`docs/AI-DANGEROUS-COMMAND-FUZZING-GUIDE.zh.md`](./AI-DANGEROUS-COMMAND-FUZZING-GUIDE.zh.md)，运行 `npm run fuzz:check` 即可秒出结果！

#### 4. 打包成可发给别人安装的 `.tgz` 插件包
```bash
npm pack
```
当前目录下就会生成 **`dsh-wsl-sandbox-0.2.0.tgz`**。

---

## 六、新手常见报错与排坑速查表（FAQ）

### Q1：为什么以前有人反馈 `node test` 跑不起来？现在修好了吗？
**在 `v0.2.0` 中已彻底修好！** 之前跑不起来是因为：
1. 有人直接敲 `node test`（少写了 `--`），旧版根目录没有 `test.js` 入口文件；
2. 旧版 `package.json` 打包配置漏了 `tests/` 目录，或没跑 `npm run build` 直接跑单测导致缺 `client.js` / `dist/`；
3. 在纯 Windows 命令行下跑 Linux 专属的 `bwrap` 内核测试未自动标记跳过。
现在无论敲 `node test`、`npm test` 还是 `node --test`，无论在 Windows 还是 WSL 2 下，都会自动加锁完成预编译并稳定运行。

### Q2：我电脑里有 DSH 桌面版，但命令行里没单独装过 Node.js，能部署这个插件吗？
**完全可以！** 安装脚本会自动寻找并复用 DSH Desktop 自带的运行环境（或直接调用 Windows 自带 `tar.exe` 部署预编译包），插件运行在 DSH 进程内部，与其他所有 DSH 插件共用同一个 Node，无需你在 Windows 上重复安装 Node.js。

### Q3：我要给手机解 BL 锁（Fastboot / ADB / 9008 线刷），或者插了「Windows 免驱、但不支持 Linux」的 USB 网卡调驱动，该怎么用？
**直接在 Windows 宿主侧调用驱动和刷机工具即可，不要强行用 `usbipd` 塞进 WSL 2！**
- 微软默认 WSL 2 内核没有手机厂商的 Windows WinUSB/OEM 驱动，也缺少绝大多数免驱 USB 网卡的 Linux `.ko` 驱动模块。
- 当需要执行 `fastboot`、`adb`、`pnputil`（装驱动）或 `NetAdapter`（改网卡）时，本插件会在 Windows 侧弹出 **单次硬件人工审批卡片**，点一次批准安全执行一次，既不耽误刷机/调驱动，又防止 AI 擅自乱动硬件。

### Q4：以后不想用了怎么卸载？会不会锁死文件夹删不掉？
**绝不会锁文件夹！**（采用 `--cd ~` + WSL 原生 `ext4` + 日志空闲 `0` 文件句柄设计）：
1. 在 DSH 插件管理里禁用或移除 `dsh-wsl-sandbox`；
2. Windows 上的源码/安装包文件夹随时可直接删除；
3. 如需彻底清理配置与缓存，按需删除 `%USERPROFILE%\.dsh\dsh-wsl-sandbox` 与 WSL 内的 `~/.local/share/dsh-wsl-sandbox` 即可。
