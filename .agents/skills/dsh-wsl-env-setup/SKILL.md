---
name: dsh-wsl-env-setup
description: "受控四步式、零 Docker、零内核编译的 DSH WSL 2 沙箱环境引导建置技能（强制先在设置页开启受控引导通道并完成 -DryRun 预览确认卡片后再分步单次审批安装）。"
---

# DSH WSL 2 沙箱环境受控引导建置技能（零 Docker / 零内核编译）

> **双入口防冲突约定**：  
> - 本插件常态下通过宿主 `L0` 单调守卫**机械锁定** `install-dsh-plugin.ps1`、`stage-wsl-runner.mjs`、`provision-wsl.sh` 与 `uninstall-dsh-plugin.ps1`，防止 AI 未经人类授权私自修改宿主/WSL 环境；  
> - 如用户在尚未配齐 WSL 2 环境时先行导入了插件，须由人类在 DSH **「设置 -> WSL 2 沙箱」**（或 `/wsl-sandbox/ui`）先审阅脚本源码与 `SHA-256` 并点击 **「开启受控引导通道」**（20 分钟限时），本技能方可严格按下方四步顺序引导执行，首次沙箱绑定就绪后引导通道自动关闭。

## 不可逾越的安全红线

1. **常态闭闸、顺序锁定与禁止命令拼接**：
   - 未开启受控引导通道前，**禁止尝试执行任何安装/置备/卸载脚本**；
   - 开启引导通道后，宿主门禁仍**机械拦截**「未先运行 `-DryRun` / `--dry-run` 预览就企图真实安装」的行为，且**严禁使用 `;`、`|`、`&&`、`||`、`$()` 或输出重定向拼接多条命令**，严禁跨越锁定的 `targetDistro` 操作其他 WSL 发行版。
2. **保证主流发行版开箱即用，零 Docker / 零源码编译**：
   - 覆盖主流 WSL 2 发行版：**Ubuntu (26.04/24.04/22.04)、Debian、Kali、Fedora、Arch Linux (`archlinux`)、openSUSE、Alpine**（包括通过 **WSL Manager** 导入/迁移 VHDX 磁盘的自定义实例）；
   - 若探测到 NixOS 等声明式不可变发行版或 WSL 版本 `< 2.4`，须明确提示官方声明式包配置/`wsl --update` 注意事项，绝不强行下载破损 glibc 预编译包或篡改系统。
3. **默认保持 WSL `NAT` 网络模式（无需改为 `mirrored`）**：
   - `dsh-wsl-sandbox` 使用宿主机 `wsl.exe` 标准流管道 + WSL 内 `AF_UNIX` UDS 白名单代理，**不依赖 `mirrored` 网络模式**；日常开发及手机/USB 硬件联调测试强烈建议保留 WSL 2 默认 **`NAT`** 模式。
4. **严禁静默改写共享 WSL 配置 & 严禁全局 `wsl.exe --shutdown`**：
   - `/etc/wsl.conf` 与 `%USERPROFILE%\.wslconfig` 与官方 **WSL Settings** / **WSL Manager** 共享；原始备份以只读权限（`0400` / `attrib +R`）保存；仅重启单一发行版时使用 `wsl.exe --terminate <目标发行版>`，严禁使用 `--shutdown`。
5. **原生 `ext4` 落地 & 强制非 `root`**：固定使用 `wsl.exe -d <Distro> --cd ~`，将 Runner 部署至 `$HOME/.local/share/dsh-wsl-sandbox/runner/`，禁止 `uid == 0`。

---

## 强制四步受控引导流程（严禁跳步）

### 步骤 1/4：只读探测与选型确认（单次审批，不改任何文件）

1. 在用户开启引导通道并允许探测后，仅在宿主机执行单条只读命令列出已注册 WSL 发行版及自定义 VHDX 路径（自动排除 `docker-desktop` 等容器内部实例）：
   ```powershell
   wsl.exe -l -v
   ```
   如需核对经 WSL Manager 迁移后的 `BasePath`，可单独提交只读注册表查询（不得与上条拼接）：
   ```powershell
   Get-ChildItem HKCU:\Software\Microsoft\Windows\CurrentVersion\Lxss | ForEach-Object { Get-ItemProperty $_.PSPath | Select-Object DistributionName, BasePath, Version }
   ```
2. 确认目标发行版后，发送单条带 `--cd ~` 的只读探针：
   ```powershell
   wsl.exe -d <distro> --cd ~ -- sh -c 'id; head -n 3 /etc/os-release 2>/dev/null; uname -r; uname -m; command -v bwrap prlimit socat node python3 git rg fdfind fd jq uv go cargo mise || true'
   ```
3. 与人类确认三项参数：
   - **目标 WSL 2 发行版**（复用已有或全新安装 `Ubuntu-26.04` / `Ubuntu-24.04` / `Debian` / `FedoraLinux-42` / `archlinux`）；
   - **环境档位**：`core`（~350MB）、`standard`（~1.2GB，默认推荐）或 `universal`（~3.5GB）；
   - **网络镜像与上游代理**：是否启用 `--mirror cn`（清华/国内源）以及可选 `--proxy http://<host>:<port>`（提示：默认 `NAT` 模式下宿主机代理需开 `Allow LAN` 并填宿主机 NAT 网关 IP，不要求改 `mirrored`）。

### 步骤 2/4：强制 `-DryRun` 预览与固定格式确认卡片（解锁门禁）

在**任何真实安装、staging 或 `wsl --install` 之前**，必须独立提交一次 `-DryRun` 预览请求，让人类先审阅真实将执行的脚本计划：

```powershell
.\packages\bootstrap\install-dsh-plugin.ps1 -NonInteractive -Distro <distro> -Profile <core|standard|universal> -Mirror <global|cn> -Provision -DryRun
```

> 只有在 `-DryRun` 通过单次人工审批执行后，宿主 `pwsh-hook` 才会解锁步骤 3。随后必须在对话中输出如下**固定格式《安装脚本与变更预览卡片》**，并等待用户明确回复同意：

```markdown
### 【安装脚本与变更预览卡片】
- **目标 WSL 2 发行版**：<Distro>
- **环境档位 / 镜像源 / 代理**：<core|standard|universal> / <global|cn> / <无或代理URL>
- **WSL 网络模式建议**：保持默认 `NAT`（本插件通过 UDS 代理通信，不依赖 `mirrored`）
- **原始配置只读备份**：`%USERPROFILE%\.wslconfig` 与 `/etc/wsl.conf` -> `<backupDir>`（`0400`/只读，绝不自动篡改原配置）
- **原生 ext4 部署路径**：`$HOME/.local/share/dsh-wsl-sandbox/runner/`（零 `/mnt` 锁）
- **脚本 SHA-256 校验与 `-DryRun` 摘要**：<摘录 Dry-Run 输出的脚本 SHA-256 与待运行步骤>
- **下一步将申请单次审批的命令**：`.\packages\bootstrap\install-dsh-plugin.ps1 -NonInteractive -Distro <Distro> -Profile <...> -Mirror <...> -Provision`
请确认上述参数与预览结果无误后回复“确认安装”。
```

### 步骤 3/4：分步单次人工审批安装

得到用户明确确认后，申请一次受控真实安装（每次均强制人工单次 `allow-once` 审批，绝不记忆前缀）：

```powershell
.\packages\bootstrap\install-dsh-plugin.ps1 -NonInteractive -Distro <distro> -Profile <core|standard|universal> -Mirror <global|cn> -Provision
```

如仅需在 WSL 内分步重跑单一工具链步骤，可使用单条命令配 `--step`（支持 `base|cli|node|python|go|rust|go-rust|extra`）：
```powershell
.\packages\bootstrap\install-dsh-plugin.ps1 -NonInteractive -Distro <distro> -Profile <core|standard|universal> -Mirror <global|cn> -Provision -Step <step>
```

### 步骤 4/4：强门禁闭环验收与自动关闸

执行闭环自检核验全项指标（`os.isWsl2`、`user.nonRoot`、`sandbox.unprivilegedUserns`、`seccompIoUringBlocked`、`seccompAfVsockBlocked`、`escapeMaskSelfTest`、`configMaskSelfTest`、`configDirPermsOk`）：
```powershell
wsl.exe -d <distro> --cd ~ -- node ~/.local/share/dsh-wsl-sandbox/runner/dist/packages/bootstrap/src/doctor.js --strict-wsl2 --profile <core|standard|universal> --json
```
验证全部通过后即可正常切换使用 `wsl_bash` 等 `wsl_*` 沙箱工具；首次沙箱绑定就绪后，「受控 AI 初始化引导通道」会自动关闭并恢复常态 `L0` 安装脚本锁定。
