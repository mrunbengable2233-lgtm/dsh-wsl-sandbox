# DSH WSL 2 沙箱环境受控建置引导提示词（四步预览门禁 · 零 Docker / 零内核编译）

> **推荐使用方式**：在 DSH **「设置 -> WSL 2 沙箱」**（或 `/wsl-sandbox/ui`）点击 **「预览安装脚本与 SHA-256」** 并点击 **「开启受控引导通道并复制会话指令」** 后，将自动复制好的会话指令（或本文档标准指令）发送给 DSH Agent。常态下 `L0` 单调守卫默认拦截 AI 私自调用安装脚本，只有人类手动开启 20 分钟限时引导通道并完成 `-DryRun` 预览确认卡片后，才会放行单次人工审批安装。

---

## 注入给 Agent 的标准执行约束（不可逾越）

你现在在用户手动开启的 **「受控 AI 初始化引导通道」** 中协助配置 `dsh-wsl-sandbox` 所需的 WSL 2 沙箱环境，必须严格遵守以下规则：

1. **严禁跳步与命令拼接**：严格按 **步骤 1（只读探测） -> 步骤 2（`-DryRun` 预览 + 固定格式确认卡片） -> 步骤 3（人工单次审批安装） -> 步骤 4（`dsh-wsl-doctor` 闭环验收）** 执行。宿主门禁会在未完成 `-DryRun` 预览前机械拦截一切真实安装与部署命令；所有命令不得包含 `;`、`|`、`&&`、`||`、`$()` 或输出重定向拼接。
2. **保证主流发行版开箱即用，零 Docker / 零源码编译**：全面支持 Ubuntu (26.04/24.04/22.04)、Debian、Kali、Fedora、Arch (`archlinux`)、openSUSE、Alpine 及 WSL Manager 迁移实例；如遇 NixOS 或 WSL `< 2.4`，须清晰告知官方声明式包/`wsl --update` 提示，不下载不兼容的 glibc 二进制或私自改系统配置。
3. **WSL 网络模式保持默认 `NAT` 即可**：本插件基于宿主机 `wsl.exe` 管道与 WSL 内 `AF_UNIX` UDS 代理运行，**完全不强制要求 `mirrored` 网络模式**；日常开发及手机/USB 联调测试优先推荐保持默认 `NAT`。
4. **严禁私改共享配置、严禁使用 `--shutdown`、严禁卸载脚本**：`/etc/wsl.conf` 与 `%USERPROFILE%\.wslconfig` 由官方 WSL Settings / WSL Manager 共用，只作 `0400`/只读备份；如确需重启目标发行版仅使用 `wsl.exe --terminate <目标发行版>`；绝对禁止 `wsl --shutdown`、`--unregister` 或非 `-DryRun` 卸载命令。

---

### 强制四步执行清单

#### 步骤 1/4：只读探测并确认 3 项选型
1. 独立执行 `wsl.exe -l -v`（如需识别 WSL Manager 迁移磁盘路径，再独立查询只读 `HKCU:\Software\Microsoft\Windows\CurrentVersion\Lxss`），过滤掉 `docker-desktop` 等容器内部实例。
2. 对用户指定的目标发行版执行单条只读探针（必须带 `--cd ~`）：
   ```powershell
   wsl.exe -d <distro> --cd ~ -- sh -c 'id; head -n 3 /etc/os-release 2>/dev/null; uname -r; uname -m; command -v bwrap prlimit socat node python3 git rg fdfind fd jq uv go cargo mise || true'
   ```
3. 与用户确认：**目标 WSL 2 发行版**、**工具链档位（`core` ~350MB / `standard` ~1.2GB / `universal` ~3.5GB）**、以及**是否开启 `--mirror cn` / `--proxy`**。

#### 步骤 2/4：强制 `-DryRun` 预览与固定格式确认卡片
先独立运行一次 `-DryRun` 预览命令（不写入配置、不改动系统）：
```powershell
.\packages\bootstrap\install-dsh-plugin.ps1 -NonInteractive -Distro <目标发行版> -Profile <core|standard|universal> -Mirror <global|cn> -Provision -DryRun
```
执行完成后，按固定格式向用户展示确认卡片并**等待用户回复同意**：
```markdown
### 【安装脚本与变更预览卡片】
- **目标 WSL 2 发行版**：<Distro>
- **环境档位 / 镜像源 / 代理**：<core|standard|universal> / <global|cn> / <无或代理URL>
- **WSL 网络模式建议**：保持默认 `NAT`（无需改 `mirrored`）
- **原始 WSL 配置只读备份**：`%USERPROFILE%\.wslconfig` 与 `/etc/wsl.conf` -> `<backupDir>`
- **原生 ext4 部署路径**：`$HOME/.local/share/dsh-wsl-sandbox/runner/`
- **脚本 SHA-256 与 `-DryRun` 摘要**：<附上刚才 -DryRun 输出的 SHA-256 与计划命令>
- **将申请单次审批的命令**：`.\packages\bootstrap\install-dsh-plugin.ps1 -NonInteractive -Distro <Distro> -Profile <...> -Mirror <...> -Provision`
请确认后回复“确认安装”。
```

#### 步骤 3/4：分步单次人工审批安装
仅在用户明确回复同意后，申请执行真实安装（每次均走人类单次 `allow-once` 审批；若需分步可加 `-Step base|cli|node|python|go|rust|extra`）：
```powershell
.\packages\bootstrap\install-dsh-plugin.ps1 -NonInteractive -Distro <目标发行版> -Profile <core|standard|universal> -Mirror <global|cn> -Provision
```

#### 步骤 4/4：闭环实机验收
```powershell
wsl.exe -d <目标发行版> --cd ~ -- node ~/.local/share/dsh-wsl-sandbox/runner/dist/packages/bootstrap/src/doctor.js --strict-wsl2 --profile <所选档位> --json
```
核验 `os.isWsl2`、`user.nonRoot`、`sandbox.unprivilegedUserns`、`seccompIoUringBlocked`、`seccompAfVsockBlocked`、`escapeMaskSelfTest`、`configMaskSelfTest` 与 `configDirPermsOk` 全部通过；随后首次 `wsl_bash` 绑定成功后引导通道自动关闭。
