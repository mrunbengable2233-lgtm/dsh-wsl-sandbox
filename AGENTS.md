# AGENTS.md — `dsh-wsl-sandbox` 项目开发与协作规范

> **主页导航**：[**简体中文**](./README.md) | [**English**](./README.en.md)

## Trellis 规范记忆与便携技能包

本项目采用 **Trellis** 规范树与 **`dsh-wsl-env-setup`** 技能包来沉淀架构决策、可执行契约与跨会话安全不变量：

- [`.trellis/workflow.md`](./.trellis/workflow.md) — 开发阶段、硬性门禁与验收流程。
- `.trellis/spec/` — 按包与分层组织的可执行代码规格（改动核心代码前务必先阅读）：
  - [`.trellis/spec/guides/`](./.trellis/spec/guides/index.md) — 安全不变量与 `dsh-purge` 插件共存准则。
  - [`.trellis/spec/core/`](./.trellis/spec/core/index.md) — 核心安全内核：`seccomp-bpf`、`bwrap`、`BashAstGuard`、`PwshGuard`、`pwsh-system-parser`、`ApprovalController`、`UdsProxy`。
  - [`.trellis/spec/runner/`](./.trellis/spec/runner/index.md) — WSL 原生 `ext4` 常驻 NDJSON Runner 与 FS / 进程 / PTY 协议。
  - [`.trellis/spec/plugin/`](./.trellis/spec/plugin/index.md) — DSH Cordis 插件（`wsl_*` 工具、系统提示词路由、宿主 `pwsh` 守卫、审批桥接与控制台界面）。
  - [`.trellis/spec/bootstrap/`](./.trellis/spec/bootstrap/index.md) — 零 Docker / 零内核编译的 WSL 2 环境置备脚本与 `dsh-wsl-doctor` 自检。
- [`.trellis/tasks/archive/11-23-dsh-wsl-sandbox/prd.md`](./.trellis/tasks/archive/11-23-dsh-wsl-sandbox/prd.md) — 已归档任务需求与验收基准。
- [`.trellis/workspace/antigravity/journal.md`](./.trellis/workspace/antigravity/journal.md) — 研发审计工作日志。
- [`.agents/skills/dsh-wsl-env-setup/SKILL.md`](./.agents/skills/dsh-wsl-env-setup/SKILL.md) — 便携式 WSL 2 沙箱环境引导建置技能包。

## 不可妥协的工程红线

1. **先规格后代码（Spec Before Code）**：跨层契约、`seccomp-bpf` 规则、`bwrap` 挂载顺序、审批状态机与 DSH 插件共存边界必须先在 `.trellis/spec/` 明确并保持一致。
2. **禁止手搓不严谨的简化正则替代官方解析器**：Windows PowerShell/CMD 审查必须结合微软官方 `[System.Management.Automation.Language.Parser]` AST，WSL 侧保持 8 层剥壳 `BashAstGuard`。
3. **零静默降级、零宿主插件冲突**：严禁从 WSL 2 静默回退到 Windows `pwsh`，严禁在沙箱失效时无隔离裸跑，严禁覆盖 DSH 原生内置服务或破坏宿主已装插件（如 `dsh-purge`）。
4. **笔记本零 Docker / 零内核编译**：环境建置统一使用官方或用户已有 WSL 2 发行版（含 WSL Manager 迁移磁盘实例）+ 预编译二进制安装包，并由 `dsh-wsl-doctor` 自检验证。
5. **诚实验证与 WSL 实例隔离红线**：明确区分宿主机静态/单元门禁测试（默认启用 `DSH_WSL_NO_HOST_SPAWN=1`）与用户明确授权并指定目标发行版后的真机 WSL 2 实测，严禁擅自探测或触碰其他 WSL 发行版。
