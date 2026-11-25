# Host Plugin Coexistence Thinking Guide (`dsh-purge` & Ecosystem)

Before editing `packages/dsh-plugin` or `cordis.patch.yml`, verify every coexistence rule below:

## 1. Zero Root Service Replacement (Q12=B Structural Guarantee)
- **Never** disable or overwrite DSH's stock `fs-local`, `subprocess-local`, `sandbox-local`, `pwsh-local`, or `system-prompt` rows in `cordis.patch.yml`.
- Keep all Windows native tools intact (essential for `usbipd-win`, ESP32 COM ports, and mixed host+WSL workflows).
- Register our capabilities cleanly as additive `wsl_*` tools on `ctx.tools` and namespaced services (`dsh-wsl-sandbox-*`). This makes Cordis duplicate-service registration crashes (like `Big-Dao` Issue `#39`) structurally impossible.

## 2. Zero Preset Isolation
- **Never** clone an isolated `preset-wsl` that strips out host plugins.
- All host plugins (`dsh-purge` prompts/skills/autoRetry, compaction plugins, MCP servers, themes) execute inside the exact same host DSH process and preset.

## 3. Non-Invasive Prompt Guidance (Q14=A)
- Register WSL-first routing instructions ONLY via `ctx.systemPrompt` incremental section API (never overwrite `id: system-prompt` config row, which `dsh-purge` customizes).
- Give our incremental section an explicit non-colliding priority/order and a toggleable config flag (`injectSystemPromptSection: true`).

## 4. Approval & Hook Etiquette (Q4=A + Q15=A)
- In `approval/request` waterfall: claim ONLY requests tagged with our `dsh-wsl-sandbox` namespace/metadata; for every other request (e.g. `dsh-purge` tools, MCP tools), immediately `return next()`.
- In `tools/pre-execute`: inspect ONLY Windows shell tools (`pwsh`, `powershell`, `cmd`, `bash` when host-native) through `PwshGuard`; pass all other tools through untouched.
- In `balanced` mode: honor `ctx.approval.request()` for L3 actions, but detect synthetic/bypassed instant-approvals (e.g. when `dsh-purge` `hooksDenyBypass: true` skips host approval) for L3 high-risk / physical-device / out-of-workspace / `wsl.exe` bypass commands and route them to our independent fallback approval gate so safety never silently degrades.

## 5. Host File & UI Hygiene
- **Never** touch `resources/app.asar`, `@deepseek-ai/*` files, profile `pnpm-workspace.yaml`, or other plugins' `cordis.patch.yml`.
- Zero native C++ / `node-gyp` dependencies in `package.json` so pnpm 11/12 never trips `allowBuilds` conflicts.
- Web API strictly under `/wsl-sandbox/api/*`; CSS classes strictly `.dsh-wsl-sbx-*`; overlay `z-index` strictly `<= 850` (below `dsh-purge` 900/950 and DSH modal dialogs 1000).
