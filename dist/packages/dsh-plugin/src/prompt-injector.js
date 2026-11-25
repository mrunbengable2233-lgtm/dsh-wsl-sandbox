import fs from 'node:fs';
import path from 'node:path';
                                                          
                                                          

export const SYSTEM_PROMPT_SECTION_ID = 'dsh-wsl-sandbox-routing';
export const SYSTEM_PROMPT_SECTION_ORDER = 4200;

export const AGENTS_MD_START_MARKER = '<!-- dsh-wsl-sandbox:start -->';
export const AGENTS_MD_END_MARKER = '<!-- dsh-wsl-sandbox:end -->';

export function buildWslRoutingPromptSection(config                  )         {
  const sharesSummary =
    config.advanced.shares.length > 0
      ? config.advanced.shares.map((s) => `/shares/${s.alias} (${s.mode})`).join(', ')
      : 'none (Windows /mnt drives are hidden by default; copy files via Windows Explorer Linux sidebar or authorize a per-use share under Advanced)';

  const devicesSummary =
    config.advanced.deviceNodes.length > 0
      ? config.advanced.deviceNodes.map((d) => d.path).join(', ')
      : 'none (physical hardware nodes disabled by default)';

  return [
    '## WSL 2 Sandbox Execution Policy (dsh-wsl-sandbox)',
    `- Active WSL 2 sandbox: distro \`${config.distro}\`, workspace \`${config.workspaceRoot}\`, mode \`${config.sandboxMode}\`, network \`${config.networkMode}\`.`,
    '- **WSL-first routing**: Prefer `wsl_bash`, `wsl_read`, `wsl_write`, `wsl_edit`, `wsl_glob`, `wsl_grep`, and `wsl_terminal` for all coding, git, build, test, Python/Node/Go/Rust, Linux CLI, ESP-IDF/firmware compilation, and Kali/Linux tooling tasks.',
    '- **Host Windows tools (`pwsh` / `powershell` / `cmd`)**: Reserve strictly for Windows-only host hardware/OS queries (e.g., `usbipd list`, `usbipd attach`, Windows COM port queries). NEVER invoke `wsl.exe` or `bash.exe` from host `pwsh`, NEVER wrap or transpile `cmd` / `cmd /c` (`mkdir ... && move ...`, `xcopy`, `robocopy`, `mklink`) inside `pwsh`, and NEVER touch `\\\\wsl.localhost\\` or `\\\\wsl$\\` UNC paths from Windows.',
    `- Authorized single-directory shares: ${sharesSummary}.`,
    `- Authorized physical device nodes: ${devicesSummary}. Note: any physical device operation (USBIP bind/attach/detach, serial/JTAG flashing) ALWAYS requires explicit single-shot human approval.`,
    '- Never attempt to read `.env*` secret files unless the user explicitly unmasked the project, and never modify `.git/hooks`, `.git/config`, or `.wslconfig`.',
  ].join('\n');
}

export function buildAgentsMdWslBlock(config                                                              )         {
  const distro = config?.distro ?? 'Ubuntu-24.04';
  const workspaceRoot = config?.workspaceRoot ?? '/home/dev/workspace';
  return [
    AGENTS_MD_START_MARKER,
    '## WSL 2 Sandbox Tool Routing (Managed by dsh-wsl-sandbox)',
    '',
    `- Default Linux sandbox distro: \`${distro}\` (workspace: \`${workspaceRoot}\`).`,
    '- **Always prefer `wsl_*` tools** (`wsl_bash`, `wsl_read`, `wsl_write`, `wsl_edit`, `wsl_glob`, `wsl_grep`, `wsl_terminal`) for repository work, directory creation, file moves, builds, tests, git operations, ESP32/firmware compilation, and Linux/Kali workflows.',
    '- **Use Windows host tools (`pwsh`) only for Windows-side hardware/OS actions** such as `usbipd list` / `usbipd attach --wsl` (USBIP passthrough for ESP32/USB adapters), COM port checks, or Windows-only driver utilities.',
    '- Do **not** invoke `wsl.exe`/`bash.exe` through host `pwsh`, do **not** transpile or nest `cmd` / `cmd /c` (`mkdir` + `move` / `xcopy` / `robocopy` / `mklink`) inside `pwsh`, and never write to `\\\\wsl.localhost\\` or `\\\\wsl$\\` UNC shares.',
    '- Physical device actions (USBIP attach/bind, serial flashing via `esptool`/`openocd`/`minicom`) always require single-shot human approval.',
    '- To move files between Windows and WSL without mounting `/mnt`, drag/copy via the **Windows Explorer -> Linux** sidebar, or grant a temporary single-directory `/shares/<alias>` under Advanced settings.',
    AGENTS_MD_END_MARKER,
  ].join('\n');
}

/**
 * Registers a non-invasive incremental prompt section (`order: 4200`) on `ctx.systemPrompt`.
 * NEVER modifies or replaces the stock `id: system-prompt` row (100% compatible with `dsh-purge`).
 */
export function registerWslPromptSection(
  ctx                  ,
  getConfig                        ,
)                           {
  if (!ctx.systemPrompt) return undefined;
  const render = ()         => {
    const cfg = getConfig();
    if (!cfg.enabled || !cfg.enablePromptInjection) return '';
    return buildWslRoutingPromptSection(cfg);
  };

  // Real `@deepseek-ai/dsh-system-prompt` (>=0.2.1 / 0.2.2) API
  if (typeof ctx.systemPrompt.section === 'function') {
    const dispose = ctx.systemPrompt.section({
      name: SYSTEM_PROMPT_SECTION_ID,
      order: SYSTEM_PROMPT_SECTION_ORDER,
      interpolate: false,
      text: () => render(),
    });
    return typeof dispose === 'function' ? dispose : undefined;
  }

  // Fallback for standalone test harnesses
  if (typeof ctx.systemPrompt.register === 'function') {
    const dispose = ctx.systemPrompt.register({
      id: SYSTEM_PROMPT_SECTION_ID,
      order: SYSTEM_PROMPT_SECTION_ORDER,
      content: () => render(),
    });
    return typeof dispose === 'function' ? () => void dispose() : undefined;
  }

  return undefined;
}

/**
 * Cleanly inserts or updates the `dsh-wsl-sandbox` WSL-first routing block inside `<projectRoot>/AGENTS.md`
 * without altering any user-authored sections outside the markers.
 */
export function upsertAgentsMdWslSection(
  projectRoot        ,
  config                                                              ,
)                                                                   {
  const filePath = path.join(projectRoot, 'AGENTS.md');
  const block = buildAgentsMdWslBlock(config);

  if (!fs.existsSync(filePath)) {
    fs.mkdirSync(projectRoot, { recursive: true });
    fs.writeFileSync(filePath, `# Project Agent Instructions\n\n${block}\n`, 'utf8');
    return { filePath, action: 'created' };
  }

  const existing = fs.readFileSync(filePath, 'utf8');
  const startIdx = existing.indexOf(AGENTS_MD_START_MARKER);
  const endIdx = existing.indexOf(AGENTS_MD_END_MARKER);

  if (startIdx !== -1 && endIdx !== -1 && endIdx > startIdx) {
    const before = existing.slice(0, startIdx);
    const after = existing.slice(endIdx + AGENTS_MD_END_MARKER.length);
    fs.writeFileSync(filePath, `${before}${block}${after}`, 'utf8');
    return { filePath, action: 'updated' };
  }

  const sep = existing.endsWith('\n') ? '\n' : '\n\n';
  fs.writeFileSync(filePath, `${existing}${sep}${block}\n`, 'utf8');
  return { filePath, action: 'appended' };
}
