import fs from 'node:fs';
import path from 'node:path';
import type { WslSandboxConfig } from './config-store.ts';
import type { DshCordisContext } from './cordis-types.ts';

export const SYSTEM_PROMPT_SECTION_ID = 'dsh-wsl-sandbox-routing';
export const SYSTEM_PROMPT_SECTION_ORDER = 4200;

export const AGENTS_MD_START_MARKER = '<!-- dsh-wsl-sandbox:start -->';
export const AGENTS_MD_END_MARKER = '<!-- dsh-wsl-sandbox:end -->';

export function buildWslRoutingPromptSection(config: WslSandboxConfig): string {
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
    `- Active WSL 2 sandbox: distro \`${config.distro}\`, workspace \`${config.workspaceRoot}\`, profile \`${config.environmentProfile}\`, mode \`${config.sandboxMode}\`, network \`${config.networkMode}\`.`,
    '- **WSL-first routing**: Prefer `wsl_bash`, `wsl_read`, `wsl_write`, `wsl_edit`, `wsl_glob`, `wsl_grep`, and `wsl_terminal` for all coding, git, build, test, Python/Node/Go/Rust, C/C++, firmware compilation, and Linux CLI tooling tasks.',
    '- **Host Windows tools (`pwsh` / `powershell`)**: Reserve strictly for Windows-side hardware, OS, or Windows-only driver workflows — such as `usbipd list` / `usbipd attach`, phone Bootloader/Fastboot/ADB/EDL OEM drivers, Windows-driverless USB NICs/adapters that lack stock WSL 2 Linux kernel modules (`Get-PnpDevice`, `Get-NetAdapter`, `pnputil`), or COM port queries. NEVER invoke `wsl.exe` or `bash.exe` from host `pwsh`, NEVER wrap or transpile `cmd` / `cmd /c` (`mkdir ... && move ...`, `xcopy`, `robocopy`, `mklink`) inside `pwsh`, and NEVER touch `\\\\wsl.localhost\\` or `\\\\wsl$\\` UNC paths from Windows.',
    `- Authorized single-directory shares: ${sharesSummary}.`,
    `- Authorized physical device nodes: ${devicesSummary}. Note: stock WSL 2 Linux kernels ship minimal USB drivers — user-space libusb nodes (\`/dev/bus/usb/NNN/NNN\`) work over USBIP, whereas devices needing Windows OEM/WinUSB drivers (e.g., phone Bootloader unlock tools or USB NICs lacking Linux/WSL 2 \`.ko\` modules) should stay on Windows host under single-shot human approval. Every physical hardware or driver mutation (\`usbipd bind|attach\`, \`fastboot\`, \`adb reboot/flash\`, \`pnputil\`, \`NetAdapter\`, flashing tools) ALWAYS requires explicit single-shot human approval.`,
    '- Never attempt to read `.env*` secret files unless the user explicitly unmasked the project, and never access or modify `~/.dsh`, `~/.config/dsh-wsl-sandbox`, `.git/hooks`, `.git/config`, `.wslconfig`, or `/etc/wsl.conf`.',
  ].join('\n');
}

export function buildAgentsMdWslBlock(config?: Partial<Pick<WslSandboxConfig, 'distro' | 'workspaceRoot'>>): string {
  const distro = config?.distro ?? 'Ubuntu-26.04';
  const workspaceRoot = config?.workspaceRoot ?? '~/workspace';
  return [
    AGENTS_MD_START_MARKER,
    '## WSL 2 Sandbox Tool Routing (Managed by dsh-wsl-sandbox)',
    '',
    `- Default Linux sandbox distro: \`${distro}\` (workspace: \`${workspaceRoot}\`).`,
    '- **Always prefer `wsl_*` tools** (`wsl_bash`, `wsl_read`, `wsl_write`, `wsl_edit`, `wsl_glob`, `wsl_grep`, `wsl_terminal`) for repository work, directory creation, file moves, builds, tests, git operations, cross-compilation, and Linux workflows.',
    '- **Use Windows host tools (`pwsh`) only for Windows-side hardware/driver/OS actions**: e.g., `usbipd list` / `usbipd attach --wsl` (for generic USB peripherals, phones in ADB/Fastboot/EDL mode, HID/CDC/serial devices), Windows-only OEM/WinUSB driver utilities (`pnputil`, `fastboot`, `adb`), or Windows-driverless USB NICs/adapters that lack stock WSL 2 Linux kernel drivers.',
    '- Do **not** invoke `wsl.exe`/`bash.exe` through host `pwsh`, do **not** transpile or nest `cmd` / `cmd /c` (`mkdir` + `move` / `xcopy` / `robocopy` / `mklink`) inside `pwsh`, and never write to `\\\\wsl.localhost\\` or `\\\\wsl$\\` UNC shares.',
    '- Physical device and driver mutations (`usbipd bind|attach`, `fastboot`, `adb reboot/sideload`, `pnputil`, `Set-NetAdapter`, serial/JTAG flashing) always require single-shot human approval.',
    '- Note on WSL Manager / moved VHDX instances: even if an imported distro does not appear in Windows Explorer\'s left "Linux" sidebar, `wsl_*` tools work normally over `wsl.exe` + native ext4. For ad-hoc host file exchange without mounting `/mnt`, authorize a single-directory `/shares/<alias>` under Advanced settings.',
    AGENTS_MD_END_MARKER,
  ].join('\n');
}

/**
 * Registers a non-invasive incremental prompt section (`order: 4200`) on `ctx.systemPrompt`.
 * NEVER modifies or replaces the stock `id: system-prompt` row (100% compatible with `dsh-purge`).
 */
export function registerWslPromptSection(
  ctx: DshCordisContext,
  getConfig: () => WslSandboxConfig,
): (() => void) | undefined {
  if (!ctx.systemPrompt) return undefined;
  const render = (): string => {
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

const AGENTS_MD_BLOCK_RE =
  /[ \t]*<!--\s*dsh-wsl-sandbox:(?:start|begin)\s*-->[\s\S]*?<!--\s*dsh-wsl-sandbox:end\s*-->[ \t]*\r?\n?/g;

/**
 * Cleanly inserts or updates the `dsh-wsl-sandbox` WSL-first routing block inside `<projectRoot>/AGENTS.md`
 * without altering any user-authored sections outside the markers.
 */
export function upsertAgentsMdWslSection(
  projectRoot: string,
  config?: Partial<Pick<WslSandboxConfig, 'distro' | 'workspaceRoot'>>,
): { filePath: string; action: 'created' | 'updated' | 'appended' } {
  const filePath = path.join(projectRoot, 'AGENTS.md');
  const block = buildAgentsMdWslBlock(config);

  if (!fs.existsSync(filePath)) {
    fs.mkdirSync(projectRoot, { recursive: true });
    fs.writeFileSync(filePath, `# Project Agent Instructions\n\n${block}\n`, 'utf8');
    return { filePath, action: 'created' };
  }

  const existing = fs.readFileSync(filePath, 'utf8');
  if (AGENTS_MD_BLOCK_RE.test(existing)) {
    AGENTS_MD_BLOCK_RE.lastIndex = 0;
    const updated = existing.replace(AGENTS_MD_BLOCK_RE, `${block}\n`);
    fs.writeFileSync(filePath, updated, 'utf8');
    return { filePath, action: 'updated' };
  }

  const sep = existing.endsWith('\n') ? '\n' : '\n\n';
  fs.writeFileSync(filePath, `${existing}${sep}${block}\n`, 'utf8');
  return { filePath, action: 'appended' };
}

/**
 * Cleanly removes the `dsh-wsl-sandbox` block from `<projectRoot>/AGENTS.md` (or a direct `AGENTS.md` file path).
 * If the remaining file only contains the default `# Project Agent Instructions` scaffold (or whitespace),
 * deletes the empty `AGENTS.md` file completely so zero residual file is left behind on uninstall.
 */
export function removeAgentsMdWslSection(
  projectRootOrFile: string,
): {
  filePath: string;
  action: 'not-found' | 'unchanged' | 'removed-section' | 'deleted-empty-file';
} {
  const filePath =
    path.basename(projectRootOrFile).toLowerCase() === 'agents.md'
      ? projectRootOrFile
      : path.join(projectRootOrFile, 'AGENTS.md');

  if (!fs.existsSync(filePath)) {
    return { filePath, action: 'not-found' };
  }

  const existing = fs.readFileSync(filePath, 'utf8');
  AGENTS_MD_BLOCK_RE.lastIndex = 0;
  if (!AGENTS_MD_BLOCK_RE.test(existing)) {
    return { filePath, action: 'unchanged' };
  }

  AGENTS_MD_BLOCK_RE.lastIndex = 0;
  const stripped = existing
    .replace(AGENTS_MD_BLOCK_RE, '')
    .replace(/\n{3,}/g, '\n\n')
    .trim();

  if (stripped === '' || stripped === '# Project Agent Instructions') {
    fs.rmSync(filePath, { force: true });
    return { filePath, action: 'deleted-empty-file' };
  }

  fs.writeFileSync(filePath, `${stripped}\n`, 'utf8');
  return { filePath, action: 'removed-section' };
}

