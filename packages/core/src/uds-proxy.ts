import dns from 'node:dns/promises';
import fs from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import path from 'node:path';
import { URL } from 'node:url';

/**
 * Outbound Allowlist HTTP/CONNECT Proxy listening on a Unix Domain Socket (Q5=B + Q16=A).
 *
 * Security properties:
 * 1. Sandbox keeps `--unshare-net` (zero direct internet or host-LAN access).
 * 2. Only allowed dev domains (or dynamically session-approved domains) pass through.
 * 3. Private / loopback / link-local / metadata IPv4 & IPv6 addresses are ALWAYS blocked
 *    to prevent SSRF, unless matched by human-configured Advanced `localLabCidrs` / `localLabPorts`.
 * 4. Supports chaining to an upstream local proxy (`http://` or `socks5://`, e.g. Clash/Mihomo/v2rayN).
 */

export const DEFAULT_DEV_DOMAIN_ALLOWLIST: readonly string[] = [
  'github.com',
  'api.github.com',
  'raw.githubusercontent.com',
  'objects.githubusercontent.com',
  'codeload.github.com',
  'release-assets.githubusercontent.com',
  'registry.npmjs.org',
  'registry.npmmirror.com',
  'cdn.npmmirror.com',
  'pypi.org',
  'files.pythonhosted.org',
  'pypi.tuna.tsinghua.edu.cn',
  'mirrors.aliyun.com',
  'mirrors.tuna.tsinghua.edu.cn',
  'crates.io',
  'static.crates.io',
  'index.crates.io',
  'rsproxy.cn',
  'proxy.golang.org',
  'sum.golang.org',
  'goproxy.cn',
  'archive.ubuntu.com',
  'security.ubuntu.com',
  'deb.nodesource.com',
  'mise.jdx.dev',
  'astral.sh',
  'sh.rustup.rs',
  'static.rust-lang.org',
];

export interface ParsedCidr {
  readonly network: number;
  readonly mask: number;
}

export interface UdsProxyConfig {
  readonly socketPath: string;
  readonly allowedDomains?: readonly string[];
  readonly customAllowedDomains?: readonly string[];
  readonly upstreamProxy?: string;
  readonly localLabCidrs?: readonly string[];
  readonly localLabPorts?: readonly number[];
  readonly onDenied?: (info: { host: string; port: number; reason: string }) => void;
  readonly onAllowed?: (info: { host: string; port: number; via: 'direct' | 'upstream-http' | 'upstream-socks5' }) => void;
  /** Optional dynamic approval callback when a non-SSRF host is outside allowlist. */
  readonly authorizeUnknownHost?: (host: string, port: number) => Promise<boolean>;
}

function ipv4ToInt(ip: string): number | null {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  let val = 0;
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p)) return null;
    const n = Number(p);
    if (n < 0 || n > 255) return null;
    val = (val << 8) | n;
  }
  return val >>> 0;
}

export function parseIpv4Cidr(cidr: string): ParsedCidr | null {
  const [ipStr, prefixStr] = cidr.trim().split('/');
  if (!ipStr) return null;
  const ip = ipv4ToInt(ipStr);
  if (ip === null) return null;
  const prefix = prefixStr === undefined ? 32 : Number(prefixStr);
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > 32) return null;
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return { network: (ip & mask) >>> 0, mask };
}

const PRIVATE_IPV4_CIDRS: readonly ParsedCidr[] = [
  '0.0.0.0/8',
  '10.0.0.0/8',
  '100.64.0.0/10',
  '127.0.0.0/8',
  '169.254.0.0/16',
  '172.16.0.0/12',
  '192.0.0.0/24',
  '192.168.0.0/16',
  '224.0.0.0/4',
  '240.0.0.0/4',
].map((c) => parseIpv4Cidr(c)!);

function ipMatchesCidrs(ip: string, cidrs: readonly ParsedCidr[]): boolean {
  const val = ipv4ToInt(ip);
  if (val === null) return false;
  return cidrs.some((c) => ((val & c.mask) >>> 0) === c.network);
}

export function isPrivateOrLoopbackIp(rawIp: string): boolean {
  const ip = rawIp.trim().toLowerCase().replace(/^\[|\]$/g, '');
  // IPv4-mapped IPv6 e.g. ::ffff:127.0.0.1
  if (ip.startsWith('::ffff:')) {
    const mapped = ip.slice(7);
    if (net.isIPv4(mapped)) return ipMatchesCidrs(mapped, PRIVATE_IPV4_CIDRS);
  }
  if (net.isIPv4(ip)) {
    return ipMatchesCidrs(ip, PRIVATE_IPV4_CIDRS);
  }
  if (net.isIPv6(ip)) {
    if (ip === '::' || ip === '::1') return true;
    if (ip.startsWith('fc') || ip.startsWith('fd')) return true; // fc00::/7 ULA
    if (ip.startsWith('fe8') || ip.startsWith('fe9') || ip.startsWith('fea') || ip.startsWith('feb')) return true; // fe80::/10
    if (ip.startsWith('ff')) return true; // multicast
    return false;
  }
  return false;
}

export function domainMatchesPattern(host: string, pattern: string): boolean {
  const h = host.trim().toLowerCase().replace(/^\[|\]$/g, '');
  const p = pattern.trim().toLowerCase();
  if (!p) return false;
  if (p.startsWith('*.')) {
    const suffix = p.slice(1); // ".example.com"
    return h.endsWith(suffix) && h.length > suffix.length;
  }
  return h === p;
}

export interface TargetPolicyVerdict {
  readonly allowed: boolean;
  readonly reason: string;
  readonly isLocalLab?: boolean;
  readonly isSsrfBlocked?: boolean;
}

export async function evaluateProxyTarget(
  rawHost: string,
  port: number,
  options: {
    readonly allowlist: readonly string[];
    readonly sessionAllowed: ReadonlySet<string>;
    readonly localLabCidrs: readonly ParsedCidr[];
    readonly localLabPorts: ReadonlySet<number>;
    readonly resolveHost?: (host: string) => Promise<string[]>;
    readonly hasUpstreamProxy?: boolean;
  },
): Promise<TargetPolicyVerdict> {
  const host = rawHost.trim().toLowerCase().replace(/^\[|\]$/g, '');
  if (!host || !Number.isInteger(port) || port < 1 || port > 65535) {
    return { allowed: false, reason: `Invalid target host or port: ${rawHost}:${port}` };
  }

  const isLocalhostName = host === 'localhost' || host.endsWith('.localhost') || host === 'host.docker.internal';
  const literalIpType = net.isIP(host);

  const checkLocalLab = (ipList: readonly string[]): boolean => {
    if (options.localLabPorts.size > 0 && !options.localLabPorts.has(port)) {
      // If ports are specified, check if port matches when hitting loopback
    }
    for (const ip of ipList) {
      const normalized = ip.toLowerCase();
      if (normalized === '127.0.0.1' || normalized === '::1') {
        if (options.localLabPorts.has(port)) return true;
      }
      if (net.isIPv4(normalized) && ipMatchesCidrs(normalized, options.localLabCidrs)) {
        if (options.localLabPorts.size === 0 || options.localLabPorts.has(port)) {
          return true;
        }
      }
    }
    return false;
  };

  // 1. Literal IP or localhost checks
  if (isLocalhostName) {
    if (checkLocalLab(['127.0.0.1', '::1'])) {
      return { allowed: true, reason: `Matched Advanced local lab loopback port ${port}`, isLocalLab: true };
    }
    return { allowed: false, reason: `SSRF blocked: localhost target ${host}:${port} is not in Advanced localLabPorts`, isSsrfBlocked: true };
  }

  if (literalIpType !== 0) {
    if (isPrivateOrLoopbackIp(host)) {
      if (checkLocalLab([host])) {
        return { allowed: true, reason: `Matched Advanced local lab CIDR/port (${host}:${port})`, isLocalLab: true };
      }
      return { allowed: false, reason: `SSRF blocked: private/loopback IP ${host}:${port} denied`, isSsrfBlocked: true };
    }
    // Public literal IP still requires allowlist
    const inList =
      options.sessionAllowed.has(host) ||
      options.allowlist.some((p) => domainMatchesPattern(host, p));
    return inList
      ? { allowed: true, reason: 'Allowed public IP' }
      : { allowed: false, reason: `Target IP ${host} is not in proxy allowlist` };
  }

  // 2. Domain allowlist check
  const domainAllowed =
    options.sessionAllowed.has(host) ||
    options.allowlist.some((pattern) => domainMatchesPattern(host, pattern));

  if (!domainAllowed) {
    return { allowed: false, reason: `Domain ${host} is not in proxy allowlist` };
  }

  // 3. DNS rebinding / SSRF protection (skip DNS only if caller explicitly mocks or delegates remote DNS to upstream proxy)
  if (!options.hasUpstreamProxy || options.resolveHost) {
    const resolver = options.resolveHost ?? (async (h: string) => {
      const results = await dns.lookup(h, { all: true });
      return results.map((r) => r.address);
    });
    try {
      const ips = await resolver(host);
      for (const ip of ips) {
        if (isPrivateOrLoopbackIp(ip)) {
          if (checkLocalLab([ip])) {
            return { allowed: true, reason: `Resolved ${host} -> ${ip} matched Advanced local lab`, isLocalLab: true };
          }
          return {
            allowed: false,
            reason: `SSRF blocked: domain ${host} resolved to private/loopback IP ${ip}`,
            isSsrfBlocked: true,
          };
        }
      }
    } catch {
      if (!options.hasUpstreamProxy) {
        return { allowed: false, reason: `DNS resolution failed for ${host}` };
      }
    }
  }

  return { allowed: true, reason: `Domain ${host} allowed` };
}

function connectViaHttpUpstream(
  upstreamUrl: URL,
  targetHost: string,
  targetPort: number,
): Promise<net.Socket> {
  return new Promise((resolve, reject) => {
    const proxyHost = upstreamUrl.hostname;
    const proxyPort = Number(upstreamUrl.port || (upstreamUrl.protocol === 'https:' ? 443 : 80));
    const sock = net.connect(proxyPort, proxyHost);
    let settled = false;
    let buf = '';

    const fail = (err: Error): void => {
      if (settled) return;
      settled = true;
      sock.destroy();
      reject(err);
    };

    sock.once('error', fail);
    sock.once('connect', () => {
      const headers = [`CONNECT ${targetHost}:${targetPort} HTTP/1.1`, `Host: ${targetHost}:${targetPort}`];
      if (upstreamUrl.username || upstreamUrl.password) {
        const token = Buffer.from(
          `${decodeURIComponent(upstreamUrl.username)}:${decodeURIComponent(upstreamUrl.password)}`,
        ).toString('base64');
        headers.push(`Proxy-Authorization: Basic ${token}`);
      }
      headers.push('', '');
      sock.write(headers.join('\r\n'));
    });

    const onData = (chunk: Buffer): void => {
      buf += chunk.toString('latin1');
      const endIdx = buf.indexOf('\r\n\r\n');
      if (endIdx === -1) {
        if (buf.length > 16384) fail(new Error('Upstream HTTP proxy response header too large'));
        return;
      }
      sock.off('data', onData);
      const statusLine = buf.slice(0, buf.indexOf('\r\n'));
      const match = statusLine.match(/^HTTP\/\d\.\d\s+(\d{3})/);
      if (!match || Number(match[1]) !== 200) {
        fail(new Error(`Upstream HTTP proxy rejected CONNECT: ${statusLine}`));
        return;
      }
      settled = true;
      const leftover = buf.slice(endIdx + 4);
      if (leftover.length > 0) {
        sock.unshift(Buffer.from(leftover, 'latin1'));
      }
      resolve(sock);
    };

    sock.on('data', onData);
  });
}

function connectViaSocks5Upstream(
  upstreamUrl: URL,
  targetHost: string,
  targetPort: number,
): Promise<net.Socket> {
  return new Promise((resolve, reject) => {
    const proxyHost = upstreamUrl.hostname;
    const proxyPort = Number(upstreamUrl.port || 1080);
    const sock = net.connect(proxyPort, proxyHost);
    let settled = false;
    let stage: 'greeting' | 'auth' | 'connect' = 'greeting';
    let acc = Buffer.alloc(0);

    const hasAuth = Boolean(upstreamUrl.username || upstreamUrl.password);

    const fail = (err: Error): void => {
      if (settled) return;
      settled = true;
      sock.destroy();
      reject(err);
    };

    const sendConnectRequest = (): void => {
      stage = 'connect';
      const hostBuf = Buffer.from(targetHost, 'utf8');
      if (hostBuf.length > 255) {
        fail(new Error('Target hostname too long for SOCKS5'));
        return;
      }
      const req = Buffer.alloc(7 + hostBuf.length);
      req[0] = 0x05; // VER
      req[1] = 0x01; // CMD CONNECT
      req[2] = 0x00; // RSV
      req[3] = 0x03; // ATYP DOMAINNAME
      req[4] = hostBuf.length;
      hostBuf.copy(req, 5);
      req.writeUInt16BE(targetPort, 5 + hostBuf.length);
      sock.write(req);
    };

    sock.once('error', fail);
    sock.once('connect', () => {
      if (hasAuth) {
        sock.write(Buffer.from([0x05, 0x02, 0x00, 0x02]));
      } else {
        sock.write(Buffer.from([0x05, 0x01, 0x00]));
      }
    });

    const onData = (chunk: Buffer): void => {
      acc = Buffer.concat([acc, chunk]);
      if (stage === 'greeting') {
        if (acc.length < 2) return;
        const ver = acc[0];
        const method = acc[1];
        acc = acc.subarray(2);
        if (ver !== 0x05 || method === 0xff) {
          fail(new Error('SOCKS5 upstream rejected auth methods'));
          return;
        }
        if (method === 0x02) {
          stage = 'auth';
          const u = Buffer.from(decodeURIComponent(upstreamUrl.username), 'utf8');
          const p = Buffer.from(decodeURIComponent(upstreamUrl.password), 'utf8');
          sock.write(Buffer.concat([Buffer.from([0x01, u.length]), u, Buffer.from([p.length]), p]));
        } else if (method === 0x00) {
          sendConnectRequest();
        } else {
          fail(new Error(`Unsupported SOCKS5 auth method: ${method}`));
        }
      }

      if (stage === 'auth') {
        if (acc.length < 2) return;
        const status = acc[1];
        acc = acc.subarray(2);
        if (status !== 0x00) {
          fail(new Error('SOCKS5 upstream authentication failed'));
          return;
        }
        sendConnectRequest();
      }

      if (stage === 'connect') {
        if (acc.length < 4) return;
        const ver = acc[0];
        const rep = acc[1];
        const atyp = acc[3];
        if (ver !== 0x05 || rep !== 0x00) {
          fail(new Error(`SOCKS5 CONNECT failed with code ${rep}`));
          return;
        }
        let headerLen = 4;
        if (atyp === 0x01) headerLen += 4 + 2;
        else if (atyp === 0x04) headerLen += 16 + 2;
        else if (atyp === 0x03) {
          if (acc.length < 5) return;
          headerLen += 1 + acc[4]! + 2;
        } else {
          fail(new Error(`Invalid SOCKS5 ATYP: ${atyp}`));
          return;
        }
        if (acc.length < headerLen) return;
        const leftover = acc.subarray(headerLen);
        sock.off('data', onData);
        settled = true;
        if (leftover.length > 0) sock.unshift(leftover);
        resolve(sock);
      }
    };

    sock.on('data', onData);
  });
}

export class UdsAllowlistProxy {
  private readonly socketPath: string;
  private allowlist: string[];
  private readonly sessionAllowed = new Set<string>();
  private localLabCidrs: ParsedCidr[];
  private localLabPorts: Set<number>;
  private upstreamUrl: URL | undefined;
  private readonly onDenied?: UdsProxyConfig['onDenied'];
  private readonly onAllowed?: UdsProxyConfig['onAllowed'];
  private readonly authorizeUnknownHost?: UdsProxyConfig['authorizeUnknownHost'];
  private server: http.Server | undefined;

  constructor(config: UdsProxyConfig) {
    this.socketPath = config.socketPath;
    this.allowlist = [
      ...(config.allowedDomains ?? DEFAULT_DEV_DOMAIN_ALLOWLIST),
      ...(config.customAllowedDomains ?? []),
    ];
    this.localLabCidrs = (config.localLabCidrs ?? [])
      .map(parseIpv4Cidr)
      .filter((c): c is ParsedCidr => c !== null);
    this.localLabPorts = new Set(config.localLabPorts ?? []);
    if (config.upstreamProxy && config.upstreamProxy.trim().length > 0) {
      this.upstreamUrl = new URL(config.upstreamProxy.trim());
    }
    this.onDenied = config.onDenied;
    this.onAllowed = config.onAllowed;
    this.authorizeUnknownHost = config.authorizeUnknownHost;
  }

  getSocketPath(): string {
    return this.socketPath;
  }

  addSessionAllowedDomain(host: string): void {
    this.sessionAllowed.add(host.trim().toLowerCase());
  }

  clearSessionAllowedDomains(): void {
    this.sessionAllowed.clear();
  }

  updatePolicy(patch: {
    customAllowedDomains?: readonly string[];
    upstreamProxy?: string;
    localLabCidrs?: readonly string[];
    localLabPorts?: readonly number[];
  }): void {
    if (patch.customAllowedDomains) {
      this.allowlist = [...DEFAULT_DEV_DOMAIN_ALLOWLIST, ...patch.customAllowedDomains];
    }
    if (patch.upstreamProxy !== undefined) {
      this.upstreamUrl = patch.upstreamProxy.trim() ? new URL(patch.upstreamProxy.trim()) : undefined;
    }
    if (patch.localLabCidrs) {
      this.localLabCidrs = patch.localLabCidrs
        .map(parseIpv4Cidr)
        .filter((c): c is ParsedCidr => c !== null);
    }
    if (patch.localLabPorts) {
      this.localLabPorts = new Set(patch.localLabPorts);
    }
  }

  private async checkAndAuthorize(host: string, port: number): Promise<TargetPolicyVerdict> {
    const verdict = await evaluateProxyTarget(host, port, {
      allowlist: this.allowlist,
      sessionAllowed: this.sessionAllowed,
      localLabCidrs: this.localLabCidrs,
      localLabPorts: this.localLabPorts,
      hasUpstreamProxy: Boolean(this.upstreamUrl),
    });

    if (verdict.allowed || verdict.isSsrfBlocked) {
      return verdict;
    }

    if (this.authorizeUnknownHost) {
      const approved = await this.authorizeUnknownHost(host, port);
      if (approved) {
        this.addSessionAllowedDomain(host);
        return { allowed: true, reason: `User approved domain ${host}` };
      }
    }
    return verdict;
  }

  private async openTargetSocket(
    host: string,
    port: number,
    isLocalLab: boolean,
  ): Promise<{ socket: net.Socket; via: 'direct' | 'upstream-http' | 'upstream-socks5' }> {
    // Local lab targets always connect directly (never sent to external upstream proxy)
    if (!isLocalLab && this.upstreamUrl) {
      if (this.upstreamUrl.protocol === 'socks5:' || this.upstreamUrl.protocol === 'socks5h:') {
        const socket = await connectViaSocks5Upstream(this.upstreamUrl, host, port);
        return { socket, via: 'upstream-socks5' };
      }
      const socket = await connectViaHttpUpstream(this.upstreamUrl, host, port);
      return { socket, via: 'upstream-http' };
    }
    const socket = await new Promise<net.Socket>((resolve, reject) => {
      const s = net.connect(port, host);
      s.once('error', reject);
      s.once('connect', () => {
        s.off('error', reject);
        resolve(s);
      });
    });
    return { socket, via: 'direct' };
  }

  async start(): Promise<void> {
    if (this.server) return;
    const dir = path.dirname(this.socketPath);
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    fs.rmSync(this.socketPath, { force: true });

    const server = http.createServer(async (req, res) => {
      try {
        const rawUrl = req.url ?? '';
        const targetUrl = new URL(rawUrl.startsWith('http') ? rawUrl : `http://${req.headers.host ?? ''}${rawUrl}`);
        const host = targetUrl.hostname;
        const port = Number(targetUrl.port || (targetUrl.protocol === 'https:' ? 443 : 80));

        const verdict = await this.checkAndAuthorize(host, port);
        if (!verdict.allowed) {
          this.onDenied?.({ host, port, reason: verdict.reason });
          res.writeHead(403, { 'content-type': 'text/plain; charset=utf-8' });
          res.end(`DSH WSL Sandbox Proxy Blocked: ${verdict.reason}\n`);
          return;
        }

        const useUpstreamHttp =
          !verdict.isLocalLab &&
          this.upstreamUrl &&
          (this.upstreamUrl.protocol === 'http:' || this.upstreamUrl.protocol === 'https:');

        if (useUpstreamHttp && this.upstreamUrl) {
          this.onAllowed?.({ host, port, via: 'upstream-http' });
          const upstreamHeaders: Record<string, string | string[] | undefined> = { ...req.headers };
          delete upstreamHeaders['proxy-connection'];
          if (this.upstreamUrl.username || this.upstreamUrl.password) {
            const token = Buffer.from(
              `${decodeURIComponent(this.upstreamUrl.username)}:${decodeURIComponent(this.upstreamUrl.password)}`,
            ).toString('base64');
            upstreamHeaders['proxy-authorization'] = `Basic ${token}`;
          }
          const proxyReq = http.request(
            {
              host: this.upstreamUrl.hostname,
              port: Number(this.upstreamUrl.port || 80),
              method: req.method,
              path: targetUrl.toString(),
              headers: upstreamHeaders,
            },
            (proxyRes) => {
              res.writeHead(proxyRes.statusCode ?? 502, proxyRes.headers);
              proxyRes.pipe(res);
            },
          );
          proxyReq.on('error', (err) => {
            if (!res.headersSent) res.writeHead(502);
            res.end(`Upstream proxy error: ${err.message}\n`);
          });
          req.pipe(proxyReq);
          return;
        }

        const { socket, via } = await this.openTargetSocket(host, port, Boolean(verdict.isLocalLab));
        this.onAllowed?.({ host, port, via });

        const reqHeaders: Record<string, string | string[] | undefined> = { ...req.headers };
        delete reqHeaders['proxy-connection'];
        delete reqHeaders['proxy-authorization'];

        const outReq = http.request(
          {
            createConnection: () => socket,
            method: req.method,
            host,
            port,
            path: targetUrl.pathname + targetUrl.search,
            headers: reqHeaders,
          },
          (outRes) => {
            res.writeHead(outRes.statusCode ?? 502, outRes.headers);
            outRes.pipe(res);
          },
        );
        outReq.on('error', (err) => {
          if (!res.headersSent) res.writeHead(502);
          res.end(`Target error: ${err.message}\n`);
        });
        req.pipe(outReq);
      } catch (err) {
        if (!res.headersSent) res.writeHead(400);
        res.end(`Proxy request error: ${err instanceof Error ? err.message : String(err)}\n`);
      }
    });

    server.on('connect', async (req, clientSocket, head) => {
      try {
        const authority = req.url ?? '';
        const lastColon = authority.lastIndexOf(':');
        const host = lastColon > 0 ? authority.slice(0, lastColon).replace(/^\[|\]$/g, '') : authority;
        const port = lastColon > 0 ? Number(authority.slice(lastColon + 1)) : 443;

        const verdict = await this.checkAndAuthorize(host, port);
        if (!verdict.allowed) {
          this.onDenied?.({ host, port, reason: verdict.reason });
          clientSocket.write(
            `HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nDSH WSL Sandbox Proxy Blocked: ${verdict.reason}\r\n`,
          );
          clientSocket.destroy();
          return;
        }

        const { socket: upstream, via } = await this.openTargetSocket(host, port, Boolean(verdict.isLocalLab));
        this.onAllowed?.({ host, port, via });

        clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
        if (head && head.length > 0) {
          upstream.write(head);
        }
        upstream.pipe(clientSocket);
        clientSocket.pipe(upstream);

        upstream.on('error', () => clientSocket.destroy());
        clientSocket.on('error', () => upstream.destroy());
      } catch (err) {
        clientSocket.write(
          `HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n${err instanceof Error ? err.message : String(err)}\r\n`,
        );
        clientSocket.destroy();
      }
    });

    await new Promise<void>((resolve, reject) => {
      server.once('error', reject);
      server.listen(this.socketPath, () => {
        try {
          fs.chmodSync(this.socketPath, 0o600);
        } catch {
          // Best-effort chmod
        }
        resolve();
      });
    });

    this.server = server;
  }

  async stop(): Promise<void> {
    const srv = this.server;
    this.server = undefined;
    if (srv) {
      await new Promise<void>((resolve) => srv.close(() => resolve()));
    }
    fs.rmSync(this.socketPath, { force: true });
  }
}
