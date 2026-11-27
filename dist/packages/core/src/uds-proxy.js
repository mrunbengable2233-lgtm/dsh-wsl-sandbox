import dns from 'node:dns/promises';
import fs from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import path from 'node:path';
import tls from 'node:tls';
import { URL } from 'node:url';

/**
 * Outbound Allowlist HTTP/CONNECT Proxy listening on a Unix Domain Socket (Q5=B + Q16=A).
 *
 * Security properties:
 * 1. Sandbox keeps `--unshare-net` (zero direct internet or host-LAN access).
 * 2. Only allowed dev domains (or dynamically session-approved domains) pass through.
 * 3. Private / loopback / link-local / metadata IPv4 & IPv6 addresses are ALWAYS blocked
 *    to prevent SSRF, unless matched by human-configured Advanced `localLabCidrs` / `localLabPorts`.
 * 4. Pins DNS resolution results from policy check into `net.connect` custom `lookup` to defeat DNS rebinding TOCTOU.
 * 5. Supports chaining to an upstream local proxy (`http://`, `https://`, or `socks5://`).
 */

export const DEFAULT_DEV_DOMAIN_ALLOWLIST                    = [
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

                             
                           
                        
 

                                 
                              
                                              
                                                    
                                  
                                             
                                             
                                                                                     
                                                                                                                           
                                                                                      
                                                                                   
 

const UPSTREAM_HANDSHAKE_TIMEOUT_MS = 15_000;

function ipv4ToInt(ip        )                {
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

export function parseIpv4Cidr(cidr        )                    {
  const [ipStr, prefixStr] = cidr.trim().split('/');
  if (!ipStr) return null;
  const ip = ipv4ToInt(ipStr);
  if (ip === null) return null;
  const prefix = prefixStr === undefined ? 32 : Number(prefixStr);
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > 32) return null;
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return { network: (ip & mask) >>> 0, mask };
}

const PRIVATE_IPV4_CIDR_STRS = [
  '0.0.0.0/8',
  '10.0.0.0/8',
  '100.64.0.0/10',
  '127.0.0.0/8',
  '169.254.0.0/16',
  '172.16.0.0/12',
  '192.0.0.0/24',
  '192.168.0.0/16',
  '198.18.0.0/15',
  '224.0.0.0/4',
  '240.0.0.0/4',
]         ;

const PRIVATE_IPV4_CIDRS                        = PRIVATE_IPV4_CIDR_STRS.map((c) => parseIpv4Cidr(c) );

const PRIVATE_BLOCKLIST = (() => {
  const bl = new net.BlockList();
  for (const cidr of PRIVATE_IPV4_CIDR_STRS) {
    const [addr, prefix] = cidr.split('/');
    bl.addSubnet(addr , Number(prefix), 'ipv4');
  }
  bl.addAddress('::', 'ipv6');
  bl.addAddress('::1', 'ipv6');
  bl.addSubnet('64:ff9b::', 96, 'ipv6');
  bl.addSubnet('100::', 64, 'ipv6');
  bl.addSubnet('fc00::', 7, 'ipv6');
  bl.addSubnet('fe80::', 10, 'ipv6');
  bl.addSubnet('ff00::', 8, 'ipv6');
  return bl;
})();

function ipMatchesCidrs(ip        , cidrs                       )          {
  const val = ipv4ToInt(ip);
  if (val === null) return false;
  return cidrs.some((c) => ((val & c.mask) >>> 0) === c.network);
}

function stripIpBracketsAndZone(rawIp        )         {
  let ip = rawIp.trim().toLowerCase().replace(/^\[|\]$/g, '');
  const zoneIdx = ip.indexOf('%');
  if (zoneIdx !== -1) {
    ip = ip.slice(0, zoneIdx);
  }
  return ip;
}

function expandIpv6Hextets(ip        )                  {
  if (!net.isIPv6(ip)) return null;

  let work = ip;
  if (work.includes('.')) {
    const lastColon = work.lastIndexOf(':');
    if (lastColon === -1) return null;
    const v4Int = ipv4ToInt(work.slice(lastColon + 1));
    if (v4Int === null) return null;
    const hi = ((v4Int >>> 16) & 0xffff).toString(16);
    const lo = (v4Int & 0xffff).toString(16);
    work = `${work.slice(0, lastColon + 1)}${hi}:${lo}`;
  }

  const dblParts = work.split('::');
  if (dblParts.length > 2) return null;

  const parseSegs = (part        )                  => {
    if (!part) return [];
    const segs = part.split(':');
    const nums           = [];
    for (const seg of segs) {
      if (!/^[0-9a-f]{1,4}$/.test(seg)) return null;
      nums.push(parseInt(seg, 16));
    }
    return nums;
  };

  if (dblParts.length === 1) {
    const full = parseSegs(dblParts[0] );
    return full && full.length === 8 ? full : null;
  }

  const left = parseSegs(dblParts[0] );
  const right = parseSegs(dblParts[1] );
  if (!left || !right) return null;
  const missing = 8 - (left.length + right.length);
  if (missing < 1) return null;
  return [...left, ...new Array        (missing).fill(0), ...right];
}

function hextetsToIpv4(h6        , h7        )         {
  return `${(h6 >>> 8) & 0xff}.${h6 & 0xff}.${(h7 >>> 8) & 0xff}.${h7 & 0xff}`;
}

function canonicalizeIp(rawIp        )         {
  const ip = stripIpBracketsAndZone(rawIp);
  if (net.isIPv4(ip)) return ip;
  const hextets = expandIpv6Hextets(ip);
  if (!hextets) return ip;
  // Normalize IPv4-mapped ::ffff:0:0/96 or ::1 / ::
  const isAllZeroPrefix =
    hextets[0] === 0 && hextets[1] === 0 && hextets[2] === 0 && hextets[3] === 0 && hextets[4] === 0;
  if (isAllZeroPrefix && hextets[5] === 0 && hextets[6] === 0 && hextets[7] === 1) {
    return '::1';
  }
  if (isAllZeroPrefix && hextets[5] === 0xffff) {
    return hextetsToIpv4(hextets[6] , hextets[7] );
  }
  return ip;
}

export function isPrivateOrLoopbackIp(rawIp        )          {
  const ip = stripIpBracketsAndZone(rawIp);
  if (net.isIPv4(ip)) {
    return PRIVATE_BLOCKLIST.check(ip, 'ipv4') || ipMatchesCidrs(ip, PRIVATE_IPV4_CIDRS);
  }
  if (net.isIPv6(ip)) {
    if (PRIVATE_BLOCKLIST.check(ip, 'ipv6')) return true;
    const hextets = expandIpv6Hextets(ip);
    if (!hextets) return false;
    const zeroFirstFive =
      hextets[0] === 0 && hextets[1] === 0 && hextets[2] === 0 && hextets[3] === 0 && hextets[4] === 0;
    // ::ffff:0:0/96 IPv4-mapped IPv6 (including hex forms like ::ffff:7f00:1)
    if (zeroFirstFive && hextets[5] === 0xffff) {
      const innerV4 = hextetsToIpv4(hextets[6] , hextets[7] );
      return PRIVATE_BLOCKLIST.check(innerV4, 'ipv4');
    }
    // Deprecated IPv4-compatible ::/96
    if (zeroFirstFive && hextets[5] === 0) {
      const innerV4 = hextetsToIpv4(hextets[6] , hextets[7] );
      return PRIVATE_BLOCKLIST.check(innerV4, 'ipv4');
    }
    // 64:ff9b::/96 NAT64 (block both prefix and embedded IPv4)
    if (
      hextets[0] === 0x0064 &&
      hextets[1] === 0xff9b &&
      hextets[2] === 0 &&
      hextets[3] === 0 &&
      hextets[4] === 0 &&
      hextets[5] === 0
    ) {
      return true;
    }
    return false;
  }
  return false;
}

export function domainMatchesPattern(host        , pattern        )          {
  const h = stripIpBracketsAndZone(host);
  const p = pattern.trim().toLowerCase();
  if (!p) return false;
  if (p.startsWith('*.')) {
    const suffix = p.slice(1); // ".example.com"
    return h.endsWith(suffix) && h.length > suffix.length;
  }
  return h === p;
}

                                      
                            
                          
                                
                                   
                             
 

export async function evaluateProxyTarget(
  rawHost        ,
  port        ,
  options   
                                          
                                                 
                                                  
                                                
                                                               
                                        
   ,
)                               {
  const host = stripIpBracketsAndZone(rawHost);
  if (!host || !Number.isInteger(port) || port < 1 || port > 65535) {
    return { allowed: false, reason: `Invalid target host or port: ${rawHost}:${port}` };
  }

  const isLocalhostName = host === 'localhost' || host.endsWith('.localhost') || host === 'host.docker.internal';
  const literalIpType = net.isIP(host);

  const checkLocalLab = (ipList                   )          => {
    for (const ip of ipList) {
      const normalized = canonicalizeIp(ip);
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

  // 1. Literal IP or localhost checks (ALWAYS enforced even when upstreamProxy is configured!)
  if (isLocalhostName) {
    if (checkLocalLab(['127.0.0.1', '::1'])) {
      return {
        allowed: true,
        reason: `Matched Advanced local lab loopback port ${port}`,
        isLocalLab: true,
        pinnedIp: '127.0.0.1',
      };
    }
    return {
      allowed: false,
      reason: `SSRF blocked: localhost target ${host}:${port} is not in Advanced localLabPorts`,
      isSsrfBlocked: true,
    };
  }

  if (literalIpType !== 0) {
    const canonIp = canonicalizeIp(host);
    if (isPrivateOrLoopbackIp(host)) {
      if (checkLocalLab([host])) {
        return {
          allowed: true,
          reason: `Matched Advanced local lab CIDR/port (${host}:${port})`,
          isLocalLab: true,
          pinnedIp: canonIp,
        };
      }
      return {
        allowed: false,
        reason: `SSRF blocked: private/loopback IP ${host}:${port} denied`,
        isSsrfBlocked: true,
      };
    }
    // Public literal IP still requires allowlist
    const inList =
      options.sessionAllowed.has(host) ||
      options.allowlist.some((p) => domainMatchesPattern(host, p));
    return inList
      ? { allowed: true, reason: 'Allowed public IP', pinnedIp: host }
      : { allowed: false, reason: `Target IP ${host} is not in proxy allowlist` };
  }

  // 2. Domain allowlist check
  const domainAllowed =
    options.sessionAllowed.has(host) ||
    options.allowlist.some((pattern) => domainMatchesPattern(host, pattern));

  if (!domainAllowed) {
    return { allowed: false, reason: `Domain ${host} is not in proxy allowlist` };
  }

  // 3. DNS rebinding / SSRF protection + IP pinning
  let pinnedIp                    ;
  if (!options.hasUpstreamProxy || options.resolveHost) {
    const resolver = options.resolveHost ?? (async (h        ) => {
      const results = await dns.lookup(h, { all: true });
      return results.map((r) => r.address);
    });
    try {
      const ips = await resolver(host);
      if (ips.length === 0 && !options.hasUpstreamProxy) {
        return { allowed: false, reason: `DNS resolution returned no addresses for ${host}` };
      }
      for (const ip of ips) {
        if (isPrivateOrLoopbackIp(ip)) {
          if (checkLocalLab([ip])) {
            return {
              allowed: true,
              reason: `Resolved ${host} -> ${ip} matched Advanced local lab`,
              isLocalLab: true,
              pinnedIp: canonicalizeIp(ip),
            };
          }
          return {
            allowed: false,
            reason: `SSRF blocked: domain ${host} resolved to private/loopback IP ${ip}`,
            isSsrfBlocked: true,
          };
        }
      }
      if (ips.length > 0) {
        pinnedIp = ips[0];
      }
    } catch {
      if (!options.hasUpstreamProxy) {
        return { allowed: false, reason: `DNS resolution failed for ${host}` };
      }
    }
  }

  return { allowed: true, reason: `Domain ${host} allowed`, ...(pinnedIp ? { pinnedIp } : {}) };
}

function connectViaHttpUpstream(
  upstreamUrl     ,
  targetHost        ,
  targetPort        ,
)                      {
  return new Promise((resolve, reject) => {
    const proxyHost = upstreamUrl.hostname;
    const isHttpsUpstream = upstreamUrl.protocol === 'https:';
    const proxyPort = Number(upstreamUrl.port || (isHttpsUpstream ? 443 : 80));
    const sock             = isHttpsUpstream
      ? tls.connect({ host: proxyHost, port: proxyPort, servername: proxyHost })
      : net.connect(proxyPort, proxyHost);
    let settled = false;
    let buf = '';

    const timer = setTimeout(() => {
      fail(new Error('Upstream HTTP proxy handshake timed out'));
    }, UPSTREAM_HANDSHAKE_TIMEOUT_MS);
    timer.unref();

    const cleanupListeners = ()       => {
      clearTimeout(timer);
      sock.off('error', fail);
      sock.off('close', onClose);
      sock.off('data', onData);
    };

    const fail = (err       )       => {
      if (settled) return;
      settled = true;
      cleanupListeners();
      sock.destroy();
      reject(err);
    };

    const onClose = ()       => {
      fail(new Error('Upstream HTTP proxy closed before CONNECT completed'));
    };

    sock.on('error', fail);
    sock.once('close', onClose);
    sock.once(isHttpsUpstream ? 'secureConnect' : 'connect', () => {
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

    const onData = (chunk        )       => {
      buf += chunk.toString('latin1');
      const endIdx = buf.indexOf('\r\n\r\n');
      if (endIdx === -1) {
        if (buf.length > 16384) fail(new Error('Upstream HTTP proxy response header too large'));
        return;
      }
      const statusLine = buf.slice(0, buf.indexOf('\r\n'));
      const match = statusLine.match(/^HTTP\/\d\.\d\s+(\d{3})/);
      if (!match || Number(match[1]) !== 200) {
        fail(new Error(`Upstream HTTP proxy rejected CONNECT: ${statusLine}`));
        return;
      }
      settled = true;
      cleanupListeners();
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
  upstreamUrl     ,
  targetHost        ,
  targetPort        ,
)                      {
  return new Promise((resolve, reject) => {
    const proxyHost = upstreamUrl.hostname;
    const proxyPort = Number(upstreamUrl.port || 1080);
    const sock = net.connect(proxyPort, proxyHost);
    let settled = false;
    let stage                                  = 'greeting';
    let acc = Buffer.alloc(0);

    const hasAuth = Boolean(upstreamUrl.username || upstreamUrl.password);

    const timer = setTimeout(() => {
      fail(new Error('Upstream SOCKS5 proxy handshake timed out'));
    }, UPSTREAM_HANDSHAKE_TIMEOUT_MS);
    timer.unref();

    const cleanupListeners = ()       => {
      clearTimeout(timer);
      sock.off('error', fail);
      sock.off('close', onClose);
      sock.off('data', onData);
    };

    const fail = (err       )       => {
      if (settled) return;
      settled = true;
      cleanupListeners();
      sock.destroy();
      reject(err);
    };

    const onClose = ()       => {
      fail(new Error('Upstream SOCKS5 proxy closed before CONNECT completed'));
    };

    const sendConnectRequest = ()       => {
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

    sock.on('error', fail);
    sock.once('close', onClose);
    sock.once('connect', () => {
      if (hasAuth) {
        sock.write(Buffer.from([0x05, 0x02, 0x00, 0x02]));
      } else {
        sock.write(Buffer.from([0x05, 0x01, 0x00]));
      }
    });

    const onData = (chunk        )       => {
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
          headerLen += 1 + acc[4]  + 2;
        } else {
          fail(new Error(`Invalid SOCKS5 ATYP: ${atyp}`));
          return;
        }
        if (acc.length < headerLen) return;
        const leftover = acc.subarray(headerLen);
        settled = true;
        cleanupListeners();
        if (leftover.length > 0) sock.unshift(leftover);
        resolve(sock);
      }
    };

    sock.on('data', onData);
  });
}

export class UdsAllowlistProxy {
                   socketPath        ;
                   baseAllowedDomains                   ;
          allowlist          ;
                   sessionAllowed = new Set        ();
          localLabCidrs              ;
          localLabPorts             ;
          upstreamUrl                 ;
                   onDenied                             ;
                   onAllowed                              ;
                   authorizeUnknownHost                                         ;
          server                         ;

  constructor(config                ) {
    this.socketPath = config.socketPath;
    this.baseAllowedDomains = [...(config.allowedDomains ?? DEFAULT_DEV_DOMAIN_ALLOWLIST)];
    this.allowlist = [
      ...this.baseAllowedDomains,
      ...(config.customAllowedDomains ?? []),
    ];
    this.localLabCidrs = (config.localLabCidrs ?? [])
      .map(parseIpv4Cidr)
      .filter((c)                  => c !== null);
    this.localLabPorts = new Set(config.localLabPorts ?? []);
    if (config.upstreamProxy && config.upstreamProxy.trim().length > 0) {
      this.upstreamUrl = new URL(config.upstreamProxy.trim());
    }
    this.onDenied = config.onDenied;
    this.onAllowed = config.onAllowed;
    this.authorizeUnknownHost = config.authorizeUnknownHost;
  }

  getSocketPath()         {
    return this.socketPath;
  }

  getAllowlistSnapshot()                    {
    return [...this.allowlist];
  }

  addSessionAllowedDomain(host        )       {
    this.sessionAllowed.add(stripIpBracketsAndZone(host));
  }

  clearSessionAllowedDomains()       {
    this.sessionAllowed.clear();
  }

  updatePolicy(patch   
                                             
                           
                                      
                                      
   )       {
    if (patch.customAllowedDomains) {
      this.allowlist = [...this.baseAllowedDomains, ...patch.customAllowedDomains];
    }
    if (patch.upstreamProxy !== undefined) {
      this.upstreamUrl = patch.upstreamProxy.trim() ? new URL(patch.upstreamProxy.trim()) : undefined;
    }
    if (patch.localLabCidrs) {
      this.localLabCidrs = patch.localLabCidrs
        .map(parseIpv4Cidr)
        .filter((c)                  => c !== null);
    }
    if (patch.localLabPorts) {
      this.localLabPorts = new Set(patch.localLabPorts);
    }
  }

          async checkAndAuthorize(host        , port        )                               {
    const evalOpts = {
      allowlist: this.allowlist,
      sessionAllowed: this.sessionAllowed,
      localLabCidrs: this.localLabCidrs,
      localLabPorts: this.localLabPorts,
      hasUpstreamProxy: Boolean(this.upstreamUrl),
    };
    const verdict = await evaluateProxyTarget(host, port, evalOpts);

    if (verdict.allowed || verdict.isSsrfBlocked) {
      return verdict;
    }

    if (this.authorizeUnknownHost) {
      const approved = await this.authorizeUnknownHost(host, port);
      if (approved) {
        this.addSessionAllowedDomain(host);
        return evaluateProxyTarget(host, port, evalOpts);
      }
    }
    return verdict;
  }

          async openTargetSocket(
    host        ,
    port        ,
    isLocalLab         ,
    pinnedIp         ,
  )                                                                                       {
    // Local lab targets always connect directly (never sent to external upstream proxy)
    if (!isLocalLab && this.upstreamUrl) {
      if (this.upstreamUrl.protocol === 'socks5:' || this.upstreamUrl.protocol === 'socks5h:') {
        const socket = await connectViaSocks5Upstream(this.upstreamUrl, host, port);
        return { socket, via: 'upstream-socks5' };
      }
      const socket = await connectViaHttpUpstream(this.upstreamUrl, host, port);
      return { socket, via: 'upstream-http' };
    }

    const connectHost = stripIpBracketsAndZone(host);
    const socket = await new Promise            ((resolve, reject) => {
      let s            ;
      if (pinnedIp && net.isIP(pinnedIp) !== 0 && net.isIP(connectHost) === 0) {
        const family = net.isIPv6(pinnedIp) ? 6 : 4;
        const pinnedLookup = ((
          _hostname        ,
          opts                   ,
          cb                                                                                                                      ,
        ) => {
          if (opts && opts.all) {
            cb(null, [{ address: pinnedIp, family }]);
          } else {
            cb(null, pinnedIp, family);
          }
        })                                 ;
        s = net.connect({ host: connectHost, port, lookup: pinnedLookup });
      } else {
        s = net.connect(port, pinnedIp && net.isIP(pinnedIp) !== 0 ? pinnedIp : connectHost);
      }
      s.once('error', reject);
      s.once('connect', () => {
        s.off('error', reject);
        resolve(s);
      });
    });
    return { socket, via: 'direct' };
  }

                   activeSockets = new Set            ();

          trackSocket(sock            )       {
    this.activeSockets.add(sock);
    sock.once('close', () => {
      this.activeSockets.delete(sock);
    });
  }

  async start()                {
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
          const upstreamHeaders                                                = { ...req.headers };
          delete upstreamHeaders['proxy-connection'];
          if (this.upstreamUrl.username || this.upstreamUrl.password) {
            const token = Buffer.from(
              `${decodeURIComponent(this.upstreamUrl.username)}:${decodeURIComponent(this.upstreamUrl.password)}`,
            ).toString('base64');
            upstreamHeaders['proxy-authorization'] = `Basic ${token}`;
          }
          const isHttpsUpstream = this.upstreamUrl.protocol === 'https:';
          const reqFn = isHttpsUpstream ? https.request : http.request;
          const proxyReq = reqFn(
            {
              host: this.upstreamUrl.hostname,
              port: Number(this.upstreamUrl.port || (isHttpsUpstream ? 443 : 80)),
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

        const { socket, via } = await this.openTargetSocket(
          host,
          port,
          Boolean(verdict.isLocalLab),
          verdict.pinnedIp,
        );
        this.trackSocket(socket);
        this.onAllowed?.({ host, port, via });

        const reqHeaders                                                = { ...req.headers };
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

    server.on('clientError', (_err, socket) => {
      try {
        socket.destroy();
      } catch {
        // ignore
      }
    });

    server.on('connection', (sock) => {
      sock.on('error', () => {});
      this.trackSocket(sock);
    });

    server.on('connect', async (req, clientSocket, head) => {
      clientSocket.on('error', () => {});
      this.trackSocket(clientSocket);
      try {
        const authority = req.url ?? '';
        const lastColon = authority.lastIndexOf(':');
        const host = lastColon > 0 ? authority.slice(0, lastColon).replace(/^\[|\]$/g, '') : authority;
        const port = lastColon > 0 ? Number(authority.slice(lastColon + 1)) : 443;

        const verdict = await this.checkAndAuthorize(host, port);
        if (!verdict.allowed) {
          this.onDenied?.({ host, port, reason: verdict.reason });
          if (!clientSocket.destroyed && clientSocket.writable) {
            clientSocket.write(
              `HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nDSH WSL Sandbox Proxy Blocked: ${verdict.reason}\r\n`,
            );
          }
          clientSocket.destroy();
          return;
        }

        const { socket: upstream, via } = await this.openTargetSocket(
          host,
          port,
          Boolean(verdict.isLocalLab),
          verdict.pinnedIp,
        );
        upstream.on('error', () => clientSocket.destroy());
        this.trackSocket(upstream);
        this.onAllowed?.({ host, port, via });

        if (!clientSocket.destroyed && clientSocket.writable) {
          clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
        }
        if (head && head.length > 0 && !upstream.destroyed && upstream.writable) {
          upstream.write(head);
        }
        upstream.pipe(clientSocket);
        clientSocket.pipe(upstream);

        upstream.on('close', () => clientSocket.destroy());
        clientSocket.on('close', () => upstream.destroy());
      } catch (err) {
        if (!clientSocket.destroyed && clientSocket.writable) {
          clientSocket.write(
            `HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n${err instanceof Error ? err.message : String(err)}\r\n`,
          );
        }
        clientSocket.destroy();
      }
    });

    await new Promise      ((resolve, reject) => {
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

  getActiveSocketCount()         {
    return this.activeSockets.size;
  }

  async stop()                {
    const srv = this.server;
    this.server = undefined;

    for (const sock of this.activeSockets) {
      try {
        sock.destroy();
      } catch {
        // ignore
      }
    }
    this.activeSockets.clear();

    if (srv) {
      try {
        if (typeof srv.closeAllConnections === 'function') {
          srv.closeAllConnections();
        }
      } catch {
        // ignore
      }
      await new Promise      ((resolve) => {
        const timer = setTimeout(resolve, 500);
        timer.unref();
        srv.close(() => {
          clearTimeout(timer);
          resolve();
        });
      });
    }
    fs.rmSync(this.socketPath, { force: true });
  }
}
