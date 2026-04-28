// src/utils/subscription.js - 订阅配置生成工具
import { buildClashTemplate } from "./templates/clashTemplate";
import { buildSingboxTemplate } from "./templates/singboxTemplate";
import { buildSurgeTemplate } from "./templates/surgeTemplate";
import { ensureNumber, ensureString } from "./d1";

function isObjectRecord(value: unknown): value is Record<string, any> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function decodeJsonValue(raw: unknown, maxDepth = 2): unknown {
  let current = raw;
  for (let depth = 0; depth < maxDepth; depth += 1) {
    if (typeof current !== "string") break;
    const text = current.trim();
    if (!text) return {};
    try {
      current = JSON.parse(text);
    } catch {
      break;
    }
  }
  return current;
}

function parseNodeConfig(node: any) {
  try {
    const parsedRaw = decodeJsonValue(node?.node_config ?? {});
    const parsed = isObjectRecord(parsedRaw) ? parsedRaw : {};
    const basicRaw = decodeJsonValue((parsed as any).basic);
    const configRaw = decodeJsonValue((parsed as any).config);
    const clientRaw = decodeJsonValue((parsed as any).client);
    const basic = isObjectRecord(basicRaw) ? basicRaw : {};
    const config = isObjectRecord(configRaw) ? configRaw : parsed;
    const client = isObjectRecord(clientRaw) ? clientRaw : {};
    return {
      basic,
      config,
      client
    };
  } catch {
    return { basic: {}, config: {}, client: {} };
  }
}

function resolveNodeEndpoint(node: any) {
  const { config, client, basic } = parseNodeConfig(node);
  const server = client.server || '';
  const port = client.port || config.port || 443;
  const tlsHost = client.tls_host || config.host || server;
  return {
    server,
    port,
    tlsHost,
    config,
    client,
    basic
  };
}

function normalizeStringList(value: unknown): string[] {
  if (Array.isArray(value)) {
    return value.map((item) => String(item).trim()).filter(Boolean);
  }
  if (typeof value === "string") {
    return value
      .split(",")
      .map((item) => item.trim())
      .filter(Boolean);
  }
  return [];
}

function pickRandomShortId(value: unknown): string {
  const list = normalizeStringList(value);
  if (!list.length) return "";
  const index = Math.floor(Math.random() * list.length);
  return list[index];
}

function resolveRealityPublicKey(config: any, client: any) {
  return ensureString(client?.publickey || client?.public_key || config.public_key, "");
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function resolveEchConfig(config: any, client: any): string {
  const fromClient = isRecord(client?.ech) ? ensureString((client.ech as any).config, "") : "";
  if (fromClient) return fromClient.trim();
  if (isRecord(config?.ech)) {
    return ensureString((config.ech as any).config, "").trim();
  }
  return "";
}

function resolveEchState(config: any, client: any): Record<string, unknown> | null {
  if (isRecord(client?.ech)) return client.ech as Record<string, unknown>;
  if (isRecord(config?.ech)) return config.ech as Record<string, unknown>;
  return null;
}

function parseBooleanFlag(value: unknown): boolean | null {
  if (typeof value === "boolean") return value;
  if (typeof value === "number") return value !== 0;
  if (typeof value === "string") {
    const normalized = value.trim().toLowerCase();
    if (["1", "true", "yes", "on"].includes(normalized)) return true;
    if (["0", "false", "no", "off", ""].includes(normalized)) return false;
  }
  return null;
}

function resolveSkipCertVerify(config: any, client: any, fallback = false): boolean {
  const fromClient = parseBooleanFlag(
    client?.["skip-cert-verify"]
    ?? client?.skip_cert_verify
    ?? client?.insecure
    ?? client?.allow_insecure
    ?? client?.allowInsecure
  );
  if (fromClient !== null) return fromClient;

  const fromConfig = parseBooleanFlag(
    config?.["skip-cert-verify"]
    ?? config?.skip_cert_verify
    ?? config?.insecure
    ?? config?.allow_insecure
    ?? config?.allowInsecure
  );
  if (fromConfig !== null) return fromConfig;
  return fallback;
}

function splitPemLines(raw: string): string[] {
  return raw
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);
}

function toSingboxPemLines(label: string, raw: string): string[] {
  const cleaned = ensureString(raw, "").trim();
  if (!cleaned) return [];
  if (cleaned.includes("-----BEGIN")) {
    return splitPemLines(cleaned);
  }
  const compact = cleaned.replace(/\s+/g, "");
  const chunks: string[] = [];
  for (let index = 0; index < compact.length; index += 64) {
    chunks.push(compact.slice(index, index + 64));
  }
  return [`-----BEGIN ${label}-----`, ...chunks, `-----END ${label}-----`];
}

function buildClashEchOpts(config: any, client: any) {
  const echState = resolveEchState(config, client);
  const echConfig = resolveEchConfig(config, client);
  if (!echState && !echConfig) return null;

  const opts: Record<string, unknown> = { enable: true };
  if (echConfig) {
    opts.config = echConfig;
  }
  return opts;
}

function resolveVlessClientEncryption(config: any, client: any) {
  const encryption = ensureString(client?.encryption || config?.encryption, "").trim();
  return encryption || "none";
}

function isVlessEncryptionEnabled(config: any, client: any) {
  return resolveVlessClientEncryption(config, client).toLowerCase() !== "none";
}

/**
 * 生成 V2Ray 订阅配置
 * @param {Array} nodes - 节点列表
 * @param {Object} user - 用户信息
 * @returns {string} - Base64 编码的 V2Ray 链接
 */
export function generateV2rayConfig(nodes, user) {
  const links = [];

  for (const node of nodes) {
    const endpoint = resolveNodeEndpoint(node);
    const nodeResolved = { ...node, server: endpoint.server, server_port: endpoint.port, tls_host: endpoint.tlsHost };
    const config = endpoint.config;
    const client = endpoint.client;

    switch (node.type) {
      case "v2ray":
        links.push(generateVmessLink(nodeResolved, config, user, client));
        break;
      case "vless":
        links.push(generateVlessLink(nodeResolved, config, user, client));
        break;
      case "trojan":
        links.push(generateTrojanLink(nodeResolved, config, user, client));
        break;
      case "ss":
        links.push(generateShadowsocksLink(nodeResolved, config, user));
        break;
      case "hysteria":
        links.push(generateHysteriaLink(nodeResolved, config, user, client));
        break;
    }
  }

  return btoa(links.join("\n"));
}

/**
 * 生成 VMess 链接
 */
function generateVmessLink(node, config, user, client = {}) {
  const streamType = String(config.stream_type || "tcp").toLowerCase();
  const hostCandidate = ensureString(
    config.server || node.tls_host || config.host || config.sni || node.server,
    ""
  );
  const sni = ensureString(config.sni || node.tls_host || config.host || config.server || node.server, "");
  const needsHost = ["ws", "http", "h2"].includes(streamType);
  const host = needsHost ? hostCandidate : ensureString(config.server, "");
  const tlsMode = config.tls_type === "reality" ? "reality" : config.tls_type === "tls" ? "tls" : "";
  const vmessConfig: Record<string, unknown> = {
    v: "2",
    ps: node.name,
    add: node.server,
    port: node.server_port,
    id: user.uuid,
    aid: config.aid || 0,
    net: config.stream_type || "tcp",
    type: "none",
    host,
    path: config.path || "",
    tls: tlsMode,
    sni,
    alpn: config.alpn || "",
  };

  if (config.tls_type === "reality") {
    vmessConfig.security = "reality";
    vmessConfig.pbk = resolveRealityPublicKey(config, client);
    vmessConfig.fp = config.fingerprint || "chrome";
    const shortId = pickRandomShortId(config.short_ids);
    if (shortId) {
      vmessConfig.sid = shortId;
    }
  }

  if (config.tls_type === "tls") {
    const echConfig = resolveEchConfig(config, client);
    if (echConfig) {
      vmessConfig.ech = echConfig;
      vmessConfig.echConfigList = echConfig;
    }
  }

  return `vmess://${btoa(JSON.stringify(vmessConfig))}`;
}

/**
 * 生成 VLESS 链接
 */
function generateVlessLink(node, config, user, client) {
  const params = new URLSearchParams();
  const streamType = String(config.stream_type || "tcp").toLowerCase();
  const hostCandidate = ensureString(
    config.server || node.tls_host || config.host || config.sni || node.server,
    ""
  );
  const sni = ensureString(config.sni || node.tls_host || config.host || config.server || node.server, "");

  params.set("encryption", resolveVlessClientEncryption(config, client));
  params.set("type", config.stream_type || "tcp");

  if (config.tls_type === "tls") {
    params.set("security", "tls");
    if (sni) params.set("sni", sni);
    if (config.alpn) params.set("alpn", config.alpn);
  } else if (config.tls_type === "reality") {
    params.set("security", "reality");
    params.set("pbk", resolveRealityPublicKey(config, client));
    params.set("fp", config.fingerprint || "chrome");
    if (sni) params.set("sni", sni);
    const shortId = pickRandomShortId(config.short_ids);
    if (shortId) params.set("sid", shortId);
  }
  if (config.tls_type === "tls") {
    const echConfig = resolveEchConfig(config, client);
    if (echConfig) {
      params.set("ech", echConfig);
      params.set("echConfigList", echConfig);
    }
  }

  if (config.flow) params.set("flow", config.flow);
  if (config.path) params.set("path", config.path);
  if (config.server) {
    params.set("host", config.server);
  } else if (["ws", "http", "h2"].includes(streamType) && hostCandidate) {
    params.set("host", hostCandidate);
  }
  if (config.service_name) params.set("serviceName", config.service_name);

  const host = formatHostForUrl(node.server);
  return `vless://${user.uuid}@${host}:${node.server_port}?${params.toString()}#${encodeURIComponent(node.name)}`;
}

/**
 * 生成 Trojan 链接
 */
function generateTrojanLink(node, config, user, client = {}) {
  const params = new URLSearchParams();
  const streamType = String(config.stream_type || "tcp").toLowerCase();
  const hostCandidate = ensureString(
    config.server || node.tls_host || config.host || config.sni || node.server,
    ""
  );
  const sni = ensureString(config.sni || node.tls_host || config.host || config.server || node.server, "");

  const tlsMode = config.tls_type === "reality" ? "reality" : "tls";
  params.set("security", tlsMode);
  if (sni) params.set("sni", sni);
  if (config.alpn) params.set("alpn", config.alpn);
  if (config.tls_type === "reality") {
    params.set("pbk", resolveRealityPublicKey(config, client));
    params.set("fp", config.fingerprint || "chrome");
    const shortId = pickRandomShortId(config.short_ids);
    if (shortId) params.set("sid", shortId);
  }
  if (config.tls_type !== "reality") {
    const echConfig = resolveEchConfig(config, client);
    if (echConfig) {
      params.set("ech", echConfig);
      params.set("echConfigList", echConfig);
    }
  }
  if (config.path) params.set("path", config.path);
  if (config.server) {
    params.set("host", config.server);
  } else if (["ws", "http", "h2"].includes(streamType) && hostCandidate) {
    params.set("host", hostCandidate);
  }

  const queryString = params.toString();
  const host = formatHostForUrl(node.server);
  const password = encodeURIComponent(String(user.passwd ?? ""));
  const url = `trojan://${password}@${host}:${node.server_port}`;

  return queryString
    ? `${url}?${queryString}#${encodeURIComponent(node.name)}`
    : `${url}#${encodeURIComponent(node.name)}`;
}

/**
 * 生成 Shadowsocks 链接
 */
function deriveSS2022UserKey(method: string, userPassword: string) {
  const needs = method.toLowerCase().includes('aes-128') ? 16 : 32;
  const decodeBase64 = (value: string) => {
    try {
      const cleaned = value.trim();
      if (!cleaned) return null;
      const decoded = atob(cleaned);
      return Uint8Array.from(decoded, (c) => c.charCodeAt(0));
    } catch {
      return null;
    }
  };
  const toUtf8 = (value: string) => {
    try {
      return new TextEncoder().encode(value);
    } catch {
      return Uint8Array.from([]);
    }
  };

  let bytes = decodeBase64(userPassword) || toUtf8(userPassword);
  if (!bytes || bytes.length === 0) {
    bytes = Uint8Array.from([0]);
  }

  const out = new Uint8Array(needs);
  for (let i = 0; i < needs; i++) {
    out[i] = bytes[i % bytes.length];
  }

  let binary = '';
  out.forEach((b) => {
    binary += String.fromCharCode(b);
  });
  return btoa(binary);
}

function generateShadowsocksLink(node, config, user) {
  const method = config.cipher || 'aes-128-gcm';
  const password = buildSS2022Password(config, user.passwd || config.password || "");
  const userInfo = `${method}:${password}`;
  const encoded = btoa(userInfo);

  const host = formatHostForUrl(node.server);
  let link = `ss://${encoded}@${host}:${node.server_port}`;

  // 添加混淆参数
  if (config.obfs && config.obfs !== "plain") {
    const params = new URLSearchParams();
    params.set("plugin", "obfs-local");
    let pluginOpts = `obfs=${config.obfs}`;
    if (config.server) pluginOpts += `;obfs-host=${config.server}`;
    if (config.path) pluginOpts += `;obfs-uri=${config.path}`;
    params.set("plugin-opts", pluginOpts);
    link += `?${params.toString()}`;
  }

  return `${link}#${encodeURIComponent(node.name)}`;
}

function buildSS2022Password(config: any, userPassword: string) {
  const method = config.cipher || config.method || '';
  const serverPassword = config.password || '';
  const isSS2022 = String(method).toLowerCase().includes('2022-blake3');
  if (!isSS2022) {
    return userPassword || serverPassword;
  }
  const userPart = deriveSS2022UserKey(method, userPassword || serverPassword);
  return [serverPassword, userPart].filter(Boolean).join(':');
}

/**
 * 生成 Hysteria 链接
 */
function generateHysteriaLink(node, config, user, client = {}) {
  const params = new URLSearchParams();

  params.set("protocol", "udp");
  params.set("auth", user.passwd);
  params.set("peer", node.tls_host || node.server);
  if (resolveSkipCertVerify(config, client, false)) {
    params.set("insecure", "1");
  }
  params.set("upmbps", config.up_mbps || "100");
  params.set("downmbps", config.down_mbps || "100");

  if (config.obfs && config.obfs !== "plain") {
    params.set("obfs", config.obfs);
    if (config.obfs_password) params.set("obfsParam", config.obfs_password);
  }
  const echConfig = resolveEchConfig(config, client);
  if (echConfig) {
    params.set("ech", echConfig);
    params.set("echConfigList", echConfig);
  }

  const host = formatHostForUrl(node.server);
  return `hysteria2://${host}:${node.server_port}?${params.toString()}#${encodeURIComponent(node.name)}`;
}

/**
 * 生成 Clash 配置
 * @param {Array} nodes - 节点列表
 * @param {Object} user - 用户信息
 * @returns {string} - YAML 格式的 Clash 配置
 */
export function generateClashConfig(nodes, user) {
  const proxies = [];
  const proxyNames = [];

  for (const node of nodes) {
    const { config, server, port, tlsHost, client } = resolveNodeEndpoint(node);
    let proxy = null;

    switch (node.type) {
      case "v2ray":
        const vmessTlsEnabled = config.tls_type === "tls" || config.tls_type === "reality";
        proxy = {
          name: node.name,
          type: "vmess",
          server,
          port,
          uuid: user.uuid,
          alterId: config.aid || 0,
          cipher: "auto",
          tls: vmessTlsEnabled,
          network: config.stream_type || "tcp",
        };
        if (vmessTlsEnabled) {
          proxy["skip-cert-verify"] = resolveSkipCertVerify(config, client, false);
        }

        // 添加 TLS 相关配置
        if (config.tls_type === "tls" || config.tls_type === "reality") {
          if (tlsHost || config.sni) {
            proxy.servername = tlsHost || config.sni;
          }
          if (config.alpn) {
            proxy.alpn = config.alpn.split(',');
          }
        }
        if (config.tls_type === "reality") {
          const realityOpts: Record<string, string> = {
            "public-key": resolveRealityPublicKey(config, client)
          };
          const shortId = pickRandomShortId(config.short_ids);
          if (shortId) {
            realityOpts["short-id"] = shortId;
          }
          proxy["reality-opts"] = realityOpts;
          proxy["client-fingerprint"] = config.fingerprint || "chrome";
        }
        if (config.tls_type === "tls") {
          const echOpts = buildClashEchOpts(config, client);
          if (echOpts) {
            proxy["ech-opts"] = echOpts;
          }
        }

        // WebSocket 配置
        if (config.stream_type === "ws") {
          proxy["ws-opts"] = {
            path: config.path || "/",
            headers: { Host: tlsHost || config.server || server },
          };
        } 
        // gRPC 配置
        else if (config.stream_type === "grpc") {
          proxy["grpc-opts"] = {
            "grpc-service-name": config.service_name || "grpc",
          };
        }
        // HTTP 配置
        else if (config.stream_type === "http") {
          proxy["http-opts"] = {
            method: "GET",
            path: [config.path || "/"],
          };
          if (config.server) {
            proxy["http-opts"].headers = {
              Connection: ["keep-alive"],
              Host: [node.tls_host || config.server]
            };
          }
        }
        break;

      case "vless":
        const vlessTlsEnabled = config.tls_type === "tls" || config.tls_type === "reality";
        proxy = {
          name: node.name,
          type: "vless",
          server,
          port,
          uuid: user.uuid,
          encryption: resolveVlessClientEncryption(config, client),
          tls: vlessTlsEnabled,
          network: config.stream_type || "tcp",
        };
        if (vlessTlsEnabled) {
          proxy["skip-cert-verify"] = resolveSkipCertVerify(config, client, false);
        }

        // TLS 配置
        if (config.tls_type === "tls") {
          if (tlsHost || config.sni) {
            proxy.servername = tlsHost || config.sni;
          }
          if (config.alpn) {
            proxy.alpn = config.alpn.split(',');
          }
        }

        // Reality 配置
        if (config.tls_type === "reality") {
          const realityOpts: Record<string, string> = {
            "public-key": resolveRealityPublicKey(config, client)
          };
          const shortId = pickRandomShortId(config.short_ids);
          if (shortId) {
            realityOpts["short-id"] = shortId;
          }
          proxy["reality-opts"] = realityOpts;
          proxy["client-fingerprint"] = config.fingerprint || "chrome";
          if (tlsHost) {
            proxy.servername = tlsHost;
          }
        }
        if (config.tls_type === "tls") {
          const echOpts = buildClashEchOpts(config, client);
          if (echOpts) {
            proxy["ech-opts"] = echOpts;
          }
        }

        if (config.flow) {
          proxy.flow = config.flow;
        }

        // WebSocket 配置
        if (config.stream_type === "ws") {
          proxy["ws-opts"] = {
            path: config.path || "/",
            headers: { Host: tlsHost || config.server || server },
          };
        }
        // gRPC 配置
        else if (config.stream_type === "grpc") {
          proxy["grpc-opts"] = {
            "grpc-service-name": config.service_name || "grpc",
          };
        }
        break;

      case "trojan":
        proxy = {
          name: node.name,
          type: "trojan",
          server,
          port,
          password: user.passwd,
          "skip-cert-verify": resolveSkipCertVerify(config, client, false),
          sni: tlsHost || config.sni || server,
        };
        if (config.tls_type === "reality") {
          const realityOpts: Record<string, string> = {
            "public-key": resolveRealityPublicKey(config, client)
          };
          const shortId = pickRandomShortId(config.short_ids);
          if (shortId) {
            realityOpts["short-id"] = shortId;
          }
          proxy["reality-opts"] = realityOpts;
          proxy["client-fingerprint"] = config.fingerprint || "chrome";
        }
        if (config.tls_type !== "reality") {
          const echOpts = buildClashEchOpts(config, client);
          if (echOpts) {
            proxy["ech-opts"] = echOpts;
          }
        }

        // 添加 WebSocket 支持
        if (config.stream_type === "ws") {
          proxy.network = "ws";
          proxy["ws-opts"] = {
            path: config.path || "/",
            headers: {
              Host: tlsHost || config.sni || server
            }
          };
        }

        // 添加 gRPC 支持
        if (config.stream_type === "grpc") {
          proxy.network = "grpc";
          proxy["grpc-opts"] = {
            "grpc-service-name": config.service_name || "grpc"
          };
        }
        break;

      case "ss":
        proxy = {
          name: node.name,
          type: "ss",
          server,
          port,
          cipher: config.cipher || "aes-128-gcm",
          password: buildSS2022Password(config, user.passwd || ""),
          udp: true,
        };

        // 混淆插件配置
        if (config.obfs && config.obfs !== "plain") {
          proxy.plugin = "obfs";
          proxy["plugin-opts"] = {
            mode: config.obfs === "simple_obfs_http" ? "http" : "tls",
            host: tlsHost || config.server || "bing.com",
          };
        }
        break;

      case "ssr":
      case "shadowsocksr":
        proxy = {
          name: node.name,
          type: "ssr",
          server,
          port,
          cipher: config.method || config.cipher || "aes-256-cfb",
          password: String(config.password || ""),
          protocol: config.protocol || "origin",
          obfs: config.obfs || "plain",
          udp: true,
        };
        {
          const protocolParam =
            config.protocol_param ||
            config["protocol-param"] ||
            config.protocolparam ||
            (Number(user.id) > 0 ? `${user.id}:${String(user.passwd || "")}` : "") ||
            "";
          const obfsParamCandidate =
            config.obfs_param || config["obfs-param"] || config.obfsparam || tlsHost || config.server || "";
          const obfsName = String(config.obfs || "").toLowerCase();
          const needObfsParam = ["http_simple", "http_post", "tls1.2_ticket_auth", "simple_obfs_http", "simple_obfs_tls"].includes(obfsName);
          if (protocolParam) proxy["protocol-param"] = protocolParam;
          if (needObfsParam && obfsParamCandidate) proxy["obfs-param"] = obfsParamCandidate;
        }
        break;

      case "anytls":
        proxy = {
          name: node.name,
          type: "anytls",
          server,
          port,
          password: String(user.passwd || config.password || ""),
          "client-fingerprint": config.fingerprint || "chrome",
          udp: true,
          "idle-session-check-interval": config.idle_session_check_interval ?? 30,
          "idle-session-timeout": config.idle_session_timeout ?? 30,
          "min-idle-session": config.min_idle_session ?? 0,
          "skip-cert-verify": resolveSkipCertVerify(config, client, false),
        };
        {
          const sni = tlsHost || config.sni || config.server;
          if (sni) proxy.sni = sni;
          const alpnRaw = config.alpn;
          if (Array.isArray(alpnRaw) && alpnRaw.length) proxy.alpn = alpnRaw;
          else if (typeof alpnRaw === "string" && alpnRaw.trim()) {
            proxy.alpn = alpnRaw.split(",").map((v: string) => v.trim()).filter(Boolean);
          }
          const echOpts = buildClashEchOpts(config, client);
          if (echOpts) {
            proxy["ech-opts"] = echOpts;
          }
        }
        break;

      case "hysteria":
        proxy = {
          name: node.name,
          type: "hysteria2",
          server,
          port,
          password: user.passwd,
          "skip-cert-verify": resolveSkipCertVerify(config, client, false),
        };

        // 添加 SNI 配置
        if (tlsHost || config.sni) {
          proxy.sni = tlsHost || config.sni;
        }

        // 添加混淆配置
        if (config.obfs && config.obfs !== "plain") {
          proxy.obfs = config.obfs;
          if (config.obfs_password) {
            proxy["obfs-password"] = config.obfs_password;
          }
        }

        // 添加带宽配置
        if (config.up_mbps) {
          proxy.up = `${config.up_mbps} Mbps`;
        }
        if (config.down_mbps) {
          proxy.down = `${config.down_mbps} Mbps`;
        }

        // 添加 ALPN 配置
        if (config.alpn) {
          proxy.alpn = config.alpn.split(',');
        }
        {
          const echOpts = buildClashEchOpts(config, client);
          if (echOpts) {
            proxy["ech-opts"] = echOpts;
          }
        }
        break;
    }

    if (proxy) {
      proxies.push(proxy);
      proxyNames.push(node.name);
    }
  }

  const clashConfig = buildClashTemplate(proxyNames, proxies);

  return yaml.dump(clashConfig);
}

// ---------------- Sing-box 配置（使用模板） ----------------

type SingboxOutbound = Record<string, unknown>;

const SINGBOX_GROUP_MATCHERS: Array<{ tag: string; patterns: RegExp[] }> = [
  { tag: "🇭🇰 香港节点", patterns: [/香港/, /hong\s*kong/i, /\bHK\b/i, /🇭🇰/] },
  { tag: "🇨🇳 台湾节点", patterns: [/台湾/, /台北/, /taiwan/i, /taipei/i, /\bTW\b/i, /🇹🇼/] },
  { tag: "🇸🇬 狮城节点", patterns: [/狮城/, /新加坡/, /singapore/i, /\bSG\b/i, /🇸🇬/] },
  { tag: "🇯🇵 日本节点", patterns: [/日本/, /东京/, /大阪/, /japan/i, /\bJP\b/i, /🇯🇵/] },
  { tag: "🇺🇲 美国节点", patterns: [/美国/, /洛杉矶/, /纽约/, /硅谷/, /united\s*states/i, /\bUSA?\b/i, /🇺🇸|🇺🇲/] },
  { tag: "🇰🇷 韩国节点", patterns: [/韩国/, /首尔/, /korea/i, /\bKR\b/i, /🇰🇷/] },
  { tag: "🎥 奈飞节点", patterns: [/奈飞/, /netflix/i, /\bNF\b/i] }
];

function normalizeAlpn(value: unknown): string[] | undefined {
  if (Array.isArray(value)) {
    const list = value
      .map((item) => ensureString(item).trim())
      .filter(Boolean);
    return list.length ? list : undefined;
  }
  if (typeof value === "string") {
    const list = value
      .split(",")
      .map((item) => item.trim())
      .filter(Boolean);
    return list.length ? list : undefined;
  }
  return undefined;
}

function resolveFirstString(value: unknown): string {
  if (Array.isArray(value) && value.length > 0) {
    return ensureString(value[0], "");
  }
  if (typeof value === "string") return value;
  return "";
}

function resolveOutboundTag(node: any, usedTags: Set<string>): string {
  const fallback = `${ensureString(node.type, "node")}-${ensureString(node.id, "0")}`;
  const rawName = ensureString(node.name, fallback).trim();
  const base = rawName || fallback;
  let tag = base;
  let index = 2;
  while (usedTags.has(tag)) {
    tag = `${base}-${index}`;
    index += 1;
  }
  usedTags.add(tag);
  return tag;
}

function resolveSni(config: any, tlsHost: string, server: string): string {
  return ensureString(config.sni || tlsHost || server, "");
}

function buildSingboxEch(config: any, client: any) {
  const echState = resolveEchState(config, client);
  const echConfig = resolveEchConfig(config, client);
  if (!echState && !echConfig) return null;

  const ech: Record<string, unknown> = { enabled: true };
  if (echConfig) {
    const pemLines = toSingboxPemLines("ECH CONFIGS", echConfig);
    if (pemLines.length) {
      ech.config = pemLines;
    }
  }
  return ech;
}

function buildSingboxTls(config: any, tlsHost: string, server: string, mode: "none" | "tls" | "reality", client?: any) {
  if (mode === "none") return null;
  const tls: Record<string, unknown> = {
    enabled: true,
    server_name: resolveSni(config, tlsHost, server),
    insecure: resolveSkipCertVerify(config, client, false)
  };
  const alpn = normalizeAlpn(config.alpn);
  if (alpn?.length) tls.alpn = alpn;
  if (mode === "tls") {
    const ech = buildSingboxEch(config, client);
    if (ech) tls.ech = ech;
  }

  if (mode === "reality") {
    const serverName = tlsHost || resolveFirstString(config.server_names) || server;
    tls.server_name = serverName;
    const utlsFingerprint = ensureString(config.fingerprint, "chrome");
    tls.utls = { enabled: true, fingerprint: utlsFingerprint };
    const reality: Record<string, unknown> = {
      enabled: true,
      public_key: resolveRealityPublicKey(config, client)
    };
    const shortId = pickRandomShortId(config.short_ids);
    if (shortId) reality.short_id = shortId;
    tls.reality = reality;
  }

  return tls;
}

function applySingboxTransport(outbound: Record<string, unknown>, config: any, server: string, tlsHost: string) {
  const streamType = String(config.stream_type || "tcp").toLowerCase();
  if (streamType === "ws") {
    const host = ensureString(config.server || tlsHost || server, "");
    const transport: Record<string, unknown> = {
      type: "ws",
      path: normalizePath(config.path)
    };
    if (host) transport.headers = { Host: host };
    outbound.transport = transport;
  } else if (streamType === "grpc") {
    outbound.transport = {
      type: "grpc",
      service_name: ensureString(config.service_name, "grpc")
    };
  }
}

function collectSingboxGroups(name: string, tag: string, groups: Record<string, string[]>) {
  if (!name) return;
  for (const matcher of SINGBOX_GROUP_MATCHERS) {
    if (matcher.patterns.some((pattern) => pattern.test(name))) {
      groups[matcher.tag].push(tag);
    }
  }
}

export function generateSingboxConfig(nodes, user): string {
  const nodeOutbounds: SingboxOutbound[] = [];
  const nodeTags: string[] = [];
  const usedTags = new Set<string>();
  const groupMatches: Record<string, string[]> = {};

  for (const matcher of SINGBOX_GROUP_MATCHERS) {
    groupMatches[matcher.tag] = [];
  }

  for (const node of nodes) {
    const { config, server, port, tlsHost, client } = resolveNodeEndpoint(node);
    if (node.type === "vless" && isVlessEncryptionEnabled(config, client)) {
      continue;
    }
    const tag = resolveOutboundTag(node, usedTags);
    const matchName = ensureString(node.name, tag);
    let outbound: SingboxOutbound | null = null;

    switch (node.type) {
      case "ss":
        outbound = {
          type: "shadowsocks",
          tag,
          server,
          server_port: port,
          method: config.cipher || "aes-128-gcm",
          password: buildSS2022Password(config, user.passwd || config.password || "")
        };
        break;

      case "v2ray": {
        const vmess: Record<string, unknown> = {
          type: "vmess",
          tag,
          server,
          server_port: port,
          uuid: user.uuid,
          alter_id: config.aid || 0,
          security: config.security || "auto"
        };
        const tlsMode = config.tls_type === "reality" ? "reality" : config.tls_type === "tls" ? "tls" : "none";
        const tls = buildSingboxTls(config, tlsHost, server, tlsMode, client);
        if (tls) vmess.tls = tls;
        applySingboxTransport(vmess, config, server, tlsHost);
        outbound = vmess;
        break;
      }

      case "vless": {
        const vless: Record<string, unknown> = {
          type: "vless",
          tag,
          server,
          server_port: port,
          uuid: user.uuid
        };
        if (config.flow) vless.flow = config.flow;
        const tlsMode = config.tls_type === "reality" ? "reality" : config.tls_type === "tls" ? "tls" : "none";
        const tls = buildSingboxTls(config, tlsHost, server, tlsMode, client);
        if (tls) vless.tls = tls;
        applySingboxTransport(vless, config, server, tlsHost);
        outbound = vless;
        break;
      }

      case "trojan": {
        const trojan: Record<string, unknown> = {
          type: "trojan",
          tag,
          server,
          server_port: port,
          password: ensureString(user.passwd, "")
        };
        const tlsMode = config.tls_type === "reality" ? "reality" : "tls";
        const tls = buildSingboxTls(config, tlsHost, server, tlsMode, client);
        if (tls) trojan.tls = tls;
        applySingboxTransport(trojan, config, server, tlsHost);
        outbound = trojan;
        break;
      }

      case "hysteria": {
        const hysteria: Record<string, unknown> = {
          type: "hysteria2",
          tag,
          server,
          server_port: port,
          password: ensureString(user.passwd, ""),
          up_mbps: ensureNumber(config.up_mbps, 100),
          down_mbps: ensureNumber(config.down_mbps, 100)
        };
        const tls = buildSingboxTls(config, tlsHost, server, "tls", client);
        if (tls) hysteria.tls = tls;
        if (config.obfs && config.obfs !== "plain") {
          const obfs: Record<string, unknown> = { type: config.obfs };
          if (config.obfs_password) obfs.password = config.obfs_password;
          hysteria.obfs = obfs;
        }
        outbound = hysteria;
        break;
      }

      case "anytls": {
        const anytls: Record<string, unknown> = {
          type: "anytls",
          tag,
          server,
          server_port: port,
          password: ensureString(user.passwd || config.password, "")
        };
        const tls = buildSingboxTls(config, tlsHost, server, "tls", client);
        if (tls) anytls.tls = tls;
        outbound = anytls;
        break;
      }
    }

    if (outbound) {
      nodeOutbounds.push(outbound);
      nodeTags.push(tag);
      collectSingboxGroups(matchName, tag, groupMatches);
    }
  }

  const allRegionTags = SINGBOX_GROUP_MATCHERS.map((matcher) => matcher.tag);
  const availableRegionTags = allRegionTags.filter((tag) => (groupMatches[tag] || []).length > 0);
  const groupOverrides: Record<string, string[]> = {
    "🚀 节点选择": ["🚀 手动切换", ...availableRegionTags, "DIRECT"],
    "🚀 手动切换": nodeTags,
    "GLOBAL": ["DIRECT", ...nodeTags]
  };

  for (const tag of availableRegionTags) {
    const matches = groupMatches[tag] || [];
    if (matches.length) groupOverrides[tag] = matches;
  }

  const singboxConfig = buildSingboxTemplate(nodeOutbounds, groupOverrides, {
    regionTags: allRegionTags,
    availableRegionTags
  });
  return JSON.stringify(singboxConfig, null, 2);
}

/**
 * 生成 Quantumult X 配置
 * @param {Array} nodes - 节点列表
 * @param {Object} user - 用户信息
 * @returns {string} - Quantumult X 格式配置
 */
export function generateQuantumultXConfig(nodes, user) {
  const entries = [];

  for (const node of nodes) {
    const { config, server, port, tlsHost, client } = resolveNodeEndpoint(node);
    if (node.type === "vless" && isVlessEncryptionEnabled(config, client)) {
      continue;
    }
    let line = "";

    switch (node.type) {
      case "v2ray":
        line = buildQuantumultXVmessEntry({ ...node, server, server_port: port, tls_host: tlsHost }, config, user);
        break;
      case "vless":
        line = buildQuantumultXVlessEntry({ ...node, server, server_port: port, tls_host: tlsHost }, config, user, client);
        break;
      case "trojan":
        line = buildQuantumultXTrojanEntry({ ...node, server, server_port: port, tls_host: tlsHost }, config, user);
        break;
      case "ss":
        line = buildQuantumultXSSEntry({ ...node, server, server_port: port, tls_host: tlsHost }, config, user);
        break;
      case "anytls":
        line = buildQuantumultXAnyTLSEntry({ ...node, server, server_port: port, tls_host: tlsHost }, config, user, client);
        break;
      default:
        line = "";
    }

    if (line) {
      entries.push(line);
    }
  }

  return entries.join("\n");
}

function buildQuantumultXSSEntry(node, config, user) {
  const options = [];
  pushOption(options, "method", config.cipher || "aes-128-gcm");
  const ssPassword = buildSS2022Password(config, user.passwd || "");
  pushOption(options, "password", ssPassword);
  pushOption(options, "fast-open", false);
  pushOption(options, "udp-relay", true);

  const obfs = normalizeObfs(config.obfs);
  if (obfs && obfs !== "plain") {
    pushOption(options, "obfs", obfs);
    pushOption(options, "obfs-host", getHeaderHost(node, config));
    pushOption(options, "obfs-uri", normalizePath(config.path));
  }

  pushOption(options, "tag", node.name);
  return formatQuantumultXEntry("shadowsocks", node.server, node.server_port, options);
}

function buildQuantumultXVmessEntry(node, config, user) {
  const streamType = String(config.stream_type || "tcp").toLowerCase();
  if (streamType === "grpc") {
    return "";
  }

  const options = [];
  pushOption(options, "method", "chacha20-poly1305");
  pushOption(options, "password", user.uuid);
  pushOption(options, "fast-open", false);
  pushOption(options, "udp-relay", false);
  if (typeof config.aead === "boolean") {
    pushOption(options, "aead", config.aead);
  }

  applyStreamOptions(options, node, config);
  pushOption(options, "tag", node.name);
  return formatQuantumultXEntry("vmess", node.server, node.server_port, options);
}

function buildQuantumultXVlessEntry(node, config, user, client) {
  const streamType = String(config.stream_type || "tcp").toLowerCase();
  if (streamType === "grpc") {
    return "";
  }

  const options = [];
  pushOption(options, "method", "none");
  pushOption(options, "password", user.uuid);
  pushOption(options, "fast-open", false);
  pushOption(options, "udp-relay", false);

  if (config.tls_type === "reality") {
    pushOption(options, "obfs", "over-tls");
    pushOption(options, "obfs-host", getHeaderHost(node, config));
    pushOption(options, "reality-base64-pubkey", resolveRealityPublicKey(config, client));
    const shortId = pickRandomShortId(config.short_ids);
    if (shortId) {
      pushOption(options, "reality-hex-shortid", shortId);
    }
    if (config.flow) {
      pushOption(options, "vless-flow", config.flow);
    }
  } else {
    applyStreamOptions(options, node, config);
  }
  pushOption(options, "tag", node.name);
  return formatQuantumultXEntry("vless", node.server, node.server_port, options);
}

function buildQuantumultXTrojanEntry(node, config, user) {
  const options = [];
  const streamType = String(config.stream_type || "tcp").toLowerCase();
  if (streamType === "grpc") {
    // Quantumult X 尚不支持 Trojan gRPC，直接跳过避免生成无效节点
    return "";
  }
  const isWebsocket = streamType === "ws";
  const host = getHeaderHost(node, config);

  pushOption(options, "password", user.passwd);
  pushOption(options, "fast-open", false);
  pushOption(options, "tls-verification", false);

  if (isWebsocket) {
    pushOption(options, "obfs", "wss");
    pushOption(options, "obfs-host", host);
    pushOption(options, "obfs-uri", normalizePath(config.path));
    pushOption(options, "udp-relay", true);
  } else {
    pushOption(options, "over-tls", true);
    pushOption(options, "tls-host", host);
    pushOption(options, "udp-relay", false);
  }

  pushOption(options, "tag", node.name);
  return formatQuantumultXEntry("trojan", node.server, node.server_port, options);
}

function buildQuantumultXAnyTLSEntry(node, config, user, client) {
  const options = [];
  pushOption(options, "password", ensureString(user.passwd || config.password, ""));
  pushOption(options, "over-tls", true);
  pushOption(options, "tls-host", getHeaderHost(node, config));

  if (config.tls_type === "reality") {
    const publicKey = resolveRealityPublicKey(config, client);
    if (publicKey) {
      pushOption(options, "reality-base64-pubkey", publicKey);
    }
    const shortId = pickRandomShortId(config.short_ids);
    if (shortId) {
      pushOption(options, "reality-hex-shortid", shortId);
    }
  }

  pushOption(options, "udp-relay", true);
  pushOption(options, "tag", node.name);
  return formatQuantumultXEntry("anytls", node.server, node.server_port, options);
}

function applyStreamOptions(options, node, config) {
  const streamType = String(config.stream_type || "tcp").toLowerCase();
  const isTLS = config.tls_type === "tls";
  const host = getHeaderHost(node, config);

  if (streamType === "ws") {
    pushOption(options, "obfs", isTLS ? "wss" : "ws");
    pushOption(options, "obfs-host", host);
    pushOption(options, "obfs-uri", normalizePath(config.path));
  } else if (streamType === "http") {
    pushOption(options, "obfs", "http");
    pushOption(options, "obfs-host", host);
    pushOption(options, "obfs-uri", normalizePath(config.path));
  } else if (isTLS) {
    pushOption(options, "obfs", "over-tls");
    pushOption(options, "obfs-host", host);
  }
}

function getHeaderHost(node, config) {
  return node.tls_host || config.sni || config.host || config.server || node.server;
}

function normalizePath(path) {
  if (!path || typeof path !== "string") return "/";
  return path.startsWith("/") ? path : `/${path}`;
}

function normalizeObfs(obfs) {
  if (!obfs) return "";
  const value = String(obfs);
  const lower = value.toLowerCase();
  if (lower === "simple_obfs_http") return "http";
  if (lower === "simple_obfs_tls") return "tls";
  return value;
}

function pushOption(options, key, value) {
  if (value === undefined || value === null || value === "") {
    return;
  }
  if (typeof value === "boolean") {
    options.push(`${key}=${value ? "true" : "false"}`);
  } else {
    options.push(`${key}=${value}`);
  }
}

function formatQuantumultXEntry(protocol, server, port, options) {
  const endpoint = `${formatHostForUrl(server)}:${port}`;
  return options.length ? `${protocol}=${endpoint}, ${options.join(", ")}` : `${protocol}=${endpoint}`;
}

function formatHostForUrl(host) {
  if (!host) return "";
  const value = String(host).trim();
  if (value.includes(":") && !value.startsWith("[") && !value.endsWith("]")) {
    return `[${value}]`;
  }
  return value;
}

/**
 * 生成 Shadowrocket 配置
 * @param {Array} nodes - 节点列表
 * @param {Object} user - 用户信息
 * @returns {string} - Shadowrocket 格式配置
 */
export function generateShadowrocketConfig(nodes, user) {
  const links = [];

  for (const node of nodes) {
    const { config, server, port, tlsHost, client } = resolveNodeEndpoint(node);
    const nodeResolved = { ...node, server, server_port: port, tls_host: tlsHost };

    switch (nodeResolved.type) {
      case "v2ray":
        links.push(generateVmessLink(nodeResolved, config, user, client));
        break;
      case "vless":
        links.push(generateVlessLink(nodeResolved, config, user, client));
        break;
      case "trojan":
        links.push(generateTrojanLink(nodeResolved, config, user, client));
        break;
      case "ss":
        links.push(generateShadowsocksLink(nodeResolved, config, user));
        break;
      case "hysteria":
        links.push(generateHysteriaLink(nodeResolved, config, user, client));
        break;
    }
  }

  return links.join("\n");
}

/**
 * 生成 Surge 配置
 * @param {Array} nodes - 节点列表
 * @param {Object} user - 用户信息
 * @returns {string} - Surge 格式配置
 */
export function generateSurgeConfig(nodes, user) {
  const proxies = [];
  const proxyNames = [];

  for (const node of nodes) {
    const { config, server, port, tlsHost, client } = resolveNodeEndpoint(node);
    const nodeType = ensureString(node.type, "").toLowerCase();
    if (nodeType === "vless" && isVlessEncryptionEnabled(config, client)) {
      continue;
    }
    let proxy = "";

    switch (nodeType) {
      case "v2ray":
      case "vless":
        proxy = `${node.name} = vmess, ${server}, ${port}, username=${user.uuid}`;
        if (config.tls_type === "tls" || config.tls_type === "reality") {
          proxy += ", tls=true";
          if (resolveSkipCertVerify(config, client, false)) {
            proxy += ", skip-cert-verify=true";
          }
          if (tlsHost || config.sni) proxy += `, sni=${tlsHost || config.sni}`;
        }
        if (config.stream_type === "ws") {
          proxy += `, ws=true, ws-path=${config.path || "/"}`;
          if (config.server || tlsHost) proxy += `, ws-headers=Host:${config.server || tlsHost}`;
        }
        break;

      case "trojan":
        proxy = `${node.name} = trojan, ${server}, ${port}, password=${user.passwd}`;
        proxy += ", tls=true";
        if (resolveSkipCertVerify(config, client, false)) {
          proxy += ", skip-cert-verify=true";
        }
        if (tlsHost || config.sni) proxy += `, sni=${tlsHost || config.sni}`;
        break;

      case "ss":
        const ssPassword = buildSS2022Password(config, user.passwd || "");
        proxy = `${node.name} = ss, ${server}, ${port}, encrypt-method=${config.cipher || "aes-128-gcm"}, password=${ssPassword}`;
        if (config.obfs && config.obfs !== "plain") {
          const obfsMode = config.obfs === "simple_obfs_http" ? "http" : "tls";
          proxy += `, obfs=${obfsMode}`;
          if (config.server || tlsHost) proxy += `, obfs-host=${config.server || tlsHost}`;
        }
        break;

      case "hysteria":
        proxy = `${node.name} = hysteria2, ${server}, ${port}, password=${user.passwd}`;
        if (resolveSkipCertVerify(config, client, false)) {
          proxy += ", skip-cert-verify=true";
        }
        if (tlsHost || config.sni) proxy += `, sni=${tlsHost || config.sni}`;
        break;

      case "anytls":
        proxy = `${node.name} = anytls, ${server}, ${port}, password=${ensureString(user.passwd || config.password, "")}`;
        if (resolveSkipCertVerify(config, client, false)) {
          proxy += ", skip-cert-verify=true";
        }
        if (tlsHost || config.sni) proxy += `, sni=${tlsHost || config.sni}`;
        break;
    }

    if (proxy) {
      proxies.push(proxy);
      proxyNames.push(node.name);
    }
  }

  return buildSurgeTemplate(proxies, proxyNames);
}

// 简单的 YAML 转换函数（用于 Clash 配置）
const yaml = {
  dump: function (obj) {
    return this._stringify(obj, 0);
  },

  _stringify: function (obj, indent) {
    const spaces = "  ".repeat(indent);
    let result = "";

    if (Array.isArray(obj)) {
      obj.forEach((item) => {
        if (this._isObject(item)) {
          const entries = Object.entries(item);
          if (entries.length === 0) {
            result += `${spaces}- {}\n`;
            return;
          }

          entries.forEach(([key, value], index) => {
            if (index === 0) {
              if (Array.isArray(value) || this._isObject(value)) {
                result += `${spaces}- ${key}:\n`;
                result += this._stringify(value, indent + 2);
              } else {
                result += `${spaces}- ${key}: ${this._formatScalar(value)}\n`;
              }
            } else {
              result += this._stringifyPair(key, value, indent + 1);
            }
          });
        } else {
          result += `${spaces}- ${this._formatScalar(item)}\n`;
        }
      });
    } else if (this._isObject(obj)) {
      Object.entries(obj).forEach(([key, value]) => {
        result += this._stringifyPair(key, value, indent);
      });
    }

    return result;
  },

  _stringifyPair: function (key, value, indent) {
    const spaces = "  ".repeat(indent);
    if (Array.isArray(value)) {
      if (value.length === 0) return `${spaces}${key}: []\n`;
      return `${spaces}${key}:\n${this._stringify(value, indent + 1)}`;
    }
    if (this._isObject(value)) {
      if (Object.keys(value).length === 0) return `${spaces}${key}: {}\n`;
      return `${spaces}${key}:\n${this._stringify(value, indent + 1)}`;
    }
    return `${spaces}${key}: ${this._formatScalar(value)}\n`;
  },

  _isObject: function (value) {
    return typeof value === "object" && value !== null && !Array.isArray(value);
  },

  _formatScalar: function (value) {
    if (value === null || value === undefined) return "null";
    if (typeof value === "number" || typeof value === "boolean") return String(value);
    if (typeof value !== "string") return JSON.stringify(value);

    if (value === "") return "\"\"";
    if (/^[\w\-./]+$/.test(value)) return value;
    return JSON.stringify(value);
  },
};
