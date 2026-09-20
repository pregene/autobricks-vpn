import fs from "node:fs";
import path from "node:path";

function sectionBounds(lines, section) {
  const header = `[${section}]`;
  const start = lines.findIndex((line) => line.trim().toLowerCase() === header);
  if (start < 0) return { start: -1, end: -1 };
  const next = lines.findIndex((line, index) => index > start && /^\s*\[[^\]]+\]\s*$/.test(line));
  return { start, end: next < 0 ? lines.length : next };
}

function parseSection(text, section) {
  const lines = text.split(/\r?\n/);
  const { start, end } = sectionBounds(lines, section);
  if (start < 0) return [];
  return lines.slice(start + 1, end).flatMap((line) => {
    const content = line.trim();
    if (!content || content.startsWith("#") || content.startsWith(";")) return [];
    const separator = content.indexOf("=");
    return separator < 0 ? [] : [[content.slice(0, separator).trim(), content.slice(separator + 1).trim()]];
  });
}

export function readServerSettings(configPath) {
  const entries = new Map(parseSection(fs.readFileSync(configPath, "utf8"), "server"));
  const port = Number.parseInt(entries.get("port") ?? "4433", 10);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error("server.ini contains an invalid port");
  return {
    listenAddress: entries.get("listen_address") ?? "0.0.0.0",
    port,
    controlSocket: entries.get("control_socket") ?? "/var/run/autobricks-vpn.sock",
    vpnAddress: entries.get("vpn_address") ?? "10.8.1.1",
    vpnNetwork: entries.get("vpn_network") ?? "10.8.1.0/24",
    mtu: Number.parseInt(entries.get("mtu") ?? "1200", 10),
    ...(entries.has("certificate_file") && { certificateFile: entries.get("certificate_file") }),
    ...(entries.has("root_ca_file") && { rootCaFile: entries.get("root_ca_file") }),
    ...(entries.has("intermediate_ca_file") && { intermediateCaFile: entries.get("intermediate_ca_file") }),
    ...(entries.has("intermediate_ca_key_file") && { intermediateCaKeyFile: entries.get("intermediate_ca_key_file") }),
    ...(entries.has("public_address") && { publicAddress: entries.get("public_address") }),
  };
}

function ipv4Number(value) {
  if (typeof value !== "string" || !/^(?:\d{1,3}\.){3}\d{1,3}$/.test(value)) return null;
  const parts = value.split(".").map(Number);
  if (parts.some((part) => part > 255)) return null;
  return parts.reduce((number, part) => (number * 256 + part) >>> 0, 0);
}

export function validateClientAddress(value, settings) {
  const [network, prefixText] = settings.vpnNetwork.split("/");
  const prefix = Number(prefixText);
  const addressNumber = ipv4Number(value);
  const networkNumber = ipv4Number(network);
  const mask = prefix >= 0 && prefix <= 32 ? (0xffffffff << (32 - prefix)) >>> 0 : null;
  const subnet = mask === null || networkNumber === null ? null : (networkNumber & mask) >>> 0;
  if (addressNumber === null || subnet === null || (addressNumber & mask) >>> 0 !== subnet ||
      addressNumber === subnet || addressNumber === (subnet | ~mask) >>> 0 || value === settings.vpnAddress) {
    throw Object.assign(new Error(`vpnAddress must be a client address in ${settings.vpnNetwork}.`), { status: 400, code: "invalid_vpn_address" });
  }
  return value;
}

function validateFingerprint(value) {
  const normalized = typeof value === "string" ? value.replaceAll(":", "").toLowerCase() : "";
  if (!/^[0-9a-f]{64}$/.test(normalized)) {
    throw Object.assign(new Error("fingerprint must contain 64 SHA-256 hexadecimal digits."), { status: 400, code: "invalid_fingerprint" });
  }
  return normalized;
}

export class ServerConfig {
  constructor(configPath) {
    this.configPath = configPath;
  }

  listClients() {
    return this.#readClients().map(({ vpnAddress, fingerprint, loginId }) => ({
      vpnAddress, fingerprint, ...(loginId && { loginId, requiresLogin: true }),
    }));
  }

  #readClients() {
    return parseSection(fs.readFileSync(this.configPath, "utf8"), "client").map(([vpnAddress, value]) => {
      const [fingerprint, loginId, password] = value.split(/\s+/);
      return { vpnAddress, fingerprint: fingerprint.replaceAll(":", "").toLowerCase(), loginId, password };
    });
  }

  saveClient(input = {}) {
    const vpnAddress = validateClientAddress(input.vpnAddress, readServerSettings(this.configPath));
    const fingerprint = validateFingerprint(input.fingerprint);
    const clients = this.#readClients();
    if (clients.some((client) => client.fingerprint === fingerprint && client.vpnAddress !== vpnAddress)) {
      throw Object.assign(new Error("fingerprint is already assigned to another VPN address."), { status: 409, code: "fingerprint_exists" });
    }
    const loginId = input.loginId == null ? "" : String(input.loginId).trim();
    const password = input.password == null ? "" : String(input.password);
    if (Boolean(loginId) !== Boolean(password) || (loginId && !/^[A-Za-z0-9_.@-]{1,64}$/.test(loginId)) || (password && (!/^[^\s#]{1,128}$/.test(password)))) {
      throw Object.assign(new Error("ID와 암호를 함께 입력하세요. 공백과 #은 사용할 수 없습니다."), { status: 400, code: "invalid_login" });
    }
    const updated = clients.filter((client) => client.vpnAddress !== vpnAddress);
    updated.push({ vpnAddress, fingerprint, loginId, password });
    this.#writeClients(updated);
    return { vpnAddress, fingerprint, ...(loginId && { loginId, requiresLogin: true }) };
  }

  removeClient(vpnAddress) {
    validateClientAddress(vpnAddress, readServerSettings(this.configPath));
    const clients = this.#readClients();
    const updated = clients.filter((client) => client.vpnAddress !== vpnAddress);
    if (updated.length === clients.length) {
      throw Object.assign(new Error("client binding was not found."), { status: 404, code: "client_not_found" });
    }
    this.#writeClients(updated);
  }

  #writeClients(clients) {
    const text = fs.readFileSync(this.configPath, "utf8");
    const lines = text.split(/\r?\n/);
    const bounds = sectionBounds(lines, "client");
    const body = ["# Managed by Autobricks VPN Web. The VPN server reloads this section.", ...clients
      .sort((left, right) => left.vpnAddress.localeCompare(right.vpnAddress, undefined, { numeric: true }))
      .map((client) => `${client.vpnAddress} = ${client.fingerprint}${client.loginId ? ` ${client.loginId} ${client.password}` : ""}`)];
    const output = bounds.start < 0
      ? [...lines, "", "[client]", ...body]
      : [...lines.slice(0, bounds.start + 1), ...body, ...lines.slice(bounds.end)];
    const temporary = path.join(path.dirname(this.configPath), `.${path.basename(this.configPath)}.${process.pid}.tmp`);
    const mode = fs.statSync(this.configPath).mode;
    fs.writeFileSync(temporary, `${output.join("\n").replace(/\n+$/, "")}\n`, { mode });
    fs.renameSync(temporary, this.configPath);
  }
}
