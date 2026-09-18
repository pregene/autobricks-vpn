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
  };
}

function validateAddress(value) {
  if (typeof value !== "string" || !/^10\.8\.1\.(?:[2-9]|[1-9]\d|1\d\d|2[0-4]\d|25[0-4])$/.test(value)) {
    throw Object.assign(new Error("vpnAddress must be in 10.8.1.2-10.8.1.254."), { status: 400, code: "invalid_vpn_address" });
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
    return parseSection(fs.readFileSync(this.configPath, "utf8"), "client").map(([vpnAddress, fingerprint]) => ({
      vpnAddress,
      fingerprint: fingerprint.replaceAll(":", "").toLowerCase(),
    }));
  }

  saveClient(input = {}) {
    const vpnAddress = validateAddress(input.vpnAddress);
    const fingerprint = validateFingerprint(input.fingerprint);
    const clients = this.listClients();
    if (clients.some((client) => client.fingerprint === fingerprint && client.vpnAddress !== vpnAddress)) {
      throw Object.assign(new Error("fingerprint is already assigned to another VPN address."), { status: 409, code: "fingerprint_exists" });
    }
    const updated = clients.filter((client) => client.vpnAddress !== vpnAddress);
    updated.push({ vpnAddress, fingerprint });
    this.#writeClients(updated);
    return { vpnAddress, fingerprint };
  }

  removeClient(vpnAddress) {
    validateAddress(vpnAddress);
    const clients = this.listClients();
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
      .map((client) => `${client.vpnAddress} = ${client.fingerprint}`)];
    const output = bounds.start < 0
      ? [...lines, "", "[client]", ...body]
      : [...lines.slice(0, bounds.start + 1), ...body, ...lines.slice(bounds.end)];
    const temporary = path.join(path.dirname(this.configPath), `.${path.basename(this.configPath)}.${process.pid}.tmp`);
    const mode = fs.statSync(this.configPath).mode;
    fs.writeFileSync(temporary, `${output.join("\n").replace(/\n+$/, "")}\n`, { mode });
    fs.renameSync(temporary, this.configPath);
  }
}
