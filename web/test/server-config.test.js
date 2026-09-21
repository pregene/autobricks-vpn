import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { readServerSettings, ServerConfig } from "../src/server-config.js";

const SAMPLE = `[server]
listen_address = 0.0.0.0
port = 4433

[client]
10.8.1.2 = ${"a".repeat(64)}
`;

test("reads only the TCP port setting needed by the local web listener", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "autobricks-web-test-"));
  const configPath = path.join(directory, "server.ini");
  fs.writeFileSync(configPath, SAMPLE);
  try {
    assert.deepEqual(readServerSettings(configPath), {
      listenAddress: "0.0.0.0",
      port: 4433,
      controlSocket: "/var/run/autobricks-vpn.sock",
      vpnAddress: "10.8.1.1",
      vpnNetwork: "10.8.1.0/24",
      mtu: 1200,
      issuedClientVerifyServerSanIp: true,
    });
  } finally {
    fs.rmSync(directory, { recursive: true });
  }
});

test("reads the explicit SAN verification policy for issued clients", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "autobricks-web-test-"));
  const configPath = path.join(directory, "server.ini");
  fs.writeFileSync(configPath, SAMPLE.replace("port = 4433", "port = 4433\nissued_client_verify_server_san_ip = false"));
  try {
    assert.equal(readServerSettings(configPath).issuedClientVerifyServerSanIp, false);
  } finally {
    fs.rmSync(directory, { recursive: true });
  }
});

test("adds and removes client bindings without changing the server section", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "autobricks-web-test-"));
  const configPath = path.join(directory, "server.ini");
  fs.writeFileSync(configPath, SAMPLE);
  const config = new ServerConfig(configPath);
  try {
    config.saveClient({ vpnAddress: "10.8.1.3", fingerprint: "BB:".repeat(31) + "BB" });
    assert.equal(config.listClients().length, 2);
    assert.equal(config.listClients()[1].fingerprint, "b".repeat(64));
    assert.match(fs.readFileSync(configPath, "utf8"), /port = 4433/);

    config.removeClient("10.8.1.2");
    assert.deepEqual(config.listClients(), [{ vpnAddress: "10.8.1.3", fingerprint: "b".repeat(64) }]);
  } finally {
    fs.rmSync(directory, { recursive: true });
  }
});

test("uses the configured VPN network for client addresses", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "autobricks-web-test-"));
  const configPath = path.join(directory, "server.ini");
  fs.writeFileSync(configPath, SAMPLE.replace("port = 4433", "port = 4433\nvpn_address = 10.9.1.1\nvpn_network = 10.9.1.0/24"));
  const config = new ServerConfig(configPath);
  try {
    config.saveClient({ vpnAddress: "10.9.1.4", fingerprint: "b".repeat(64) });
    assert.equal(config.listClients().at(-1).vpnAddress, "10.9.1.4");
    assert.throws(() => config.saveClient({ vpnAddress: "10.8.1.4", fingerprint: "c".repeat(64) }), /10.9.1.0\/24/);
  } finally {
    fs.rmSync(directory, { recursive: true });
  }
});

test("stores optional login only on the server and preserves it during other edits", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "autobricks-web-test-"));
  const configPath = path.join(directory, "server.ini");
  fs.writeFileSync(configPath, SAMPLE);
  const config = new ServerConfig(configPath);
  try {
    config.saveClient({ vpnAddress: "10.8.1.3", fingerprint: "b".repeat(64), loginId: "alice", password: "secret123" });
    assert.deepEqual(config.listClients().at(-1), { vpnAddress: "10.8.1.3", fingerprint: "b".repeat(64), loginId: "alice", requiresLogin: true });
    assert.match(fs.readFileSync(configPath, "utf8"), new RegExp(`${"b".repeat(64)} alice secret123`));
    config.removeClient("10.8.1.2");
    assert.match(fs.readFileSync(configPath, "utf8"), /alice secret123/);
    assert.throws(() => config.saveClient({ vpnAddress: "10.8.1.4", fingerprint: "c".repeat(64), loginId: "bob" }), /함께/);
  } finally {
    fs.rmSync(directory, { recursive: true });
  }
});
