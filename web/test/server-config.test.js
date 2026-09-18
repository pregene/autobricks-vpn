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
    });
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
