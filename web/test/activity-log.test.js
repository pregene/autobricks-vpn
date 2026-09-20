import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { ActivityLog } from "../src/activity-log.js";

test("records VPN start, client transitions, and stop in newest-first order", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "autobricks-activity-"));
  const socketPath = path.join(directory, "control.sock");
  fs.writeFileSync(socketPath, "");
  const callbacks = {};
  const control = {
    socketPath,
    watch(onMessage, _onError, onClose) {
      callbacks.message = onMessage;
      callbacks.close = onClose;
      return { destroy() {} };
    },
  };
  const filePath = path.join(directory, "data", "activity.json");
  const log = new ActivityLog(control, filePath);
  try {
    log.start();
    callbacks.message({ type: "sessions", sessions: [] });
    callbacks.message({ type: "sessions", sessions: [{ vpnAddress: "10.9.1.2", fingerprint: "abc", clientIp: "192.0.2.2" }] });
    callbacks.message({ type: "sessions", sessions: [] });
    callbacks.close();
    assert.deepEqual(log.list().map((entry) => entry.type), [
      "server_stopped", "client_disconnected", "client_connected", "server_started",
    ]);
    assert.equal(log.list()[2].clientIp, "192.0.2.2");
    assert.equal(new ActivityLog(control, filePath).list().length, 4);
  } finally {
    log.stop();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("keeps only the newest 100 events", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "autobricks-activity-"));
  const socketPath = path.join(directory, "control.sock");
  fs.writeFileSync(socketPath, "");
  let send;
  const control = {
    socketPath,
    watch(onMessage) {
      send = onMessage;
      return { destroy() {} };
    },
  };
  const log = new ActivityLog(control, path.join(directory, "activity.json"));
  try {
    log.start();
    send({ type: "sessions", sessions: [] });
    for (let index = 0; index < 110; index += 1) {
      send({ type: "sessions", sessions: [{ vpnAddress: `10.9.1.${index + 2}` }] });
      send({ type: "sessions", sessions: [] });
    }
    assert.equal(log.list().length, 100);
    assert.equal(log.list()[0].type, "client_disconnected");
  } finally {
    log.stop();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
