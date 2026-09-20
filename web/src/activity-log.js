import fs from "node:fs";
import path from "node:path";
import { randomUUID } from "node:crypto";

const MAX_ENTRIES = 100;

export class ActivityLog {
  constructor(vpnControl, filePath) {
    this.vpnControl = vpnControl;
    this.filePath = filePath;
    this.listeners = new Set();
    this.entries = [];
    this.serverId = null;
    this.sessions = null;
    this.connected = false;
    this.stopping = false;
    this.socket = null;
    this.retryTimer = null;
    try {
      const saved = JSON.parse(fs.readFileSync(filePath, "utf8"));
      this.entries = Array.isArray(saved.entries) ? saved.entries.slice(0, MAX_ENTRIES) : [];
      this.serverId = saved.serverId ?? null;
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
    }
  }

  list() {
    return [...this.entries];
  }

  subscribe(listener) {
    this.listeners.add(listener);
    listener(this.list());
    return () => this.listeners.delete(listener);
  }

  start() {
    this.stopping = false;
    this.#connect();
  }

  stop() {
    this.stopping = true;
    clearTimeout(this.retryTimer);
    this.socket?.destroy();
  }

  #record(type, details = {}, occurredAt = new Date().toISOString()) {
    this.entries.unshift({ id: randomUUID(), type, occurredAt, ...details });
    this.entries.sort((left, right) => right.occurredAt.localeCompare(left.occurredAt));
    this.entries.length = Math.min(this.entries.length, MAX_ENTRIES);
    fs.mkdirSync(path.dirname(this.filePath), { recursive: true, mode: 0o700 });
    const temporary = `${this.filePath}.${process.pid}.tmp`;
    fs.writeFileSync(temporary, JSON.stringify({ serverId: this.serverId, entries: this.entries }), { mode: 0o600 });
    fs.renameSync(temporary, this.filePath);
    for (const listener of this.listeners) listener(this.list());
  }

  #connect() {
    if (this.stopping) return;
    this.socket = this.vpnControl.watch(
      (message) => this.#handleMessage(message),
      (error) => console.error("[web] VPN activity watcher:", error.message),
      () => this.#handleClose(),
    );
  }

  #handleMessage(message) {
    if (message.type !== "sessions" || !Array.isArray(message.sessions)) return;
    if (!this.connected) {
      this.connected = true;
      this.sessions = new Map(message.sessions.map((session) => [session.vpnAddress, session]));
      try {
        const socket = fs.statSync(this.vpnControl.socketPath);
        const serverId = `${socket.dev}:${socket.ino}:${socket.birthtimeMs}`;
        if (serverId !== this.serverId) {
          this.serverId = serverId;
          this.#record("server_started", {}, socket.birthtime.toISOString());
        }
      } catch (error) {
        console.error("[web] unable to identify VPN server start:", error.message);
      }
      return;
    }
    const next = new Map(message.sessions.map((session) => [session.vpnAddress, session]));
    for (const [vpnAddress, session] of next) {
      if (!this.sessions.has(vpnAddress)) {
        this.#record("client_connected", { vpnAddress, fingerprint: session.fingerprint, clientIp: session.clientIp ?? null });
      }
    }
    for (const [vpnAddress, session] of this.sessions) {
      if (!next.has(vpnAddress)) {
        this.#record("client_disconnected", { vpnAddress, fingerprint: session.fingerprint, clientIp: session.clientIp ?? null });
      }
    }
    this.sessions = next;
  }

  #handleClose() {
    if (this.stopping) return;
    if (this.connected) {
      for (const [vpnAddress, session] of this.sessions) {
        this.#record("client_disconnected", { vpnAddress, fingerprint: session.fingerprint, clientIp: session.clientIp ?? null });
      }
      this.#record("server_stopped");
    }
    this.connected = false;
    this.sessions = null;
    this.retryTimer = setTimeout(() => this.#connect(), 1000);
    this.retryTimer.unref?.();
  }
}
