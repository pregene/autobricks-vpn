import { createApp } from "./app.js";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { readServerSettings, ServerConfig } from "./server-config.js";
import { VpnControl } from "./vpn-control.js";

const currentDirectory = path.dirname(fileURLToPath(import.meta.url));
const configPath = path.resolve(process.env.VPN_CONFIG ?? path.join(currentDirectory, "../../server.ini"));
const settings = readServerSettings(configPath);
const host = "127.0.0.1";
const port = settings.port;

if (!Number.isInteger(port) || port < 1 || port > 65535) {
  throw new Error("WEB_PORT must be an integer between 1 and 65535");
}

const server = createApp({
  clientRegistry: new ServerConfig(configPath),
  vpnControl: new VpnControl(settings.controlSocket),
}).listen(port, host, () => {
  console.log(`[web] Autobricks VPN dashboard listening on TCP http://${host}:${port}`);
  console.log(`[web] VPN configuration: ${configPath}`);
});

function shutdown(signal) {
  console.log(`[web] ${signal} received; shutting down`);
  server.close((error) => {
    if (error) {
      console.error("[web] shutdown failed", error);
      process.exitCode = 1;
    }
  });
}

process.on("SIGINT", () => shutdown("SIGINT"));
process.on("SIGTERM", () => shutdown("SIGTERM"));
