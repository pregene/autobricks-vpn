import express from "express";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { PkiError, PkiService } from "./pki-service.js";

const currentDirectory = path.dirname(fileURLToPath(import.meta.url));
const publicDirectory = path.resolve(currentDirectory, "../public");

export function createApp({ startedAt = new Date(), pkiService = new PkiService(), clientRegistry, vpnControl } = {}) {
  const app = express();

  app.disable("x-powered-by");
  app.use(express.json({ limit: "32kb" }));

  app.get("/api/health", (_request, response) => {
    response.json({
      status: "ok",
      service: "autobricks-vpn-web",
      uptimeSeconds: Math.floor((Date.now() - startedAt.getTime()) / 1000),
      timestamp: new Date().toISOString(),
    });
  });

  app.get("/api/status", (_request, response) => {
    response.json({
      web: {
        state: "online",
        startedAt: startedAt.toISOString(),
      },
      vpn: {
        state: "integration_pending",
        message: "VPN server status provider is not connected yet.",
      },
    });
  });

  app.get("/api/pki", (_request, response) => {
    response.json({
      capabilities: pkiService.capabilities(),
      ...pkiService.list(),
    });
  });

  app.post("/api/pki/server-certificates", (request, response) => {
    const certificate = pkiService.registerServerCertificate(request.body);
    response.status(201).json({ certificate });
  });

  app.post("/api/pki/client-certificates", (request, response) => {
    const certificateRequest = pkiService.requestClientCertificate(request.body);
    response.status(202).json({ request: certificateRequest });
  });

  app.get("/api/clients", (_request, response) => {
    response.json({ clients: clientRegistry?.listClients() ?? [] });
  });

  app.put("/api/clients/:vpnAddress", (request, response) => {
    if (!clientRegistry) return response.status(503).json({ error: "server_config_not_connected" });
    const client = clientRegistry.saveClient({ ...request.body, vpnAddress: request.params.vpnAddress });
    response.json({ client });
  });

  app.delete("/api/clients/:vpnAddress", (request, response) => {
    if (!clientRegistry) return response.status(503).json({ error: "server_config_not_connected" });
    clientRegistry.removeClient(request.params.vpnAddress);
    response.status(204).end();
  });

  app.get("/api/vpn/events", (request, response) => {
    if (!vpnControl) return response.status(503).json({ error: "vpn_control_not_connected" });
    response.set({
      "content-type": "text/event-stream",
      "cache-control": "no-cache, no-transform",
      connection: "keep-alive",
    });
    response.flushHeaders();
    const socket = vpnControl.watch(
      (message) => response.write(`event: ${message.type ?? "message"}\ndata: ${JSON.stringify(message)}\n\n`),
      (error) => {
        if (!response.writableEnded) {
          response.write(`event: unavailable\ndata: ${JSON.stringify({ message: error.message })}\n\n`);
          response.end();
        }
      },
    );
    request.on("close", () => socket.destroy());
  });

  app.delete("/api/vpn/sessions/:vpnAddress", async (request, response, next) => {
    if (!vpnControl) return response.status(503).json({ error: "vpn_control_not_connected" });
    try {
      const result = await vpnControl.command(`DISCONNECT ${request.params.vpnAddress}`);
      response.status(result.disconnected > 0 ? 200 : 404).json(result);
    } catch (error) {
      next(Object.assign(error, { status: 503, code: "vpn_control_unavailable" }));
    }
  });

  app.use(express.static(publicDirectory, {
    etag: true,
    maxAge: "1h",
  }));

  app.use((_request, response) => {
    response.status(404).json({ error: "not_found" });
  });

  app.use((error, _request, response, _next) => {
    if (error instanceof PkiError) {
      response.status(error.status).json({ error: error.code, message: error.message });
      return;
    }
    if (Number.isInteger(error.status) && error.code) {
      response.status(error.status).json({ error: error.code, message: error.message });
      return;
    }
    console.error("[web] request failed", error);
    response.status(500).json({ error: "internal_server_error" });
  });

  return app;
}
