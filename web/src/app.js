import express from "express";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { PkiError, PkiService } from "./pki-service.js";

const currentDirectory = path.dirname(fileURLToPath(import.meta.url));
const publicDirectory = path.resolve(currentDirectory, "../public");

export function createApp({ startedAt = new Date(), pkiService = new PkiService(), clientRegistry, clientIssuer, vpnControl, serverSettings, activityLog } = {}) {
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

  app.get("/api/status", async (_request, response) => {
    let vpn;
    try {
      if (!vpnControl) throw new Error("VPN control socket is not configured");
      const snapshot = await vpnControl.command("STATUS");
      if (snapshot.type !== "sessions" || !Array.isArray(snapshot.sessions)) {
        throw new Error("VPN server returned an invalid status response");
      }
      vpn = { state: "online", message: "VPN 서버 제어 소켓 연결됨", sessions: snapshot.sessions };
    } catch (error) {
      vpn = { state: "unavailable", message: `VPN 서버 상태를 읽을 수 없습니다: ${error.message}`, sessions: [] };
    }
    response.json({
      web: {
        state: "online",
        startedAt: startedAt.toISOString(),
      },
      vpn,
      server: serverSettings ? { listenAddress: serverSettings.listenAddress, port: serverSettings.port, controlSocket: serverSettings.controlSocket, vpnAddress: serverSettings.vpnAddress, vpnNetwork: serverSettings.vpnNetwork, mtu: serverSettings.mtu } : null,
      clients: clientRegistry?.listClients() ?? [],
    });
  });

  app.get("/api/activity", (_request, response) => {
    response.json({ entries: activityLog?.list() ?? [] });
  });

  app.get("/api/activity/events", (request, response) => {
    if (!activityLog) return response.status(503).json({ error: "activity_log_not_connected" });
    response.set({
      "content-type": "text/event-stream",
      "cache-control": "no-cache, no-transform",
      connection: "keep-alive",
    });
    response.flushHeaders();
    const unsubscribe = activityLog.subscribe((entries) => {
      response.write(`event: activity\ndata: ${JSON.stringify({ entries })}\n\n`);
    });
    request.on("close", unsubscribe);
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

  app.post("/api/clients/issue", async (request, response, next) => {
    if (!clientRegistry || !clientIssuer || !vpnControl) return response.status(503).json({ error: "signer_not_configured" });
    try {
      const ready = await vpnControl.command("RELOAD");
      if (!ready.ok) throw Object.assign(new Error("VPN 서버를 새 바이너리로 다시 시작해야 발급할 수 있습니다."), { status: 503, code: "vpn_reload_unavailable" });
      if (clientRegistry.listClients().some((client) => client.vpnAddress === request.body?.vpnAddress)) {
        throw Object.assign(new Error("이미 등록된 VPN 주소입니다."), { status: 409, code: "client_exists" });
      }
      const issued = clientIssuer.issue(request.body);
      clientRegistry.saveClient({ ...issued, loginId: request.body.loginId, password: request.body.password });
      try {
        const result = await vpnControl.command("RELOAD");
        if (!result.ok) throw new Error("VPN 서버가 설정 갱신을 거부했습니다.");
      } catch (error) {
        clientRegistry.removeClient(issued.vpnAddress);
        throw Object.assign(new Error(`발급한 클라이언트를 등록할 수 없습니다: ${error.message}`), { status: 503, code: "vpn_reload_failed" });
      }
      response.set({ "content-type": "application/octet-stream", "content-disposition": `attachment; filename="${issued.filename}"`, "cache-control": "no-store" });
      response.send(issued.content);
    } catch (error) { next(error); }
  });

  app.put("/api/clients/:vpnAddress", (request, response) => {
    if (!clientRegistry) return response.status(503).json({ error: "server_config_not_connected" });
    const client = clientRegistry.saveClient({ ...request.body, vpnAddress: request.params.vpnAddress });
    response.json({ client });
  });

  app.delete("/api/clients/:vpnAddress", async (request, response, next) => {
    if (!clientRegistry || !vpnControl) return response.status(503).json({ error: "vpn_control_not_connected" });
    try {
      const ready = await vpnControl.command("RELOAD").catch((error) => {
        throw Object.assign(new Error(`VPN 서버를 새 바이너리로 다시 시작한 뒤 삭제할 수 있습니다: ${error.message}`), {
          status: 503, code: "vpn_reload_unavailable",
        });
      });
      if (!ready.ok) {
        throw Object.assign(new Error("VPN 서버를 새 바이너리로 다시 시작한 뒤 삭제할 수 있습니다."), {
          status: 503, code: "vpn_reload_unavailable",
        });
      }
      clientRegistry.removeClient(request.params.vpnAddress);
      const result = await vpnControl.command("RELOAD").catch((error) => {
        throw Object.assign(new Error(`Client registration was removed, but VPN server reload failed: ${error.message}`), {
          status: 503, code: "vpn_reload_failed",
        });
      });
      if (!result.ok) {
        throw Object.assign(new Error("Client registration was removed, but VPN server reload failed."), {
          status: 503, code: "vpn_reload_failed",
        });
      }
      response.status(204).end();
    } catch (error) {
      next(error);
    }
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
    maxAge: 0,
    setHeaders(response) {
      response.setHeader("Cache-Control", "no-store");
    },
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
