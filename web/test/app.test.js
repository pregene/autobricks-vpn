import assert from "node:assert/strict";
import test from "node:test";
import { createApp } from "../src/app.js";

test("health endpoint reports the web service", async (context) => {
  const server = createApp({ startedAt: new Date("2026-01-01T00:00:00Z") }).listen(
    0,
    "127.0.0.1",
  );
  context.after(() => server.close());

  await new Promise((resolve) => server.once("listening", resolve));
  const address = server.address();
  const response = await fetch(`http://127.0.0.1:${address.port}/api/health`);
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.status, "ok");
  assert.equal(body.service, "autobricks-vpn-web");
});

test("unknown API routes return JSON 404", async (context) => {
  const server = createApp().listen(0, "127.0.0.1");
  context.after(() => server.close());

  await new Promise((resolve) => server.once("listening", resolve));
  const address = server.address();
  const response = await fetch(`http://127.0.0.1:${address.port}/api/missing`);

  assert.equal(response.status, 404);
  assert.deepEqual(await response.json(), { error: "not_found" });
});

test("PKI endpoint exposes signer capability without private key access", async (context) => {
  const server = createApp().listen(0, "127.0.0.1");
  context.after(() => server.close());

  await new Promise((resolve) => server.once("listening", resolve));
  const address = server.address();
  const response = await fetch(`http://127.0.0.1:${address.port}/api/pki`);
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.capabilities.signer, "not_configured");
  assert.equal(body.capabilities.clientCertificateIssuance, false);
  assert.deepEqual(body.certificates, []);
});

test("client certificate request validates VPN IP and queues a CSR", async (context) => {
  const server = createApp().listen(0, "127.0.0.1");
  context.after(() => server.close());

  await new Promise((resolve) => server.once("listening", resolve));
  const address = server.address();
  const base = `http://127.0.0.1:${address.port}`;
  const invalid = await fetch(`${base}/api/pki/client-certificates`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      name: "test-client",
      vpnAddress: "10.8.2.4",
      csrPem: "-----BEGIN CERTIFICATE REQUEST-----\ntest\n-----END CERTIFICATE REQUEST-----",
      validityDays: 365,
    }),
  });
  assert.equal(invalid.status, 400);
  assert.equal((await invalid.json()).error, "invalid_vpn_address");

  const accepted = await fetch(`${base}/api/pki/client-certificates`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      name: "test-client",
      vpnAddress: "10.8.1.4",
      csrPem: "-----BEGIN CERTIFICATE REQUEST-----\ntest\n-----END CERTIFICATE REQUEST-----",
      validityDays: 365,
    }),
  });
  const body = await accepted.json();
  assert.equal(accepted.status, 202);
  assert.equal(body.request.status, "awaiting_signer");
  assert.equal(body.request.vpnAddress, "10.8.1.4");
  assert.equal("csrPem" in body.request, false);
});

test("disconnect API forwards the VPN address to the Rust control channel", async (context) => {
  const commands = [];
  const vpnControl = {
    command: async (command) => {
      commands.push(command);
      return { ok: true, disconnected: 1 };
    },
  };
  const server = createApp({ vpnControl }).listen(0, "127.0.0.1");
  context.after(() => server.close());

  await new Promise((resolve) => server.once("listening", resolve));
  const address = server.address();
  const response = await fetch(`http://127.0.0.1:${address.port}/api/vpn/sessions/10.8.1.3`, {
    method: "DELETE",
  });

  assert.equal(response.status, 200);
  assert.deepEqual(commands, ["DISCONNECT 10.8.1.3"]);
  assert.deepEqual(await response.json(), { ok: true, disconnected: 1 });
});
