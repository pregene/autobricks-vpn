const webState = document.querySelector("#web-state");
const vpnState = document.querySelector("#vpn-state");
const vpnMessage = document.querySelector("#vpn-message");
const startedAt = document.querySelector("#started-at");
const refreshButton = document.querySelector("#refresh-button");
const pkiRefreshButton = document.querySelector("#pki-refresh-button");
const signerState = document.querySelector("#signer-state");
const inventoryList = document.querySelector("#inventory-list");
const serverCertificateForm = document.querySelector("#server-certificate-form");
const clientCertificateForm = document.querySelector("#client-certificate-form");
const clientBindingForm = document.querySelector("#client-binding-form");
const clientList = document.querySelector("#client-list");
const liveSessionList = document.querySelector("#live-session-list");
const liveSessionState = document.querySelector("#live-session-state");

function formatDate(value) {
  return new Intl.DateTimeFormat("ko-KR", {
    dateStyle: "medium",
    timeStyle: "medium",
  }).format(new Date(value));
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"]/g, (character) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;",
  })[character]);
}

function renderInventory(data) {
  const items = [
    ...data.certificates.map((item) => ({
      title: item.subject,
      detail: item.subjectAltName || item.fingerprint,
      meta: `서버 인증서 · ${formatDate(item.validTo)} 만료`,
      status: "등록됨",
    })),
    ...data.requests.map((item) => ({
      title: item.name,
      detail: item.vpnAddress,
      meta: `클라이언트 발급 요청 · ${item.validityDays}일`,
      status: "서명 대기",
    })),
  ];
  inventoryList.innerHTML = items.length ? items.map((item) => `
    <div class="inventory-item">
      <div><strong>${escapeHtml(item.title)}</strong><small>${escapeHtml(item.detail)}</small></div>
      <div><span>${escapeHtml(item.meta)}</span><b>${escapeHtml(item.status)}</b></div>
    </div>`).join("") : '<p class="empty-state">등록된 인증서와 발급 요청이 없습니다.</p>';
}

function renderLiveSessions(sessions) {
  liveSessionState.textContent = `${sessions.length}개 연결됨`;
  vpnState.textContent = "실시간 연결됨";
  vpnMessage.textContent = "Rust VPN 서버 이벤트 스트림 수신 중";
  liveSessionList.innerHTML = sessions.length ? sessions.map((session) => `
    <div class="inventory-item live-session-item">
      <div><strong>${escapeHtml(session.vpnAddress)}</strong><small>${escapeHtml(session.fingerprint)}</small></div>
      <div class="session-counters"><span>RX ${Number(session.bytesRx).toLocaleString()} B · TX ${Number(session.bytesTx).toLocaleString()} B</span><small>${Number(session.connectedSeconds).toLocaleString()}초 연결</small></div>
      <button class="danger-action" type="button" data-disconnect-session="${escapeHtml(session.vpnAddress)}">연결 끊기</button>
    </div>`).join("") : '<p class="empty-state">현재 연결된 VPN 클라이언트가 없습니다.</p>';
}

const sessionEvents = new EventSource("/api/vpn/events");
sessionEvents.addEventListener("sessions", (event) => renderLiveSessions(JSON.parse(event.data).sessions));
sessionEvents.addEventListener("unavailable", () => {
  liveSessionState.textContent = "VPN 서버 연결 안 됨";
  vpnState.textContent = "오프라인";
});
sessionEvents.onerror = () => { liveSessionState.textContent = "다시 연결 중"; };

async function refreshPki() {
  pkiRefreshButton.disabled = true;
  try {
    const [pkiResponse, clientsResponse] = await Promise.all([
      fetch("/api/pki", { cache: "no-store" }),
      fetch("/api/clients", { cache: "no-store" }),
    ]);
    if (!pkiResponse.ok || !clientsResponse.ok) throw new Error("PKI API response failed");
    const data = await pkiResponse.json();
    const clientData = await clientsResponse.json();
    signerState.textContent = data.capabilities.signer === "not_configured" ? "CA 서명 서비스 연결 대기" : "CA 서명 서비스 연결됨";
    renderInventory(data);
    clientList.innerHTML = clientData.clients.length ? clientData.clients.map((client) => `
      <div class="inventory-item">
        <div><strong>${escapeHtml(client.vpnAddress)}</strong><small>${escapeHtml(client.fingerprint)}</small></div>
        <button class="danger-action" type="button" data-remove-client="${escapeHtml(client.vpnAddress)}">등록 해제</button>
      </div>`).join("") : '<p class="empty-state">등록된 VPN 클라이언트가 없습니다.</p>';
  } catch (error) {
    signerState.textContent = "PKI 상태 확인 실패";
    console.error("Unable to refresh PKI status", error);
  } finally {
    pkiRefreshButton.disabled = false;
  }
}

async function submitForm(form, endpoint, options = {}) {
  const result = form.querySelector(".form-result");
  const button = form.querySelector("button[type=submit]");
  result.textContent = "처리 중…";
  result.className = "form-result";
  button.disabled = true;
  try {
    const response = await fetch(endpoint, {
      method: options.method ?? "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(Object.fromEntries(new FormData(form))),
    });
    const body = await response.json();
    if (!response.ok) throw new Error(body.message || body.error);
    result.textContent = options.success ?? (response.status === 201 ? "서버 인증서를 등록했습니다." : "발급 요청을 안전하게 접수했습니다.");
    result.classList.add("success");
    form.reset();
    await refreshPki();
  } catch (error) {
    result.textContent = error.message;
    result.classList.add("error");
  } finally {
    button.disabled = false;
  }
}

async function refreshStatus() {
  refreshButton.disabled = true;
  try {
    const response = await fetch("/api/status", { cache: "no-store" });
    if (!response.ok) throw new Error(`status ${response.status}`);
    const status = await response.json();

    webState.textContent = status.web.state === "online" ? "정상 운영 중" : status.web.state;
    vpnState.textContent = status.vpn.state === "integration_pending" ? "연결 대기" : status.vpn.state;
    vpnMessage.textContent = status.vpn.message;
    startedAt.textContent = `${formatDate(status.web.startedAt)} 시작`;
  } catch (error) {
    webState.textContent = "연결 오류";
    vpnState.textContent = "확인 불가";
    vpnMessage.textContent = "웹 API 응답을 확인할 수 없습니다.";
    console.error("Unable to refresh dashboard", error);
  } finally {
    refreshButton.disabled = false;
  }
}

refreshButton.addEventListener("click", refreshStatus);
pkiRefreshButton.addEventListener("click", refreshPki);
serverCertificateForm.addEventListener("submit", (event) => {
  event.preventDefault();
  submitForm(serverCertificateForm, "/api/pki/server-certificates");
});
clientCertificateForm.addEventListener("submit", (event) => {
  event.preventDefault();
  submitForm(clientCertificateForm, "/api/pki/client-certificates");
});
clientBindingForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const vpnAddress = new FormData(clientBindingForm).get("vpnAddress");
  await submitForm(clientBindingForm, `/api/clients/${encodeURIComponent(vpnAddress)}`,
    { method: "PUT", success: "클라이언트를 server.ini에 등록했습니다." });
});
clientList.addEventListener("click", async (event) => {
  const button = event.target.closest("[data-remove-client]");
  if (!button) return;
  button.disabled = true;
  const response = await fetch(`/api/clients/${encodeURIComponent(button.dataset.removeClient)}`, { method: "DELETE" });
  if (response.ok) await refreshPki();
  else button.disabled = false;
});
liveSessionList.addEventListener("click", async (event) => {
  const button = event.target.closest("[data-disconnect-session]");
  if (!button) return;
  button.disabled = true;
  const response = await fetch(`/api/vpn/sessions/${encodeURIComponent(button.dataset.disconnectSession)}`, { method: "DELETE" });
  if (!response.ok) button.disabled = false;
});
refreshStatus();
refreshPki();
