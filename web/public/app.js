const webState = document.querySelector("#web-state");
const vpnState = document.querySelector("#vpn-state");
const vpnMessage = document.querySelector("#vpn-message");
const activityList = document.querySelector("#activity-list");
const refreshButton = document.querySelector("#refresh-button");
const clientDialog = document.querySelector("#client-dialog");
const openClientDialog = document.querySelector("#open-client-dialog");
const closeClientDialog = document.querySelector("#close-client-dialog");
const clientAddForm = document.querySelector("#client-add-form");
const clientAddResult = document.querySelector("#client-add-result");
const deleteClientDialog = document.querySelector("#delete-client-dialog");
const deleteClientAddress = document.querySelector("#delete-client-address");
const deleteClientResult = document.querySelector("#delete-client-result");
const cancelDeleteClient = document.querySelector("#cancel-delete-client");
const confirmDeleteClient = document.querySelector("#confirm-delete-client");
const registeredClientList = document.querySelector("#registered-client-list");
const liveSessionState = document.querySelector("#live-session-state");
const serverAddress = document.querySelector("#server-vpn-address");
const serverMtu = document.querySelector("#server-mtu");
let registeredClients = [];
let activeSessions = [];
let vpnAvailable = false;
let pendingDeleteAddress = null;

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

function renderRegisteredClients() {
  const sessionsByAddress = new Map(activeSessions.map((session) => [session.vpnAddress, session]));
  liveSessionState.textContent = `${registeredClients.length}개 등록 · ${vpnAvailable ? `${activeSessions.length}개 연결` : "연결 상태 확인 불가"}`;
  registeredClientList.innerHTML = registeredClients.length ? registeredClients.map((client) => {
    const session = sessionsByAddress.get(client.vpnAddress);
    const status = !vpnAvailable ? "확인 불가" : session ? "연결됨" : "연결 안 됨";
    return `<tr><td>${escapeHtml(client.vpnAddress)}</td><td class="fingerprint">${escapeHtml(client.fingerprint)}</td><td>${escapeHtml(session?.clientIp || "-")}</td><td class="${session ? "connected" : ""}">${status}</td><td><button class="danger-action" type="button" data-delete-client="${escapeHtml(client.vpnAddress)}">삭제</button></td></tr>`;
  }).join("") : '<tr><td colspan="5">등록된 클라이언트가 없습니다.</td></tr>';
}

function renderActivity(entries) {
  const labels = {
    server_started: "VPN 서버 시작",
    server_stopped: "VPN 서버 종료",
    client_connected: "클라이언트 접속",
    client_disconnected: "클라이언트 해지",
  };
  activityList.innerHTML = entries.length ? entries.map((entry) => {
    const details = [entry.vpnAddress, entry.clientIp].filter(Boolean).join(" · ");
    return `<li><span class="activity-icon ${entry.type === "server_started" || entry.type === "client_connected" ? "success" : "neutral"}"></span><div><strong>${escapeHtml(labels[entry.type] ?? entry.type)}${details ? ` · ${escapeHtml(details)}` : ""}</strong><small>${escapeHtml(formatDate(entry.occurredAt))}</small></div></li>`;
  }).join("") : '<li class="empty-state">기록된 이벤트가 없습니다.</li>';
}

async function refreshActivity() {
  try {
    const response = await fetch("/api/activity", { cache: "no-store" });
    if (!response.ok) throw new Error(`status ${response.status}`);
    renderActivity((await response.json()).entries);
  } catch (error) {
    activityList.innerHTML = '<li class="empty-state">이벤트를 읽을 수 없습니다.</li>';
    console.error("Unable to refresh activity", error);
  }
}

const activityEvents = new EventSource("/api/activity/events");
activityEvents.addEventListener("activity", (event) => renderActivity(JSON.parse(event.data).entries));

const sessionEvents = new EventSource("/api/vpn/events");
sessionEvents.addEventListener("sessions", (event) => {
  activeSessions = JSON.parse(event.data).sessions;
  vpnAvailable = true;
  renderRegisteredClients();
});
sessionEvents.addEventListener("unavailable", () => {
  vpnAvailable = false;
  renderRegisteredClients();
});
sessionEvents.onerror = () => {
  vpnAvailable = false;
  renderRegisteredClients();
};

async function refreshStatus() {
  refreshButton.disabled = true;
  try {
    const response = await fetch("/api/status", { cache: "no-store" });
    if (!response.ok) throw new Error(`status ${response.status}`);
    const status = await response.json();

    webState.textContent = status.web.state === "online" ? "정상 운영 중" : status.web.state;
    vpnState.textContent = status.vpn.state === "online" ? "정상 운영 중" : "상태 확인 불가";
    vpnMessage.textContent = status.vpn.message;
    serverAddress.textContent = status.server?.vpnAddress ?? "확인 불가";
    serverMtu.textContent = status.server?.mtu ?? "확인 불가";
    registeredClients = status.clients;
    activeSessions = status.vpn.sessions;
    vpnAvailable = status.vpn.state === "online";
    renderRegisteredClients();
  } catch (error) {
    webState.textContent = "연결 오류";
    vpnState.textContent = "확인 불가";
    vpnMessage.textContent = "웹 API 응답을 확인할 수 없습니다.";
    console.error("Unable to refresh dashboard", error);
  } finally {
    refreshButton.disabled = false;
  }
}

refreshButton.addEventListener("click", () => { refreshStatus(); refreshActivity(); });
openClientDialog.addEventListener("click", () => {
  clientAddResult.textContent = "";
  clientDialog.showModal();
});
closeClientDialog.addEventListener("click", () => clientDialog.close());
clientAddForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = clientAddForm.querySelector('button[type="submit"]');
  const input = Object.fromEntries(new FormData(clientAddForm));
  const vpnAddress = String(input.vpnAddress).trim();
  if (registeredClients.some((client) => client.vpnAddress === vpnAddress)) {
    clientAddResult.textContent = "이미 등록된 VPN 주소입니다.";
    clientAddResult.className = "form-result error";
    return;
  }
  button.disabled = true;
  clientAddResult.textContent = "인증서 발급 중…";
  clientAddResult.className = "form-result";
  try {
    const response = await fetch("/api/clients/issue", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ name: input.name, vpnAddress, validityDays: Number(input.validityDays), loginId: input.loginId, password: input.password }),
    });
    if (!response.ok) {
      const body = await response.json();
      throw new Error(body.message ?? body.error);
    }
    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const download = document.createElement("a");
    download.href = url;
    download.download = `${String(input.name).trim()}-client.ini`;
    download.click();
    setTimeout(() => URL.revokeObjectURL(url), 60_000);
    clientAddForm.reset();
    clientDialog.close();
    await refreshStatus();
  } catch (error) {
    clientAddResult.textContent = error.message;
    clientAddResult.classList.add("error");
  } finally {
    button.disabled = false;
  }
});
registeredClientList.addEventListener("click", (event) => {
  const button = event.target.closest("[data-delete-client]");
  if (!button) return;
  pendingDeleteAddress = button.dataset.deleteClient;
  deleteClientAddress.textContent = pendingDeleteAddress;
  deleteClientResult.textContent = "";
  deleteClientResult.className = "form-result";
  deleteClientDialog.showModal();
});
cancelDeleteClient.addEventListener("click", () => deleteClientDialog.close());
deleteClientDialog.addEventListener("close", () => { pendingDeleteAddress = null; });
confirmDeleteClient.addEventListener("click", async () => {
  if (!pendingDeleteAddress) return;
  const vpnAddress = pendingDeleteAddress;
  confirmDeleteClient.disabled = true;
  cancelDeleteClient.disabled = true;
  deleteClientResult.textContent = "삭제 중…";
  try {
    const response = await fetch(`/api/clients/${encodeURIComponent(vpnAddress)}`, { method: "DELETE" });
    if (!response.ok) {
      const body = await response.json();
      throw new Error(body.message ?? body.error);
    }
    await refreshStatus();
    deleteClientDialog.close();
  } catch (error) {
    deleteClientResult.textContent = `삭제할 수 없습니다: ${error.message}`;
    deleteClientResult.className = "form-result error";
    await refreshStatus();
  } finally {
    confirmDeleteClient.disabled = false;
    cancelDeleteClient.disabled = false;
  }
});
refreshStatus();
refreshActivity();
