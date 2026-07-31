"use strict";

const byId = (id) => document.getElementById(id);
const state = { preview: null, configText: "", autoOpenedImport: false };

function apiUrl(path) {
  return new URL(path, document.baseURI).toString();
}

async function apiRequest(path, options = {}) {
  const response = await fetch(apiUrl(path), {
    ...options,
    headers: {
      "Content-Type": "application/json",
      "X-WG-Request": "1",
      ...(options.headers || {}),
    },
    cache: "no-store",
  });
  let payload;
  try {
    payload = await response.json();
  } catch (_error) {
    throw new Error("Die Antwort des Add-ons war ungültig.");
  }
  if (!response.ok) {
    throw new Error(payload.error || "Die Anfrage ist fehlgeschlagen.");
  }
  return payload;
}

function showToast(message, isError = false) {
  const toast = byId("toast");
  toast.textContent = message;
  toast.classList.toggle("is-error", isError);
  toast.hidden = false;
  window.clearTimeout(showToast.timer);
  showToast.timer = window.setTimeout(() => { toast.hidden = true; }, 5000);
}

function setBusy(button, busy, busyText) {
  if (!button.dataset.label) button.dataset.label = button.textContent;
  button.disabled = busy;
  button.textContent = busy ? busyText : button.dataset.label;
}

function selectTab(tabName) {
  document.querySelectorAll(".tab").forEach((button) => {
    const active = button.dataset.tab === tabName;
    button.classList.toggle("is-active", active);
    button.setAttribute("aria-selected", String(active));
  });
  byId("overviewPanel").hidden = tabName !== "overview";
  byId("configurationPanel").hidden = tabName !== "configuration";
  if (tabName === "configuration") byId("configurationTitle").focus?.();
}

function phaseLabel(phase) {
  return {
    connected: "Verbunden",
    waiting_handshake: "Warte auf Handshake",
    starting: "Tunnelaufbau",
    reloading: "Wird aktiviert",
    degraded: "Handshake veraltet",
    unconfigured: "Einrichtung erforderlich",
    configuration_error: "Konfiguration fehlerhaft",
    error: "Verbindungsfehler",
    stopped: "Gestoppt",
  }[phase] || "Status unbekannt";
}

function formatBytes(value) {
  const bytes = Number(value || 0);
  if (!bytes) return "0 B";
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  const index = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  return `${(bytes / (1024 ** index)).toFixed(index === 0 ? 0 : 1)} ${units[index]}`;
}

function formatAge(seconds) {
  if (seconds === null || seconds === undefined) return "Noch nie";
  if (seconds < 60) return `vor ${seconds} s`;
  if (seconds < 3600) return `vor ${Math.floor(seconds / 60)} min`;
  if (seconds < 86400) return `vor ${Math.floor(seconds / 3600)} h`;
  return `vor ${Math.floor(seconds / 86400)} Tagen`;
}

function renderChips(container, values) {
  container.replaceChildren();
  if (!values || values.length === 0) {
    const empty = document.createElement("span");
    empty.className = "empty-value";
    empty.textContent = "–";
    container.append(empty);
    return;
  }
  values.forEach((value) => {
    const chip = document.createElement("span");
    chip.className = "chip";
    chip.textContent = value;
    container.append(chip);
  });
}

function renderStatus(status) {
  const header = byId("headerStatus");
  header.dataset.phase = status.phase;
  byId("headerStatusText").textContent = phaseLabel(status.phase);
  byId("statusMessage").textContent = status.message || phaseLabel(status.phase);
  byId("connectionOrbit").dataset.phase = status.phase;
  byId("handshakeValue").textContent = formatAge(status.handshake_age_seconds);
  byId("handshakeDetail").textContent = status.latest_handshake ? "Authentifiziert" : "Noch kein Handshake";
  byId("receivedValue").textContent = formatBytes(status.received_bytes);
  byId("sentValue").textContent = formatBytes(status.sent_bytes);
  byId("endpointValue").textContent = status.endpoint || "–";
  byId("clientAddressValue").textContent = status.client_address || "–";
  byId("configSource").textContent = status.source === "import" ? "GUI-Import" : status.configured ? "Home Assistant" : "Nicht konfiguriert";
  renderChips(byId("remoteNetworkList"), status.remote_subnets);
  renderChips(byId("lanTargetList"), status.lan_targets);

  const publicKeyRow = byId("publicKeyRow");
  publicKeyRow.hidden = !status.public_key;
  byId("publicKeyValue").textContent = status.public_key || "";
  byId("resetImport").hidden = status.source !== "import";

  if (!status.configured && !state.autoOpenedImport) {
    state.autoOpenedImport = true;
    selectTab("configuration");
  }
}

async function refreshStatus() {
  try {
    const status = await apiRequest("api/status", { method: "GET", headers: {} });
    renderStatus(status);
  } catch (error) {
    byId("headerStatus").dataset.phase = "error";
    byId("headerStatusText").textContent = "Nicht erreichbar";
    byId("statusMessage").textContent = error.message;
  }
}

function parseNetworkInput(value) {
  return value.split(/[\n,]+/).map((item) => item.trim()).filter(Boolean);
}

function renderPreview(preview) {
  state.preview = preview;
  byId("previewEmpty").hidden = true;
  byId("previewContent").hidden = false;
  byId("previewIntro").textContent = "Import erfolgreich gelesen. Routing bitte bestätigen.";
  byId("previewEndpoint").textContent = preview.endpoint;
  byId("previewAddress").textContent = preview.client_address;
  byId("previewFingerprint").textContent = `SHA-256 ${preview.server_key_fingerprint}`;
  byId("previewAdvanced").textContent = `${preview.mtu} / ${preview.persistent_keepalive} s`;
  byId("remoteSubnets").value = preview.suggested_remote_subnets.join("\n");
  byId("lanTargets").value = preview.suggested_lan_targets.join("\n");
  renderChips(byId("allowedIpList"), preview.allowed_ips);

  const warningBox = byId("warningBox");
  const warningList = byId("warningList");
  warningList.replaceChildren();
  warningBox.hidden = preview.warnings.length === 0;
  preview.warnings.forEach((warning) => {
    const item = document.createElement("li");
    item.textContent = warning;
    warningList.append(item);
  });
}

async function previewConfiguration() {
  const button = byId("previewConfig");
  const configText = byId("configText").value.trim();
  if (!configText) {
    showToast("Bitte zuerst eine WireGuard-Konfiguration auswählen oder einfügen.", true);
    return;
  }
  state.configText = configText;
  setBusy(button, true, "Wird geprüft …");
  try {
    const preview = await apiRequest("api/import/preview", {
      method: "POST",
      body: JSON.stringify({ config_text: configText }),
    });
    renderPreview(preview);
    showToast("Konfiguration erfolgreich geprüft.");
  } catch (error) {
    state.preview = null;
    showToast(error.message, true);
  } finally {
    setBusy(button, false, "");
  }
}

async function applyConfiguration() {
  if (!state.preview || !state.configText) {
    showToast("Bitte die Konfiguration zuerst prüfen.", true);
    return;
  }
  const remoteSubnets = parseNetworkInput(byId("remoteSubnets").value);
  const lanTargets = parseNetworkInput(byId("lanTargets").value);
  if (!remoteSubnets.length || !lanTargets.length) {
    showToast("Mindestens ein entferntes Quellnetz und ein LAN-Ziel sind erforderlich.", true);
    return;
  }
  const button = byId("applyConfig");
  setBusy(button, true, "Wird aktiviert …");
  try {
    const result = await apiRequest("api/import/apply", {
      method: "POST",
      body: JSON.stringify({
        config_text: state.configText,
        remote_subnets: remoteSubnets,
        lan_targets: lanTargets,
      }),
    });
    byId("configText").value = "";
    state.configText = "";
    showToast(result.message);
    selectTab("overview");
    window.setTimeout(refreshStatus, 700);
  } catch (error) {
    showToast(error.message, true);
  } finally {
    setBusy(button, false, "");
  }
}

async function readFile(file) {
  if (!file) return;
  if (file.size > 64 * 1024) {
    showToast("Die Datei ist größer als 64 KiB.", true);
    return;
  }
  try {
    const content = await file.text();
    byId("configText").value = content;
    state.preview = null;
    state.configText = content;
    byId("previewEmpty").hidden = false;
    byId("previewContent").hidden = true;
    byId("previewIntro").textContent = `${file.name} ist bereit zur Prüfung.`;
    showToast(`${file.name} wurde eingelesen.`);
  } catch (_error) {
    showToast("Die Datei konnte nicht gelesen werden.", true);
  }
}

async function resetImportedConfiguration() {
  if (!window.confirm("Importierte Konfiguration entfernen und wieder die Home-Assistant-Optionen verwenden?")) return;
  try {
    const result = await apiRequest("api/config/reset", {
      method: "POST",
      body: JSON.stringify({}),
    });
    showToast(result.message);
    window.setTimeout(refreshStatus, 700);
  } catch (error) {
    showToast(error.message, true);
  }
}

document.querySelectorAll(".tab").forEach((button) => {
  button.addEventListener("click", () => selectTab(button.dataset.tab));
});
byId("openImport").addEventListener("click", () => selectTab("configuration"));
byId("previewConfig").addEventListener("click", previewConfiguration);
byId("applyConfig").addEventListener("click", applyConfiguration);
byId("resetImport").addEventListener("click", resetImportedConfiguration);
byId("copyPublicKey").addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText(byId("publicKeyValue").textContent);
    showToast("Öffentlicher Schlüssel kopiert.");
  } catch (_error) {
    showToast("Der Schlüssel konnte nicht kopiert werden.", true);
  }
});

const fileInput = byId("configFile");
const dropZone = byId("dropZone");
dropZone.addEventListener("click", () => fileInput.click());
fileInput.addEventListener("change", () => readFile(fileInput.files[0]));
["dragenter", "dragover"].forEach((eventName) => {
  dropZone.addEventListener(eventName, (event) => {
    event.preventDefault();
    dropZone.classList.add("is-dragging");
  });
});
["dragleave", "drop"].forEach((eventName) => {
  dropZone.addEventListener(eventName, (event) => {
    event.preventDefault();
    dropZone.classList.remove("is-dragging");
  });
});
dropZone.addEventListener("drop", (event) => readFile(event.dataTransfer.files[0]));

refreshStatus();
window.setInterval(refreshStatus, 5000);
