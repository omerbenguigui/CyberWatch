const DEVELOPMENT_API_KEY = "dev-key-change-me";
const formatLabel = (value) => value.replaceAll("_", " ").replace(/\b\w/g, char => char.toUpperCase());
const formatTime = (value) => new Intl.DateTimeFormat(undefined, { dateStyle: "short", timeStyle: "medium" }).format(new Date(value));
const safe = (value) => String(value ?? "—").replace(/[&<>'"]/g, char => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;" })[char]);

let currentAlerts = [];
let selectedAlert = null;
let demoEnabled = true;

async function api(path, options = {}) {
  const headers = { Accept: "application/json", ...(options.headers || {}) };
  if (options.body) headers["Content-Type"] = "application/json";
  const response = await fetch(path, { ...options, headers });
  if (!response.ok) {
    const payload = await response.json().catch(() => ({}));
    throw new Error(payload.detail || `${response.status} ${response.statusText}`);
  }
  return response.json();
}

function showToast(message, tone = "success") {
  const toast = document.querySelector("#toast");
  toast.textContent = message;
  toast.className = `visible ${tone}`;
  setTimeout(() => { toast.className = ""; }, 4000);
}

function renderSummary(summary) {
  document.querySelector("#total-events").textContent = summary.total_events.toLocaleString();
  document.querySelector("#open-alerts").textContent = summary.open_alerts.toLocaleString();
  document.querySelector("#critical-alerts").textContent = summary.critical_alerts.toLocaleString();
  document.querySelector("#unique-sources").textContent = summary.unique_sources.toLocaleString();
  document.querySelector("#updated-at").textContent = new Date().toLocaleTimeString();

  const entries = Object.entries(summary.events_by_type).sort((a, b) => b[1] - a[1]);
  const maximum = Math.max(1, ...entries.map(([, count]) => count));
  document.querySelector("#event-chart").innerHTML = entries.length ? entries.map(([name, count]) => `
    <div class="bar-row"><span>${safe(formatLabel(name))}</span><div class="bar-track"><div class="bar-fill" style="width:${(count / maximum) * 100}%"></div></div><span class="bar-count">${count}</span></div>
  `).join("") : '<p class="empty">Waiting for event data…</p>';

  const severities = ["critical", "high", "medium", "low"];
  const alertTotal = severities.reduce((sum, level) => sum + (summary.alerts_by_severity[level] || 0), 0);
  document.querySelector("#severity-chart").innerHTML = alertTotal ? severities.map(level => `
    <div class="severity-item ${level}"><span>${level}</span><strong>${summary.alerts_by_severity[level] || 0}</strong></div>
  `).join("") : '<p class="empty">No alerts detected.</p>';
}

function renderAlerts(alerts) {
  currentAlerts = alerts;
  document.querySelector("#alerts-body").innerHTML = alerts.length ? alerts.map(alert => `
    <tr class="alert-row" data-alert-id="${alert.id}" tabindex="0">
      <td>${safe(formatTime(alert.created_at))}</td>
      <td><span class="badge ${safe(alert.severity)}">${safe(alert.severity)}</span></td>
      <td>${safe(alert.rule_id)}</td>
      <td><button class="row-link" type="button" data-alert-id="${alert.id}">${safe(alert.title)}</button></td>
      <td><span class="mitre-tag">${safe(alert.evidence.mitre_id || "—")}</span></td>
      <td>${safe(alert.source_ip)}</td>
      <td><span class="status-pill ${safe(alert.status)}">${safe(formatLabel(alert.status))}</span></td>
    </tr>
  `).join("") : '<tr><td colspan="7" class="empty">No alerts match these filters.</td></tr>';
}

function renderEvents(events) {
  document.querySelector("#events-body").innerHTML = events.length ? events.map(event => {
    const destination = event.destination_ip ? `${event.destination_ip}${event.destination_port ? `:${event.destination_port}` : ""}` : "—";
    const simulated = event.metadata.simulation ? '<span class="demo-tag">DEMO</span>' : "";
    return `<tr><td>${safe(formatTime(event.timestamp))}</td><td>${safe(formatLabel(event.event_type))} ${simulated}</td><td>${safe(event.source_ip)}</td><td>${safe(destination)}</td><td>${safe(event.username)}</td><td title="${safe(event.message)}">${safe(event.message || "—")}</td></tr>`;
  }).join("") : '<tr><td colspan="6" class="empty">No events have been ingested.</td></tr>';
}

function openAlert(alertId) {
  selectedAlert = currentAlerts.find(alert => alert.id === Number(alertId));
  if (!selectedAlert) return;
  const evidence = selectedAlert.evidence;
  document.querySelector("#dialog-title").textContent = selectedAlert.title;
  document.querySelector("#dialog-content").innerHTML = `
    <div class="alert-overview">
      <div><span>Severity</span><strong class="${safe(selectedAlert.severity)}">${safe(formatLabel(selectedAlert.severity))}</strong></div>
      <div><span>Source</span><strong>${safe(selectedAlert.source_ip)}</strong></div>
      <div><span>Rule</span><strong>${safe(selectedAlert.rule_id)}</strong></div>
      <div><span>Detected</span><strong>${safe(formatTime(selectedAlert.created_at))}</strong></div>
    </div>
    <section class="investigation-section"><h3>Why it was detected</h3><p>${safe(selectedAlert.description)}</p></section>
    <section class="mitre-card"><div><span>MITRE ATT&amp;CK</span><strong>${safe(evidence.mitre_id || "Not mapped")}</strong></div><div><span>Tactic</span><strong>${safe(evidence.mitre_tactic || "—")}</strong></div><div><span>Technique</span><strong>${safe(evidence.mitre_technique || "—")}</strong></div></section>
    <section class="investigation-section"><h3>Detection evidence</h3><pre>${safe(JSON.stringify(evidence, null, 2))}</pre></section>
  `;
  document.querySelector("#alert-status").value = selectedAlert.status === "acknowledged" ? "resolved" : selectedAlert.status;
  document.querySelector("#analyst-note").value = selectedAlert.analyst_note || "";
  document.querySelector("#triage-form").hidden = !demoEnabled;
  document.querySelector("#alert-dialog").showModal();
}

async function refresh() {
  try {
    const severity = document.querySelector("#severity-filter").value;
    const status = document.querySelector("#status-filter").value;
    const params = new URLSearchParams({ limit: "20" });
    if (severity) params.set("severity", severity);
    if (status) params.set("status", status);
    const [summary, alerts, events] = await Promise.all([
      api("/api/dashboard/summary"), api(`/api/alerts?${params}`), api("/api/events?limit=20")
    ]);
    renderSummary(summary);
    renderAlerts(alerts);
    renderEvents(events);
  } catch (error) {
    showToast(`Unable to refresh dashboard: ${error.message}`, "error");
  }
}

async function simulateAttack(scenario, button) {
  const original = button.innerHTML;
  button.disabled = true;
  button.innerHTML = "<strong>Running detection…</strong><small>Generating safe telemetry</small>";
  try {
    const result = await api(`/api/demo/simulate/${scenario}`, { method: "POST" });
    await refresh();
    showToast(`${formatLabel(result.scenario)} detected — ${result.generated_alerts} alert created.`);
    document.querySelector("#simulation-options").hidden = true;
    const firstAlert = currentAlerts.find(alert => alert.source_ip === result.source_ip);
    if (firstAlert) setTimeout(() => openAlert(firstAlert.id), 450);
  } catch (error) {
    showToast(`Simulation failed: ${error.message}`, "error");
  } finally {
    button.disabled = false;
    button.innerHTML = original;
  }
}

document.querySelector("#severity-filter").addEventListener("change", refresh);
document.querySelector("#status-filter").addEventListener("change", refresh);
document.querySelector("#simulation-toggle").addEventListener("click", () => {
  const options = document.querySelector("#simulation-options");
  options.hidden = !options.hidden;
});
document.querySelectorAll("[data-scenario]").forEach(button => {
  button.addEventListener("click", () => simulateAttack(button.dataset.scenario, button));
});
document.querySelector("#alerts-body").addEventListener("click", event => {
  const target = event.target.closest("[data-alert-id]");
  if (target) openAlert(target.dataset.alertId);
});
document.querySelector("#alerts-body").addEventListener("keydown", event => {
  if ((event.key === "Enter" || event.key === " ") && event.target.matches(".alert-row")) {
    openAlert(event.target.dataset.alertId);
  }
});
document.querySelector("#dialog-close").addEventListener("click", () => document.querySelector("#alert-dialog").close());
document.querySelector("#dialog-cancel").addEventListener("click", () => document.querySelector("#alert-dialog").close());
document.querySelector("#triage-form").addEventListener("submit", async event => {
  event.preventDefault();
  if (!selectedAlert) return;
  try {
    await api(`/api/alerts/${selectedAlert.id}`, {
      method: "PATCH",
      headers: { "X-API-Key": DEVELOPMENT_API_KEY },
      body: JSON.stringify({
        status: document.querySelector("#alert-status").value,
        analyst_note: document.querySelector("#analyst-note").value,
      }),
    });
    document.querySelector("#alert-dialog").close();
    await refresh();
    showToast("Investigation updated successfully.");
  } catch (error) {
    showToast(`Could not update alert: ${error.message}`, "error");
  }
});

api("/api/demo/status").then(status => {
  demoEnabled = status.enabled;
  if (!status.enabled) document.querySelector("#simulation-menu").hidden = true;
});
refresh();
setInterval(refresh, 10000);
