const formatLabel = (value) => value.replaceAll("_", " ").replace(/\b\w/g, c => c.toUpperCase());
const formatTime = (value) => new Intl.DateTimeFormat(undefined, { dateStyle: "short", timeStyle: "medium" }).format(new Date(value));
const safe = (value) => String(value ?? "—").replace(/[&<>'"]/g, char => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;" })[char]);

async function api(path) {
  const response = await fetch(path, { headers: { Accept: "application/json" } });
  if (!response.ok) throw new Error(`${response.status} ${response.statusText}`);
  return response.json();
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
  document.querySelector("#alerts-body").innerHTML = alerts.length ? alerts.map(alert => `
    <tr><td>${safe(formatTime(alert.created_at))}</td><td><span class="badge ${safe(alert.severity)}">${safe(alert.severity)}</span></td><td>${safe(alert.rule_id)}</td><td title="${safe(alert.description)}">${safe(alert.title)}</td><td>${safe(alert.source_ip)}</td><td class="${safe(alert.status)}">${safe(formatLabel(alert.status))}</td></tr>
  `).join("") : '<tr><td colspan="6" class="empty">No alerts match this filter.</td></tr>';
}

function renderEvents(events) {
  document.querySelector("#events-body").innerHTML = events.length ? events.map(event => {
    const destination = event.destination_ip ? `${event.destination_ip}${event.destination_port ? `:${event.destination_port}` : ""}` : "—";
    return `<tr><td>${safe(formatTime(event.timestamp))}</td><td>${safe(formatLabel(event.event_type))}</td><td>${safe(event.source_ip)}</td><td>${safe(destination)}</td><td>${safe(event.username)}</td><td title="${safe(event.message)}">${safe(event.message || "—")}</td></tr>`;
  }).join("") : '<tr><td colspan="6" class="empty">No events have been ingested.</td></tr>';
}

async function refresh() {
  try {
    const severity = document.querySelector("#severity-filter").value;
    const alertQuery = severity ? `?limit=20&severity=${encodeURIComponent(severity)}` : "?limit=20";
    const [summary, alerts, events] = await Promise.all([
      api("/api/dashboard/summary"), api(`/api/alerts${alertQuery}`), api("/api/events?limit=20")
    ]);
    renderSummary(summary); renderAlerts(alerts); renderEvents(events);
  } catch (error) {
    const toast = document.querySelector("#error-toast");
    toast.textContent = `Unable to refresh dashboard: ${error.message}`;
    toast.classList.add("visible");
    setTimeout(() => toast.classList.remove("visible"), 4000);
  }
}

document.querySelector("#severity-filter").addEventListener("change", refresh);
refresh();
setInterval(refresh, 10000);

