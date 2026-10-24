/* CYBER-SENTINEL SOC JAVASCRIPT CONTROLLER */

let severityChart = null;
let mitreChart = null;
let pollTimer = null;
let isSimulatorRunning = false;

document.addEventListener("DOMContentLoaded", () => {
  initCharts();
  fetchMetrics();
  fetchAlerts();

  // Poll telemetry every 2.0 seconds
  pollTimer = setInterval(() => {
    fetchMetrics();
    fetchAlerts();
  }, 2000);
});

function initCharts() {
  const chartFont = {
    family: "'JetBrains Mono', monospace",
    size: 11
  };

  // 1. Severity Doughnut Chart
  const sevCtx = document.getElementById("severityChart").getContext("2d");
  severityChart = new Chart(sevCtx, {
    type: "doughnut",
    data: {
      labels: ["Critical", "High", "Medium", "Low", "Info"],
      datasets: [{
        data: [0, 0, 0, 0, 0],
        backgroundColor: ["#ef4444", "#f97316", "#eab308", "#06b6d4", "#3b82f6"],
        borderColor: "#0f172a",
        borderWidth: 2,
        hoverOffset: 4
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          position: "right",
          labels: { color: "#94a3b8", font: chartFont }
        }
      },
      cutout: "65%"
    }
  });

  // 2. MITRE ATT&CK Tactics Horizontal Bar Chart
  const mitreCtx = document.getElementById("mitreChart").getContext("2d");
  mitreChart = new Chart(mitreCtx, {
    type: "bar",
    data: {
      labels: ["Initial Access", "Execution", "Discovery", "Credential Access", "Impact", "Reconnaissance"],
      datasets: [{
        label: "Detections",
        data: [0, 0, 0, 0, 0, 0],
        backgroundColor: "rgba(0, 245, 255, 0.65)",
        borderColor: "#00f5ff",
        borderWidth: 1,
        borderRadius: 4
      }]
    },
    options: {
      indexAxis: "y",
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        x: {
          grid: { color: "#1e293b" },
          ticks: { color: "#64748b", font: chartFont, stepSize: 1 }
        },
        y: {
          grid: { display: false },
          ticks: { color: "#94a3b8", font: chartFont }
        }
      },
      plugins: {
        legend: { display: false }
      }
    }
  });
}

async function fetchMetrics() {
  try {
    const res = await fetch("/api/metrics");
    if (!res.ok) return;
    const data = await res.json();

    // Key stats
    document.getElementById("totalEvents").innerText = Number(data.total_events).toLocaleString();
    document.getElementById("totalAlerts").innerText = Number(data.total_alerts).toLocaleString();

    const crit = data.severity_counts["CRITICAL"] || 0;
    const high = data.severity_counts["HIGH"] || 0;
    document.getElementById("critAlertSubtext").innerText = `${crit} Critical • ${high} High`;

    document.getElementById("blockedIpsCount").innerText = data.blocked_ips_count || 0;
    document.getElementById("blockedCountBadge").innerText = `${data.blocked_ips_count || 0} Quarantined`;

    // Host Vitals
    if (data.host_vitals) {
      document.getElementById("hostHealthVitals").innerText =
        `CPU ${data.host_vitals.cpu_percent}% | RAM ${data.host_vitals.memory_percent}%`;
      document.getElementById("activeSocketsSubtext").innerText =
        `Active Sockets: ${data.host_vitals.active_connections} | Recv: ${data.host_vitals.bytes_recv_mb}MB`;
    }

    // Threat Posture Badge
    const postureBadge = document.getElementById("threatPostureBadge");
    postureBadge.innerText = data.threat_posture;
    postureBadge.style.color = data.posture_color;
    postureBadge.style.borderColor = data.posture_color;
    postureBadge.style.background = `${data.posture_color}1a`;

    // Update Severity Chart
    if (severityChart && data.severity_counts) {
      severityChart.data.datasets[0].data = [
        data.severity_counts["CRITICAL"] || 0,
        data.severity_counts["HIGH"] || 0,
        data.severity_counts["MEDIUM"] || 0,
        data.severity_counts["LOW"] || 0,
        data.severity_counts["INFO"] || 0
      ];
      severityChart.update();
    }

    // Update MITRE ATT&CK Chart
    if (mitreChart && data.mitre_tactic_counts) {
      const labels = ["Initial Access", "Execution", "Discovery", "Credential Access", "Impact", "Reconnaissance"];
      const counts = labels.map(l => data.mitre_tactic_counts[l] || 0);
      mitreChart.data.datasets[0].data = counts;
      mitreChart.update();
    }

    // Update Blacklist Table
    renderBlacklistTable(data.blocked_ips || []);

    // Update Top Attacking Sources
    renderTopOffenders(data.top_offenders || []);

    // Update continuous simulator button state
    isSimulatorRunning = !!data.simulator_active;
    updateSimulatorButtonUI();

  } catch (err) {
    console.warn("Failed fetching SOC telemetry:", err);
  }
}

async function fetchAlerts() {
  try {
    const res = await fetch("/api/alerts?limit=50");
    if (!res.ok) return;
    const data = await res.json();
    renderAlertFeed(data.alerts || []);
  } catch (err) {
    console.warn("Failed fetching alerts:", err);
  }
}

function renderAlertFeed(alerts) {
  const container = document.getElementById("alertFeedList");
  document.getElementById("feedCounterBadge").innerText = `${alerts.length} alerts`;

  if (!alerts || alerts.length === 0) {
    container.innerHTML = `
      <div class="empty-state">
        <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
        <p>No active security alerts. System is monitoring network traffic and host operations.</p>
        <span class="empty-hint">Use the attack buttons above to simulate an intrusion scenario.</span>
      </div>`;
    return;
  }

  container.innerHTML = alerts.map(a => `
    <div class="alert-item severity-${a.severity}">
      <div class="alert-topline">
        <div class="alert-badges">
          <span class="sev-badge ${a.severity}">${a.severity}</span>
          <span class="mitre-badge">${escapeHtml(a.mitre_technique_id)} • ${escapeHtml(a.mitre_tactic)}</span>
        </div>
        <span class="alert-time">${a.formatted_time || ''}</span>
      </div>
      <div class="alert-headline">${escapeHtml(a.title)}</div>
      <div class="alert-desc">${escapeHtml(a.description)}</div>
      ${a.raw_payload_snippet ? `<div class="alert-snippet">Payload/Match: ${escapeHtml(a.raw_payload_snippet)}</div>` : ''}
      <div class="alert-remediation">🛡️ Recommendation: ${escapeHtml(a.mitigation_recommendation)}</div>
    </div>
  `).join("");
}

function renderBlacklistTable(blockedList) {
  const tbody = document.getElementById("blacklistTableBody");
  if (!blockedList || blockedList.length === 0) {
    tbody.innerHTML = `<tr><td colspan="4" class="text-center text-muted" style="text-align:center; padding: 18px;">No IPs currently blacklisted. System posture clean.</td></tr>`;
    return;
  }

  tbody.innerHTML = blockedList.map(item => `
    <tr>
      <td><span class="ip-text">${escapeHtml(item.ip)}</span></td>
      <td><small style="color: #cbd5e1;">${escapeHtml(item.reason)}</small></td>
      <td><span class="badge badge-warning">${item.alert_count} Hits</span></td>
      <td>
        <button class="btn-small" onclick="unblockIp('${item.ip}')">Unblock</button>
      </td>
    </tr>
  `).join("");
}

function renderTopOffenders(offenders) {
  const container = document.getElementById("topOffendersList");
  if (!offenders || offenders.length === 0) {
    container.innerHTML = `<span class="text-muted" style="font-size:0.75rem;">Awaiting traffic telemetry...</span>`;
    return;
  }

  container.innerHTML = offenders.map(o => `
    <div class="offender-row">
      <span class="ip-text" style="${o.blocked ? 'color: #ef4444;' : 'color: #38bdf8;'}">${escapeHtml(o.ip)}</span>
      <span>${o.count} alert(s) ${o.blocked ? '<span style="color:#ef4444;">[BLOCKED]</span>' : ''}</span>
    </div>
  `).join("");
}

// Attack Simulation Actions
async function simulateAttack(type) {
  try {
    const res = await fetch(`/api/simulate/${type}`, { method: "POST" });
    const data = await res.json();
    showToast(data.message || `Simulated ${type} event dispatched.`);
    fetchMetrics();
    fetchAlerts();
  } catch (err) {
    showToast(`Failed triggering simulation: ${err}`, true);
  }
}

async function runHostScan() {
  try {
    showToast("Executing Host Intrusion & File Integrity Audit...");
    const res = await fetch("/api/scan/host", { method: "POST" });
    const data = await res.json();
    showToast(`Host audit complete: ${data.host_alerts_found} anomaly/integrity issues found.`);
    fetchMetrics();
    fetchAlerts();
  } catch (err) {
    showToast(`Host audit failed: ${err}`, true);
  }
}

async function toggleContinuousSimulation() {
  try {
    const res = await fetch("/api/simulator/toggle", { method: "POST" });
    const data = await res.json();
    isSimulatorRunning = (data.simulator_state === "started");
    updateSimulatorButtonUI();
    showToast(`Continuous Attack Feed ${isSimulatorRunning ? 'Started' : 'Stopped'}.`);
  } catch (err) {
    showToast(`Failed toggling feed: ${err}`, true);
  }
}

function updateSimulatorButtonUI() {
  const btn = document.getElementById("toggleSimulatorBtn");
  const txt = document.getElementById("simulatorBtnText");
  if (isSimulatorRunning) {
    txt.innerText = "Stop Attack Feed";
    btn.style.background = "linear-gradient(135deg, #b91c1c, #991b1b)";
    btn.style.borderColor = "#ef4444";
  } else {
    txt.innerText = "Start Continuous Attack Feed";
    btn.style.background = "linear-gradient(135deg, #0284c7, #0369a1)";
    btn.style.borderColor = "rgba(56, 189, 248, 0.4)";
  }
}

async function unblockIp(ip) {
  try {
    const res = await fetch("/api/blacklist/unblock", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ip })
    });
    const data = await res.json();
    if (data.unblocked) {
      showToast(`IP ${ip} removed from blacklist.`);
      fetchMetrics();
    }
  } catch (err) {
    showToast(`Failed unblocking IP: ${err}`, true);
  }
}

async function clearData() {
  if (!confirm("Are you sure you want to reset all session alerts and metrics?")) return;
  try {
    await fetch("/api/clear", { method: "POST" });
    showToast("Session logs and blacklists cleared.");
    fetchMetrics();
    fetchAlerts();
  } catch (err) {
    showToast(`Failed clearing data: ${err}`, true);
  }
}

function exportReport() {
  window.location.href = "/api/export";
}

function showToast(msg, isError = false) {
  const container = document.getElementById("toastContainer");
  const toast = document.createElement("div");
  toast.className = `toast ${isError ? 'toast-error' : 'toast-success'}`;
  toast.innerText = msg;
  container.appendChild(toast);
  setTimeout(() => {
    toast.remove();
  }, 3500);
}

function escapeHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
