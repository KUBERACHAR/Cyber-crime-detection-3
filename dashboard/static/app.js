/**
 * AI-Based Cyber Crime Observation Device
 * SOC Dashboard — frontend JavaScript
 *
 * Polls /api/status every (interval) seconds, renders live data:
 *  - Threat gauge (SVG arc)
 *  - Metric tiles (CPU, RAM, Procs, File rate, New procs, Connections)
 *  - Threat history chart (canvas, no dependencies)
 *  - Flagged process table + terminate buttons
 *  - Feature vector table
 *  - Action log
 *  - Settings persistence via /api/settings
 */

/* ── State ── */
let _prevScore    = 0;
let _pollTimer    = null;
let _allowTerm    = true;
let _running      = true;
let _threshold    = 0.7;
let _pendingKill  = null;
let _chartHistory = [];

const POLL_INTERVAL_MS = 1500;

/* ── Boot ── */
document.addEventListener("DOMContentLoaded", () => {
  updateClock();
  setInterval(updateClock, 1000);
  fetchAndRender();
  setInterval(fetchAndRender, POLL_INTERVAL_MS);
});

/* ── Clock ── */
function updateClock() {
  const now = new Date();
  const h = String(now.getHours()).padStart(2,"0");
  const m = String(now.getMinutes()).padStart(2,"0");
  const s = String(now.getSeconds()).padStart(2,"0");
  document.getElementById("clock").textContent = `${h}:${m}:${s}`;
}

/* ── Navigation ── */
function showSection(name) {
  document.querySelectorAll(".section").forEach(el => el.classList.remove("active"));
  document.querySelectorAll(".nav-item").forEach(el => el.classList.remove("active"));
  const sec = document.getElementById(`section-${name}`);
  const nav = document.getElementById(`nav-${name}`);
  if (sec) sec.classList.add("active");
  if (nav) nav.classList.add("active");
  document.getElementById("sectionTitle").textContent = {
    dashboard: "Dashboard",
    processes: "Processes",
    features:  "Feature Vector",
    log:       "Action Log",
    settings:  "Settings",
  }[name] || name;
}

function toggleSidebar() {
  document.getElementById("sidebar").classList.toggle("hidden");
  document.body.classList.toggle("sidebar-hidden");
}

/* ── Fetch ── */
async function fetchAndRender() {
  try {
    const res  = await fetch("/api/status");
    if (!res.ok) return;
    const data = await res.json();
    render(data);
  } catch (e) {
    setStatus("error");
  }
}

/* ── Render ── */
function render(d) {
  _allowTerm  = d.allow_terminate;
  _running    = d.running;
  _threshold  = d.threshold;

  setStatus(d.alert ? "alert" : "ok", d.scorer);

  // Topbar
  document.getElementById("watchDirLabel").textContent = `Watching: ${d.watch_dir}`;
  document.getElementById("alertBadge").style.display  = d.alert ? "" : "none";

  // Gauge
  renderGauge(d.score);

  // Alert box
  renderAlertBox(d.alert, d.candidates, d.allow_terminate);

  // Metrics
  const m = d.metrics;
  setMetric("cpu",  m.cpu_pct.toFixed(1)  + "%",  m.cpu_pct);
  setMetric("ram",  m.ram_pct.toFixed(1)  + "%",  m.ram_pct);
  setMetric("procs", m.process_count,             null);
  setMetric("frate", m.file_event_rate.toFixed(1) + "/s", null);
  setMetric("newp",  m.new_process_count,          null);
  setMetric("conn",  m.conn_count,                 null);

  // History chart
  _chartHistory = d.history;
  renderChart(d.history, d.threshold);

  // History count badge
  document.getElementById("historyCount").textContent = `${d.history.length} samples`;

  // Processes tab
  renderFlagged(d.flagged, d.allow_terminate);

  // Features tab
  renderFeatures(d.feature_vec);

  // Log tab
  renderLog(d.actions);

  // Settings tab — sync controls without triggering change events
  syncSettings(d);
}

/* ── Gauge ── */
function renderGauge(score) {
  const pct   = Math.round(score * 100);
  const ARC   = 283; // full half-circle circumference (r=90, π*r ≈ 283)
  const fill  = (score * ARC).toFixed(1);
  const color = score >= 0.7 ? "#ef4444" : score >= 0.4 ? "#f59e0b" : "#22c55e";
  const label = score >= 0.7 ? "HIGH THREAT" : score >= 0.4 ? "ELEVATED" : "NORMAL";

  const arc = document.getElementById("gaugeArc");
  arc.setAttribute("stroke-dasharray", `${fill} ${ARC}`);
  arc.setAttribute("stroke", color);

  const pctEl = document.getElementById("gaugePct");
  const lvlEl = document.getElementById("gaugeLevel");
  pctEl.textContent = pct + "%";
  pctEl.style.color = color;
  lvlEl.textContent = label;
  lvlEl.style.color = color;
  _prevScore = score;
}

/* ── Alert box ── */
function renderAlertBox(alert, candidates, allowTerm) {
  const box     = document.getElementById("alertBox");
  const actions = document.getElementById("alertActions");
  box.style.display = alert ? "" : "none";
  if (!alert) return;

  if (!candidates || candidates.length === 0) {
    actions.innerHTML = `<div style="font-size:0.75rem;color:#94a3b8;padding:4px 0;">
      No specific terminable process identified this window. Review manually.</div>`;
    return;
  }

  actions.innerHTML = candidates.map(proc => `
    <div class="alert-proc-row">
      <span class="alert-proc-name">${proc.name} · PID ${proc.pid} · ${proc.username || "—"}</span>
      <button class="btn-kill" id="kill-${proc.pid}"
        ${allowTerm ? "" : "disabled"}
        onclick="confirmKill(${proc.pid}, '${proc.name}')">Terminate</button>
    </div>
  `).join("");
}

/* ── Metrics ── */
function setMetric(key, display, pct) {
  const valEl = document.getElementById(`val-${key}`);
  const barEl = document.getElementById(`bar-${key}`);
  if (valEl) valEl.textContent = display;
  if (barEl && pct !== null) barEl.style.width = Math.min(pct, 100) + "%";
}

/* ── Canvas chart ── */
function renderChart(history, threshold) {
  const canvas = document.getElementById("historyChart");
  if (!canvas) return;
  const ctx    = canvas.getContext("2d");
  const W      = canvas.offsetWidth  || canvas.parentElement.offsetWidth || 600;
  const H      = canvas.height || 90;
  canvas.width = W;

  ctx.clearRect(0, 0, W, H);

  if (history.length < 2) {
    ctx.fillStyle = "rgba(100,116,139,0.4)";
    ctx.font = "13px Inter, sans-serif";
    ctx.fillText("Collecting data…", W / 2 - 50, H / 2);
    return;
  }

  const n   = history.length;
  const xStep = W / (n - 1);

  // Threshold line
  const ty = H - threshold * H;
  ctx.save();
  ctx.setLineDash([6, 4]);
  ctx.strokeStyle = "rgba(239,68,68,0.4)";
  ctx.lineWidth   = 1;
  ctx.beginPath();
  ctx.moveTo(0, ty);
  ctx.lineTo(W, ty);
  ctx.stroke();
  ctx.restore();

  // Gradient fill
  const grad = ctx.createLinearGradient(0, 0, 0, H);
  grad.addColorStop(0, "rgba(0,229,255,0.25)");
  grad.addColorStop(1, "rgba(0,229,255,0.01)");

  ctx.beginPath();
  history.forEach((v, i) => {
    const x = i * xStep;
    const y = H - v * H;
    i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
  });
  // Close fill path
  ctx.lineTo((n - 1) * xStep, H);
  ctx.lineTo(0, H);
  ctx.closePath();
  ctx.fillStyle = grad;
  ctx.fill();

  // Stroke line
  ctx.beginPath();
  history.forEach((v, i) => {
    const x = i * xStep;
    const y = H - v * H;
    i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
  });
  ctx.strokeStyle = "#00e5ff";
  ctx.lineWidth   = 2.5;
  ctx.lineJoin    = "round";
  ctx.stroke();

  // Latest dot
  const lv = history[n - 1];
  const lx = (n - 1) * xStep;
  const ly = H - lv * H;
  ctx.beginPath();
  ctx.arc(lx, ly, 4, 0, Math.PI * 2);
  ctx.fillStyle   = "#00e5ff";
  ctx.shadowColor = "#00e5ff";
  ctx.shadowBlur  = 8;
  ctx.fill();
  ctx.shadowBlur  = 0;
}

/* ── Flagged process table ── */
function renderFlagged(flagged, allowTerm) {
  const tbody = document.getElementById("flaggedBody");
  const badge = document.getElementById("flaggedCount");
  const notice = document.getElementById("terminateNotice");

  badge.textContent = `${flagged.length} flagged`;
  badge.className   = "card-badge" + (flagged.length ? " danger" : "");
  notice.style.display = (flagged.length && !allowTerm) ? "" : "none";

  if (!flagged.length) {
    tbody.innerHTML = `<tr><td colspan="5" class="empty-cell">No flagged LOLBin processes in this window.</td></tr>`;
    return;
  }
  tbody.innerHTML = flagged.map(p => `
    <tr>
      <td>${p.pid}</td>
      <td>${p.ppid || "—"}</td>
      <td style="color:#f87171">${p.name}</td>
      <td>${p.username || "—"}</td>
      <td>
        <button class="btn-kill" ${allowTerm ? "" : "disabled"}
          onclick="confirmKill(${p.pid}, '${p.name}')">Terminate</button>
      </td>
    </tr>
  `).join("");
}

/* ── Feature vector table ── */
function renderFeatures(vec) {
  const tbody = document.getElementById("featureBody");
  if (!vec || !vec.length) return;
  // Find max value for scaling bars
  const maxVal = Math.max(...vec.map(f => Math.abs(parseFloat(f.value) || 0)), 1);
  tbody.innerHTML = vec.map(f => {
    const v   = parseFloat(f.value) || 0;
    const pct = Math.min((v / maxVal) * 100, 100).toFixed(1);
    return `<tr>
      <td style="color:#94a3b8">${f.feature}</td>
      <td style="color:#00e5ff">${v.toFixed ? v.toFixed(3) : v}</td>
      <td><span class="feat-bar"><span class="feat-fill" style="width:${pct}%"></span></span></td>
    </tr>`;
  }).join("");
}

/* ── Action log ── */
function renderLog(actions) {
  const list  = document.getElementById("logList");
  const badge = document.getElementById("logCount");
  badge.textContent = `${actions.length} entries`;
  if (!actions.length) {
    list.innerHTML = `<div class="log-empty">No actions recorded yet.</div>`;
    return;
  }
  list.innerHTML = [...actions].reverse().map(a =>
    `<div class="log-entry">${a}</div>`
  ).join("");
}

/* ── Settings sync ── */
function syncSettings(d) {
  _syncToggle("liveMon",       d.running);
  _syncToggle("allowTerminate",d.allow_terminate);
  _syncToggle("popupAlerts",   d.popup_alerts);
  _syncSlider("intervalSlider","intervalVal",  d.interval,   v => v + "s");
  _syncSlider("thresholdSlider","thresholdVal",d.threshold,  v => (v*100).toFixed(0)+"%");
  const wdEl = document.getElementById("watchDirInput");
  if (wdEl && document.activeElement !== wdEl) wdEl.value = d.watch_dir;

  // Model status card
  const ms = document.getElementById("modelStatus");
  if (ms) {
    if (d.bundle_error) {
      ms.innerHTML = `<span style="color:#ef4444">⚠ Model failed to load</span><br>
        <span style="font-size:0.72rem;color:#64748b">${d.bundle_error}</span><br><br>
        Using heuristic fallback scorer.`;
    } else if (d.scorer && d.scorer.startsWith("Random Forest")) {
      ms.innerHTML = `<span style="color:#22c55e">✓ Model loaded</span><br>
        <span style="font-size:0.72rem;color:#64748b">${d.scorer}</span>`;
    } else {
      ms.innerHTML = `<span style="color:#f59e0b">⚠ ${d.scorer}</span><br>
        <span style="font-size:0.72rem;color:#64748b">Train model in Colab → commit models/model.pkl</span>`;
    }
  }
}

function _syncToggle(id, val) {
  const el = document.getElementById(id);
  if (el && document.activeElement !== el) el.checked = !!val;
}

function _syncSlider(sliderId, labelId, val, fmt) {
  const el  = document.getElementById(sliderId);
  const lbl = document.getElementById(labelId);
  if (el && document.activeElement !== el) { el.value = val; }
  if (lbl) lbl.textContent = fmt(val);
}

/* ── Status dot ── */
function setStatus(state, scorer) {
  const dot   = document.getElementById("statusDot");
  const label = document.getElementById("statusLabel");
  const sc    = document.getElementById("scorerLabel");
  dot.className = "status-dot " + (state === "alert" ? "alert" : state === "ok" ? "ok" : "loading");
  label.textContent = state === "alert" ? "THREAT DETECTED" : state === "ok" ? "Monitoring" : "Error";
  if (scorer && sc) sc.textContent = scorer;
}

/* ── Save setting ── */
async function saveSetting(key, value) {
  try {
    await fetch("/api/settings", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ [key]: value }),
    });
  } catch (e) { /* silent */ }
}

/* ── Terminate flow ── */
function confirmKill(pid, name) {
  _pendingKill = pid;
  document.getElementById("modalTitle").textContent = `Terminate ${name}?`;
  document.getElementById("modalBody").textContent  =
    `This will send a termination signal to PID ${pid} (${name}). Core system processes are protected. This action will be logged.`;
  document.getElementById("modalConfirmBtn").onclick = () => doKill(pid);
  document.getElementById("confirmModal").style.display = "flex";
}

function closeModal() {
  document.getElementById("confirmModal").style.display = "none";
  _pendingKill = null;
}

async function doKill(pid) {
  closeModal();
  try {
    const res  = await fetch("/api/terminate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ pid }),
    });
    const data = await res.json();
    toast(data.message, data.ok ? "ok" : "err");
    fetchAndRender(); // immediate refresh
  } catch (e) {
    toast("Request failed. Check server.", "err");
  }
}

/* ── Snooze ── */
async function snooze() {
  await fetch("/api/snooze", { method: "POST" });
  toast("Monitoring continues for 30 s without alert.", "ok");
}

/* ── Toast ── */
function toast(msg, type = "ok") {
  const area = document.getElementById("toastArea");
  const el   = document.createElement("div");
  el.className = `toast ${type}`;
  el.textContent = msg;
  area.appendChild(el);
  setTimeout(() => el.remove(), 4000);
}
