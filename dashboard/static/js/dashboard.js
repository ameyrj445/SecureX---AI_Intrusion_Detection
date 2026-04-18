/**
 * dashboard.js — SecureX AI IDS/IPS Dashboard Frontend
 * Real-time Socket.IO client, Chart.js visualizations, alert management.
 */

'use strict';

// ─── State ────────────────────────────────────────────────────────────────────
const state = {
  alerts: [],
  blocked: [],
  popupFeed: [],
  stats: {},
  attackCounts: {},
  ipHitCounts: {},
  severityCounts: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 },
  trafficHistory: [],
  geoAttacks: {},
  connected: false,
  alertsCount: 0,
};

// ─── Chart.js Global Defaults ────────────────────────────────────────────────
Chart.defaults.color = '#7a93b3';
Chart.defaults.borderColor = '#1e2d40';
Chart.defaults.font.family = "'Inter', sans-serif";

const CHART_COLORS = {
  teal:   '#00d2ff',
  blue:   '#4d9fff',
  purple: '#a855f7',
  orange: '#fb923c',
  red:    '#f43f5e',
  green:  '#22d3ee',
  yellow: '#fbbf24',
};

// ─── Charts ───────────────────────────────────────────────────────────────────
let trafficChart, protocolChart, attackChart, pktRateChart, severityChart, topIpChart;

function initCharts() {
  // Traffic Volume (line chart)
  const trafficCtx = document.getElementById('trafficChart').getContext('2d');
  trafficChart = new Chart(trafficCtx, {
    type: 'line',
    data: {
      labels: [],
      datasets: [
        {
          label: 'Packets/min',
          data: [],
          borderColor: CHART_COLORS.teal,
          backgroundColor: 'rgba(0,210,255,0.08)',
          borderWidth: 2,
          fill: true,
          tension: 0.4,
          pointRadius: 0,
        },
        {
          label: 'Alerts',
          data: [],
          borderColor: CHART_COLORS.red,
          backgroundColor: 'rgba(244,63,94,0.08)',
          borderWidth: 2,
          fill: true,
          tension: 0.4,
          pointRadius: 0,
        },
      ],
    },
    options: {
      animation: false,
      responsive: true,
      interaction: { mode: 'index', intersect: false },
      plugins: { legend: { display: false } },
      scales: {
        x: { grid: { color: '#1e2d40' }, ticks: { maxTicksLimit: 8, font: { size: 10 } } },
        y: { grid: { color: '#1e2d40' }, ticks: { font: { size: 10 } }, beginAtZero: true },
      },
    },
  });

  // Protocol Distribution (doughnut)
  const protoCtx = document.getElementById('protocolChart').getContext('2d');
  protocolChart = new Chart(protoCtx, {
    type: 'doughnut',
    data: {
      labels: ['TCP', 'UDP', 'ICMP', 'OTHER'],
      datasets: [{
        data: [0, 0, 0, 0],
        backgroundColor: [CHART_COLORS.teal, CHART_COLORS.purple, CHART_COLORS.orange, CHART_COLORS.blue],
        borderWidth: 0,
        hoverOffset: 5,
      }],
    },
    options: {
      cutout: '65%',
      plugins: {
        legend: { position: 'bottom', labels: { font: { size: 11 }, padding: 12, boxWidth: 10 } }
      },
    },
  });

  // Attack Types (doughnut)
  const attackCtx = document.getElementById('attackChart').getContext('2d');
  attackChart = new Chart(attackCtx, {
    type: 'doughnut',
    data: {
      labels: [],
      datasets: [{
        data: [],
        backgroundColor: [
          CHART_COLORS.red, CHART_COLORS.orange, CHART_COLORS.purple,
          CHART_COLORS.blue, CHART_COLORS.yellow, CHART_COLORS.teal,
        ],
        borderWidth: 0,
      }],
    },
    options: {
      cutout: '65%',
      plugins: {
        legend: { position: 'bottom', labels: { font: { size: 11 }, padding: 10, boxWidth: 10 } }
      },
    },
  });

  // Packet Rate (traffic tab)
  const pktCtx = document.getElementById('pktRateChart').getContext('2d');
  pktRateChart = new Chart(pktCtx, {
    type: 'bar',
    data: {
      labels: [],
      datasets: [{
        label: 'Packets',
        data: [],
        backgroundColor: 'rgba(0,210,255,0.45)',
        borderColor: CHART_COLORS.teal,
        borderWidth: 1,
        borderRadius: 3,
      }],
    },
    options: {
      animation: false, responsive: true,
      plugins: { legend: { display: false } },
      scales: {
        x: { grid: { color: '#1e2d40' }, ticks: { font: { size: 10 }, maxTicksLimit: 12 } },
        y: { grid: { color: '#1e2d40' }, ticks: { font: { size: 10 } }, beginAtZero: true },
      },
    },
  });

  // Severity Distribution (polar area)
  const sevCtx = document.getElementById('severityChart').getContext('2d');
  severityChart = new Chart(sevCtx, {
    type: 'polarArea',
    data: {
      labels: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],
      datasets: [{
        data: [0, 0, 0, 0],
        backgroundColor: [
          'rgba(244,63,94,0.7)',
          'rgba(251,146,60,0.7)',
          'rgba(251,191,36,0.7)',
          'rgba(34,211,238,0.4)',
        ],
        borderWidth: 0,
      }],
    },
    options: {
      plugins: { legend: { position: 'bottom', labels: { font: { size: 11 }, padding: 10, boxWidth: 10 } } },
      scales: { r: { grid: { color: '#1e2d40' }, ticks: { display: false } } },
    },
  });

  // Top Attacking IPs (horizontal bar)
  const topIpCtx = document.getElementById('topIpChart').getContext('2d');
  topIpChart = new Chart(topIpCtx, {
    type: 'bar',
    data: {
      labels: [],
      datasets: [{
        label: 'Alerts',
        data: [],
        backgroundColor: 'rgba(168,85,247,0.5)',
        borderColor: CHART_COLORS.purple,
        borderWidth: 1,
        borderRadius: 3,
      }],
    },
    options: {
      indexAxis: 'y',
      responsive: true,
      plugins: { legend: { display: false } },
      scales: {
        x: { grid: { color: '#1e2d40' }, ticks: { font: { size: 10 } }, beginAtZero: true },
        y: { grid: { display: false }, ticks: { font: { size: 10, family: "'JetBrains Mono', monospace" } } },
      },
    },
  });
}

// ─── Socket.IO ────────────────────────────────────────────────────────────────
const socket = io({ transports: ['websocket', 'polling'] });

socket.on('connect', () => {
  state.connected = true;
  setConnectionStatus(true);
});

socket.on('disconnect', () => {
  state.connected = false;
  setConnectionStatus(false);
});

socket.on('init_data', (data) => {
  if (data.alerts) data.alerts.forEach(a => ingestAlert(a, false));
  if (data.stats) updateStats(data.stats);
  renderAlertsTable();
});

socket.on('new_alert', (alert) => {
  ingestAlert(alert, true);
  showToast(alert);
  renderAlertsTable();
  renderMiniAlerts();
  updateAttackChart();
  updateSeverityChart();
  updateTopIpChart();
});

socket.on('stats_update', (stats) => {
  updateStats(stats);
});

// ─── Connection Status ────────────────────────────────────────────────────────
function setConnectionStatus(connected) {
  const dot = document.getElementById('connection-dot');
  const label = document.getElementById('connection-label');
  if (connected) {
    dot.className = 'status-dot connected';
    label.textContent = 'Connected';
  } else {
    dot.className = 'status-dot error';
    label.textContent = 'Disconnected';
  }
}

// ─── Alert Ingestion ──────────────────────────────────────────────────────────
function ingestAlert(alert, isNew = true) {
  state.alerts.unshift(alert);
  if (state.alerts.length > 500) state.alerts.pop();

  // Track attack type counts
  const at = alert.attack_type || 'Unknown';
  state.attackCounts[at] = (state.attackCounts[at] || 0) + 1;

  // Track IP hit counts
  const ip = alert.src_ip || '';
  state.ipHitCounts[ip] = (state.ipHitCounts[ip] || 0) + 1;

  // Severity counts
  const sev = alert.severity || 'LOW';
  state.severityCounts[sev] = (state.severityCounts[sev] || 0) + 1;

  // Geo
  if (alert.geo && alert.geo.country) {
    const c = alert.geo.country;
    state.geoAttacks[c] = (state.geoAttacks[c] || 0) + 1;
  }

  if (isNew) {
    state.alertsCount++;
    document.getElementById('alert-count').textContent = state.alertsCount;
  }
}

// ─── Stats Update ─────────────────────────────────────────────────────────────
let _prevPkts = 0;
function updateStats(stats) {
  state.stats = stats;

  animateNumber('kpi-total-packets', stats.total_packets || 0);
  animateNumber('kpi-alerts', stats.alerts_today || state.alertsCount);
  animateNumber('kpi-blocked', stats.blocked_count || 0);
  animateNumber('kpi-active-ips', stats.active_ips || 0);

  document.getElementById('blocked-count').textContent = stats.blocked_count || 0;

  // Uptime
  const uptime = stats.uptime || 0;
  const h = Math.floor(uptime / 3600);
  const m = Math.floor((uptime % 3600) / 60);
  const s = uptime % 60;
  document.getElementById('uptime-val').textContent =
    `${h.toString().padStart(2,'0')}:${m.toString().padStart(2,'0')}:${s.toString().padStart(2,'0')}`;

  // Threat level
  const totalAlerts = state.alertsCount;
  let level = 'LOW', lvlClass = '';
  if (totalAlerts > 50) { level = 'CRITICAL'; lvlClass = 'level-critical'; }
  else if (totalAlerts > 20) { level = 'HIGH'; lvlClass = 'level-high'; }
  else if (totalAlerts > 5)  { level = 'MEDIUM'; lvlClass = 'level-medium'; }
  document.getElementById('current-threat-level').textContent = level;
  const badge = document.getElementById('threat-level-badge');
  badge.className = 'threat-level-badge ' + lvlClass;

  // Protocol chart
  const pd = stats.protocol_dist || {};
  protocolChart.data.datasets[0].data = [
    pd.TCP || 0, pd.UDP || 0, pd.ICMP || 0, pd.OTHER || 0
  ];
  protocolChart.update('none');

  // Packet trend indicator
  const curPkts = stats.total_packets || 0;
  const trend = document.getElementById('kpi-pkt-trend');
  if (curPkts > _prevPkts) { trend.className = 'kpi-trend up'; trend.textContent = '↑'; }
  else { trend.className = 'kpi-trend down'; trend.textContent = '→'; }
  _prevPkts = curPkts;

  // Traffic history
  if (stats.traffic_history && stats.traffic_history.length) {
    updateTrafficChart(stats.traffic_history);
  }
}

// ─── Traffic Chart Update ─────────────────────────────────────────────────────
let _localTrafficLabels = [];
let _localTrafficPkts   = [];
let _localTrafficAlerts = [];

function updateTrafficChart(history) {
  const labels = history.map(h => {
    const d = new Date(h.timestamp + (h.timestamp.endsWith('Z') ? '' : 'Z'));
    return d.toLocaleTimeString([], {hour: '2-digit', minute: '2-digit', second: '2-digit'});
  });
  const pkts   = history.map(h => h.total_packets || 0);
  const alerts = history.map(h => h.alerts_count || 0);

  trafficChart.data.labels = labels;
  trafficChart.data.datasets[0].data = pkts;
  trafficChart.data.datasets[1].data = alerts;
  trafficChart.update('none');

  // Packet rate chart (traffic tab)
  if (labels.length > 0) {
    pktRateChart.data.labels = labels.slice(-20);
    pktRateChart.data.datasets[0].data = pkts.slice(-20);
    pktRateChart.update('none');
  }
}

// Live traffic injection (called every 3s when no history available)
function injectLiveTrafficPoint() {
  const now = new Date().toLocaleTimeString([], {hour:'2-digit',minute:'2-digit',second:'2-digit'});
  const pkts = state.stats.total_packets || 0;
  const alts = state.alertsCount;

  _localTrafficLabels.push(now);
  _localTrafficPkts.push(pkts);
  _localTrafficAlerts.push(alts);

  if (_localTrafficLabels.length > 40) {
    _localTrafficLabels.shift();
    _localTrafficPkts.shift();
    _localTrafficAlerts.shift();
  }

  trafficChart.data.labels = _localTrafficLabels;
  trafficChart.data.datasets[0].data = _localTrafficPkts;
  trafficChart.data.datasets[1].data = _localTrafficAlerts;
  trafficChart.update('none');
}

// ─── Attack Type Chart ────────────────────────────────────────────────────────
function updateAttackChart() {
  const entries = Object.entries(state.attackCounts).sort((a,b) => b[1]-a[1]).slice(0,6);
  attackChart.data.labels   = entries.map(e => e[0]);
  attackChart.data.datasets[0].data = entries.map(e => e[1]);
  attackChart.update('none');
}

// ─── Severity Chart ───────────────────────────────────────────────────────────
function updateSeverityChart() {
  const sc = state.severityCounts;
  severityChart.data.datasets[0].data = [sc.CRITICAL, sc.HIGH, sc.MEDIUM, sc.LOW];
  severityChart.update('none');
}

// ─── Top IPs Chart ────────────────────────────────────────────────────────────
function updateTopIpChart() {
  const entries = Object.entries(state.ipHitCounts).sort((a,b) => b[1]-a[1]).slice(0,8);
  topIpChart.data.labels = entries.map(e => e[0]);
  topIpChart.data.datasets[0].data = entries.map(e => e[1]);
  topIpChart.update('none');
}

// ─── Alerts Table ─────────────────────────────────────────────────────────────
let _allAlerts = [];
function renderAlertsTable() {
  _allAlerts = [...state.alerts];
  filterAlerts();
}

function filterAlerts() {
  const search = document.getElementById('alert-search').value.toLowerCase();
  const sevFilter = document.getElementById('severity-filter').value;
  let filtered = _allAlerts;

  if (search) {
    filtered = filtered.filter(a =>
      (a.src_ip || '').includes(search) ||
      (a.attack_type || '').toLowerCase().includes(search)
    );
  }
  if (sevFilter) {
    filtered = filtered.filter(a => a.severity === sevFilter);
  }

  const tbody = document.getElementById('alerts-tbody');
  if (!filtered.length) {
    tbody.innerHTML = '<tr><td colspan="9" class="empty-cell">No alerts matching your filter</td></tr>';
    return;
  }

  tbody.innerHTML = filtered.slice(0, 100).map(a => {
    const score = Math.round(a.threat_score || 0);
    const scoreColor = score > 80 ? '#f43f5e' : score > 60 ? '#fb923c' : score > 30 ? '#fbbf24' : '#22d3ee';
    const geo = a.geo || {};
    const blocked = a.blocked;
    return `
      <tr onclick="showAlertDetail(${state.alerts.indexOf(a)})" style="cursor:pointer">
        <td>${formatTime(a.timestamp)}</td>
        <td class="ip-cell">${esc(a.src_ip || '-')}</td>
        <td><strong>${esc(a.attack_type || '-')}</strong></td>
        <td><span class="sev-badge sev-${a.severity}">${a.severity || '-'}</span></td>
        <td>
          <div class="score-cell">
            <div class="score-bar"><div class="score-fill" style="width:${score}%;background:${scoreColor}"></div></div>
            <span style="font-family:monospace;font-size:11px">${score}</span>
          </div>
        </td>
        <td>${Math.round((a.confidence || 0) * 100)}%</td>
        <td>${esc(geo.city || '?')}, ${esc(geo.country_code || '?')}</td>
        <td><span style="font-size:10px;padding:2px 6px;background:rgba(255,255,255,.06);border-radius:4px">${esc(a.source || '-')}</span></td>
        <td>
          ${blocked ? '' : `<button class="btn-danger" onclick="event.stopPropagation();blockIp('${esc(a.src_ip)}')">Block</button>`}
        </td>
      </tr>
    `;
  }).join('');
}

// ─── Mini Alert List ──────────────────────────────────────────────────────────
function renderMiniAlerts() {
  const container = document.getElementById('mini-alert-list');
  const recent = state.alerts.slice(0, 8);
  if (!recent.length) {
    container.innerHTML = '<div class="empty-state-mini">No alerts yet — system is monitoring...</div>';
    return;
  }
  container.innerHTML = recent.map(a => `
    <div class="mini-alert-item">
      <span class="sev-badge sev-${a.severity}">${a.severity}</span>
      <span class="mini-ip">${esc(a.src_ip)}</span>
      <span class="mini-type">${esc(a.attack_type)}</span>
      <span class="mini-time">${formatTime(a.timestamp)}</span>
    </div>
  `).join('');
}

// ─── Blocked IPs ──────────────────────────────────────────────────────────────
function pushPopupFeed(entry) {
  state.popupFeed.unshift(entry);
  if (state.popupFeed.length > 20) state.popupFeed.pop();
}

function renderPopupFeed() {
  const container = document.getElementById('popup-feed-list');
  if (!container) return;

  const entries = state.popupFeed.length
    ? state.popupFeed
    : state.alerts.slice(0, 6).map(alert => ({
        attack_type: alert.attack_type,
        src_ip: alert.src_ip,
        severity: alert.severity || 'HIGH',
        threat_score: alert.threat_score,
        geo: alert.geo,
        timestamp: alert.timestamp,
      }));

  if (!entries.length) {
    container.innerHTML = '<div class="empty-state-mini">Popup notifications will appear here as new alerts arrive.</div>';
    return;
  }

  container.innerHTML = entries.map(entry => {
    const severity = (entry.severity || 'HIGH').toLowerCase();
    const location = entry.geo?.country || entry.geo?.country_code || entry.location || 'Live event';
    const scoreMarkup = entry.threat_score !== undefined && entry.threat_score !== null
      ? `<span class="popup-feed-score">Score ${Math.round(entry.threat_score)}</span>`
      : '';

    return `
      <div class="popup-feed-item ${severity}">
        <div class="popup-feed-head">
          <span class="popup-feed-title">${esc(entry.attack_type || 'Notification')}</span>
          <span class="sev-badge sev-${entry.severity || 'HIGH'}">${entry.severity || 'HIGH'}</span>
        </div>
        <div class="popup-feed-meta">
          <span class="popup-feed-ip">${esc(entry.src_ip || '')}</span>
          <span>${esc(location)}</span>
          ${scoreMarkup}
          <span class="popup-feed-time">${formatTime(entry.timestamp || new Date().toISOString())}</span>
        </div>
      </div>
    `;
  }).join('');
}

function clearPopupFeed() {
  state.popupFeed = [];
  renderPopupFeed();
}

async function refreshBlocked() {
  const res = await fetch('/api/blocked');
  const data = await res.json();
  state.blocked = data;
  renderBlockedTable();
}

function renderBlockedTable() {
  const tbody = document.getElementById('blocked-tbody');
  if (!state.blocked.length) {
    tbody.innerHTML = '<tr><td colspan="7" class="empty-cell">No IPs currently blocked.</td></tr>';
    return;
  }
  tbody.innerHTML = state.blocked.map(b => `
    <tr>
      <td class="ip-cell">${esc(b.ip)}</td>
      <td>${formatTime(b.blocked_at)}</td>
      <td>${b.unblock_at ? formatTime(b.unblock_at) : '<span style="color:#f43f5e">Permanent</span>'}</td>
      <td>${esc(b.reason || '-')}</td>
      <td>${esc(b.country || '-')}</td>
      <td>${esc(b.city || '-')}</td>
      <td><button class="btn-success" onclick="unblockIp('${esc(b.ip)}')">Unblock</button></td>
    </tr>
  `).join('');
}

async function unblockIp(ip) {
  if (!confirm(`Unblock ${ip}?`)) return;
  const res = await fetch(`/api/unblock/${ip}`, { method: 'POST' });
  const data = await res.json();
  if (data.success) {
    showToast({ attack_type: 'Unblocked', src_ip: ip, severity: 'LOW' }, 'success');
    refreshBlocked();
  }
}

async function blockIp(ip) {
  const res = await fetch(`/api/block/${ip}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ reason: 'Manual block via dashboard' }),
  });
  const data = await res.json();
  if (data.success) {
    showToast({ attack_type: 'Blocked', src_ip: ip, severity: 'HIGH' }, 'block');
    refreshBlocked();
  }
}

// ─── Alert Detail Modal ───────────────────────────────────────────────────────
function showAlertDetail(idx) {
  const a = state.alerts[idx];
  if (!a) return;
  const geo = a.geo || {};
  const details = a.details || {};

  document.getElementById('modal-title').textContent = `${a.attack_type} — ${a.src_ip}`;
  document.getElementById('modal-body').innerHTML = `
    <div class="detail-row"><span class="detail-key">Timestamp</span><span class="detail-val">${esc(a.timestamp)}</span></div>
    <div class="detail-row"><span class="detail-key">Source IP</span><span class="detail-val" style="color:#00d2ff">${esc(a.src_ip)}</span></div>
    <div class="detail-row"><span class="detail-key">Attack Type</span><span class="detail-val"><strong>${esc(a.attack_type)}</strong></span></div>
    <div class="detail-row"><span class="detail-key">Severity</span><span class="detail-val"><span class="sev-badge sev-${a.severity}">${a.severity}</span></span></div>
    <div class="detail-row"><span class="detail-key">Threat Score</span><span class="detail-val">${Math.round(a.threat_score || 0)} / 100</span></div>
    <div class="detail-row"><span class="detail-key">Confidence</span><span class="detail-val">${Math.round((a.confidence || 0)*100)}%</span></div>
    <div class="detail-row"><span class="detail-key">Detection Source</span><span class="detail-val">${esc(a.source || '-')}</span></div>
    <div class="detail-row"><span class="detail-key">Location</span><span class="detail-val">${esc(geo.city||'?')}, ${esc(geo.country||'?')} (${esc(geo.country_code||'?')})</span></div>
    <div class="detail-row"><span class="detail-key">ISP</span><span class="detail-val">${esc(geo.isp||'Unknown')}</span></div>
    <div class="detail-row"><span class="detail-key">Coordinates</span><span class="detail-val">${geo.lat || 0}, ${geo.lon || 0}</span></div>
    <div style="margin-top:10px"><div class="detail-key" style="margin-bottom:6px">Detection Details</div>
    <div class="detail-pre">${esc(JSON.stringify(details, null, 2))}</div></div>
  `;
  document.getElementById('alert-modal').classList.remove('hidden');
}

function closeModal() {
  document.getElementById('alert-modal').classList.add('hidden');
}

document.getElementById('alert-modal').addEventListener('click', (e) => {
  if (e.target === e.currentTarget) closeModal();
});

// ─── Toast Notifications ──────────────────────────────────────────────────────
function showToast(alert, type = 'alert') {
  const container = document.getElementById('toast-container');
  const severity = alert.severity || 'HIGH';
  const cls = severity === 'CRITICAL' ? 'critical' : severity === 'MEDIUM' ? 'medium' : '';
  const popupEntry = {
    attack_type: alert.attack_type || (type === 'success' ? 'Success' : 'Notification'),
    src_ip: alert.src_ip || '',
    severity,
    threat_score: alert.threat_score,
    geo: alert.geo,
    location: type === 'success' ? 'Dashboard action' : '',
    timestamp: alert.timestamp || new Date().toISOString(),
  };

  pushPopupFeed(popupEntry);
  renderPopupFeed();

  const toast = document.createElement('div');
  toast.className = `toast ${cls}`;
  toast.innerHTML = `
    <div class="toast-header">
      <span class="toast-title">🚨 ${esc(alert.attack_type)}</span>
      <span class="sev-badge sev-${severity}">${severity}</span>
    </div>
    <div class="toast-ip">${esc(alert.src_ip || '')}</div>
    <div class="toast-body">${esc(alert.geo?.country || '')} ${alert.threat_score ? `• Score: ${Math.round(alert.threat_score)}` : ''}</div>
  `;

  container.appendChild(toast);

  setTimeout(() => {
    toast.style.animation = 'toastOut .3s ease forwards';
    setTimeout(() => toast.remove(), 300);
  }, 5000);
}

// ─── Threat Map ───────────────────────────────────────────────────────────────
const GEO_POS = {
  US: [215, 140], CN: [690, 140], RU: [600, 90], DE: [475, 100],
  GB: [445, 100], IN: [620, 180], BR: [240, 290], KP: [730, 130],
  IR: [575, 155], NG: [470, 220], FR: [455, 110], JP: [750, 140],
  AU: [760, 310], CA: [180, 110], MX: [170, 175], AR: [220, 340],
  ZA: [510, 310], EG: [530, 170], PK: [608, 168], UA: [520, 100],
};

function updateThreatMap() {
  const svgDots = document.getElementById('attack-dots');
  const svgLines = document.getElementById('attack-lines');
  const originList = document.getElementById('origin-list');

  // Target: center of USA (destination)
  const TX = 215, TY = 140;

  const sortedGeo = Object.entries(state.geoAttacks).sort((a,b) => b[1]-a[1]);

  // Clear previous
  svgDots.innerHTML = '';
  svgLines.innerHTML = '';

  sortedGeo.slice(0, 15).forEach(([country, count]) => {
    const code = Object.keys(GEO_POS).find(k =>
      country.toLowerCase().includes(k.toLowerCase()) ||
      k === country.substring(0, 2).toUpperCase()
    );
    const pos = GEO_POS[code] || [Math.random()*900+50, Math.random()*400+50];
    const [x, y] = pos;

    const color = count > 10 ? '#f43f5e' : count > 5 ? '#fb923c' : '#fbbf24';
    const r = Math.min(3 + count * 0.5, 12);

    // Animated attack dot
    svgDots.innerHTML += `
      <circle cx="${x}" cy="${y}" r="${r}" fill="${color}" opacity="0.8">
        <animate attributeName="r" values="${r};${r+5};${r}" dur="2s" repeatCount="indefinite"/>
        <animate attributeName="opacity" values="0.8;0.4;0.8" dur="2s" repeatCount="indefinite"/>
      </circle>
      <circle cx="${x}" cy="${y}" r="${r-1}" fill="${color}"/>
    `;

    // Attack line
    svgLines.innerHTML += `
      <line x1="${x}" y1="${y}" x2="${TX}" y2="${TY}"
        stroke="${color}" stroke-width="0.8" stroke-dasharray="4 4" opacity="0.4">
        <animate attributeName="stroke-dashoffset" from="0" to="16" dur="1s" repeatCount="indefinite"/>
      </line>
    `;
  });

  // Origin list
  if (!sortedGeo.length) {
    originList.innerHTML = '<div class="empty-state-mini">No geo data available yet</div>';
    return;
  }
  originList.innerHTML = sortedGeo.slice(0, 10).map(([country, count]) => `
    <div class="origin-item">
      <span class="origin-country">${esc(country)}</span>
      <span class="origin-count">${count} attack${count > 1 ? 's' : ''}</span>
    </div>
  `).join('');
}

// ─── Tab Navigation ───────────────────────────────────────────────────────────
function switchTab(tabName, el) {
  document.querySelectorAll('.tab-section').forEach(s => s.classList.add('hidden'));
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));

  document.getElementById(`tab-${tabName}`).classList.remove('hidden');
  if (el) el.classList.add('active');

  const titles = {
    dashboard: 'System Dashboard',
    alerts: 'Live Intrusion Alerts',
    blocked: 'Blocked IP Addresses',
    traffic: 'Traffic Analysis',
    map: 'Global Threat Map',
  };
  document.getElementById('page-heading').textContent = titles[tabName] || 'Dashboard';

  if (tabName === 'blocked') refreshBlocked();
  if (tabName === 'map') updateThreatMap();
  if (tabName === 'traffic') {
    updateTopIpChart();
    updateSeverityChart();
  }

  return false;
}

// ─── Utilities ────────────────────────────────────────────────────────────────
function esc(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}

function formatTime(ts) {
  if (!ts) return '-';
  const d = new Date(ts.endsWith('Z') ? ts : ts + 'Z');
  return d.toLocaleTimeString([], {hour: '2-digit', minute: '2-digit', second: '2-digit'});
}

function animateNumber(id, target) {
  const el = document.getElementById(id);
  if (!el) return;
  const current = parseInt(el.textContent.replace(/,/g, '')) || 0;
  if (current === target) return;
  const step = Math.ceil(Math.abs(target - current) / 10);
  const interval = setInterval(() => {
    const cur = parseInt(el.textContent.replace(/,/g, '')) || 0;
    if (Math.abs(cur - target) <= step) {
      el.textContent = target.toLocaleString();
      clearInterval(interval);
    } else {
      el.textContent = (cur + (target > cur ? step : -step)).toLocaleString();
    }
  }, 30);
}

// ─── Live Clock ───────────────────────────────────────────────────────────────
function updateClock() {
  document.getElementById('clock').textContent = new Date().toLocaleTimeString();
}
setInterval(updateClock, 1000);
updateClock();

// ─── Particle Animation ───────────────────────────────────────────────────────
function createParticles() {
  const container = document.getElementById('particles');
  for (let i = 0; i < 20; i++) {
    const p = document.createElement('div');
    p.className = 'particle';
    p.style.left = Math.random() * 100 + '%';
    p.style.animationDuration = (15 + Math.random() * 20) + 's';
    p.style.animationDelay = (Math.random() * 10) + 's';
    p.style.opacity = Math.random() * 0.6;
    container.appendChild(p);
  }
}

// ─── Periodic Data Refresh ────────────────────────────────────────────────────
async function fetchInitialData() {
  try {
    const [alertsRes, statsRes] = await Promise.all([
      fetch('/api/alerts?limit=100'),
      fetch('/api/stats'),
    ]);
    const alerts = await alertsRes.json();
    const stats  = await statsRes.json();

    alerts.forEach(a => ingestAlert(a, false));
    updateStats(stats);
    renderAlertsTable();
    renderMiniAlerts();
    renderPopupFeed();
    updateAttackChart();
    updateSeverityChart();
    updateTopIpChart();
  } catch (e) {
    console.warn('Initial data fetch failed:', e);
  }
}

// ─── Init ─────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  initCharts();
  createParticles();
  fetchInitialData();

  // Live traffic injection every 5s (supplement Socket.IO)
  setInterval(injectLiveTrafficPoint, 5000);

  // Refresh threat map every 15s if on that tab
  setInterval(() => {
    const mapTab = document.getElementById('tab-map');
    if (!mapTab.classList.contains('hidden')) updateThreatMap();
  }, 15000);

  // Poll replay status every 3s
  setInterval(pollReplayStatus, 3000);
});

// ─── Tab Navigation (patched to include replay) ───────────────────────────────
function switchTab(tabName, el) {
  document.querySelectorAll('.tab-section').forEach(s => s.classList.add('hidden'));
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));

  document.getElementById(`tab-${tabName}`).classList.remove('hidden');
  if (el) el.classList.add('active');

  const titles = {
    dashboard: 'System Dashboard',
    alerts:    'Live Intrusion Alerts',
    blocked:   'Blocked IP Addresses',
    traffic:   'Traffic Analysis',
    map:       'Global Threat Map',
    replay:    'Dataset Replay Mode',
  };
  document.getElementById('page-heading').textContent = titles[tabName] || 'Dashboard';

  if (tabName === 'blocked') refreshBlocked();
  if (tabName === 'map')     updateThreatMap();
  if (tabName === 'traffic') { updateTopIpChart(); updateSeverityChart(); }
  if (tabName === 'replay')  pollReplayStatus();

  return false;
}

// ════════════════════════ DATASET REPLAY ════════════════════════

// SocketIO events for replay
socket.on('replay_status', (data) => { applyReplayStats(data); });
socket.on('replay_stats',  (data) => { applyReplayStats(data); });

// Also route replay alerts to the replay tab feed
socket.on('new_alert', (alert) => {
  if (alert.source === 'replay') {
    addReplayAlertItem(alert);
  }
});

const _replayAlerts = [];

function addReplayAlertItem(alert) {
  _replayAlerts.unshift(alert);
  if (_replayAlerts.length > 50) _replayAlerts.pop();

  const container = document.getElementById('replay-alert-list');
  if (!container) return;

  const dot = document.getElementById('replay-live-dot');
  if (dot) dot.classList.add('active');

  container.innerHTML = _replayAlerts.slice(0, 12).map(a => `
    <div class="mini-alert-item">
      <span class="sev-badge sev-${a.severity}">${a.severity}</span>
      <span class="mini-ip">${esc(a.src_ip)}</span>
      <span class="mini-type">${esc(a.attack_type)}</span>
      <span class="mini-time">${formatTime(a.timestamp)}</span>
    </div>
  `).join('');
}

function applyReplayStats(data) {
  if (!data) return;

  const status = (data.status || 'idle').toUpperCase();

  // Status pill
  const pill = document.getElementById('replay-status-pill');
  if (pill) {
    pill.textContent = status;
    pill.className = 'replay-status-pill ' + (data.status || 'idle');
  }

  // Sidebar badge
  const badge = document.getElementById('replay-badge');
  if (badge) {
    badge.style.display = data.status === 'running' ? 'inline-block' : 'none';
  }

  // Buttons
  const isRunning = data.status === 'running';
  const isPaused  = data.status === 'paused';
  const isActive  = isRunning || isPaused;

  const btnPlay  = document.getElementById('btn-replay-play');
  const btnPause = document.getElementById('btn-replay-pause');
  const btnStop  = document.getElementById('btn-replay-stop');

  if (btnPlay)  btnPlay.disabled  = isRunning;
  if (btnPause) { btnPause.disabled = !isRunning; btnPause.textContent = isPaused ? '▶ Resume' : '⏸ Pause'; }
  if (btnStop)  btnStop.disabled  = !isActive;

  // Live dot
  const dot = document.getElementById('replay-live-dot');
  if (dot) dot.classList.toggle('active', isRunning);

  // Progress
  const pct = data.progress_pct || 0;
  const bar = document.getElementById('replay-progress-bar');
  const pctLabel = document.getElementById('replay-pct');
  if (bar) bar.style.width = pct + '%';
  if (pctLabel) pctLabel.textContent = pct + '%';

  // Current file
  const fileEl = document.getElementById('replay-current-file');
  if (fileEl && data.current_file) fileEl.textContent = data.current_file;

  // Stats
  if (data.rows_processed !== undefined) animateNumber('rstat-processed', data.rows_processed);
  if (data.attacks_found  !== undefined) animateNumber('rstat-attacks',   data.attacks_found);
  if (data.benign_found   !== undefined) animateNumber('rstat-benign',    data.benign_found);
  if (data.speed !== undefined) {
    document.getElementById('rstat-speed').textContent = data.speed + 'x';
  }
}

async function replayStart() {
  const speed       = parseInt(document.getElementById('speed-slider').value) || 1;
  const attacksOnly = document.getElementById('attacks-only-toggle').checked;

  const res = await fetch('/api/replay/start', {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body:    JSON.stringify({ speed, attacks_only: attacksOnly }),
  });
  const data = await res.json();
  if (data.success) {
    applyReplayStats(data.stats);
    // Clear previous replay alerts
    _replayAlerts.length = 0;
    document.getElementById('replay-alert-list').innerHTML =
      '<div class="empty-state-mini">Replay started — detections will appear here...</div>';
  } else {
    alert('Replay failed: ' + (data.error || 'Unknown error'));
  }
}

async function replayPause() {
  const pill = document.getElementById('replay-status-pill');
  const isPaused = pill && pill.textContent === 'PAUSED';
  const url = isPaused ? '/api/replay/start' : '/api/replay/pause';
  await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
  pollReplayStatus();
}

async function replayStop() {
  await fetch('/api/replay/stop', { method: 'POST' });
  applyReplayStats({ status: 'idle', progress_pct: 0 });
  const dot = document.getElementById('replay-live-dot');
  if (dot) dot.classList.remove('active');
}

async function replaySetSpeed(val) {
  const speed = parseInt(val) || 1;
  document.getElementById('speed-label').textContent = speed + 'x';
  document.getElementById('rstat-speed').textContent = speed + 'x';
  await fetch('/api/replay/speed', {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body:    JSON.stringify({ speed }),
  });
}

function updateSpeedLabel(val) {
  document.getElementById('speed-label').textContent = val + 'x';
}

async function pollReplayStatus() {
  try {
    const res  = await fetch('/api/replay/status');
    const data = await res.json();
    applyReplayStats(data);
  } catch (e) { /* ignore */ }
}
