/* ================================================================
   ThreatScope Dashboard — JavaScript
   ================================================================ */

'use strict';

// ----------------------------------------------------------------
// CONFIG
// ----------------------------------------------------------------
const API_BASE   = 'http://127.0.0.1:5000/api';
let isLiveMode   = false;
const SEV_COLORS = {
  Low:      '#22c55e',
  Medium:   '#f59e0b',
  High:     '#f97316',
  Critical: '#ef4444',
};
const STAGE_LABELS = {
  NORMAL:               'Normal',
  RECONNAISSANCE:       'Recon',
  INITIAL_ACCESS:       'Initial Access',
  COMMAND_AND_CONTROL:  'C2',
  LATERAL_MOVEMENT:     'Lateral Move',
  IMPACT:               'Impact',
};

const STAGE_DESCRIPTIONS = {
  NORMAL:               'Normal Traffic: No attack activity detected.',
  RECONNAISSANCE:       'Recon: Attacker is gathering info and scanning for vulnerabilities.',
  INITIAL_ACCESS:       'Initial Access: Attacker is trying to break into the network.',
  COMMAND_AND_CONTROL:  'C2: Attacker compromised a system and communicates with it remotely.',
  LATERAL_MOVEMENT:     'Lateral Move: Attacker is moving through the internal network.',
  IMPACT:               'Impact: Attacker is disrupting services or destroying data.',
};

// ----------------------------------------------------------------
// STATE
// ----------------------------------------------------------------
let alertCount   = 0;
let historyData  = [];
let demoStream   = null;
let timelineData = [];  // {score, severity, ts}
let timelineCtx  = null;

// ----------------------------------------------------------------
// INIT
// ----------------------------------------------------------------
document.addEventListener('DOMContentLoaded', () => {
  initClock();
  initTimeline();
  pollStatus();
  setInterval(pollStatus, 10000);
});

// ----------------------------------------------------------------
// CLOCK
// ----------------------------------------------------------------
function initClock() {
  const el = document.getElementById('navTime');
  function tick() {
    const now = new Date();
    el.textContent = now.toLocaleTimeString('en-GB', { hour12: false });
  }
  tick();
  setInterval(tick, 1000);
}

// ----------------------------------------------------------------
// STATUS POLL
// ----------------------------------------------------------------
async function pollStatus() {
  try {
    const res  = await fetch(`${API_BASE}/status`);
    const data = await res.json();

    setDot('statusPipeline', data.pipeline_ready ? 'ok' : 'error');
    setDot('statusXgb',      data.xgb_available  ? 'ok' : 'warning');
    setDot('statusIF',       data.models_present?.isolation_forest ? 'ok' : 'error');
  } catch {
    setDot('statusPipeline', 'error');
    setDot('statusXgb',      'error');
    setDot('statusIF',       'error');
  }
}

function setDot(id, state) {
  const el = document.querySelector(`#${id} .status-dot`);
  if (!el) return;
  el.className = 'status-dot dot-' + state;
}

// ----------------------------------------------------------------
// DEMO / LIVE REPLAY
// ----------------------------------------------------------------
function toggleMode() {
  const toggle = document.getElementById('modeToggle');
  const label = document.getElementById('modeLabel');
  const btn = document.getElementById('btnStartDemo');
  
  isLiveMode = toggle.checked;
  if (isLiveMode) {
    label.textContent = "Live Feed";
    btn.textContent = "▶ Start Live Tail";
    document.getElementById('demoStatusText').textContent = 'Live Feed Ready';
  } else {
    label.textContent = "Demo Mode";
    btn.textContent = "▶ Start Demo Replay";
    document.getElementById('demoStatusText').textContent = 'Demo Ready';
  }
  
  // Stop current stream if running
  if (demoStream) stopDemo();
}

function startDemo() {
  if (demoStream) demoStream.close();

  document.getElementById('btnStartDemo').disabled = true;
  document.getElementById('btnStopDemo').disabled  = false;
  document.getElementById('demoDot').classList.add('running');
  
  const endpoint = isLiveMode ? '/live/stream' : '/demo/stream';
  document.getElementById('demoStatusText').textContent = isLiveMode ? 'Listening for live traffic…' : 'Replay Running…';

  demoStream = new EventSource(`${API_BASE}${endpoint}`);

  demoStream.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data);
      if (data.event === 'connected') return;
      if (data.event === 'replay_complete') {
        stopDemo();
        document.getElementById('demoStatusText').textContent = 'Replay Complete ✓';
        return;
      }
      if (data.event === 'error') {
        console.error('Demo stream error:', data.message);
        return;
      }
      ingestResult(data);
    } catch (e) {
      console.error('Parse error:', e);
    }
  };

  demoStream.onerror = () => {
    stopDemo();
    document.getElementById('demoStatusText').textContent = 'Stream Error';
  };
}

function stopDemo() {
  if (demoStream) { demoStream.close(); demoStream = null; }
  document.getElementById('btnStartDemo').disabled = false;
  document.getElementById('btnStopDemo').disabled  = true;
  document.getElementById('demoDot').classList.remove('running');
}

// ----------------------------------------------------------------
// INGEST A PIPELINE RESULT
// ----------------------------------------------------------------
function ingestResult(r) {
  // Update all panels
  updateRiskGauge(r.risk.score, r.risk.severity, r.risk.breakdown);
  updateClassification(r.attack_label, r.confidence, r.anomaly_score);
  updateMitre(r.mitre);
  updateChain(r.attack_chain);
  updateRecommendations(r.recommendations, r.disclaimer);
  updateFeatures(r.features);
  addAlert(r);
  addHistory(r);
  pushTimeline(r.risk.score, r.risk.severity, r.timestamp);
}

// ----------------------------------------------------------------
// RISK GAUGE
// ----------------------------------------------------------------
function updateRiskGauge(score, severity, breakdown) {
  const color   = SEV_COLORS[severity] || '#00d4ff';
  const arcLen  = 173;
  const offset  = arcLen * (1 - score / 100);
  const degrees = -90 + (score / 100) * 180;

  const arc    = document.getElementById('riskArc');
  const needle = document.getElementById('riskNeedle');
  const num    = document.getElementById('riskNumber');
  const lbl    = document.getElementById('riskLabel');

  arc.style.strokeDashoffset = offset;
  arc.style.stroke           = color;
  needle.style.transform     = `rotate(${degrees}deg)`;

  num.textContent = score;
  num.className   = 'risk-number sev-' + severity.toLowerCase();
  lbl.textContent = severity;
  lbl.className   = 'risk-label sev-' + severity.toLowerCase();

  // Breakdown bars (max values from engine: anom=20, attack=35, conf=15, stage=15, next=15)
  const maxes = { brkAnomaly: 20, brkAttack: 35, brkConf: 15, brkStage: 15, brkNext: 15 };
  const keys  = {
    brkAnomaly: 'anomaly_score_component',
    brkAttack:  'attack_type_component',
    brkConf:    'confidence_component',
    brkStage:   'stage_component',
    brkNext:    'next_stage_component',
  };
  for (const [elId, maxVal] of Object.entries(maxes)) {
    const val = breakdown[keys[elId]] || 0;
    const pct = Math.min(100, (val / maxVal) * 100);
    const bar = document.getElementById(elId);
    if (bar) {
      bar.style.width      = pct + '%';
      bar.style.background = color;
    }
  }
}

// ----------------------------------------------------------------
// CLASSIFICATION
// ----------------------------------------------------------------
function updateClassification(label, confidence, anomalyScore) {
  document.getElementById('classLabel').textContent = label;
  const pct = Math.round((confidence || 0) * 100);
  document.getElementById('confBar').style.width = pct + '%';
  document.getElementById('confPct').textContent  = pct + '%';
  document.getElementById('anomalyBadge').textContent = (anomalyScore || 0).toFixed(4);
}

// ----------------------------------------------------------------
// MITRE
// ----------------------------------------------------------------
function updateMitre(mitre) {
  document.getElementById('mitreTactic').textContent = mitre.tactic || '–';
  const techName = mitre.technique_id
    ? `${mitre.technique_id} — ${mitre.technique_name}`
    : (mitre.technique_name || '–');
  document.getElementById('mitreTech').textContent = techName;
  const linkEl = document.getElementById('mitreLink');
  if (mitre.reference) {
    linkEl.href = mitre.reference;
    linkEl.style.display = '';
  } else {
    linkEl.style.display = 'none';
  }
}

// ----------------------------------------------------------------
// ATTACK CHAIN
// ----------------------------------------------------------------
function updateChain(chain) {
  const current   = chain.current_stage;
  const predicted = chain.next_stage;

  document.querySelectorAll('.chain-stage').forEach(el => {
    const s = el.dataset.stage;
    el.className = 'chain-stage ' + (
      s === current   ? 'active' :
      s === predicted ? 'predicted' :
                        'inactive'
    );
  });

  const nextLabel = STAGE_LABELS[chain.next_stage] || chain.next_stage;
  const nextDesc  = STAGE_DESCRIPTIONS[chain.next_stage] || '';
  
  const nextEl = document.getElementById('predNext');
  nextEl.textContent = nextLabel;
  if (nextDesc) {
      nextEl.setAttribute('data-tooltip', nextDesc);
  } else {
      nextEl.removeAttribute('data-tooltip');
  }
  
  document.getElementById('predNextProb').textContent  = Math.round((chain.next_probability || 0) * 100) + '%';
  
  const altLabel = STAGE_LABELS[chain.alt_stage] || chain.alt_stage || '–';
  const altDesc  = STAGE_DESCRIPTIONS[chain.alt_stage] || '';
  
  const altEl = document.getElementById('predAlt');
  altEl.textContent = altLabel;
  if (altDesc) {
      altEl.setAttribute('data-tooltip', altDesc);
  } else {
      altEl.removeAttribute('data-tooltip');
  }
  
  document.getElementById('predAltProb').textContent   = chain.alt_stage
    ? Math.round((chain.alt_probability || 0) * 100) + '%' : '–';
}

// ----------------------------------------------------------------
// RECOMMENDATIONS
// ----------------------------------------------------------------
function updateRecommendations(actions, disclaimer) {
  const list = document.getElementById('recsList');
  list.innerHTML = '';

  if (!actions || actions.length === 0) {
    list.innerHTML = '<p class="recs-empty">No recommendations.</p>';
    return;
  }

  actions.forEach(action => {
    const div = document.createElement('div');
    div.className = 'rec-item' + (action.startsWith('URGENT') || action.startsWith('ESCALATE') ? ' rec-urgent' : '');
    div.textContent = action;
    list.appendChild(div);
  });

  const discEl = document.getElementById('disclaimer');
  discEl.textContent = disclaimer || '';
}

// ----------------------------------------------------------------
// FEATURES
// ----------------------------------------------------------------
function updateFeatures(features) {
  if (!features) return;
  const tbody = document.getElementById('featureTableBody');
  tbody.innerHTML = Object.entries(features)
    .map(([k, v]) => {
      const fmt = Number.isInteger(v) ? v.toLocaleString() : v.toLocaleString(undefined, {maximumFractionDigits: 2});
      return `<tr><td>${k}</td><td>${fmt}</td></tr>`;
    })
    .join('');
}

// ----------------------------------------------------------------
// ALERT FEED
// ----------------------------------------------------------------
function addAlert(r) {
  alertCount++;
  document.getElementById('alertCount').textContent = alertCount;

  const feed = document.getElementById('alertFeed');

  // Remove empty state
  const empty = feed.querySelector('.alert-empty');
  if (empty) empty.remove();

  const color = SEV_COLORS[r.risk.severity] || '#00d4ff';
  const ts    = r.timestamp ? new Date(r.timestamp).toLocaleTimeString('en-GB') : '--:--:--';
  const src   = r.source_ip || '–';
  const dst   = r.dest_ip   || '–';

  const item = document.createElement('div');
  item.className = 'alert-item';
  item.onclick   = () => ingestResult(r);  // re-select this alert
  item.innerHTML = `
    <div class="alert-stripe" style="background:${color}"></div>
    <div class="alert-body">
      <div class="alert-label">${escHtml(r.attack_label)}</div>
      <div class="alert-meta">${escHtml(r.scenario_name || 'Flow')} &bull; ${src} → ${dst}</div>
    </div>
    <div class="alert-right">
      <div class="alert-score" style="color:${color}">${r.risk.score}</div>
      <div class="alert-time">${ts}</div>
    </div>
  `;

  // Prepend new alerts
  feed.insertBefore(item, feed.firstChild);

  // Cap feed at 50 items
  while (feed.children.length > 50) feed.removeChild(feed.lastChild);
}

function clearAlerts() {
  const feed = document.getElementById('alertFeed');
  feed.innerHTML = `
    <div class="alert-empty">
      <div class="empty-icon">📊</div>
      <p>Alert feed cleared.</p>
    </div>`;
  alertCount = 0;
  document.getElementById('alertCount').textContent = 0;
}

// ----------------------------------------------------------------
// INVESTIGATION HISTORY
// ----------------------------------------------------------------
function addHistory(r) {
  historyData.push(r);
  document.getElementById('historyCount').textContent = historyData.length;

  const ts    = r.timestamp ? new Date(r.timestamp).toLocaleTimeString('en-GB') : '--:--:--';
  const color = SEV_COLORS[r.risk.severity] || '#00d4ff';
  const tbody = document.getElementById('historyBody');

  const row = document.createElement('tr');
  row.innerHTML = `
    <td>${historyData.length}</td>
    <td>${ts}</td>
    <td>${escHtml(r.scenario_name || 'Flow')}</td>
    <td>${escHtml(r.attack_label)}</td>
    <td style="color:${color};font-family:var(--font-mono);font-weight:700">${r.risk.score}</td>
    <td style="color:${color}">${r.risk.severity}</td>
    <td>${STAGE_LABELS[r.attack_chain?.current_stage] || r.attack_chain?.current_stage || '–'}</td>
    <td>${r.mitre?.technique_id || '–'}</td>
  `;
  tbody.appendChild(row);
}

function toggleHistory() {
  const panel = document.getElementById('historyPanel');
  panel.style.display = panel.style.display === 'none' ? 'block' : 'none';
}

function exportHistory() {
  const blob = new Blob([JSON.stringify(historyData, null, 2)], { type: 'application/json' });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href     = url;
  a.download = `threatscope_history_${Date.now()}.json`;
  a.click();
  URL.revokeObjectURL(url);
}

// ----------------------------------------------------------------
// TIMELINE CHART (vanilla canvas)
// ----------------------------------------------------------------
function initTimeline() {
  const canvas = document.getElementById('timelineCanvas');
  timelineCtx  = canvas.getContext('2d');
  canvas.width = canvas.offsetWidth || 600;
  drawTimeline();
}

function pushTimeline(score, severity, ts) {
  timelineData.push({ score, severity, ts });
  if (timelineData.length > 60) timelineData.shift();
  drawTimeline();
}

function drawTimeline() {
  const canvas = document.getElementById('timelineCanvas');
  const ctx    = timelineCtx;
  if (!ctx) return;

  const W = canvas.clientWidth || canvas.width;
  const H = 100;
  canvas.width  = W;
  canvas.height = H;

  // Background
  ctx.fillStyle = '#0d1526';
  ctx.fillRect(0, 0, W, H);

  // Grid lines
  ctx.strokeStyle = '#1e2f4a';
  ctx.lineWidth   = 0.5;
  [25, 50, 75].forEach(v => {
    const y = H - (v / 100) * (H - 10) - 5;
    ctx.beginPath();
    ctx.moveTo(0, y); ctx.lineTo(W, y);
    ctx.stroke();
    ctx.fillStyle = '#3d5270';
    ctx.font = '9px Inter';
    ctx.fillText(v, 3, y - 2);
  });

  if (timelineData.length < 2) return;

  const step = W / (timelineData.length - 1);

  // Gradient fill
  const grad = ctx.createLinearGradient(0, 0, 0, H);
  grad.addColorStop(0,   'rgba(0,212,255,0.3)');
  grad.addColorStop(1,   'rgba(0,212,255,0.0)');

  ctx.beginPath();
  timelineData.forEach((d, i) => {
    const x = i * step;
    const y = H - (d.score / 100) * (H - 10) - 5;
    i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
  });
  // Close fill path
  ctx.lineTo((timelineData.length - 1) * step, H);
  ctx.lineTo(0, H);
  ctx.closePath();
  ctx.fillStyle = grad;
  ctx.fill();

  // Line
  ctx.beginPath();
  ctx.lineWidth   = 2;
  ctx.strokeStyle = '#00d4ff';
  timelineData.forEach((d, i) => {
    const x = i * step;
    const y = H - (d.score / 100) * (H - 10) - 5;
    i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
  });
  ctx.stroke();

  // Dots coloured by severity
  timelineData.forEach((d, i) => {
    const x = i * step;
    const y = H - (d.score / 100) * (H - 10) - 5;
    ctx.beginPath();
    ctx.arc(x, y, 3, 0, Math.PI * 2);
    ctx.fillStyle = SEV_COLORS[d.severity] || '#00d4ff';
    ctx.fill();
  });
}

// ----------------------------------------------------------------
// UTILITY
// ----------------------------------------------------------------
function escHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// Resize timeline on window resize
window.addEventListener('resize', () => {
  const canvas = document.getElementById('timelineCanvas');
  if (canvas) { canvas.width = canvas.clientWidth; drawTimeline(); }
});
