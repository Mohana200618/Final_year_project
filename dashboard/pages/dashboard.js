'use strict';

const THREATSCOPE_STAGES = [
  ['NORMAL', 'Normal'],
  ['RECONNAISSANCE', 'Reconnaissance'],
  ['RESOURCE_DEVELOPMENT', 'Resource Development'],
  ['INITIAL_ACCESS', 'Initial Access'],
  ['EXECUTION', 'Execution'],
  ['PERSISTENCE', 'Persistence'],
  ['PRIVILEGE_ESCALATION', 'Privilege Escalation'],
  ['STEALTH', 'Stealth'],
  ['DEFENSE_IMPAIRMENT', 'Defense Impairment'],
  ['CREDENTIAL_ACCESS', 'Credential Access'],
  ['DISCOVERY', 'Discovery'],
  ['LATERAL_MOVEMENT', 'Lateral Movement'],
  ['COLLECTION', 'Collection'],
  ['COMMAND_AND_CONTROL', 'Command and Control'],
  ['EXFILTRATION', 'Exfiltration'],
  ['IMPACT', 'Impact']
];

TS.pages = TS.pages || {};

TS.pages.dashboard = {
  render() {
    return `
      <style>
        .old-main-layout {
          display: grid;
          grid-template-columns: 280px 1fr 300px;
          grid-template-rows: 1fr;
          gap: var(--gap);
          padding: var(--gap);
          height: calc(100vh - var(--navbar-h));
          overflow: hidden;
        }
        .old-sidebar, .old-right-panel {
          display: flex; flex-direction: column; gap: var(--gap);
          overflow-y: auto; height: 100%;
        }
        .old-center-panel {
          display: flex; flex-direction: column; gap: var(--gap);
          overflow-y: auto; height: 100%;
        }
        
        .card { background: var(--bg-card); border-radius: var(--radius); padding: var(--gap); border: 1px solid var(--border); }
        .card-header { display: flex; align-items: center; gap: 8px; margin-bottom: 15px; }
        .card-title { font-size: 14px; font-weight: 600; color: #fff; margin:0; }
        .card-icon { font-size: 16px; }

        /* Risk Gauge */
        .risk-gauge-wrap { position: relative; text-align: center; }
        .risk-score-display { position: absolute; bottom: 0; width: 100%; display: flex; flex-direction: column; align-items: center; }
        .risk-number { font-size: 36px; font-weight: 700; font-family: var(--font-mono); line-height: 1; }
        .risk-label { font-size: 12px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; margin-top: 4px; }
        .sev-low { color: #22c55e; } .sev-medium { color: #f59e0b; } .sev-high { color: #f97316; } .sev-critical { color: #ef4444; }

        /* Breakdown Bars */
        .risk-breakdown { margin-top: 20px; font-size: 12px; }
        .breakdown-row { display: flex; justify-content: space-between; margin-bottom: 8px; color: var(--text-secondary); }
        .breakdown-bar { flex: 1; height: 6px; background: #1e2a3a; margin-left: 10px; border-radius: 3px; overflow: hidden; align-self: center; }
        .bar-fill { height: 100%; border-radius: 3px; transition: width 0.5s ease; }

        /* Classification */
        .class-label { font-size: 20px; font-weight: 700; color: #fff; margin-bottom: 15px; }
        .class-conf { display: flex; align-items: center; gap: 10px; font-size: 12px; color: var(--text-secondary); margin-bottom: 12px; }
        .conf-bar-wrap { flex: 1; height: 6px; background: #1e2a3a; border-radius: 3px; overflow: hidden; }
        .conf-bar { height: 100%; background: var(--accent-cyan); transition: width 0.5s ease; }
        .anomaly-row { display: flex; justify-content: space-between; align-items: center; font-size: 12px; color: var(--text-secondary); }
        .anomaly-badge { background: #1e2a3a; padding: 2px 6px; border-radius: 4px; font-family: var(--font-mono); color: var(--accent-purple); }

        /* MITRE */
        .mitre-tactic { font-size: 13px; color: var(--text-secondary); margin-bottom: 5px; }
        .mitre-technique { font-size: 15px; font-weight: 600; color: #fff; margin-bottom: 15px; }
        .mitre-link { display: inline-block; font-size: 12px; color: var(--accent-blue); text-decoration: none; }
        .mitre-link:hover { text-decoration: underline; }

        /* Alerts Feed */
        .alerts-panel { flex: 1; display: flex; flex-direction: column; overflow: hidden; }
        .alert-feed { flex: 1; overflow-y: auto; display: flex; flex-direction: column; gap: 8px; padding-right: 5px; }
        .alert-item { display: flex; background: #162038; border-radius: 6px; padding: 10px; gap: 12px; position: relative; overflow: hidden; animation: slideIn 0.3s ease-out; }
        @keyframes slideIn { from{opacity:0; transform:translateX(-10px);} to{opacity:1; transform:translateX(0);} }
        .alert-stripe { position: absolute; left: 0; top: 0; bottom: 0; width: 4px; }
        .alert-body { flex: 1; min-width: 0; }
        .alert-label { font-size: 13px; font-weight: 600; color: #fff; margin-bottom: 4px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
        .alert-meta { font-size: 11px; color: var(--text-secondary); }
        .alert-right { text-align: right; }
        .alert-score { font-family: var(--font-mono); font-size: 14px; font-weight: 700; margin-bottom: 4px; }
        .alert-time { font-family: var(--font-mono); font-size: 10px; color: var(--text-muted); }

        /* Attack Chain */
        .chain-stages { display: flex; flex-direction: column; gap: 4px; margin-bottom: 20px; }
        .chain-stage { padding: 8px 12px; background: #162038; border-radius: 6px; font-size: 13px; font-weight: 500; border-left: 4px solid transparent; transition: all 0.3s ease; }
        .chain-stage.inactive { color: var(--text-muted); }
        .chain-stage.active { color: #fff; background: #1e2f4a; border-left-color: var(--accent-cyan); box-shadow: 0 0 10px rgba(0,212,255,0.1); }
        .chain-stage.predicted { color: var(--text-primary); border-left-color: var(--sev-medium); border-left-style: dashed; }
        .chain-arrow { text-align: center; color: var(--text-muted); font-size: 12px; line-height: 1; }
        
        .chain-prediction { background: rgba(0,0,0,0.2); padding: 12px; border-radius: 6px; }
        .pred-row { display: flex; justify-content: space-between; align-items: center; font-size: 12px; margin-bottom: 8px; }
        .pred-row:last-child { margin-bottom: 0; }
        .pred-stage { font-weight: 600; color: var(--accent-cyan); }
        .pred-stage.alt { color: var(--text-secondary); font-weight: 400; }
        .pred-prob { font-family: var(--font-mono); color: #fff; }
        .pred-note { font-size: 10px; color: var(--text-muted); margin-top: 10px; text-align: center; font-style: italic; }

        /* Features */
        .feature-table { width: 100%; border-collapse: collapse; font-family: var(--font-mono); font-size: 11px; }
        .feature-table td { padding: 4px 0; border-bottom: 1px solid rgba(255,255,255,0.05); }
        .feature-table td:first-child { color: var(--text-secondary); }
        .feature-table td:last-child { text-align: right; color: #fff; }

        /* Recs */
        .recs-card { flex: 1; }
        .recs-list { display: flex; flex-direction: column; gap: 8px; }
        .rec-item { font-size: 13px; padding: 10px; background: rgba(0,212,255,0.05); border-left: 3px solid var(--accent-cyan); border-radius: 0 6px 6px 0; }
        .rec-urgent { background: rgba(239,68,68,0.1); border-left-color: var(--sev-critical); }
        .disclaimer { font-size: 10px; color: var(--text-muted); margin-top: 15px; text-align: center; font-style: italic; }
      </style>
      <main class="old-main-layout">
        <!-- ---- LEFT SIDEBAR ---- -->
        <aside class="old-sidebar" id="sidebar">
          
          <!-- Risk Score Widget -->
          <section class="card risk-card" id="riskCard">
            <div class="card-header">
              <span class="card-icon">🎯</span>
              <h2 class="card-title">Risk Score</h2>
            </div>
            <div class="risk-gauge-wrap">
              <svg class="risk-gauge" viewBox="0 0 120 70" id="riskGaugeSvg">
                <path d="M10,65 A55,55 0 0,1 110,65" fill="none" stroke="#1e2a3a" stroke-width="10" stroke-linecap="round"/>
                <path id="riskArc" d="M10,65 A55,55 0 0,1 110,65" fill="none" stroke="#00d4ff" stroke-width="10" stroke-linecap="round"
                      stroke-dasharray="173" stroke-dashoffset="173" style="transition:stroke-dashoffset 1s ease,stroke 0.5s"/>
                <line id="riskNeedle" x1="60" y1="65" x2="60" y2="20"
                      stroke="#fff" stroke-width="2" stroke-linecap="round"
                      style="transform-origin:60px 65px; transform:rotate(0deg); transition:transform 1s ease"/>
                <circle cx="60" cy="65" r="4" fill="#fff"/>
              </svg>
              <div class="risk-score-display">
                <span class="risk-number" id="riskNumber">--</span>
                <span class="risk-label" id="riskLabel">—</span>
              </div>
            </div>
            <div class="risk-breakdown" id="riskBreakdown">
              <div class="breakdown-row"><span>Anomaly</span><div class="breakdown-bar"><div class="bar-fill" id="brkAnomaly" style="width:0%"></div></div></div>
              <div class="breakdown-row"><span>Attack Type</span><div class="breakdown-bar"><div class="bar-fill" id="brkAttack"  style="width:0%"></div></div></div>
              <div class="breakdown-row"><span>Confidence</span><div class="breakdown-bar"><div class="bar-fill" id="brkConf"   style="width:0%"></div></div></div>
              <div class="breakdown-row"><span>Stage</span><div class="breakdown-bar"><div class="bar-fill" id="brkStage"   style="width:0%"></div></div></div>
              <div class="breakdown-row"><span>Next Stage</span><div class="breakdown-bar"><div class="bar-fill" id="brkNext"    style="width:0%"></div></div></div>
            </div>
          </section>

          <!-- Attack Classification -->
          <section class="card" id="classCard">
            <div class="card-header">
              <span class="card-icon">🎯</span>
              <h2 class="card-title">Classification</h2>
            </div>
            <div class="class-label" id="classLabel">Awaiting data…</div>
            <div class="class-conf">
              <span>Confidence</span>
              <div class="conf-bar-wrap"><div class="conf-bar" id="confBar" style="width:0%"></div></div>
              <span id="confPct">--</span>
            </div>
            <div class="anomaly-row">
              <span>Anomaly Score</span>
              <span class="anomaly-badge" id="anomalyBadge">--</span>
            </div>
          </section>

          <!-- MITRE Technique -->
          <section class="card" id="mitreCard">
            <div class="card-header">
              <span class="card-icon">🛡️</span>
              <h2 class="card-title">MITRE ATT&CK</h2>
            </div>
            <div class="mitre-tactic" id="mitreTactic">—</div>
            <div class="mitre-technique" id="mitreTech">—</div>
            <a class="mitre-link" id="mitreLink" href="#" target="_blank" rel="noopener" style="display:none">View on ATT&CK ↗</a>
          </section>

        </aside>

        <!-- ---- CENTER PANEL ---- -->
        <section class="old-center-panel">

          <!-- Alert Feed -->
          <div class="card alerts-panel" id="alertsPanel">
            <div class="card-header">
              <span class="card-icon">📡</span>
              <h2 class="card-title">Live Alert Feed</h2>
              <span class="alert-count badge" id="alertCount">0</span>
            </div>
            <div class="alert-feed" id="alertFeed">
              <div class="alert-empty" style="text-align:center; padding: 40px 0; color: #3d5270;">
                <div class="empty-icon" style="font-size: 24px; margin-bottom: 10px;">📊</div>
                <p>No alerts yet.<br/>Start a demo replay.</p>
              </div>
            </div>
          </div>

          <!-- Attack Timeline -->
          <div class="card timeline-card" id="timelineCard">
            <div class="card-header">
              <span class="card-icon">📈</span>
              <h2 class="card-title">Attack Timeline</h2>
            </div>
            <div class="timeline-wrap" id="timelineWrap">
              <canvas id="dashTimelineCanvas" height="100"></canvas>
            </div>
          </div>

        </section>

        <!-- ---- RIGHT PANEL ---- -->
        <aside class="old-right-panel">

          <!-- Attack Chain -->
          <section class="card" id="chainCard">
            <div class="card-header">
              <span class="card-icon">🔗</span>
              <h2 class="card-title">Attack Chain</h2>
            </div>
            <div class="chain-stages" id="chainStages">
              ${THREATSCOPE_STAGES.map(([key, label], index) =>
                `<div class="chain-stage inactive" data-stage="${key}">${label}</div>${index < THREATSCOPE_STAGES.length - 1 ? '<div class="chain-arrow">↓</div>' : ''}`
              ).join('')}
            </div>
            <div class="chain-prediction" id="chainPrediction">
              <div class="pred-row">
                <span>Next Stage</span>
                <span class="pred-stage" id="predNext">—</span>
                <span class="pred-prob" id="predNextProb">—</span>
              </div>
              <div class="pred-row">
                <span>Alternative</span>
                <span class="pred-stage alt" id="predAlt">—</span>
                <span class="pred-prob" id="predAltProb">—</span>
              </div>
              <p class="pred-note">Predictions based on Markov chain — advisory only.</p>
            </div>
          </section>

          <!-- Recommendations -->
          <section class="card recs-card" id="recsCard">
            <div class="card-header">
              <span class="card-icon">💡</span>
              <h2 class="card-title">Recommendations</h2>
            </div>
            <div class="recs-list" id="recsList">
              <p class="recs-empty" style="color:var(--text-muted); font-style:italic;">Awaiting classification…</p>
            </div>
            <div class="disclaimer" id="disclaimer"></div>
          </section>

          <!-- Feature Vector -->
          <section class="card" id="featuresCard">
            <div class="card-header">
              <span class="card-icon">🔍</span>
              <h2 class="card-title">Feature Vector</h2>
            </div>
            <table class="feature-table" id="featureTable">
              <tbody id="featureTableBody">
                <tr class="feat-empty"><td colspan="2">No flow selected</td></tr>
              </tbody>
            </table>
          </section>

        </aside>
      </main>
    `;
  },

  init() {
    this.initTimeline();

    // Populate with existing data if available
    TS.state.history.forEach(r => this.addAlert(r));
    if (TS.state.history.length > 0) {
      const last = TS.state.history[TS.state.history.length - 1];
      this.updateRiskGauge(last.risk.score, last.risk.severity, last.risk.breakdown);
      this.updateClassification(last.attack_label, last.confidence, last.anomaly_score);
      this.updateMitre(last.mitre);
      this.updateChain(last.attack_chain);
      this.updateRecommendations(last.recommendations, last.disclaimer);
      this.updateFeatures(last.features);
    }
    
    this.drawTimeline();
  },

  destroy() {
    // nothing to clean up here
  },

  onData(result) {
    this.updateRiskGauge(result.risk.score, result.risk.severity, result.risk.breakdown);
    this.updateClassification(result.attack_label, result.confidence, result.anomaly_score);
    this.updateMitre(result.mitre);
    this.updateChain(result.attack_chain);
    this.updateRecommendations(result.recommendations, result.disclaimer);
    this.updateFeatures(result.features);
    this.addAlert(result);
    this.drawTimeline();
  },

  updateRiskGauge(score, severity, breakdown) {
    const SEV_COLORS = { Low: '#22c55e', Medium: '#f59e0b', High: '#f97316', Critical: '#ef4444' };
    const color = SEV_COLORS[severity] || '#00d4ff';
    const arcLen = 173;
    const offset = arcLen * (1 - score / 100);
    const degrees = -90 + (score / 100) * 180;

    const arc = document.getElementById('riskArc');
    const needle = document.getElementById('riskNeedle');
    const num = document.getElementById('riskNumber');
    const lbl = document.getElementById('riskLabel');
    if(!arc) return;

    arc.style.strokeDashoffset = offset;
    arc.style.stroke = color;
    needle.style.transform = `rotate(${degrees}deg)`;

    num.textContent = score;
    num.className = 'risk-number sev-' + severity.toLowerCase();
    lbl.textContent = severity;
    lbl.className = 'risk-label sev-' + severity.toLowerCase();

    const maxes = { brkAnomaly: 20, brkAttack: 35, brkConf: 15, brkStage: 15, brkNext: 15 };
    const keys = {
      brkAnomaly: 'anomaly_score_component', brkAttack: 'attack_type_component',
      brkConf: 'confidence_component', brkStage: 'stage_component', brkNext: 'next_stage_component'
    };
    for (const [elId, maxVal] of Object.entries(maxes)) {
      const val = breakdown[keys[elId]] || 0;
      const pct = Math.min(100, (val / maxVal) * 100);
      const bar = document.getElementById(elId);
      if (bar) { bar.style.width = pct + '%'; bar.style.background = color; }
    }
  },

  updateClassification(label, confidence, anomalyScore) {
    const el = document.getElementById('classLabel');
    if(!el) return;
    el.textContent = label;
    const pct = Math.round((confidence || 0) * 100);
    document.getElementById('confBar').style.width = pct + '%';
    document.getElementById('confPct').textContent = pct + '%';
    document.getElementById('anomalyBadge').textContent = (anomalyScore || 0).toFixed(4);
  },

  updateMitre(mitre) {
    const el = document.getElementById('mitreTactic');
    if(!el) return;
    el.textContent = mitre.tactic || '—';
    const techName = mitre.technique_id ? `${mitre.technique_id} — ${mitre.technique_name}` : (mitre.technique_name || '—');
    document.getElementById('mitreTech').textContent = techName;
    const linkEl = document.getElementById('mitreLink');
    if (mitre.reference) {
      linkEl.href = mitre.reference;
      linkEl.style.display = '';
    } else {
      linkEl.style.display = 'none';
    }
  },

  updateChain(chain) {
    const current = chain.current_stage;
    const predicted = chain.next_stage;
    const STAGE_LABELS = Object.fromEntries(THREATSCOPE_STAGES);

    document.querySelectorAll('#chainStages .chain-stage').forEach(el => {
      const s = el.dataset.stage;
      el.className = 'chain-stage ' + (s === current ? 'active' : s === predicted ? 'predicted' : 'inactive');
    });

    const nextEl = document.getElementById('predNext');
    if(!nextEl) return;
    nextEl.textContent = STAGE_LABELS[chain.next_stage] || chain.next_stage;
    document.getElementById('predNextProb').textContent = Math.round((chain.next_probability || 0) * 100) + '%';
    
    document.getElementById('predAlt').textContent = STAGE_LABELS[chain.alt_stage] || chain.alt_stage || '—';
    document.getElementById('predAltProb').textContent = chain.alt_stage ? Math.round((chain.alt_probability || 0) * 100) + '%' : '—';
  },

  updateRecommendations(actions, disclaimer) {
    const list = document.getElementById('recsList');
    if(!list) return;
    list.innerHTML = '';
    if (!actions || actions.length === 0) {
      list.innerHTML = '<p class="recs-empty" style="color:var(--text-muted); font-style:italic;">No recommendations.</p>';
      return;
    }
    actions.forEach(action => {
      const div = document.createElement('div');
      div.className = 'rec-item' + (action.startsWith('URGENT') || action.startsWith('ESCALATE') ? ' rec-urgent' : '');
      div.textContent = action;
      list.appendChild(div);
    });
    document.getElementById('disclaimer').textContent = disclaimer || '';
  },

  updateFeatures(features) {
    if (!features) return;
    const tbody = document.getElementById('featureTableBody');
    if(!tbody) return;
    tbody.innerHTML = Object.entries(features).map(([k, v]) => {
      const fmt = Number.isInteger(v) ? v.toLocaleString() : v.toLocaleString(undefined, {maximumFractionDigits: 2});
      return `<tr><td>${k}</td><td>${fmt}</td></tr>`;
    }).join('');
  },

  addAlert(r) {
    const SEV_COLORS = { Low: '#22c55e', Medium: '#f59e0b', High: '#f97316', Critical: '#ef4444' };
    const countEl = document.getElementById('alertCount');
    if(!countEl) return;
    
    const count = TS.state.alerts.length;
    countEl.textContent = count;

    const feed = document.getElementById('alertFeed');
    const empty = feed.querySelector('.alert-empty');
    if (empty) empty.remove();

    const color = SEV_COLORS[r.risk.severity] || '#00d4ff';
    const ts = r.timestamp ? new Date(r.timestamp).toLocaleTimeString('en-GB') : '--:--:--';
    
    const item = document.createElement('div');
    item.className = 'alert-item';
    item.innerHTML = `
      <div class="alert-stripe" style="background:${color}"></div>
      <div class="alert-body">
        <div class="alert-label">${TS.escHtml(r.attack_label)}</div>
        <div class="alert-meta">${TS.escHtml(r.scenario_name || 'Flow')}</div>
      </div>
      <div class="alert-right">
        <div class="alert-score" style="color:${color}">${r.risk.score}</div>
        <div class="alert-time">${ts}</div>
      </div>
    `;
    
    feed.insertBefore(item, feed.firstChild);
    while (feed.children.length > 50) feed.removeChild(feed.lastChild);
  },

  initTimeline() {
    this.canvas = document.getElementById('dashTimelineCanvas');
    if(this.canvas) {
      this.ctx = this.canvas.getContext('2d');
      this.canvas.width = this.canvas.offsetWidth || 600;
    }
  },

  drawTimeline() {
    if (!this.ctx || !this.canvas) return;
    const W = this.canvas.clientWidth || this.canvas.width;
    const H = 100;
    this.canvas.width = W;
    this.canvas.height = H;
    
    this.ctx.fillStyle = '#0d1526';
    this.ctx.fillRect(0, 0, W, H);
    
    this.ctx.strokeStyle = '#1e2f4a';
    this.ctx.lineWidth = 0.5;
    [25, 50, 75].forEach(v => {
      const y = H - (v / 100) * (H - 10) - 5;
      this.ctx.beginPath();
      this.ctx.moveTo(0, y); this.ctx.lineTo(W, y);
      this.ctx.stroke();
      this.ctx.fillStyle = '#3d5270';
      this.ctx.font = '9px Inter';
      this.ctx.fillText(v, 3, y - 2);
    });

    if (TS.state.timeline.length < 2) return;

    const step = W / (TS.state.timeline.length - 1);
    const grad = this.ctx.createLinearGradient(0, 0, 0, H);
    grad.addColorStop(0, 'rgba(0,212,255,0.3)');
    grad.addColorStop(1, 'rgba(0,212,255,0.0)');

    this.ctx.beginPath();
    TS.state.timeline.forEach((d, i) => {
      const x = i * step;
      const y = H - (d.score / 100) * (H - 10) - 5;
      i === 0 ? this.ctx.moveTo(x, y) : this.ctx.lineTo(x, y);
    });
    this.ctx.lineTo((TS.state.timeline.length - 1) * step, H);
    this.ctx.lineTo(0, H);
    this.ctx.closePath();
    this.ctx.fillStyle = grad;
    this.ctx.fill();

    this.ctx.beginPath();
    this.ctx.lineWidth = 2;
    this.ctx.strokeStyle = '#00d4ff';
    TS.state.timeline.forEach((d, i) => {
      const x = i * step;
      const y = H - (d.score / 100) * (H - 10) - 5;
      i === 0 ? this.ctx.moveTo(x, y) : this.ctx.lineTo(x, y);
    });
    this.ctx.stroke();

    const SEV_COLORS = { Low: '#22c55e', Medium: '#f59e0b', High: '#f97316', Critical: '#ef4444' };
    TS.state.timeline.forEach((d, i) => {
      const x = i * step;
      const y = H - (d.score / 100) * (H - 10) - 5;
      this.ctx.beginPath();
      this.ctx.arc(x, y, 3, 0, Math.PI * 2);
      this.ctx.fillStyle = SEV_COLORS[d.severity] || '#00d4ff';
      this.ctx.fill();
    });
  }
};
