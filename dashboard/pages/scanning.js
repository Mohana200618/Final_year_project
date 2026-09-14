'use strict';

TS.pages = TS.pages || {};

TS.pages.scanning = {
  render() {
    return `
      <style>
        .page-scanning { padding: 30px; color: #e2eaf5; max-width: 1400px; margin: 0 auto; }
        .scan-header { margin-bottom: 25px; }
        .scan-header h1 { font-size: 26px; font-weight: 700; color: #fff; display: flex; align-items: center; gap: 12px; margin: 0 0 8px 0; }
        .scan-header p { font-size: 14px; color: var(--text-secondary); margin: 0; }
        
        .control-bar { display: flex; justify-content: space-between; align-items: center; background: var(--bg-card); padding: 15px 25px; border-radius: var(--radius); border: 1px solid var(--border); margin-bottom: 25px; }
        .sys-status { display: flex; align-items: center; gap: 10px; font-size: 14px; color: #fff; font-weight: 500; }
        .sys-dot { width: 10px; height: 10px; border-radius: 50%; background: #3d5270; }
        .sys-dot.active { background: #22c55e; box-shadow: 0 0 8px rgba(34,197,94,0.5); }
        .ctrl-actions { display: flex; align-items: center; gap: 20px; }
        
        .toggle-wrap { display: flex; align-items: center; gap: 10px; font-size: 13px; color: var(--text-secondary); }
        .switch { position: relative; display: inline-block; width: 34px; height: 20px; }
        .switch input { opacity: 0; width: 0; height: 0; }
        .slider { position: absolute; cursor: pointer; top: 0; left: 0; right: 0; bottom: 0; background-color: #1e2f4a; transition: .4s; border-radius: 34px; }
        .slider:before { position: absolute; content: ""; height: 14px; width: 14px; left: 3px; bottom: 3px; background-color: #fff; transition: .4s; border-radius: 50%; }
        input:checked + .slider { background-color: var(--accent-cyan); }
        input:checked + .slider:before { transform: translateX(14px); }
        
        .btn-scan { padding: 8px 16px; border-radius: 6px; font-size: 13px; font-weight: 600; border: none; cursor: pointer; display: flex; align-items: center; gap: 8px; transition: 0.2s; }
        .btn-scan-primary { background: var(--accent-cyan); color: #000; }
        .btn-scan-primary:hover { filter: brightness(1.1); box-shadow: 0 0 10px rgba(0,212,255,0.3); }
        .btn-scan-secondary { background: transparent; color: var(--text-muted); }
        .btn-scan-secondary.active { color: #fff; background: rgba(255,255,255,0.1); }
        
        .scan-grid { display: grid; grid-template-columns: 1fr 380px; gap: 25px; align-items: start; }
        
        .filter-bar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
        .filter-tabs { display: flex; gap: 10px; background: rgba(0,0,0,0.2); padding: 5px; border-radius: 8px; border: 1px solid var(--border); }
        .f-tab { background: transparent; border: 1px solid transparent; color: var(--text-secondary); padding: 4px 12px; border-radius: 4px; font-size: 12px; cursor: pointer; }
        .f-tab.active { border-color: var(--accent-cyan); color: var(--accent-cyan); }
        .filter-meta { display: flex; align-items: center; gap: 15px; font-size: 12px; font-weight: 600; }
        .meta-count { background: var(--accent-cyan); color: #000; padding: 2px 10px; border-radius: 12px; }
        .meta-csv { color: var(--text-secondary); cursor: pointer; }
        
        .feed-container { background: var(--bg-card); border: 1px solid var(--border); border-radius: var(--radius); padding: 15px; min-height: 500px; max-height: 700px; overflow-y: auto; display: flex; flex-direction: column; gap: 10px; }
        
        .alert-row { display: flex; background: #080e1a; border-radius: 6px; border: 1px solid var(--border); overflow: hidden; padding: 15px; position: relative; justify-content: space-between; align-items: center; }
        .alert-row::before { content: ''; position: absolute; left: 0; top: 0; bottom: 0; width: 4px; background: var(--border); }
        .alert-row.sev-Low::before { background: var(--sev-low); }
        .alert-row.sev-Medium::before { background: var(--sev-medium); }
        .alert-row.sev-High::before { background: var(--sev-high); }
        .alert-row.sev-Critical::before { background: var(--sev-critical); }
        
        .alert-left h4 { margin: 0 0 5px 0; font-size: 15px; color: #fff; }
        .alert-left p { margin: 0; font-size: 12px; color: var(--text-secondary); }
        .alert-right { text-align: right; }
        .alert-right .score { font-size: 18px; font-weight: 700; font-family: var(--font-mono); margin-bottom: 2px; }
        .alert-right .time { font-size: 11px; color: var(--text-muted); font-family: var(--font-mono); }
        
        .right-col { display: flex; flex-direction: column; gap: 20px; }
        .scan-card { background: var(--bg-card); border-radius: var(--radius); border: 1px solid var(--border); padding: 20px; }
        .scan-card h3 { font-size: 12px; color: var(--text-secondary); text-transform: uppercase; letter-spacing: 1px; margin: 0 0 20px 0; display: flex; align-items: center; gap: 8px; }
        
        /* Classification Card */
        #lblClass { font-size: 24px; font-weight: 700; color: #fff; margin-bottom: 25px; }
        .class-row { display: flex; justify-content: space-between; align-items: center; font-size: 13px; color: var(--text-secondary); margin-bottom: 15px; }
        .class-row:last-child { margin-bottom: 0; }
        .conf-track { flex: 0.8; height: 4px; background: #1e2f4a; border-radius: 2px; margin-left: 15px; overflow: hidden; display: flex; align-items: center; }
        #barConf { height: 100%; background: var(--accent-blue); width: 0%; transition: width 0.3s; }
        #lblAnomaly, #lblIsAnomaly { font-family: var(--font-mono); color: #fff; font-size: 14px; }
        
        .timeline-wrap { height: 150px; width: 100%; position: relative; }
      </style>
      <div class="page-scanning">
        <div class="scan-header">
          <h1><span style="font-size: 28px;">🔍</span> Scanning & Detection</h1>
          <p>Monitor network flows and detect threats in real-time</p>
        </div>

        <div class="control-bar">
          <div class="sys-status">
            <div class="sys-dot" id="scanStatusDot"></div> <span id="scanStatusText">Ready</span>
          </div>
          <div class="ctrl-actions">
            <div class="toggle-wrap">
              Demo Mode
              <label class="switch">
                <input type="checkbox" id="chkDemoMode" checked>
                <span class="slider"></span>
              </label>
            </div>
            <button class="btn-scan btn-scan-primary" id="btnScanStart">► Start Demo Replay</button>
            <button class="btn-scan btn-scan-secondary" id="btnScanStop">■ Stop</button>
          </div>
        </div>

        <div class="scan-grid">
          <div class="left-col">
            <div class="filter-bar">
              <div class="filter-tabs">
                <button class="f-tab active">All</button>
                <button class="f-tab">Critical</button>
                <button class="f-tab">High</button>
                <button class="f-tab">Medium</button>
                <button class="f-tab">Low</button>
              </div>
              <div class="filter-meta">
                <span class="meta-count" id="scanAlertCount">0</span>
                <span class="meta-csv">⬇ CSV</span>
              </div>
            </div>
            <div class="feed-container" id="scanFeed">
              <div style="text-align:center; padding: 40px; color: var(--text-muted);">Awaiting traffic...</div>
            </div>
          </div>
          
          <div class="right-col">
            <div class="scan-card">
              <h3><span style="color:var(--sev-critical)">🎯</span> CLASSIFICATION</h3>
              <div id="lblClass">—</div>
              <div class="class-row">
                Confidence 
                <div class="conf-track"><div id="barConf"></div></div>
              </div>
              <div class="class-row">
                Anomaly Score <span id="lblAnomaly">—</span>
              </div>
              <div class="class-row">
                Is Anomalous <span id="lblIsAnomaly">—</span>
              </div>
            </div>
            
            <div class="scan-card">
              <h3><span style="color:var(--accent-cyan)">📈</span> ATTACK TIMELINE</h3>
              <div class="timeline-wrap">
                <canvas id="scanTimelineCanvas"></canvas>
              </div>
            </div>
          </div>
        </div>
      </div>
    `;
  },

  init() {
    this.canvas = document.getElementById('scanTimelineCanvas');
    if(this.canvas) {
      this.ctx = this.canvas.getContext('2d');
      this.canvas.width = this.canvas.parentElement.offsetWidth;
      this.canvas.height = 150;
    }

    const btnStart = document.getElementById('btnScanStart');
    const btnStop = document.getElementById('btnScanStop');
    
    if (TS.state.demoRunning) {
      this.setRunningState(true);
    }

    btnStart.addEventListener('click', () => {
      TS.api.startDemo();
      this.setRunningState(true);
    });
    
    btnStop.addEventListener('click', () => {
      TS.api.stopDemo();
      this.setRunningState(false);
    });

    // Populate existing
    const feed = document.getElementById('scanFeed');
    if(feed) feed.innerHTML = '';
    TS.state.history.forEach(r => this.addAlert(r));
    if(TS.state.history.length > 0) {
      this.updateClass(TS.state.history[TS.state.history.length-1]);
    }
    this.drawTimeline();
  },

  setRunningState(isRunning) {
    const btnStart = document.getElementById('btnScanStart');
    const btnStop = document.getElementById('btnScanStop');
    const dot = document.getElementById('scanStatusDot');
    const txt = document.getElementById('scanStatusText');
    if (isRunning) {
      btnStart.style.display = 'none';
      btnStop.className = 'btn-scan btn-scan-secondary active';
      dot.className = 'sys-dot active';
      txt.textContent = 'Scanning...';
    } else {
      btnStart.style.display = 'flex';
      btnStop.className = 'btn-scan btn-scan-secondary';
      dot.className = 'sys-dot';
      txt.textContent = 'Ready';
    }
  },

  onData(result) {
    this.addAlert(result);
    this.updateClass(result);
    this.drawTimeline();
  },

  destroy() {},

  updateClass(result) {
    const lbl = document.getElementById('lblClass');
    const bar = document.getElementById('barConf');
    const anom = document.getElementById('lblAnomaly');
    const isAnom = document.getElementById('lblIsAnomaly');
    
    if(!lbl) return;
    
    lbl.textContent = result.attack_label;
    bar.style.width = Math.round((result.confidence||0)*100) + '%';
    anom.textContent = (result.anomaly_score||0).toFixed(4);
    isAnom.textContent = result.is_anomaly ? 'True' : 'False';
    isAnom.style.color = result.is_anomaly ? 'var(--sev-critical)' : 'var(--sev-low)';
  },

  addAlert(r) {
    const feed = document.getElementById('scanFeed');
    const count = document.getElementById('scanAlertCount');
    if(!feed) return;
    
    count.textContent = TS.state.history.length;
    
    const SEV_COLORS = { Low: '#22c55e', Medium: '#f59e0b', High: '#f97316', Critical: '#ef4444' };
    const color = SEV_COLORS[r.risk.severity] || '#00d4ff';
    const ts = r.timestamp ? new Date(r.timestamp).toLocaleTimeString('en-GB') : '--:--:--';
    
    const div = document.createElement('div');
    div.className = 'alert-row sev-' + r.risk.severity;
    div.innerHTML = `
      <div class="alert-left">
        <h4>${TS.escHtml(r.attack_label)}</h4>
        <p>${TS.escHtml(r.scenario_name || 'Flow')} • ${TS.escHtml(r.features['Src IP'] || '')} &rarr; ${TS.escHtml(r.features['Dst IP'] || '')}</p>
      </div>
      <div class="alert-right">
        <div class="score" style="color:${color}">${r.risk.score}</div>
        <div class="time">${ts}</div>
      </div>
    `;
    feed.insertBefore(div, feed.firstChild);
    while (feed.children.length > 100) feed.removeChild(feed.lastChild);
  },

  drawTimeline() {
    if (!this.ctx || !this.canvas) return;
    const W = this.canvas.width;
    const H = 150;
    
    this.ctx.clearRect(0,0,W,H);
    
    // Grid lines
    this.ctx.strokeStyle = '#1e2f4a';
    this.ctx.lineWidth = 1;
    [25, 50, 75].forEach(v => {
      const y = H - (v / 100) * (H - 20) - 10;
      this.ctx.beginPath();
      this.ctx.moveTo(0, y); this.ctx.lineTo(W, y);
      this.ctx.stroke();
      this.ctx.fillStyle = '#3d5270';
      this.ctx.font = '10px Inter';
      this.ctx.fillText(v, 0, y - 4);
    });

    if (TS.state.timeline.length < 2) return;

    const step = W / (TS.state.timeline.length - 1);

    this.ctx.beginPath();
    this.ctx.lineWidth = 2;
    this.ctx.strokeStyle = '#00d4ff';
    TS.state.timeline.forEach((d, i) => {
      const x = i * step;
      const y = H - (d.score / 100) * (H - 20) - 10;
      i === 0 ? this.ctx.moveTo(x, y) : this.ctx.lineTo(x, y);
    });
    this.ctx.stroke();

    const SEV_COLORS = { Low: '#22c55e', Medium: '#f59e0b', High: '#f97316', Critical: '#ef4444' };
    TS.state.timeline.forEach((d, i) => {
      const x = i * step;
      const y = H - (d.score / 100) * (H - 20) - 10;
      this.ctx.beginPath();
      this.ctx.arc(x, y, 4, 0, Math.PI * 2);
      this.ctx.fillStyle = SEV_COLORS[d.severity] || '#00d4ff';
      this.ctx.fill();
    });
  }
};
