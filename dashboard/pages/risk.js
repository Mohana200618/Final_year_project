'use strict';

TS.pages = TS.pages || {};

TS.pages.risk = {
  render() {
    return `
      <div class="page page-risk" style="padding: 20px;">
        <div class="page-header" style="margin-bottom: 20px;">
          <h1 class="page-title" style="font-size: 24px; color: #fff; margin:0;"><span class="page-icon">📈</span> Risk Analysis</h1>
        </div>

        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
          <!-- Gauge Card -->
          <section class="card" style="background: var(--bg-card); border-radius: var(--radius); padding: var(--gap); border: 1px solid var(--border);">
            <div class="card-header" style="margin-bottom: 20px;">
              <h2 class="card-title" style="font-size: 16px; color: #fff; margin:0;">Real-time Risk Score</h2>
            </div>
            <div class="risk-gauge-wrap" style="position: relative; text-align: center; max-width: 300px; margin: 0 auto;">
              <svg viewBox="0 0 120 70" id="riskPageGaugeSvg">
                <path d="M10,65 A55,55 0 0,1 110,65" fill="none" stroke="#1e2a3a" stroke-width="10" stroke-linecap="round"/>
                <path id="riskPageArc" d="M10,65 A55,55 0 0,1 110,65" fill="none" stroke="#00d4ff" stroke-width="10" stroke-linecap="round" stroke-dasharray="173" stroke-dashoffset="173" style="transition:stroke-dashoffset 1s ease,stroke 0.5s"/>
                <line id="riskPageNeedle" x1="60" y1="65" x2="60" y2="20" stroke="#fff" stroke-width="2" stroke-linecap="round" style="transform-origin:60px 65px; transform:rotate(0deg); transition:transform 1s ease"/>
                <circle cx="60" cy="65" r="4" fill="#fff"/>
              </svg>
              <div style="margin-top: 10px;">
                <div id="riskPageNumber" style="font-size: 48px; font-weight: 700; font-family: var(--font-mono); line-height: 1; color: #fff;">--</div>
                <div id="riskPageLabel" style="font-size: 14px; font-weight: 600; text-transform: uppercase; margin-top: 5px; color: var(--text-secondary);">—</div>
              </div>
            </div>
          </section>

          <!-- Breakdown Card -->
          <section class="card" style="background: var(--bg-card); border-radius: var(--radius); padding: var(--gap); border: 1px solid var(--border);">
            <div class="card-header" style="margin-bottom: 20px;">
              <h2 class="card-title" style="font-size: 16px; color: #fff; margin:0;">Risk Factor Breakdown</h2>
            </div>
            <div id="riskPageBreakdown" style="display: flex; flex-direction: column; gap: 15px;">
              <div style="display: flex; flex-direction: column; gap: 5px;">
                <div style="display: flex; justify-content: space-between; font-size: 13px; color: #fff;"><span>Anomaly Baseline</span><span id="txtBrkAnomaly">0</span></div>
                <div style="width: 100%; background: #1e2a3a; height: 8px; border-radius: 4px; overflow: hidden;"><div id="pgBrkAnomaly" style="height: 100%; width: 0%; background: #00d4ff; transition: width 0.5s;"></div></div>
              </div>
              <div style="display: flex; flex-direction: column; gap: 5px;">
                <div style="display: flex; justify-content: space-between; font-size: 13px; color: #fff;"><span>Attack Signature</span><span id="txtBrkAttack">0</span></div>
                <div style="width: 100%; background: #1e2a3a; height: 8px; border-radius: 4px; overflow: hidden;"><div id="pgBrkAttack" style="height: 100%; width: 0%; background: #00d4ff; transition: width 0.5s;"></div></div>
              </div>
              <div style="display: flex; flex-direction: column; gap: 5px;">
                <div style="display: flex; justify-content: space-between; font-size: 13px; color: #fff;"><span>Model Confidence</span><span id="txtBrkConf">0</span></div>
                <div style="width: 100%; background: #1e2a3a; height: 8px; border-radius: 4px; overflow: hidden;"><div id="pgBrkConf" style="height: 100%; width: 0%; background: #00d4ff; transition: width 0.5s;"></div></div>
              </div>
              <div style="display: flex; flex-direction: column; gap: 5px;">
                <div style="display: flex; justify-content: space-between; font-size: 13px; color: #fff;"><span>Current Stage</span><span id="txtBrkStage">0</span></div>
                <div style="width: 100%; background: #1e2a3a; height: 8px; border-radius: 4px; overflow: hidden;"><div id="pgBrkStage" style="height: 100%; width: 0%; background: #00d4ff; transition: width 0.5s;"></div></div>
              </div>
              <div style="display: flex; flex-direction: column; gap: 5px;">
                <div style="display: flex; justify-content: space-between; font-size: 13px; color: #fff;"><span>Stage Escalation</span><span id="txtBrkNext">0</span></div>
                <div style="width: 100%; background: #1e2a3a; height: 8px; border-radius: 4px; overflow: hidden;"><div id="pgBrkNext" style="height: 100%; width: 0%; background: #00d4ff; transition: width 0.5s;"></div></div>
              </div>
            </div>
          </section>
        </div>
      </div>
    `;
  },

  init() {
    if (TS.state.history.length > 0) {
      this.update(TS.state.history[TS.state.history.length - 1]);
    }
  },

  onData(result) {
    this.update(result);
  },

  destroy() {},

  update(result) {
    const score = result.risk.score;
    const severity = result.risk.severity;
    const breakdown = result.risk.breakdown;

    const SEV_COLORS = { Low: '#22c55e', Medium: '#f59e0b', High: '#f97316', Critical: '#ef4444' };
    const color = SEV_COLORS[severity] || '#00d4ff';
    const arcLen = 173;
    const offset = arcLen * (1 - score / 100);
    const degrees = -90 + (score / 100) * 180;

    const arc = document.getElementById('riskPageArc');
    const needle = document.getElementById('riskPageNeedle');
    const num = document.getElementById('riskPageNumber');
    const lbl = document.getElementById('riskPageLabel');
    if(!arc) return;

    arc.style.strokeDashoffset = offset;
    arc.style.stroke = color;
    needle.style.transform = `rotate(${degrees}deg)`;

    num.textContent = score;
    num.style.color = color;
    lbl.textContent = severity;
    lbl.style.color = color;

    const maxes = { pgBrkAnomaly: 20, pgBrkAttack: 35, pgBrkConf: 15, pgBrkStage: 15, pgBrkNext: 15 };
    const txtIds = { pgBrkAnomaly: 'txtBrkAnomaly', pgBrkAttack: 'txtBrkAttack', pgBrkConf: 'txtBrkConf', pgBrkStage: 'txtBrkStage', pgBrkNext: 'txtBrkNext' };
    const keys = {
      pgBrkAnomaly: 'anomaly_score_component', pgBrkAttack: 'attack_type_component',
      pgBrkConf: 'confidence_component', pgBrkStage: 'stage_component', pgBrkNext: 'next_stage_component'
    };

    for (const [elId, maxVal] of Object.entries(maxes)) {
      const val = breakdown[keys[elId]] || 0;
      const pct = Math.min(100, (val / maxVal) * 100);
      const bar = document.getElementById(elId);
      const txt = document.getElementById(txtIds[elId]);
      if (bar) {
        bar.style.width = pct + '%';
        bar.style.background = color;
        txt.textContent = val.toFixed(1) + ' / ' + maxVal;
      }
    }
  }
};
