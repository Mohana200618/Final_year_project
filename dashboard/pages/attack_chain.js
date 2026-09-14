'use strict';

TS.pages = TS.pages || {};

TS.pages.attack_chain = {
  render() {
    return `
      <div class="page page-attack-chain" style="padding: 20px;">
        <div class="page-header" style="margin-bottom: 20px;">
          <h1 class="page-title" style="font-size: 24px; color: #fff; margin:0;"><span class="page-icon">🔗</span> Attack Chain Progression</h1>
        </div>

        <section class="card" style="background: var(--bg-card); border-radius: var(--radius); padding: 40px; border: 1px solid var(--border); display: flex; flex-direction: column; align-items: center;">
          
          <div class="chain-stages-horizontal" id="pageChainStages" style="display: flex; align-items: center; justify-content: space-between; width: 100%; max-width: 800px; margin-bottom: 50px;">
            <!-- Stages will be populated via JS -->
            <div class="h-stage inactive" data-stage="NORMAL">Normal</div>
            <div class="h-arrow">→</div>
            <div class="h-stage inactive" data-stage="RECONNAISSANCE">Recon</div>
            <div class="h-arrow">→</div>
            <div class="h-stage inactive" data-stage="INITIAL_ACCESS">Initial Access</div>
            <div class="h-arrow">→</div>
            <div class="h-stage inactive" data-stage="COMMAND_AND_CONTROL">C2</div>
            <div class="h-arrow">→</div>
            <div class="h-stage inactive" data-stage="LATERAL_MOVEMENT">Lateral Move</div>
            <div class="h-arrow">→</div>
            <div class="h-stage inactive" data-stage="IMPACT">Impact</div>
          </div>

          <style>
            .h-stage { padding: 15px 25px; border-radius: 8px; font-weight: 600; text-align: center; border: 2px solid transparent; background: #162038; color: var(--text-muted); transition: 0.3s; }
            .h-stage.active { background: #1e2f4a; color: #fff; border-color: var(--accent-cyan); box-shadow: 0 0 15px rgba(0,212,255,0.2); transform: scale(1.1); }
            .h-stage.predicted { border-color: var(--sev-medium); border-style: dashed; color: #fff; }
            .h-arrow { color: var(--text-muted); font-size: 24px; }
          </style>

          <div style="background: rgba(0,0,0,0.3); padding: 20px; border-radius: 8px; width: 100%; max-width: 600px;">
            <h3 style="color: var(--text-secondary); font-size: 14px; text-transform: uppercase; margin-bottom: 15px;">Markov Chain Prediction</h3>
            <div style="display: flex; justify-content: space-between; margin-bottom: 10px;">
              <span style="font-size: 16px; color: #fff;">Most Likely Next Stage:</span>
              <span id="pagePredNext" style="font-size: 18px; font-weight: 700; color: var(--accent-cyan);">—</span>
              <span id="pagePredNextProb" style="font-family: var(--font-mono); color: #22c55e; font-size: 18px; font-weight: 700;">—</span>
            </div>
            <div style="display: flex; justify-content: space-between;">
              <span style="font-size: 14px; color: var(--text-secondary);">Alternative:</span>
              <span id="pagePredAlt" style="font-size: 14px; color: var(--text-primary);">—</span>
              <span id="pagePredAltProb" style="font-family: var(--font-mono); color: var(--text-secondary); font-size: 14px;">—</span>
            </div>
          </div>

        </section>
      </div>
    `;
  },

  init() {
    if (TS.state.history.length > 0) {
      this.update(TS.state.history[TS.state.history.length - 1].attack_chain);
    }
  },

  onData(result) {
    this.update(result.attack_chain);
  },

  destroy() {},

  update(chain) {
    if (!chain) return;
    const current = chain.current_stage;
    const predicted = chain.next_stage;
    const STAGE_LABELS = { NORMAL: 'Normal', RECONNAISSANCE: 'Recon', INITIAL_ACCESS: 'Initial Access', COMMAND_AND_CONTROL: 'C2', LATERAL_MOVEMENT: 'Lateral Move', IMPACT: 'Impact' };

    document.querySelectorAll('#pageChainStages .h-stage').forEach(el => {
      const s = el.dataset.stage;
      el.className = 'h-stage ' + (s === current ? 'active' : s === predicted ? 'predicted' : 'inactive');
    });

    const nextEl = document.getElementById('pagePredNext');
    if(!nextEl) return;
    nextEl.textContent = STAGE_LABELS[chain.next_stage] || chain.next_stage;
    document.getElementById('pagePredNextProb').textContent = Math.round((chain.next_probability || 0) * 100) + '%';
    
    document.getElementById('pagePredAlt').textContent = STAGE_LABELS[chain.alt_stage] || chain.alt_stage || '—';
    document.getElementById('pagePredAltProb').textContent = chain.alt_stage ? Math.round((chain.alt_probability || 0) * 100) + '%' : '—';
  }
};
