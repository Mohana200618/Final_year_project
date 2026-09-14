'use strict';

TS.pages = TS.pages || {};

TS.pages.recommendations = {
  render() {
    return `
      <div class="page page-recs" style="padding: 20px;">
        <div class="page-header" style="margin-bottom: 20px;">
          <h1 class="page-title" style="font-size: 24px; color: #fff; margin:0;"><span class="page-icon">💡</span> Required Actions & Features</h1>
        </div>

        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
          <section class="card" style="background: var(--bg-card); border-radius: var(--radius); padding: var(--gap); border: 1px solid var(--border);">
            <div class="card-header" style="margin-bottom: 20px;">
              <h2 class="card-title" style="font-size: 16px; color: #fff; margin:0;">AI Playbook Recommendations</h2>
            </div>
            <div id="pageRecsList" style="display: flex; flex-direction: column; gap: 15px;">
              <p style="color: var(--text-muted); font-style: italic;">Awaiting classification...</p>
            </div>
            <div id="pageRecsDisclaimer" style="margin-top: 20px; font-size: 11px; color: var(--text-muted); text-align: center; font-style: italic;"></div>
          </section>

          <section class="card" style="background: var(--bg-card); border-radius: var(--radius); padding: var(--gap); border: 1px solid var(--border); max-height: calc(100vh - 120px); overflow-y: auto;">
            <div class="card-header" style="margin-bottom: 20px;">
              <h2 class="card-title" style="font-size: 16px; color: #fff; margin:0;">Flow Feature Vector</h2>
            </div>
            <table style="width: 100%; border-collapse: collapse; font-family: var(--font-mono); font-size: 13px;">
              <tbody id="pageFeatureTable">
                <tr><td style="padding: 10px; color: var(--text-muted);">No flow selected</td></tr>
              </tbody>
            </table>
          </section>
        </div>
      </div>
    `;
  },

  init() {
    if (TS.state.history.length > 0) {
      const last = TS.state.history[TS.state.history.length - 1];
      this.updateRecs(last.recommendations, last.disclaimer);
      this.updateFeatures(last.features);
    }
  },

  onData(result) {
    this.updateRecs(result.recommendations, result.disclaimer);
    this.updateFeatures(result.features);
  },

  destroy() {},

  updateRecs(actions, disclaimer) {
    const list = document.getElementById('pageRecsList');
    if(!list) return;
    list.innerHTML = '';
    if (!actions || actions.length === 0) {
      list.innerHTML = '<p style="color:var(--text-muted); font-style:italic;">No recommendations.</p>';
      return;
    }
    actions.forEach(action => {
      const isUrgent = action.startsWith('URGENT') || action.startsWith('ESCALATE');
      const bg = isUrgent ? 'rgba(239,68,68,0.1)' : 'rgba(0,212,255,0.05)';
      const border = isUrgent ? 'var(--sev-critical)' : 'var(--accent-cyan)';
      const div = document.createElement('div');
      div.style = `font-size: 14px; padding: 15px; background: ${bg}; border-left: 4px solid ${border}; border-radius: 0 6px 6px 0; color: #fff; line-height: 1.4;`;
      div.textContent = action;
      list.appendChild(div);
    });
    document.getElementById('pageRecsDisclaimer').textContent = disclaimer || '';
  },

  updateFeatures(features) {
    const tbody = document.getElementById('pageFeatureTable');
    if(!tbody || !features) return;
    tbody.innerHTML = Object.entries(features).map(([k, v]) => {
      const fmt = Number.isInteger(v) ? v.toLocaleString() : v.toLocaleString(undefined, {maximumFractionDigits: 4});
      return `<tr><td style="padding: 8px 0; border-bottom: 1px solid rgba(255,255,255,0.05); color: var(--text-secondary);">${k}</td>
              <td style="padding: 8px 0; border-bottom: 1px solid rgba(255,255,255,0.05); text-align: right; color: #fff;">${fmt}</td></tr>`;
    }).join('');
  }
};
