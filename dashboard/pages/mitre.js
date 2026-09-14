'use strict';

TS.pages = TS.pages || {};

TS.pages.mitre = {
  render() {
    return `
      <div class="page page-mitre" style="padding: 20px;">
        <div class="page-header" style="margin-bottom: 20px;">
          <h1 class="page-title" style="font-size: 24px; color: #fff; margin:0;"><span class="page-icon">🛡️</span> MITRE ATT&CK Mapping</h1>
        </div>

        <section class="card" style="background: var(--bg-card); border-radius: var(--radius); padding: var(--gap); border: 1px solid var(--border);">
          <div style="text-align: center; padding: 40px 20px;">
            <div id="mitrePageTactic" style="font-size: 18px; color: var(--text-secondary); margin-bottom: 10px; text-transform: uppercase; letter-spacing: 2px;">—</div>
            <div id="mitrePageTech" style="font-size: 36px; font-weight: 700; color: #fff; margin-bottom: 20px;">Awaiting Data...</div>
            <a id="mitrePageLink" href="#" target="_blank" style="display:none; padding: 10px 20px; background: var(--accent-cyan); color: #000; border-radius: 6px; text-decoration: none; font-weight: 600;">View on ATT&CK Website ↗</a>
          </div>
        </section>
      </div>
    `;
  },

  init() {
    if (TS.state.history.length > 0) {
      this.update(TS.state.history[TS.state.history.length - 1].mitre);
    }
  },

  onData(result) {
    this.update(result.mitre);
  },

  destroy() {},

  update(mitre) {
    if (!mitre) return;
    const elTac = document.getElementById('mitrePageTactic');
    const elTech = document.getElementById('mitrePageTech');
    const elLink = document.getElementById('mitrePageLink');
    if (!elTac) return;

    elTac.textContent = mitre.tactic || '—';
    const techName = mitre.technique_id ? `${mitre.technique_id} — ${mitre.technique_name}` : (mitre.technique_name || '—');
    elTech.textContent = techName;
    
    if (mitre.reference) {
      elLink.href = mitre.reference;
      elLink.style.display = 'inline-block';
    } else {
      elLink.style.display = 'none';
    }
  }
};
