/* ================================================================
   ThreatScope — Shared Core
   Event bus, state management, API layer, and utilities.
   ================================================================ */

'use strict';

window.TS = window.TS || {};
TS.API_BASE = 'http://127.0.0.1:5000/api';

TS.events = (() => {
  const _listeners = {};
  function subscribe(event, fn) {
    if (!_listeners[event]) _listeners[event] = [];
    _listeners[event].push(fn);
  }
  function publish(event, data) {
    if (_listeners[event]) _listeners[event].forEach(fn => { try { fn(data); } catch(e) {} });
  }
  return { subscribe, publish };
})();

TS.state = {
  alerts: [],
  history: [],
  timeline: [],
  isLiveMode: false,
  demoRunning: false
};

TS.escHtml = function(str) {
  if (!str) return '';
  return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
};

TS.boot = function() {
  TS.router.register('#/dashboard', TS.pages.dashboard);
  TS.router.register('#/scanning', TS.pages.scanning);
  TS.router.register('#/risk', TS.pages.risk);
  TS.router.register('#/mitre', TS.pages.mitre);
  TS.router.register('#/attack-chain', TS.pages.attack_chain);
  TS.router.register('#/recommendations', TS.pages.recommendations);
  
  TS.router.init('#pageContainer', '#/dashboard');

  const btnToggle = document.getElementById('btnDemoToggle');
  const btnStop = document.getElementById('btnDemoStop');
  if(btnToggle) btnToggle.addEventListener('click', () => TS.api.startDemo());
  if(btnStop) btnStop.addEventListener('click', () => TS.api.stopDemo());
};

TS.api = {
  startDemo() {
    document.getElementById('btnDemoToggle').style.display = 'none';
    document.getElementById('btnDemoStop').style.display = 'block';
    TS.state.demoRunning = true;
    TS.api.listenDemo();
  },
  stopDemo() {
    document.getElementById('btnDemoToggle').style.display = 'block';
    document.getElementById('btnDemoStop').style.display = 'none';
    TS.state.demoRunning = false;
    if(TS.demoSource) { 
      TS.demoSource.close(); 
      TS.demoSource = null; 
    }
  },
  listenDemo() {
    if(TS.demoSource) return;
    TS.demoSource = new EventSource(TS.API_BASE + '/demo/stream');
    TS.demoSource.onmessage = (e) => {
      try {
        const data = JSON.parse(e.data);
        if(data.event === 'connected' || data.event === 'replay_complete') return;
        TS.state.history.push(data);
        TS.state.timeline.push({score: data.risk.score, severity: data.risk.severity});
        TS.router.onData(data);
      } catch(err) {}
    };
  }
};
