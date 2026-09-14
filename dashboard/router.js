'use strict';
window.TS = window.TS || {};
TS.router = (() => {
  const _routes = {};
  let _current = null, _contentEl = null;
  function register(hash, page) { _routes[hash] = page; }
  function init(selector, defaultHash) {
    _contentEl = document.querySelector(selector);
    window.addEventListener('hashchange', _handle);
    if (!window.location.hash) window.location.hash = defaultHash;
    else _handle();
  }
  function _handle() {
    const hash = window.location.hash || '#/dashboard';
    if (_current && _routes[_current] && _routes[_current].destroy) _routes[_current].destroy();
    _current = hash;
    const page = _routes[hash];
    if (page) {
      _contentEl.innerHTML = page.render();
      if (page.init) page.init();
      document.querySelectorAll('.nav-item').forEach(el => {
        el.classList.toggle('active', el.getAttribute('href') === hash);
      });
    }
  }
  function onData(res) {
    if (_current && _routes[_current] && _routes[_current].onData) _routes[_current].onData(res);
  }
  return { register, init, onData };
})();
