"""Boundary recorders: crypto.subtle, eval/Function, fetch/XHR.

Unlike hooks (Debugger breakpoints on the live object — invisible), these are
main-world wrappers installed via Page.addScriptToEvaluateOnNewDocument *before
any page script runs*, so they also see destructured references taken at load
time. They ARE patching and a determined SDK can detect them (descriptor
checks, toString identity); use them for boundary observation, use hooks for
stealth. toString/name are masqueraded to keep casual detection away.
"""

import json

_CORE = """
(() => {
  const G = window;
  if (G.__sbi__ && G.__sbi__.installed) return;
  const MAX = %(max)d;
  const buf = [];
  const clip = (s, n) => { s = String(s); return s.length > n ? s.slice(0, n) : s; };
  const b64 = (v) => {
    try {
      const u = v instanceof ArrayBuffer ? new Uint8Array(v)
        : ArrayBuffer.isView(v) ? new Uint8Array(v.buffer, v.byteOffset, v.byteLength)
        : new TextEncoder().encode(String(v));
      let s = ''; const CH = 0x8000;
      for (let i = 0; i < u.length; i += CH) s += String.fromCharCode.apply(null, u.subarray(i, i + CH));
      return btoa(s);
    } catch (e) { return '<err:' + e + '>'; }
  };
  const masq = (wrapper, original) => {
    try {
      const s = Function.prototype.toString.call(original);
      Object.defineProperty(wrapper, 'toString', { value: function () { return s; }, writable: true, configurable: true });
      Object.defineProperty(wrapper, 'name', { value: original.name, configurable: true });
    } catch (e) {}
    return wrapper;
  };
  G.__sbi__ = {
    installed: true,
    rec: (r) => { if (buf.length < MAX) buf.push(r); },
    drain: () => JSON.stringify(buf.splice(0, buf.length)),
    size: () => buf.length
  };
  G.__sbi__._clip = clip; G.__sbi__._b64 = b64; G.__sbi__._masq = masq;
})();
"""

_CRYPTO = """
(() => {
  const { _clip: clip, _b64, _masq: masq, rec } = window.__sbi__;
  const sub = (window.crypto && window.crypto.subtle) || (window.msCrypto && window.msCrypto.subtle);
  if (!sub) return;
  for (const op of ['digest', 'encrypt', 'decrypt', 'sign', 'verify', 'deriveBits', 'deriveKey', 'importKey']) {
    const orig = sub[op];
    if (typeof orig !== 'function') continue;
    const w = function (...a) {
      try {
        const safe = a.map((x) => {
          if (x instanceof ArrayBuffer || ArrayBuffer.isView(x)) return { b64: _b64(x) };
          if (x && typeof x === 'object') {
            try { return JSON.parse(JSON.stringify(x, (k, v) => v instanceof ArrayBuffer ? { b64: _b64(v) } : v)); }
            catch (e) { return clip(x, 200); }
          }
          return x;
        });
        rec({ probe: 'crypto', op, phase: 'in', args: safe });
      } catch (e) {}
      return Promise.resolve(orig.apply(this, a)).then(
        (out) => {
          try { rec({ probe: 'crypto', op, phase: 'out',
                      out: (out instanceof ArrayBuffer || ArrayBuffer.isView(out)) ? _b64(out) : clip(out, 500) }); }
          catch (e) {}
          return out;
        },
        (err) => { try { rec({ probe: 'crypto', op, phase: 'error', error: String(err) }); } catch (e) {} throw err; });
    };
    masq(w, orig);
    try { Object.defineProperty(sub, op, { value: w, writable: true, configurable: true }); } catch (e) {}
  }
})();
"""

_EVALFN = """
(() => {
  const { _clip: clip, _masq: masq, rec } = window.__sbi__;
  const oe = window.eval;
  const we = function (s) { try { rec({ probe: 'eval', src: clip(s, 4000) }); } catch (e) {} return oe.apply(window, arguments); };
  masq(we, oe);
  try { window.eval = we; } catch (e) {}
  const F = window.Function;
  const WF = function (...a) {
    try { rec({ probe: 'Function', src: clip(a[a.length - 1], 4000) }); } catch (e) {}
    return F.apply(this, a);
  };
  WF.prototype = F.prototype;
  masq(WF, F);
  try { window.Function = WF; } catch (e) {}
})();
"""

_NET = """
(() => {
  const { _clip: clip, _b64, _masq: masq, rec } = window.__sbi__;
  if (typeof window.fetch === 'function') {
    const of = window.fetch;
    const wf = function (input, init) {
      const r = { probe: 'fetch', phase: 'in',
                  url: clip(typeof input === 'string' ? input : (input && input.url), 2000),
                  method: (init && init.method) || (input && input.method) || 'GET' };
      try {
        const b = init && init.body;
        if (typeof b === 'string') r.body = clip(b, 4000);
        else if (b instanceof ArrayBuffer || ArrayBuffer.isView(b)) r.body_b64 = _b64(b);
        else if (b && typeof b === 'object') r.body = clip(JSON.stringify(b), 4000);
      } catch (e) {}
      rec(r);
      return of.apply(this, arguments).then((res) => {
        try { rec({ probe: 'fetch', phase: 'out', url: r.url, status: res.status }); } catch (e) {}
        return res;
      });
    };
    masq(wf, of);
    try { window.fetch = wf; } catch (e) {}
  }
  const X = window.XMLHttpRequest;
  if (X && X.prototype) {
    const oo = X.prototype.open, ss = X.prototype.send;
    const wo = function (m, u) { this.__sbi = { m, u }; return oo.apply(this, arguments); };
    const ws = function (body) {
      try {
        const i = this.__sbi || {};
        rec({ probe: 'xhr', phase: 'in', method: i.m, url: clip(i.u, 2000),
              body: typeof body === 'string' ? clip(body, 4000) : (body ? clip(body, 200) : null) });
      } catch (e) {}
      return ss.apply(this, arguments);
    };
    masq(wo, oo); masq(ws, ss);
    try { X.prototype.open = wo; X.prototype.send = ws; } catch (e) {}
  }
})();
"""

_FINGERPRINT = """
(() => {
  const { _clip: clip, rec } = window.__sbi__;
  const masq = window.__sbi__._masq;
  // canvas 2D: getContext + the read-back calls that feed fingerprint hashes
  try {
    const origGet = HTMLCanvasElement.prototype.getContext;
    const wg = function (type) {
      try { rec({ probe: 'fp', api: 'canvas.getContext', args: [String(type)] }); } catch (e) {}
      const ctx = origGet.apply(this, arguments);
      if (ctx && ctx.getImageData && !ctx.__sbi__) {
        const oi = ctx.getImageData, od = ctx.toDataURL;
        try {
          const wi = function () { rec({ probe: 'fp', api: 'canvas.getImageData' }); return oi.apply(this, arguments); };
          masq(wi, oi);
          Object.defineProperty(ctx, 'getImageData', { value: wi, writable: true, configurable: true });
        } catch (e) {}
      }
      return ctx;
    };
    masq(wg, origGet);
    Object.defineProperty(HTMLCanvasElement.prototype, 'getContext', { value: wg, writable: true, configurable: true });
  } catch (e) {}
  // webgl: vendor/renderer strings are the classic fingerprint read
  try {
    for (const name of ['WebGLRenderingContext', 'WebGL2RenderingContext']) {
      const Proto = window[name] && window[name].prototype;
      if (!Proto) continue;
      const op = Proto.getParameter;
      const wp = function (p) {
        const v = op.apply(this, arguments);
        try { if (typeof v === 'string') rec({ probe: 'fp', api: 'webgl.getParameter', args: [String(p), String(v).slice(0, 120)] }); } catch (e) {}
        return v;
      };
      masq(wp, op);
      Object.defineProperty(Proto, 'getParameter', { value: wp, writable: true, configurable: true });
    }
  } catch (e) {}
  // audio fingerprint read
  try {
    if (window.OfflineAudioContext) {
      const oc = OfflineAudioContext.prototype.startRendering;
      const wo = function () { rec({ probe: 'fp', api: 'audio.startRendering' }); return oc.apply(this, arguments); };
      masq(wo, oc);
      Object.defineProperty(OfflineAudioContext.prototype, 'startRendering', { value: wo, writable: true, configurable: true });
    }
  } catch (e) {}
  // battery / hardware hints
  try {
    if (navigator.getBattery) {
      const ob = navigator.getBattery.bind(navigator);
      const wb = function () { rec({ probe: 'fp', api: 'navigator.getBattery' }); return ob(); };
      masq(wb, ob);
      Object.defineProperty(navigator, 'getBattery', { value: wb, writable: true, configurable: true });
    }
  } catch (e) {}
})();
"""

_DOM = """
(() => {
  try {
    const { rec } = window.__sbi__;
    const obs = new MutationObserver((muts) => {
      for (const m of muts) {
        if (m.type === 'childList') {
          for (const n of m.addedNodes) {
            rec({ probe: 'dom', phase: 'added',
                  tag: n.tagName || null,
                  detail: n.tagName === 'IFRAME' || n.tagName === 'SCRIPT'
                    ? String(n.src || '').slice(0, 200) : null });
          }
        } else if (m.type === 'attributes') {
          rec({ probe: 'dom', phase: 'attr', tag: m.target.tagName,
                attr: m.attributeName });
        }
      }
    });
    obs.observe(document.documentElement, { childList: true, subtree: true, attributes: true });
    window.__sbi__.rec({ probe: 'dom', phase: 'installed' });
  } catch (e) {}
})();
"""

_API = """
(() => {
  const { rec, _masq: masq } = window.__sbi__;
  const wrap = (obj, prop, kind, label) => {
    try {
      const d = Object.getOwnPropertyDescriptor(obj, prop);
      if (!d || !d.configurable) return;
      Object.defineProperty(obj, prop, { configurable: true,
        get() { rec({ probe: 'api', kind: kind + '.get', target: label }); return d.get ? d.get.call(this) : d.value; },
        set(v) { rec({ probe: 'api', kind: kind + '.set', target: label, value: String(v).slice(0, 120) }); d.set ? d.set.call(this, v) : (d.value = v); }
      });
    } catch (e) {}
  };
  wrap(document, 'cookie', 'cookie', 'document');
  wrap(document, 'referrer', 'referrer', 'document');
  for (const p of ['userAgent', 'plugins', 'languages', 'hardwareConcurrency', 'deviceMemory', 'webdriver'])
    wrap(Navigator.prototype, p, 'navigator', p);
  for (const p of ['getItem', 'setItem'])
    for (const [n, s] of [['local', localStorage], ['session', sessionStorage]]) {
      const o = s[p];
      const w = function (k) { rec({ probe: 'api', kind: n + '.' + p, target: String(k).slice(0, 80) }); return o.apply(this, arguments); };
      masq(w, o);
      Object.defineProperty(Storage.prototype, p, { value: w, writable: true, configurable: true });
    }
  const oa = EventTarget.prototype.addEventListener;
  const wa = function (t) { rec({ probe: 'api', kind: 'addEventListener', target: String(t).slice(0, 60) }); return oa.apply(this, arguments); };
  masq(wa, oa);
  EventTarget.prototype.addEventListener = wa;
  const opm = window.postMessage;
  const wpm = function (m, t) { rec({ probe: 'api', kind: 'postMessage', value: String(m).slice(0, 120) }); return opm.apply(this, arguments); };
  masq(wpm, opm);
  try { Object.defineProperty(window, 'postMessage', { value: wpm, writable: true, configurable: true }); } catch (e) {}
  const ow = window.Worker;
  if (ow) { const ww = function (u) { rec({ probe: 'api', kind: 'new Worker', target: String(u).slice(0, 120) }); return new ow(u, ...[].slice.call(arguments, 1)); }; masq(ww, ow); try { window.Worker = ww; } catch (e) {} }
  if (window.WebAssembly) {
    const oi = WebAssembly.instantiate;
    const wi = function (b) { rec({ probe: 'api', kind: 'wasm.instantiate' }); return oi.apply(this, arguments); };
    masq(wi, oi);
    try { Object.defineProperty(WebAssembly, 'instantiate', { value: wi, writable: true, configurable: true }); } catch (e) {}
  }
})();
"""

_BODIES = {"crypto": _CRYPTO, "eval": _EVALFN, "net": _NET,
           "fingerprint": _FINGERPRINT, "dom": _DOM, "api": _API}


def build_sources(names, buffer_max=800):
    """One combined script; installed on every instrumented page before page scripts run."""
    names = [n for n in (names or []) if n in _BODIES]
    if not names:
        return []
    core = _CORE % {"max": buffer_max}
    return [core + "".join(_BODIES[n] for n in names)]


def install(cdp, sid, names, buffer_max=800):
    for src in build_sources(names, buffer_max):
        cdp.send("Page.addScriptToEvaluateOnNewDocument", {"source": src}, session_id=sid)
        # also wrap the current document: hostile SDKs often destructure
        # crypto.subtle/fetch at load, and the recorder must exist by then on
        # both this document and every future one
        try:
            cdp.send("Runtime.evaluate", {"expression": src}, session_id=sid)
        except Exception:
            pass


def drain(cdp, sid):
    r = cdp.send("Runtime.evaluate",
                 {"expression": "window.__sbi__ ? window.__sbi__.drain() : '[]'",
                  "returnByValue": True}, session_id=sid)
    try:
        return json.loads(r.get("result", {}).get("value") or "[]")
    except Exception:
        return []
