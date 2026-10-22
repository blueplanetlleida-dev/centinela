/* Centinela central - comportamiento del panel.
   Sin dependencias. Todo el DOM se construye con createElement/textContent:
   ningun dato llega a innerHTML. */
(function () {
  'use strict';

  var BASE = document.body.getAttribute('data-base') || '';
  var nf0 = new Intl.NumberFormat('es-ES', { maximumFractionDigits: 0 });
  var nf1 = new Intl.NumberFormat('es-ES', { maximumFractionDigits: 1 });
  var nf2 = new Intl.NumberFormat('es-ES', { maximumFractionDigits: 2 });
  var SVGNS = 'http://www.w3.org/2000/svg';

  function el(tag, attrs, text) {
    var e = document.createElement(tag);
    if (attrs) for (var k in attrs) e.setAttribute(k, attrs[k]);
    if (text != null) e.textContent = text;
    return e;
  }
  function svg(tag, attrs) {
    var e = document.createElementNS(SVGNS, tag);
    if (attrs) for (var k in attrs) e.setAttribute(k, attrs[k]);
    return e;
  }

  // ---------------------------------------------------------------- tiempo relativo
  function dur(sec) {
    if (sec < 60) return sec + ' s';
    if (sec < 3600) return Math.floor(sec / 60) + ' min';
    if (sec < 86400) {
      var h = Math.floor(sec / 3600), m = Math.floor(sec % 3600 / 60);
      return m ? h + ' h ' + m + ' min' : h + ' h';
    }
    var d = Math.floor(sec / 86400), hh = Math.floor(sec % 86400 / 3600);
    return hh && d < 10 ? d + ' d ' + hh + ' h' : d + ' d';
  }
  function tickTimes() {
    var now = Date.now() / 1000;
    document.querySelectorAll('time[data-ts]').forEach(function (t) {
      var diff = Math.max(0, Math.round(now - Number(t.getAttribute('data-ts'))));
      t.textContent = diff < 45 ? 'ahora' : 'hace ' + dur(diff);
    });
  }
  setInterval(tickTimes, 20000);

  // ---------------------------------------------------------------- filas que enlazan
  document.addEventListener('click', function (e) {
    var tr = e.target.closest('tr[data-href]');
    if (!tr || e.target.closest('a, button, input, form')) return;
    if (e.metaKey || e.ctrlKey) { window.open(tr.getAttribute('data-href')); return; }
    location.href = tr.getAttribute('data-href');
  });

  // ---------------------------------------------------------------- confirmaciones
  document.addEventListener('submit', function (e) {
    // Un formulario con varios botones (guardar, borrar...) confirma segun el boton pulsado.
    var b = e.submitter;
    var msg = (b && b.getAttribute('data-confirm')) || e.target.getAttribute('data-confirm');
    if (msg && !window.confirm(msg)) e.preventDefault();
  });

  // ---------------------------------------------------------------- copiar ordenes
  function iconUse(name) {
    var s = svg('svg', { class: 'icon', 'aria-hidden': 'true' });
    var u = svg('use');
    u.setAttribute('href', BASE + '/static/icons.svg#i-' + name);
    s.appendChild(u);
    return s;
  }
  document.querySelectorAll('[data-copy]').forEach(function (box) {
    var text = box.textContent;
    var b = el('button', { type: 'button', class: 'copy', title: 'Copiar', 'aria-label': 'Copiar' });
    b.appendChild(iconUse('copy'));
    b.addEventListener('click', function () {
      var done = function () {
        b.replaceChildren(iconUse('check'));
        setTimeout(function () { b.replaceChildren(iconUse('copy')); }, 1600);
      };
      if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(text).then(done);
      } else {
        var ta = el('textarea');
        ta.value = text;
        ta.style.position = 'fixed'; ta.style.opacity = '0';
        document.body.appendChild(ta); ta.select();
        try { document.execCommand('copy'); done(); } catch (err) { /* sin portapapeles */ }
        ta.remove();
      }
    });
    box.appendChild(b);
  });

  // ---------------------------------------------------------------- refresco de fragmentos
  function refresh(box) {
    if (document.hidden) return;
    fetch(box.getAttribute('data-refresh'), { credentials: 'same-origin', headers: { 'X-Requested-With': 'fetch' } })
      .then(function (r) {
        if (r.status === 401) { location.reload(); return null; }
        return r.ok ? r.text() : null;
      })
      .then(function (html) {
        if (html == null) return;
        // DOMParser no ejecuta scripts; el HTML viene del propio servidor ya escapado.
        var doc = new DOMParser().parseFromString('<div>' + html + '</div>', 'text/html');
        box.replaceChildren.apply(box, Array.prototype.slice.call(doc.body.firstChild.childNodes));
        tickTimes();
      })
      .catch(function () { /* sin red: se reintenta en la vuelta siguiente */ });
  }
  document.querySelectorAll('[data-refresh]').forEach(function (box) {
    setInterval(function () { refresh(box); }, 30000);
  });
  document.addEventListener('visibilitychange', function () {
    if (!document.hidden) document.querySelectorAll('[data-refresh]').forEach(refresh);
  });

  // ---------------------------------------------------------------- graficas
  var CHARTS = {
    cpu: { unit: 'pct', max: 100, series: [['cpu', 'Uso'], ['iowait', 'Espera de E/S'], ['steal', 'Retenida (steal)']] },
    mem: { unit: 'pct', max: 100, series: [['mem', 'RAM'], ['swap', 'Swap']] },
    load: { unit: 'num', series: [['load', 'Carga']] },
    disk: { unit: 'pct', max: 100, series: [['disk', 'Ocupación']] },
    net: { unit: 'rate', series: [['rx', 'Entrada'], ['tx', 'Salida']] },
    io: { unit: 'rate', series: [['rd', 'Lectura'], ['wr', 'Escritura']] },
    temp: { unit: 'temp', series: [['temp', 'Máxima']] }
  };

  function bytes(v) {
    var u = ['B', 'KB', 'MB', 'GB', 'TB'], i = 0;
    while (Math.abs(v) >= 1024 && i < u.length - 1) { v /= 1024; i++; }
    return (i === 0 ? nf0 : nf1).format(v) + ' ' + u[i];
  }
  function fmt(unit, v) {
    if (v == null) return '—';
    if (unit === 'pct') return nf1.format(v) + ' %';
    if (unit === 'temp') return nf1.format(v) + ' °C';
    if (unit === 'rate') return bytes(v) + '/s';
    return nf2.format(v);
  }
  function fmtAxis(unit, v) {
    if (unit === 'pct') return nf0.format(v) + ' %';
    if (unit === 'temp') return nf0.format(v) + ' °';
    if (unit === 'rate') return bytes(v) + '/s';
    return nf1.format(v);
  }

  function niceStep(span, count) {
    var rough = span / Math.max(1, count);
    var p = Math.pow(10, Math.floor(Math.log10(rough)));
    var f = rough / p;
    return (f <= 1 ? 1 : f <= 2 ? 2 : f <= 2.5 ? 2.5 : f <= 5 ? 5 : 10) * p;
  }
  function yScale(def, maxVal) {
    if (def.max) return { max: def.max, step: def.max / 4 };
    if (def.unit === 'rate') {
      // Pasos redondos en la unidad que se va a leer (KB, MB...), no en bytes.
      var m = Math.max(maxVal, 1024), k = 1;
      while (m / k >= 1024) k *= 1024;
      var st = niceStep(m / k, 4) * k;
      return { max: Math.ceil(m / st) * st, step: st };
    }
    var floor = def.unit === 'temp' ? 40 : 1;
    var mx = Math.max(maxVal * 1.08, floor);
    var s = niceStep(mx, 4);
    return { max: Math.ceil(mx / s) * s, step: s };
  }

  var dtTime = new Intl.DateTimeFormat('es-ES', { hour: '2-digit', minute: '2-digit' });
  var dtDay = new Intl.DateTimeFormat('es-ES', { weekday: 'short', day: 'numeric' });
  var dtDate = new Intl.DateTimeFormat('es-ES', { day: '2-digit', month: '2-digit' });
  var dtMonth = new Intl.DateTimeFormat('es-ES', { month: 'short' });
  var dtFull = new Intl.DateTimeFormat('es-ES', { weekday: 'short', day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' });

  function xTicks(x0, x1, maxTicks) {
    var steps = [900, 1800, 3600, 7200, 10800, 21600, 43200, 86400, 172800, 432000, 604800, 1209600, 2592000];
    var span = x1 - x0, step = steps[steps.length - 1];
    for (var i = 0; i < steps.length; i++) { if (span / steps[i] <= maxTicks) { step = steps[i]; break; } }
    var off = -new Date(x0 * 1000).getTimezoneOffset() * 60;   // marcas alineadas a la hora local
    var out = [];
    for (var t = Math.ceil((x0 + off) / step) * step - off; t <= x1; t += step) out.push(t);
    var f = step < 86400 ? dtTime : step < 432000 ? dtDay : step < 2592000 ? dtDate : dtMonth;
    return out.map(function (t) { return [t, f.format(new Date(t * 1000))]; });
  }

  function bisect(ts, x) {
    var lo = 0, hi = ts.length - 1;
    if (hi < 0) return -1;
    while (hi - lo > 1) { var mid = (lo + hi) >> 1; if (ts[mid] < x) lo = mid; else hi = mid; }
    return Math.abs(ts[lo] - x) <= Math.abs(ts[hi] - x) ? lo : hi;
  }

  var tip = document.getElementById('tip');
  var activeChart = null;

  function Chart(card, def) {
    this.card = card;
    this.def = def;
    this.box = card.querySelector('.chart');
    this.legend = card.querySelector('.legend');
    this.nowEl = card.querySelector('.chart-now');
    this.tableBox = card.querySelector('.chart-table');
    this.toggle = card.querySelector('.chart-toggle');
    this.data = null;
    this.idx = -1;
    var self = this;
    this.toggle.addEventListener('click', function () {
      var open = self.tableBox.hidden;
      self.tableBox.hidden = !open;
      self.toggle.textContent = open ? 'Ocultar tabla' : 'Ver como tabla';
      if (open) self.renderTable();
    });
    this.box.addEventListener('pointermove', function (e) { self.pointer(e); });
    this.box.addEventListener('pointerdown', function (e) { self.pointer(e); });
    this.box.addEventListener('pointerleave', function (e) { if (e.pointerType === 'mouse') self.hide(); });
    this.box.addEventListener('keydown', function (e) { self.key(e); });
    this.box.addEventListener('focus', function () { if (self.idx < 0 && self.data) self.show(self.lastIdx()); });
    this.box.addEventListener('blur', function () { self.hide(); });
  }

  Chart.prototype.active = function () {
    var d = this.data;
    return this.def.series.map(function (s, i) {
      return { key: s[0], name: s[1], cls: 'c' + (i + 1), vals: d.cols[s[0]] || [] };
    }).filter(function (s) { return s.vals.some(function (v) { return v != null; }); });
  };

  Chart.prototype.lastIdx = function () {
    var ts = this.data.ts;
    return ts.length ? ts.length - 1 : -1;
  };

  Chart.prototype.set = function (data) {
    this.data = data;
    this.series = this.active();
    if (this.def === CHARTS.temp) this.card.hidden = this.series.length === 0;
    this.render();
    if (!this.tableBox.hidden) this.renderTable();
  };

  Chart.prototype.render = function () {
    var box = this.box, d = this.data, def = this.def, series = this.series;
    box.classList.remove('loading');
    box.replaceChildren();
    this.legend.replaceChildren();
    this.idx = -1;
    var W = box.clientWidth, H = box.clientHeight;
    if (!series.length || W < 50) {
      box.appendChild(el('div', { class: 'nodata' }, 'Sin datos en este periodo'));
      this.nowEl.textContent = '';
      return;
    }
    var maxVal = 0;
    series.forEach(function (s) { s.vals.forEach(function (v) { if (v != null && v > maxVal) maxVal = v; }); });
    var ys = yScale(def, maxVal);
    var labelW = Math.max(fmtAxis(def.unit, ys.max).length, fmtAxis(def.unit, ys.step).length) * 6.4 + 10;
    var m = { l: Math.round(labelW), r: 10, t: 8, b: 22 };
    var pw = W - m.l - m.r, ph = H - m.t - m.b;
    var x0 = d.from, x1 = d.to;
    var X = function (t) { return m.l + (t - x0) / (x1 - x0) * pw; };
    var Y = function (v) { return m.t + ph - Math.min(v, ys.max) / ys.max * ph; };
    this.X = X; this.Y = Y; this.m = m; this.pw = pw; this.ph = ph;

    var root = svg('svg', { viewBox: '0 0 ' + W + ' ' + H, 'aria-hidden': 'true' });
    for (var v = 0; v <= ys.max + 1e-9; v += ys.step) {
      var y = Y(v);
      root.appendChild(svg('line', { x1: m.l, x2: W - m.r, y1: y, y2: y, class: v === 0 ? 'base-line' : 'grid-line' }));
      var lab = svg('text', { x: m.l - 8, y: y + 3.5, 'text-anchor': 'end', class: 'tick' });
      lab.textContent = fmtAxis(def.unit, v);
      root.appendChild(lab);
    }
    xTicks(x0, x1, Math.max(2, Math.floor(pw / 78))).forEach(function (tk) {
      var t = svg('text', { x: X(tk[0]), y: H - 5, 'text-anchor': 'middle', class: 'tick' });
      t.textContent = tk[1];
      root.appendChild(t);
    });

    // Un hueco mayor de dos pasos y medio es un corte (agente parado): la linea se interrumpe.
    // El paso es el mayor entre el esperado y la mediana real, porque un agente
    // puede haber informado con otro intervalo en el pasado.
    var ts = d.ts, diffs = [];
    for (var di = 1; di < ts.length; di++) diffs.push(ts[di] - ts[di - 1]);
    diffs.sort(function (a, b) { return a - b; });
    var med = diffs.length ? diffs[diffs.length >> 1] : d.step;
    var gap = Math.max(d.step, med) * 2.5 + 5;
    series.forEach(function (s, si) {
      var path = '', area = '', open = false, segStart = 0, lastX = 0;
      for (var i = 0; i < ts.length; i++) {
        var val = s.vals[i];
        var broken = val == null || (i > 0 && ts[i] - ts[i - 1] > gap);
        if (broken && open) {
          area += 'L' + lastX + ',' + Y(0) + 'L' + segStart + ',' + Y(0) + 'Z';
          open = false;
        }
        if (val == null) continue;
        var px = X(ts[i]).toFixed(1), py = Y(val).toFixed(1);
        if (!open) { path += 'M' + px + ',' + py; area += 'M' + px + ',' + Y(0) + 'L' + px + ',' + py; segStart = px; open = true; }
        else { path += 'L' + px + ',' + py; area += 'L' + px + ',' + py; }
        lastX = px;
      }
      if (open) area += 'L' + lastX + ',' + Y(0) + 'L' + segStart + ',' + Y(0) + 'Z';
      if (series.length === 1) root.appendChild(svg('path', { d: area, class: 'wash', style: 'fill: var(--s' + (si + 1) + ')' }));
      root.appendChild(svg('path', { d: path, class: 'series', style: 'stroke: var(--s' + (si + 1) + ')' }));
    });

    this.cross = svg('line', { y1: m.t, y2: m.t + ph, class: 'cross', visibility: 'hidden' });
    root.appendChild(this.cross);
    this.marks = series.map(function (s, si) {
      var c = svg('circle', { r: 4.5, class: 'mark', visibility: 'hidden', style: 'fill: var(--s' + (si + 1) + ')' });
      root.appendChild(c);
      return c;
    });
    box.appendChild(root);

    if (series.length > 1) {
      var lg = this.legend;
      series.forEach(function (s) {
        var item = el('span', { class: s.cls });
        item.appendChild(el('i'));
        item.appendChild(document.createTextNode(s.name));
        lg.appendChild(item);
      });
    }
    var li = this.lastIdx();
    var primero = series[0];
    this.nowEl.textContent = li >= 0 && primero.vals[li] != null ? 'ahora ' + fmt(def.unit, primero.vals[li]) : '';
  };

  Chart.prototype.pointer = function (e) {
    if (!this.data || !this.series.length || !this.X) return;
    var r = this.box.getBoundingClientRect();
    var x = e.clientX - r.left;
    var t = this.data.from + (x - this.m.l) / this.pw * (this.data.to - this.data.from);
    var i = bisect(this.data.ts, t);
    if (i < 0) return;
    this.show(i, e.clientX, e.clientY);
  };

  Chart.prototype.key = function (e) {
    if (!this.data || !this.data.ts.length) return;
    var n = this.data.ts.length, i = this.idx < 0 ? n - 1 : this.idx;
    var jump = Math.max(1, Math.round(n / 24));
    if (e.key === 'ArrowLeft') i = Math.max(0, i - (e.shiftKey ? jump : 1));
    else if (e.key === 'ArrowRight') i = Math.min(n - 1, i + (e.shiftKey ? jump : 1));
    else if (e.key === 'Home') i = 0;
    else if (e.key === 'End') i = n - 1;
    else if (e.key === 'Escape') { this.hide(); return; }
    else return;
    e.preventDefault();
    this.show(i);
  };

  Chart.prototype.show = function (i, cx, cy) {
    var d = this.data, self = this;
    if (i < 0) return;
    this.idx = i;
    var x = this.X(d.ts[i]);
    this.cross.setAttribute('x1', x); this.cross.setAttribute('x2', x);
    this.cross.setAttribute('visibility', 'visible');
    this.series.forEach(function (s, si) {
      var v = s.vals[i], c = self.marks[si];
      if (v == null) { c.setAttribute('visibility', 'hidden'); return; }
      c.setAttribute('cx', x); c.setAttribute('cy', self.Y(v)); c.setAttribute('visibility', 'visible');
    });
    tip.replaceChildren(el('div', { class: 't-when' }, dtFull.format(new Date(d.ts[i] * 1000))));
    this.series.forEach(function (s) {
      var row = el('div', { class: 't-row ' + s.cls });
      row.appendChild(el('i'));
      row.appendChild(el('b', null, fmt(self.def.unit, s.vals[i])));
      row.appendChild(el('span', null, s.name));
      tip.appendChild(row);
    });
    var r = this.box.getBoundingClientRect();
    if (cx == null) { cx = r.left + x; cy = r.top + 20; }
    tip.classList.add('on');
    var tw = tip.offsetWidth, th = tip.offsetHeight;
    var left = cx + 14, top = cy - th - 12;
    if (left + tw > window.innerWidth - 8) left = cx - tw - 14;
    if (left < 8) left = 8;
    if (top < 8) top = cy + 18;
    tip.style.left = left + 'px';
    tip.style.top = top + 'px';
    activeChart = this;
  };

  Chart.prototype.hide = function () {
    if (!this.cross) return;
    this.idx = -1;
    this.cross.setAttribute('visibility', 'hidden');
    this.marks.forEach(function (c) { c.setAttribute('visibility', 'hidden'); });
    if (activeChart === this) { tip.classList.remove('on'); activeChart = null; }
  };

  // Tabla equivalente: medias por tramos, como mucho 48 filas.
  Chart.prototype.renderTable = function () {
    var d = this.data, def = this.def, series = this.series || [];
    var box = this.tableBox;
    box.replaceChildren();
    if (!d || !series.length) { box.appendChild(el('div', { class: 'empty' }, 'Sin datos en este periodo')); return; }
    var n = d.ts.length, per = Math.max(1, Math.ceil(n / 48));
    var table = el('table', { class: 't' }), thead = el('thead'), hr = el('tr');
    hr.appendChild(el('th', null, per > 1 ? 'Desde' : 'Momento'));
    series.forEach(function (s) { hr.appendChild(el('th', { class: 'num' }, s.name + (per > 1 ? ' (media)' : ''))); });
    thead.appendChild(hr); table.appendChild(thead);
    var tb = el('tbody');
    for (var i = n - 1; i >= 0; i -= per) {
      var lo = Math.max(0, i - per + 1), tr = el('tr');
      tr.appendChild(el('td', { class: 'nowrap' }, dtFull.format(new Date(d.ts[lo] * 1000))));
      series.forEach(function (s) {
        var sum = 0, cnt = 0;
        for (var j = lo; j <= i; j++) if (s.vals[j] != null) { sum += s.vals[j]; cnt++; }
        tr.appendChild(el('td', { class: 'num' }, cnt ? fmt(def.unit, sum / cnt) : '—'));
      });
      tb.appendChild(tr);
    }
    table.appendChild(tb);
    box.appendChild(table);
  };

  document.addEventListener('pointerdown', function (e) {
    if (activeChart && !activeChart.box.contains(e.target)) activeChart.hide();
  });
  window.addEventListener('scroll', function () { if (activeChart) activeChart.hide(); }, { passive: true });

  var grid = document.getElementById('charts');
  if (grid) {
    var src = grid.getAttribute('data-src');
    var range = '24h';
    var charts = [];
    grid.querySelectorAll('[data-chart]').forEach(function (card) {
      var def = CHARTS[card.getAttribute('data-chart')];
      if (def) charts.push(new Chart(card, def));
    });
    var load = function () {
      charts.forEach(function (c) { if (c.data) c.box.classList.add('loading'); });
      fetch(src + '?range=' + encodeURIComponent(range), { credentials: 'same-origin' })
        .then(function (r) {
          if (r.status === 401) { location.reload(); return null; }
          return r.ok ? r.json() : null;
        })
        .then(function (data) { if (data && data.ts) charts.forEach(function (c) { c.set(data); }); })
        .catch(function () { charts.forEach(function (c) { c.box.classList.remove('loading'); }); });
    };
    var seg = document.getElementById('range');
    if (seg) seg.addEventListener('click', function (e) {
      var b = e.target.closest('button[data-range]');
      if (!b) return;
      seg.querySelectorAll('button').forEach(function (x) { x.classList.remove('on'); x.removeAttribute('aria-pressed'); });
      b.classList.add('on'); b.setAttribute('aria-pressed', 'true');
      range = b.getAttribute('data-range');
      load();
    });
    var resizeTimer = null;
    if (window.ResizeObserver) {
      var lastW = grid.clientWidth;
      new ResizeObserver(function () {
        if (grid.clientWidth === lastW) return;
        lastW = grid.clientWidth;
        clearTimeout(resizeTimer);
        resizeTimer = setTimeout(function () { charts.forEach(function (c) { if (c.data) c.render(); }); }, 150);
      }).observe(grid);
    }
    load();
    setInterval(function () { if (!document.hidden) load(); }, 60000);
  }
})();
