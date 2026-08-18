/* Centinela - looking glass.
   Sin dependencias externas: la politica de contenido no admite CDN.

   Todo el contenido dinamico se inserta con textContent y nodos creados a
   mano. Nunca con innerHTML: parte de lo que mostramos procede de servidores
   de terceros (cabeceras HTTP, certificados, TXT de DNS) y no debe poder
   inyectar marcado en esta pagina. */
(function () {
  'use strict';

  var form       = document.getElementById('lgform');
  var results    = document.getElementById('results');
  var runBtn     = document.getElementById('run');
  var targetIn   = document.getElementById('target');
  var portIn     = document.getElementById('port');
  var typeIn     = document.getElementById('type');
  var optPort    = document.getElementById('opt-port');
  var optType    = document.getElementById('opt-type');
  var capRow     = document.getElementById('captcha-row');
  var capQ       = document.getElementById('cquestion');
  var capA       = document.getElementById('canswer');
  var capT       = document.getElementById('ctoken');
  var quota      = document.getElementById('quota');
  var activeLbl  = document.getElementById('active-label');
  var activeDesc = document.getElementById('active-desc');
  var activeIcon = document.getElementById('active-icon');
  var historyBox = document.getElementById('history');
  var historyList= document.getElementById('history-list');
  var tools      = Array.prototype.slice.call(document.querySelectorAll('.tool'));

  var current = null;
  var busy = false;

  /* ------------------------------------------------------------- utiles -- */
  function el(tag, cls, text) {
    var n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text !== undefined && text !== null) n.textContent = String(text);
    return n;
  }

  function icon(name, cls) {
    var svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('viewBox', '0 0 16 16');
    svg.setAttribute('fill', 'none');
    svg.setAttribute('stroke', 'currentColor');
    svg.setAttribute('aria-hidden', 'true');
    // Sin medidas propias un SVG ocupa el tamano por defecto de elemento
    // reemplazado (300x150). Las reglas de la hoja de estilos siguen mandando
    // donde existan; esto solo evita el desbordamiento donde no las hay.
    svg.setAttribute('width', '15');
    svg.setAttribute('height', '15');
    if (cls) svg.setAttribute('class', cls);
    var use = document.createElementNS('http://www.w3.org/2000/svg', 'use');
    use.setAttribute('href', '#i-' + name);
    svg.appendChild(use);
    return svg;
  }

  var STATUS_TEXT = { good: 'correcto', warn: 'atencion', crit: 'critico' };
  var STATUS_GLYPH = { good: '✓', warn: '!', crit: '✕' };

  /* Indicador de estado: glifo + palabra, para no depender del color. */
  function pill(status) {
    if (!status || !STATUS_TEXT[status]) return null;
    var p = el('span', 'pill pill-' + status);
    p.appendChild(el('span', 'g', STATUS_GLYPH[status]));
    p.appendChild(document.createTextNode(STATUS_TEXT[status]));
    return p;
  }

  /* --------------------------------------------------- seleccion de tool -- */
  function selectTool(btn, focus) {
    tools.forEach(function (t) { t.setAttribute('aria-pressed', String(t === btn)); });
    current = {
      cmd:   btn.dataset.cmd,
      label: btn.dataset.label,
      field: btn.dataset.field,
      icon:  btn.dataset.icon
    };

    activeLbl.textContent = btn.dataset.label;
    activeDesc.textContent = btn.dataset.desc;
    activeIcon.firstChild.setAttribute('href', '#i-' + btn.dataset.icon);
    targetIn.placeholder = btn.dataset.hint || 'ejemplo.com';

    optPort.hidden = btn.dataset.field !== 'port';
    optType.hidden = btn.dataset.field !== 'type';
    if (btn.dataset.cmd === 'tls' && !portIn.value) portIn.value = '443';

    if (focus) targetIn.focus();
  }

  tools.forEach(function (btn) {
    btn.addEventListener('click', function () { selectTool(btn, true); });
  });
  selectTool(tools[0], false);

  /* -------------------------------------------------------- renderizado -- */
  function renderRows(block) {
    var card = el('div', 'card' + (block.status ? ' st-' + block.status : ''));
    var h = el('h3');
    h.appendChild(document.createTextNode(block.title));
    var st = pill(block.status);
    if (st) { h.appendChild(el('span', '', ' ')); h.appendChild(st); }
    card.appendChild(h);

    (block.data || []).forEach(function (row) {
      var r = el('div', 'kv-row');
      r.appendChild(el('div', 'k', row.k));
      var v = el('div', 'v');
      v.appendChild(document.createTextNode(
        Array.isArray(row.v) ? row.v.join(', ') : String(row.v)
      ));
      if (row.status) {
        v.appendChild(document.createTextNode(' '));
        v.appendChild(pill(row.status));
      }
      if (row.note) v.appendChild(el('span', 'note', row.note));
      r.appendChild(v);
      card.appendChild(r);
    });
    return card;
  }

  function renderScore(block) {
    var d = block.data || {};
    var card = el('div', 'card' + (block.status ? ' st-' + block.status : ''));
    card.appendChild(el('h3', null, block.title));

    var wrap = el('div', 'scoreblock');
    var g = el('div', 'grade ' + (block.status ? 'st-' + block.status : '') +
                     (String(d.grade || '').length > 2 ? ' sm' : ''), d.grade);
    wrap.appendChild(g);

    var meta = el('div', 'meta');
    meta.appendChild(el('div', 'lead', d.label || ''));
    if (d.total) {
      meta.appendChild(el('div', 'sub', d.score + ' de ' + d.total));
      var m = el('div', 'meter');
      var i = el('i', block.status ? 'st-' + block.status : '');
      i.style.width = Math.max(3, Math.round((d.score / d.total) * 100)) + '%';
      m.appendChild(i);
      meta.appendChild(m);
    }
    wrap.appendChild(meta);
    card.appendChild(wrap);
    return card;
  }

  function renderTags(block) {
    var card = el('div', 'card');
    card.appendChild(el('h3', null, block.title));
    var box = el('div', 'tags');
    (block.data || []).forEach(function (t) { box.appendChild(el('span', 'tag', t)); });
    if (!(block.data || []).length) box.appendChild(el('span', 'tag', 'sin datos'));
    card.appendChild(box);
    return card;
  }

  /* ------------------------------------------------------- mapa BGP ------ */
  /* El mapa mundial (Natural Earth, dominio publico) vive en un asset propio
     y se carga solo la primera vez que alguien pide esta herramienta. */

  function ensureWorld(cb) {
    if (window.CENT_WORLD) { cb(true); return; }
    var sc = document.createElement('script');
    sc.src = 'assets/worldmap.js?v=' + Date.now();
    sc.onload = function () { cb(!!window.CENT_WORLD); };
    sc.onerror = function () { cb(false); };
    document.head.appendChild(sc);
  }

  var SVGNS = 'http://www.w3.org/2000/svg';
  function svgEl(tag, attrs) {
    var n = document.createElementNS(SVGNS, tag);
    for (var k in attrs) n.setAttribute(k, attrs[k]);
    return n;
  }

  // Debe coincidir con la proyeccion con la que se genero worldmap.js
  var MAP_W = 1000, MAP_H = 400, LAT_TOP = 84, LAT_BOT = -60;
  function projX(lon) { return (lon + 180) / 360 * MAP_W; }
  function projY(lat) { return (LAT_TOP - lat) / (LAT_TOP - LAT_BOT) * MAP_H; }

  function renderMap(block) {
    var d = block.data || {};
    var card = el('div', 'card bgpmap-card');
    var h = el('h3', null, block.title + ' · ' + (d.asn || ''));
    if (d.org) h.appendChild(el('span', 'muted', '  ' + d.org));
    card.appendChild(h);

    var wrap = el('div', 'bgpmap');
    card.appendChild(wrap);
    var detail = el('div', 'mapdetail');
    card.appendChild(detail);

    ensureWorld(function (okWorld) {
      if (!okWorld) {
        wrap.appendChild(el('div', 'muted', 'No se pudo cargar el mapa base.'));
        return;
      }
      buildMap(wrap, detail, d);
    });

    var notas = [];
    if (d.clipped > 0) notas.push('Se muestran los ' + '400 puntos con mas prefijos (' + d.clipped + ' recortados).');
    if (d.nogeo > 0) notas.push(d.nogeo + ' prefijo(s) sin geolocalizacion conocida.');
    notas.push('Geolocalizacion aproximada (MaxMind GeoLite): situa el registro del prefijo, no necesariamente el trafico. Datos BGP: RIPEstat / RIPE NCC.');
    card.appendChild(el('div', 'mapnote', notas.join(' ')));
    return card;
  }

  function buildMap(wrap, detail, d) {
    var world = window.CENT_WORLD;
    var view = { x: 0, y: 0, w: MAP_W, h: MAP_H };
    var svg = svgEl('svg', { 'class': 'bgpsvg', viewBox: '0 0 ' + MAP_W + ' ' + MAP_H, role: 'img' });
    svg.setAttribute('aria-label', 'Mapa mundial con los anuncios BGP');

    // tierra
    var land = svgEl('g', { 'class': 'land' });
    world.countries.forEach(function (c) {
      var pth = svgEl('path', { d: c.d, 'data-cc': c.i });
      land.appendChild(pth);
    });
    svg.appendChild(land);

    // puntos de anuncio
    var dots = svgEl('g', { 'class': 'dots' });
    var maxN = 1;
    (d.points || []).forEach(function (p) { if (p.n > maxN) maxN = p.n; });

    (d.points || []).forEach(function (p, idx) {
      var x = projX(p.lon), y = projY(p.lat);
      if (y < 0 || y > MAP_H) return;
      var r = 2.2 + 2.4 * Math.log(1 + p.n) / Math.log(1 + maxN) * 2.6;
      var halo = svgEl('circle', { cx: x, cy: y, r: r * 2.1, 'class': 'halo' + (idx < 3 ? ' pulse' : '') });
      var core = svgEl('circle', { cx: x, cy: y, r: r, 'class': 'core' });
      halo.setAttribute('data-r', String(r * 2.1));
      core.setAttribute('data-r', String(r));
      var g = svgEl('g', { 'class': 'dot', 'data-cc': p.cc, tabindex: '0' });
      g.appendChild(halo); g.appendChild(core);
      g.addEventListener('mouseenter', function (e) { showMapTip(wrap, p, e); });
      g.addEventListener('mousemove', function (e) { moveMapTip(wrap, e); });
      g.addEventListener('mouseleave', function () { hideMapTip(wrap); });
      var act = function () { showDetail(detail, p); };
      g.addEventListener('click', act);
      g.addEventListener('keydown', function (e) { if (e.key === 'Enter') act(); });
      dots.appendChild(g);
    });
    svg.appendChild(dots);
    wrap.appendChild(svg);

    // controles de zoom
    var ctl = el('div', 'mapctl');
    [['+', 1 / 1.5], ['−', 1.5], ['⟲', 0]].forEach(function (c) {
      var b = el('button', 'btn btn-ghost', c[0]);
      b.type = 'button';
      b.addEventListener('click', function () {
        if (c[1] === 0) { view = { x: 0, y: 0, w: MAP_W, h: MAP_H }; }
        else { zoomAt(view, MAP_W / 2, MAP_H / 2, c[1]); }
        applyView(svg, dots, view);
      });
      ctl.appendChild(b);
    });
    wrap.appendChild(ctl);

    // rueda: zoom sobre el cursor; arrastre: desplazamiento
    svg.addEventListener('wheel', function (e) {
      e.preventDefault();
      var pt = clientToMap(svg, view, e.clientX, e.clientY);
      zoomAt(view, pt.x, pt.y, e.deltaY > 0 ? 1.35 : 1 / 1.35);
      applyView(svg, dots, view);
    }, { passive: false });

    var drag = null;
    svg.addEventListener('pointerdown', function (e) {
      drag = { cx: e.clientX, cy: e.clientY, x: view.x, y: view.y };
      svg.setPointerCapture(e.pointerId);
    });
    svg.addEventListener('pointermove', function (e) {
      if (!drag) return;
      var box = svg.getBoundingClientRect();
      view.x = drag.x - (e.clientX - drag.cx) * view.w / box.width;
      view.y = drag.y - (e.clientY - drag.cy) * view.h / box.height;
      applyView(svg, dots, view);
    });
    svg.addEventListener('pointerup', function () { drag = null; });
    svg.addEventListener('dblclick', function () {
      view = { x: 0, y: 0, w: MAP_W, h: MAP_H };
      applyView(svg, dots, view);
    });

    // fichas por pais: al pasar se atenua el resto; al pulsar, zoom al pais
    var chips = el('div', 'mapchips');
    (d.countries || []).slice(0, 18).forEach(function (c) {
      var chip = el('button', 'chip', c.cc + ' ' + c.n);
      chip.type = 'button';
      chip.addEventListener('mouseenter', function () { svg.classList.add('filtering'); markCc(dots, land, c.cc, true); });
      chip.addEventListener('mouseleave', function () { svg.classList.remove('filtering'); markCc(dots, land, c.cc, false); });
      chip.addEventListener('click', function () {
        var bb = ccBounds(d.points, c.cc);
        if (bb) { view = bb; applyView(svg, dots, view); }
      });
      chips.appendChild(chip);
    });
    wrap.appendChild(chips);
  }

  function clientToMap(svg, view, cx, cy) {
    var box = svg.getBoundingClientRect();
    return { x: view.x + (cx - box.left) / box.width * view.w,
             y: view.y + (cy - box.top) / box.height * view.h };
  }

  function zoomAt(view, mx, my, f) {
    var w = Math.min(MAP_W, Math.max(30, view.w * f));
    var h = w * MAP_H / MAP_W;
    view.x = mx - (mx - view.x) * (w / view.w);
    view.y = my - (my - view.y) * (h / view.h);
    view.w = w; view.h = h;
  }

  function applyView(svg, dots, view) {
    view.x = Math.max(-MAP_W * 0.2, Math.min(MAP_W * 1.2 - view.w, view.x));
    view.y = Math.max(-40, Math.min(MAP_H + 40 - view.h, view.y));
    svg.setAttribute('viewBox', view.x + ' ' + view.y + ' ' + view.w + ' ' + view.h);
    // los puntos conservan su tamano en pantalla aunque se acerque el mapa
    var k = view.w / MAP_W;
    Array.prototype.forEach.call(dots.querySelectorAll('circle'), function (c) {
      c.setAttribute('r', parseFloat(c.getAttribute('data-r')) * k);
    });
  }

  function ccBounds(points, cc) {
    var xs = [], ys = [];
    (points || []).forEach(function (p) {
      if (p.cc === cc) { xs.push(projX(p.lon)); ys.push(projY(p.lat)); }
    });
    if (!xs.length) return null;
    var minX = Math.min.apply(null, xs), maxX = Math.max.apply(null, xs);
    var minY = Math.min.apply(null, ys), maxY = Math.max.apply(null, ys);
    var w = Math.max(60, (maxX - minX) * 1.6), h = w * MAP_H / MAP_W;
    return { x: (minX + maxX) / 2 - w / 2, y: (minY + maxY) / 2 - h / 2, w: w, h: h };
  }

  function markCc(dots, land, cc, on) {
    Array.prototype.forEach.call(dots.querySelectorAll('.dot'), function (g) {
      g.classList.toggle('dim', on && g.getAttribute('data-cc') !== cc);
    });
    Array.prototype.forEach.call(land.querySelectorAll('path'), function (p) {
      p.classList.toggle('lit', on && p.getAttribute('data-cc') === cc);
    });
  }

  function mapTipEl(wrap) {
    var t = wrap.querySelector('.maptip');
    if (!t) { t = el('div', 'maptip'); wrap.appendChild(t); }
    return t;
  }

  function showMapTip(wrap, p, e) {
    var t = mapTipEl(wrap);
    t.textContent = '';
    t.appendChild(el('b', null, (p.city || 'Sin ciudad') + ' · ' + p.cc));
    t.appendChild(el('div', null, p.n + ' prefijo(s)' + (p.v6 ? ' · ' + p.v6 + ' IPv6' : '')));
    if (p.pfx && p.pfx.length) t.appendChild(el('div', 'mono', p.pfx.slice(0, 3).join('  ')));
    t.classList.add('on');
    moveMapTip(wrap, e);
  }

  function moveMapTip(wrap, e) {
    var t = mapTipEl(wrap);
    var box = wrap.getBoundingClientRect();
    var x = e.clientX - box.left + 14, y = e.clientY - box.top - 10;
    if (x + 220 > box.width) x = e.clientX - box.left - 230;
    t.style.left = x + 'px';
    t.style.top = y + 'px';
  }

  function hideMapTip(wrap) {
    var t = wrap.querySelector('.maptip');
    if (t) t.classList.remove('on');
  }

  function showDetail(detail, p) {
    detail.textContent = '';
    detail.classList.add('on');
    detail.appendChild(el('b', null, (p.city || 'Sin ciudad') + ' · ' + p.cc + ' — ' + p.n + ' prefijo(s) anunciados'));
    var box = el('div', 'pfxlist');
    (p.pfx || []).forEach(function (x) { box.appendChild(el('span', 'tag mono', x)); });
    if (p.n > (p.pfx || []).length) box.appendChild(el('span', 'muted', 'y ' + (p.n - p.pfx.length) + ' mas'));
    detail.appendChild(box);
  }

  function renderRaw(text, openByDefault) {
    var d = el('details', 'raw card');
    if (openByDefault) d.setAttribute('open', '');
    d.appendChild(el('summary', null, 'Salida completa'));
    d.appendChild(el('pre', null, text));
    return d;
  }

  function renderResult(data, toolLabel, target) {
    results.textContent = '';

    var head = el('div', 'result-head');
    head.appendChild(el('span', 'title', toolLabel));
    head.appendChild(el('span', 'target', target));
    head.appendChild(el('div', 'grow'));

    var timing = el('div', 'timing');
    if (data.meta && data.meta.target && data.meta.target !== target) {
      timing.appendChild(el('span', null, '→ ' + data.meta.target));
    }
    if (typeof data.ms === 'number') timing.appendChild(el('span', null, data.ms + ' ms'));
    head.appendChild(timing);

    var copy = el('button', 'btn btn-ghost', 'Copiar');
    copy.type = 'button';
    copy.addEventListener('click', function () {
      var txt = data.output || '';
      if (navigator.clipboard) {
        navigator.clipboard.writeText(txt).then(function () {
          copy.textContent = 'Copiado';
          setTimeout(function () { copy.textContent = 'Copiar'; }, 1600);
        });
      }
    });
    head.appendChild(copy);
    results.appendChild(head);

    var blocks = data.blocks || [];
    blocks.forEach(function (b) {
      if (b.type === 'score')      results.appendChild(renderScore(b));
      else if (b.type === 'tags')  results.appendChild(renderTags(b));
      else if (b.type === 'map')   results.appendChild(renderMap(b));
      else                         results.appendChild(renderRows(b));
    });

    if (data.output) results.appendChild(renderRaw(data.output, blocks.length === 0));
  }

  function renderError(msg) {
    results.textContent = '';
    var b = el('div', 'banner err');
    b.appendChild(el('span', null, '⚠'));
    var t = el('span');
    t.appendChild(el('b', null, 'No se pudo completar. '));
    t.appendChild(document.createTextNode(msg));
    b.appendChild(t);
    results.appendChild(b);
  }

  function renderBusy(label, target) {
    results.textContent = '';
    var card = el('div', 'card');
    var body = el('div', 'scanning');
    body.appendChild(el('span', 'spinner'));
    var txt = el('div');
    txt.appendChild(el('div', null, label + ' · ' + target));
    var bar = el('div', 'scanbar');
    bar.appendChild(el('i'));
    txt.appendChild(bar);
    body.appendChild(txt);
    card.appendChild(body);
    results.appendChild(card);
  }

  /* --------------------------------------------------------- historial --- */
  var history = [];
  try {
    history = JSON.parse(sessionStorage.getItem('cent_lg_hist') || '[]');
  } catch (e) { history = []; }

  function pushHistory(entry) {
    history = history.filter(function (h) {
      return !(h.cmd === entry.cmd && h.target === entry.target);
    });
    history.unshift(entry);
    history = history.slice(0, 12);
    try { sessionStorage.setItem('cent_lg_hist', JSON.stringify(history)); } catch (e) {}
    drawHistory();
  }

  function drawHistory() {
    historyList.textContent = '';
    if (!history.length) { historyBox.hidden = true; return; }
    historyBox.hidden = false;

    history.forEach(function (h) {
      var b = el('button', 'hitem');
      b.type = 'button';
      b.appendChild(icon(h.icon || 'search'));
      b.appendChild(el('span', 'tool-name', h.label));
      b.appendChild(el('span', 'tgt', h.target));
      b.appendChild(el('span', 'when', relTime(h.at)));
      b.addEventListener('click', function () {
        var btn = tools.filter(function (t) { return t.dataset.cmd === h.cmd; })[0];
        if (btn) selectTool(btn, false);
        targetIn.value = h.target;
        if (h.port) portIn.value = h.port;
        if (h.type) typeIn.value = h.type;
        form.dispatchEvent(new Event('submit', { cancelable: true }));
        window.scrollTo({ top: form.offsetTop - 20, behavior: 'smooth' });
      });
      historyList.appendChild(b);
    });
  }

  function relTime(ts) {
    var s = Math.max(0, Math.round((Date.now() - ts) / 1000));
    if (s < 60) return 'hace ' + s + ' s';
    if (s < 3600) return 'hace ' + Math.floor(s / 60) + ' min';
    return 'hace ' + Math.floor(s / 3600) + ' h';
  }
  drawHistory();

  /* ------------------------------------------------------------- envio --- */
  function setBusy(on) {
    busy = on;
    runBtn.disabled = on;
    runBtn.textContent = '';
    if (on) {
      runBtn.appendChild(el('span', 'spinner'));
      runBtn.appendChild(document.createTextNode(' Ejecutando'));
    } else {
      runBtn.appendChild(icon('search'));
      runBtn.appendChild(document.createTextNode(' Ejecutar'));
    }
  }

  form.addEventListener('submit', function (e) {
    e.preventDefault();
    if (busy) return;

    var target = targetIn.value.trim();
    if (!target) { targetIn.focus(); return; }

    var body = new URLSearchParams();
    body.append('cmd', current.cmd);
    body.append('target', target);
    if (current.field === 'port') body.append('port', portIn.value);
    if (current.field === 'type') body.append('type', typeIn.value);
    if (capT.value) {
      body.append('ctoken', capT.value);
      body.append('canswer', capA.value);
    }

    setBusy(true);
    renderBusy(current.label, target);

    fetch('lg.php', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString()
    })
      .then(function (r) { return r.json(); })
      .then(function (d) {
        if (d.need_captcha) {
          capRow.hidden = false;
          capQ.textContent = d.captcha.question;
          capT.value = d.captcha.token;
          capA.value = '';
          capA.focus();
          results.textContent = '';
          var b = el('div', 'banner warn');
          b.appendChild(el('span', null, '⚠'));
          b.appendChild(document.createTextNode(
            d.error ? d.error + ' Resuelve la verificacion y vuelve a intentarlo.'
                    : 'Resuelve la verificacion para lanzar la primera consulta.'
          ));
          results.appendChild(b);
          return;
        }

        capRow.hidden = true;
        capT.value = '';

        if (typeof d.remaining === 'number') {
          quota.textContent = d.remaining + ' consultas disponibles este minuto';
        }

        if (!d.ok) { renderError(d.error || 'La consulta no devolvio resultado.'); return; }

        renderResult(d, current.label, target);
        pushHistory({
          cmd: current.cmd, label: current.label, icon: current.icon,
          target: target, at: Date.now(),
          port: current.field === 'port' ? portIn.value : null,
          type: current.field === 'type' ? typeIn.value : null
        });
      })
      .catch(function () {
        renderError('No se pudo contactar con el servidor. Comprueba tu conexion.');
      })
      .finally(function () { setBusy(false); });
  });

  /* ------------------------------------------------------------ teclado -- */
  document.addEventListener('keydown', function (e) {
    if (e.key === '/' && document.activeElement !== targetIn && !e.metaKey && !e.ctrlKey) {
      e.preventDefault();
      targetIn.focus();
      targetIn.select();
    }
    if (e.key === 'Escape' && document.activeElement === targetIn) {
      targetIn.value = '';
    }
  });
})();
