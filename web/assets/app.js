/* Centinela - interaccion del panel.
   Sin dependencias externas: la politica de contenido no permite CDN. */
(function () {
  'use strict';

  /* --------------------------------------------------- tooltips de graficas */
  var tt = document.getElementById('tt');

  function showTip(e, text) {
    if (!tt) return;
    tt.textContent = text;
    tt.classList.add('on');
    position(e);
  }
  function position(e) {
    if (!tt) return;
    var pad = 12;
    var x = e.clientX + pad;
    var y = e.clientY - 32;
    var r = tt.getBoundingClientRect();
    if (x + r.width > window.innerWidth - 8) x = e.clientX - r.width - pad;
    if (y < 8) y = e.clientY + 20;
    tt.style.left = x + 'px';
    tt.style.top = y + 'px';
  }
  function hideTip() {
    if (tt) tt.classList.remove('on');
  }

  // Delegacion: funciona con cualquier marca que declare data-tip
  document.addEventListener('mouseover', function (e) {
    var el = e.target.closest('[data-tip]');
    if (el) showTip(e, el.getAttribute('data-tip'));
  });
  document.addEventListener('mousemove', function (e) {
    if (tt && tt.classList.contains('on')) position(e);
  });
  document.addEventListener('mouseout', function (e) {
    if (e.target.closest('[data-tip]')) hideTip();
  });
  // Equivalente tactil
  document.addEventListener('touchstart', function (e) {
    var el = e.target.closest('[data-tip]');
    if (el) {
      var t = e.touches[0];
      showTip({ clientX: t.clientX, clientY: t.clientY }, el.getAttribute('data-tip'));
      setTimeout(hideTip, 2500);
    }
  }, { passive: true });

  /* ------------------------------------------------------ edad de los datos */
  var generated = parseInt(document.body.getAttribute('data-generated') || '0', 10);
  var ageEl = document.getElementById('age');

  function relative(sec) {
    if (sec < 60) return 'hace ' + sec + ' s';
    if (sec < 3600) return 'hace ' + Math.floor(sec / 60) + ' min';
    if (sec < 86400) return 'hace ' + Math.floor(sec / 3600) + ' h';
    return 'hace ' + Math.floor(sec / 86400) + ' d';
  }

  if (ageEl && generated > 0) {
    setInterval(function () {
      ageEl.textContent = relative(Math.max(0, Math.floor(Date.now() / 1000) - generated));
    }, 10000);
  }

  /* ------------------------------------------------------- refresco en vivo */
  /* Se consulta solo la marca de tiempo del estado. Si el colector ha
     generado datos nuevos, se recarga la pagina: asi el renderizado vive
     en un unico sitio (el servidor) en vez de duplicarse aqui. */
  var failures = 0;
  // Mientras una recomprobacion esta en curso no se recarga la pagina: el
  // veredicto se pinta en la propia tarjeta y una recarga lo borraria.
  var busy = false;

  function poll() {
    if (busy) return;
    fetch('api.php?v=stamp', { credentials: 'same-origin', cache: 'no-store' })
      .then(function (r) {
        if (r.status === 401 || r.status === 403) { location.href = 'login.php'; return null; }
        if (!r.ok) throw new Error('http ' + r.status);
        return r.json();
      })
      .then(function (d) {
        if (!d) return;
        failures = 0;
        if (d.generated_at && d.generated_at > generated) {
          location.reload();
        }
      })
      .catch(function () {
        // Si falla varias veces seguidas espaciamos las consultas
        failures++;
      });
  }

  // Cada 30 s, y con espera creciente si hay errores. Se pausa si la
  // pestana no esta visible, para no consultar en balde.
  setInterval(function () {
    if (document.hidden) return;
    if (failures > 3 && Date.now() % 4 !== 0) return;
    poll();
  }, 30000);

  document.addEventListener('visibilitychange', function () {
    if (!document.hidden) poll();
  });

  /* ------------------------------------------------ copiar comandos de guia */
  function copyText(text, btn) {
    var done = function () {
      var prev = btn.textContent;
      btn.textContent = 'Copiado';
      btn.classList.add('ok');
      setTimeout(function () { btn.textContent = prev; btn.classList.remove('ok'); }, 1600);
    };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(done, function () { fallback(text, done); });
    } else {
      fallback(text, done);
    }
  }

  function fallback(text, done) {
    var ta = document.createElement('textarea');
    ta.value = text;
    ta.setAttribute('readonly', '');
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand('copy'); done(); } catch (e) { /* sin portapapeles */ }
    document.body.removeChild(ta);
  }

  document.addEventListener('click', function (e) {
    var b = e.target.closest('.copy');
    if (b) copyText(b.getAttribute('data-cmd') || '', b);
  });

  /* ------------------------------------------- recomprobar una incidencia -- */
  /* El navegador no puede medir nada del servidor: pide al colector que
     vuelva a recogerlo todo y despues mira si este hallazgo sigue en la
     lista. Resuelto = ha dejado de aparecer. */

  var csrf = document.body.getAttribute('data-csrf') || '';
  var WAIT_MS = 150000;   // margen amplio: la recogida completa puede tardar

  function verdictBox(card) {
    var v = card.querySelector('.verdict');
    v.hidden = false;
    return v;
  }

  function setState(v, cls, html) {
    v.className = 'verdict ' + cls;
    v.innerHTML = html;
  }

  function findingStillThere(id) {
    return fetch('api.php?v=health', { credentials: 'same-origin', cache: 'no-store' })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (h) {
        if (!h || !h.findings) return null;
        for (var i = 0; i < h.findings.length; i++) {
          if (h.findings[i].id === id) return h.findings[i];
        }
        return false;   // ya no esta: resuelta
      });
  }

  function waitForFreshState(since, deadline, onDone, onTimeout) {
    fetch('api.php?v=stamp', { credentials: 'same-origin', cache: 'no-store' })
      .then(function (r) {
        if (r.status === 401 || r.status === 403) { location.href = 'login.php'; return null; }
        return r.ok ? r.json() : null;
      })
      .then(function (d) {
        if (d && d.generated_at > since) { onDone(d); return; }
        if (Date.now() > deadline) { onTimeout(); return; }
        setTimeout(function () { waitForFreshState(since, deadline, onDone, onTimeout); }, 2000);
      })
      .catch(function () {
        if (Date.now() > deadline) { onTimeout(); return; }
        setTimeout(function () { waitForFreshState(since, deadline, onDone, onTimeout); }, 3000);
      });
  }

  function recheck(card, btn) {
    var id = btn.getAttribute('data-fid');
    var v  = verdictBox(card);

    busy = true;
    btn.disabled = true;
    document.querySelectorAll('.recheck').forEach(function (b) { b.disabled = true; });
    setState(v, 'working', '<span class="spinner" aria-hidden="true"></span> Recomprobando: el colector esta volviendo a medir el servidor…');

    var body = new URLSearchParams();
    body.set('action', 'recheck');
    body.set('csrf', csrf);

    fetch('api.php', {
      method: 'POST',
      credentials: 'same-origin',
      cache: 'no-store',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString()
    })
      .then(function (r) {
        if (r.status === 401) { location.href = 'login.php'; return null; }
        return r.json().then(function (d) { return { ok: r.ok, d: d }; });
      })
      .then(function (res) {
        if (!res) return;
        if (!res.ok || !res.d.queued) {
          finish(v, 'fail', '<strong>No se ha podido recomprobar.</strong> ' +
            escapeHtml(res.d.error || 'respuesta inesperada del servidor.'));
          return;
        }
        waitForFreshState(res.d.since || 0, Date.now() + WAIT_MS,
          function () {
            findingStillThere(id).then(function (still) {
              if (still === null) {
                finish(v, 'fail', 'Se ha recogido el estado pero no se ha podido leer la lista de incidencias.');
              } else if (still === false) {
                finish(v, 'solved', '<strong>Resuelta.</strong> Esta incidencia ya no aparece en la nueva recogida. ' +
                  'El panel se actualiza en un momento.');
                setTimeout(function () { location.reload(); }, 3500);
              } else {
                finish(v, 'persists', '<strong>Sigue presente.</strong> ' +
                  escapeHtml(still.detail || 'La comprobacion vuelve a fallar.') +
                  ' <button type="button" class="linkish" data-reload="1">Actualizar el panel</button>');
              }
            });
          },
          function () {
            finish(v, 'fail', '<strong>Sin respuesta del colector.</strong> La peticion quedo encolada pero no se ' +
              'ha recogido nada nuevo. Comprueba <code>systemctl status centinela-recheck.path</code>.');
          });
      })
      .catch(function () {
        finish(v, 'fail', 'Fallo de red al pedir la recomprobacion.');
      });
  }

  function finish(v, cls, html) {
    setState(v, cls, html);
    document.querySelectorAll('.recheck, .autofix').forEach(function (b) { b.disabled = false; });
    // El refresco automatico vuelve a la carga pasado un rato, para que el
    // veredicto se pueda leer con calma.
    setTimeout(function () { busy = false; }, 120000);
  }

  function escapeHtml(s) {
    var d = document.createElement('div');
    d.textContent = String(s);
    return d.innerHTML;
  }

  /* ---------------------------------------- bloquear o desbloquear una IP -- */
  /* Igual que la recomprobacion: el navegador no toca fail2ban, solo encola la
     peticion. El ejecutor privilegiado valida y responde, y aqui se sondea el
     resultado hasta que aparece. */

  var ACT_WAIT_MS = 60000;

  function actionResult(id, deadline, onDone, onTimeout) {
    fetch('api.php?v=action&id=' + encodeURIComponent(id), { credentials: 'same-origin', cache: 'no-store' })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (d) {
        if (d && d.done) { onDone(d.result); return; }
        if (Date.now() > deadline) { onTimeout(); return; }
        setTimeout(function () { actionResult(id, deadline, onDone, onTimeout); }, 1500);
      })
      .catch(function () {
        if (Date.now() > deadline) { onTimeout(); return; }
        setTimeout(function () { actionResult(id, deadline, onDone, onTimeout); }, 2500);
      });
  }

  function ipAction(btn) {
    var ip   = btn.getAttribute('data-ip');
    var act  = btn.getAttribute('data-act');
    var cell = btn.parentNode;

    if (act === 'ban' && !window.confirm('¿Bloquear ' + ip + ' en fail2ban?')) return;

    busy = true;
    cell.innerHTML = '<span class="spinner" aria-hidden="true"></span> <span class="muted">' +
      (act === 'ban' ? 'bloqueando…' : 'desbloqueando…') + '</span>';

    var body = new URLSearchParams();
    body.set('action', act);
    body.set('ip', ip);
    body.set('csrf', csrf);

    fetch('api.php', {
      method: 'POST',
      credentials: 'same-origin',
      cache: 'no-store',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString()
    })
      .then(function (r) {
        if (r.status === 401) { location.href = 'login.php'; return null; }
        return r.json().then(function (d) { return { ok: r.ok, d: d }; });
      })
      .then(function (res) {
        if (!res) return;
        if (!res.ok || !res.d.queued) {
          actionFailed(cell, res.d.error || 'no se pudo encolar la accion');
          return;
        }
        actionResult(res.d.id, Date.now() + ACT_WAIT_MS,
          function (r) {
            if (r.ok) {
              cell.innerHTML = '<span class="tag ' + (act === 'ban' ? 'ok' : 'warn') + '">' +
                (act === 'ban' ? '<span aria-hidden="true">✓</span> Bloqueada'
                               : '<span aria-hidden="true">!</span> Suelta') +
                '</span> <span class="muted">' + escapeHtml(r.detail || '') + '</span>';
            } else {
              actionFailed(cell, r.detail || 'fail2ban rechazo la orden');
            }
            setTimeout(function () { busy = false; }, 15000);
          },
          function () {
            actionFailed(cell, 'sin respuesta del ejecutor; mira centinela-action.path');
          });
      })
      .catch(function () { actionFailed(cell, 'fallo de red'); });
  }

  /* ------------------------------------- aplicar una correccion del catalogo -- */
  /* Mismo reparto que en todo lo demas: el navegador manda una clave, nunca un
     comando, y el ejecutor privilegiado decide. Lo que se aNade aqui es el
     segundo tiempo: cuando el arreglo se aplica, el ejecutor pide una recogida
     completa, y en vez de dar por buena la respuesta se espera a esa recogida
     para comprobar que la incidencia ha desaparecido de verdad. */

  function autofix(card, btn) {
    var id    = btn.getAttribute('data-fid');
    var clave = btn.getAttribute('data-fix');
    var desc  = btn.getAttribute('data-desc') || '';
    var label = (btn.textContent || 'Aplicar').trim();

    if (!window.confirm(label + '\n\n' + desc + '\n\n¿Aplicarlo ahora?')) return;

    var v = verdictBox(card);
    busy = true;
    document.querySelectorAll('.recheck, .autofix').forEach(function (b) { b.disabled = true; });
    setState(v, 'working', '<span class="spinner" aria-hidden="true"></span> Aplicando la correccion…');

    var body = new URLSearchParams();
    body.set('action', 'fix');
    body.set('fix', clave);
    body.set('csrf', csrf);

    fetch('api.php', {
      method: 'POST',
      credentials: 'same-origin',
      cache: 'no-store',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString()
    })
      .then(function (r) {
        if (r.status === 401) { location.href = 'login.php'; return null; }
        return r.json().then(function (d) { return { ok: r.ok, d: d }; });
      })
      .then(function (res) {
        if (!res) return;
        if (!res.ok || !res.d.queued) {
          finish(v, 'fail', '<strong>No se ha podido encolar.</strong> ' +
            escapeHtml(res.d.error || 'respuesta inesperada del servidor.'));
          return;
        }
        var desde = res.d.since || 0;

        actionResult(res.d.id, Date.now() + ACT_WAIT_MS,
          function (r) {
            if (!r.ok) {
              finish(v, 'fail', '<strong>No se ha podido aplicar.</strong> ' +
                escapeHtml(r.detail || 'el ejecutor rechazo la correccion.'));
              return;
            }
            setState(v, 'working', '<span class="spinner" aria-hidden="true"></span> ' +
              escapeHtml(r.detail || 'Aplicada') +
              '. Volviendo a medir el servidor para confirmarlo…');

            waitForFreshState(desde, Date.now() + WAIT_MS,
              function () {
                findingStillThere(id).then(function (still) {
                  if (still === null) {
                    finish(v, 'fail', 'Se aplico la correccion pero no se ha podido leer la lista de incidencias.');
                  } else if (still === false) {
                    finish(v, 'solved', '<strong>Resuelta.</strong> ' + escapeHtml(r.detail || '') +
                      ', y la incidencia ya no aparece en la nueva recogida. El panel se actualiza en un momento.');
                    setTimeout(function () { location.reload(); }, 3500);
                  } else {
                    // Caso incomodo pero el mas util de contar bien: el comando
                    // no protesto y aun asi el problema sigue ahi.
                    finish(v, 'persists', '<strong>Aplicada, pero sigue presente.</strong> ' +
                      escapeHtml(still.detail || '') +
                      ' <button type="button" class="linkish" data-reload="1">Actualizar el panel</button>');
                  }
                });
              },
              function () {
                finish(v, 'persists', '<strong>Aplicada,</strong> pero la recogida posterior no ha llegado a tiempo. ' +
                  'Pulsa «Volver a comprobar» dentro de un momento.');
              });
          },
          function () {
            finish(v, 'fail', '<strong>Sin respuesta del ejecutor.</strong> La peticion quedo encolada; ' +
              'comprueba <code>systemctl status centinela-action.path</code>.');
          });
      })
      .catch(function () { finish(v, 'fail', 'Fallo de red al pedir la correccion.'); });
  }

  function actionFailed(cell, msg) {
    cell.innerHTML = '<span class="tag crit"><span aria-hidden="true">×</span> Error</span> ' +
      '<span class="muted">' + escapeHtml(msg) + '</span>';
    setTimeout(function () { busy = false; }, 15000);
  }

  document.addEventListener('click', function (e) {
    var b = e.target.closest('.recheck');
    if (b && !b.disabled) { recheck(b.closest('.finding'), b); return; }
    var fx = e.target.closest('.autofix');
    if (fx && !fx.disabled) { autofix(fx.closest('.finding'), fx); return; }
    var a = e.target.closest('.ipact');
    if (a && !a.disabled) { a.disabled = true; ipAction(a); return; }
    if (e.target.closest('[data-reload]')) location.reload();
  });
})();
