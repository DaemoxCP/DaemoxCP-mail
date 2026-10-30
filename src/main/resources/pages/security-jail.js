
        // ===== Fail2ban Health Check / Setup Wizard =====
        let fhcCsrfToken = null;

        function ensureFhcCsrfToken() {
            // riusa csrf token globale se esiste, altrimenti chiama un endpoint dedicato
            // (qui assumiamo esista document.getElementById('csrf_token'))
            try {
                const el = document.getElementById('csrf_token');
                if (el && el.value) return el.value;
            } catch (e) {}
            return fhcCsrfToken || '';
        }

        // ===== Postfix Aliases =====
        function paliasEscape(s) {
            const d = document.createElement('div');
            d.textContent = s == null ? '' : String(s);
            return d.innerHTML;
        }

        // ===== Stato live jail Fail2ban =====
        // Stampa per ogni jail attiva l'output di:
        //   fail2ban-client get <jail> maxretry/findtime/bantime/logpath/filter/ignoreip
        //   fail2ban-client status <jail>
        // così l'utente vede SUBITO se la config è quella che ha impostato.
        function loadJailLiveState() {
            const body = document.getElementById('jailLiveBody');
            body.innerHTML = '<p class="text-muted small mb-0 p-2"><i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('sj.running')) + '</p>';
            fetch('/api/fail2ban?action=live_state_all').then(r => r.json()).then(data => {
                if (!data.success) {
                    body.innerHTML = '<div class="alert alert-danger m-2 mb-0">' + escHtml(t('common.error', { message: data.error || t('common.unknownError') })) + '</div>';
                    return;
                }
                if (!data.installed) {
                    body.innerHTML = '<div class="alert alert-warning m-2 mb-0">' + escHtml(t('sj.notInstalled')) + '</div>';
                    return;
                }
                if (!data.running) {
                    // Il pannello sa avviarlo da solo (start_service): dettare un comando da
                    // terminale per una cosa che il pannello fa gia' e' mandare fuori da qui
                    // un lavoro che sta qui dentro.
                    body.innerHTML = '<div class="alert alert-warning m-2 mb-0">'
                        + '<strong>' + escHtml(t('sj.notRunning')) + '</strong> ' + escHtml(t('sj.notRunningHint')) + ''
                        + '<button class="btn btn-sm btn-warning ms-2" onclick="startFail2banFromPanel()">'
                        + '<i class="fas fa-play me-1" aria-hidden="true"></i>' + escHtml(t('sj.startNow')) + '</button></div>';
                    return;
                }
                const jails = data.jails || [];
                if (jails.length === 0) {
                    body.innerHTML = '<div class="alert alert-info m-2 mb-0">' + escHtml(t('sec.noJails')) + '</div>';
                    return;
                }
                let html = '<div class="p-2">';
                jails.forEach(j => {
                    html += renderJailLiveCard(j);
                });
                html += '</div>';
                body.innerHTML = html;
            }).catch(e => {
                body.innerHTML = '<div class="alert alert-danger m-2 mb-0">' + escHtml(t('common.networkError', { message: e.message })) + '</div>';
            });
        }

        function renderJailLiveCard(j) {
            const name = j.name || '?';
            // Tag colorato per "currently banned": 0 = grigio, >0 = giallo
            const cbBadge = j.currently_banned > 0
                ? '<span class="badge bg-warning text-dark ms-1">' + escHtml(tn('sj.bannedNow', j.currently_banned)) + '</span>'
                : '<span class="badge bg-light text-dark ms-1">' + escHtml(tn('sj.bannedNow', 0)) + '</span>';
            const tbBadge = j.total_banned > 0
                ? '<span class="badge bg-secondary ms-1">' + escHtml(t('sj.total', { n: j.total_banned })) + '</span>'
                : '';

            let html = '<div class="card mb-3"><div class="card-header py-1 px-2 d-flex justify-content-between align-items-center bg-light">';
            html += '<div><strong><code>' + paliasEscape(name) + '</code></strong>' + cbBadge + tbBadge + '</div>';
            html += '<button class="btn btn-sm btn-link p-0" onclick="this.parentElement.parentElement.parentElement.querySelector(\'.jail-raw-' + paliasEscape(name) + '\').classList.toggle(\'d-none\')"><i class="fas fa-terminal me-1" aria-hidden="true"></i>' + escHtml(t('sj.raw')) + '</button>';
            html += '</div>';
            html += '<div class="card-body p-2 small">';
            html += '<table class="table table-sm table-borderless mb-2"><tbody>';
            html += renderJailGetRow('maxretry',  j.maxretry,  t('sj.maxretry'));
            html += renderJailGetRow('findtime',  j.findtime,  t('sj.findtime'), true);
            html += renderJailGetRow('bantime',   j.bantime,   t('sj.bantime'), true);
            html += renderJailGetRow('logpath',   j.logpath,   t('sj.logpath'));
            html += renderJailGetRow('filter',    j.filter,    t('sj.filter'));
            html += renderJailGetRow('ignoreip',  j.ignoreip,  t('sj.ignoreip'));
            html += '</tbody></table>';

            // Status counters parsati
            html += '<div class="row g-2 mb-2">';
            html += '<div class="col-6 col-md-3"><div class="border rounded p-1 text-center"><div class="text-muted small">' + escHtml(t('sj.curFailed')) + '</div><strong class="fs-5">' + escHtml(j.currently_failed) + '</strong></div></div>';
            html += '<div class="col-6 col-md-3"><div class="border rounded p-1 text-center"><div class="text-muted small">' + escHtml(t('sj.totFailed')) + '</div><strong class="fs-5">' + escHtml(j.total_failed) + '</strong></div></div>';
            html += '<div class="col-6 col-md-3"><div class="border rounded p-1 text-center"><div class="text-muted small">' + escHtml(t('sj.curBanned')) + '</div><strong class="fs-5">' + escHtml(j.currently_banned) + '</strong></div></div>';
            html += '<div class="col-6 col-md-3"><div class="border rounded p-1 text-center"><div class="text-muted small">' + escHtml(t('sj.totBanned')) + '</div><strong class="fs-5">' + escHtml(j.total_banned) + '</strong></div></div>';
            html += '</div>';

            if (j.banned_ips_raw) {
                html += '<div class="mb-2"><strong class="small">' + escHtml(t('sj.bannedList')) + '</strong> <code class="small" style="word-break:break-all">' + paliasEscape(j.banned_ips_raw) + '</code></div>';
            }

            // Output RAW del comando "fail2ban-client status <jail>" — chiuso di default
            html += '<div class="jail-raw-' + paliasEscape(name) + ' d-none">';
            html += '<div class="small text-muted mb-1"><i class="fas fa-terminal me-1" aria-hidden="true"></i>' + escHtml(t('sj.outputOf')) + ' <code>fail2ban-client status ' + paliasEscape(name) + '</code></div>';
            html += '<pre class="bg-dark text-light p-2 small rounded mb-0" style="font-size:0.75rem;white-space:pre-wrap">' + paliasEscape(j.status_raw || '') + '</pre>';
            html += '</div>';

            html += '</div></div>';
            return html;
        }

        function renderJailGetRow(key, value, descr, isSeconds) {
            let display = paliasEscape(value || '');
            // Se è in secondi, mostra anche la conversione umana
            if (isSeconds && /^-?\d+$/.test((value || '').trim())) {
                const n = parseInt(value, 10);
                if (n === -1) {
                    display += ' <span class="text-muted">(' + escHtml(t('jc.permanent')) + ')</span>';
                } else if (n > 0) {
                    const fmt = (v, unit) => new Intl.NumberFormat(window.I18N_LANG, { style: 'unit', unit: unit, unitDisplay: 'long', maximumFractionDigits: 1 }).format(v);
                    let human;
                    if (n >= 86400) human = fmt(n / 86400, 'day');
                    else if (n >= 3600) human = fmt(n / 3600, 'hour');
                    else if (n >= 60) human = fmt(n / 60, 'minute');
                    else human = fmt(n, 'second');
                    display += ' <span class="text-muted">(' + escHtml(human) + ')</span>';
                }
            }
            return '<tr>' +
                '<td style="width:130px;vertical-align:top"><code class="text-primary">' + escHtml(key) + '</code></td>' +
                '<td><strong>' + display + '</strong>' + (descr ? '<br><small class="text-muted">' + escHtml(descr) + '</small>' : '') + '</td>' +
                '</tr>';
        }

        function paliasLoad() {
            const body = document.getElementById('paliasBody');
            const badge = document.getElementById('paliasOverallBadge');
            const fixBtn = document.getElementById('paliasFixBtn');
            body.innerHTML = '<p class="text-muted mb-0"><i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('common.loading')) + '</p>';
            badge.innerHTML = '';
            fixBtn.classList.add('d-none');

            fetch('/api/postfix-aliases-health').then(r => r.json()).then(data => {
                if (!data.success) {
                    body.innerHTML = '<div class="alert alert-danger mb-0">' + escHtml(t('common.error', { message: data.error || t('common.unknownError') })) + '</div>';
                    badge.innerHTML = '<span class="badge bg-danger">' + escHtml(t('common.errorShort')) + '</span>';
                    return;
                }
                paliasRender(data);
            }).catch(e => {
                body.innerHTML = '<div class="alert alert-danger mb-0">' + escHtml(t('common.networkError', { message: e.message })) + '</div>';
            });
        }

        function paliasRender(data) {
            const body = document.getElementById('paliasBody');
            const badge = document.getElementById('paliasOverallBadge');
            const fixBtn = document.getElementById('paliasFixBtn');
            const overall = data.overall || 'UNKNOWN';

            // Badge nell'header
            if (overall === 'OK') {
                badge.innerHTML = '<span class="badge bg-success"><i class="fas fa-check-circle me-1" aria-hidden="true"></i>OK</span>';
                fixBtn.classList.add('d-none');
            } else if (overall === 'MISSING_SOURCE') {
                badge.innerHTML = '<span class="badge bg-danger"><i class="fas fa-times-circle me-1" aria-hidden="true"></i>' + escHtml(t('sj.aliasMissing')) + '</span>';
                fixBtn.classList.remove('d-none');
            } else if (overall === 'MISSING_DB') {
                badge.innerHTML = '<span class="badge bg-warning text-dark"><i class="fas fa-exclamation-triangle me-1" aria-hidden="true"></i>' + escHtml(t('sj.dbMissing')) + '</span>';
                fixBtn.classList.remove('d-none');
            } else if (overall === 'STALE_DB') {
                badge.innerHTML = '<span class="badge bg-warning text-dark"><i class="fas fa-clock me-1" aria-hidden="true"></i>' + escHtml(t('sj.dbStale')) + '</span>';
                fixBtn.classList.remove('d-none');
            } else {
                badge.innerHTML = '<span class="badge bg-secondary">?</span>';
            }

            // Tabella stato
            let html = '';
            if (overall !== 'OK') {
                html += '<div class="alert alert-warning small"><i class="fas fa-exclamation-triangle me-1" aria-hidden="true"></i>' + paliasEscape(data.summary || '') + ' ' + escHtml(t('sj.clickFix')) + '</div>';
            } else {
                html += '<div class="alert alert-success small mb-2"><i class="fas fa-check-circle me-1" aria-hidden="true"></i>' + paliasEscape(data.summary || 'OK') + '</div>';
            }
            html += '<table class="table table-sm align-middle mb-0">';
            const exists = '<span class="badge bg-success">' + escHtml(t('sj.exists')) + '</span>', missing = '<span class="badge bg-danger">' + escHtml(t('ad.missing')) + '</span>';
            html += '<tr><td class="fw-bold" style="width:30%">' + escHtml(t('sj.source')) + '</td><td><code>' + paliasEscape(data.alias_file || '?') + '</code> ' + (data.source_exists ? exists : missing) + '</td></tr>';
            html += '<tr><td class="fw-bold">' + escHtml(t('sj.compiled')) + '</td><td><code>' + paliasEscape(data.alias_db_file || '?') + '</code> ' + (data.db_exists ? exists : missing) + (data.db_stale_vs_source ? ' <span class="badge bg-warning text-dark">' + escHtml(t('sj.stale')) + '</span>' : '') + '</td></tr>';
            if (data.alias_database_raw) {
                html += '<tr><td class="fw-bold">alias_database (postconf)</td><td><code>' + paliasEscape(data.alias_database_raw) + '</code></td></tr>';
            }
            if (data.alias_maps_raw) {
                html += '<tr><td class="fw-bold">alias_maps (postconf)</td><td><code>' + paliasEscape(data.alias_maps_raw) + '</code></td></tr>';
            }
            if (data.root_forward) {
                html += '<tr><td class="fw-bold">' + escHtml(t('sj.rootTo')) + '</td><td><code>' + paliasEscape(data.root_forward) + '</code></td></tr>';
            }
            html += '</table>';
            body.innerHTML = html;

            // Pre-compila il campo "root forward" se disponibile
            const fwInput = document.getElementById('paliasRootForward');
            if (fwInput && data.root_forward) fwInput.value = data.root_forward;
        }

        function paliasFix() {
            if (!confirm(t('sj.confirmFix'))) return;
            const fixBtn = document.getElementById('paliasFixBtn');
            const origBtn = fixBtn.innerHTML;
            fixBtn.disabled = true;
            fixBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-1" aria-hidden="true"></span>' + escHtml(t('sj.fixing')) + '';
            const logEl = document.getElementById('paliasLog');
            logEl.innerHTML = '';
            fetch('/api/postfix-aliases-health', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'fix', csrf_token: csrfToken })
            })
            .then(r => r.json())
            .then(data => {
                fixBtn.disabled = false;
                fixBtn.innerHTML = origBtn;
                let html = '<div class="alert alert-' + (data.success ? 'success' : 'danger') + ' py-2 mb-2"><i class="fas fa-' + (data.success ? 'check' : 'times') + '-circle me-1" aria-hidden="true"></i>' + paliasEscape(data.message || '') + '</div>';
                if (data.log) {
                    html += '<pre class="bg-light p-2 rounded small mb-0" style="white-space:pre-wrap">' + paliasEscape(data.log) + '</pre>';
                }
                logEl.innerHTML = html;
                paliasRender(data);
            })
            .catch(e => {
                fixBtn.disabled = false;
                fixBtn.innerHTML = origBtn;
                logEl.innerHTML = '<div class="alert alert-danger py-2 mb-0">' + escHtml(t('common.networkError', { message: e.message })) + '</div>';
            });
        }

        function paliasSetRootForward() {
            const v = document.getElementById('paliasRootForward').value.trim();
            if (!v) { alert(t('sj.needAddress')); return; }
            if (!confirm(t('sj.confirmRootFwd', { to: v }))) return;
            const logEl = document.getElementById('paliasLog');
            logEl.innerHTML = '<div class="text-muted small"><i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('jc.saving')) + '</div>';
            fetch('/api/postfix-aliases-health', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'set_root_forward', forward_to: v, csrf_token: csrfToken })
            })
            .then(r => r.json())
            .then(data => {
                let html = '<div class="alert alert-' + (data.success ? 'success' : 'danger') + ' py-2 mb-2"><i class="fas fa-' + (data.success ? 'check' : 'times') + '-circle me-1" aria-hidden="true"></i>' + paliasEscape(data.message || '') + '</div>';
                if (data.log) {
                    html += '<pre class="bg-light p-2 rounded small mb-0" style="white-space:pre-wrap">' + paliasEscape(data.log) + '</pre>';
                }
                logEl.innerHTML = html;
                paliasRender(data);
            })
            .catch(e => {
                logEl.innerHTML = '<div class="alert alert-danger py-2 mb-0">' + escHtml(t('common.networkError', { message: e.message })) + '</div>';
            });
        }

        function loadFail2banHealth() {
            const c = document.getElementById('fhcContainer');
            const overall = document.getElementById('fhcOverallStatus');
            const btnFixAll = document.getElementById('btnFixAll');
            c.innerHTML = '<p class="text-muted mb-0"><i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('sec.diagnosing')) + '</p>';
            fetch('/api/fail2ban_health', { method: 'GET' })
                .then(r => r.json())
                .then(data => {
                    if (!data.success) {
                        c.innerHTML = '<div class="alert alert-danger mb-0">' + escHtml(t('common.error', { message: data.error || t('common.unknownError') })) + '</div>';
                        return;
                    }
                    if (data.all_ok) {
                        overall.innerHTML = '<span class="badge bg-success">' + escHtml(t('sj.allOk')) + '</span>';
                        if (btnFixAll) btnFixAll.classList.add('d-none');
                    } else {
                        overall.innerHTML = '<span class="badge bg-warning text-dark">' + escHtml(t('sj.actionNeeded')) + '</span>';
                        if (btnFixAll) btnFixAll.classList.remove('d-none');
                    }
                    let html = '<div class="list-group list-group-flush">';
                    (data.checks || []).forEach((chk, idx) => {
                        const icon = chk.ok
                            ? '<i class="fas fa-check-circle text-success" aria-hidden="true"></i><span class="visually-hidden">' + escHtml(t('dns.succeeded')) + '</span>'
                            : '<i class="fas fa-times-circle text-danger" aria-hidden="true"></i><span class="visually-hidden">' + escHtml(t('dns.failed')) + '</span>';
                        html += '<div class="list-group-item">';
                        html += '<div class="d-flex justify-content-between align-items-start gap-3 flex-wrap">';
                        html += '<div class="flex-grow-1">';
                        html += '<div><strong>' + icon + ' ' + escapeHtml(chk.label) + '</strong></div>';
                        html += '<div class="small text-muted">' + escapeHtml(chk.status || '') + '</div>';
                        if (!chk.ok && chk.impact) {
                            html += '<div class="small text-danger mt-1"><i class="fas fa-exclamation-triangle me-1" aria-hidden="true"></i>' + escHtml(t('sj.ifNotFixed', { impact: chk.impact })) + '</div>';
                        }
                        if (!chk.ok && chk.fix_description) {
                            html += '<div class="small text-info mt-1"><i class="fas fa-magic me-1" aria-hidden="true"></i>' + escapeHtml(chk.fix_description) + '</div>';
                        }
                        html += '</div>';
                        if (!chk.ok && chk.fix_action) {
                            html += '<button class="btn btn-warning btn-sm" data-action="' + escHtml(chk.fix_action) + '" onclick="runFhcFix(this.dataset.action, this)">';
                            html += '<i class="fas fa-wrench me-1" aria-hidden="true"></i>' + escHtml(t('sec.fix'));
                            html += '</button>';
                        }
                        html += '</div>';
                        html += '</div>';
                    });
                    html += '</div>';
                    if (data.all_ok) {
                        html += '<div class="alert alert-success mb-0 mt-3 py-2"><i class="fas fa-shield-alt me-2" aria-hidden="true"></i>' + escHtml(t('sj.complete')) + '</div>';
                    }
                    c.innerHTML = html;
                })
                .catch(e => {
                    c.innerHTML = '<div class="alert alert-danger mb-0">' + escHtml(t('common.networkError', { message: e.message })) + '</div>';
                });
        }

        function runFhcFixAll() {
            const confirmMsg = t('sj.confirmFixAll');
            if (!confirm(confirmMsg)) return;

            const btn = document.getElementById('btnFixAll');
            const original = btn.innerHTML;
            btn.disabled = true;
            btn.innerHTML = '<span class="spinner-border spinner-border-sm me-1" aria-hidden="true"></span>' + escHtml(t('sj.inProgress')) + '';

            fetch('/api/fail2ban_health', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'fix_all', csrf_token: ensureFhcCsrfToken() })
            }).then(r => r.json()).then(data => {
                btn.disabled = false;
                btn.innerHTML = original;

                // Render report passo-passo
                const report = document.getElementById('fhcFixAllReport');
                const stepsEl = document.getElementById('fhcFixAllSteps');
                let html = '';
                (data.steps || []).forEach(s => {
                    let icon, badge;
                    if (s.status === 'skipped') {
                        icon = '<i class="fas fa-forward text-secondary" aria-hidden="true"></i>';
                        badge = '<span class="badge bg-secondary">' + escHtml(t('sj.skipped')) + '</span>';
                    } else if (s.success) {
                        icon = '<i class="fas fa-check-circle text-success" aria-hidden="true"></i>';
                        badge = '<span class="badge bg-success">OK</span>';
                    } else {
                        icon = '<i class="fas fa-times-circle text-danger" aria-hidden="true"></i>';
                        badge = '<span class="badge bg-danger">' + escHtml(t('sj.fail')) + '</span>';
                    }
                    html += '<div class="d-flex align-items-start gap-2 mb-2">' + icon +
                        '<div class="flex-grow-1"><div>' + badge + ' <strong>' + escapeHtml(s.label) + '</strong></div>';
                    if (s.message) html += '<div class="small text-muted">' + escapeHtml(s.message) + '</div>';
                    if (s.output && s.output.length > 0) html += '<details class="small mt-1"><summary>' + escHtml(t('sj.output')) + '</summary><pre class="mb-0 mt-1" style="font-size:0.75rem;max-height:200px;overflow:auto">' + escapeHtml(s.output) + '</pre></details>';
                    html += '</div></div>';
                });
                stepsEl.innerHTML = html;
                report.classList.remove('d-none');

                // Riricarica lo stato
                loadFail2banHealth();
                loadStatus();
            }).catch(e => {
                btn.disabled = false;
                btn.innerHTML = original;
                alert(t('common.networkError', { message: e.message }));
            });
        }

        function runFhcFix(action, btn) {
            // Warning rafforzato per le azioni pf (rischio lockout SSH)
            const pfActions = { 'start_pf': true, 'enable_pf_at_boot': true, 'add_pf_anchor': true };
            let confirmMsg = t('sj.confirmOne');
            if (pfActions[action]) confirmMsg = t('sj.confirmPf');
            if (action === 'repair_ban_action') confirmMsg = t('sj.confirmBanAction');
            if (!confirm(confirmMsg)) return;
            const original = btn.innerHTML;
            btn.disabled = true;
            btn.innerHTML = '<span class="spinner-border spinner-border-sm me-1" aria-hidden="true"></span>' + escHtml(t('sj.inProgress')) + '';
            fetch('/api/fail2ban_health', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    action: action,
                    csrf_token: ensureFhcCsrfToken()
                })
            }).then(r => r.json()).then(data => {
                btn.disabled = false;
                btn.innerHTML = original;
                // Una riparazione che scrive file e poi si verifica ha un racconto da fare:
                // ricaricare la diagnosi e basta butterebbe via il passo che conta, cioe' cosa
                // ha risposto fail2ban DOPO il reload.
                if (data.steps) {
                    const rep = document.getElementById('fhcFixAllReport');
                    const el = document.getElementById('fhcFixAllSteps');
                    let hh = '';
                    (data.steps || []).forEach(pz => {
                        hh += '<div class="d-flex align-items-start gap-2 mb-2">' +
                              (pz.ok ? '<i class="fas fa-check-circle text-success" aria-hidden="true"></i>'
                                     : '<i class="fas fa-times-circle text-danger" aria-hidden="true"></i>') +
                              '<div class="flex-grow-1"><strong>' + escapeHtml(pz.step) + '</strong>' +
                              '<div class="small text-muted">' + escapeHtml(pz.text) + '</div></div></div>';
                    });
                    (data.verification || []).forEach(v => {
                        hh += '<div class="small ' + (v.ok ? 'text-success' : 'text-danger') + '">' +
                              '<i class="fas fa-' + (v.ok ? 'check' : 'times') + ' me-1" aria-hidden="true"></i>' +
                              escapeHtml(v.jail) + ': ' +
                              escapeHtml(v.command || v.note || '') + '</div>';
                        if (v.log) hh += '<pre class="small mb-2 mt-1" style="white-space:pre-wrap;max-height:220px;overflow:auto">' + escapeHtml(v.log) + '</pre>';
                    });
                    if (data.message) hh += '<div class="mt-2">' + escapeHtml(data.message) + '</div>';
                    if (el) { el.innerHTML = hh; }
                    if (rep) rep.classList.remove('d-none');
                }
                if (data.success) {
                    // ricarica la diagnosi
                    loadFail2banHealth();
                    loadStatus();
                } else if (data.steps) {
                    loadFail2banHealth();
                } else {
                    alert(t('common.error', { message: data.message || data.error || t('common.unknownError') }) +
                        (data.output ? '\n\n' + t('sj.output') + ':\n' + data.output : ''));
                    loadFail2banHealth();
                }
            }).catch(e => {
                btn.disabled = false;
                btn.innerHTML = original;
                alert(t('common.networkError', { message: e.message }));
            });
        }

        // Helper escapeHtml (se non già definita altrove nella pagina)
        if (typeof escapeHtml !== 'function') {
            window.escapeHtml = function(text) {
                const div = document.createElement('div');
                div.textContent = text == null ? '' : String(text);
                return div.innerHTML;
            };
        }

        // Reload morbido (fail2ban-client reload): rilegge i file senza killare il daemon
        function reloadFail2banFromPanel() {
            if (!confirm(t('sj.confirmReload'))) return;
            fetch('/api/fail2ban_health', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'reload_fail2ban', csrf_token: ensureFhcCsrfToken() })
            }).then(r => r.json()).then(data => {
                alert((data.success ? '✅ ' : '❌ ') + (data.message || t('common.done')) +
                    (data.output ? '\n\n' + t('sj.output') + ':\n' + data.output : ''));
                loadFail2banHealth();
                if (typeof loadJailLiveState === 'function') loadJailLiveState();
            }).catch(e => alert(t('common.networkError', { message: e.message })));
        }

        // Restart pulito (service fail2ban restart): killa il daemon e lo riavvia
        function restartFail2banFromPanel() {
            if (!confirm(t('sj.confirmRestart'))) return;
            fetch('/api/fail2ban_health', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'restart_service', csrf_token: ensureFhcCsrfToken() })
            }).then(r => r.json()).then(data => {
                alert((data.success ? '✅ ' : '❌ ') + (data.message || t('common.done')) +
                    (data.output ? '\n\n' + t('sj.output') + ':\n' + data.output : ''));
                loadFail2banHealth();
                if (typeof loadJailLiveState === 'function') loadJailLiveState();
            }).catch(e => alert(t('common.networkError', { message: e.message })));
        }

        // Avvio di fail2ban dal pannello. Esiste gia' l'azione start_service: quello che
        // mancava era il modo di premerla dalla pagina dove il problema si vede.
        function startFail2banFromPanel() {
            // La barra rovesciata va DOPPIA qui dentro. Dentro un text block Java la sequenza
            // barra-n e' un a capo VERO: arriva al browser come un ritorno a capo dentro una
            // stringa JavaScript, la stringa non si chiude, il parser si ferma e l'INTERO blocco
            // di script non viene eseguito. La pagina resta con tutti gli indicatori che girano,
            // e sembra che le chiamate non finiscano mentre non sono nemmeno partite.
            //
            // Questo commento stesso, scritto la prima volta con la sequenza singola per
            // spiegarla, ha rotto la pagina allo stesso modo: qui non si nomina, si descrive.
            if (!confirm(t('sj.confirmStart'))) return;
            fetch('/api/fail2ban_health', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'start_service', csrf_token: ensureFhcCsrfToken() })
            }).then(r => r.json()).then(data => {
                alert((data.success ? '✅ ' : '❌ ') + (data.message || t('common.done')) +
                    (data.output ? '\n\n' + t('sj.output') + ':\n' + data.output : ''));
                if (typeof loadFail2banHealth === 'function') loadFail2banHealth();
                if (typeof loadJailLiveState === 'function') loadJailLiveState();
            }).catch(e => alert(t('common.networkError', { message: e.message })));
        }

        // ===== End Health Check =====

        // Distingue "nessuno ha attaccato" da "la jail non vede niente": a schermo sono lo
        // stesso zero, ma vogliono dire il contrario. Legge e basta.
        async function checkJailFilter(entryName) {
            const box = document.getElementById('filter-' + entryName);
            if (!box) return;
            box.innerHTML = '<span class="text-muted"><i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('sj.regexRunning')) + '</span>';
            try {
                const res = await fetch('/api/fail2ban', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ action: 'verify_filter', jail: entryName,
                        csrf_token: document.getElementById('csrf_token').value })
                });
                const r = await res.json();
                // Non verificato NON e' verde e non e' rosso: e' "non lo so".
                const cls = !r.verified ? 'secondary' : (r.hooks > 0 ? 'success' : 'danger');
                box.innerHTML = '<div class="alert alert-' + cls + ' py-1 px-2 mb-0 small">'
                    + escapeHtml(r.messageText || '')
                    + (r.log ? '<div class="text-muted mt-1">Log: <code>' + escapeHtml(r.log) + '</code>'
                        + (r.log_lines ? ' &middot; ' + escHtml(tn('sj.lines', r.log_lines)) : '') + '</div>' : '')
                    + '</div>';
            } catch (e) {
                box.innerHTML = '<div class="alert alert-secondary py-1 px-2 mb-0 small">'
                    + escHtml(t('dns.sumAskFailed', { message: String(e) })) + '</div>';
            }
        }
