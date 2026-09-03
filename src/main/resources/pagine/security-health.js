
        // ===== Unbound (Resolver DNS locale) Health Check =====
        function loadUnboundHealth() {
            const c = document.getElementById('ubContainer');
            const overall = document.getElementById('ubOverallStatus');
            const btnFixAll = document.getElementById('btnUbFixAll');
            c.innerHTML = '<p class="text-muted mb-0"><i class="fas fa-spinner fa-spin me-1"></i>Diagnosi in corso...</p>';
            fetch('/api/unbound_health', { method: 'GET' }).then(r => r.json()).then(data => {
                if (!data.success) {
                    c.innerHTML = '<div class="alert alert-danger mb-0">Errore: ' + (data.error || 'sconosciuto') + '</div>';
                    return;
                }
                if (data.all_ok) {
                    overall.innerHTML = '<span class="badge bg-success">Tutto OK</span>';
                    if (btnFixAll) btnFixAll.classList.add('d-none');
                } else {
                    overall.innerHTML = '<span class="badge bg-warning text-dark">Azione richiesta</span>';
                    if (btnFixAll) btnFixAll.classList.remove('d-none');
                }
                let html = '<div class="list-group list-group-flush">';
                (data.checks || []).forEach(chk => {
                    const icon = chk.ok ? '<i class="fas fa-check-circle text-success"></i>' : '<i class="fas fa-times-circle text-danger"></i>';
                    html += '<div class="list-group-item">';
                    html += '<div class="d-flex justify-content-between align-items-start gap-3 flex-wrap">';
                    html += '<div class="flex-grow-1">';
                    html += '<div><strong>' + icon + ' ' + escapeHtmlUb(chk.label) + '</strong></div>';
                    html += '<div class="small text-muted">' + escapeHtmlUb(chk.status || '') + '</div>';
                    if (!chk.ok && chk.impact) html += '<div class="small text-danger mt-1"><i class="fas fa-exclamation-triangle me-1"></i>Se non lo risolvi: ' + escapeHtmlUb(chk.impact) + '</div>';
                    if (!chk.ok && chk.fix_description) html += '<div class="small text-info mt-1"><i class="fas fa-magic me-1"></i>' + escapeHtmlUb(chk.fix_description) + '</div>';
                    html += '</div>';
                    if (!chk.ok && chk.fix_action) {
                        html += '<button class="btn btn-warning btn-sm" onclick="runUbFix(\'' + chk.fix_action + '\', this)">';
                        html += '<i class="fas fa-wrench me-1"></i>Risolvi';
                        html += '</button>';
                    }
                    html += '</div></div>';
                });
                html += '</div>';
                if (data.all_ok) html += '<div class="alert alert-success mb-0 mt-3 py-2"><i class="fas fa-shield-alt me-2"></i>Resolver locale operativo. Le query DNSBL (Spamhaus, ecc.) ora vengono risolte correttamente.</div>';
                c.innerHTML = html;
            }).catch(e => {
                c.innerHTML = '<div class="alert alert-danger mb-0">Errore rete: ' + e.message + '</div>';
            });
        }

        function runUbFix(action, btn) {
            const warning = (action === 'switch_resolv_conf')
                ? '\n\n⚠️ Questo passo modifica /etc/resolv.conf. Il pannello fa pre-flight test e rollback automatico se qualcosa va storto, ma è raccomandato avere accesso console al server come backup.'
                : '';
            if (!confirm('Applicare la correzione?' + warning)) return;
            const original = btn.innerHTML;
            btn.disabled = true;
            btn.innerHTML = '<span class="spinner-border spinner-border-sm me-1"></span>In corso...';
            fetch('/api/unbound_health', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: action, csrf_token: document.getElementById('csrf_token').value })
            }).then(r => r.json()).then(data => {
                btn.disabled = false;
                btn.innerHTML = original;
                if (data.success) loadUnboundHealth();
                else alert('Errore: ' + (data.message || data.error || 'sconosciuto') + (data.output ? '\n\n' + data.output : ''));
                loadUnboundHealth();
            }).catch(e => {
                btn.disabled = false;
                btn.innerHTML = original;
                alert('Errore rete: ' + e.message);
            });
        }

        function runUbFixAll() {
            const msg = '🪄 Risolvi tutto unbound — esegue in ordine:\n' +
                '1. Installa unbound (se manca)\n' +
                '2. Scrive config sicura (solo loopback)\n' +
                '3. Abilita al boot\n' +
                '4. Avvia il servizio\n' +
                '5. Switcha /etc/resolv.conf su 127.0.0.1\n\n' +
                'Step 5 ha PRE-FLIGHT test + AUTO-ROLLBACK in caso di problemi.\n' +
                'Però è sempre raccomandato avere accesso console al server.\n\n' +
                'Procedo?';
            if (!confirm(msg)) return;

            const btn = document.getElementById('btnUbFixAll');
            const original = btn.innerHTML;
            btn.disabled = true;
            btn.innerHTML = '<span class="spinner-border spinner-border-sm me-1"></span>In corso (può richiedere 1-2 min)...';

            fetch('/api/unbound_health', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'fix_all', csrf_token: document.getElementById('csrf_token').value })
            }).then(r => r.json()).then(data => {
                btn.disabled = false;
                btn.innerHTML = original;
                const report = document.getElementById('ubFixAllReport');
                const stepsEl = document.getElementById('ubFixAllSteps');
                let html = '';
                (data.steps || []).forEach(s => {
                    let icon, badge;
                    if (s.status === 'skipped') { icon = '<i class="fas fa-forward text-secondary"></i>'; badge = '<span class="badge bg-secondary">SKIP</span>'; }
                    else if (s.success) { icon = '<i class="fas fa-check-circle text-success"></i>'; badge = '<span class="badge bg-success">OK</span>'; }
                    else { icon = '<i class="fas fa-times-circle text-danger"></i>'; badge = '<span class="badge bg-danger">FAIL</span>'; }
                    html += '<div class="d-flex align-items-start gap-2 mb-2">' + icon +
                        '<div class="flex-grow-1"><div>' + badge + ' <strong>' + escapeHtmlUb(s.label) + '</strong></div>';
                    if (s.message) html += '<div class="small text-muted">' + escapeHtmlUb(s.message) + '</div>';
                    if (s.output && s.output.length > 0) html += '<details class="small mt-1"><summary>Output</summary><pre class="mb-0 mt-1" style="font-size:0.75rem;max-height:200px;overflow:auto">' + escapeHtmlUb(s.output) + '</pre></details>';
                    html += '</div></div>';
                });
                stepsEl.innerHTML = html;
                report.classList.remove('d-none');
                loadUnboundHealth();
            }).catch(e => {
                btn.disabled = false;
                btn.innerHTML = original;
                alert('Errore rete: ' + e.message);
            });
        }

        function runUbTestQuery() {
            const btn = document.getElementById('btnUbTestQuery');
            const original = btn.innerHTML;
            btn.disabled = true;
            btn.innerHTML = '<span class="spinner-border spinner-border-sm me-1"></span>Test...';
            fetch('/api/unbound_health', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'test_query', csrf_token: document.getElementById('csrf_token').value })
            }).then(r => r.json()).then(data => {
                btn.disabled = false;
                btn.innerHTML = original;
                const resultEl = document.getElementById('ubTestResult');
                const bodyEl = document.getElementById('ubTestBody');
                bodyEl.textContent = data.message || JSON.stringify(data);
                bodyEl.className = 'small mb-0' + (data.success ? ' text-success' : ' text-warning');
                resultEl.classList.remove('d-none');
            }).catch(e => {
                btn.disabled = false;
                btn.innerHTML = original;
                alert('Errore rete: ' + e.message);
            });
        }

        function escapeHtmlUb(s) {
            const d = document.createElement('div');
            d.textContent = s == null ? '' : String(s);
            return d.innerHTML;
        }

        // ===== ClamAV Health Check =====
        function loadClamavHealth() {
            const c = document.getElementById('cavContainer');
            const overall = document.getElementById('cavOverallStatus');
            const btnFixAll = document.getElementById('btnCavFixAll');
            c.innerHTML = '<p class="text-muted mb-0"><i class="fas fa-spinner fa-spin me-1"></i>Diagnosi in corso...</p>';
            fetch('/api/clamav_health', { method: 'GET' })
                .then(r => r.json())
                .then(data => {
                    if (!data.success) {
                        c.innerHTML = '<div class="alert alert-danger mb-0">Errore: ' + (data.error || 'sconosciuto') + '</div>';
                        return;
                    }
                    if (data.all_ok) {
                        overall.innerHTML = '<span class="badge bg-success">Tutto OK</span>';
                        if (btnFixAll) btnFixAll.classList.add('d-none');
                    } else {
                        overall.innerHTML = '<span class="badge bg-warning text-dark">Azione richiesta</span>';
                        if (btnFixAll) btnFixAll.classList.remove('d-none');
                    }
                    let html = '<div class="list-group list-group-flush">';
                    (data.checks || []).forEach(chk => {
                        const icon = chk.ok ? '<i class="fas fa-check-circle text-success"></i>' : '<i class="fas fa-times-circle text-danger"></i>';
                        html += '<div class="list-group-item">';
                        html += '<div class="d-flex justify-content-between align-items-start gap-3 flex-wrap">';
                        html += '<div class="flex-grow-1">';
                        html += '<div><strong>' + icon + ' ' + escapeHtmlCav(chk.label) + '</strong></div>';
                        html += '<div class="small text-muted">' + escapeHtmlCav(chk.status || '') + '</div>';
                        if (!chk.ok && chk.impact) html += '<div class="small text-danger mt-1"><i class="fas fa-exclamation-triangle me-1"></i>Se non lo risolvi: ' + escapeHtmlCav(chk.impact) + '</div>';
                        if (!chk.ok && chk.fix_description) html += '<div class="small text-info mt-1"><i class="fas fa-magic me-1"></i>' + escapeHtmlCav(chk.fix_description) + '</div>';
                        html += '</div>';
                        if (!chk.ok && chk.fix_action) {
                            html += '<button class="btn btn-warning btn-sm" onclick="runCavFix(\'' + chk.fix_action + '\', this)">';
                            html += '<i class="fas fa-wrench me-1"></i>Risolvi';
                            html += '</button>';
                        }
                        html += '</div></div>';
                    });
                    html += '</div>';
                    if (data.all_ok) html += '<div class="alert alert-success mb-0 mt-3 py-2"><i class="fas fa-virus-slash me-2"></i>ClamAV operativo, Rspamd lo chiama, tutte le mail vengono scansionate.</div>';
                    c.innerHTML = html;
                })
                .catch(e => {
                    c.innerHTML = '<div class="alert alert-danger mb-0">Errore rete: ' + e.message + '</div>';
                });
        }

        function runCavFix(action, btn) {
            if (!confirm('Applicare la correzione automatica?')) return;
            const original = btn.innerHTML;
            btn.disabled = true;
            btn.innerHTML = '<span class="spinner-border spinner-border-sm me-1"></span>In corso (alcune operazioni richiedono minuti)...';
            fetch('/api/clamav_health', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: action, csrf_token: document.getElementById('csrf_token').value })
            }).then(r => r.json()).then(data => {
                btn.disabled = false;
                btn.innerHTML = original;
                if (data.success) loadClamavHealth();
                else alert('Errore: ' + (data.message || data.error || 'sconosciuto') + (data.output ? '\n\n' + data.output : ''));
                loadClamavHealth();
            }).catch(e => {
                btn.disabled = false;
                btn.innerHTML = original;
                alert('Errore rete: ' + e.message);
            });
        }

        function runCavFixAll() {
            if (!confirm('Risolvi tutto ClamAV — esegue in ordine:\n' +
                '1. Installa ClamAV (se manca)\n' +
                '2. Abilita freshclam e clamd al boot\n' +
                '3. Scarica database virus (può richiedere 2-5 min)\n' +
                '4. Avvia freshclam e clamd\n' +
                '5. Configura Rspamd per usare ClamAV\n\n' +
                'Procedo?')) return;

            const btn = document.getElementById('btnCavFixAll');
            const original = btn.innerHTML;
            btn.disabled = true;
            btn.innerHTML = '<span class="spinner-border spinner-border-sm me-1"></span>In corso (può richiedere fino a 10 min)...';

            fetch('/api/clamav_health', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'fix_all', csrf_token: document.getElementById('csrf_token').value })
            }).then(r => r.json()).then(data => {
                btn.disabled = false;
                btn.innerHTML = original;
                const report = document.getElementById('cavFixAllReport');
                const stepsEl = document.getElementById('cavFixAllSteps');
                let html = '';
                (data.steps || []).forEach(s => {
                    let icon, badge;
                    if (s.status === 'skipped') { icon = '<i class="fas fa-forward text-secondary"></i>'; badge = '<span class="badge bg-secondary">SKIP</span>'; }
                    else if (s.success) { icon = '<i class="fas fa-check-circle text-success"></i>'; badge = '<span class="badge bg-success">OK</span>'; }
                    else { icon = '<i class="fas fa-times-circle text-danger"></i>'; badge = '<span class="badge bg-danger">FAIL</span>'; }
                    html += '<div class="d-flex align-items-start gap-2 mb-2">' + icon +
                        '<div class="flex-grow-1"><div>' + badge + ' <strong>' + escapeHtmlCav(s.label) + '</strong></div>';
                    if (s.message) html += '<div class="small text-muted">' + escapeHtmlCav(s.message) + '</div>';
                    if (s.output && s.output.length > 0) html += '<details class="small mt-1"><summary>Output</summary><pre class="mb-0 mt-1" style="font-size:0.75rem;max-height:200px;overflow:auto">' + escapeHtmlCav(s.output) + '</pre></details>';
                    html += '</div></div>';
                });
                stepsEl.innerHTML = html;
                report.classList.remove('d-none');
                loadClamavHealth();
            }).catch(e => {
                btn.disabled = false;
                btn.innerHTML = original;
                alert('Errore rete: ' + e.message);
            });
        }

        function runCavTestEicar() {
            const btn = document.getElementById('btnCavTestEicar');
            const original = btn.innerHTML;
            btn.disabled = true;
            btn.innerHTML = '<span class="spinner-border spinner-border-sm me-1"></span>Test in corso...';
            fetch('/api/clamav_health', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'test_eicar', csrf_token: document.getElementById('csrf_token').value })
            }).then(r => r.json()).then(data => {
                btn.disabled = false;
                btn.innerHTML = original;
                const resultEl = document.getElementById('cavEicarResult');
                const bodyEl = document.getElementById('cavEicarBody');
                let alertClass, icon;
                if (data.success && data.detected) {
                    alertClass = 'alert-success';
                    icon = '<i class="fas fa-shield-virus me-2"></i>';
                } else if (data.detected === false) {
                    alertClass = 'alert-warning';
                    icon = '<i class="fas fa-exclamation-triangle me-2"></i>';
                } else {
                    alertClass = 'alert-danger';
                    icon = '<i class="fas fa-times-circle me-2"></i>';
                }
                let html = '<div class="alert ' + alertClass + ' mb-2">' + icon + escapeHtmlCav(data.message || 'Risultato sconosciuto') + '</div>';
                if (data.scan_output) {
                    html += '<details class="small"><summary>Output clamdscan</summary>';
                    html += '<pre class="mb-0 mt-1" style="font-size:0.8rem;max-height:200px;overflow:auto">' + escapeHtmlCav(data.scan_output) + '</pre>';
                    html += '</details>';
                }
                html += '<div class="small text-muted mt-2"><i class="fas fa-info-circle me-1"></i>EICAR è un file di test standard riconosciuto da tutti gli antivirus, completamente innocuo. Se ClamAV NON lo rileva, c\'è un problema con scan/database.</div>';
                bodyEl.innerHTML = html;
                resultEl.classList.remove('d-none');
            }).catch(e => {
                btn.disabled = false;
                btn.innerHTML = original;
                alert('Errore rete: ' + e.message);
            });
        }

        function escapeHtmlCav(s) {
            const d = document.createElement('div');
            d.textContent = s == null ? '' : String(s);
            return d.innerHTML;
        }

        // ===== Refresh Jail Attive (spinner visivo + feedback) =====
        function refreshJails(userTriggered) {
            const icon = document.getElementById('iconRefreshJails');
            const btn = document.getElementById('btnRefreshJails');
            if (icon) icon.classList.add('fa-spin');
            if (btn) btn.disabled = true;
            // Mostra "Aggiornamento..." nel container
            const container = document.getElementById('jailsContainer');
            if (container && userTriggered) {
                container.innerHTML = '<p class="text-muted mb-0"><i class="fas fa-spinner fa-spin me-1"></i>Aggiornamento in corso...</p>';
            }
            // Carica + delay artificiale per feedback visivo
            const promise = fetch('/api/fail2ban?action=status').then(r => r.json());
            const minDelay = new Promise(r => setTimeout(r, 400));
            Promise.all([promise, minDelay]).then(([data]) => {
                // Riusa la logica di loadStatus chiamandola
                loadStatus();
            }).catch(e => {
                if (container) container.innerHTML = '<p class="text-danger mb-0">Errore: ' + e.message + '</p>';
            }).finally(() => {
                if (icon) icon.classList.remove('fa-spin');
                if (btn) btn.disabled = false;
            });
        }

        // ===== Permaban =====
        function permabanAdd(ip) {
            if (!confirm('Aggiungere ' + ip + ' al ban PERMANENTE?\n\n' +
                'L\'IP verrà bloccato da pf indipendentemente da Fail2ban e\n' +
                'sopravviverà a tutti i riavvii. Per sbannare dovrai rimuoverlo dalla lista permaban.')) return;
            fetch('/api/fail2ban', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'permaban_add', ip: ip })
            }).then(r => r.json()).then(data => {
                if (data.success) {
                    permabanList();
                    loadStatus();
                } else {
                    alert('Errore: ' + (data.message || 'sconosciuto'));
                }
            }).catch(e => alert('Errore rete: ' + e.message));
        }

        function permabanAddManual() {
            const input = document.getElementById('permabanIpInput');
            const ip = input.value.trim();
            if (!ip) { alert('Inserisci un IP'); return; }
            if (!confirm('Aggiungere ' + ip + ' al ban PERMANENTE via pf?')) return;
            fetch('/api/fail2ban', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'permaban_add', ip: ip })
            }).then(r => r.json()).then(data => {
                if (data.success) {
                    input.value = '';
                    permabanList();
                } else {
                    alert('Errore: ' + (data.message || 'sconosciuto'));
                }
            }).catch(e => alert('Errore rete: ' + e.message));
        }

        function permabanRemove(ip) {
            if (!confirm('Rimuovere ' + ip + ' dal permaban?\n\nL\'IP NON sarà più bloccato da pf.')) return;
            fetch('/api/fail2ban', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'permaban_remove', ip: ip })
            }).then(r => r.json()).then(data => {
                if (data.success) permabanList();
                else alert('Errore: ' + (data.message || 'sconosciuto'));
            }).catch(e => alert('Errore rete: ' + e.message));
        }

        function permabanReload() {
            fetch('/api/fail2ban', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'permaban_reload' })
            }).then(r => r.json()).then(data => {
                alert(data.message || (data.success ? 'OK' : 'Errore'));
                permabanList();
            }).catch(e => alert('Errore rete: ' + e.message));
        }

        function permabanList() {
            fetch('/api/fail2ban?action=permaban_list')
                .then(r => r.json())
                .then(data => {
                    const tbody = document.getElementById('permabanBody');
                    const counter = document.getElementById('permabanCount');
                    if (!data.success) {
                        tbody.innerHTML = '<tr><td colspan="3" class="text-muted">Errore: ' + (data.error || 'sconosciuto') + '</td></tr>';
                        return;
                    }
                    counter.textContent = data.count || 0;
                    const list = data.permabans || [];
                    if (list.length === 0) {
                        tbody.innerHTML = '<tr><td colspan="3" class="text-muted">Nessun IP in permaban</td></tr>';
                        return;
                    }
                    tbody.innerHTML = list.map(item => `
                        <tr>
                            <td><span class="ip-badge">${escapeHtmlPermaban(item.ip)}</span></td>
                            <td>${item.in_runtime ? '<span class="badge bg-success">attivo</span>' : '<span class="badge bg-warning text-dark">non runtime</span>'}</td>
                            <td>
                                <button class="btn btn-sm btn-outline-success" onclick="permabanRemove('${item.ip}')" title="Rimuovi dal permaban">
                                    <i class="fas fa-unlock"></i>
                                </button>
                                <button class="btn btn-link btn-sm p-0 ms-1" onclick="showIpInfo('${item.ip}')" title="Info IP">
                                    <i class="fas fa-info-circle"></i>
                                </button>
                            </td>
                        </tr>
                    `).join('');
                })
                .catch(e => {
                    document.getElementById('permabanBody').innerHTML =
                        '<tr><td colspan="3" class="text-danger">Errore rete: ' + e.message + '</td></tr>';
                });
        }

        // Helper per permaban (escapeHtml potrebbe non essere definita prima)
        function escapeHtmlPermaban(s) {
            const d = document.createElement('div');
            d.textContent = s == null ? '' : String(s);
            return d.innerHTML;
        }

        // Load on page load
        loadStatus();
        // Popola prima il selettore con tutte le jail attive, poi carica la config
        populateJailSelect(() => loadJailConfig());
        loadFail2banHealth();
        loadJailLiveState();
        paliasLoad();
        loadClamavHealth();
        loadUnboundHealth();
        permabanList();
        // Auto-refresh every minute
        setInterval(loadStatus, 60000);
        setInterval(permabanList, 60000);
