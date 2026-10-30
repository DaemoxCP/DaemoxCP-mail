
        // ===== Unbound (Resolver DNS locale) Health Check =====
        function loadUnboundHealth() {
            const c = document.getElementById('ubContainer');
            const overall = document.getElementById('ubOverallStatus');
            const btnFixAll = document.getElementById('btnUbFixAll');
            c.innerHTML = '<p class="text-muted mb-0"><i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('sec.diagnosing')) + '</p>';
            fetch('/api/unbound_health', { method: 'GET' }).then(r => r.json()).then(data => {
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
                (data.checks || []).forEach(chk => {
                    const icon = chk.ok ? '<i class="fas fa-check-circle text-success" aria-hidden="true"></i><span class="visually-hidden">' + escHtml(t('dns.succeeded')) + '</span>'
                                       : '<i class="fas fa-times-circle text-danger" aria-hidden="true"></i><span class="visually-hidden">' + escHtml(t('dns.failed')) + '</span>';
                    html += '<div class="list-group-item">';
                    html += '<div class="d-flex justify-content-between align-items-start gap-3 flex-wrap">';
                    html += '<div class="flex-grow-1">';
                    html += '<div><strong>' + icon + ' ' + escapeHtmlUb(chk.label) + '</strong></div>';
                    html += '<div class="small text-muted">' + escapeHtmlUb(chk.status || '') + '</div>';
                    if (!chk.ok && chk.impact) html += '<div class="small text-danger mt-1"><i class="fas fa-exclamation-triangle me-1" aria-hidden="true"></i>' + escHtml(t('sj.ifNotFixed', { impact: chk.impact })) + '</div>';
                    if (!chk.ok && chk.fix_description) html += '<div class="small text-info mt-1"><i class="fas fa-magic me-1" aria-hidden="true"></i>' + escapeHtmlUb(chk.fix_description) + '</div>';
                    html += '</div>';
                    if (!chk.ok && chk.fix_action) {
                        html += '<button class="btn btn-warning btn-sm" data-action="' + escHtml(chk.fix_action) + '" onclick="runUbFix(this.dataset.action, this)">';
                        html += '<i class="fas fa-wrench me-1" aria-hidden="true"></i>' + escHtml(t('sec.fix'));
                        html += '</button>';
                    }
                    html += '</div></div>';
                });
                html += '</div>';
                if (data.all_ok) html += '<div class="alert alert-success mb-0 mt-3 py-2"><i class="fas fa-shield-alt me-2" aria-hidden="true"></i>' + escHtml(t('shu.ubOk')) + '</div>';
                c.innerHTML = html;
            }).catch(e => {
                c.innerHTML = '<div class="alert alert-danger mb-0">' + escHtml(t('common.networkError', { message: e.message })) + '</div>';
            });
        }

        function runUbFix(action, btn) {
            const warning = (action === 'switch_resolv_conf') ? '\n\n' + t('shu.resolvWarning') : '';
            if (!confirm(t('shu.confirmFix') + warning)) return;
            const original = btn.innerHTML;
            btn.disabled = true;
            btn.innerHTML = '<span class="spinner-border spinner-border-sm me-1" aria-hidden="true"></span>' + escHtml(t('sj.inProgress')) + '';
            fetch('/api/unbound_health', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: action, csrf_token: document.getElementById('csrf_token').value })
            }).then(r => r.json()).then(data => {
                btn.disabled = false;
                btn.innerHTML = original;
                if (data.success) loadUnboundHealth();
                else alert(t('common.error', { message: data.message || data.error || t('common.unknownError') }) + (data.output ? '\n\n' + data.output : ''));
                loadUnboundHealth();
            }).catch(e => {
                btn.disabled = false;
                btn.innerHTML = original;
                alert(t('common.networkError', { message: e.message }));
            });
        }

        function runUbFixAll() {
            if (!confirm(t('shu.confirmUbFixAll'))) return;

            const btn = document.getElementById('btnUbFixAll');
            const original = btn.innerHTML;
            btn.disabled = true;
            btn.innerHTML = '<span class="spinner-border spinner-border-sm me-1" aria-hidden="true"></span>' + escHtml(t('shu.inProgress2')) + '';

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
                    if (s.status === 'skipped') { icon = '<i class="fas fa-forward text-secondary" aria-hidden="true"></i>'; badge = '<span class="badge bg-secondary">' + escHtml(t('sj.skipped')) + '</span>'; }
                    else if (s.success) { icon = '<i class="fas fa-check-circle text-success" aria-hidden="true"></i>'; badge = '<span class="badge bg-success">OK</span>'; }
                    else { icon = '<i class="fas fa-times-circle text-danger" aria-hidden="true"></i>'; badge = '<span class="badge bg-danger">' + escHtml(t('sj.fail')) + '</span>'; }
                    html += '<div class="d-flex align-items-start gap-2 mb-2">' + icon +
                        '<div class="flex-grow-1"><div>' + badge + ' <strong>' + escapeHtmlUb(s.label) + '</strong></div>';
                    if (s.message) html += '<div class="small text-muted">' + escapeHtmlUb(s.message) + '</div>';
                    if (s.output && s.output.length > 0) html += '<details class="small mt-1"><summary>' + escHtml(t('sj.output')) + '</summary><pre class="mb-0 mt-1" style="font-size:0.75rem;max-height:200px;overflow:auto">' + escapeHtmlUb(s.output) + '</pre></details>';
                    html += '</div></div>';
                });
                stepsEl.innerHTML = html;
                report.classList.remove('d-none');
                loadUnboundHealth();
            }).catch(e => {
                btn.disabled = false;
                btn.innerHTML = original;
                alert(t('common.networkError', { message: e.message }));
            });
        }

        function runUbTestQuery() {
            const btn = document.getElementById('btnUbTestQuery');
            const original = btn.innerHTML;
            btn.disabled = true;
            btn.innerHTML = '<span class="spinner-border spinner-border-sm me-1" aria-hidden="true"></span>' + escHtml(t('shu.testing')) + '';
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
                alert(t('common.networkError', { message: e.message }));
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
            c.innerHTML = '<p class="text-muted mb-0"><i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('sec.diagnosing')) + '</p>';
            fetch('/api/clamav_health', { method: 'GET' })
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
                    (data.checks || []).forEach(chk => {
                        const icon = chk.ok ? '<i class="fas fa-check-circle text-success" aria-hidden="true"></i><span class="visually-hidden">' + escHtml(t('dns.succeeded')) + '</span>'
                                       : '<i class="fas fa-times-circle text-danger" aria-hidden="true"></i><span class="visually-hidden">' + escHtml(t('dns.failed')) + '</span>';
                        html += '<div class="list-group-item">';
                        html += '<div class="d-flex justify-content-between align-items-start gap-3 flex-wrap">';
                        html += '<div class="flex-grow-1">';
                        html += '<div><strong>' + icon + ' ' + escapeHtmlCav(chk.label) + '</strong></div>';
                        html += '<div class="small text-muted">' + escapeHtmlCav(chk.status || '') + '</div>';
                        if (!chk.ok && chk.impact) html += '<div class="small text-danger mt-1"><i class="fas fa-exclamation-triangle me-1" aria-hidden="true"></i>' + escHtml(t('sj.ifNotFixed', { impact: chk.impact })) + '</div>';
                        if (!chk.ok && chk.fix_description) html += '<div class="small text-info mt-1"><i class="fas fa-magic me-1" aria-hidden="true"></i>' + escapeHtmlCav(chk.fix_description) + '</div>';
                        html += '</div>';
                        if (!chk.ok && chk.fix_action) {
                            html += '<button class="btn btn-warning btn-sm" data-action="' + escHtml(chk.fix_action) + '" onclick="runCavFix(this.dataset.action, this)">';
                            html += '<i class="fas fa-wrench me-1" aria-hidden="true"></i>' + escHtml(t('sec.fix'));
                            html += '</button>';
                        }
                        html += '</div></div>';
                    });
                    html += '</div>';
                    if (data.all_ok) html += '<div class="alert alert-success mb-0 mt-3 py-2"><i class="fas fa-virus-slash me-2" aria-hidden="true"></i>' + escHtml(t('shu.cavOk')) + '</div>';
                    c.innerHTML = html;
                })
                .catch(e => {
                    c.innerHTML = '<div class="alert alert-danger mb-0">' + escHtml(t('common.networkError', { message: e.message })) + '</div>';
                });
        }

        function runCavFix(action, btn) {
            if (!confirm(t('shu.confirmAutoFix'))) return;
            const original = btn.innerHTML;
            btn.disabled = true;
            btn.innerHTML = '<span class="spinner-border spinner-border-sm me-1" aria-hidden="true"></span>' + escHtml(t('shu.inProgressSlow')) + '';
            fetch('/api/clamav_health', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: action, csrf_token: document.getElementById('csrf_token').value })
            }).then(r => r.json()).then(data => {
                btn.disabled = false;
                btn.innerHTML = original;
                if (data.success) loadClamavHealth();
                else alert(t('common.error', { message: data.message || data.error || t('common.unknownError') }) + (data.output ? '\n\n' + data.output : ''));
                loadClamavHealth();
            }).catch(e => {
                btn.disabled = false;
                btn.innerHTML = original;
                alert(t('common.networkError', { message: e.message }));
            });
        }

        function runCavFixAll() {
            if (!confirm(t('shu.confirmCavFixAll'))) return;

            const btn = document.getElementById('btnCavFixAll');
            const original = btn.innerHTML;
            btn.disabled = true;
            btn.innerHTML = '<span class="spinner-border spinner-border-sm me-1" aria-hidden="true"></span>' + escHtml(t('shu.inProgress10')) + '';

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
                    if (s.status === 'skipped') { icon = '<i class="fas fa-forward text-secondary" aria-hidden="true"></i>'; badge = '<span class="badge bg-secondary">' + escHtml(t('sj.skipped')) + '</span>'; }
                    else if (s.success) { icon = '<i class="fas fa-check-circle text-success" aria-hidden="true"></i>'; badge = '<span class="badge bg-success">OK</span>'; }
                    else { icon = '<i class="fas fa-times-circle text-danger" aria-hidden="true"></i>'; badge = '<span class="badge bg-danger">' + escHtml(t('sj.fail')) + '</span>'; }
                    html += '<div class="d-flex align-items-start gap-2 mb-2">' + icon +
                        '<div class="flex-grow-1"><div>' + badge + ' <strong>' + escapeHtmlCav(s.label) + '</strong></div>';
                    if (s.message) html += '<div class="small text-muted">' + escapeHtmlCav(s.message) + '</div>';
                    if (s.output && s.output.length > 0) html += '<details class="small mt-1"><summary>' + escHtml(t('sj.output')) + '</summary><pre class="mb-0 mt-1" style="font-size:0.75rem;max-height:200px;overflow:auto">' + escapeHtmlCav(s.output) + '</pre></details>';
                    html += '</div></div>';
                });
                stepsEl.innerHTML = html;
                report.classList.remove('d-none');
                loadClamavHealth();
            }).catch(e => {
                btn.disabled = false;
                btn.innerHTML = original;
                alert(t('common.networkError', { message: e.message }));
            });
        }

        function runCavTestEicar() {
            const btn = document.getElementById('btnCavTestEicar');
            const original = btn.innerHTML;
            btn.disabled = true;
            btn.innerHTML = '<span class="spinner-border spinner-border-sm me-1" aria-hidden="true"></span>' + escHtml(t('shu.testRunning')) + '';
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
                    icon = '<i class="fas fa-shield-virus me-2" aria-hidden="true"></i>';
                } else if (data.detected === false) {
                    alertClass = 'alert-warning';
                    icon = '<i class="fas fa-exclamation-triangle me-2" aria-hidden="true"></i>';
                } else {
                    alertClass = 'alert-danger';
                    icon = '<i class="fas fa-times-circle me-2" aria-hidden="true"></i>';
                }
                let html = '<div class="alert ' + alertClass + ' mb-2">' + icon + escapeHtmlCav(data.message || t('shu.unknownResult')) + '</div>';
                if (data.scan_output) {
                    html += '<details class="small"><summary>' + escHtml(t('sj.outputOf')) + ' clamdscan</summary>';
                    html += '<pre class="mb-0 mt-1" style="font-size:0.8rem;max-height:200px;overflow:auto">' + escapeHtmlCav(data.scan_output) + '</pre>';
                    html += '</details>';
                }
                html += '<div class="small text-muted mt-2"><i class="fas fa-info-circle me-1" aria-hidden="true"></i>' + escHtml(t('shu.eicarInfo')) + '</div>';
                bodyEl.innerHTML = html;
                resultEl.classList.remove('d-none');
            }).catch(e => {
                btn.disabled = false;
                btn.innerHTML = original;
                alert(t('common.networkError', { message: e.message }));
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
                container.innerHTML = '<p class="text-muted mb-0"><i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('shu.refreshing')) + '</p>';
            }
            // Carica + delay artificiale per feedback visivo
            const promise = fetch('/api/fail2ban?action=status').then(r => r.json());
            const minDelay = new Promise(r => setTimeout(r, 400));
            Promise.all([promise, minDelay]).then(([data]) => {
                // Riusa la logica di loadStatus chiamandola
                loadStatus();
            }).catch(e => {
                if (container) container.innerHTML = '<p class="text-danger mb-0">' + escHtml(t('common.error', { message: e.message })) + '</p>';
            }).finally(() => {
                if (icon) icon.classList.remove('fa-spin');
                if (btn) btn.disabled = false;
            });
        }

        // ===== Permaban =====
        function permabanAdd(ip) {
            if (!confirm(t('shu.confirmPermaban', { ip: ip }))) return;
            fetch('/api/fail2ban', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'permaban_add', ip: ip })
            }).then(r => r.json()).then(data => {
                if (data.success) {
                    permabanList();
                    loadStatus();
                } else {
                    alert(t('common.error', { message: data.message || t('common.unknownError') }));
                }
            }).catch(e => alert(t('common.networkError', { message: e.message })));
        }

        function permabanAddManual() {
            const input = document.getElementById('permabanIpInput');
            const ip = input.value.trim();
            if (!ip) { alert(t('sec.needIp')); return; }
            if (!confirm(t('shu.confirmPermabanPf', { ip: ip }))) return;
            fetch('/api/fail2ban', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'permaban_add', ip: ip })
            }).then(r => r.json()).then(data => {
                if (data.success) {
                    input.value = '';
                    permabanList();
                } else {
                    alert(t('common.error', { message: data.message || t('common.unknownError') }));
                }
            }).catch(e => alert(t('common.networkError', { message: e.message })));
        }

        function permabanRemove(ip) {
            if (!confirm(t('shu.confirmUnban', { ip: ip }))) return;
            fetch('/api/fail2ban', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'permaban_remove', ip: ip })
            }).then(r => r.json()).then(data => {
                if (data.success) permabanList();
                else alert(t('common.error', { message: data.message || t('common.unknownError') }));
            }).catch(e => alert(t('common.networkError', { message: e.message })));
        }

        function permabanReload() {
            fetch('/api/fail2ban', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'permaban_reload' })
            }).then(r => r.json()).then(data => {
                alert(data.message || (data.success ? t('common.done') : t('common.errorShort')));
                permabanList();
            }).catch(e => alert(t('common.networkError', { message: e.message })));
        }

        function permabanList() {
            fetch('/api/fail2ban?action=permaban_list')
                .then(r => r.json())
                .then(data => {
                    const tbody = document.getElementById('permabanBody');
                    const counter = document.getElementById('permabanCount');
                    if (!data.success) {
                        tbody.innerHTML = '<tr><td colspan="3" class="text-muted">' + escHtml(t('common.error', { message: data.error || t('common.unknownError') })) + '</td></tr>';
                        return;
                    }
                    counter.textContent = data.count || 0;
                    const list = data.permabans || [];
                    if (list.length === 0) {
                        tbody.innerHTML = '<tr><td colspan="3" class="text-muted">' + escHtml(t('shu.noPermaban')) + '</td></tr>';
                        return;
                    }
                    tbody.innerHTML = list.map(item => `
                        <tr>
                            <td><span class="ip-badge">${escapeHtmlPermaban(item.ip)}</span></td>
                            <td>${item.at_runtime ? '<span class="badge bg-success">' + escHtml(t('shu.inPf')) + '</span>' : '<span class="badge bg-warning text-dark">' + escHtml(t('shu.notInPf')) + '</span>'}</td>
                            <td>
                                <button class="btn btn-sm btn-outline-success" data-ip="${escHtml(item.ip)}" onclick="permabanRemove(this.dataset.ip)" title="${escHtml(t('shu.unban'))}" aria-label="${escHtml(t('shu.unban'))}">
                                    <i class="fas fa-unlock" aria-hidden="true"></i>
                                </button>
                                <button class="btn btn-link btn-sm p-0 ms-1" data-ip="${escHtml(item.ip)}" onclick="showIpInfo(this.dataset.ip)" title="${escHtml(t('sec.ipInfo'))}" aria-label="${escHtml(t('sec.ipInfo'))}">
                                    <i class="fas fa-info-circle" aria-hidden="true"></i>
                                </button>
                            </td>
                        </tr>
                    `).join('');
                })
                .catch(e => {
                    document.getElementById('permabanBody').innerHTML =
                        '<tr><td colspan="3" class="text-danger">' + escHtml(t('common.networkError', { message: e.message })) + '</td></tr>';
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
