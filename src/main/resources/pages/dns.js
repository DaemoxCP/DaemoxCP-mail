        // ===== Cloudflare multi-account integration =====
        // Cache locale per usare i dati in giro (rotateDkim, dkim card info)
        let cfAccounts = [];     // [{id,label,email,token_masked,...}]
        let cfDomainsCf = [];    // [{id,domain,cloudflare_account_id}]

        function escapeHtmlCf(s) {
            const d = document.createElement('div');
            d.textContent = s == null ? '' : String(s);
            return d.innerHTML;
        }

        function refreshCloudflare() {
            const badge = document.getElementById('cfAccountsCountBadge');
            const list = document.getElementById('cfAccountsList');
            const assign = document.getElementById('cfDomainAssignments');
            badge.innerHTML = '<span class="badge bg-light text-dark"><i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('common.loading')) + '</span>';

            fetch('/api/cloudflare').then(r => {
                if (!r.ok) throw new Error('HTTP ' + r.status);
                return r.json();
            }).then(data => {
                cfAccounts = data.accounts || [];
                cfDomainsCf = data.domains || [];

                badge.innerHTML = cfAccounts.length === 0
                    ? '<span class="badge bg-secondary">' + escHtml(tn('dns.cfCount', 0)) + '</span>'
                    : '<span class="badge bg-success">' + escHtml(tn('dns.cfCount', cfAccounts.length)) + '</span>';

                // Lista account
                if (cfAccounts.length === 0) {
                    list.innerHTML = '<div class="alert alert-secondary py-2 mb-0 small"><i class="fas fa-info-circle me-1" aria-hidden="true"></i>' + escHtml(t('dns.cfNone')) + '</div>';
                } else {
                    let html = '<div class="table-responsive"><table class="table table-sm align-middle mb-0">';
                    html += '<thead><tr><th scope="col">' + escHtml(t('dns.cfLabel')) + '</th><th scope="col">' + escHtml(t('dns.cfEmail')) + '</th><th scope="col">Token</th><th scope="col">' + escHtml(t('dns.cfLinked')) + '</th><th scope="col" class="text-end">' + escHtml(t('home.colActions')) + '</th></tr></thead><tbody>';
                    cfAccounts.forEach(a => {
                        const linkedDomains = cfDomainsCf.filter(d => d.cloudflare_account_id === a.id).map(d => d.domain);
                        const safeLabel = escapeHtmlCf(a.label).replace(/'/g, "\\'");
                        // Riga di visualizzazione
                        html += '<tr id="cfRowView-' + a.id + '">';
                        html += '<td><strong>' + escapeHtmlCf(a.label) + '</strong></td>';
                        html += '<td>' + (a.email ? escapeHtmlCf(a.email) : '<span class="text-muted">—</span>') + '</td>';
                        html += '<td><code>' + escapeHtmlCf(a.token_masked) + '</code></td>';
                        html += '<td>' + (linkedDomains.length === 0
                            ? '<span class="text-muted small">' + escHtml(t('dns.none')) + '</span>'
                            : linkedDomains.map(d => '<span class="badge bg-info text-dark me-1">' + escapeHtmlCf(d) + '</span>').join('')) + '</td>';
                        html += '<td class="text-end text-nowrap">';
                        html += '<button class="btn btn-sm btn-outline-primary me-1" title="' + escHtml(t('common.edit')) + '" aria-label="' + escHtml(t('common.edit')) + ' ' + escapeHtmlCf(a.label) + '" data-on-click="cfEditOpen(' + a.id + ')"><i class="fas fa-pen" aria-hidden="true"></i></button>';
                        html += '<button class="btn btn-sm btn-outline-danger" title="' + escHtml(t('dns.remove')) + '" aria-label="' + escHtml(t('dns.remove')) + ' ' + escapeHtmlCf(a.label) + '" data-on-click="cfDeleteAccount(' + a.id + ', \'' + safeLabel + '\')"><i class="fas fa-trash" aria-hidden="true"></i></button>';
                        html += '</td>';
                        html += '</tr>';
                        // Riga di edit (nascosta finché non clicchi la matita)
                        html += '<tr id="cfRowEdit-' + a.id + '" class="d-none table-warning"><td colspan="5">';
                        html += '<div class="row g-2 align-items-end">';
                        html += '  <div class="col-md-3"><label class="form-label small mb-1" for="cfEditLabel-' + a.id + '">' + escHtml(t('dns.cfLabel')) + '</label><input type="text" class="form-control form-control-sm" id="cfEditLabel-' + a.id + '" value="' + escapeHtmlCf(a.label) + '"></div>';
                        html += '  <div class="col-md-3"><label class="form-label small mb-1" for="cfEditEmail-' + a.id + '">' + escHtml(t('dns.cfEmail')) + '</label><input type="email" class="form-control form-control-sm" id="cfEditEmail-' + a.id + '" value="' + escapeHtmlCf(a.email || '') + '" placeholder="' + escHtml(t('dns.optional')) + '"></div>';
                        html += '  <div class="col-md-4"><label class="form-label small mb-1" for="cfEditToken-' + a.id + '">' + escHtml(t('dns.cfNewToken')) + ' <small class="text-muted">' + escHtml(t('dns.cfNewTokenHint')) + '</small></label><input type="password" class="form-control form-control-sm" id="cfEditToken-' + a.id + '" placeholder="' + escHtml(t('dns.cfNewTokenPh')) + '" autocomplete="off"></div>';
                        html += '  <div class="col-md-2 text-end">';
                        html += '    <button class="btn btn-sm btn-primary me-1" data-on-click="cfEditSave(' + a.id + ')"><i class="fas fa-save" aria-hidden="true"></i> ' + escHtml(t('common.save')) + '</button>';
                        html += '    <button class="btn btn-sm btn-secondary" data-on-click="cfEditClose(' + a.id + ')" aria-label="' + escHtml(t('common.cancel')) + '"><i class="fas fa-times" aria-hidden="true"></i></button>';
                        html += '  </div>';
                        html += '</div>';
                        html += '</td></tr>';
                    });
                    html += '</tbody></table></div>';
                    list.innerHTML = html;
                }

                // Tabella assegnazione domini -> account
                if (cfDomainsCf.length === 0) {
                    assign.innerHTML = '<div class="text-muted small">' + escHtml(t('dns.cfAddDomainFirst')) + '</div>';
                } else {
                    let html = '<div class="table-responsive"><table class="table table-sm align-middle mb-0">';
                    html += '<thead><tr><th scope="col">' + escHtml(t('st.colDomain')) + '</th><th scope="col">' + escHtml(t('dns.rotationMode')) + '</th></tr></thead><tbody>';
                    cfDomainsCf.forEach(d => {
                        html += '<tr>';
                        html += '<td><code>' + escapeHtmlCf(d.domain) + '</code></td>';
                        html += '<td><select class="form-select form-select-sm" aria-label="' + escHtml(t('dns.rotationMode')) + ' ' + escapeHtmlCf(d.domain) + '" data-on-change="cfAssignDomain(' + d.id + ', this.value)">';
                        const cur = d.cloudflare_account_id || 0;
                        html += '<option value="0"' + (cur === 0 ? ' selected' : '') + '>' + escHtml(t('dns.manualMode')) + '</option>';
                        cfAccounts.forEach(a => {
                            const lbl = a.label + (a.email ? ' — ' + a.email : '');
                            html += '<option value="' + a.id + '"' + (cur === a.id ? ' selected' : '') + '>Cloudflare: ' + escapeHtmlCf(lbl) + '</option>';
                        });
                        html += '</select></td>';
                        html += '</tr>';
                    });
                    html += '</tbody></table></div>';
                    assign.innerHTML = html;
                }

                // Aggiorna eventuale stato visibile della rotazione (se l'utente ha già selezionato un dominio)
                if (currentDomainId) loadDkimRotationStatus(currentDomainId);
            }).catch(e => {
                console.error('cf', e);
                badge.innerHTML = '<span class="badge bg-danger">' + escHtml(t('common.errorShort')) + '</span>';
                list.innerHTML = '<div class="alert alert-danger py-2 mb-0"><i class="fas fa-exclamation-triangle me-1" aria-hidden="true"></i>' + escHtml(t('dns.cfReadError', { message: e.message })) + '</div>';
                assign.innerHTML = '';
            });
        }
        refreshCloudflare();

        function cfTestNewToken() {
            const tok = document.getElementById('cfNewToken').value.trim();
            if (!tok) { panelSay('warning', t('dns.cfPasteFirst')); return; }
            fetch('/api/cloudflare', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'test', token: tok })
            }).then(r => r.json()).then(data => {
                panelSay('danger', (data.success ? '✓ ' : '✗ ') + (data.message || data.error || ''));
            }).catch(e => panelSay('danger', t('common.networkError', { message: e.message })));
        }

        function cfAddAccount() {
            const label = document.getElementById('cfNewLabel').value.trim();
            const email = document.getElementById('cfNewEmail').value.trim();
            const token = document.getElementById('cfNewToken').value.trim();
            if (!label) { panelSay('info', t('dns.cfLabelRequired')); return; }
            if (!token) { panelSay('info', t('dns.cfTokenRequired')); return; }
            fetch('/api/cloudflare', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'add', label: label, email: email, token: token })
            }).then(r => r.json()).then(data => {
                panelSay('danger', (data.success ? '✓ ' : '✗ ') + (data.message || data.error || ''));
                if (data.success) {
                    document.getElementById('cfNewLabel').value = '';
                    document.getElementById('cfNewEmail').value = '';
                    document.getElementById('cfNewToken').value = '';
                    refreshCloudflare();
                }
            }).catch(e => panelSay('danger', t('common.networkError', { message: e.message })));
        }

        function cfEditOpen(id) {
            // Chiudi eventuali altre righe di edit aperte
            cfAccounts.forEach(a => {
                if (a.id !== id) cfEditClose(a.id);
            });
            const view = document.getElementById('cfRowView-' + id);
            const edit = document.getElementById('cfRowEdit-' + id);
            if (view) view.classList.add('d-none');
            if (edit) edit.classList.remove('d-none');
        }

        function cfEditClose(id) {
            const view = document.getElementById('cfRowView-' + id);
            const edit = document.getElementById('cfRowEdit-' + id);
            if (view) view.classList.remove('d-none');
            if (edit) edit.classList.add('d-none');
            // Pulisci il campo token così non resta in memoria nel DOM
            const tok = document.getElementById('cfEditToken-' + id);
            if (tok) tok.value = '';
        }

        function cfEditSave(id) {
            const label = document.getElementById('cfEditLabel-' + id).value.trim();
            const email = document.getElementById('cfEditEmail-' + id).value.trim();
            const token = document.getElementById('cfEditToken-' + id).value.trim();
            if (!label) { panelSay('info', t('dns.cfLabelRequired')); return; }
            const payload = { action: 'update', account_id: id, label: label, email: email };
            // Includi il token SOLO se l'utente l'ha effettivamente compilato
            if (token) payload.token = token;
            fetch('/api/cloudflare', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            }).then(r => r.json()).then(data => {
                panelSay('danger', (data.success ? '✓ ' : '✗ ') + (data.message || data.error || ''));
                if (data.success) {
                    cfEditClose(id);
                    refreshCloudflare();
                }
            }).catch(e => panelSay('danger', t('common.networkError', { message: e.message })));
        }

        async function cfDeleteAccount(id, label) {
            if (!await panelConfirmDanger(t('dns.cfConfirmDelete', { label: label }))) return;
            fetch('/api/cloudflare', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'delete', account_id: id })
            }).then(r => r.json()).then(data => {
                panelSay('danger', (data.success ? '✓ ' : '✗ ') + (data.message || data.error || ''));
                if (data.success) refreshCloudflare();
            }).catch(e => panelSay('danger', t('common.networkError', { message: e.message })));
        }

        function cfAssignDomain(domainId, accountId) {
            fetch('/api/cloudflare', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'assign', domain_id: domainId, account_id: parseInt(accountId) })
            }).then(r => r.json()).then(data => {
                if (!data.success) panelSay('danger', '✗ ' + (data.message || data.error || ''));
                refreshCloudflare();
            }).catch(e => panelSay('danger', t('common.networkError', { message: e.message })));
        }

        function loadDnsRecords() {
            const domain = document.getElementById('domainSelect').value;
            if (!domain) { panelSay('warning', t('dns.chooseDomainFirst')); return; }

            currentDomainId = document.getElementById('domainSelect').selectedOptions[0].dataset.id;
            document.getElementById('generateDkimBtn').disabled = false;

            fetch('/api/dns?domain=' + encodeURIComponent(domain)).then(r => r.json()).then(data => {
                if (!data.success) { panelSay('danger', t('common.error', { message: data.error })); return; }

                // Extract mail hostname parent domain
                const mailHostname = data.mail_hostname;
                const mailHostnameParts = mailHostname.split('.');
                const mailServerParentDomain = mailHostnameParts.slice(1).join('.');

                let html = '<div class="alert alert-info mb-4">';
                html += '<h5><i class="fas fa-info-circle me-2" aria-hidden="true"></i>' + escHtml(t('dns.zonesSummary')) + '</h5>';
                // Le due zone sono diverse solo quando l'hostname di posta sta in un altro
                // dominio. Quando coincidono — il caso normale — annunciare "2 zone DNS
                // diverse" ed elencare due volte lo stesso nome manda a cercare una zona che
                // non esiste.
                const dueZone = mailServerParentDomain !== domain;
                html += dueZone
                    ? '<p class="mb-2">' + escHtml(t('dns.twoZones')) + '</p>'
                      + '<ul class="mb-0">'
                      + '<li><strong>' + escHtml(mailServerParentDomain) + '</strong> → ' + escHtml(t('dns.zoneForA')) + '</li>'
                      + '<li><strong>' + escHtml(domain) + '</strong> → ' + escHtml(t('dns.zoneForMail')) + '</li>'
                      + '</ul>'
                    : '<p class="mb-0">' + escHtml(t('dns.oneZone', { zone: domain })) + '</p>';
                html += '</div>';

                html += '<div class="mb-3"><strong>' + escHtml(t('dns.serverIp')) + '</strong> <code>' + escHtml(data.server_ip) + '</code> | <strong>' + escHtml(t('dns.mailHostname')) + '</strong> <code>' + escHtml(data.mail_hostname) + '</code></div>';

                // Group records by zone
                let currentZone = '';
                data.records.forEach(r => {
                    // Add zone header if changed
                    if (r.dnsZone && r.dnsZone !== currentZone) {
                        currentZone = r.dnsZone;
                        html += '<div class="mt-4 mb-3 p-2 bg-primary text-white rounded"><strong><i class="fas fa-globe me-2" aria-hidden="true"></i>' + escHtml(t('dns.zone', { zone: currentZone })) + '</strong></div>';
                    }

                    const reqClass = r.required ? 'required' : 'optional';
                    const badge = r.required ? '<span class="badge bg-danger">' + escHtml(t('dns.required')) + '</span>' : '<span class="badge bg-secondary">' + escHtml(t('dns.optionalBadge')) + '</span>';
                    // ID univoco basato su name+type per il matching con la verifica
                    const recordKey = (r.name + '|' + r.type).replace(/[^a-zA-Z0-9_|.\-]/g, '_');
                    html += '<div class="dns-record ' + reqClass + '" data-record-key="' + recordKey + '" data-record-name="' + escHtml(r.name) + '" data-record-type="' + escHtml(r.type) + '" data-check-type="' + escHtml(r.checkType || '') + '" data-record-zone="' + escHtml(r.dnsZone || '') + '">';
                    html += '<div class="d-flex justify-content-between align-items-start">';
                    html += '<div><span class="record-type">' + escHtml(r.type) + '</span> ' + badge;
                    // Status badge — placeholder finché non parte la verifica automatica
                    html += ' <span class="record-status-badge" data-status-key="' + recordKey + '"><span class="badge bg-light text-dark border"><i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('dns.checkingRecord')) + '</span></span>';
                    if (r.dnsZone) {
                        html += ' <small class="text-muted">' + escHtml(t('dns.onZone', { zone: r.dnsZone })) + '</small>';
                    }
                    html += '</div>';
                    html += '<button type="button" class="btn btn-link p-0 copy-btn" data-on-click="copyToClipboard(this.parentElement.parentElement)" title="' + escHtml(t('common.copy')) + '" aria-label="' + escHtml(t('common.copy')) + '"><i class="fas fa-copy" aria-hidden="true"></i></button>';
                    html += '</div>';
                    html += '<div class="mt-2"><strong>' + escHtml(t('dns.recName')) + '</strong> <code class="record-name">' + escHtml(r.name) + '</code></div>';
                    // Si mostra il valore COMPLETO quando esiste: per MX e SRV "value" contiene
                    // la sola destinazione, e sotto un'etichetta che dice "consigliato" quello
                    // sarebbe un record da copiare a cui mancano dei campi.
                    html += '<div class="mt-1"><strong>' + escHtml(t('dns.recValue')) + '</strong> <code class="record-value" data-style="word-break:break-all">' + escHtml(r.fullValue || r.value) + '</code></div>';
                    html += '<small class="text-muted">' + r.description + '</small>';
                    // Area dettagli verifica (popolata dopo verifyDnsAuto)
                    html += '<div class="record-verify-detail mt-2" data-detail-key="' + recordKey + '"></div>';
                    if (r.explanation) {
                        html += '<details class="mt-2"><summary><i class="fas fa-cog me-1" aria-hidden="true"></i>' + escHtml(t('dns.cfInstructions')) + '</summary><div class="mt-2 p-3 bg-white border rounded" data-style="font-size:0.9rem">' + r.explanation + '</div></details>';
                    }
                    html += '</div>';
                });

                document.getElementById('dnsRecordsContainer').innerHTML = html;

                // Load DKIM status (parallelo alla verifica DNS)
                loadDkimStatus(currentDomainId);
                // Verifica automatica e silenziosa di tutti i record DNS
                verifyDnsAuto();
            });
        }

        /**
         * Verifica DNS in background: per ogni record, mostra un badge inline
         * "Configurato ✓" / "Da configurare ⚠" / "Verifica web" etc., così l'utente
         * sa al volo cosa serve fare senza dover scendere al pannello "Verifica" in fondo.
         */
        /**
         * Calcola l'FQDN di un record dato il suo nome relativo (può essere "@", una
         * sottoparte, o già un FQDN) e la zona DNS di appartenenza.
         * Necessario perché i record generati usano nomi relativi ("@", "mail._domainkey"),
         * mentre i check del verifier usano FQDN ("domain-a.test", "mail._domainkey.domain-a.test").
         */
        function recordFqdn(name, zone) {
            if (!name || name === '@' || name === '') return zone || '';
            // Se è già FQDN (contiene la zona alla fine) lasciamo invariato
            if (zone && name.toLowerCase().endsWith('.' + zone.toLowerCase())) return name;
            if (zone && name.toLowerCase() === zone.toLowerCase()) return name;
            // Altrimenti concatena con la zona
            return zone ? (name + '.' + zone) : name;
        }

        function verifyDnsAuto() {
            const domain = document.getElementById('domainSelect').value;
            if (!domain) return;
            fetch('/api/dns', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'verify', domain: domain })
            }).then(r => r.json()).then(data => {
                if (!data.success) {
                    document.querySelectorAll('.record-status-badge').forEach(el => {
                        el.innerHTML = '<span class="badge bg-secondary"><i class="fas fa-question-circle me-1" aria-hidden="true"></i>' + escHtml(t('dns.checkUnavailable')) + '</span>';
                    });
                    return;
                }
                // Mappa fqdn → check (i check del verifier usano sempre FQDN come name)
                const checkByFqdn = new Map();
                // E mappa TIPO → check, che e' quella giusta: all'apice del dominio MX e SPF
                // hanno lo STESSO nome, quindi appaiare per nome faceva sovrascrivere l'uno
                // con l'altro e la scheda MX mostrava il verdetto dell'SPF. Il tipo lo dichiara
                // il record stesso (checkType), cosi' l'accoppiamento e' un dato e non
                // un'ipotesi ricavata dal nome.
                const checkByKind = new Map();
                (data.checks || []).forEach(c => {
                    if (c.name) checkByFqdn.set(c.name.toLowerCase(), c);
                    if (c.type) checkByKind.set(c.type, c);
                });

                let okCount = 0, koCount = 0, unkCount = 0;
                document.querySelectorAll('.dns-record').forEach(card => {
                    const rname = card.getAttribute('data-record-name');
                    const rtype = card.getAttribute('data-record-type');
                    const rzone = card.getAttribute('data-record-zone') || '';
                    const key = card.getAttribute('data-record-key');
                    const badgeWrap = card.querySelector('[data-status-key="' + key + '"]');
                    const detailWrap = card.querySelector('[data-detail-key="' + key + '"]');
                    if (!badgeWrap) return;

                    // Prima per tipo dichiarato: e' l'unico appaiamento che non puo' confondere
                    // due record diversi con lo stesso nome.
                    const ctype = card.getAttribute('data-check-type') || '';
                    let check = ctype ? checkByKind.get(ctype) : null;
                    // Solo se il record non dichiara un tipo si ripiega sul nome, com'era prima.
                    if (!check) {
                        const fqdn = recordFqdn(rname, rzone).toLowerCase();
                        check = checkByFqdn.get(fqdn);
                        if (!check && rname) check = checkByFqdn.get(rname.toLowerCase());
                    }
                    if (!check) {
                        // Nessun check per questo record (es. SRV autodiscover, MTA-STS policy, alcuni TXT secondari)
                        badgeWrap.innerHTML = '<span class="badge bg-light text-dark border"><i class="fas fa-minus-circle me-1" aria-hidden="true"></i>' + escHtml(t('dns.notChecked')) + '</span>';
                        if (detailWrap) detailWrap.innerHTML = '';
                        unkCount++;
                        return;
                    }

                    if (check.passed) {
                        badgeWrap.innerHTML = '<span class="badge bg-success"><i class="fas fa-check-circle me-1" aria-hidden="true"></i>' + escHtml(t('dns.configuredOk')) + '</span>';
                        if (detailWrap) {
                            let ok = '<div class="alert alert-success py-1 px-2 mb-0 small mt-2"><i class="fas fa-check me-1" aria-hidden="true"></i><strong>' + escHtml(t('dns.noAction')) + '</strong> ' + (check.message ? escapeHtmlBl(check.message) : '');
                            // Il valore vero si mostra anche quando il record PASSA, non solo
                            // quando fallisce: senza, a schermo resta la sola proposta e sembra
                            // che sia quello pubblicato.
                            //
                            // E si mostra SENZA confrontarlo con la proposta. Il confronto che
                            // avevo scritto dichiarava "diverso" per un punto finale, per le
                            // virgolette di un TXT, o perche' per un SRV la proposta e' il solo
                            // host e il valore vero contiene anche priorita' e peso — e in piu'
                            // aggiungeva "e va bene cosi'", che e' un giudizio che questa riga
                            // non e' in grado di dare. Il giudizio lo da' gia' check.message.
                            const real = check.current_value;
                            if (real) {
                                const brief = real.length > 140 ? real.substring(0, 140) + '…' : real;
                                ok += '<div class="mt-1"><span class="text-muted">' + escHtml(t('dns.published')) + '</span> '
                                    + '<code class="small" data-style="word-break:break-all">' + escapeHtmlBl(brief) + '</code></div>';
                            }
                            detailWrap.innerHTML = ok + '</div>';
                        }
                        // Stile leggero: bordo verde
                        card.style.borderLeft = '4px solid #198754';
                        okCount++;
                    } else {
                        badgeWrap.innerHTML = '<span class="badge bg-warning text-dark"><i class="fas fa-exclamation-triangle me-1" aria-hidden="true"></i>' + escHtml(t('dns.toDo')) + '</span>';
                        if (detailWrap) {
                            let html = '<div class="alert alert-warning py-2 px-2 mb-0 small mt-2"><i class="fas fa-exclamation-triangle me-1" aria-hidden="true"></i><strong>' + escHtml(t('dns.actionNeeded')) + '</strong> ' + escapeHtmlBl(check.message || t('dns.missingOrWrong')) + '.';
                            if (check.current_value) {
                                const shortCur = check.current_value.length > 100 ? check.current_value.substring(0, 100) + '…' : check.current_value;
                                html += '<div class="mt-1"><span class="text-muted">' + escHtml(t('dns.found')) + '</span> <code class="small">' + escapeHtmlBl(shortCur) + '</code></div>';
                            }
                            html += '</div>';
                            detailWrap.innerHTML = html;
                        }
                        card.style.borderLeft = '4px solid #ffc107';
                        koCount++;
                    }
                });

                // Banner riassuntivo in cima al contenitore
                const container = document.getElementById('dnsRecordsContainer');
                if (container && (okCount + koCount + unkCount) > 0) {
                    const summary = document.createElement('div');
                    let cls, icon, msg;
                    if (koCount === 0 && okCount > 0) {
                        cls = 'alert-success'; icon = 'check-circle';
                        msg = escHtml(tn('dns.sumAllOk', okCount));
                    } else if (koCount > 0) {
                        cls = 'alert-warning'; icon = 'exclamation-triangle';
                        msg = '<strong>' + escHtml(tn('dns.sumToDo', koCount)) + '</strong> ' + escHtml(t('dns.sumToDoRest', { ok: okCount }));
                    } else {
                        cls = 'alert-info'; icon = 'info-circle';
                        msg = escHtml(tn('dns.sumUnchecked', unkCount));
                    }
                    summary.className = 'alert ' + cls + ' mb-3';
                    summary.innerHTML = '<i class="fas fa-' + icon + ' me-2" aria-hidden="true"></i>' + msg + ' <span class="ms-2 small text-muted">' + escHtml(t('dns.sumCounts', { ok: okCount, todo: koCount, unk: unkCount })) + '</span>';
                    // Inserisci prima del primo .dns-record (o all'inizio se non c'è)
                    const firstRecord = container.querySelector('.dns-record');
                    if (firstRecord) container.insertBefore(summary, firstRecord);
                    else container.insertBefore(summary, container.firstChild);
                }
            }).catch(e => {
                console.error('verifyDnsAuto error', e);
                document.querySelectorAll('.record-status-badge').forEach(el => {
                    el.innerHTML = '<span class="badge bg-secondary"><i class="fas fa-times me-1" aria-hidden="true"></i>' + escHtml(t('dns.checkFailed')) + '</span>';
                });
            });
        }

        function loadDkimStatus(domainId) {
            fetch('/api/dkim?id=' + domainId).then(r => r.json()).then(data => {
                const status = document.getElementById('dkimStatus');
                const rotateBtn = document.getElementById('rotateDkimBtn');
                const verifyBtn = document.getElementById('verifyActiveDkimBtn');
                const generateBtn = document.getElementById('generateDkimBtn');
                if (data.configured) {
                    status.innerHTML = '<div class="alert alert-secondary"><i class="fas fa-database me-2" aria-hidden="true"></i>'
                        + escHtml(t('dns.dkimInPanel')) + '<br>'
                        + escHtml(t('dns.dkimSelector')) + ' <code>' + escHtml(data.selector) + '</code><br>'
                        + escHtml(t('dns.dkimRecordName')) + ' <code>' + escHtml(data.dns_record_name) + '</code>'
                        + '<div class="small text-muted mt-1">' + escHtml(t('dns.dkimNotYetVerified')) + '</div></div>';
                    if (rotateBtn) rotateBtn.disabled = false;
                    if (verifyBtn) verifyBtn.disabled = false;
                    // DKIM già configurato: il bottone "Genera Chiavi DKIM" deve essere NASCOSTO/disabilitato
                    // perché sovrascriverebbe la chiave attiva senza il workflow di rotazione (no grace period).
                    // Per cambiare chiave su un dominio già configurato, USARE "Avvia rotazione chiave".
                    if (generateBtn) {
                        generateBtn.style.display = 'none';
                        generateBtn.disabled = true;
                    }
                } else {
                    status.innerHTML = '<div class="alert alert-warning"><i class="fas fa-exclamation-triangle me-2" aria-hidden="true"></i>' + escHtml(t('dns.dkimMissing')) + '<br><small class="text-muted">' + escHtml(t('dns.dkimMissingHint')) + '</small></div>';
                    if (rotateBtn) rotateBtn.disabled = true;
                    if (verifyBtn) verifyBtn.disabled = true;
                    // DKIM mai configurato: SOLO ora il "Genera Chiavi DKIM" ha senso (setup iniziale)
                    if (generateBtn) {
                        generateBtn.style.display = '';
                        generateBtn.disabled = false;
                    }
                    // Nascondi anche i box timeline se non c'è DKIM
                    const tl = document.getElementById('dkimRotationTimeline');
                    if (tl) tl.classList.add('d-none');
                }
                const vr = document.getElementById('dkimVerifyResult'); if (vr) vr.innerHTML = '';
                loadDkimRotationStatus(domainId);
                loadDkimHistory(domainId);
                loadDkimSchedule(domainId);
            });
        }

        // ===== Rotazione programmata =====
        let dkimSchedulePresets = [];

        // Parsing tollerante per timestamp del server.
        // Numero (epoch ms) → unambiguo, preferito quando disponibile.
        // ISO 8601 con Z o offset → parsato come UTC.
        // Fallback legacy "yyyy-MM-dd HH:mm:ss" senza TZ → assunto ora locale.
        function parseTs(s) {
            if (s == null || s === '') return null;
            // Numero o stringa numerica = epoch milliseconds
            if (typeof s === 'number') {
                const d = new Date(s);
                return isNaN(d.getTime()) ? null : d;
            }
            const v = String(s);
            if (/^\d{10,}$/.test(v)) {
                const d = new Date(parseInt(v));
                return isNaN(d.getTime()) ? null : d;
            }
            if (/T.*([Zz]|[+\-]\d{2}:?\d{2})$/.test(v)) {
                const d = new Date(v);
                return isNaN(d.getTime()) ? null : d;
            }
            const norm = v.replace(' ', 'T').replace(/\.\d+$/, '');
            const d = new Date(norm);
            return isNaN(d.getTime()) ? null : d;
        }

        // Wrapper: preferisce data._ms (epoch) se presente, altrimenti data[key].
        // Uso: pickTs(data, 'last_rotation_at') → cerca data.last_rotation_at_ms, poi data.last_rotation_at.
        function pickTs(obj, key) {
            if (!obj) return null;
            const ms = obj[key + '_ms'];
            if (ms != null && ms !== '') return parseTs(ms);
            return parseTs(obj[key]);
        }

        // Tempo relativo nella lingua della pagina: "3 ore fa", "tra 27 giorni", "3 hours ago"
        function formatRelativeTime(date) {
            if (!date) return '';
            const sec = Math.round((date.getTime() - Date.now()) / 1000);
            const abs = Math.abs(sec);
            const rtf = new Intl.RelativeTimeFormat(window.I18N_LANG, { numeric: 'auto' });
            if (abs < 60) return rtf.format(sec, 'second');
            if (abs < 3600) return rtf.format(Math.round(sec / 60), 'minute');
            if (abs < 86400) return rtf.format(Math.round(sec / 3600), 'hour');
            if (abs < 86400 * 30) return rtf.format(Math.round(sec / 86400), 'day');
            if (abs < 86400 * 365) return rtf.format(Math.round(sec / (86400 * 30)), 'month');
            return rtf.format(Math.round(sec / (86400 * 365)), 'year');
        }

        // Data e ora nella lingua della pagina, nel fuso di chi guarda: "15 mag 2026, 16:08"
        function formatPanelDate(date) {
            if (!date) return '';
            return date.toLocaleString(window.I18N_LANG, { day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' });
        }

        // Aggiorna i due box prominenti "Ultima/Prossima rotazione"
        // Lo scheduler vive dentro il server web del pannello. Dire "gira mentre il pannello
        // e' acceso" e' un avvertimento generico che scarica su chi legge il compito di andare
        // a controllare da un'altra parte; il pannello quel dato ce l'ha e puo' dirlo.
        function autoStartSentence(data) {
            if (data.auto_start === true)
                return escHtml(t('dns.autostartYes'));
            if (data.auto_start === false)
                return '<span class="text-warning">' + escHtml(t('dns.autostartNo')) + '</span>';
            // Il campo non e' arrivato: si dice quel che si sa, senza inventare un verdetto.
            return escHtml(t('dns.autostartUnknown'));
        }

        // Com'e' messa la prossima rotazione, decisa in un posto solo.
        //
        // Esiste perche' la stessa domanda veniva risposta due volte nella stessa scheda: il
        // riquadro in alto e la riga di riepilogo qui sotto. Corretto il primo, il secondo ha
        // continuato ad annunciare "prossima rotazione prevista" una data del 13 agosto mentre
        // una rotazione era gia' in corso. Due risposte alla stessa domanda divergono sempre:
        // quella che si guarda meno resta indietro.
        //
        // Ritorna: 'in_progress' | 'dovuta' | 'programmata' | 'disattivata' | 'mai'
        function nextRotationStatus(data) {
            if (data.rotation_state) return 'in_progress';
            if (!(data.interval_days > 0)) return 'disabled';
            const ts = pickTs(data, 'next_rotation_at');
            if (!ts) return 'never';
            return ts.getTime() <= Date.now() ? 'due' : 'scheduled';
        }

        function renderRotationTimeline(data, hasDkim) {
            const wrap = document.getElementById('dkimRotationTimeline');
            const lastEl = document.getElementById('dkimLastRotationText');
            const nextEl = document.getElementById('dkimNextRotationText');
            if (!hasDkim) {
                wrap.classList.add('d-none');
                return;
            }
            wrap.classList.remove('d-none');

            // DIAGNOSTICA: confronta clock server vs browser. Skew > 5 min = problema reale.
            if (data.server_now_ms) {
                const skewMs = data.server_now_ms - Date.now();
                if (Math.abs(skewMs) > 5 * 60 * 1000) {
                    const skewMin = Math.round(skewMs / 60000);
                    console.warn('[DKIM] Server clock skew: ' + skewMin + ' min (' + (skewMin > 0 ? 'ahead of' : 'behind') + ' the browser)');
                }
            }

            // Ultima rotazione: il "now" di riferimento è il SERVER (server_now_ms se disponibile),
            // non il browser. Questo evita che skew di clock tra server e browser facciano
            // sembrare la rotazione "nel futuro".
            const referenceNowMs = data.server_now_ms || Date.now();
            const lastTs = pickTs(data, 'last_rotation_at');
            if (lastTs) {
                const deltaMs = lastTs.getTime() - referenceNowMs;
                let relText;
                let showFixButtons = false;
                if (deltaMs > 0 && deltaMs < 60 * 1000) {
                    relText = escHtml(t('dns.justNow'));
                } else if (deltaMs > 0) {
                    const minAhead = Math.round(deltaMs / 60000);
                    relText = '<span class="text-warning" title="' + escHtml(t('dns.futureTsHint', { min: minAhead })) + '">' + escHtml(t('dns.futureTs', { min: minAhead })) + '</span>';
                    showFixButtons = true;
                } else {
                    const fakeDate = new Date(lastTs.getTime() - (Date.now() - referenceNowMs));
                    relText = formatRelativeTime(fakeDate);
                }
                let html = '<strong>' + formatPanelDate(lastTs) + '</strong>' +
                    '<div class="small text-muted">' + relText + '</div>';
                if (showFixButtons) {
                    html += '<div class="mt-2 d-flex gap-1 flex-wrap">';
                    html += '<button class="btn btn-sm btn-outline-warning" data-on-click="resetLastRotationTimestamp()" title="' + escHtml(t('dns.resetNowHint')) + '"><i class="fas fa-sync-alt me-1" aria-hidden="true"></i>' + escHtml(t('dns.resetNow')) + '</button>';
                    html += '<button class="btn btn-sm btn-outline-secondary" data-on-click="clearLastRotationTimestamp()" title="' + escHtml(t('dns.clearTsHint')) + '"><i class="fas fa-eraser me-1" aria-hidden="true"></i>' + escHtml(t('dns.clearTs')) + '</button>';
                    html += '</div>';
                }
                lastEl.innerHTML = html;
            } else {
                lastEl.innerHTML = '<span class="text-warning"><i class="fas fa-exclamation-triangle me-1" aria-hidden="true"></i>' + escHtml(t('dns.never')) + '</span>' +
                    '<div class="small text-muted">' + escHtml(t('dns.noRotation')) + '</div>';
            }

            // Prossima rotazione (calcolata se schedule attivo)
            const nextTs = pickTs(data, 'next_rotation_at');
            const interval = data.interval_days || 0;
            // Una rotazione GIA' in corso ha la precedenza su qualunque data calcolata: dire
            // "dovuta, parte al prossimo controllo" mentre la chiave nuova e' gia' pubblicata
            // e' promettere al futuro una cosa gia' accaduta — ed e' esattamente cio' che
            // questo riquadro faceva. La data prossima tornera' ad avere senso a rotazione
            // conclusa, quando "ultima rotazione" sara' quella nuova.
            const when = nextRotationStatus(data);
            if (when === 'in_progress') {
                const steps = {
                    'pending_dns': t('dns.stepPendingDns'),
                    'propagated': t('dns.stepPropagated'),
                    'active_grace': t('dns.stepActiveGrace')
                };
                nextEl.innerHTML = '<strong>' + escHtml(t('dns.rotationInProgress')) + '</strong> '
                    + '<span class="badge bg-info text-dark ms-1">' + escapeHtmlBl(data.rotation_state) + '</span>'
                    + '<div class="small text-muted">'
                    + escHtml(steps[data.rotation_state] || t('dns.inProgress'))
                    + (data.rotation_pending_selector
                        ? ' &mdash; ' + escHtml(t('dns.newSelector')) + ' <code>' + escapeHtmlBl(data.rotation_pending_selector) + '</code>' : '')
                    + '. ' + escHtml(t('dns.stepsBelow')) + '</div>';
            } else if (when === 'disabled') {
                nextEl.innerHTML = '<span class="text-muted"><i class="fas fa-pause-circle me-1" aria-hidden="true"></i>' + escHtml(t('dns.notScheduled')) + '</span>' +
                    '<div class="small text-muted">' + escHtml(t('dns.autoOff')) + '</div>';
            } else if (nextTs) {
                if (when === 'due') {
                    // Una data passata sotto l'etichetta "Prossima rotazione", con un bollino
                    // rosso e nient'altro, si legge come "il pannello sa di essere in ritardo e
                    // non fa niente". Non e' cosi': lo scheduler confronta (adesso - ultima)
                    // con l'intervallo, quindi una scadenza passata e' gia' "dovuta" e parte al
                    // primo controllo. Quello che mancava non era il meccanismo, era dirlo.
                    nextEl.innerHTML = '<strong>' + escHtml(t('dns.due')) + '</strong> '
                        + '<span class="badge bg-warning text-dark ms-1">' + escHtml(t('dns.nextCheck')) + '</span>'
                        + '<div class="small text-muted">' + escHtml(t('dns.dueWas', { date: formatPanelDate(nextTs), rel: formatRelativeTime(nextTs), days: interval })) + ' '
                        + escHtml(t('dns.dueHow')) + ' ' + autoStartSentence(data) + '</div>';
                } else {
                    nextEl.innerHTML = '<strong>' + formatPanelDate(nextTs) + '</strong>' +
                        '<div class="small text-muted">' + escHtml(t('dns.relEvery', { rel: formatRelativeTime(nextTs), days: interval })) + '</div>';
                }
            } else {
                nextEl.innerHTML = '<strong>' + escHtml(t('dns.atNextCheck')) + '</strong> <span class="badge bg-warning text-dark ms-1">' + escHtml(t('dns.soon')) + '</span>' +
                    '<div class="small text-muted">' + escHtml(t('dns.scheduleNoRotation', { days: interval })) + '</div>';
            }
        }

        function loadDkimSchedule(domainId) {
            const panel = document.getElementById('dkimSchedulePanel');
            const info = document.getElementById('dkimScheduleInfo');
            panel.classList.remove('d-none');
            info.innerHTML = '<i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('common.loading'));
            fetch('/api/dkim', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'schedule_get', domain_id: parseInt(domainId) })
            }).then(r => r.json()).then(data => {
                if (!data.success) {
                    info.innerHTML = '<span class="text-danger">' + escapeHtmlBl(data.error || t('common.errorShort')) + '</span>';
                    return;
                }
                // Aggiorna i due box prominenti
                renderRotationTimeline(data, true);
                dkimSchedulePresets = data.presets || [];
                const cur = data.interval_days || 0;
                // Popola la dropdown con i preset + l'opzione "Custom"
                const sel = document.getElementById('dkimSchedulePreset');
                let optionsHtml = '';
                let matched = false;
                dkimSchedulePresets.forEach(p => {
                    const isSel = (p.days === cur);
                    if (isSel) matched = true;
                    optionsHtml += '<option value="' + escHtml(p.days) + '"' + (isSel ? ' selected' : '') + '>' + escapeHtmlBl(p.label) + (p.days > 0 ? ' ' + escHtml(tn('dns.daysParen', p.days)) : '') + '</option>';
                });
                // Custom: se cur > 0 ma non corrisponde a nessun preset, selezioniamo custom
                optionsHtml += '<option value="custom"' + (!matched && cur > 0 ? ' selected' : '') + '>' + escHtml(t('dns.customOption')) + '</option>';
                sel.innerHTML = optionsHtml;
                // Mostra/nascondi campo custom
                if (!matched && cur > 0) {
                    document.getElementById('dkimScheduleCustomWrap').style.display = '';
                    document.getElementById('dkimScheduleCustomDays').value = cur;
                } else {
                    document.getElementById('dkimScheduleCustomWrap').style.display = 'none';
                    document.getElementById('dkimScheduleCustomDays').value = '';
                }
                // Riepilogo testuale
                let html = '';
                if (cur === 0) {
                    html = '<span class="text-muted"><i class="fas fa-info-circle me-1" aria-hidden="true"></i>' + escHtml(t('dns.autoOffLong')) + '</span>';
                } else {
                    html = '<i class="fas fa-clock text-primary me-1" aria-hidden="true"></i>' + escHtml(tn('dns.autoEvery', cur)) + ' ';
                    // Le date qui si formattano come nei due riquadri sopra.
                    //
                    // Prima questa riga stampava il timestamp grezzo in UTC mentre i riquadri
                    // mostravano l'ora locale: lo STESSO istante appariva come "14 ago 2026
                    // 00:13" sopra e "2026-08-13T22:13:41Z" sotto. Non e' un errore di calcolo,
                    // ma chi legge vede due date diverse a due righe di distanza e comincia a
                    // non fidarsi — e ha ragione a non fidarsi, perche' non ha modo di sapere
                    // che una delle due e' UTC.
                    const lastHere = pickTs(data, 'last_rotation_at');
                    const nextHere = pickTs(data, 'next_rotation_at');
                    if (lastHere) {
                        html += escHtml(t('dns.lastWas', { date: formatPanelDate(lastHere) })) + ' ';
                    } else if (data.last_rotation_at) {
                        html += escHtml(t('dns.lastWas', { date: data.last_rotation_at })) + ' ';
                    } else {
                        html += '<span class="text-warning">' + escHtml(t('dns.noRotationYet')) + '</span> ';
                    }
                    // Stessa domanda, stessa risposta del riquadro qui sopra.
                    const whenHere = nextRotationStatus(data);
                    if (whenHere === 'in_progress') {
                        html += escHtml(t('dns.alreadyRunning'))
                             + (data.rotation_pending_selector
                                 ? ' (' + escHtml(t('dns.newSelector')) + ' <code>' + escapeHtmlBl(data.rotation_pending_selector) + '</code>)' : '')
                             + ': ' + escHtml(t('dns.nextAfter'));
                    } else if (whenHere === 'due') {
                        html += escHtml(t('dns.dueAt', { date: nextHere ? formatPanelDate(nextHere) : data.next_rotation_at }));
                    } else if (data.next_rotation_at) {
                        html += escHtml(t('dns.nextAt', { date: nextHere ? formatPanelDate(nextHere) : data.next_rotation_at }));
                    }
                    // Il flag arriva con la risposta; la globale resta solo come ripiego per
                    // non cambiare comportamento se il campo mancasse.
                    const cfHere = (data.cloudflare_configured !== undefined)
                        ? !!data.cloudflare_configured : cloudflareConfigured;
                    if (!cfHere) {
                        html += '<br><span class="text-warning"><i class="fas fa-exclamation-triangle me-1" aria-hidden="true"></i>' + escHtml(t('dns.needCf')) + '</span>';
                    } else {
                        html += '<br><small class="text-muted">' + escHtml(t('dns.schedulerPlan', { hours: data.auto_activate_after_hours || 24, days: data.grace_period_days || 7 })) + '</small>';
                    }
                }
                info.innerHTML = html;
            }).catch(e => {
                info.innerHTML = '<span class="text-danger">' + escHtml(t('common.networkError', { message: e.message })) + '</span>';
            });
        }

        function onSchedulePresetChange() {
            const sel = document.getElementById('dkimSchedulePreset');
            const wrap = document.getElementById('dkimScheduleCustomWrap');
            if (sel.value === 'custom') {
                wrap.style.display = '';
            } else {
                wrap.style.display = 'none';
            }
        }

        async function resetLastRotationTimestamp() {
            if (!currentDomainId) return;
            if (!await panelConfirmDanger(t('dns.confirmResetNow'))) return;
            fetch('/api/dkim', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'last_rotation_reset', domain_id: parseInt(currentDomainId) })
            }).then(r => r.json()).then(data => {
                panelSay('danger', (data.success ? '✓ ' : '✗ ') + (data.message || data.error || ''));
                if (data.success) loadDkimSchedule(currentDomainId);
            }).catch(e => panelSay('danger', t('common.networkError', { message: e.message })));
        }

        async function clearLastRotationTimestamp() {
            if (!currentDomainId) return;
            if (!await panelConfirmDanger(t('dns.confirmClearTs'))) return;
            fetch('/api/dkim', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'last_rotation_clear', domain_id: parseInt(currentDomainId) })
            }).then(r => r.json()).then(data => {
                panelSay('danger', (data.success ? '✓ ' : '✗ ') + (data.message || data.error || ''));
                if (data.success) loadDkimSchedule(currentDomainId);
            }).catch(e => panelSay('danger', t('common.networkError', { message: e.message })));
        }

        function saveDkimSchedule() {
            if (!currentDomainId) { panelSay('warning', t('dns.chooseDomainFirst')); return; }
            const sel = document.getElementById('dkimSchedulePreset');
            let days;
            if (sel.value === 'custom') {
                const v = parseInt(document.getElementById('dkimScheduleCustomDays').value);
                if (isNaN(v) || v < 1 || v > 3650) {
                    panelSay('warning', t('dns.daysRange'));
                    return;
                }
                days = v;
            } else {
                days = parseInt(sel.value);
            }
            fetch('/api/dkim', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'schedule_set', domain_id: parseInt(currentDomainId), interval_days: days })
            }).then(r => r.json()).then(data => {
                panelSay('danger', (data.success ? '✓ ' : '✗ ') + (data.message || data.error || ''));
                if (data.success) {
                    loadDkimSchedule(currentDomainId);
                    loadDkimHistory(currentDomainId);
                }
            }).catch(e => panelSay('danger', t('common.networkError', { message: e.message })));
        }


        // ---------- DKIM: come stanno tutti i domini ----------
        // Esiste perche' la scheda per singolo dominio non risponde alla domanda "come
        // stanno messi tutti?": per saperlo si dovevano selezionare i domini uno per uno e
        // tenere a mente i numeri. Le cose che contano — un dominio senza chiave, uno fermo
        // da mesi mentre gli altri ruotano — si vedono solo mettendoli in fila.
        async function dkSummary() {
            const el = document.getElementById('dkSummaryBody');
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('dns.sumAsking'));
            let r;
            try {
                const resp = await fetch('/api/dkim', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ action: 'domains_summary' })
                });
                r = await resp.json();
            } catch (e) {
                el.innerHTML = '<div class="alert alert-danger py-2 small mb-0">' + escHtml(t('dns.sumAskFailed', { message: String(e) })) + '</div>';
                return;
            }
            if (!r || !r.success) {
                el.innerHTML = '<div class="alert alert-danger py-2 small mb-0">'
                             + escapeHtmlBl((r && r.error) || t('dns.requestFailed')) + '</div>';
                return;
            }

            const lines = r.domains || [];
            // Il titolo dice la cosa peggiore per prima: un dominio senza chiave non deve
            // finire in fondo a un elenco che comincia con "tutto bene".
            let cls = 'success', textValue = t('dns.sumAllMatch');
            if (r.withoutKey > 0) {
                cls = 'danger';
                textValue = tn('dns.sumNoKey', r.withoutKey);
            } else if (lines.some(d => d.state === 'not_matching')) {
                cls = 'danger';
                textValue = t('dns.sumMismatch');
            } else if (r.unverifiable > 0) {
                cls = 'warning';
                textValue = tn('dns.sumUnverifiable', r.unverifiable);
            }
            let h = '<div class="alert alert-' + cls + ' py-2 small mb-2">' + escapeHtmlBl(textValue) + '</div>';

            h += '<div class="table-responsive"><table class="table table-sm align-middle mb-2"><thead><tr>'
               + '<th scope="col">' + escHtml(t('st.colDomain')) + '</th><th scope="col">' + escHtml(t('dns.colSelector')) + '</th><th scope="col">' + escHtml(t('dns.colVerifies')) + '</th>'
               + '<th scope="col">' + escHtml(t('dns.colKeyAge')) + '</th><th scope="col">' + escHtml(t('dns.colRotation')) + '</th></tr></thead><tbody>';
            lines.forEach(d => {
                let state;
                if (d.state === 'absent')
                    state = '<span class="badge bg-danger">' + escHtml(t('dns.noKey')) + '</span>';
                else if (d.state === 'ok')
                    state = '<span class="badge bg-success">' + escHtml(t('dns.yes')) + '</span>';
                else if (d.state === 'not_matching')
                    state = '<span class="badge bg-danger">' + escHtml(t('dns.otherKey')) + '</span>';
                else
                    // "Non ho potuto controllare" non e' "va bene", e non e' nemmeno "e' rotto".
                    state = '<span class="badge bg-secondary">' + escHtml(t('dns.unverifiable')) + '</span>';

                let ageText = '<span class="text-muted">&mdash;</span>';
                if (d.daysSinceLast !== undefined && d.daysSinceLast !== null) {
                    const g = d.daysSinceLast;
                    // Oltre l'intervallo scelto la chiave e' in ritardo; senza intervallo il
                    // riferimento e' 90 giorni, la cadenza che il pannello consiglia.
                    const limit = (d.intervalDays && d.intervalDays > 0) ? d.intervalDays : 90;
                    ageText = escHtml(tn('dns.days', g))
                        + (g > limit ? ' <span class="badge bg-warning text-dark">' + escHtml(t('dns.overLimit', { limit: limit })) + '</span>' : '');
                }

                let rot;
                if (d.state === 'absent') rot = '<span class="text-muted">&mdash;</span>';
                else if (d.intervalDays && d.intervalDays > 0)
                    rot = escHtml(tn('dns.every', d.intervalDays))
                        + (d.nextRotation ? '<div class="small text-muted">' + escHtml(t('dns.nextShort', { date: String(d.nextRotation).substring(0, 10) })) + '</div>' : '');
                else
                    rot = '<span class="badge bg-warning text-dark">' + escHtml(t('dns.off')) + '</span>';

                h += '<tr class="upd-cell"><td><code class="small">' + escapeHtmlBl(d.domain) + '</code></td>'
                   + '<td><code class="small">' + escapeHtmlBl(d.selector || '') + '</code>'
                   + (d.rotationInProgress ? '<div class="small text-muted">' + escHtml(t('dns.rotatingNow', { state: d.rotationInProgress })) + '</div>' : '')
                   + '</td>'
                   + '<td>' + state
                   + (d.state === 'ok' ? '' : '<div class="small text-muted">'
                        + escapeHtmlBl(d.note || d.messageText || '') + '</div>')
                   + '</td>'
                   + '<td>' + ageText + '</td><td>' + rot + '</td></tr>';
            });
            h += '</tbody></table></div>'
               + '<div class="small text-muted">' + escHtml(t('dns.sumHow')) + '</div>';
            el.innerHTML = h;
        }
