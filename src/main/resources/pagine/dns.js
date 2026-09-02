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
            badge.innerHTML = '<span class="badge bg-light text-dark"><i class="fas fa-spinner fa-spin me-1"></i>caricamento</span>';

            fetch('/api/cloudflare').then(r => {
                if (!r.ok) throw new Error('HTTP ' + r.status);
                return r.json();
            }).then(data => {
                cfAccounts = data.accounts || [];
                cfDomainsCf = data.domains || [];

                badge.innerHTML = cfAccounts.length === 0
                    ? '<span class="badge bg-secondary">0 account</span>'
                    : '<span class="badge bg-success">' + cfAccounts.length + ' account configurat' + (cfAccounts.length === 1 ? 'o' : 'i') + '</span>';

                // Lista account
                if (cfAccounts.length === 0) {
                    list.innerHTML = '<div class="alert alert-secondary py-2 mb-0 small"><i class="fas fa-info-circle me-1"></i>Nessun account configurato. Aggiungine uno qui sotto per abilitare la rotazione DKIM automatica.</div>';
                } else {
                    let html = '<div class="table-responsive"><table class="table table-sm align-middle mb-0">';
                    html += '<thead class="table-light"><tr><th>Etichetta</th><th>Email account</th><th>Token</th><th>Domini collegati</th><th class="text-end">Azioni</th></tr></thead><tbody>';
                    cfAccounts.forEach(a => {
                        const linkedDomains = cfDomainsCf.filter(d => d.cloudflare_account_id === a.id).map(d => d.domain);
                        const safeLabel = escapeHtmlCf(a.label).replace(/'/g, "\\'");
                        // Riga di visualizzazione
                        html += '<tr id="cfRowView-' + a.id + '">';
                        html += '<td><strong>' + escapeHtmlCf(a.label) + '</strong></td>';
                        html += '<td>' + (a.email ? escapeHtmlCf(a.email) : '<span class="text-muted">—</span>') + '</td>';
                        html += '<td><code>' + escapeHtmlCf(a.token_masked) + '</code></td>';
                        html += '<td>' + (linkedDomains.length === 0
                            ? '<span class="text-muted small">nessuno</span>'
                            : linkedDomains.map(d => '<span class="badge bg-info text-dark me-1">' + escapeHtmlCf(d) + '</span>').join('')) + '</td>';
                        html += '<td class="text-end text-nowrap">';
                        html += '<button class="btn btn-sm btn-outline-primary me-1" title="Modifica" onclick="cfEditOpen(' + a.id + ')"><i class="fas fa-pen"></i></button>';
                        html += '<button class="btn btn-sm btn-outline-danger" title="Rimuovi" onclick="cfDeleteAccount(' + a.id + ', \'' + safeLabel + '\')"><i class="fas fa-trash"></i></button>';
                        html += '</td>';
                        html += '</tr>';
                        // Riga di edit (nascosta finché non clicchi la matita)
                        html += '<tr id="cfRowEdit-' + a.id + '" class="d-none table-warning"><td colspan="5">';
                        html += '<div class="row g-2 align-items-end">';
                        html += '  <div class="col-md-3"><label class="form-label small mb-1">Etichetta</label><input type="text" class="form-control form-control-sm" id="cfEditLabel-' + a.id + '" value="' + escapeHtmlCf(a.label) + '"></div>';
                        html += '  <div class="col-md-3"><label class="form-label small mb-1">Email account</label><input type="email" class="form-control form-control-sm" id="cfEditEmail-' + a.id + '" value="' + escapeHtmlCf(a.email || '') + '" placeholder="opzionale"></div>';
                        html += '  <div class="col-md-4"><label class="form-label small mb-1">Nuovo token <small class="text-muted">(lascia vuoto per non cambiarlo)</small></label><input type="password" class="form-control form-control-sm" id="cfEditToken-' + a.id + '" placeholder="Incolla un nuovo token solo se vuoi sostituirlo" autocomplete="off"></div>';
                        html += '  <div class="col-md-2 text-end">';
                        html += '    <button class="btn btn-sm btn-primary me-1" onclick="cfEditSave(' + a.id + ')"><i class="fas fa-save"></i> Salva</button>';
                        html += '    <button class="btn btn-sm btn-secondary" onclick="cfEditClose(' + a.id + ')"><i class="fas fa-times"></i></button>';
                        html += '  </div>';
                        html += '</div>';
                        html += '</td></tr>';
                    });
                    html += '</tbody></table></div>';
                    list.innerHTML = html;
                }

                // Tabella assegnazione domini -> account
                if (cfDomainsCf.length === 0) {
                    assign.innerHTML = '<div class="text-muted small">Aggiungi prima un dominio nella sezione Domini per gestirne l\'assegnazione qui.</div>';
                } else {
                    let html = '<div class="table-responsive"><table class="table table-sm align-middle mb-0">';
                    html += '<thead class="table-light"><tr><th>Dominio</th><th>Modalità rotazione DKIM</th></tr></thead><tbody>';
                    cfDomainsCf.forEach(d => {
                        html += '<tr>';
                        html += '<td><code>' + escapeHtmlCf(d.domain) + '</code></td>';
                        html += '<td><select class="form-select form-select-sm" onchange="cfAssignDomain(' + d.id + ', this.value)">';
                        const cur = d.cloudflare_account_id || 0;
                        html += '<option value="0"' + (cur === 0 ? ' selected' : '') + '>Manuale (devo aggiungere il record TXT a mano)</option>';
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
                badge.innerHTML = '<span class="badge bg-danger">Errore</span>';
                list.innerHTML = '<div class="alert alert-danger py-2 mb-0"><i class="fas fa-exclamation-triangle me-1"></i>Impossibile leggere gli account (' + e.message + '). Ricarica la pagina.</div>';
                assign.innerHTML = '';
            });
        }
        refreshCloudflare();

        function cfTestNewToken() {
            const tok = document.getElementById('cfNewToken').value.trim();
            if (!tok) { alert('Incolla prima il token'); return; }
            fetch('/api/cloudflare', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'test', token: tok })
            }).then(r => r.json()).then(data => {
                alert((data.success ? '✓ ' : '✗ ') + (data.message || data.error || ''));
            }).catch(e => alert('Errore rete: ' + e.message));
        }

        function cfAddAccount() {
            const label = document.getElementById('cfNewLabel').value.trim();
            const email = document.getElementById('cfNewEmail').value.trim();
            const token = document.getElementById('cfNewToken').value.trim();
            if (!label) { alert('Etichetta obbligatoria'); return; }
            if (!token) { alert('Token obbligatorio'); return; }
            fetch('/api/cloudflare', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'add', label: label, email: email, token: token })
            }).then(r => r.json()).then(data => {
                alert((data.success ? '✓ ' : '✗ ') + (data.message || data.error || ''));
                if (data.success) {
                    document.getElementById('cfNewLabel').value = '';
                    document.getElementById('cfNewEmail').value = '';
                    document.getElementById('cfNewToken').value = '';
                    refreshCloudflare();
                }
            }).catch(e => alert('Errore rete: ' + e.message));
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
            if (!label) { alert('Etichetta obbligatoria'); return; }
            const payload = { action: 'update', account_id: id, label: label, email: email };
            // Includi il token SOLO se l'utente l'ha effettivamente compilato
            if (token) payload.token = token;
            fetch('/api/cloudflare', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            }).then(r => r.json()).then(data => {
                alert((data.success ? '✓ ' : '✗ ') + (data.message || data.error || ''));
                if (data.success) {
                    cfEditClose(id);
                    refreshCloudflare();
                }
            }).catch(e => alert('Errore rete: ' + e.message));
        }

        function cfDeleteAccount(id, label) {
            if (!confirm('Rimuovere l\'account "' + label + '"?\n\nI domini collegati torneranno in modalità manuale.')) return;
            fetch('/api/cloudflare', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'delete', account_id: id })
            }).then(r => r.json()).then(data => {
                alert((data.success ? '✓ ' : '✗ ') + (data.message || data.error || ''));
                if (data.success) refreshCloudflare();
            }).catch(e => alert('Errore rete: ' + e.message));
        }

        function cfAssignDomain(domainId, accountId) {
            fetch('/api/cloudflare', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'assign', domain_id: domainId, account_id: parseInt(accountId) })
            }).then(r => r.json()).then(data => {
                if (!data.success) alert('✗ ' + (data.message || data.error || ''));
                refreshCloudflare();
            }).catch(e => alert('Errore rete: ' + e.message));
        }

        function loadDnsRecords() {
            const domain = document.getElementById('domainSelect').value;
            if (!domain) { alert('Seleziona un dominio'); return; }

            currentDomainId = document.getElementById('domainSelect').selectedOptions[0].dataset.id;
            document.getElementById('generateDkimBtn').disabled = false;

            fetch('/api/dns?domain=' + domain).then(r => r.json()).then(data => {
                if (!data.success) { alert('Errore: ' + data.error); return; }

                // Extract mail hostname parent domain
                const mailHostname = data.mail_hostname;
                const mailHostnameParts = mailHostname.split('.');
                const mailServerParentDomain = mailHostnameParts.slice(1).join('.');

                let html = '<div class="alert alert-info mb-4">';
                html += '<h5><i class="fas fa-info-circle me-2"></i>Riepilogo Zone DNS</h5>';
                // Le due zone sono diverse solo quando l'hostname di posta sta in un altro
                // dominio. Quando coincidono — il caso normale — annunciare "2 zone DNS
                // diverse" ed elencare due volte lo stesso nome manda a cercare una zona che
                // non esiste.
                const dueZone = mailServerParentDomain !== domain;
                html += dueZone
                    ? '<p class="mb-2">Dovrai configurare record in <strong>2 zone DNS diverse</strong>:</p>'
                      + '<ul class="mb-0">'
                      + '<li><strong>' + mailServerParentDomain + '</strong> → per il record A del server mail</li>'
                      + '<li><strong>' + domain + '</strong> → per MX, SPF, DKIM, DMARC e altri record</li>'
                      + '</ul>'
                    : '<p class="mb-0">Tutti i record stanno in <strong>una sola zona DNS</strong>: '
                      + '<strong>' + domain + '</strong> — sia il record A del server di posta sia MX, '
                      + 'SPF, DKIM, DMARC e gli altri.</p>';
                html += '</div>';

                html += '<div class="mb-3"><strong>Server IP:</strong> <code>' + data.server_ip + '</code> | <strong>Mail Hostname:</strong> <code>' + data.mail_hostname + '</code></div>';

                // Group records by zone
                let currentZone = '';
                data.records.forEach(r => {
                    // Add zone header if changed
                    if (r.dnsZone && r.dnsZone !== currentZone) {
                        currentZone = r.dnsZone;
                        html += '<div class="mt-4 mb-3 p-2 bg-primary text-white rounded"><strong><i class="fas fa-globe me-2"></i>Zona DNS: ' + currentZone + '</strong></div>';
                    }

                    const reqClass = r.required ? 'required' : 'optional';
                    const badge = r.required ? '<span class="badge bg-danger">Richiesto</span>' : '<span class="badge bg-secondary">Opzionale</span>';
                    // ID univoco basato su name+type per il matching con la verifica
                    const recordKey = (r.name + '|' + r.type).replace(/[^a-zA-Z0-9_|.\-]/g, '_');
                    html += '<div class="dns-record ' + reqClass + '" data-record-key="' + recordKey + '" data-record-name="' + r.name + '" data-record-type="' + r.type + '" data-check-type="' + (r.checkType || '') + '" data-record-zone="' + (r.dnsZone || '') + '">';
                    html += '<div class="d-flex justify-content-between align-items-start">';
                    html += '<div><span class="record-type">' + r.type + '</span> ' + badge;
                    // Status badge — placeholder finché non parte la verifica automatica
                    html += ' <span class="record-status-badge" data-status-key="' + recordKey + '"><span class="badge bg-light text-dark border"><i class="fas fa-spinner fa-spin me-1"></i>Verifica in corso...</span></span>';
                    if (r.dnsZone) {
                        html += ' <small class="text-muted">su ' + r.dnsZone + '</small>';
                    }
                    html += '</div>';
                    html += '<i class="fas fa-copy copy-btn" onclick="copyToClipboard(this.parentElement.parentElement)" title="Copia"></i>';
                    html += '</div>';
                    html += '<div class="mt-2"><strong>Nome:</strong> <code>' + r.name + '</code></div>';
                    // Si mostra il valore COMPLETO quando esiste: per MX e SRV "value" contiene
                    // la sola destinazione, e sotto un'etichetta che dice "consigliato" quello
                    // sarebbe un record da copiare a cui mancano dei campi.
                    html += '<div class="mt-1"><strong>Valore consigliato dal pannello:</strong> <code style="word-break:break-all">' + (r.valoreCompleto || r.value) + '</code></div>';
                    html += '<small class="text-muted">' + r.description + '</small>';
                    // Area dettagli verifica (popolata dopo verifyDnsAuto)
                    html += '<div class="record-verify-detail mt-2" data-detail-key="' + recordKey + '"></div>';
                    if (r.explanation) {
                        html += '<details class="mt-2"><summary><i class="fas fa-cog me-1"></i>Istruzioni dettagliate Cloudflare</summary><div class="mt-2 p-3 bg-white border rounded" style="font-size:0.9rem">' + r.explanation + '</div></details>';
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
                        el.innerHTML = '<span class="badge bg-secondary"><i class="fas fa-question-circle me-1"></i>Verifica non disponibile</span>';
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
                const checkByTipo = new Map();
                (data.checks || []).forEach(c => {
                    if (c.name) checkByFqdn.set(c.name.toLowerCase(), c);
                    if (c.type) checkByTipo.set(c.type, c);
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
                    let check = ctype ? checkByTipo.get(ctype) : null;
                    // Solo se il record non dichiara un tipo si ripiega sul nome, com'era prima.
                    if (!check) {
                        const fqdn = recordFqdn(rname, rzone).toLowerCase();
                        check = checkByFqdn.get(fqdn);
                        if (!check && rname) check = checkByFqdn.get(rname.toLowerCase());
                    }
                    if (!check) {
                        // Nessun check per questo record (es. SRV autodiscover, MTA-STS policy, alcuni TXT secondari)
                        badgeWrap.innerHTML = '<span class="badge bg-light text-dark border"><i class="fas fa-minus-circle me-1"></i>Non verificato</span>';
                        if (detailWrap) detailWrap.innerHTML = '';
                        unkCount++;
                        return;
                    }

                    if (check.passed) {
                        badgeWrap.innerHTML = '<span class="badge bg-success"><i class="fas fa-check-circle me-1"></i>Configurato correttamente</span>';
                        if (detailWrap) {
                            let ok = '<div class="alert alert-success py-1 px-2 mb-0 small mt-2"><i class="fas fa-check me-1"></i><strong>Nessuna azione richiesta</strong> — il record DNS risulta già configurato correttamente. ' + (check.message ? escapeHtmlBl(check.message) : '');
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
                            const vero = check.current_value;
                            if (vero) {
                                const corto = vero.length > 140 ? vero.substring(0, 140) + '…' : vero;
                                ok += '<div class="mt-1"><span class="text-muted">Pubblicato in DNS:</span> '
                                    + '<code class="small" style="word-break:break-all">' + escapeHtmlBl(corto) + '</code></div>';
                            }
                            detailWrap.innerHTML = ok + '</div>';
                        }
                        // Stile leggero: bordo verde
                        card.style.borderLeft = '4px solid #198754';
                        okCount++;
                    } else {
                        badgeWrap.innerHTML = '<span class="badge bg-warning text-dark"><i class="fas fa-exclamation-triangle me-1"></i>Da configurare</span>';
                        if (detailWrap) {
                            let html = '<div class="alert alert-warning py-2 px-2 mb-0 small mt-2"><i class="fas fa-exclamation-triangle me-1"></i><strong>Azione richiesta:</strong> ' + escapeHtmlBl(check.message || 'record mancante o errato') + '.';
                            if (check.current_value) {
                                const shortCur = check.current_value.length > 100 ? check.current_value.substring(0, 100) + '…' : check.current_value;
                                html += '<div class="mt-1"><span class="text-muted">Trovato in DNS:</span> <code class="small">' + escapeHtmlBl(shortCur) + '</code></div>';
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
                        msg = '<strong>Tutto a posto!</strong> ' + okCount + ' record DNS verificati e configurati correttamente.';
                    } else if (koCount > 0) {
                        cls = 'alert-warning'; icon = 'exclamation-triangle';
                        msg = '<strong>' + koCount + ' record DNS da configurare</strong> e ' + okCount + ' già a posto. Controlla i badge gialli qui sotto.';
                    } else {
                        cls = 'alert-info'; icon = 'info-circle';
                        msg = 'Verifica completata. ' + unkCount + ' record non sono soggetti a verifica automatica.';
                    }
                    summary.className = 'alert ' + cls + ' mb-3';
                    summary.innerHTML = '<i class="fas fa-' + icon + ' me-2"></i>' + msg + ' <span class="ms-2 small text-muted">(' + okCount + ' OK · ' + koCount + ' da fare · ' + unkCount + ' non verificati)</span>';
                    // Inserisci prima del primo .dns-record (o all'inizio se non c'è)
                    const firstRecord = container.querySelector('.dns-record');
                    if (firstRecord) container.insertBefore(summary, firstRecord);
                    else container.insertBefore(summary, container.firstChild);
                }
            }).catch(e => {
                console.error('verifyDnsAuto error', e);
                document.querySelectorAll('.record-status-badge').forEach(el => {
                    el.innerHTML = '<span class="badge bg-secondary"><i class="fas fa-times me-1"></i>Verifica fallita</span>';
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
                    status.innerHTML = '<div class="alert alert-secondary"><i class="fas fa-database me-2"></i>'
                        + '<strong>Nel pannello:</strong> esiste una chiave DKIM per questo dominio.<br>'
                        + 'Selector attivo: <code>' + data.selector + '</code><br>'
                        + 'Record che deve esistere in DNS: <code>' + data.dns_record_name + '</code>'
                        + '<div class="small text-muted mt-1">Questo non dice ancora se la firma sia verificabile:'
                        + ' dipende dal record TXT pubblico, che si controlla qui sotto.</div></div>';
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
                    status.innerHTML = '<div class="alert alert-warning"><i class="fas fa-exclamation-triangle me-2"></i>DKIM non configurato per questo dominio.<br><small class="text-muted">Clicca "Genera Chiavi DKIM" per il setup iniziale.</small></div>';
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

        // Formatta tempo relativo: "3 ore fa", "tra 27 giorni", ecc.
        function formatRelativeTime(date) {
            if (!date) return '';
            const ms = date.getTime() - Date.now();
            const past = ms < 0;
            const abs = Math.abs(ms);
            const sec = Math.floor(abs / 1000);
            const min = Math.floor(sec / 60);
            const hr  = Math.floor(min / 60);
            const day = Math.floor(hr / 24);
            const mon = Math.floor(day / 30);
            const yr  = Math.floor(day / 365);
            let val, unit;
            if (yr > 0)        { val = yr;  unit = (yr === 1 ? 'anno' : 'anni'); }
            else if (mon > 0)  { val = mon; unit = (mon === 1 ? 'mese' : 'mesi'); }
            else if (day > 0)  { val = day; unit = (day === 1 ? 'giorno' : 'giorni'); }
            else if (hr  > 0)  { val = hr;  unit = (hr === 1 ? 'ora' : 'ore'); }
            else if (min > 0)  { val = min; unit = (min === 1 ? 'minuto' : 'minuti'); }
            else               { val = sec; unit = (sec === 1 ? 'secondo' : 'secondi'); }
            if (sec < 5 && !past) return 'tra pochi secondi';
            if (sec < 5 && past)  return 'pochi secondi fa';
            return past ? (val + ' ' + unit + ' fa') : ('tra ' + val + ' ' + unit);
        }

        // Formatta data assoluta in italiano: "15 mag 2026 16:08"
        function formatItalianDate(date) {
            if (!date) return '';
            const months = ['gen','feb','mar','apr','mag','giu','lug','ago','set','ott','nov','dic'];
            const dd = String(date.getDate()).padStart(2, '0');
            const mm = months[date.getMonth()];
            const yyyy = date.getFullYear();
            const hh = String(date.getHours()).padStart(2, '0');
            const mi = String(date.getMinutes()).padStart(2, '0');
            return dd + ' ' + mm + ' ' + yyyy + ' ' + hh + ':' + mi;
        }

        // Aggiorna i due box prominenti "Ultima/Prossima rotazione"
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
                    const sign = skewMin > 0 ? 'avanti' : 'indietro';
                    console.warn('[DKIM] Server clock skew: ' + skewMin + ' min ' + sign + ' rispetto al browser');
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
                    relText = 'appena adesso';
                } else if (deltaMs > 0) {
                    const minAhead = Math.round(deltaMs / 60000);
                    relText = '<span class="text-warning" title="Il timestamp risulta ' + minAhead + ' minuti nel futuro rispetto al clock del server. È un valore fossile salvato prima del fix timezone — usa i bottoni per correggerlo.">incongruenza dati ⚠ (+' + minAhead + ' min)</span>';
                    showFixButtons = true;
                } else {
                    const fakeDate = new Date(lastTs.getTime() - (Date.now() - referenceNowMs));
                    relText = formatRelativeTime(fakeDate);
                }
                let html = '<strong>' + formatItalianDate(lastTs) + '</strong>' +
                    '<div class="small text-muted">' + relText + '</div>';
                if (showFixButtons) {
                    html += '<div class="mt-2 d-flex gap-1 flex-wrap">';
                    html += '<button class="btn btn-sm btn-outline-warning" onclick="resetLastRotationTimestamp()" title="Imposta il timestamp \'ultima rotazione\' a ora"><i class="fas fa-sync-alt me-1"></i>Reset a ora</button>';
                    html += '<button class="btn btn-sm btn-outline-secondary" onclick="clearLastRotationTimestamp()" title="Cancella il timestamp (mostra \'Mai effettuata\')"><i class="fas fa-eraser me-1"></i>Cancella</button>';
                    html += '</div>';
                }
                lastEl.innerHTML = html;
            } else {
                lastEl.innerHTML = '<span class="text-warning"><i class="fas fa-exclamation-triangle me-1"></i>Mai effettuata</span>' +
                    '<div class="small text-muted">Nessuna rotazione registrata per questo dominio</div>';
            }

            // Prossima rotazione (calcolata se schedule attivo)
            const nextTs = pickTs(data, 'next_rotation_at');
            const interval = data.interval_days || 0;
            if (interval === 0) {
                nextEl.innerHTML = '<span class="text-muted"><i class="fas fa-pause-circle me-1"></i>Non programmata</span>' +
                    '<div class="small text-muted">La rotazione automatica è disattivata. Avviala manualmente quando vuoi.</div>';
            } else if (nextTs) {
                const isOverdue = nextTs.getTime() <= Date.now();
                const badge = isOverdue
                    ? '<span class="badge bg-danger ms-1">in ritardo</span>'
                    : '';
                nextEl.innerHTML = '<strong>' + formatItalianDate(nextTs) + '</strong> ' + badge +
                    '<div class="small text-muted">' + formatRelativeTime(nextTs) + ' (ogni ' + interval + ' giorni)</div>';
            } else {
                nextEl.innerHTML = '<strong>Al prossimo check</strong> <span class="badge bg-warning text-dark ms-1">subito</span>' +
                    '<div class="small text-muted">Schedule attivo ogni ' + interval + ' giorni, ma nessuna rotazione ancora registrata.</div>';
            }
        }

        function loadDkimSchedule(domainId) {
            const panel = document.getElementById('dkimSchedulePanel');
            const info = document.getElementById('dkimScheduleInfo');
            panel.classList.remove('d-none');
            info.innerHTML = '<i class="fas fa-spinner fa-spin me-1"></i>Caricamento...';
            fetch('/api/dkim', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'schedule_get', domain_id: parseInt(domainId) })
            }).then(r => r.json()).then(data => {
                if (!data.success) {
                    info.innerHTML = '<span class="text-danger">' + escapeHtmlBl(data.error || 'errore') + '</span>';
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
                    optionsHtml += '<option value="' + p.days + '"' + (isSel ? ' selected' : '') + '>' + escapeHtmlBl(p.label) + (p.days > 0 ? ' (' + p.days + ' giorni)' : '') + '</option>';
                });
                // Custom: se cur > 0 ma non corrisponde a nessun preset, selezioniamo custom
                optionsHtml += '<option value="custom"' + (!matched && cur > 0 ? ' selected' : '') + '>Custom (giorni specifici)</option>';
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
                    html = '<span class="text-muted"><i class="fas fa-info-circle me-1"></i>Rotazione automatica programmata: <strong>disattivata</strong>. Devi avviare la rotazione manualmente quando vuoi.</span>';
                } else {
                    html = '<i class="fas fa-clock text-primary me-1"></i>Rotazione automatica ogni <strong>' + cur + ' giorni</strong>. ';
                    if (data.last_rotation_at) {
                        html += 'Ultima rotazione: <strong>' + escapeHtmlBl(data.last_rotation_at) + '</strong>. ';
                    } else {
                        html += '<span class="text-warning">Nessuna rotazione ancora effettuata.</span> ';
                    }
                    if (data.next_rotation_at) {
                        html += 'Prossima rotazione prevista: <strong>' + escapeHtmlBl(data.next_rotation_at) + '</strong>.';
                    }
                    if (!cloudflareConfigured) {
                        html += '<br><span class="text-warning"><i class="fas fa-exclamation-triangle me-1"></i><strong>Attenzione:</strong> per attivare lo schedule in automatico è necessario un account Cloudflare assegnato a questo dominio. Senza CF, lo schedule resta inattivo.</span>';
                    } else {
                        html += '<br><small class="text-muted">Lo scheduler creerà la nuova chiave, pubblicherà il record TXT, attenderà ' + (data.auto_activate_after_hours || 24) + 'h di propagazione, attiverà la firma, poi dopo ' + (data.grace_period_days || 7) + ' giorni di grace period rimuoverà la vecchia chiave. Tutto automatico.</small>';
                    }
                }
                info.innerHTML = html;
            }).catch(e => {
                info.innerHTML = '<span class="text-danger">Errore rete: ' + e.message + '</span>';
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

        function resetLastRotationTimestamp() {
            if (!currentDomainId) return;
            if (!confirm('Resettare il timestamp \'ultima rotazione\' a ora?\n\nUsa questa funzione se il valore mostrato è un fossile dovuto a timezone MySQL sbagliata (prima del fix). Il nuovo timestamp userà il clock corrente del JVM Java.')) return;
            fetch('/api/dkim', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'last_rotation_reset', domain_id: parseInt(currentDomainId) })
            }).then(r => r.json()).then(data => {
                alert((data.success ? '✓ ' : '✗ ') + (data.message || data.error || ''));
                if (data.success) loadDkimSchedule(currentDomainId);
            }).catch(e => alert('Errore rete: ' + e.message));
        }

        function clearLastRotationTimestamp() {
            if (!currentDomainId) return;
            if (!confirm('Cancellare il timestamp \'ultima rotazione\'?\n\nIl campo verrà impostato a NULL e l\'UI mostrerà \'Mai effettuata\'. La prossima rotazione lo ripopolerà con il valore corretto.')) return;
            fetch('/api/dkim', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'last_rotation_clear', domain_id: parseInt(currentDomainId) })
            }).then(r => r.json()).then(data => {
                alert((data.success ? '✓ ' : '✗ ') + (data.message || data.error || ''));
                if (data.success) loadDkimSchedule(currentDomainId);
            }).catch(e => alert('Errore rete: ' + e.message));
        }

        function saveDkimSchedule() {
            if (!currentDomainId) { alert('Seleziona un dominio'); return; }
            const sel = document.getElementById('dkimSchedulePreset');
            let days;
            if (sel.value === 'custom') {
                const v = parseInt(document.getElementById('dkimScheduleCustomDays').value);
                if (isNaN(v) || v < 1 || v > 3650) {
                    alert('Inserisci un numero di giorni tra 1 e 3650');
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
                alert((data.success ? '✓ ' : '✗ ') + (data.message || data.error || ''));
                if (data.success) {
                    loadDkimSchedule(currentDomainId);
                    loadDkimHistory(currentDomainId);
                }
            }).catch(e => alert('Errore rete: ' + e.message));
        }

