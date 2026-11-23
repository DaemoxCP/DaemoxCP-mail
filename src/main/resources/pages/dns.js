        // ===== Cloudflare multi-account integration =====
        // Local cache to use the data elsewhere (rotateDkim, dkim card info)
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

                // Account list
                if (cfAccounts.length === 0) {
                    list.innerHTML = '<div class="alert alert-secondary py-2 mb-0 small"><i class="fas fa-info-circle me-1" aria-hidden="true"></i>' + escHtml(t('dns.cfNone')) + '</div>';
                } else {
                    let html = '<div class="table-responsive"><table class="table table-sm align-middle mb-0">';
                    html += '<thead><tr><th scope="col">' + escHtml(t('dns.cfLabel')) + '</th><th scope="col">' + escHtml(t('dns.cfEmail')) + '</th><th scope="col">Token</th><th scope="col">' + escHtml(t('dns.cfLinked')) + '</th><th scope="col" class="text-end">' + escHtml(t('home.colActions')) + '</th></tr></thead><tbody>';
                    cfAccounts.forEach(a => {
                        const linkedDomains = cfDomainsCf.filter(d => d.cloudflare_account_id === a.id).map(d => d.domain);
                        const safeLabel = escapeHtmlCf(a.label).replace(/'/g, "\\'");
                        // Display row
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
                        // Edit row (hidden until you click the pencil)
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

                // Domain -> account assignment table
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

                // Update any visible rotation state (if the user has already selected a domain)
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
            // Close any other open edit rows
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
            // Clear the token field so it does not stay in memory in the DOM
            const tok = document.getElementById('cfEditToken-' + id);
            if (tok) tok.value = '';
        }

        function cfEditSave(id) {
            const label = document.getElementById('cfEditLabel-' + id).value.trim();
            const email = document.getElementById('cfEditEmail-' + id).value.trim();
            const token = document.getElementById('cfEditToken-' + id).value.trim();
            if (!label) { panelSay('info', t('dns.cfLabelRequired')); return; }
            const payload = { action: 'update', account_id: id, label: label, email: email };
            // Include the token ONLY if the user actually filled it in
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
                // The two zones differ only when the mail hostname is in another
                // domain. When they coincide (the normal case), announcing "2 different
                // DNS zones" and listing the same name twice sends people looking for a
                // zone that does not exist.
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
                    // Unique ID based on name+type for matching with the check
                    const recordKey = (r.name + '|' + r.type).replace(/[^a-zA-Z0-9_|.\-]/g, '_');
                    html += '<div class="dns-record ' + reqClass + '" data-record-key="' + recordKey + '" data-record-name="' + escHtml(r.name) + '" data-record-type="' + escHtml(r.type) + '" data-check-type="' + escHtml(r.checkType || '') + '" data-record-zone="' + escHtml(r.dnsZone || '') + '">';
                    html += '<div class="d-flex justify-content-between align-items-start">';
                    html += '<div><span class="record-type">' + escHtml(r.type) + '</span> ' + badge;
                    // Status badge: placeholder until the automatic check starts
                    html += ' <span class="record-status-badge" data-status-key="' + recordKey + '"><span class="badge bg-light text-dark border"><i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('dns.checkingRecord')) + '</span></span>';
                    if (r.dnsZone) {
                        html += ' <small class="text-muted">' + escHtml(t('dns.onZone', { zone: r.dnsZone })) + '</small>';
                    }
                    html += '</div>';
                    html += '<button type="button" class="btn btn-link p-0 copy-btn" data-on-click="copyToClipboard(this.parentElement.parentElement)" title="' + escHtml(t('common.copy')) + '" aria-label="' + escHtml(t('common.copy')) + '"><i class="fas fa-copy" aria-hidden="true"></i></button>';
                    html += '</div>';
                    html += '<div class="mt-2"><strong>' + escHtml(t('dns.recName')) + '</strong> <code class="record-name">' + escHtml(r.name) + '</code></div>';
                    // The FULL value is shown when it exists: for MX and SRV "value" contains
                    // only the target, and under a label that says "recommended" that
                    // would be a record to copy with some fields missing.
                    html += '<div class="mt-1"><strong>' + escHtml(t('dns.recValue')) + '</strong> <code class="record-value" data-style="word-break:break-all">' + escHtml(r.fullValue || r.value) + '</code></div>';
                    html += '<small class="text-muted">' + r.description + '</small>';
                    // Check details area (filled after verifyDnsAuto)
                    html += '<div class="record-verify-detail mt-2" data-detail-key="' + recordKey + '"></div>';
                    if (r.explanation) {
                        html += '<details class="mt-2"><summary><i class="fas fa-cog me-1" aria-hidden="true"></i>' + escHtml(t('dns.cfInstructions')) + '</summary><div class="mt-2 p-3 bg-white border rounded" data-style="font-size:0.9rem">' + r.explanation + '</div></details>';
                    }
                    html += '</div>';
                });

                document.getElementById('dnsRecordsContainer').innerHTML = html;

                // Load DKIM status (in parallel with the DNS check)
                loadDkimStatus(currentDomainId);
                // Automatic, silent check of all DNS records
                verifyDnsAuto();
            });
        }

        /**
         * Background DNS check: for each record, shows an inline badge
         * "Configured" (tick) / "To configure" (warning sign) / "Web check" etc., so the user
         * knows at a glance what needs doing without scrolling down to the "Check" panel at the bottom.
         */
        /**
         * Computes the FQDN of a record given its relative name (it can be "@", a
         * sub-part, or already an FQDN) and the DNS zone it belongs to.
         * Needed because the generated records use relative names ("@", "mail._domainkey"),
         * while the verifier's checks use FQDNs ("example.org", "mail._domainkey.example.org").
         */
        function recordFqdn(name, zone) {
            if (!name || name === '@' || name === '') return zone || '';
            // If it is already an FQDN (it contains the zone at the end) we leave it unchanged
            if (zone && name.toLowerCase().endsWith('.' + zone.toLowerCase())) return name;
            if (zone && name.toLowerCase() === zone.toLowerCase()) return name;
            // Otherwise concatenate it with the zone
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
                // Map fqdn -> check (the verifier's checks always use the FQDN as name)
                const checkByFqdn = new Map();
                // And a TYPE -> check map, which is the right one: at the domain apex MX and SPF
                // have the SAME name, so pairing by name made one overwrite
                // the other and the MX card showed the SPF verdict. The type is declared by
                // the record itself (checkType), so the pairing is a fact and not
                // a guess derived from the name.
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

                    // First by declared type: it is the only pairing that cannot confuse
                    // two different records with the same name.
                    const ctype = card.getAttribute('data-check-type') || '';
                    let check = ctype ? checkByKind.get(ctype) : null;
                    // Only if the record does not declare a type does it fall back to the name, as before.
                    if (!check) {
                        const fqdn = recordFqdn(rname, rzone).toLowerCase();
                        check = checkByFqdn.get(fqdn);
                        if (!check && rname) check = checkByFqdn.get(rname.toLowerCase());
                    }
                    if (!check) {
                        // No check for this record (e.g. SRV autodiscover, MTA-STS policy, some secondary TXTs)
                        badgeWrap.innerHTML = '<span class="badge bg-light text-dark border"><i class="fas fa-minus-circle me-1" aria-hidden="true"></i>' + escHtml(t('dns.notChecked')) + '</span>';
                        if (detailWrap) detailWrap.innerHTML = '';
                        unkCount++;
                        return;
                    }

                    if (check.passed) {
                        badgeWrap.innerHTML = '<span class="badge bg-success"><i class="fas fa-check-circle me-1" aria-hidden="true"></i>' + escHtml(t('dns.configuredOk')) + '</span>';
                        if (detailWrap) {
                            let ok = '<div class="alert alert-success py-1 px-2 mb-0 small mt-2"><i class="fas fa-check me-1" aria-hidden="true"></i><strong>' + escHtml(t('dns.noAction')) + '</strong> ' + (check.message ? escapeHtmlBl(check.message) : '');
                            // The real value is shown also when the record PASSES, not only
                            // when it fails: without it, only the proposal stays on screen and it
                            // looks as if that is what is published.
                            //
                            // And it is shown WITHOUT comparing it with the proposal. The comparison
                            // I had written declared "different" for a trailing dot, for the
                            // quotes of a TXT, or because for an SRV the proposal is only the
                            // host and the real value also contains priority and weight, and on
                            // top of that it added "and that is fine", which is a judgement this
                            // line is not able to give. The judgement is already given by check.message.
                            const real = check.current_value;
                            if (real) {
                                const brief = real.length > 140 ? real.substring(0, 140) + '…' : real;
                                ok += '<div class="mt-1"><span class="text-muted">' + escHtml(t('dns.published')) + '</span> '
                                    + '<code class="small" data-style="word-break:break-all">' + escapeHtmlBl(brief) + '</code></div>';
                            }
                            detailWrap.innerHTML = ok + '</div>';
                        }
                        // Light style: green border
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

                // Summary banner at the top of the container
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
                    // Insert before the first .dns-record (or at the start if there is none)
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
                    // DKIM already configured: the "Generate DKIM keys" button must be HIDDEN/disabled
                    // because it would overwrite the active key without the rotation workflow (no grace period).
                    // To change the key on an already configured domain, USE "Start key rotation".
                    if (generateBtn) {
                        generateBtn.style.display = 'none';
                        generateBtn.disabled = true;
                    }
                } else {
                    status.innerHTML = '<div class="alert alert-warning"><i class="fas fa-exclamation-triangle me-2" aria-hidden="true"></i>' + escHtml(t('dns.dkimMissing')) + '<br><small class="text-muted">' + escHtml(t('dns.dkimMissingHint')) + '</small></div>';
                    if (rotateBtn) rotateBtn.disabled = true;
                    if (verifyBtn) verifyBtn.disabled = true;
                    // DKIM never configured: ONLY now does "Generate DKIM keys" make sense (initial setup)
                    if (generateBtn) {
                        generateBtn.style.display = '';
                        generateBtn.disabled = false;
                    }
                    // Also hide the timeline boxes if there is no DKIM
                    const tl = document.getElementById('dkimRotationTimeline');
                    if (tl) tl.classList.add('d-none');
                }
                const vr = document.getElementById('dkimVerifyResult'); if (vr) vr.innerHTML = '';
                loadDkimRotationStatus(domainId);
                loadDkimHistory(domainId);
                loadDkimSchedule(domainId);
            });
        }

        // ===== Scheduled rotation =====
        let dkimSchedulePresets = [];

        // Tolerant parsing of the server's timestamps.
        // Number (epoch ms) -> unambiguous, preferred when available.
        // ISO 8601 with Z or offset -> parsed as UTC.
        // Legacy fallback "yyyy-MM-dd HH:mm:ss" without TZ -> assumed to be local time.
        function parseTs(s) {
            if (s == null || s === '') return null;
            // Number or numeric string = epoch milliseconds
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

        // Wrapper: prefers data._ms (epoch) if present, otherwise data[key].
        // Usage: pickTs(data, 'last_rotation_at') -> looks for data.last_rotation_at_ms, then data.last_rotation_at.
        function pickTs(obj, key) {
            if (!obj) return null;
            const ms = obj[key + '_ms'];
            if (ms != null && ms !== '') return parseTs(ms);
            return parseTs(obj[key]);
        }

        // Relative time in the page's language: `3 ore fa`, `tra 27 giorni`, "3 hours ago"
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

        // Date and time in the page's language, in the viewer's time zone: `15 mag 2026, 16:08`
        function formatPanelDate(date) {
            if (!date) return '';
            return date.toLocaleString(window.I18N_LANG, { day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' });
        }

        // Updates the two prominent boxes "Last/Next rotation"
        // The scheduler lives inside the panel's web server. Saying "it runs while the panel
        // is on" is a generic warning that hands the reader the task of going to check
        // somewhere else; the panel has that information and can say it.
        function autoStartSentence(data) {
            if (data.auto_start === true)
                return escHtml(t('dns.autostartYes'));
            if (data.auto_start === false)
                return '<span class="text-warning">' + escHtml(t('dns.autostartNo')) + '</span>';
            // The field did not arrive: say what is known, without inventing a verdict.
            return escHtml(t('dns.autostartUnknown'));
        }

        // How the next rotation stands, decided in a single place.
        //
        // It exists because the same question was answered twice in the same card: the
        // box at the top and the summary line below. Once the first was fixed, the second
        // kept announcing "next rotation due" with a date of 13 August while
        // a rotation was already in progress. Two answers to the same question always diverge:
        // the one that is looked at less falls behind.
        //
        // Returns: 'in_progress' | 'due' | 'scheduled' | 'disabled' | 'never'
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

            // DIAGNOSTICS: compare server vs browser clock. Skew > 5 min = real problem.
            if (data.server_now_ms) {
                const skewMs = data.server_now_ms - Date.now();
                if (Math.abs(skewMs) > 5 * 60 * 1000) {
                    const skewMin = Math.round(skewMs / 60000);
                    console.warn('[DKIM] Server clock skew: ' + skewMin + ' min (' + (skewMin > 0 ? 'ahead of' : 'behind') + ' the browser)');
                }
            }

            // Last rotation: the reference "now" is the SERVER's (server_now_ms if available),
            // not the browser's. This keeps clock skew between server and browser from making
            // the rotation look "in the future".
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

            // Next rotation (computed if the schedule is active)
            const nextTs = pickTs(data, 'next_rotation_at');
            const interval = data.interval_days || 0;
            // A rotation ALREADY in progress takes precedence over any computed date: saying
            // "due, starts at the next check" while the new key is already published
            // is promising for the future something that has already happened, and that is
            // exactly what this box did. The next date will make sense again once the rotation
            // has finished, when "last rotation" is the new one.
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
                    // A past date under the label "Next rotation", with a red
                    // badge and nothing else, reads as "the panel knows it is late and
                    // does nothing". That is not so: the scheduler compares (now - last)
                    // with the interval, so a past due date is already "due" and starts at
                    // the first check. What was missing was not the mechanism, it was saying so.
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
                // Update the two prominent boxes
                renderRotationTimeline(data, true);
                dkimSchedulePresets = data.presets || [];
                const cur = data.interval_days || 0;
                // Fill the dropdown with the presets + the "Custom" option
                const sel = document.getElementById('dkimSchedulePreset');
                let optionsHtml = '';
                let matched = false;
                dkimSchedulePresets.forEach(p => {
                    const isSel = (p.days === cur);
                    if (isSel) matched = true;
                    optionsHtml += '<option value="' + escHtml(p.days) + '"' + (isSel ? ' selected' : '') + '>' + escapeHtmlBl(p.label) + (p.days > 0 ? ' ' + escHtml(tn('dns.daysParen', p.days)) : '') + '</option>';
                });
                // Custom: if cur > 0 but matches no preset, we select custom
                optionsHtml += '<option value="custom"' + (!matched && cur > 0 ? ' selected' : '') + '>' + escHtml(t('dns.customOption')) + '</option>';
                sel.innerHTML = optionsHtml;
                // Show/hide the custom field
                if (!matched && cur > 0) {
                    document.getElementById('dkimScheduleCustomWrap').style.display = '';
                    document.getElementById('dkimScheduleCustomDays').value = cur;
                } else {
                    document.getElementById('dkimScheduleCustomWrap').style.display = 'none';
                    document.getElementById('dkimScheduleCustomDays').value = '';
                }
                // Text summary
                let html = '';
                if (cur === 0) {
                    html = '<span class="text-muted"><i class="fas fa-info-circle me-1" aria-hidden="true"></i>' + escHtml(t('dns.autoOffLong')) + '</span>';
                } else {
                    html = '<i class="fas fa-clock text-primary me-1" aria-hidden="true"></i>' + escHtml(tn('dns.autoEvery', cur)) + ' ';
                    // The dates here are formatted as in the two boxes above.
                    //
                    // Before, this line printed the raw timestamp in UTC while the boxes
                    // showed local time: the SAME instant appeared as `14 ago 2026 00:13`
                    // above and "2026-08-13T22:13:41Z" below. It is not a calculation error,
                    // but whoever reads sees two different dates two lines apart and starts
                    // not to trust them, and is right not to, because there is no way to
                    // know that one of the two is UTC.
                    const lastHere = pickTs(data, 'last_rotation_at');
                    const nextHere = pickTs(data, 'next_rotation_at');
                    if (lastHere) {
                        html += escHtml(t('dns.lastWas', { date: formatPanelDate(lastHere) })) + ' ';
                    } else if (data.last_rotation_at) {
                        html += escHtml(t('dns.lastWas', { date: data.last_rotation_at })) + ' ';
                    } else {
                        html += '<span class="text-warning">' + escHtml(t('dns.noRotationYet')) + '</span> ';
                    }
                    // Same question, same answer as the box above.
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
                    // The flag arrives with the response; the global remains only as a fallback so as
                    // not to change behavior if the field were missing.
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


        // ---------- DKIM: how all the domains stand ----------
        // It exists because the card for a single domain does not answer the question "how
        // do they all stand?": to know, one had to select the domains one by one and
        // keep the numbers in mind. The things that matter (a domain without a key, one stuck
        // for months while the others rotate) can be seen only by putting them in a row.
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
            // The title says the worst thing first: a domain without a key must not
            // end up at the bottom of a list that starts with "all good".
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
                    // "I could not check" is not "all good", and it is not "broken" either.
                    state = '<span class="badge bg-secondary">' + escHtml(t('dns.unverifiable')) + '</span>';

                let ageText = '<span class="text-muted">&mdash;</span>';
                if (d.daysSinceLast !== undefined && d.daysSinceLast !== null) {
                    const g = d.daysSinceLast;
                    // Beyond the chosen interval the key is late; without an interval the
                    // reference is 90 days, the cadence the panel recommends.
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
