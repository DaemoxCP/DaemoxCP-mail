        // ---------- SPF and DMARC created by the panel on Cloudflare ----------
        // The rules are not decoration: two SPF records on the same name give "permerror"
        // and SPF stops working (RFC 7208 section 4.5); two DMARC records are both discarded
        // (RFC 9989). That is why nothing is ever overwritten here, and the question "does it
        // already exist?" is asked about the record's CONTENT, not about its name.
        async function autoDnsApi(actionItem, extra) {
            const bodyText = Object.assign({ action: actionItem, domain_id: parseInt(currentDomainId) }, extra || {});
            const r = await fetch('/api/autodns', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(bodyText)
            });
            return await r.json();
        }

        // The confirmation: the panel's window (finding 198), not the browser's prompt with the word to type. The
        // server always receives its fixed code (CREATE, CHANGE, CONFIGURE), in the caller's code.
        function adConfirm(textValue) {
            return panelConfirm(textValue);
        }

        function adEsc(v) {
            const d = document.createElement('div');
            d.textContent = v === null || v === undefined ? '' : String(v);
            return d.innerHTML;
        }

        function adWarnings(itemList) {
            if (!itemList || !itemList.length) return '';
            return '<div class="mt-2">' + itemList.map(a =>
                '<div class="small d-flex gap-2 mb-1">'
                + '<i class="fas fa-triangle-exclamation text-warning mt-1" aria-hidden="true"></i>'
                + '<span>' + adEsc(a) + '</span></div>').join('') + '</div>';
        }

        // The reading of the card in progress: it starts by itself when the domain is chosen, and "Set up
        // everything" pressed while it is in progress waits for it, or the redrawn card would erase the outcome
        // just written (finding 250)
        let adLoading = null;
        async function autoDnsLoad() {
            const run = autoDnsRead();
            adLoading = run;
            try { await run; } finally { if (adLoading === run) adLoading = null; }
        }

        async function autoDnsRead() {
            const el = document.getElementById('autoDnsBody');
            if (!el) return;
            if (!currentDomainId) { el.innerHTML = '<span class="text-muted small">' + escHtml(t('dns.chooseDomainFirst')) + '</span>'; return; }
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('ad.askingCf'));
            const r = await autoDnsApi('status');
            if (!r.success) { el.innerHTML = '<div class="alert alert-danger py-2 small mb-0">' + adEsc(r.error) + '</div>'; return; }
            if (!r.cloudflare || !r.zone) {
                el.innerHTML = '<div class="alert alert-warning py-2 small mb-0">' + adEsc(r.note) + '</div>'
                             + '<div id="autoDnsOutcome" class="mt-2" aria-live="polite"></div>';
                return;
            }
            let h = '<div class="small text-muted mb-2">' + escHtml(t('ad.accountZone', { account: r.account, zone: r.domain })) + '</div>'
                  + '<div class="table-responsive"><table class="table table-sm align-middle mb-2"><thead><tr>'
                  + '<th scope="col">Record</th><th scope="col">' + escHtml(t('ad.colInCf')) + '</th><th scope="col">' + escHtml(t('ad.colWouldWrite')) + '</th><th scope="col"><span class="visually-hidden">' + escHtml(t('home.colActions')) + '</span></th>'
                  + '</tr></thead><tbody>';
            (r.record || []).forEach(x => {
                const entryName = x.which === 'spf' ? 'SPF' : 'DMARC';
                const tooMany = (x.howMany || 0) > 1;

                let state;
                if (tooMany) state = '<span class="badge bg-danger">' + escHtml(t('ad.cancelOut', { n: x.howMany })) + '</span>';
                else if (x.exists) state = '<span class="badge bg-success">' + escHtml(t('ad.exists')) + '</span>';
                else state = '<span class="badge bg-warning text-dark">' + escHtml(t('ad.missing')) + '</span>';
                if (x.otherTxt > 0)
                    state += '<div class="small text-muted mt-1">' + escHtml(tn('ad.otherTxt', x.otherTxt)) + '</div>';
                if (x.content)
                    state += '<div class="small mt-1" data-style="word-break:break-all"><code>' + adEsc(x.content) + '</code></div>';

                let proposal;
                if (x.locked) {
                    proposal = '<div class="small text-danger">' + adEsc(x.locked) + '</div>';
                } else {
                    proposal = '<code class="small" data-style="word-break:break-all">' + adEsc(x.proposed) + '</code>';
                    if (x.which === 'dmarc' && !x.exists)
                        proposal += '<div class="mt-1"><select class="form-select form-select-sm" id="adPolicy" data-style="max-width:22rem" aria-label="' + escHtml(t('ad.policy')) + '">'
                                  + '<option value="none" selected>p=none &mdash; ' + escHtml(t('ad.pNone')) + '</option>'
                                  + '<option value="quarantine">p=quarantine &mdash; ' + escHtml(t('ad.pQuarantine')) + '</option>'
                                  + '<option value="reject">p=reject &mdash; ' + escHtml(t('ad.pReject')) + '</option>'
                                  + '</select>'
                                  + '<div class="small text-muted mt-1">' + escHtml(t('ad.pStart')) + '</div></div>';
                }

                let actionItem;
                if (x.which === 'dmarc' && x.exists && x.currentPolicy) {
                    // The path is none -> quarantine -> reject: the panel must make
                    // the two steps after the first easy too, not just the first.
                    const option = ['none', 'quarantine', 'reject'].map(v =>
                        '<option value="' + v + '"' + (v === x.currentPolicy ? ' selected' : '') + '>p='
                        + v + '</option>').join('');
                    actionItem = '<select class="form-select form-select-sm mb-1" id="adPolicyNew" aria-label="' + escHtml(t('ad.policy')) + '">' + option + '</select>'
                           + '<button class="btn btn-sm btn-outline-warning" data-on-click="autoDnsChangePolicy()">'
                           + '<i class="fas fa-pen me-1" aria-hidden="true"></i>' + escHtml(t('ad.changePolicy')) + '</button>';
                } else if (x.exists || x.locked) {
                    actionItem = '<span class="small text-muted">' + escHtml(x.exists ? t('ad.nothingToDo') : t('ad.cannotCreate')) + '</span>';
                } else {
                    actionItem = '<button class="btn btn-sm btn-outline-success" data-on-click="autoDnsCreate(\'' + adEsc(x.which) + '\')">'
                           + '<i class="fas fa-cloud-arrow-up me-1" aria-hidden="true"></i>' + escHtml(t('ad.create')) + '</button>';
                }

                h += '<tr class="upd-cell"><td><strong>' + escHtml(entryName) + '</strong><br>'
                   + '<code class="small">' + adEsc(x.name) + '</code></td>'
                   + '<td>' + state + '</td><td>' + proposal + '</td>'
                   + '<td class="text-end">' + actionItem + '</td></tr>';

                if (x.warnings && x.warnings.length)
                    h += '<tr><td colspan="4" class="pt-0">' + adWarnings(x.warnings) + '</td></tr>';
            });
            h += '</tbody></table></div><div id="autoDnsOutcome" aria-live="polite"></div>';

            h += adReports(r.reports);
            h += adOptional(r.optionalItems);

            h += '<div class="small text-muted mt-3">' + escHtml(t('ad.noRotation')) + '</div>';
            el.innerHTML = h;
            if (r.reports && !r.reports.exists) adLoadMailboxes();
        }

        // The mailbox the DMARC reports arrive at. It must be set up BEFORE publishing the
        // record: as soon as DMARC is public the reports start, and if the address does not
        // exist they all bounce (RFC 9989 section 5.1.4).
        //
        // Two ways, because they are two different choices and neither is obvious: forward the
        // mail to an address that is already read, or keep the reports in a mailbox of their own.
        function adReports(reportList) {
            if (!reportList) return '';
            if (reportList.exists) {
                return '<div class="alert alert-success py-2 small mb-0 mt-2">'
                     + '<i class="fas fa-inbox me-1" aria-hidden="true"></i>'
                     + escHtml(reportList.destination ? t('ad.reportsToFwd', { address: reportList.address, kind: reportList.type, to: reportList.destination }) : t('ad.reportsTo', { address: reportList.address, kind: reportList.type })) + '</div>';
            }
            return '<div class="card mt-2"><div class="card-body py-3">'
                 + '<div class="small mb-3"><i class="fas fa-inbox me-1" aria-hidden="true"></i>'
                 + '<strong>' + escHtml(t('ad.noReportBox')) + '</strong> ' + escHtml(t('ad.noReportBoxWhy', { address: reportList.address })) + ' '
                 + adEsc(reportList.note || '') + ' <strong>' + escHtml(t('ad.pickOne')) + '</strong></div>'

                 + '<div class="row g-3">'

                 // --- A: forward ---
                 + '<div class="col-lg-6"><div class="border rounded p-3 h-100">'
                 + '<div class="fw-bold mb-1"><i class="fas fa-share me-1" aria-hidden="true"></i>' + escHtml(t('ad.fwdTitle')) + '</div>'
                 + '<div class="small text-muted mb-3">' + escHtml(t('ad.fwdHint', { address: reportList.address })) + ' <strong>' + escHtml(t('ad.recommended')) + '</strong></div>'
                 + '<label class="form-label small mb-1" for="adDestination">' + escHtml(t('ad.fwdTo', { address: reportList.address })) + '</label>'
                 + '<select class="form-select form-select-sm mb-2" id="adDestination" data-on-change="adDestinationChange()">'
                 + '<option value="">' + escHtml(t('ad.loadingAddresses')) + '</option></select>'
                 + '<input type="email" class="form-control form-control-sm mb-2 d-none" id="adDestinationOther" '
                 + 'placeholder="' + escHtml(t('al.destPh')) + '" aria-label="' + escHtml(t('ad.otherAddress')) + '" autocomplete="off">'
                 + '<div class="small text-muted mb-2 d-none" id="adDestinationOtherNote">' + escHtml(t('ad.otherAddressNote')) + '</div>'
                 + '<button class="btn btn-sm btn-outline-success" data-on-click="autoDnsCreateAlias()">'
                 + '<i class="fas fa-share me-1" aria-hidden="true"></i>' + escHtml(t('ad.createFwd')) + '</button>'
                 + '</div></div>'

                 // --- B: real mailbox ---
                 + '<div class="col-lg-6"><div class="border rounded p-3 h-100">'
                 + '<div class="fw-bold mb-1"><i class="fas fa-inbox me-1" aria-hidden="true"></i>' + escHtml(t('ad.boxTitle', { address: reportList.address })) + '</div>'
                 + '<div class="small text-muted mb-3">' + escHtml(t('ad.boxHint')) + '</div>'
                 + '<button class="btn btn-sm btn-outline-secondary" data-on-click="autoDnsCreateMailbox()">'
                 + '<i class="fas fa-inbox me-1" aria-hidden="true"></i>' + escHtml(t('ad.createBox')) + '</button>'
                 + '</div></div>'

                 + '</div><div id="adAliasOutcome" class="mt-3"></div></div></div>';
        }

        function adDestinationChange() {
            const sel = document.getElementById('adDestination');
            const field = document.getElementById('adDestinationOther');
            const noteText = document.getElementById('adDestinationOtherNote');
            if (!sel || !field) return;
            const otherOne = sel.value === '__other__';
            field.classList.toggle('d-none', !otherOne);
            if (noteText) noteText.classList.toggle('d-none', !otherOne);
            if (otherOne) field.focus();
        }

        // Addresses are chosen from a list. Whoever wants a different one types it, but
        // must ask for it on purpose: a free field as the first choice is the fastest way
        // to write an address that does not exist and notice six months later.
        async function adLoadMailboxes() {
            const sel = document.getElementById('adDestination');
            if (!sel) return;
            const r = await autoDnsApi('mailboxes');
            const mailboxes = (r.success && r.mailboxes) ? r.mailboxes : [];
            sel.innerHTML = '<option value="">&mdash; ' + escHtml(t('ad.chooseAddress')) + ' &mdash;</option>'
                + mailboxes.map(c => '<option value="' + adEsc(c) + '">' + adEsc(c) + '</option>').join('')
                + '<option value="__other__">&mdash; ' + escHtml(t('ad.anotherAddress')) + ' &mdash;</option>';
        }

        function adDestinationChosen() {
            const sel = document.getElementById('adDestination');
            if (!sel) return '';
            if (sel.value === '__other__') {
                const field = document.getElementById('adDestinationOther');
                return field ? field.value.trim() : '';
            }
            return sel.value;
        }

        async function autoDnsCreateAlias() {
            const destination = adDestinationChosen();
            const el = document.getElementById('adAliasOutcome');
            if (!destination) {
                el.innerHTML = '<div class="alert alert-warning py-2 small mb-0">' + escHtml(t('ad.chooseFirst')) + '</div>';
                return;
            }
            if (!await adConfirm(t('ad.confirmFwd', { to: destination }), t('ad.wordCreate'))) return;
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('ad.creatingFwd'));
            const r = await autoDnsApi('alias_create', { confirm: 'CREATE', destination: destination });
            el.innerHTML = '<div class="alert alert-' + (r.success ? 'success' : 'danger') + ' py-2 small mb-0">'
                         + adEsc(r.note || r.error) + '</div>';
            // It reloads even when the panel REFUSES: the "already exists" refusal means
            // that the state on screen was stale, and that is exactly what must be read again.
            // Leaving the prompt where it is would invite pressing again.
            setTimeout(autoDnsLoad, 1000);
        }

        async function autoDnsCreateMailbox() {
            const el = document.getElementById('adAliasOutcome');
            if (!await adConfirm(t('ad.confirmBox'), t('ad.wordCreate'))) return;
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('ad.creatingBox'));
            const r = await autoDnsApi('mailbox_create', { confirm: 'CREATE' });
            let h = '<div class="alert alert-' + (r.success ? 'success' : 'danger') + ' py-2 small mb-0">'
                  + adEsc(r.note || r.error) + '</div>';
            if (r.success && r.password)
                h += '<div class="alert alert-warning py-2 small mb-0 mt-2">'
                   + '<i class="fas fa-key me-1" aria-hidden="true"></i><strong>' + escHtml(t('ad.passwordOf', { address: r.address })) + '</strong> '
                   + '<code data-style="font-size:1.05em">' + adEsc(r.password) + '</code><br>'
                   + escHtml(t('ad.passwordKept')) + '</div>';
            el.innerHTML = h;
            // It does not reload by itself: the reload would erase the password from the screen.
            if (r.success) {
                const b = document.getElementById('autoDnsOutcome');
                if (b) b.innerHTML = '<div class="alert alert-info py-2 small mb-1">' + escHtml(t('ad.boxCreated')) + '</div>';
            }
        }


        // The "optional" records: mail works without them too, but without them whoever adds
        // the mailbox must know by heart server, ports and type of encryption. They are the same
        // values as on the DNS page, read from the same setting: two ways of deriving the
        // same hostname are two hostnames that one day diverge.
        function adOptional(itemList) {
            if (!itemList || !itemList.length) return '';
            const missingOnes = itemList.filter(x => !x.exists && !x.conflict).length;

            let h = '<div class="card mt-3"><div class="card-header d-flex justify-content-between '
                  + 'align-items-center flex-wrap gap-2"><span><i class="fas fa-wand-magic-sparkles me-2" aria-hidden="true"></i>'
                  + '<strong>' + escHtml(t('ad.optTitle')) + '</strong>'
                  + '<span class="small text-muted ms-2">' + escHtml(t('ad.optSubtitle')) + '</span></span>'
                  + (missingOnes > 1
                     ? '<button class="btn btn-sm btn-outline-success" data-on-click="autoDnsCreateAllOptional()">'
                       + '<i class="fas fa-cloud-arrow-up me-1" aria-hidden="true"></i>' + escHtml(t('ad.createAllMissing', { n: missingOnes })) + '</button>'
                     : '')
                  + '</div><div class="card-body">'
                  + '<div class="table-responsive"><table class="table table-sm align-middle mb-2"><thead><tr>'
                  + '<th scope="col">Record</th><th scope="col">' + escHtml(t('ad.colInCf')) + '</th><th scope="col">' + escHtml(t('ad.colWouldWrite')) + '</th><th scope="col"><span class="visually-hidden">' + escHtml(t('home.colActions')) + '</span></th>'
                  + '</tr></thead><tbody>';

            itemList.forEach(x => {
                let state;
                if (x.conflict) state = '<span class="badge bg-danger">' + escHtml(t('ad.conflict')) + '</span>';
                else if (x.exists) state = '<span class="badge bg-success">' + escHtml(t('ad.exists')) + '</span>';
                else state = '<span class="badge bg-warning text-dark">' + escHtml(t('ad.missing')) + '</span>';
                if (x.content)
                    state += '<div class="small mt-1" data-style="word-break:break-all"><code>'
                           + adEsc(x.content) + '</code></div>';

                const actionItem = (x.exists || x.conflict)
                    ? '<span class="small text-muted">' + escHtml(x.exists ? t('ad.nothingToDo') : t('ad.byHand')) + '</span>'
                    : '<button class="btn btn-sm btn-outline-success" data-on-click="autoDnsCreateOptional(\'' + adEsc(x.which) + '\')">'
                      + '<i class="fas fa-cloud-arrow-up me-1" aria-hidden="true"></i>' + escHtml(t('ad.create')) + '</button>';

                h += '<tr class="upd-cell"><td><strong>' + adEsc(x.type) + '</strong><br>'
                   + '<code class="small">' + adEsc(x.name) + '</code>'
                   + '<div class="small text-muted mt-1">' + adEsc(x.purpose) + '</div>'
                   + (x.premise
                      ? '<div class="small mt-1"><i class="fas fa-circle-info me-1 text-secondary" aria-hidden="true"></i>'
                        + '<span class="text-secondary">' + adEsc(x.premise) + '</span></div>'
                      : '') + '</td>'
                   + '<td>' + state + '</td>'
                   + '<td><code class="small" data-style="word-break:break-all">' + adEsc(x.proposed) + '</code></td>'
                   + '<td class="text-end">' + actionItem + '</td></tr>';

                if (x.warning || x.conflict)
                    h += '<tr><td colspan="4" class="pt-0">'
                       + adWarnings([x.warning || x.conflict]) + '</td></tr>';
            });

            h += '</tbody></table></div><div id="adOpzOutcome"></div>';

            // Here there was a fixed box: "MTA-STS is not created by the panel, because that site
            // does not serve it". It was true when it was written and stopped being true the day
            // the panel started serving the policy on 443, but the sentence stayed,
            // and the DNS page kept denying something the panel does routinely.
            // Now "Set up everything" runs the whole MTA-STS chain for this domain, so
            // there is no exception to explain: there is a button to press.
            return h + '</div></div>';
        }

        async function autoDnsCreateOptional(which) {
            const el = document.getElementById('adOpzOutcome');
            if (!await adConfirm(t('ad.confirmOpt'), t('ad.wordCreate'))) return;
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('ad.writingCf'));
            const r = await autoDnsApi('create_optional', { confirm: 'CREATE', which: which });
            el.innerHTML = '<div class="alert alert-' + (r.success ? 'success' : 'danger') + ' py-2 small mb-0">'
                         + adEsc(r.note || r.error) + '</div>';
            if (r.success) setTimeout(autoDnsLoad, 1200);
        }

        // Creates the missing ones in a row. One at a time and not all together: if the third
        // fails it must be possible to say WHICH one failed and why, not "something went wrong".
        async function autoDnsCreateAllOptional() {
            const el = document.getElementById('adOpzOutcome');
            const r0 = await autoDnsApi('status');
            const missingOnes = (r0.optionalItems || []).filter(x => !x.exists && !x.conflict);
            if (!missingOnes.length) { el.innerHTML = '<div class="alert alert-info py-2 small mb-0">' + escHtml(t('ad.nothingMissing')) + '</div>'; return; }
            if (!await adConfirm(tn('ad.confirmMany', missingOnes.length) + '\n\n'
                     + missingOnes.map(x => '• ' + x.type + ' ' + x.name).join('\n') + '\n\n'
                     + t('ad.noneTouched'), t('ad.wordCreate'))) return;

            let outcomes = '';
            for (const x of missingOnes) {
                el.innerHTML = outcomes + '<div class="small text-muted"><i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>'
                             + escHtml(t('ad.creatingName', { name: x.name })) + '</div>';
                const r = await autoDnsApi('create_optional', { confirm: 'CREATE', which: x.which });
                outcomes += '<div class="alert alert-' + (r.success ? 'success' : 'danger') + ' py-2 small mb-1">'
                       + '<code>' + adEsc(x.name) + '</code> &mdash; ' + adEsc(r.note || r.error) + '</div>';
            }
            el.innerHTML = outcomes;
            setTimeout(autoDnsLoad, 1500);
        }

        // Changes the policy of an already published DMARC. First the before/after is shown:
        // a confirmation that does not show what changes is not a confirmation.
        async function autoDnsChangePolicy() {
            const sel = document.getElementById('adPolicyNew');
            if (!sel) return;
            const fresh = sel.value;
            const el = document.getElementById('autoDnsOutcome');
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('ad.readingCurrent'));

            const a = await autoDnsApi('change_policy', { policy: fresh });
            if (!a.success) {
                el.innerHTML = '<div class="alert alert-danger py-2 small mb-0">' + adEsc(a.error) + '</div>';
                return;
            }
            if (a.unchanged) {
                el.innerHTML = '<div class="alert alert-info py-2 small mb-0">' + adEsc(a.note) + '</div>';
                return;
            }

            el.innerHTML = '<div class="alert alert-secondary py-2 small mb-0">'
                         + '<div class="mb-1">' + adEsc(a.note) + '</div>'
                         + '<div><span class="text-muted">' + escHtml(t('ad.before')) + '</span> <code data-style="word-break:break-all">'
                         + adEsc(a.before) + '</code></div>'
                         + '<div><span class="text-muted">' + escHtml(t('ad.after')) + '</span> <code data-style="word-break:break-all">'
                         + adEsc(a.after) + '</code></div></div>';

            const warning = fresh === 'reject' ? '\n\n' + t('ad.warnReject')
                : fresh === 'quarantine' ? '\n\n' + t('ad.warnQuarantine') : '';
            if (!await adConfirm(t('ad.confirmPolicy', { policy: fresh }) + '\n\n'
                     + t('ad.before') + '  ' + a.before + '\n'
                     + t('ad.after') + '  ' + a.after + '\n\n'
                     + t('ad.onlyP')
                     + warning, t('ad.wordChange'))) return;

            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('ad.editingCf'));
            const r = await autoDnsApi('change_policy', { policy: fresh, confirm: 'CHANGE' });
            el.innerHTML = '<div class="alert alert-' + (r.success ? 'success' : 'danger') + ' py-2 small mb-0">'
                         + adEsc(r.note || r.error) + '</div>';
            if (r.success) setTimeout(autoDnsLoad, 1500);
        }

        async function autoDnsCreate(which) {
            const sel = document.getElementById('adPolicy');
            const policy = (sel && sel.value) ? sel.value : 'none';
            const whichLabel = which === 'spf' ? 'SPF' : 'DMARC (p=' + policy + ')';
            if (!await adConfirm(t('ad.confirmCreate', { record: whichLabel }), t('ad.wordCreate'))) return;
            const el = document.getElementById('autoDnsOutcome');
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('ad.writingCf'));
            const r = await autoDnsApi('create', { confirm: 'CREATE', which: which, policy: policy });
            let h = '<div class="alert alert-' + (r.success ? 'success' : 'danger') + ' py-2 small mb-1">'
                  + adEsc(r.note || r.error) + '</div>';
            if (r.content)
                h += '<div class="small text-muted mb-1">' + escHtml(t('ad.alreadyThere')) + ' <code data-style="word-break:break-all">'
                   + adEsc(r.content) + '</code></div>';
            if (r.name && r.value)
                h += '<div class="small text-muted"><code>' + adEsc(r.name) + '</code> &rarr; <code '
                   + 'data-style="word-break:break-all">' + adEsc(r.value) + '</code></div>';
            el.innerHTML = h;
            if (r.success) setTimeout(autoDnsLoad, 1200);
            else if (r.mailboxMissing) setTimeout(autoDnsLoad, 300);
        }

        // Everything a domain needs, at once. No step overwrites
        // anything: it can be pressed even on a half-configured domain, it finds what
        // is already there and adds only the rest.
        async function autoDnsConfigureAll() {
            if (!currentDomainId) return;
            if (!await adConfirm(t('ad.confirmAll'), t('ad.wordConfigure'))) return;
            if (adLoading) await adLoading;

            let el = document.getElementById('autoDnsOutcome');
            if (!el) {
                // The card has not been read yet, or Cloudflare answered with an error: the place for the job
                // is created here, or the button, after the confirmation, would do nothing (finding 249)
                el = document.createElement('div');
                el.id = 'autoDnsOutcome';
                el.className = 'mt-2';
                el.setAttribute('aria-live', 'polite');
                document.getElementById('autoDnsBody').appendChild(el);
            }
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('ad.starting'));
            const r = await autoDnsApi('configure_all', { confirm: 'CONFIGURE' });
            if (!r.success || !r.jobId) {
                el.innerHTML = '<div class="alert alert-danger py-2 small mb-0">'
                             + adEsc(r.error || t('ad.startFailed')) + '</div>';
                return;
            }
            // The request returns AT ONCE with an identifier. The sequence includes waiting
            // for DNS propagation and can last minutes: keeping the request open, the
            // browser would receive the proxy's error page while on the server the job
            // goes on, and nobody would know any more how it ended.
            el.innerHTML = '<div class="alert alert-info py-2 small mb-2">'
                         + '<i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('ad.running')) + '</div>'
                         + '<pre id="adLog" class="small p-2 border rounded mb-0" '
                         + 'data-style="max-height:26rem;overflow:auto"></pre>';
            adFollow(r.jobId);
        }

        async function adFollow(id) {
            const el = document.getElementById('autoDnsOutcome');
            const pre = document.getElementById('adLog');
            const s = await autoDnsApi('job_status', { jobId: id });
            if (s.success && s.job) {
                if (pre) { pre.textContent = s.job.consoleLog || ''; pre.scrollTop = pre.scrollHeight; }
                if (s.job.status === 'completed' || s.job.status === 'error') {
                    // The card MUST be reloaded, and the log must NOT be lost: they are two real
                    // needs and before only one of them was met.
                    //
                    // Leaving it as it was, the snapshot from before the job stayed on screen.
                    // That is how the panel kept writing "The report mailbox is missing, choose
                    // one of the two ways" twenty seconds after creating that alias itself,
                    // and whoever pressed was told "already exists".
                    // Asking for an action already done, and saying so only after it has been
                    // attempted, is worse than saying nothing: it makes what worked look broken.
                    //
                    // The log is inside the container that is redrawn, so it is set
                    // aside and put back into the new card.
                    // Reached the end with some steps out of order: a warning, not green (finding 250)
                    const allDone = s.job.status === 'completed' && !s.job.result;
                    const line = (allDone
                            ? '<i class="fas fa-check-circle me-1" aria-hidden="true"></i>' + escHtml(t('ad.done', { s: s.job.elapsedSeconds }))
                            : s.job.status === 'completed'
                            ? '<i class="fas fa-triangle-exclamation me-1" aria-hidden="true"></i>' + escHtml(s.job.result)
                            : '<i class="fas fa-triangle-exclamation me-1" aria-hidden="true"></i>' + escHtml(t('ad.stopped', { message: s.job.errorMessage })));
                    const logLines = pre ? pre.textContent : '';
                    await autoDnsLoad();
                    const freshRead = document.getElementById('autoDnsOutcome');
                    if (freshRead) {
                        const p = document.createElement('pre');
                        p.className = 'small p-2 border rounded mb-0';
                        p.style.maxHeight = '26rem';
                        p.style.overflow = 'auto';
                        p.textContent = logLines;
                        freshRead.innerHTML = '<div class="alert alert-'
                            + (allDone ? 'success' : 'warning')
                            + ' py-2 small mb-2">' + line + '</div>';
                        freshRead.appendChild(p);
                    }
                    return;
                }
            }
            setTimeout(() => adFollow(id), 3000);
        }
