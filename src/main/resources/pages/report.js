        // ---------- periodic report by email ----------
        // It is in the SETTINGS because recipient, sender and frequency are choices, not
        // diagnosis. The content of the report is gathered by the Updates page, but
        // deciding it is a different thing from reading it.
        async function repApi(actionItem, extra) {
            const bodyText = Object.assign({ action: actionItem }, extra || {});
            const r = await fetch('/api/report', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(bodyText)
            });
            return await r.json();
        }

        // The confirmation: the panel's window (finding 198), not the browser's prompt with the word to type. The
        // word still goes to the server, in the caller's code.
        function repConfirm(textValue) {
            return panelConfirm(textValue);
        }

        function repEsc(v) {
            const d = document.createElement('div');
            d.textContent = v === null || v === undefined ? '' : String(v);
            return d.innerHTML;
        }

        // The sender is NOT a free field: the panel knows the valid choices, so it
        // offers them. A text field would allow typing a website's domain into it, which is
        // the mistake already made once. If there is no mailbox on the panel's domain,
        // the list says so instead of staying empty and mysterious.
        function chosenSender(s, id) {
            const choices = (id && id.availableMailboxes) || [];
            const dom = (id && id.panelDomain) || '';
            if (!id || !id.panelDomainManaged) {
                return '<div class="form-control form-control-sm bg-transparent border-warning small" id="repFrom-none">'
                     + escHtml(dom ? t('rep.domainNotManagedNamed', { domain: dom }) : t('rep.domainNotManaged')) + '</div>';
            }
            if (!choices.length) {
                return '<div class="form-control form-control-sm bg-transparent border-warning small" id="repFrom-none">'
                     + escHtml(t('rep.noMailbox', { domain: dom })) + '</div>';
            }
            return '<select class="form-select form-select-sm" id="repFrom">'
                 + choices.map(x => '<option value="' + repEsc(x) + '"'
                     + (s.sender === x ? ' selected' : '') + '>' + repEsc(x) + '</option>').join('')
                 + '</select>';
        }

        async function repLoad() {
            const el = document.getElementById('rep-body');
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('rep.reading')) + '';
            const [s, id] = await Promise.all([repApi('status'), repApi('identity')]);
            if (!s.success) { el.innerHTML = '<span class="text-danger">' + repEsc(s.error) + '</span>'; return; }

            // --- the panel's identity ---
            let h = '<h6 class="mb-1">' + escHtml(t('rep.identity')) + '</h6>';
            if (!id.success) {
                h += '<div class="alert alert-warning py-2 small mb-2">' + repEsc(id.error) + '</div>';
            } else {
                const cls = id.exists ? 'success' : (id.managedDomain ? 'warning' : 'danger');
                h += '<div class="alert alert-' + cls + ' py-2 small mb-2">'
                   + '<code>' + repEsc(id.sender || t('rep.toSet')) + '</code><br>' + repEsc(id.note) + '</div>';
                // The button to create appears ONLY if the address is really free:
                // neither a mailbox nor an alias. Before, it looked only at mailboxes.
                if (id.creatable && !id.exists && id.sender) {
                    h += '<button class="btn btn-sm btn-outline-success mb-2" data-address="' + escHtml(id.sender) + '" data-on-click="repCreateIdentity(this.dataset.address)">'
                       + '<i class="fas fa-user-plus me-1" aria-hidden="true"></i>' + escHtml(t('rep.createMailbox', { address: id.sender })) + '</button>';
                }
                const dm = id.managedDomains || [];
                if (dm.length) h += '<div class="small text-muted mb-2">' + escHtml(t('rep.managedDomains', { domains: dm.join(', ') })) + '</div>';
            }

            // --- settings ---
            // The values remain the server's; the name is shown in the page's language.
            const freq = [['daily', t('rep.daily')], ['weekly', t('rep.weekly')], ['monthly', t('rep.monthly')]];
            h += '<div id="rep-outcome-identity"></div>'
               + '<hr><h6 class="mb-2">' + escHtml(t('rep.whenWho')) + '</h6>'
               + '<div class="row g-2 align-items-end">'
               + '<div class="col-md-4"><label class="form-label small mb-1" for="repFrom">' + escHtml(t('rep.from')) + '</label>'
               + chosenSender(s, id) + '</div>'
               + '<div class="col-md-4"><label class="form-label small mb-1" for="repTo">' + escHtml(t('rep.to')) + '</label>'
               + '<input type="email" class="form-control form-control-sm" id="repTo" maxlength="254" placeholder="' + escHtml(t('rep.toPlaceholder')) + '" value="'
               + escHtml(s.recipient || '') + '"></div>'
               + '<div class="col-md-2"><label class="form-label small mb-1" for="repFreq">' + escHtml(t('rep.frequency')) + '</label>'
               + '<select class="form-select form-select-sm" id="repFreq">'
               + freq.map(f => '<option value="' + f[0] + '"' + (s.frequency === f[0] ? ' selected' : '') + '>' + escHtml(f[1]) + '</option>').join('')
               + '</select></div>'
               + '<div class="col-md-2"><label class="form-label small mb-1" for="repHour">' + escHtml(t('rep.notBefore')) + '</label>'
               + '<select class="form-select form-select-sm" id="repHour">'
               + Array.from({length: 24}, (_, i) => '<option value="' + i + '"' + (String(s.now) === String(i) ? ' selected' : '') + '>' + String(i).padStart(2, '0') + ':00</option>').join('')
               + '</select></div>'
               + '</div>'
               + '<div class="form-check mt-2"><input class="form-check-input" type="checkbox" id="repOn"'
               + (s.active ? ' checked' : '') + '><label class="form-check-label small" for="repOn">'
               + escHtml(t('rep.auto')) + '</label></div>'
               + '<div class="mt-2">'
               + '<button class="btn btn-sm btn-success me-1" data-on-click="repSave()"><i class="fas fa-floppy-disk me-1" aria-hidden="true"></i>' + escHtml(t('common.save')) + '</button>'
               + '<button class="btn btn-sm btn-outline-primary" data-on-click="repTest()"><i class="fas fa-paper-plane me-1" aria-hidden="true"></i>' + escHtml(t('rep.sendTest')) + '</button>'
               + '</div>'
               + '<div id="rep-outcome" class="mt-2"></div>'
               + '<div class="small text-muted mt-2">' + repEsc(s.next) + '</div>';
            if (s.lastOutcome) h += '<div class="small text-muted">' + escHtml(t('rep.lastResult', { result: s.lastOutcome })) + '</div>';
            el.innerHTML = h;
        }

        async function repCreateIdentity(address) {
            if (!await repConfirm(t('rep.confirmCreate', { address: address }), t('ad.wordCreate'))) return;
            const el = document.getElementById('rep-outcome-identity');
            el.innerHTML = '<i class="fas fa-spinner fa-spin" aria-hidden="true"></i><span class="visually-hidden">' + escHtml(t('sj.inProgress')) + '</span>';
            const r = await repApi('identity_create', { confirm: 'CREATE', address: address });
            el.innerHTML = '<div class="alert alert-' + (r.success ? 'success' : 'danger') + ' py-2 small">'
                         + repEsc(r.note || r.error) + '</div>';
            if (r.success) repLoad();
        }

        async function repSave() {
            const el = document.getElementById('rep-outcome');
            el.innerHTML = '<i class="fas fa-spinner fa-spin" aria-hidden="true"></i><span class="visually-hidden">' + escHtml(t('sj.inProgress')) + '</span>';
            const r = await repApi('save', {
                sender: (document.getElementById('repFrom') || { value: '' }).value.trim(),
                recipient: document.getElementById('repTo').value.trim(),
                frequency: document.getElementById('repFreq').value,
                now: document.getElementById('repHour').value,
                active: document.getElementById('repOn').checked
            });
            el.innerHTML = '<div class="alert alert-' + (r.success ? 'success' : 'danger') + ' py-2 small mb-0">'
                         + repEsc(r.note || r.error) + '</div>';
            if (r.success) setTimeout(repLoad, 900);
        }

        async function repTest() {
            const a = document.getElementById('repTo').value.trim();
            if (!a) { panelSay('warning', t('rep.needTo')); return; }
            if (!await repConfirm(t('rep.confirmSend', { address: a }), t('rep.wordSend'))) return;
            const el = document.getElementById('rep-outcome');
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('rep.sending')) + '';
            const r = await repApi('send', { confirm: 'SEND', recipient: a });
            // Yellow when Postfix has accepted it but it has not arrived yet, or it is unknown: it is not
            // an error, but not the confirmation that green would promise either.
            const cls = !r.success ? 'danger' : (r.warning ? 'warning' : 'success');
            let h = '<div class="alert alert-' + cls + ' py-2 small mb-1">'
                  + repEsc(r.note || r.error) + '</div>';
            if (r.subject) h += '<div class="small text-muted">' + escHtml(t('rep.subject')) + ' <code>' + repEsc(r.subject) + '</code></div>';
            if (r.output) h += '<pre class="upd-log mt-1">' + repEsc(r.output) + '</pre>';
            el.innerHTML = h;
        }

        async function repPreview() {
            const el = document.getElementById('rep-body');
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('rep.composing')) + '';
            const r = await repApi('preview');
            if (!r.success) { el.innerHTML = '<span class="text-danger">' + repEsc(r.error) + '</span>'; return; }
            // Sender and subject as the recipient will see them: they are the first thing they read.
            el.innerHTML = '<div class="alert alert-info py-2 small">' + escHtml(t('rep.previewNote')) + '</div>'
                         + '<div class="small text-muted">' + escHtml(t('rep.previewFrom')) + ' <code>' + repEsc(r.from) + '</code></div>'
                         + '<div class="small text-muted mb-2">' + escHtml(t('rep.subject')) + ' <code>' + repEsc(r.subject) + '</code></div>'
                         + '<pre class="upd-log">' + repEsc(r.text) + '</pre>'
                         + '<button class="btn btn-sm btn-outline-secondary" data-on-click="repLoad()">'
                         + '<i class="fas fa-arrow-left me-1" aria-hidden="true"></i>' + escHtml(t('rep.back')) + '</button>';
        }


