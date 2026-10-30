        // ---------- rapporto periodico via email ----------
        // Sta nelle IMPOSTAZIONI perche' destinatario, mittente e frequenza sono scelte, non
        // diagnosi. Il contenuto del rapporto lo raccoglie la pagina Aggiornamenti, ma
        // deciderlo e' un'altra cosa dal leggerlo.
        async function repApi(actionItem, extra) {
            const bodyText = Object.assign({ action: actionItem }, extra || {});
            const r = await fetch('/api/report', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(bodyText)
            });
            return await r.json();
        }

        // Conferma scritta: la parola si mostra nella lingua della pagina, al server va il suo codice.
        function repConfirm(textValue, keyword) {
            const typed = prompt(textValue + '\n\n' + t('ad.typeToConfirm', { word: keyword }));
            return typed !== null && typed.trim().toUpperCase() === keyword.toUpperCase();
        }

        function repEsc(v) {
            const d = document.createElement('div');
            d.textContent = v === null || v === undefined ? '' : String(v);
            return d.innerHTML;
        }

        // Il mittente NON e' un campo libero: le scelte valide le conosce il pannello, quindi
        // le offre. Un campo di testo permetterebbe di scriverci un dominio di un sito, che e'
        // l'errore gia' fatto una volta. Se sul dominio del pannello non c'e' nessuna casella,
        // l'elenco lo dice invece di restare vuoto e misterioso.
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

            // --- identita' del pannello ---
            let h = '<h6 class="mb-1">' + escHtml(t('rep.identity')) + '</h6>';
            if (!id.success) {
                h += '<div class="alert alert-warning py-2 small mb-2">' + repEsc(id.error) + '</div>';
            } else {
                const cls = id.exists ? 'success' : (id.managedDomain ? 'warning' : 'danger');
                h += '<div class="alert alert-' + cls + ' py-2 small mb-2">'
                   + '<code>' + repEsc(id.sender || t('rep.toSet')) + '</code><br>' + repEsc(id.note) + '</div>';
                // Il pulsante per creare compare SOLO se l'indirizzo e' libero davvero:
                // ne' casella ne' alias. Prima guardava solo le caselle.
                if (id.creatable && !id.exists && id.sender) {
                    h += '<button class="btn btn-sm btn-outline-success mb-2" data-address="' + escHtml(id.sender) + '" onclick="repCreateIdentity(this.dataset.address)">'
                       + '<i class="fas fa-user-plus me-1" aria-hidden="true"></i>' + escHtml(t('rep.createMailbox', { address: id.sender })) + '</button>';
                }
                const dm = id.managedDomains || [];
                if (dm.length) h += '<div class="small text-muted mb-2">' + escHtml(t('rep.managedDomains', { domains: dm.join(', ') })) + '</div>';
            }

            // --- impostazioni ---
            // I valori restano quelli del server; il nome si mostra nella lingua della pagina.
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
               + '<button class="btn btn-sm btn-success me-1" onclick="repSave()"><i class="fas fa-floppy-disk me-1" aria-hidden="true"></i>' + escHtml(t('common.save')) + '</button>'
               + '<button class="btn btn-sm btn-outline-primary" onclick="repTest()"><i class="fas fa-paper-plane me-1" aria-hidden="true"></i>' + escHtml(t('rep.sendTest')) + '</button>'
               + '</div>'
               + '<div id="rep-outcome" class="mt-2"></div>'
               + '<div class="small text-muted mt-2">' + repEsc(s.next) + '</div>';
            if (s.lastOutcome) h += '<div class="small text-muted">' + escHtml(t('rep.lastResult', { result: s.lastOutcome })) + '</div>';
            el.innerHTML = h;
        }

        async function repCreateIdentity(address) {
            if (!repConfirm(t('rep.confirmCreate', { address: address }), t('ad.wordCreate'))) return;
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
            if (!a) { alert(t('rep.needTo')); return; }
            if (!repConfirm(t('rep.confirmSend', { address: a }), t('rep.wordSend'))) return;
            const el = document.getElementById('rep-outcome');
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('rep.sending')) + '';
            const r = await repApi('send', { confirm: 'INVIA', recipient: a });
            // Giallo quando Postfix l'ha preso ma non e' ancora arrivato, o non si sa: non e'
            // un errore, ma nemmeno la conferma che il verde prometterebbe.
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
            el.innerHTML = '<div class="alert alert-info py-2 small">' + escHtml(t('rep.previewNote')) + '</div>'
                         + '<pre class="upd-log">' + repEsc(r.text) + '</pre>'
                         + '<button class="btn btn-sm btn-outline-secondary" onclick="repLoad()">'
                         + '<i class="fas fa-arrow-left me-1" aria-hidden="true"></i>' + escHtml(t('rep.back')) + '</button>';
        }


