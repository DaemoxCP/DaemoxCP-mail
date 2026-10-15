        // ---------- rapporto periodico via email ----------
        // Sta nelle IMPOSTAZIONI perche' destinatario, mittente e frequenza sono scelte, non
        // diagnosi. Il contenuto del rapporto lo raccoglie la pagina Aggiornamenti, ma
        // deciderlo e' un'altra cosa dal leggerlo.
        async function repApi(azione, extra) {
            const corpo = Object.assign({ action: azione }, extra || {});
            const r = await fetch('/api/report', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(corpo)
            });
            return await r.json();
        }

        // Conferma scritta: la parola si mostra nella lingua della pagina, al server va il suo codice.
        function repConferma(testo, parola) {
            const typed = prompt(testo + '\n\n' + t('ad.typeToConfirm', { word: parola }));
            return typed !== null && typed.trim().toUpperCase() === parola.toUpperCase();
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
        function mittenteScelta(s, id) {
            const scelte = (id && id.caselleDisponibili) || [];
            const dom = (id && id.dominioDelPannello) || '';
            if (!id || !id.dominioDelPannelloGestito) {
                return '<div class="form-control form-control-sm bg-transparent border-warning small" id="repFrom-none">'
                     + escHtml(dom ? t('rep.domainNotManagedNamed', { domain: dom }) : t('rep.domainNotManaged')) + '</div>';
            }
            if (!scelte.length) {
                return '<div class="form-control form-control-sm bg-transparent border-warning small" id="repFrom-none">'
                     + escHtml(t('rep.noMailbox', { domain: dom })) + '</div>';
            }
            return '<select class="form-select form-select-sm" id="repFrom">'
                 + scelte.map(x => '<option value="' + repEsc(x) + '"'
                     + (s.mittente === x ? ' selected' : '') + '>' + repEsc(x) + '</option>').join('')
                 + '</select>';
        }

        async function repCarica() {
            const el = document.getElementById('rep-body');
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('rep.reading')) + '';
            const [s, id] = await Promise.all([repApi('status'), repApi('identity')]);
            if (!s.success) { el.innerHTML = '<span class="text-danger">' + repEsc(s.error) + '</span>'; return; }

            // --- identita' del pannello ---
            let h = '<h6 class="mb-1">' + escHtml(t('rep.identity')) + '</h6>';
            if (!id.success) {
                h += '<div class="alert alert-warning py-2 small mb-2">' + repEsc(id.error) + '</div>';
            } else {
                const cls = id.esiste ? 'success' : (id.dominioGestito ? 'warning' : 'danger');
                h += '<div class="alert alert-' + cls + ' py-2 small mb-2">'
                   + '<code>' + repEsc(id.mittente || t('rep.toSet')) + '</code><br>' + repEsc(id.nota) + '</div>';
                // Il pulsante per creare compare SOLO se l'indirizzo e' libero davvero:
                // ne' casella ne' alias. Prima guardava solo le caselle.
                if (id.creabile && !id.esiste && id.mittente) {
                    h += '<button class="btn btn-sm btn-outline-success mb-2" data-address="' + escHtml(id.mittente) + '" onclick="repCreaIdentita(this.dataset.address)">'
                       + '<i class="fas fa-user-plus me-1" aria-hidden="true"></i>' + escHtml(t('rep.createMailbox', { address: id.mittente })) + '</button>';
                }
                const dm = id.dominiGestiti || [];
                if (dm.length) h += '<div class="small text-muted mb-2">' + escHtml(t('rep.managedDomains', { domains: dm.join(', ') })) + '</div>';
            }

            // --- impostazioni ---
            // I valori restano quelli del server; il nome si mostra nella lingua della pagina.
            const freq = [['giornaliero', t('rep.daily')], ['settimanale', t('rep.weekly')], ['mensile', t('rep.monthly')]];
            h += '<div id="rep-esito-identita"></div>'
               + '<hr><h6 class="mb-2">' + escHtml(t('rep.whenWho')) + '</h6>'
               + '<div class="row g-2 align-items-end">'
               + '<div class="col-md-4"><label class="form-label small mb-1" for="repFrom">' + escHtml(t('rep.from')) + '</label>'
               + mittenteScelta(s, id) + '</div>'
               + '<div class="col-md-4"><label class="form-label small mb-1" for="repTo">' + escHtml(t('rep.to')) + '</label>'
               + '<input type="email" class="form-control form-control-sm" id="repTo" maxlength="254" placeholder="' + escHtml(t('rep.toPlaceholder')) + '" value="'
               + escHtml(s.destinatario || '') + '"></div>'
               + '<div class="col-md-2"><label class="form-label small mb-1" for="repFreq">' + escHtml(t('rep.frequency')) + '</label>'
               + '<select class="form-select form-select-sm" id="repFreq">'
               + freq.map(f => '<option value="' + f[0] + '"' + (s.frequenza === f[0] ? ' selected' : '') + '>' + escHtml(f[1]) + '</option>').join('')
               + '</select></div>'
               + '<div class="col-md-2"><label class="form-label small mb-1" for="repHour">' + escHtml(t('rep.notBefore')) + '</label>'
               + '<select class="form-select form-select-sm" id="repHour">'
               + Array.from({length: 24}, (_, i) => '<option value="' + i + '"' + (String(s.ora) === String(i) ? ' selected' : '') + '>' + String(i).padStart(2, '0') + ':00</option>').join('')
               + '</select></div>'
               + '</div>'
               + '<div class="form-check mt-2"><input class="form-check-input" type="checkbox" id="repOn"'
               + (s.attivo ? ' checked' : '') + '><label class="form-check-label small" for="repOn">'
               + escHtml(t('rep.auto')) + '</label></div>'
               + '<div class="mt-2">'
               + '<button class="btn btn-sm btn-success me-1" onclick="repSalva()"><i class="fas fa-floppy-disk me-1" aria-hidden="true"></i>' + escHtml(t('common.save')) + '</button>'
               + '<button class="btn btn-sm btn-outline-primary" onclick="repProva()"><i class="fas fa-paper-plane me-1" aria-hidden="true"></i>' + escHtml(t('rep.sendTest')) + '</button>'
               + '</div>'
               + '<div id="rep-esito" class="mt-2"></div>'
               + '<div class="small text-muted mt-2">' + repEsc(s.prossimo) + '</div>';
            if (s.ultimoEsito) h += '<div class="small text-muted">' + escHtml(t('rep.lastResult', { result: s.ultimoEsito })) + '</div>';
            el.innerHTML = h;
        }

        async function repCreaIdentita(indirizzo) {
            if (!repConferma(t('rep.confirmCreate', { address: indirizzo }), t('ad.wordCreate'))) return;
            const el = document.getElementById('rep-esito-identita');
            el.innerHTML = '<i class="fas fa-spinner fa-spin" aria-hidden="true"></i><span class="visually-hidden">' + escHtml(t('sj.inProgress')) + '</span>';
            const r = await repApi('identity_create', { confirm: 'CREA', indirizzo: indirizzo });
            el.innerHTML = '<div class="alert alert-' + (r.success ? 'success' : 'danger') + ' py-2 small">'
                         + repEsc(r.nota || r.error) + '</div>';
            if (r.success) repCarica();
        }

        async function repSalva() {
            const el = document.getElementById('rep-esito');
            el.innerHTML = '<i class="fas fa-spinner fa-spin" aria-hidden="true"></i><span class="visually-hidden">' + escHtml(t('sj.inProgress')) + '</span>';
            const r = await repApi('save', {
                mittente: (document.getElementById('repFrom') || { value: '' }).value.trim(),
                destinatario: document.getElementById('repTo').value.trim(),
                frequenza: document.getElementById('repFreq').value,
                ora: document.getElementById('repHour').value,
                attivo: document.getElementById('repOn').checked
            });
            el.innerHTML = '<div class="alert alert-' + (r.success ? 'success' : 'danger') + ' py-2 small mb-0">'
                         + repEsc(r.nota || r.error) + '</div>';
            if (r.success) setTimeout(repCarica, 900);
        }

        async function repProva() {
            const a = document.getElementById('repTo').value.trim();
            if (!a) { alert(t('rep.needTo')); return; }
            if (!repConferma(t('rep.confirmSend', { address: a }), t('rep.wordSend'))) return;
            const el = document.getElementById('rep-esito');
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('rep.sending')) + '';
            const r = await repApi('send', { confirm: 'INVIA', destinatario: a });
            // Giallo quando Postfix l'ha preso ma non e' ancora arrivato, o non si sa: non e'
            // un errore, ma nemmeno la conferma che il verde prometterebbe.
            const cls = !r.success ? 'danger' : (r.avviso ? 'warning' : 'success');
            let h = '<div class="alert alert-' + cls + ' py-2 small mb-1">'
                  + repEsc(r.nota || r.error) + '</div>';
            if (r.oggetto) h += '<div class="small text-muted">' + escHtml(t('rep.subject')) + ' <code>' + repEsc(r.oggetto) + '</code></div>';
            if (r.output) h += '<pre class="upd-log mt-1">' + repEsc(r.output) + '</pre>';
            el.innerHTML = h;
        }

        async function repAnteprima() {
            const el = document.getElementById('rep-body');
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('rep.composing')) + '';
            const r = await repApi('preview');
            if (!r.success) { el.innerHTML = '<span class="text-danger">' + repEsc(r.error) + '</span>'; return; }
            el.innerHTML = '<div class="alert alert-info py-2 small">' + escHtml(t('rep.previewNote')) + '</div>'
                         + '<pre class="upd-log">' + repEsc(r.testo) + '</pre>'
                         + '<button class="btn btn-sm btn-outline-secondary" onclick="repCarica()">'
                         + '<i class="fas fa-arrow-left me-1" aria-hidden="true"></i>' + escHtml(t('rep.back')) + '</button>';
        }


