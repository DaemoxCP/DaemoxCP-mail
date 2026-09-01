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

        function repEsc(t) {
            const d = document.createElement('div');
            d.textContent = t === null || t === undefined ? '' : String(t);
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
                return '<div class="form-control form-control-sm bg-transparent border-warning small">'
                     + 'Il dominio di questo pannello' + (dom ? ' (' + repEsc(dom) + ')' : '')
                     + ' non &egrave; fra quelli gestiti: aggiungilo in Domini.</div>';
            }
            if (!scelte.length) {
                return '<div class="form-control form-control-sm bg-transparent border-warning small">'
                     + 'Nessuna casella su <code>' + repEsc(dom) + '</code>: creane una qui sopra.</div>';
            }
            return '<select class="form-select form-select-sm" id="repFrom">'
                 + scelte.map(x => '<option value="' + repEsc(x) + '"'
                     + (s.mittente === x ? ' selected' : '') + '>' + repEsc(x) + '</option>').join('')
                 + '</select>';
        }

        async function repCarica() {
            const el = document.getElementById('rep-body');
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1"></i>Leggo le impostazioni...';
            const [s, id] = await Promise.all([repApi('status'), repApi('identity')]);
            if (!s.success) { el.innerHTML = '<span class="text-danger">' + repEsc(s.error) + '</span>'; return; }

            // --- identita' del pannello ---
            let h = '<h6 class="mb-1">L&rsquo;identit&agrave; del pannello</h6>';
            if (!id.success) {
                h += '<div class="alert alert-warning py-2 small mb-2">' + repEsc(id.error) + '</div>';
            } else {
                const cls = id.esiste ? 'success' : (id.dominioGestito ? 'warning' : 'danger');
                h += '<div class="alert alert-' + cls + ' py-2 small mb-2">'
                   + '<code>' + repEsc(id.mittente || '(da impostare)') + '</code><br>' + repEsc(id.nota) + '</div>';
                // Il pulsante per creare compare SOLO se l'indirizzo e' libero davvero:
                // ne' casella ne' alias. Prima guardava solo le caselle.
                if (id.creabile && !id.esiste && id.mittente) {
                    h += '<button class="btn btn-sm btn-outline-success mb-2" onclick="repCreaIdentita(\''
                       + repEsc(id.mittente) + '\')"><i class="fas fa-user-plus me-1"></i>Crea la casella '
                       + repEsc(id.mittente) + '</button>';
                }
                const dm = id.dominiGestiti || [];
                if (dm.length) h += '<div class="small text-muted mb-2">Domini gestiti da questo pannello: '
                    + dm.map(repEsc).join(', ') + '</div>';
            }

            // --- impostazioni ---
            const freq = ['giornaliero', 'settimanale', 'mensile'];
            h += '<div id="rep-esito-identita"></div>'
               + '<hr><h6 class="mb-2">Quando e a chi</h6>'
               + '<div class="row g-2 align-items-end">'
               + '<div class="col-md-4"><label class="form-label small mb-1">Mittente</label>'
               + mittenteScelta(s, id) + '</div>'
               + '<div class="col-md-4"><label class="form-label small mb-1">Destinatario</label>'
               + '<input type="email" class="form-control form-control-sm" id="repTo" placeholder="tu@esempio.it" value="'
               + repEsc(s.destinatario || '') + '"></div>'
               + '<div class="col-md-2"><label class="form-label small mb-1">Ogni</label>'
               + '<select class="form-select form-select-sm" id="repFreq">'
               + freq.map(f => '<option value="' + f + '"' + (s.frequenza === f ? ' selected' : '') + '>' + f + '</option>').join('')
               + '</select></div>'
               + '<div class="col-md-2"><label class="form-label small mb-1">Non prima delle</label>'
               + '<select class="form-select form-select-sm" id="repHour">'
               + Array.from({length: 24}, (_, i) => '<option value="' + i + '"' + (String(s.ora) === String(i) ? ' selected' : '') + '>' + String(i).padStart(2, '0') + ':00</option>').join('')
               + '</select></div>'
               + '</div>'
               + '<div class="form-check mt-2"><input class="form-check-input" type="checkbox" id="repOn"'
               + (s.attivo ? ' checked' : '') + '><label class="form-check-label small" for="repOn">'
               + 'Invia il rapporto automaticamente</label></div>'
               + '<div class="mt-2">'
               + '<button class="btn btn-sm btn-success me-1" onclick="repSalva()"><i class="fas fa-floppy-disk me-1"></i>Salva</button>'
               + '<button class="btn btn-sm btn-outline-primary" onclick="repProva()"><i class="fas fa-paper-plane me-1"></i>Invia adesso una prova</button>'
               + '</div>'
               + '<div id="rep-esito" class="mt-2"></div>'
               + '<div class="small text-muted mt-2">' + repEsc(s.prossimo) + '</div>';
            if (s.ultimoEsito) h += '<div class="small text-muted">Esito dell&rsquo;ultimo invio: ' + repEsc(s.ultimoEsito) + '</div>';
            el.innerHTML = h;
        }

        async function repCreaIdentita(indirizzo) {
            if (prompt('Creare la casella "' + indirizzo + '" su questo server?\n\n'
                     + 'Serve perch\u00e9 i rapporti partano da un mittente reale.\n'
                     + 'Scrivi CREA per confermare.') !== 'CREA') return;
            const el = document.getElementById('rep-esito-identita');
            el.innerHTML = '<i class="fas fa-spinner fa-spin"></i>';
            const r = await repApi('identity_create', { confirm: 'CREA', indirizzo: indirizzo });
            el.innerHTML = '<div class="alert alert-' + (r.success ? 'success' : 'danger') + ' py-2 small">'
                         + repEsc(r.nota || r.error) + '</div>';
            if (r.success) repCarica();
        }

        async function repSalva() {
            const el = document.getElementById('rep-esito');
            el.innerHTML = '<i class="fas fa-spinner fa-spin"></i>';
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
            if (!a) { alert('Serve un destinatario.'); return; }
            if (prompt('Inviare adesso un rapporto a "' + a + '"?\n\n'
                     + 'Scrivi INVIA per confermare.') !== 'INVIA') return;
            const el = document.getElementById('rep-esito');
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1"></i>Raccolgo i dati e invio: ci vuole un minuto...';
            const r = await repApi('send', { confirm: 'INVIA', destinatario: a });
            let h = '<div class="alert alert-' + (r.success ? 'success' : 'danger') + ' py-2 small mb-1">'
                  + repEsc(r.nota || r.error) + '</div>';
            if (r.oggetto) h += '<div class="small text-muted">Oggetto: <code>' + repEsc(r.oggetto) + '</code></div>';
            if (r.uscita) h += '<pre class="upd-log mt-1">' + repEsc(r.uscita) + '</pre>';
            el.innerHTML = h;
        }

        async function repAnteprima() {
            const el = document.getElementById('rep-body');
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1"></i>Compongo il rapporto senza inviarlo...';
            const r = await repApi('preview');
            if (!r.success) { el.innerHTML = '<span class="text-danger">' + repEsc(r.error) + '</span>'; return; }
            el.innerHTML = '<div class="alert alert-info py-2 small">Questo &egrave; il testo che verrebbe inviato. '
                         + 'Non &egrave; stato mandato niente.</div>'
                         + '<pre class="upd-log">' + repEsc(r.testo) + '</pre>'
                         + '<button class="btn btn-sm btn-outline-secondary" onclick="repCarica()">'
                         + '<i class="fas fa-arrow-left me-1"></i>Torna alle impostazioni</button>';
        }


