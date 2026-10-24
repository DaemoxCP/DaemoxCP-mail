        // ---------- SPF e DMARC creati dal pannello su Cloudflare ----------
        // Le regole non sono decorazione: due record SPF sullo stesso nome danno "permerror"
        // e SPF smette di funzionare (RFC 7208 §4.5); due DMARC vengono scartati entrambi
        // (RFC 9989). Per questo qui non si sovrascrive mai, e la domanda "esiste gia'?" e'
        // posta sul CONTENUTO del record, non sul suo nome.
        async function autoDnsApi(azione, extra) {
            const corpo = Object.assign({ action: azione, domain_id: parseInt(currentDomainId) }, extra || {});
            const r = await fetch('/api/autodns', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(corpo)
            });
            return await r.json();
        }

        // La conferma scritta: la parola e' nella lingua della pagina, il server riceve sempre il
        // suo codice fisso (CREA, CAMBIA, CONFIGURA) e non dipende dalla lingua.
        function adConferma(testo, parola) {
            const typed = prompt(testo + '\n\n' + t('ad.typeToConfirm', { word: parola }));
            return typed !== null && typed.trim().toUpperCase() === parola.toUpperCase();
        }

        function adEsc(v) {
            const d = document.createElement('div');
            d.textContent = v === null || v === undefined ? '' : String(v);
            return d.innerHTML;
        }

        function adAvvisi(lista) {
            if (!lista || !lista.length) return '';
            return '<div class="mt-2">' + lista.map(a =>
                '<div class="small d-flex gap-2 mb-1">'
                + '<i class="fas fa-triangle-exclamation text-warning mt-1" aria-hidden="true"></i>'
                + '<span>' + adEsc(a) + '</span></div>').join('') + '</div>';
        }

        async function autoDnsCarica() {
            const el = document.getElementById('autoDnsBody');
            if (!el) return;
            if (!currentDomainId) { el.innerHTML = '<span class="text-muted small">' + escHtml(t('dns.chooseDomainFirst')) + '</span>'; return; }
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('ad.askingCf'));
            const r = await autoDnsApi('status');
            if (!r.success) { el.innerHTML = '<div class="alert alert-danger py-2 small mb-0">' + adEsc(r.error) + '</div>'; return; }
            if (!r.cloudflare || !r.zone) {
                el.innerHTML = '<div class="alert alert-warning py-2 small mb-0">' + adEsc(r.note) + '</div>';
                return;
            }
            let h = '<div class="small text-muted mb-2">' + escHtml(t('ad.accountZone', { account: r.account, zone: r.domain })) + '</div>'
                  + '<div class="table-responsive"><table class="table table-sm align-middle mb-2"><thead><tr>'
                  + '<th scope="col">Record</th><th scope="col">' + escHtml(t('ad.colInCf')) + '</th><th scope="col">' + escHtml(t('ad.colWouldWrite')) + '</th><th scope="col"><span class="visually-hidden">' + escHtml(t('home.colActions')) + '</span></th>'
                  + '</tr></thead><tbody>';
            (r.record || []).forEach(x => {
                const nome = x.which === 'spf' ? 'SPF' : 'DMARC';
                const troppi = (x.howMany || 0) > 1;

                let state;
                if (troppi) state = '<span class="badge bg-danger">' + escHtml(t('ad.cancelOut', { n: x.howMany })) + '</span>';
                else if (x.exists) state = '<span class="badge bg-success">' + escHtml(t('ad.exists')) + '</span>';
                else state = '<span class="badge bg-warning text-dark">' + escHtml(t('ad.missing')) + '</span>';
                if (x.otherTxt > 0)
                    state += '<div class="small text-muted mt-1">' + escHtml(tn('ad.otherTxt', x.otherTxt)) + '</div>';
                if (x.content)
                    state += '<div class="small mt-1" style="word-break:break-all"><code>' + adEsc(x.content) + '</code></div>';

                let proposta;
                if (x.locked) {
                    proposta = '<div class="small text-danger">' + adEsc(x.locked) + '</div>';
                } else {
                    proposta = '<code class="small" style="word-break:break-all">' + adEsc(x.proposed) + '</code>';
                    if (x.which === 'dmarc' && !x.exists)
                        proposta += '<div class="mt-1"><select class="form-select form-select-sm" id="adPolitica" style="max-width:22rem" aria-label="' + escHtml(t('ad.policy')) + '">'
                                  + '<option value="none" selected>p=none &mdash; ' + escHtml(t('ad.pNone')) + '</option>'
                                  + '<option value="quarantine">p=quarantine &mdash; ' + escHtml(t('ad.pQuarantine')) + '</option>'
                                  + '<option value="reject">p=reject &mdash; ' + escHtml(t('ad.pReject')) + '</option>'
                                  + '</select>'
                                  + '<div class="small text-muted mt-1">' + escHtml(t('ad.pStart')) + '</div></div>';
                }

                let azione;
                if (x.which === 'dmarc' && x.exists && x.currentPolicy) {
                    // Il percorso e' none -> quarantine -> reject: il pannello deve rendere
                    // facile anche i due passi dopo il primo, non solo il primo.
                    const opz = ['none', 'quarantine', 'reject'].map(v =>
                        '<option value="' + v + '"' + (v === x.currentPolicy ? ' selected' : '') + '>p='
                        + v + '</option>').join('');
                    azione = '<select class="form-select form-select-sm mb-1" id="adPoliticaNuova" aria-label="' + escHtml(t('ad.policy')) + '">' + opz + '</select>'
                           + '<button class="btn btn-sm btn-outline-warning" onclick="autoDnsCambiaPolitica()">'
                           + '<i class="fas fa-pen me-1" aria-hidden="true"></i>' + escHtml(t('ad.changePolicy')) + '</button>';
                } else if (x.exists || x.locked) {
                    azione = '<span class="small text-muted">' + escHtml(x.exists ? t('ad.nothingToDo') : t('ad.cannotCreate')) + '</span>';
                } else {
                    azione = '<button class="btn btn-sm btn-outline-success" onclick="autoDnsCrea(\'' + adEsc(x.which) + '\')">'
                           + '<i class="fas fa-cloud-arrow-up me-1" aria-hidden="true"></i>' + escHtml(t('ad.create')) + '</button>';
                }

                h += '<tr class="upd-cell"><td><strong>' + escHtml(nome) + '</strong><br>'
                   + '<code class="small">' + adEsc(x.name) + '</code></td>'
                   + '<td>' + state + '</td><td>' + proposta + '</td>'
                   + '<td class="text-end">' + azione + '</td></tr>';

                if (x.warnings && x.warnings.length)
                    h += '<tr><td colspan="4" class="pt-0">' + adAvvisi(x.warnings) + '</td></tr>';
            });
            h += '</tbody></table></div><div id="autoDnsOutcome"></div>';

            h += adRapporti(r.reports);
            h += adOpzionali(r.optionalItems);

            h += '<div class="small text-muted mt-3">' + escHtml(t('ad.noRotation')) + '</div>';
            el.innerHTML = h;
            if (r.reports && !r.reports.exists) adCaricaCaselle();
        }

        // La cassetta a cui arrivano i rapporti DMARC. Va predisposta PRIMA di pubblicare il
        // record: appena il DMARC e' pubblico i rapporti partono, e se l'indirizzo non
        // esiste rimbalzano tutti (RFC 9989 §5.1.4).
        //
        // Due strade, perche' sono due scelte diverse e nessuna e' ovvia: girare la posta a
        // un indirizzo che gia' si legge, oppure tenere i rapporti in una casella loro.
        function adRapporti(rap) {
            if (!rap) return '';
            if (rap.exists) {
                return '<div class="alert alert-success py-2 small mb-0 mt-2">'
                     + '<i class="fas fa-inbox me-1" aria-hidden="true"></i>'
                     + escHtml(rap.destination ? t('ad.reportsToFwd', { address: rap.address, kind: rap.type, to: rap.destination }) : t('ad.reportsTo', { address: rap.address, kind: rap.type })) + '</div>';
            }
            return '<div class="card mt-2"><div class="card-body py-3">'
                 + '<div class="small mb-3"><i class="fas fa-inbox me-1" aria-hidden="true"></i>'
                 + '<strong>' + escHtml(t('ad.noReportBox')) + '</strong> ' + escHtml(t('ad.noReportBoxWhy', { address: rap.address })) + ' '
                 + adEsc(rap.note || '') + ' <strong>' + escHtml(t('ad.pickOne')) + '</strong></div>'

                 + '<div class="row g-3">'

                 // --- A: inoltro ---
                 + '<div class="col-lg-6"><div class="border rounded p-3 h-100">'
                 + '<div class="fw-bold mb-1"><i class="fas fa-share me-1" aria-hidden="true"></i>' + escHtml(t('ad.fwdTitle')) + '</div>'
                 + '<div class="small text-muted mb-3">' + escHtml(t('ad.fwdHint', { address: rap.address })) + ' <strong>' + escHtml(t('ad.recommended')) + '</strong></div>'
                 + '<label class="form-label small mb-1" for="adVerso">' + escHtml(t('ad.fwdTo', { address: rap.address })) + '</label>'
                 + '<select class="form-select form-select-sm mb-2" id="adVerso" onchange="adVersoCambia()">'
                 + '<option value="">' + escHtml(t('ad.loadingAddresses')) + '</option></select>'
                 + '<input type="email" class="form-control form-control-sm mb-2 d-none" id="adVersoAltro" '
                 + 'placeholder="' + escHtml(t('al.destPh')) + '" aria-label="' + escHtml(t('ad.otherAddress')) + '" autocomplete="off">'
                 + '<div class="small text-muted mb-2 d-none" id="adVersoAltroNota">' + escHtml(t('ad.otherAddressNote')) + '</div>'
                 + '<button class="btn btn-sm btn-outline-success" onclick="autoDnsCreaAlias()">'
                 + '<i class="fas fa-share me-1" aria-hidden="true"></i>' + escHtml(t('ad.createFwd')) + '</button>'
                 + '</div></div>'

                 // --- B: casella vera ---
                 + '<div class="col-lg-6"><div class="border rounded p-3 h-100">'
                 + '<div class="fw-bold mb-1"><i class="fas fa-inbox me-1" aria-hidden="true"></i>' + escHtml(t('ad.boxTitle', { address: rap.address })) + '</div>'
                 + '<div class="small text-muted mb-3">' + escHtml(t('ad.boxHint')) + '</div>'
                 + '<button class="btn btn-sm btn-outline-secondary" onclick="autoDnsCreaCasella()">'
                 + '<i class="fas fa-inbox me-1" aria-hidden="true"></i>' + escHtml(t('ad.createBox')) + '</button>'
                 + '</div></div>'

                 + '</div><div id="adAliasOutcome" class="mt-3"></div></div></div>';
        }

        function adVersoCambia() {
            const sel = document.getElementById('adVerso');
            const field = document.getElementById('adVersoAltro');
            const nota = document.getElementById('adVersoAltroNota');
            if (!sel || !field) return;
            const altro = sel.value === '__altro__';
            field.classList.toggle('d-none', !altro);
            if (nota) nota.classList.toggle('d-none', !altro);
            if (altro) field.focus();
        }

        // Gli indirizzi si scelgono da un elenco. Chi ne vuole uno diverso lo scrive, ma
        // deve chiederlo apposta: un campo libero come prima scelta e' il modo piu' rapido
        // per scrivere un indirizzo che non esiste e accorgersene fra sei mesi.
        async function adCaricaCaselle() {
            const sel = document.getElementById('adVerso');
            if (!sel) return;
            const r = await autoDnsApi('mailboxes');
            const caselle = (r.success && r.mailboxes) ? r.mailboxes : [];
            sel.innerHTML = '<option value="">&mdash; ' + escHtml(t('ad.chooseAddress')) + ' &mdash;</option>'
                + caselle.map(c => '<option value="' + adEsc(c) + '">' + adEsc(c) + '</option>').join('')
                + '<option value="__altro__">&mdash; ' + escHtml(t('ad.anotherAddress')) + ' &mdash;</option>';
        }

        function adVersoScelto() {
            const sel = document.getElementById('adVerso');
            if (!sel) return '';
            if (sel.value === '__altro__') {
                const field = document.getElementById('adVersoAltro');
                return field ? field.value.trim() : '';
            }
            return sel.value;
        }

        async function autoDnsCreaAlias() {
            const verso = adVersoScelto();
            const el = document.getElementById('adAliasOutcome');
            if (!verso) {
                el.innerHTML = '<div class="alert alert-warning py-2 small mb-0">' + escHtml(t('ad.chooseFirst')) + '</div>';
                return;
            }
            if (!adConferma(t('ad.confirmFwd', { to: verso }), t('ad.wordCreate'))) return;
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('ad.creatingFwd'));
            const r = await autoDnsApi('alias_create', { confirm: 'CREATE', destination: verso });
            el.innerHTML = '<div class="alert alert-' + (r.success ? 'success' : 'danger') + ' py-2 small mb-0">'
                         + adEsc(r.note || r.error) + '</div>';
            // Si ricarica anche quando il pannello si RIFIUTA: il rifiuto "esiste gia'" vuol
            // dire che lo stato a schermo era vecchio, ed e' proprio quello da rileggere.
            // Lasciare l'invito dov'e' inviterebbe a premere di nuovo.
            setTimeout(autoDnsCarica, 1000);
        }

        async function autoDnsCreaCasella() {
            const el = document.getElementById('adAliasOutcome');
            if (!adConferma(t('ad.confirmBox'), t('ad.wordCreate'))) return;
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('ad.creatingBox'));
            const r = await autoDnsApi('mailbox_create', { confirm: 'CREATE' });
            let h = '<div class="alert alert-' + (r.success ? 'success' : 'danger') + ' py-2 small mb-0">'
                  + adEsc(r.note || r.error) + '</div>';
            if (r.success && r.password)
                h += '<div class="alert alert-warning py-2 small mb-0 mt-2">'
                   + '<i class="fas fa-key me-1" aria-hidden="true"></i><strong>' + escHtml(t('ad.passwordOf', { address: r.address })) + '</strong> '
                   + '<code style="font-size:1.05em">' + adEsc(r.password) + '</code><br>'
                   + escHtml(t('ad.passwordKept')) + '</div>';
            el.innerHTML = h;
            // Non si ricarica da soli: la ricarica cancellerebbe la password dallo schermo.
            if (r.success) {
                const b = document.getElementById('autoDnsOutcome');
                if (b) b.innerHTML = '<div class="alert alert-info py-2 small mb-1">' + escHtml(t('ad.boxCreated')) + '</div>';
            }
        }


        // I record "opzionali": la posta funziona anche senza, ma senza di loro chi aggiunge
        // la casella deve sapere a memoria server, porte e tipo di cifratura. Sono gli stessi
        // valori della pagina DNS, letti dalla stessa impostazione: due modi di ricavare lo
        // stesso hostname sono due hostname che un giorno divergono.
        function adOpzionali(lista) {
            if (!lista || !lista.length) return '';
            const mancanti = lista.filter(x => !x.exists && !x.conflict).length;

            let h = '<div class="card mt-3"><div class="card-header d-flex justify-content-between '
                  + 'align-items-center flex-wrap gap-2"><span><i class="fas fa-wand-magic-sparkles me-2" aria-hidden="true"></i>'
                  + '<strong>' + escHtml(t('ad.optTitle')) + '</strong>'
                  + '<span class="small text-muted ms-2">' + escHtml(t('ad.optSubtitle')) + '</span></span>'
                  + (mancanti > 1
                     ? '<button class="btn btn-sm btn-outline-success" onclick="autoDnsCreaTuttiOpzionali()">'
                       + '<i class="fas fa-cloud-arrow-up me-1" aria-hidden="true"></i>' + escHtml(t('ad.createAllMissing', { n: mancanti })) + '</button>'
                     : '')
                  + '</div><div class="card-body">'
                  + '<div class="table-responsive"><table class="table table-sm align-middle mb-2"><thead><tr>'
                  + '<th scope="col">Record</th><th scope="col">' + escHtml(t('ad.colInCf')) + '</th><th scope="col">' + escHtml(t('ad.colWouldWrite')) + '</th><th scope="col"><span class="visually-hidden">' + escHtml(t('home.colActions')) + '</span></th>'
                  + '</tr></thead><tbody>';

            lista.forEach(x => {
                let state;
                if (x.conflict) state = '<span class="badge bg-danger">' + escHtml(t('ad.conflict')) + '</span>';
                else if (x.exists) state = '<span class="badge bg-success">' + escHtml(t('ad.exists')) + '</span>';
                else state = '<span class="badge bg-warning text-dark">' + escHtml(t('ad.missing')) + '</span>';
                if (x.content)
                    state += '<div class="small mt-1" style="word-break:break-all"><code>'
                           + adEsc(x.content) + '</code></div>';

                const azione = (x.exists || x.conflict)
                    ? '<span class="small text-muted">' + escHtml(x.exists ? t('ad.nothingToDo') : t('ad.byHand')) + '</span>'
                    : '<button class="btn btn-sm btn-outline-success" onclick="autoDnsCreaOpzionale(\'' + adEsc(x.which) + '\')">'
                      + '<i class="fas fa-cloud-arrow-up me-1" aria-hidden="true"></i>' + escHtml(t('ad.create')) + '</button>';

                h += '<tr class="upd-cell"><td><strong>' + adEsc(x.type) + '</strong><br>'
                   + '<code class="small">' + adEsc(x.name) + '</code>'
                   + '<div class="small text-muted mt-1">' + adEsc(x.purpose) + '</div>'
                   + (x.premise
                      ? '<div class="small mt-1"><i class="fas fa-circle-info me-1 text-secondary" aria-hidden="true"></i>'
                        + '<span class="text-secondary">' + adEsc(x.premise) + '</span></div>'
                      : '') + '</td>'
                   + '<td>' + state + '</td>'
                   + '<td><code class="small" style="word-break:break-all">' + adEsc(x.proposed) + '</code></td>'
                   + '<td class="text-end">' + azione + '</td></tr>';

                if (x.warning || x.conflict)
                    h += '<tr><td colspan="4" class="pt-0">'
                       + adAvvisi([x.warning || x.conflict]) + '</td></tr>';
            });

            h += '</tbody></table></div><div id="adOpzOutcome"></div>';

            // Qui c'era un riquadro fisso: "MTA-STS il pannello non lo crea, perche' quel sito
            // non lo serve". Era vero quando fu scritto e ha smesso di esserlo il giorno in cui
            // il pannello ha cominciato a servire la politica sulla 443 — ma la frase e' rimasta,
            // e la pagina DNS ha continuato a negare una cosa che il pannello fa di routine.
            // Adesso "Configura tutto" esegue l'intera catena MTA-STS per questo dominio, quindi
            // non c'e' nessuna eccezione da spiegare: c'e' un pulsante da premere.
            return h + '</div></div>';
        }

        async function autoDnsCreaOpzionale(quale) {
            const el = document.getElementById('adOpzOutcome');
            if (!adConferma(t('ad.confirmOpt'), t('ad.wordCreate'))) return;
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('ad.writingCf'));
            const r = await autoDnsApi('create_optional', { confirm: 'CREATE', which: quale });
            el.innerHTML = '<div class="alert alert-' + (r.success ? 'success' : 'danger') + ' py-2 small mb-0">'
                         + adEsc(r.note || r.error) + '</div>';
            if (r.success) setTimeout(autoDnsCarica, 1200);
        }

        // Crea in fila quelli che mancano. Uno per volta e non tutti insieme: se il terzo
        // fallisce si deve poter dire QUALE ha fallito e perché, non "qualcosa è andato storto".
        async function autoDnsCreaTuttiOpzionali() {
            const el = document.getElementById('adOpzOutcome');
            const r0 = await autoDnsApi('status');
            const mancanti = (r0.optionalItems || []).filter(x => !x.exists && !x.conflict);
            if (!mancanti.length) { el.innerHTML = '<div class="alert alert-info py-2 small mb-0">' + escHtml(t('ad.nothingMissing')) + '</div>'; return; }
            if (!adConferma(tn('ad.confirmMany', mancanti.length) + '\n\n'
                     + mancanti.map(x => '• ' + x.type + ' ' + x.name).join('\n') + '\n\n'
                     + t('ad.noneTouched'), t('ad.wordCreate'))) return;

            let esiti = '';
            for (const x of mancanti) {
                el.innerHTML = esiti + '<div class="small text-muted"><i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>'
                             + escHtml(t('ad.creatingName', { name: x.name })) + '</div>';
                const r = await autoDnsApi('create_optional', { confirm: 'CREATE', which: x.which });
                esiti += '<div class="alert alert-' + (r.success ? 'success' : 'danger') + ' py-2 small mb-1">'
                       + '<code>' + adEsc(x.name) + '</code> &mdash; ' + adEsc(r.note || r.error) + '</div>';
            }
            el.innerHTML = esiti;
            setTimeout(autoDnsCarica, 1500);
        }

        // Cambia la politica di un DMARC gia' pubblicato. Prima si guarda il prima/dopo:
        // una conferma che non fa vedere cosa cambia non e' una conferma.
        async function autoDnsCambiaPolitica() {
            const sel = document.getElementById('adPoliticaNuova');
            if (!sel) return;
            const nuova = sel.value;
            const el = document.getElementById('autoDnsOutcome');
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('ad.readingCurrent'));

            const a = await autoDnsApi('change_policy', { policy: nuova });
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
                         + '<div><span class="text-muted">' + escHtml(t('ad.before')) + '</span> <code style="word-break:break-all">'
                         + adEsc(a.before) + '</code></div>'
                         + '<div><span class="text-muted">' + escHtml(t('ad.after')) + '</span> <code style="word-break:break-all">'
                         + adEsc(a.after) + '</code></div></div>';

            const warning = nuova === 'reject' ? '\n\n' + t('ad.warnReject')
                : nuova === 'quarantine' ? '\n\n' + t('ad.warnQuarantine') : '';
            if (!adConferma(t('ad.confirmPolicy', { policy: nuova }) + '\n\n'
                     + t('ad.before') + '  ' + a.before + '\n'
                     + t('ad.after') + '  ' + a.after + '\n\n'
                     + t('ad.onlyP')
                     + warning, t('ad.wordChange'))) return;

            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('ad.editingCf'));
            const r = await autoDnsApi('change_policy', { policy: nuova, confirm: 'CHANGE' });
            el.innerHTML = '<div class="alert alert-' + (r.success ? 'success' : 'danger') + ' py-2 small mb-0">'
                         + adEsc(r.note || r.error) + '</div>';
            if (r.success) setTimeout(autoDnsCarica, 1500);
        }

        async function autoDnsCrea(quale) {
            const sel = document.getElementById('adPolitica');
            const politica = (sel && sel.value) ? sel.value : 'none';
            const che = quale === 'spf' ? 'SPF' : 'DMARC (p=' + politica + ')';
            if (!adConferma(t('ad.confirmCreate', { record: che }), t('ad.wordCreate'))) return;
            const el = document.getElementById('autoDnsOutcome');
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('ad.writingCf'));
            const r = await autoDnsApi('create', { confirm: 'CREATE', which: quale, policy: politica });
            let h = '<div class="alert alert-' + (r.success ? 'success' : 'danger') + ' py-2 small mb-1">'
                  + adEsc(r.note || r.error) + '</div>';
            if (r.content)
                h += '<div class="small text-muted mb-1">' + escHtml(t('ad.alreadyThere')) + ' <code style="word-break:break-all">'
                   + adEsc(r.content) + '</code></div>';
            if (r.name && r.value)
                h += '<div class="small text-muted"><code>' + adEsc(r.name) + '</code> &rarr; <code '
                   + 'style="word-break:break-all">' + adEsc(r.value) + '</code></div>';
            el.innerHTML = h;
            if (r.success) setTimeout(autoDnsCarica, 1200);
            else if (r.mailboxMissing) setTimeout(autoDnsCarica, 300);
        }

        // Tutto quello che serve a un dominio, in una volta. Ogni passo non sovrascrive
        // niente: si puo' premere anche su un dominio configurato a meta', trova cio' che
        // c'e' gia' e aggiunge solo il resto.
        async function autoDnsConfiguraTutto() {
            if (!currentDomainId) return;
            if (!adConferma(t('ad.confirmAll'), t('ad.wordConfigure'))) return;

            const el = document.getElementById('autoDnsOutcome');
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('ad.starting'));
            const r = await autoDnsApi('configure_all', { confirm: 'CONFIGURE' });
            if (!r.success || !r.jobId) {
                el.innerHTML = '<div class="alert alert-danger py-2 small mb-0">'
                             + adEsc(r.error || t('ad.startFailed')) + '</div>';
                return;
            }
            // La richiesta torna SUBITO con un identificativo. La sequenza include l'attesa
            // della propagazione DNS e puo' durare minuti: tenendo aperta la richiesta, il
            // browser riceverebbe la pagina di errore del proxy mentre sul server il lavoro
            // continua, e nessuno saprebbe piu' com'e' finita.
            el.innerHTML = '<div class="alert alert-info py-2 small mb-2">'
                         + '<i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('ad.running')) + '</div>'
                         + '<pre id="adLog" class="small p-2 border rounded mb-0" '
                         + 'style="max-height:26rem;overflow:auto"></pre>';
            adSegui(r.jobId);
        }

        async function adSegui(id) {
            const el = document.getElementById('autoDnsOutcome');
            const pre = document.getElementById('adLog');
            const s = await autoDnsApi('job_status', { jobId: id });
            if (s.success && s.job) {
                if (pre) { pre.textContent = s.job.consoleLog || ''; pre.scrollTop = pre.scrollHeight; }
                if (s.job.status === 'completed' || s.job.status === 'error') {
                    // La scheda VA ricaricata, e il registro NON va perso: sono due esigenze
                    // vere e prima ne era soddisfatta una sola.
                    //
                    // Lasciandola ferma, restava a schermo la fotografia di prima del lavoro. E'
                    // cosi' che il pannello ha continuato a scrivere "Manca la cassetta dei
                    // rapporti, scegli una delle due strade" venti secondi dopo aver creato lui
                    // stesso quell'alias — e chi premeva si sentiva rispondere "esiste gia'".
                    // Chiedere un'azione gia' compiuta, e dirlo solo dopo che e' stata tentata,
                    // e' peggio di non dire niente: fa sembrare rotto cio' che ha funzionato.
                    //
                    // Il registro sta dentro il contenitore che si ridisegna, quindi lo si tiene
                    // da parte e lo si rimette nella scheda nuova.
                    const line = (s.job.status === 'completed'
                            ? '<i class="fas fa-check-circle me-1" aria-hidden="true"></i>' + escHtml(t('ad.done', { s: s.job.elapsedSeconds }))
                            : '<i class="fas fa-triangle-exclamation me-1" aria-hidden="true"></i>' + escHtml(t('ad.stopped', { message: s.job.errorMessage })));
                    const registro = pre ? pre.textContent : '';
                    await autoDnsCarica();
                    const fresco = document.getElementById('autoDnsOutcome');
                    if (fresco) {
                        const p = document.createElement('pre');
                        p.className = 'small p-2 border rounded mb-0';
                        p.style.maxHeight = '26rem';
                        p.style.overflow = 'auto';
                        p.textContent = registro;
                        fresco.innerHTML = '<div class="alert alert-'
                            + (s.job.status === 'completed' ? 'success' : 'warning')
                            + ' py-2 small mb-2">' + line + '</div>';
                        fresco.appendChild(p);
                    }
                    return;
                }
            }
            setTimeout(() => adSegui(id), 3000);
        }
