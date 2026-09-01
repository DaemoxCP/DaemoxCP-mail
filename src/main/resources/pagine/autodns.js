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

        function adEsc(t) {
            const d = document.createElement('div');
            d.textContent = t === null || t === undefined ? '' : String(t);
            return d.innerHTML;
        }

        function adAvvisi(lista) {
            if (!lista || !lista.length) return '';
            return '<div class="mt-2">' + lista.map(a =>
                '<div class="small d-flex gap-2 mb-1">'
                + '<i class="fas fa-triangle-exclamation text-warning mt-1"></i>'
                + '<span>' + adEsc(a) + '</span></div>').join('') + '</div>';
        }

        async function autoDnsCarica() {
            const el = document.getElementById('autoDnsBody');
            if (!el) return;
            if (!currentDomainId) { el.innerHTML = '<span class="text-muted small">Seleziona un dominio.</span>'; return; }
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1"></i>Chiedo a Cloudflare cosa c&rsquo;&egrave; gi&agrave;...';
            const r = await autoDnsApi('status');
            if (!r.success) { el.innerHTML = '<div class="alert alert-danger py-2 small mb-0">' + adEsc(r.error) + '</div>'; return; }
            if (!r.cloudflare || !r.zona) {
                el.innerHTML = '<div class="alert alert-warning py-2 small mb-0">' + adEsc(r.nota) + '</div>';
                return;
            }
            let h = '<div class="small text-muted mb-2">Account Cloudflare: <strong>' + adEsc(r.account)
                  + '</strong> &middot; zona <code>' + adEsc(r.dominio) + '</code></div>'
                  + '<div class="table-responsive"><table class="table table-sm align-middle mb-2"><thead><tr>'
                  + '<th>Record</th><th>In Cloudflare</th><th>Cosa scriverebbe il pannello</th><th></th>'
                  + '</tr></thead><tbody>';
            (r.record || []).forEach(x => {
                const nome = x.quale === 'spf' ? 'SPF' : 'DMARC';
                const troppi = (x.quanti || 0) > 1;

                let stato;
                if (troppi) stato = '<span class="badge bg-danger">' + x.quanti + ' record: si annullano</span>';
                else if (x.esiste) stato = '<span class="badge bg-success">esiste gi&agrave;</span>';
                else stato = '<span class="badge bg-warning text-dark">assente</span>';
                if (x.altriTxt > 0)
                    stato += '<div class="small text-muted mt-1">+ ' + x.altriTxt + ' altro TXT sullo stesso '
                           + 'nome, non pertinente</div>';
                if (x.contenuto)
                    stato += '<div class="small mt-1" style="word-break:break-all"><code>' + adEsc(x.contenuto) + '</code></div>';

                let proposta;
                if (x.bloccato) {
                    proposta = '<div class="small text-danger">' + adEsc(x.bloccato) + '</div>';
                } else {
                    proposta = '<code class="small" style="word-break:break-all">' + adEsc(x.proposto) + '</code>';
                    if (x.quale === 'dmarc' && !x.esiste)
                        proposta += '<div class="mt-1"><select class="form-select form-select-sm" id="adPolitica" style="max-width:22rem">'
                                  + '<option value="none" selected>p=none &mdash; osserva soltanto (si comincia da qui)</option>'
                                  + '<option value="quarantine">p=quarantine &mdash; in quarantena chi non si autentica</option>'
                                  + '<option value="reject">p=reject &mdash; rifiuta chi non si autentica</option>'
                                  + '</select>'
                                  + '<div class="small text-muted mt-1">Si parte da <code>none</code>: non blocca nulla e '
                                  + 'fa arrivare i rapporti. Si stringe dopo, quando i rapporti dicono che nessuna '
                                  + 'posta buona verrebbe fermata.</div></div>';
                }

                let azione;
                if (x.quale === 'dmarc' && x.esiste && x.politicaAttuale) {
                    // Il percorso e' none -> quarantine -> reject: il pannello deve rendere
                    // facile anche i due passi dopo il primo, non solo il primo.
                    const opz = ['none', 'quarantine', 'reject'].map(v =>
                        '<option value="' + v + '"' + (v === x.politicaAttuale ? ' selected' : '') + '>p='
                        + v + '</option>').join('');
                    azione = '<select class="form-select form-select-sm mb-1" id="adPoliticaNuova">' + opz + '</select>'
                           + '<button class="btn btn-sm btn-outline-warning" onclick="autoDnsCambiaPolitica()">'
                           + '<i class="fas fa-pen me-1"></i>Cambia politica</button>';
                } else if (x.esiste || x.bloccato) {
                    azione = '<span class="small text-muted">' + (x.esiste ? 'niente da fare' : 'non creabile') + '</span>';
                } else {
                    azione = '<button class="btn btn-sm btn-outline-success" onclick="autoDnsCrea(\'' + adEsc(x.quale) + '\')">'
                           + '<i class="fas fa-cloud-arrow-up me-1"></i>Crea</button>';
                }

                h += '<tr class="upd-cell"><td><strong>' + nome + '</strong><br>'
                   + '<code class="small">' + adEsc(x.nome) + '</code></td>'
                   + '<td>' + stato + '</td><td>' + proposta + '</td>'
                   + '<td class="text-end">' + azione + '</td></tr>';

                if (x.avvisi && x.avvisi.length)
                    h += '<tr><td colspan="4" class="pt-0">' + adAvvisi(x.avvisi) + '</td></tr>';
            });
            h += '</tbody></table></div><div id="autoDnsEsito"></div>';

            h += adRapporti(r.rapporti);
            h += adOpzionali(r.opzionali, r.mtaSts);

            h += '<div class="small text-muted mt-3">SPF e DMARC non contengono chiavi: sono dichiarazioni '
               + 'pubbliche di politica, e si cambiano quando cambia il server o la politica, non a scadenza. '
               + 'Per questo qui non c&rsquo;&egrave; una rotazione: sarebbe una manutenzione finta, e ogni '
               + 'cambio automatico di SPF &egrave; un&rsquo;occasione per fermare la posta in uscita.</div>';
            el.innerHTML = h;
            if (r.rapporti && !r.rapporti.esiste) adCaricaCaselle();
        }

        // La cassetta a cui arrivano i rapporti DMARC. Va predisposta PRIMA di pubblicare il
        // record: appena il DMARC e' pubblico i rapporti partono, e se l'indirizzo non
        // esiste rimbalzano tutti (RFC 9989 §5.1.4).
        //
        // Due strade, perche' sono due scelte diverse e nessuna e' ovvia: girare la posta a
        // un indirizzo che gia' si legge, oppure tenere i rapporti in una casella loro.
        function adRapporti(rap) {
            if (!rap) return '';
            if (rap.esiste) {
                return '<div class="alert alert-success py-2 small mb-0 mt-2">'
                     + '<i class="fas fa-inbox me-1"></i>I rapporti arriveranno a <code>' + adEsc(rap.indirizzo)
                     + '</code>, che esiste come <strong>' + adEsc(rap.tipo) + '</strong>'
                     + (rap.verso ? ' e viene girata a <code>' + adEsc(rap.verso) + '</code>' : '') + '.</div>';
            }
            const ind = adEsc(rap.indirizzo);
            return '<div class="card mt-2"><div class="card-body py-3">'
                 + '<div class="small mb-3"><i class="fas fa-inbox me-1"></i>'
                 + '<strong>Manca la cassetta dei rapporti.</strong> Oggi la posta indirizzata a <code>' + ind
                 + '</code> non arriva da nessuna parte: non esiste una casella con quel nome, e non c&rsquo;&egrave; '
                 + 'un inoltro che la giri altrove. Finch&eacute; &egrave; cos&igrave;, pubblicare il DMARC '
                 + 'servirebbe a poco: i rapporti partirebbero e rimbalzerebbero tutti. '
                 + adEsc(rap.nota || '') + ' <strong>Scegli una delle due strade.</strong></div>'

                 + '<div class="row g-3">'

                 // --- A: inoltro ---
                 + '<div class="col-lg-6"><div class="border rounded p-3 h-100">'
                 + '<div class="fw-bold mb-1"><i class="fas fa-share me-1"></i>Giralo a un indirizzo che leggi gi&agrave;</div>'
                 + '<div class="small text-muted mb-3">Non crea nessuna casella nuova e non occupa spazio. '
                 + 'Quello che arriva a <code>' + ind + '</code> viene consegnato all&rsquo;indirizzo che scegli '
                 + 'qui sotto. <strong>&Egrave; la strada che consiglio.</strong></div>'
                 + '<label class="form-label small mb-1">La posta per <code>' + ind + '</code> deve arrivare a:</label>'
                 + '<select class="form-select form-select-sm mb-2" id="adVerso" onchange="adVersoCambia()">'
                 + '<option value="">Carico gli indirizzi...</option></select>'
                 + '<input type="email" class="form-control form-control-sm mb-2 d-none" id="adVersoAltro" '
                 + 'placeholder="nome@dominio.it" autocomplete="off">'
                 + '<div class="small text-muted mb-2 d-none" id="adVersoAltroNota">Un indirizzo fuori da questo '
                 + 'pannello va bene, ma non posso verificare che esista: se lo sbagli, i rapporti si perdono '
                 + 'senza alcun segnale.</div>'
                 + '<button class="btn btn-sm btn-outline-success" onclick="autoDnsCreaAlias()">'
                 + '<i class="fas fa-share me-1"></i>Crea l&rsquo;inoltro</button>'
                 + '</div></div>'

                 // --- B: casella vera ---
                 + '<div class="col-lg-6"><div class="border rounded p-3 h-100">'
                 + '<div class="fw-bold mb-1"><i class="fas fa-inbox me-1"></i>Crea la casella <code>' + ind + '</code></div>'
                 + '<div class="small text-muted mb-3">Una casella vera, con la sua password e 512 MB di quota. '
                 + 'I rapporti restano separati da tutto il resto &mdash; in cambio &egrave; una casella in '
                 + 'pi&ugrave; da aprire ogni tanto. La password la genera il pannello e la conserva '
                 + 'cifrata nel vault: la rivedi quando vuoi da <strong>Caselle &rarr; Modifica &rarr; '
                 + 'Rivela</strong>.</div>'
                 + '<button class="btn btn-sm btn-outline-secondary" onclick="autoDnsCreaCasella()">'
                 + '<i class="fas fa-inbox me-1"></i>Crea la casella</button>'
                 + '</div></div>'

                 + '</div><div id="adAliasEsito" class="mt-3"></div></div></div>';
        }

        function adVersoCambia() {
            const sel = document.getElementById('adVerso');
            const campo = document.getElementById('adVersoAltro');
            const nota = document.getElementById('adVersoAltroNota');
            if (!sel || !campo) return;
            const altro = sel.value === '__altro__';
            campo.classList.toggle('d-none', !altro);
            if (nota) nota.classList.toggle('d-none', !altro);
            if (altro) campo.focus();
        }

        // Gli indirizzi si scelgono da un elenco. Chi ne vuole uno diverso lo scrive, ma
        // deve chiederlo apposta: un campo libero come prima scelta e' il modo piu' rapido
        // per scrivere un indirizzo che non esiste e accorgersene fra sei mesi.
        async function adCaricaCaselle() {
            const sel = document.getElementById('adVerso');
            if (!sel) return;
            const r = await autoDnsApi('mailboxes');
            const caselle = (r.success && r.caselle) ? r.caselle : [];
            sel.innerHTML = '<option value="">&mdash; scegli l&rsquo;indirizzo &mdash;</option>'
                + caselle.map(c => '<option value="' + adEsc(c) + '">' + adEsc(c) + '</option>').join('')
                + '<option value="__altro__">&mdash; un altro indirizzo (anche fuori dal pannello) &mdash;</option>';
        }

        function adVersoScelto() {
            const sel = document.getElementById('adVerso');
            if (!sel) return '';
            if (sel.value === '__altro__') {
                const campo = document.getElementById('adVersoAltro');
                return campo ? campo.value.trim() : '';
            }
            return sel.value;
        }

        async function autoDnsCreaAlias() {
            const verso = adVersoScelto();
            const el = document.getElementById('adAliasEsito');
            if (!verso) {
                el.innerHTML = '<div class="alert alert-warning py-2 small mb-0">Scegli prima l&rsquo;indirizzo '
                             + 'a cui far arrivare i rapporti.</div>';
                return;
            }
            if (prompt('La posta indirizzata a dmarc@ verrà consegnata a ' + verso + '.\n\n'
                     + 'Se quell\'indirizzo esiste già come casella o alias, il pannello NON lo tocca.\n'
                     + 'Scrivi CREA per confermare.') !== 'CREA') return;
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1"></i>Creo l&rsquo;inoltro...';
            const r = await autoDnsApi('alias_create', { confirm: 'CREA', verso: verso });
            el.innerHTML = '<div class="alert alert-' + (r.success ? 'success' : 'danger') + ' py-2 small mb-0">'
                         + adEsc(r.nota || r.error) + '</div>';
            if (r.success) setTimeout(autoDnsCarica, 1000);
        }

        async function autoDnsCreaCasella() {
            const el = document.getElementById('adAliasEsito');
            if (prompt('Creare la casella dei rapporti, con password generata dal pannello?\n\n'
                     + 'La password resta consultabile da Caselle > Modifica > Rivela.\n'
                     + 'Scrivi CREA per confermare.') !== 'CREA') return;
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1"></i>Creo la casella...';
            const r = await autoDnsApi('mailbox_create', { confirm: 'CREA' });
            let h = '<div class="alert alert-' + (r.success ? 'success' : 'danger') + ' py-2 small mb-0">'
                  + adEsc(r.nota || r.error) + '</div>';
            if (r.success && r.password)
                h += '<div class="alert alert-warning py-2 small mb-0 mt-2">'
                   + '<i class="fas fa-key me-1"></i><strong>Password di ' + adEsc(r.indirizzo) + ':</strong> '
                   + '<code style="font-size:1.05em">' + adEsc(r.password) + '</code><br>'
                   + 'Non serve trascriverla di fretta: resta cifrata nel vault del pannello e la '
                   + 'rivedi da <strong>Caselle &rarr; Modifica &rarr; Rivela</strong>.</div>';
            el.innerHTML = h;
            // Non si ricarica da soli: la ricarica cancellerebbe la password dallo schermo.
            if (r.success) {
                const b = document.getElementById('autoDnsEsito');
                if (b) b.innerHTML = '<div class="alert alert-info py-2 small mb-1">Casella creata. Premi '
                                   + '<strong>Aggiorna</strong> qui in alto, poi crea SPF e DMARC.</div>';
            }
        }


        // I record "opzionali": la posta funziona anche senza, ma senza di loro chi aggiunge
        // la casella deve sapere a memoria server, porte e tipo di cifratura. Sono gli stessi
        // valori della pagina DNS, letti dalla stessa impostazione: due modi di ricavare lo
        // stesso hostname sono due hostname che un giorno divergono.
        function adOpzionali(lista, mtaSts) {
            if (!lista || !lista.length) return '';
            const mancanti = lista.filter(x => !x.esiste && !x.conflitto).length;

            let h = '<div class="card mt-3"><div class="card-header d-flex justify-content-between '
                  + 'align-items-center"><span><i class="fas fa-wand-magic-sparkles me-2"></i>'
                  + '<strong>Record che facilitano la configurazione dei client</strong>'
                  + '<span class="small text-muted ms-2">opzionali: la posta funziona anche senza</span></span>'
                  + (mancanti > 1
                     ? '<button class="btn btn-sm btn-outline-success" onclick="autoDnsCreaTuttiOpzionali()">'
                       + '<i class="fas fa-cloud-arrow-up me-1"></i>Crea tutti i ' + mancanti + ' mancanti</button>'
                     : '')
                  + '</div><div class="card-body">'
                  + '<div class="table-responsive"><table class="table table-sm align-middle mb-2"><thead><tr>'
                  + '<th>Record</th><th>In Cloudflare</th><th>Cosa scriverebbe il pannello</th><th></th>'
                  + '</tr></thead><tbody>';

            lista.forEach(x => {
                let stato;
                if (x.conflitto) stato = '<span class="badge bg-danger">in conflitto</span>';
                else if (x.esiste) stato = '<span class="badge bg-success">esiste gi&agrave;</span>';
                else stato = '<span class="badge bg-warning text-dark">assente</span>';
                if (x.contenuto)
                    stato += '<div class="small mt-1" style="word-break:break-all"><code>'
                           + adEsc(x.contenuto) + '</code></div>';

                const azione = (x.esiste || x.conflitto)
                    ? '<span class="small text-muted">' + (x.esiste ? 'niente da fare' : 'da risolvere a mano') + '</span>'
                    : '<button class="btn btn-sm btn-outline-success" onclick="autoDnsCreaOpzionale(\'' + adEsc(x.quale) + '\')">'
                      + '<i class="fas fa-cloud-arrow-up me-1"></i>Crea</button>';

                h += '<tr class="upd-cell"><td><strong>' + adEsc(x.tipo) + '</strong><br>'
                   + '<code class="small">' + adEsc(x.nome) + '</code>'
                   + '<div class="small text-muted mt-1">' + adEsc(x.aCosaServe) + '</div>'
                   + (x.premessa
                      ? '<div class="small mt-1"><i class="fas fa-circle-info me-1 text-secondary"></i>'
                        + '<span class="text-secondary">' + adEsc(x.premessa) + '</span></div>'
                      : '') + '</td>'
                   + '<td>' + stato + '</td>'
                   + '<td><code class="small" style="word-break:break-all">' + adEsc(x.proposto) + '</code></td>'
                   + '<td class="text-end">' + azione + '</td></tr>';

                if (x.avviso || x.conflitto)
                    h += '<tr><td colspan="4" class="pt-0">'
                       + adAvvisi([x.avviso || x.conflitto]) + '</td></tr>';
            });

            h += '</tbody></table></div><div id="adOpzEsito"></div>';

            // L'unica eccezione, spiegata invece che nascosta.
            if (mtaSts && mtaSts.creabile === false)
                h += '<div class="alert alert-secondary py-2 small mb-0 mt-2">'
                   + '<i class="fas fa-circle-info me-1"></i><strong>MTA-STS (<code>'
                   + adEsc(mtaSts.nome) + '</code>) il pannello non lo crea.</strong> '
                   + adEsc(mtaSts.motivo) + '</div>';

            return h + '</div></div>';
        }

        async function autoDnsCreaOpzionale(quale) {
            const el = document.getElementById('adOpzEsito');
            if (prompt('Creare questo record su Cloudflare?\n\n'
                     + 'Se sul quel nome esiste già qualcosa, il pannello NON lo tocca: si ferma e te lo mostra.\n'
                     + 'Scrivi CREA per confermare.') !== 'CREA') return;
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1"></i>Scrivo su Cloudflare...';
            const r = await autoDnsApi('create_optional', { confirm: 'CREA', quale: quale });
            el.innerHTML = '<div class="alert alert-' + (r.success ? 'success' : 'danger') + ' py-2 small mb-0">'
                         + adEsc(r.nota || r.error) + '</div>';
            if (r.success) setTimeout(autoDnsCarica, 1200);
        }

        // Crea in fila quelli che mancano. Uno per volta e non tutti insieme: se il terzo
        // fallisce si deve poter dire QUALE ha fallito e perché, non "qualcosa è andato storto".
        async function autoDnsCreaTuttiOpzionali() {
            const el = document.getElementById('adOpzEsito');
            const r0 = await autoDnsApi('status');
            const mancanti = (r0.opzionali || []).filter(x => !x.esiste && !x.conflitto);
            if (!mancanti.length) { el.innerHTML = '<div class="alert alert-info py-2 small mb-0">Non manca nulla.</div>'; return; }
            if (prompt('Creare ' + mancanti.length + ' record su Cloudflare?\n\n'
                     + mancanti.map(x => '• ' + x.tipo + ' ' + x.nome).join('\n') + '\n\n'
                     + 'Nessun record esistente verrà toccato.\n'
                     + 'Scrivi CREA per confermare.') !== 'CREA') return;

            let esiti = '';
            for (const x of mancanti) {
                el.innerHTML = esiti + '<div class="small text-muted"><i class="fas fa-spinner fa-spin me-1"></i>'
                             + 'Creo ' + adEsc(x.nome) + '...</div>';
                const r = await autoDnsApi('create_optional', { confirm: 'CREA', quale: x.quale });
                esiti += '<div class="alert alert-' + (r.success ? 'success' : 'danger') + ' py-2 small mb-1">'
                       + '<code>' + adEsc(x.nome) + '</code> &mdash; ' + adEsc(r.nota || r.error) + '</div>';
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
            const el = document.getElementById('autoDnsEsito');
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1"></i>Leggo il record attuale...';

            const a = await autoDnsApi('change_policy', { politica: nuova });
            if (!a.success) {
                el.innerHTML = '<div class="alert alert-danger py-2 small mb-0">' + adEsc(a.error) + '</div>';
                return;
            }
            if (a.invariato) {
                el.innerHTML = '<div class="alert alert-info py-2 small mb-0">' + adEsc(a.nota) + '</div>';
                return;
            }

            el.innerHTML = '<div class="alert alert-secondary py-2 small mb-0">'
                         + '<div class="mb-1">' + adEsc(a.nota) + '</div>'
                         + '<div><span class="text-muted">prima:</span> <code style="word-break:break-all">'
                         + adEsc(a.prima) + '</code></div>'
                         + '<div><span class="text-muted">dopo:</span> <code style="word-break:break-all">'
                         + adEsc(a.dopo) + '</code></div></div>';

            const avviso = nuova === 'reject'
                ? '\n\nATTENZIONE: con p=reject la posta che non si autentica a nome di questo dominio\n'
                  + 'viene RIFIUTATA. Se un tuo servizio non era autorizzato, smette di essere consegnato.\n'
                : nuova === 'quarantine'
                ? '\n\nCon p=quarantine la posta che non si autentica finisce in spam.\n' : '\n';
            if (prompt('Cambiare la politica DMARC in p=' + nuova + '?\n\n'
                     + 'prima:  ' + a.prima + '\n'
                     + 'dopo:   ' + a.dopo + '\n'
                     + '\nCambia solo il valore di "p": tutto il resto del record resta com\'è.'
                     + avviso
                     + '\nScrivi CAMBIA per confermare.') !== 'CAMBIA') return;

            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1"></i>Modifico su Cloudflare...';
            const r = await autoDnsApi('change_policy', { politica: nuova, confirm: 'CAMBIA' });
            el.innerHTML = '<div class="alert alert-' + (r.success ? 'success' : 'danger') + ' py-2 small mb-0">'
                         + adEsc(r.nota || r.error) + '</div>';
            if (r.success) setTimeout(autoDnsCarica, 1500);
        }

        async function autoDnsCrea(quale) {
            const sel = document.getElementById('adPolitica');
            const politica = (sel && sel.value) ? sel.value : 'none';
            const che = quale === 'spf' ? 'SPF' : 'DMARC (p=' + politica + ')';
            if (prompt('Creare il record ' + che + ' su Cloudflare?\n\n'
                     + 'Se su quel nome esiste già un record di quel tipo, il pannello NON lo sovrascrive:\n'
                     + 'si ferma e te lo mostra.\n\n'
                     + 'Scrivi CREA per confermare.') !== 'CREA') return;
            const el = document.getElementById('autoDnsEsito');
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1"></i>Scrivo su Cloudflare...';
            const r = await autoDnsApi('create', { confirm: 'CREA', quale: quale, politica: politica });
            let h = '<div class="alert alert-' + (r.success ? 'success' : 'danger') + ' py-2 small mb-1">'
                  + adEsc(r.nota || r.error) + '</div>';
            if (r.contenuto)
                h += '<div class="small text-muted mb-1">C&rsquo;&egrave; gi&agrave;: <code style="word-break:break-all">'
                   + adEsc(r.contenuto) + '</code></div>';
            if (r.nome && r.valore)
                h += '<div class="small text-muted"><code>' + adEsc(r.nome) + '</code> &rarr; <code '
                   + 'style="word-break:break-all">' + adEsc(r.valore) + '</code></div>';
            el.innerHTML = h;
            if (r.success) setTimeout(autoDnsCarica, 1200);
            else if (r.mancaCasella) setTimeout(autoDnsCarica, 300);
        }
