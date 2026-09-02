
        // ---------- lo stato del pannello, in Home ----------
        // Qui non ci sono pulsanti che AGISCONO: quelli stanno in Aggiornamenti, in un posto
        // solo. Due copie dello stesso comando divergono, e la copia che si preme di rado
        // resta indietro — e' il difetto che abbiamo tolto tutto il giorno. Qui si legge e si
        // rimanda.
        async function homeApi(action) {
            try {
                const res = await fetch('/api/updates', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ action: action,
                        csrf_token: document.getElementById('csrf_token').value })
                });
                return await res.json();
            } catch (e) {
                return { success: false, error: 'Errore di rete: ' + e.message };
            }
        }

        function homeEsc(t) {
            const d = document.createElement('div');
            d.textContent = t === null || t === undefined ? '' : String(t);
            return d.innerHTML;
        }

        // Si carica da sola: sono due comandi di shell, non pesa. Ed e' la cosa che conta di
        // piu', perche' dentro il server web vivono lo scheduler della rotazione DKIM, il
        // rinnovo dei certificati e il rapporto periodico: se il pannello non riparte, quelli
        // si fermano dove sono e nessuno lo segnala.
        async function homeStato() {
            const el = document.getElementById('home-avvio');
            el.innerHTML = '<span class="text-muted small"><i class="fas fa-spinner fa-spin me-1"></i>Leggo...</span>';
            const r = await homeApi('rc_stato');
            if (!r || r.success === false) {
                el.innerHTML = '<div class="alert alert-secondary py-2 small mb-0">'
                             + '<i class="fas fa-question-circle me-1"></i>'
                             + homeEsc((r && (r.motivo || r.error)) || 'non ho potuto controllare')
                             + '</div>';
                return;
            }
            const ok = r.attivo === true;
            el.innerHTML = '<div class="alert alert-' + (ok ? 'success' : 'warning') + ' py-2 small mb-0">'
                + '<i class="fas fa-' + (ok ? 'check-circle' : 'triangle-exclamation') + ' me-1"></i>'
                + '<strong>Dopo un riavvio del server il pannello ' + (ok ? 'torna su da solo' : 'resta spento') + '.</strong> '
                + homeEsc(r.motivo || '')
                + (ok ? '' : ' <a href="/updates" class="alert-link">Vai alla scheda Sistema operativo</a>')
                + '</div>';
        }

        // Questa NO: fa due scaricamenti da cloudflare.com e caricare la Home non deve
        // dipendere da una rete esterna. Si preme quando serve.
        async function homeFiducia() {
            const el = document.getElementById('home-fiducia');
            el.innerHTML = '<span class="text-muted small"><i class="fas fa-spinner fa-spin me-1"></i>'
                         + 'Confronto la lista di fiducia con quella ufficiale di Cloudflare...</span>';
            const r = await homeApi('cf_intervalli');
            if (!r || !r.success) {
                el.innerHTML = '<div class="alert alert-secondary py-2 small mb-0">'
                             + '<i class="fas fa-question-circle me-1"></i>'
                             + homeEsc((r && r.error) || 'controllo non riuscito') + '</div>';
                return;
            }
            const mancanti = r.mancanti || [], inPiu = r.inPiu || [];
            const cls = mancanti.length ? 'danger' : (inPiu.length ? 'warning' : 'success');
            el.innerHTML = '<div class="alert alert-' + cls + ' py-2 small mb-0">'
                + '<i class="fas fa-' + (cls === 'success' ? 'check-circle' : 'triangle-exclamation') + ' me-1"></i>'
                + homeEsc(r.nota) + ' <a href="/updates" class="alert-link">Vedi la lista</a></div>';
        }

        document.addEventListener('DOMContentLoaded', () => {
            if (document.getElementById('home-avvio')) {
                homeStato();
                const f = document.getElementById('home-fiducia');
                if (f) f.innerHTML = '<button class="btn btn-sm btn-outline-secondary" onclick="homeFiducia()">'
                    + '<i class="fas fa-user-shield me-1"></i>Controlla la lista di chi è riconosciuto come Cloudflare</button>'
                    + '<div class="small text-muted mt-1">Scarica le liste ufficiali: qualche secondo.</div>';
            }
        });

        // La fine supporto NON e' misurata: e' una tabella copiata a mano dalla pagina
        // ufficiale di FreeBSD, e il pannello non torna a rileggerla. Mostrarne la data senza
        // dire che e' un ricordo la fa sembrare una misura di adesso.
        //
        // E il caso che conta e' quello in cui la serie NON e' in tabella: succede quando il
        // sistema e' piu' nuovo della fotografia, cioe' proprio quando andrebbe riletta. Prima
        // in quel caso non compariva niente, e un silenzio si legge come "nulla da segnalare".
        function supportoRiga(so) {
            const letta = so.fonteSupportoLetta ? ' <span class="text-muted">(tabella copiata a mano '
                        + 'il ' + homeEsc(so.fonteSupportoLetta) + ', non riletta da allora)</span>' : '';
            if (so.serieConosciuta === false || !so.fineSupporto) {
                if (!so.serie) return '';
                return '<div class="small text-warning"><i class="fas fa-circle-question me-1"></i>'
                     + 'Della serie <strong>' + homeEsc(so.serie) + '</strong> il pannello non sa la data '
                     + 'di fine supporto: la sua tabella non la contiene. Di solito vuol dire che questo '
                     + 'sistema &egrave; pi&ugrave; recente della tabella&nbsp;&mdash; da rileggere su '
                     + '<code>freebsd.org/security</code>.' + letta + '</div>';
            }
            // Se la data e' passata o vicina, dirlo: una data sola non si legge da sola.
            let stato = '';
            const p = String(so.fineSupporto).split('/');
            if (p.length === 3) {
                const q = new Date(+p[2], +p[1] - 1, +p[0]);
                const giorni = Math.round((q - Date.now()) / 86400000);
                if (giorni < 0) stato = ' <span class="badge bg-danger">supporto finito</span>';
                else if (giorni < 90) stato = ' <span class="badge bg-warning text-dark">fra ' + giorni + ' giorni</span>';
            }
            return '<div class="small text-muted">Fine supporto della serie ' + homeEsc(so.serie)
                 + ': <strong>' + homeEsc(so.fineSupporto) + '</strong>' + stato + letta + '</div>';
        }

        // ---------- versioni, riavvio, aggiornamenti ----------
        // Si carica da sola perche' e' veloce: legge il catalogo GIA' scaricato, non fa
        // "pkg update" ne' "pkg upgrade -n". Quelli stanno nella pagina Aggiornamenti e
        // possono metterci minuti; una Home che gira non la apre piu' nessuno.
        //
        // Il prezzo e' che i numeri possono essere vecchi, e si dice: accanto al conteggio
        // c'e' l'eta' del catalogo. Un numero preciso ricavato da dati di tre settimane fa
        // sembra una misura e non lo e'.
        async function homeSistema() {
            const el = document.getElementById('home-sistema');
            if (!el) return;
            el.innerHTML = '<span class="text-muted small"><i class="fas fa-spinner fa-spin me-1"></i>'
                         + 'Leggo versioni e aggiornamenti...</span>';
            const r = await homeApi('riepilogo_sistema');
            if (!r || !r.success) {
                el.innerHTML = '<div class="alert alert-secondary py-2 small mb-0">'
                             + '<i class="fas fa-question-circle me-1"></i>'
                             + homeEsc((r && r.error) || 'non ho potuto leggere lo stato del sistema')
                             + '</div>';
                return;
            }
            const so = r.so || {};
            // L'eta' del dato accanto al dato: un conteggio senza la sua data sembra una
            // misura di adesso anche quando viene da tre settimane fa.
            const eta = (g, cosa) => (g === undefined || g === null || g < 0) ? ''
                : (g === 0 ? ' <span class="text-muted">(' + cosa + ' di oggi)</span>'
                           : ' <span class="' + (g > 14 ? 'text-warning' : 'text-muted') + '">(' + cosa + ' di '
                             + g + (g === 1 ? ' giorno' : ' giorni') + ' fa)</span>');

            let h = '<div class="table-responsive"><table class="table table-sm align-middle mb-2"><tbody>';
            h += '<tr><td style="width:15rem"><strong>FreeBSD</strong></td><td><code>'
               + homeEsc(so.userland || '?') + '</code>'
               + (so.arch ? ' <span class="text-muted small">' + homeEsc(so.arch) + '</span>' : '')
               + supportoRiga(so)
               + '</td></tr>';

            // Kernel installato e in esecuzione sono due cose diverse: se differiscono manca
            // un riavvio, ed e' l'unico modo per accorgersene.
            h += '<tr><td><strong>Kernel</strong></td><td>'
               + 'in esecuzione <code>' + homeEsc(so.uname || '?') + '</code>'
               + (so.kernelInstallato && so.kernelInstallato !== so.uname
                   ? ' &middot; installato <code>' + homeEsc(so.kernelInstallato) + '</code>' : '')
               + (so.riavvioNecessario
                   ? '<div class="small text-warning"><i class="fas fa-triangle-exclamation me-1"></i>'
                     + 'Il kernel installato non &egrave; quello in esecuzione: manca un riavvio.</div>'
                   : '')
               + '</td></tr>';

            const n = r.daAggiornare || 0;
            h += '<tr><td><strong>Pacchetti da aggiornare</strong></td><td>'
               + (n === 0 ? '<span class="badge bg-success">nessuno</span>'
                          : '<span class="badge bg-warning text-dark">' + n + '</span>')
               + eta(r.catalogoGiorni, 'catalogo')
               + '<div class="small text-muted">Conteggio dal catalogo gi&agrave; scaricato, senza '
               + 'toccare la rete. La simulazione vera &egrave; in '
               + '<a href="/updates">Aggiornamenti</a>.</div></td></tr>';

            const v = r.vulnerabili || 0;
            h += '<tr><td><strong>Pacchetti vulnerabili</strong></td><td>'
               + (v === 0 ? '<span class="badge bg-success">nessuno</span>'
                          : '<span class="badge bg-danger">' + v + '</span>')
               + eta(r.vulnDbGiorni, 'database')
               + '</td></tr>';

            if (so.cePronti)
                h += '<tr><td><strong>freebsd-update</strong></td><td>'
                   + '<span class="badge bg-warning text-dark">ci sono aggiornamenti gi&agrave; pronti</span>'
                   + '<div class="small text-muted">Scaricati e in attesa di essere installati.</div></td></tr>';

            h += '</tbody></table></div>';
            el.innerHTML = h;
        }

        document.addEventListener('DOMContentLoaded', () => { homeSistema(); });
