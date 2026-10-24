
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
                return { success: false, error: t('common.networkError', { message: e.message }) };
            }
        }

        function homeEsc(v) {
            const d = document.createElement('div');
            d.textContent = v === null || v === undefined ? '' : String(v);
            return d.innerHTML;
        }

        // Si carica da sola: sono due comandi di shell, non pesa. Ed e' la cosa che conta di
        // piu', perche' dentro il server web vivono lo scheduler della rotazione DKIM, il
        // rinnovo dei certificati e il rapporto periodico: se il pannello non riparte, quelli
        // si fermano dove sono e nessuno lo segnala.
        async function homeStato() {
            const el = document.getElementById('home-avvio');
            el.innerHTML = '<span class="text-muted small"><i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + homeEsc(t('hs.reading')) + '</span>';
            const r = await homeApi('rc_state');
            if (!r || r.success === false) {
                el.innerHTML = '<div class="alert alert-secondary py-2 small mb-0">'
                             + '<i class="fas fa-question-circle me-1" aria-hidden="true"></i>'
                             + homeEsc((r && (r.reason || r.error)) || t('hs.notChecked'))
                             + '</div>';
                return;
            }
            const ok = r.active === true;
            // Il testo lo scrive il server, in "motivo": qui non se ne compone un secondo.
            //
            // Prima questa riga anteponeva un titolo ("Dopo un riavvio del server il pannello
            // torna su da solo") e poi accodava motivo, che diceva la stessa cosa con altre
            // parole: a schermo la frase compariva due volte di fila. Due punti che scrivono
            // la stessa frase sono due punti che un giorno la scriveranno diversa.
            el.innerHTML = '<div class="alert alert-' + (ok ? 'success' : 'warning') + ' py-2 small mb-0">'
                + '<i class="fas fa-' + (ok ? 'check-circle' : 'triangle-exclamation') + ' me-1" aria-hidden="true"></i>'
                + '<strong>' + homeEsc(r.reason || (ok ? t('hs.restarts') : t('hs.noRestart'))) + '</strong>'
                + (ok ? '' : ' <a href="/updates" class="alert-link">' + homeEsc(t('hs.goOs')) + '</a>')
                + '</div>';
        }

        // Questa NO: fa due scaricamenti da cloudflare.com e caricare la Home non deve
        // dipendere da una rete esterna. Si preme quando serve.
        async function homeFiducia() {
            const el = document.getElementById('home-fiducia');
            el.innerHTML = '<span class="text-muted small"><i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>'
                         + homeEsc(t('hs.comparingCf')) + '</span>';
            const r = await homeApi('cf_intervals');
            if (!r || !r.success) {
                el.innerHTML = '<div class="alert alert-secondary py-2 small mb-0">'
                             + '<i class="fas fa-question-circle me-1" aria-hidden="true"></i>'
                             + homeEsc((r && r.error) || t('hs.checkFailed')) + '</div>';
                return;
            }
            const mancanti = r.missing || [], inPiu = r.extra || [];
            const cls = mancanti.length ? 'danger' : (inPiu.length ? 'warning' : 'success');
            el.innerHTML = '<div class="alert alert-' + cls + ' py-2 small mb-0">'
                + '<i class="fas fa-' + (cls === 'success' ? 'check-circle' : 'triangle-exclamation') + ' me-1" aria-hidden="true"></i>'
                + homeEsc(r.note) + ' <a href="/updates" class="alert-link">' + homeEsc(t('hs.seeList')) + '</a></div>';
        }

        document.addEventListener('DOMContentLoaded', () => {
            if (document.getElementById('home-avvio')) {
                homeStato();
                const f = document.getElementById('home-fiducia');
                if (f) f.innerHTML = '<button class="btn btn-sm btn-outline-secondary" onclick="homeFiducia()">'
                    + '<i class="fas fa-user-shield me-1" aria-hidden="true"></i>' + homeEsc(t('hs.checkCf')) + '</button>'
                    + '<div class="small text-muted mt-1">' + homeEsc(t('hs.checkCfHint')) + '</div>';
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
            const letta = so.supportSourceRead ? ' <span class="text-muted">'
                        + homeEsc(t('hs.tableCopied', { date: so.supportSourceRead })) + '</span>' : '';
            if (so.knownSeries === false || !so.endOfSupport) {
                if (!so.series) return '';
                return '<div class="small text-warning"><i class="fas fa-circle-question me-1" aria-hidden="true"></i>'
                     + t('hs.unknownSeries.html', { series: homeEsc(so.series) }) + letta + '</div>';
            }
            // Se la data e' passata o vicina, dirlo: una data sola non si legge da sola.
            let state = '';
            const p = String(so.endOfSupport).split('/');
            if (p.length === 3) {
                const q = new Date(+p[2], +p[1] - 1, +p[0]);
                const giorni = Math.round((q - Date.now()) / 86400000);
                if (giorni < 0) state = ' <span class="badge bg-danger">' + homeEsc(t('hs.supportEnded')) + '</span>';
                else if (giorni < 90) state = ' <span class="badge bg-warning text-dark">' + homeEsc(tn('hs.inDays', giorni)) + '</span>';
            }
            return '<div class="small text-muted">' + homeEsc(t('hs.endOfSupport', { series: so.series }))
                 + ' <strong>' + homeEsc(so.endOfSupport) + '</strong>' + state + letta + '</div>';
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
            el.innerHTML = '<span class="text-muted small"><i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>'
                         + homeEsc(t('hs.readingSystem')) + '</span>';
            const r = await homeApi('system_summary');
            if (!r || !r.success) {
                el.innerHTML = '<div class="alert alert-secondary py-2 small mb-0">'
                             + '<i class="fas fa-question-circle me-1" aria-hidden="true"></i>'
                             + homeEsc((r && r.error) || t('hs.systemNotRead'))
                             + '</div>';
                return;
            }
            const so = r.os || {};
            // L'eta' del dato accanto al dato: un conteggio senza la sua data sembra una
            // misura di adesso anche quando viene da tre settimane fa.
            const eta = (g, cosa) => (g === undefined || g === null || g < 0) ? ''
                : (g === 0 ? ' <span class="text-muted">' + homeEsc(t('hs.ageToday', { what: cosa })) + '</span>'
                           : ' <span class="' + (g > 14 ? 'text-warning' : 'text-muted') + '">'
                             + homeEsc(tn('hs.ageDays', g, { what: cosa })) + '</span>');

            let h = '<div class="table-responsive"><table class="table table-sm align-middle mb-2"><tbody>';
            h += '<tr><td style="width:15rem"><strong>FreeBSD</strong></td><td><code>'
               + homeEsc(so.userland || '?') + '</code>'
               + (so.arch ? ' <span class="text-muted small">' + homeEsc(so.arch) + '</span>' : '')
               + supportoRiga(so)
               + '</td></tr>';

            // Kernel installato e in esecuzione sono due cose diverse: se differiscono manca
            // un riavvio, ed e' l'unico modo per accorgersene.
            h += '<tr><td><strong>Kernel</strong></td><td>'
               + homeEsc(t('hs.kernelRunning')) + ' <code>' + homeEsc(so.uname || '?') + '</code>'
               + (so.installedKernel && so.installedKernel !== so.uname
                   ? ' &middot; ' + homeEsc(t('hs.kernelInstalled')) + ' <code>' + homeEsc(so.installedKernel) + '</code>' : '')
               + (so.restartNeeded
                   ? '<div class="small text-warning"><i class="fas fa-triangle-exclamation me-1" aria-hidden="true"></i>'
                     + homeEsc(t('hs.kernelReboot')) + '</div>'
                   : '')
               + '</td></tr>';

            // Due conteggi diversi, e vanno etichettati come tali.
            //
            // "Da aggiornare" viene da pkg version: pacchetti con una versione piu' recente
            // nel catalogo. "Vulnerabili" viene da pkg audit: pacchetti con CVE note. Non
            // sono lo stesso insieme e spesso non si somigliano nemmeno — un pacchetto puo'
            // essere vulnerabile SENZA che esista una correzione, e aggiornabile senza avere
            // nessuna vulnerabilita'. Messi uno sotto l'altro con due numeri diversi si
            // leggono come una contraddizione, e chi guarda pensa che uno dei due sia rotto.
            const n = r.toUpdate || 0;
            // Le altre tre categorie NON sono aggiornamenti, e vanno separate: contarle insieme
            // dava un numero che nessun'altra schermata confermava.
            const altre = [];
            if (r.newerThanCatalog) altre.push(t('hs.newerThanCatalog.html', { n: homeEsc(r.newerThanCatalog) }));
            if (r.outsideCatalog) altre.push(t('hs.notInCatalog.html', { n: homeEsc(r.outsideCatalog) }));
            if (r.notComparable) altre.push(t('hs.notComparable.html', { n: homeEsc(r.notComparable) }));
            h += '<tr><td><strong>' + homeEsc(t('hs.toUpdate')) + '</strong></td><td>'
               + (n === 0 ? '<span class="badge bg-success">' + homeEsc(t('hs.none')) + '</span>'
                          : '<span class="badge bg-warning text-dark">' + n + '</span>')
               // La data del catalogo e' quella di pubblicazione sul server di pkg: la frase
               // completa (piu' repository, uno senza catalogo) sta nel title.
               // homeEsc non tocca le virgolette: dentro un attributo servono anche quelle.
               + (r.catalogDate
                   ? ' <span class="' + (r.catalogDays > 14 ? 'text-warning' : 'text-muted') + '" title="'
                     + homeEsc(r.catalogNote || '').replace(/"/g, '&quot;') + '">'
                     + homeEsc(t('hs.catalogPublished', { date: r.catalogDate })) + '</span>'
                   : (r.catalogNote ? ' <span class="text-muted" title="'
                                       + homeEsc(r.catalogNote).replace(/"/g, '&quot;')
                                       + '">' + homeEsc(t('hs.catalogNoDate')) + '</span>' : ''))
               + '<div class="small text-muted">' + t('hs.toUpdateHint.html') + ' <a href="/updates">' + homeEsc(t('nav.updates')) + '</a></div>'
               + (altre.length
                   ? '<div class="small text-muted mt-1">' + t('hs.otherDiff.html') + ' ' + altre.join('; ') + '.</div>'
                   : '')
               + '</td></tr>';

            const v = r.vulnerable || 0;
            h += '<tr><td><strong>' + homeEsc(t('hs.vulnerable')) + '</strong></td><td>'
               + (v === 0 ? '<span class="badge bg-success">' + homeEsc(t('hs.none')) + '</span>'
                          : '<span class="badge bg-danger">' + v + '</span>')
               + eta(r.vulnDbDays, t('hs.database'))
               + '<div class="small text-muted">' + t('hs.vulnHint.html') + '</div>'
               + '</td></tr>';

            if (so.readyExist)
                h += '<tr><td><strong>freebsd-update</strong></td><td>'
                   + '<span class="badge bg-warning text-dark">' + homeEsc(t('hs.fuReady')) + '</span>'
                   + '<div class="small text-muted">' + homeEsc(t('hs.fuReadyHint')) + '</div></td></tr>';

            h += '</tbody></table></div>';
            el.innerHTML = h;
        }

        document.addEventListener('DOMContentLoaded', () => { homeSistema(); });
