        // ---------- Sorveglianza: cosa e' cambiato sotto i piedi del pannello ----------
        // Il RFC Editor pubblica lo stato di ogni documento in forma leggibile da un
        // programma (rfcNNNN.json, 1,3 KB): "obsoleted_by" e "updated_by". Quello che il
        // 01/09/2026 abbiamo scoperto per caso su DMARC, da qui si vede da solo.
        async function sorvCarica() {
            const el = document.getElementById('upd-sorv');
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1"></i>Interrogo il RFC Editor e leggo le versioni installate...';
            // Una alla volta, per lo stesso motivo: il lucchetto di updApi fa fallire la
            // seconda chiamata parallela, e la sezione delle scadenze restava vuota.
            const r = await updApi('sorveglianza');
            const o = await updApi('openssl_scadenza');

            let h = '';

            // --- specifiche ---
            if (!r.success) {
                h += '<div class="alert alert-danger py-2 small mb-3">' + updEsc(r.error || 'controllo fallito') + '</div>';
            } else {
                const col = r.sostituiti > 0 ? 'danger' : (r.aggiornati > 0 ? 'warning' : (r.nonLetti > 0 ? 'secondary' : 'success'));
                h += '<div class="alert alert-' + col + ' py-2 small mb-2"><i class="fas fa-book me-1"></i>'
                   + updEsc(r.nota) + '</div>'
                   + '<div class="table-responsive"><table class="table table-sm align-middle mb-1"><thead><tr>'
                   + '<th style="width:6rem">Specifica</th><th>Cosa governa</th><th>Stato</th></tr></thead><tbody>';
                (r.standard || []).forEach(s => {
                    const g = s.gravita;
                    const icona = !s.letto ? '<i class="fas fa-circle-question text-secondary"></i>'
                                : g === 2 ? '<i class="fas fa-times-circle text-danger"></i>'
                                : g === 1 ? '<i class="fas fa-triangle-exclamation text-warning"></i>'
                                          : '<i class="fas fa-check-circle text-success"></i>';
                    // Per ogni documento nuovo c'e' un bottone che ne estrae l'elenco dei
                    // cambiamenti scritto dagli autori: e' li' che sta la risposta a "cosa e'
                    // cambiato", e non serve leggere duecento pagine per trovarla.
                    const nuovi = (s.sostituitoDa || []).concat(s.aggiornatoDa || []);
                    let bottoni = '';
                    nuovi.forEach(x => {
                        bottoni += '<button class="btn btn-sm btn-outline-secondary me-1 mt-1" '
                                 + 'onclick="sorvCambi(\'' + updEsc(x) + '\',\'' + updEsc(s.rfc) + '\')">'
                                 + '<i class="fas fa-list-check me-1"></i>Cosa cambia in RFC ' + updEsc(x)
                                 + '</button>';
                    });
                    h += '<tr class="upd-cell"><td><code class="small">RFC ' + updEsc(s.rfc) + '</code></td>'
                       + '<td class="small">' + updEsc(s.governa) + '</td>'
                       + '<td class="small">' + icona + ' '
                       + updEsc(s.letto ? s.commento : (s.problema || 'non letto'))
                       + bottoni + '</td></tr>';
                });
                h += '</tbody></table></div>'
                   + '<div class="small text-muted mb-3">Fonte: <code>' + updEsc(r.fonte) + '</code>. Il pannello '
                   + 'dice <strong>che</strong> qualcosa e&rsquo; cambiato e su quale sua parte incide, non '
                   + '<strong>cosa</strong> e&rsquo; cambiato: quello resta da leggere a mano, ma almeno si sa '
                   + 'che va fatto.</div>';
            }

            // --- scadenze OpenSSL ---
            if (!o.success) {
                h += '<div class="alert alert-danger py-2 small mb-0">' + updEsc(o.error || 'controllo fallito') + '</div>';
            } else {
                const col = o.urgenza === 2 ? 'danger' : o.urgenza === 1 ? 'warning'
                          : o.urgenza === 3 ? 'secondary' : 'success';
                h += '<div class="alert alert-' + col + ' py-2 small mb-2"><i class="fas fa-hourglass-half me-1"></i>'
                   + updEsc(o.nota) + '</div>'
                   + '<div class="table-responsive"><table class="table table-sm align-middle mb-1"><thead><tr>'
                   + '<th style="width:6rem">OpenSSL</th><th>Versione</th><th>Supporto</th></tr></thead><tbody>';
                (o.installazioni || []).forEach(i => {
                    if (!i.presente) {
                        h += '<tr class="upd-cell"><td class="small">' + updEsc(i.tipo) + '</td>'
                           + '<td class="small text-muted">non installato</td>'
                           + '<td class="small text-muted">&mdash;</td></tr>';
                        return;
                    }
                    const icona = i.urgenza === 2 ? '<i class="fas fa-times-circle text-danger"></i>'
                                : i.urgenza === 1 ? '<i class="fas fa-triangle-exclamation text-warning"></i>'
                                : i.urgenza === 3 ? '<i class="fas fa-circle-question text-secondary"></i>'
                                                  : '<i class="fas fa-check-circle text-success"></i>';
                    h += '<tr class="upd-cell"><td class="small"><strong>' + updEsc(i.tipo) + '</strong><br>'
                       + '<code class="small">' + updEsc(i.percorso) + '</code></td>'
                       + '<td class="small"><code>' + updEsc(i.versione) + '</code>'
                       + (i.lts ? ' <span class="badge bg-secondary">LTS</span>' : '') + '</td>'
                       + '<td class="small">' + icona + ' ' + updEsc(i.commento)
                       + '<div class="text-muted">' + updEsc(i.cosaSignifica) + '</div></td></tr>';
                });
                h += '</tbody></table></div>';
                if (o.nelPath)
                    h += '<div class="small text-muted">Quello che il pannello userebbe nei suoi comandi: <code>'
                       + updEsc(o.nelPath) + '</code></div>';
            }

            h += '<div id="sorv-cambi" class="mt-3"></div>';
            el.innerHTML = h;
        }

        // Scarica il documento nuovo ed estrae cio' che dice di se stesso. Il testo e'
        // copiato alla lettera: un riassunto di un elenco di cambiamenti e' il modo migliore
        // per perdere proprio la riga che contava.
        async function sorvCambi(rfc, riferimento) {
            const el = document.getElementById('sorv-cambi');
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1"></i>Scarico RFC ' + updEsc(rfc)
                         + ' dal RFC Editor...';
            const r = await updApi('sorveglianza_cambi', { rfc: rfc, riferimento: riferimento || rfc });
            if (!r.success) {
                el.innerHTML = '<div class="alert alert-danger py-2 small mb-0">' + updEsc(r.error) + '</div>';
                return;
            }
            let h = '<div class="alert alert-' + (r.tipo === 'elenco' ? 'info' : 'secondary')
                  + ' py-2 small mb-2"><strong>RFC ' + updEsc(r.rfc) + '</strong> &mdash; '
                  + updEsc(r.nota) + '</div>';

            // Prima le righe che nominano qualcosa che il pannello usa davvero: sono quelle
            // da cui cominciare. L'elenco intero resta sotto, perche' l'incrocio non e' un
            // filtro completo e presentarlo come tale farebbe saltare la riga che conta.
            const tocca = r.tiRiguarda || [];
            if (r.notaIncrocio)
                h += '<div class="alert alert-' + (tocca.length ? 'warning' : 'secondary')
                   + ' py-2 small mb-2"><i class="fas fa-crosshairs me-1"></i>'
                   + updEsc(r.notaIncrocio) + '</div>';
            if (tocca.length) {
                h += '<div class="table-responsive mb-2"><table class="table table-sm mb-0"><tbody>';
                tocca.forEach(t => {
                    const i = t.indexOf('  ->  ');
                    const chiavi = i < 0 ? '' : t.substring(0, i);
                    const riga = i < 0 ? t : t.substring(i + 6);
                    h += '<tr class="upd-cell"><td style="width:12rem" class="small"><code>'
                       + updEsc(chiavi) + '</code></td><td class="small">' + updEsc(riga) + '</td></tr>';
                });
                h += '</tbody></table></div>';
            }

            h += '<div class="small text-muted mb-1">L&rsquo;elenco completo, come lo hanno scritto gli autori:</div>'
               + '<pre class="small p-2 border rounded mb-0" style="max-height:32rem;overflow:auto">'
               + updEsc(r.testo) + '</pre>';
            el.innerHTML = h;
        }
