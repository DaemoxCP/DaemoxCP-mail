        // ---------- Sorveglianza: cosa e' cambiato sotto i piedi del pannello ----------
        // Il RFC Editor pubblica lo stato di ogni documento in forma leggibile da un
        // programma (rfcNNNN.json, 1,3 KB): "obsoleted_by" e "updated_by". Quello che il
        // 01/09/2026 abbiamo scoperto per caso su DMARC, da qui si vede da solo.
        async function watchLoad() {
            const el = document.getElementById('upd-sorv');
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('sv.querying')) + '';
            // Una alla volta, per lo stesso motivo: il lucchetto di updApi fa fallire la
            // seconda chiamata parallela, e la sezione delle scadenze restava vuota.
            const r = await updApi('watch');
            const o = await updApi('openssl_expiry');

            let h = '';

            // --- specifiche ---
            if (!r.success) {
                h += '<div class="alert alert-danger py-2 small mb-3">' + updEsc(r.error || t('cfi.failed')) + '</div>';
            } else {
                const col = r.replaced > 0 ? 'danger' : (r.updated > 0 ? 'warning' : (r.unread > 0 ? 'secondary' : 'success'));
                h += '<div class="alert alert-' + col + ' py-2 small mb-2"><i class="fas fa-book me-1" aria-hidden="true"></i>'
                   + updEsc(r.note) + '</div>'
                   + '<div class="table-responsive"><table class="table table-sm align-middle mb-1"><thead><tr>'
                   + '<th scope="col" style="width:6rem">' + escHtml(t('sv.colSpec')) + '</th><th scope="col">' + escHtml(t('sv.colGoverns')) + '</th><th scope="col">' + escHtml(t('set.colState')) + '</th></tr></thead><tbody>';
                (r.standard || []).forEach(s => {
                    const g = s.severity;
                    const iconName = !s.read ? '<i class="fas fa-circle-question text-secondary" aria-hidden="true"></i>'
                                : g === 2 ? '<i class="fas fa-times-circle text-danger" aria-hidden="true"></i>'
                                : g === 1 ? '<i class="fas fa-triangle-exclamation text-warning" aria-hidden="true"></i>'
                                          : '<i class="fas fa-check-circle text-success" aria-hidden="true"></i>';
                    // Per ogni documento nuovo c'e' un bottone che ne estrae l'elenco dei
                    // cambiamenti scritto dagli autori: e' li' che sta la risposta a "cosa e'
                    // cambiato", e non serve leggere duecento pagine per trovarla.
                    const newOnes = (s.replacedBy || []).concat(s.updatedBy || []);
                    let buttons = '';
                    newOnes.forEach(x => {
                        buttons += '<button class="btn btn-sm btn-outline-secondary me-1 mt-1" '
                                 + 'data-rfc="' + escHtml(x) + '" data-ref="' + escHtml(s.rfc) + '" onclick="watchChanges(this.dataset.rfc, this.dataset.ref)">'
                                 + '<i class="fas fa-list-check me-1" aria-hidden="true"></i>' + escHtml(t('sv.whatChanges', { rfc: x }))
                                 + '</button>';
                    });
                    h += '<tr class="upd-cell"><td><code class="small">RFC ' + updEsc(s.rfc) + '</code></td>'
                       + '<td class="small">' + updEsc(s.governs) + '</td>'
                       + '<td class="small">' + iconName + ' '
                       + updEsc(s.read ? s.comment : (s.problem || t('up.notRead')))
                       + buttons + '</td></tr>';
                });
                h += '</tbody></table></div>'
                   + '<div class="small text-muted mb-3">' + t('sv.sourceNote.html', { source: updEsc(r.source) }) + '</div>';
            }

            // --- scadenze OpenSSL ---
            if (!o.success) {
                h += '<div class="alert alert-danger py-2 small mb-0">' + updEsc(o.error || t('cfi.failed')) + '</div>';
            } else {
                const col = o.urgency === 2 ? 'danger' : o.urgency === 1 ? 'warning'
                          : o.urgency === 3 ? 'secondary' : 'success';
                h += '<div class="alert alert-' + col + ' py-2 small mb-2"><i class="fas fa-hourglass-half me-1" aria-hidden="true"></i>'
                   + updEsc(o.note) + '</div>'
                   + '<div class="table-responsive"><table class="table table-sm align-middle mb-1"><thead><tr>'
                   + '<th scope="col" style="width:6rem">OpenSSL</th><th scope="col">' + escHtml(t('up.colVersion')) + '</th><th scope="col">' + escHtml(t('sv.colSupport')) + '</th></tr></thead><tbody>';
                (o.installs || []).forEach(i => {
                    if (!i.present) {
                        h += '<tr class="upd-cell"><td class="small">' + updEsc(i.type) + '</td>'
                           + '<td class="small text-muted">' + escHtml(t('up.notInstalled')) + '</td>'
                           + '<td class="small text-muted">&mdash;</td></tr>';
                        return;
                    }
                    const iconName = i.urgency === 2 ? '<i class="fas fa-times-circle text-danger" aria-hidden="true"></i>'
                                : i.urgency === 1 ? '<i class="fas fa-triangle-exclamation text-warning" aria-hidden="true"></i>'
                                : i.urgency === 3 ? '<i class="fas fa-circle-question text-secondary" aria-hidden="true"></i>'
                                                  : '<i class="fas fa-check-circle text-success" aria-hidden="true"></i>';
                    h += '<tr class="upd-cell"><td class="small"><strong>' + updEsc(i.type) + '</strong><br>'
                       + '<code class="small">' + updEsc(i.path) + '</code></td>'
                       + '<td class="small"><code>' + updEsc(i.version) + '</code>'
                       + (i.lts ? ' <span class="badge bg-secondary">LTS</span>' : '') + '</td>'
                       + '<td class="small">' + iconName + ' ' + updEsc(i.comment)
                       + '<div class="text-muted">' + updEsc(i.whatItMeans) + '</div></td></tr>';
                });
                h += '</tbody></table></div>';
                if (o.inPath)
                    h += '<div class="small text-muted">' + escHtml(t('sv.panelWouldUse')) + ' <code>'
                       + updEsc(o.inPath) + '</code></div>';
            }

            h += '<div id="sorv-changes" class="mt-3"></div>';
            el.innerHTML = h;
        }

        // Scarica il documento nuovo ed estrae cio' che dice di se stesso. Il testo e'
        // copiato alla lettera: un riassunto di un elenco di cambiamenti e' il modo migliore
        // per perdere proprio la riga che contava.
        async function watchChanges(rfc, reference) {
            const el = document.getElementById('sorv-changes');
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('sv.downloadingRfc', { rfc: rfc }));
            const r = await updApi('watch_changes', { rfc: rfc, reference: reference || rfc });
            if (!r.success) {
                el.innerHTML = '<div class="alert alert-danger py-2 small mb-0">' + updEsc(r.error) + '</div>';
                return;
            }
            let h = '<div class="alert alert-' + (r.type === 'list' ? 'info' : 'secondary')
                  + ' py-2 small mb-2"><strong>RFC ' + updEsc(r.rfc) + '</strong> &mdash; '
                  + updEsc(r.note) + '</div>';

            // Prima le righe che nominano qualcosa che il pannello usa davvero: sono quelle
            // da cui cominciare. L'elenco intero resta sotto, perche' l'incrocio non e' un
            // filtro completo e presentarlo come tale farebbe saltare la riga che conta.
            const touches = r.concernsYou || [];
            if (r.crossNote)
                h += '<div class="alert alert-' + (touches.length ? 'warning' : 'secondary')
                   + ' py-2 small mb-2"><i class="fas fa-crosshairs me-1" aria-hidden="true"></i>'
                   + updEsc(r.crossNote) + '</div>';
            if (touches.length) {
                h += '<div class="table-responsive mb-2"><table class="table table-sm mb-0"><tbody>';
                touches.forEach(entryItem => {
                    const i = entryItem.indexOf('  ->  ');
                    const keys = i < 0 ? '' : entryItem.substring(0, i);
                    const line = i < 0 ? entryItem : entryItem.substring(i + 6);
                    h += '<tr class="upd-cell"><td style="width:12rem" class="small"><code>'
                       + updEsc(keys) + '</code></td><td class="small">' + updEsc(line) + '</td></tr>';
                });
                h += '</tbody></table></div>';
            }

            h += '<div class="small text-muted mb-1">' + escHtml(t('sv.fullList')) + '</div>'
               + '<pre class="small p-2 border rounded mb-0" style="max-height:32rem;overflow:auto">'
               + updEsc(r.text) + '</pre>';
            el.innerHTML = h;
        }
