
        // ---------- gli intervalli Cloudflare: quelli veri contro quelli compilati ----------
        // La lista compilata si disegna sempre: e' conoscenza del pannello, non dipende da
        // cloudflare.com. Sta in una funzione sua perche' serve in ENTRAMBI i rami — quando il
        // confronto riesce e quando fallisce. Anzi: quando fallisce serve di piu', perche' e'
        // l'unico momento in cui non si puo' sapere altro.
        function cfElenchi(r) {
            const uno = (titolo, voci) => !voci || !voci.length ? ''
                : '<div class="small fw-bold mt-2 mb-1">' + escHtml(titolo) + ' (' + voci.length + ')</div>'
                  + '<div class="small" style="line-height:1.9">'
                  + voci.map(c => '<code class="me-2">' + updEsc(c) + '</code>').join('') + '</div>';
            return uno('Cloudflare IPv4', r.listaV4)
                 + uno('Cloudflare IPv6', r.listaV6)
                 + uno(t('cfi.local'), r.listaLocali)
                 + '<div class="small text-muted mt-2">' + escHtml(t('cfi.compiledOn', { date: r.aggiornataIl || '?' })) + ' '
                 + t('cfi.bitwise.html') + '</div>';
        }

        async function cfIntervalli() {
            const el = document.getElementById('cf-body');
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('cfi.downloading')) + '';
            const r = await updApi('cf_intervalli');
            if (!r.success) {
                // "Non ho potuto controllare" non e' "va bene", e non deve sembrarlo.
                el.innerHTML = '<div class="alert alert-secondary py-2 small mb-2">'
                             + '<i class="fas fa-question-circle me-1" aria-hidden="true"></i>' + updEsc(r.error || t('cfi.failed'))
                             + '</div>' + cfElenchi(r);
                return;
            }
            const mancanti = r.mancanti || [], inPiu = r.inPiu || [];
            const cls = mancanti.length ? 'danger' : (inPiu.length ? 'warning' : 'success');
            let h = '<div class="alert alert-' + cls + ' py-2 small mb-2">'
                  + '<i class="fas fa-' + (cls === 'success' ? 'check-circle' : 'triangle-exclamation') + ' me-1" aria-hidden="true"></i>'
                  + updEsc(r.nota) + '</div>';

            h += '<div class="table-responsive"><table class="table table-sm mb-2"><tbody>'
               + '<tr class="upd-cell"><td style="width:16rem"><strong>' + escHtml(t('cfi.official')) + '</strong></td><td>'
               + updEsc(r.ufficialiV4) + ' IPv4 &middot; ' + updEsc(r.ufficialiV6) + ' IPv6</td></tr>'
               + '<tr class="upd-cell"><td><strong>' + escHtml(t('cfi.compiled')) + '</strong></td><td>'
               + updEsc(r.compilatiV4) + ' IPv4 &middot; ' + updEsc(r.compilatiV6) + ' IPv6'
               + '<div class="small text-muted">' + escHtml(t('cfi.alignedOn', { date: r.aggiornataIl })) + '</div></td></tr>'
               + '</tbody></table></div>';

            if (mancanti.length) {
                h += '<div class="small fw-bold mb-1 text-danger">' + t('cfi.missing.html') + '</div><ul class="small mb-2">';
                mancanti.forEach(c => { h += '<li><code>' + updEsc(c) + '</code></li>'; });
                h += '</ul>';
            }
            if (inPiu.length) {
                h += '<div class="small fw-bold mb-1">' + escHtml(t('cfi.extra')) + '</div><ul class="small mb-2">';
                inPiu.forEach(c => { h += '<li><code>' + updEsc(c) + '</code></li>'; });
                h += '</ul>';
            }
            h += cfElenchi(r);
            el.innerHTML = h;
        }
