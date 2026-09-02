
        // ---------- gli intervalli Cloudflare: quelli veri contro quelli compilati ----------
        async function cfIntervalli() {
            const el = document.getElementById('cf-body');
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1"></i>Scarico le liste ufficiali da cloudflare.com...';
            const r = await updApi('cf_intervalli');
            if (!r.success) {
                // "Non ho potuto controllare" non e' "va bene", e non deve sembrarlo.
                el.innerHTML = '<div class="alert alert-secondary py-2 small mb-0">'
                             + '<i class="fas fa-question-circle me-1"></i>' + updEsc(r.error || 'controllo non riuscito')
                             + '</div>';
                return;
            }
            const mancanti = r.mancanti || [], inPiu = r.inPiu || [];
            const cls = mancanti.length ? 'danger' : (inPiu.length ? 'warning' : 'success');
            let h = '<div class="alert alert-' + cls + ' py-2 small mb-2">'
                  + '<i class="fas fa-' + (cls === 'success' ? 'check-circle' : 'triangle-exclamation') + ' me-1"></i>'
                  + updEsc(r.nota) + '</div>';

            h += '<div class="table-responsive"><table class="table table-sm mb-2"><tbody>'
               + '<tr class="upd-cell"><td style="width:16rem"><strong>Ufficiali su cloudflare.com</strong></td><td>'
               + r.ufficialiV4 + ' IPv4 &middot; ' + r.ufficialiV6 + ' IPv6</td></tr>'
               + '<tr class="upd-cell"><td><strong>Compilati nel pannello</strong></td><td>'
               + r.compilatiV4 + ' IPv4 &middot; ' + r.compilatiV6 + ' IPv6'
               + '<div class="small text-muted">Allineati a mano il ' + updEsc(r.aggiornataIl) + '</div></td></tr>'
               + '</tbody></table></div>';

            if (mancanti.length) {
                h += '<div class="small fw-bold mb-1 text-danger">Usati da Cloudflare, assenti qui '
                   + '&mdash; da aggiungere in <code>TrustedProxy</code></div><ul class="small mb-2">';
                mancanti.forEach(c => { h += '<li><code>' + updEsc(c) + '</code></li>'; });
                h += '</ul>';
            }
            if (inPiu.length) {
                h += '<div class="small fw-bold mb-1">Qui ma non pi&ugrave; ufficiali &mdash; fiducia concessa a '
                   + 'indirizzi che Cloudflare non usa pi&ugrave;</div><ul class="small mb-2">';
                inPiu.forEach(c => { h += '<li><code>' + updEsc(c) + '</code></li>'; });
                h += '</ul>';
            }
            el.innerHTML = h;
        }
