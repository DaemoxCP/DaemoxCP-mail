        // ---------- porta 465: sottomissione autenticata ----------
        async function upd465() {
            const el = document.getElementById('upd-465');
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1"></i>Leggo master.cf...';
            const r = await updApi('porta465_status');
            if (!r.success) {
                el.innerHTML = '<div class="alert alert-danger py-2 small mb-0">' + updEsc(r.error) + '</div>';
                return;
            }
            const stato = r.stato;
            let colore = stato === 'GIA_PRESENTE' ? 'success'
                       : stato === 'VOCE_ASSENTE' ? 'secondary' : 'warning';
            let h = '<div class="alert alert-' + colore + ' py-2 small mb-2">'
                  + '<i class="fas fa-' + (stato === 'GIA_PRESENTE' ? 'check-circle' : 'triangle-exclamation')
                  + ' me-1"></i>' + updEsc(r.nota) + '</div>';

            h += '<table class="table table-sm mb-2"><tbody>'
               + '<tr><td style="width:14rem" class="small">Voce in master.cf</td><td class="small"><code>'
               + updEsc(r.voce || 'nessuna') + '</code>' + (r.riga ? ' (riga ' + updEsc(r.riga) + ')' : '') + '</td></tr>'
               + '<tr><td class="small">Riga da aggiungere</td><td class="small"><code style="word-break:break-all">-o '
               + updEsc(r.restrizione) + '</code></td></tr>'
               + '<tr><td class="small">smtpd_delay_reject</td><td class="small">'
               + (r.sicuro
                  ? '<i class="fas fa-check-circle text-success me-1"></i><code>' + updEsc(r.delayReject) + '</code>'
                    + ' &mdash; le restrizioni si valutano dopo l&rsquo;autenticazione, quindi la riga &egrave; sicura'
                  : '<i class="fas fa-times-circle text-danger me-1"></i><code>' + updEsc(r.delayReject || '?')
                    + '</code> &mdash; con questo valore la riga rifiuterebbe anche gli utenti legittimi, '
                    + 'e il pannello si rifiuta di applicarla')
               + '</td></tr></tbody></table>';

            if (stato === 'AGGIUNTA')
                h += '<button class="btn btn-sm btn-outline-warning" onclick="upd465Applica()"'
                   + (r.sicuro ? '' : ' disabled')
                   + '><i class="fas fa-lock me-1"></i>Applica la restrizione</button>';

            h += '<div id="upd-465-esito" class="mt-2"></div>';
            el.innerHTML = h;
        }

        async function upd465Applica() {
            if (prompt('Aggiungere la restrizione alla voce della porta 465?\n\n'
                     + 'Il pannello fa una copia di sicurezza di master.cf, aggiunge la riga,\n'
                     + 'esegue postfix check e solo allora ricarica. Se qualcosa non torna,\n'
                     + 'rimette il file di prima.\n\n'
                     + 'La porta 25 non viene toccata.\n\n'
                     + 'Scrivi APPLICA per confermare.') !== 'APPLICA') return;
            const el = document.getElementById('upd-465-esito');
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1"></i>Modifico, verifico e ricarico...';
            const r = await updApi('porta465_apply', { confirm: 'APPLICA' });
            let h = '<div class="alert alert-' + (r.success ? 'success' : 'danger') + ' py-2 small mb-0">'
                  + updEsc(r.nota || r.error) + '</div>';
            if (r.ripristinato)
                h += '<div class="small text-muted mt-1">La configurazione precedente &egrave; stata rimessa: '
                   + 'la posta non ha subito interruzioni.</div>';
            if (r.vocePostfix)
                h += '<div class="small text-muted mt-1">Come la vede Postfix adesso:<pre class="small p-2 '
                   + 'border rounded mt-1 mb-0" style="max-height:12rem;overflow:auto">' + updEsc(r.vocePostfix)
                   + '</pre></div>';
            el.innerHTML = h;
            if (r.success) setTimeout(upd465, 1200);
        }
