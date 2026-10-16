        // ---------- porta 465: sottomissione autenticata ----------
        async function upd465() {
            const el = document.getElementById('upd-465');
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('p465.reading')) + '';
            const r = await updApi('porta465_status');
            if (!r.success) {
                el.innerHTML = '<div class="alert alert-danger py-2 small mb-0">' + updEsc(r.error) + '</div>';
                return;
            }
            const state = r.state;
            let colore = state === 'GIA_PRESENTE' ? 'success'
                       : state === 'VOCE_ASSENTE' ? 'secondary' : 'warning';
            let h = '<div class="alert alert-' + colore + ' py-2 small mb-2">'
                  + '<i class="fas fa-' + (state === 'GIA_PRESENTE' ? 'check-circle' : 'triangle-exclamation')
                  + ' me-1" aria-hidden="true"></i>' + updEsc(r.nota) + '</div>';

            h += '<table class="table table-sm mb-2"><tbody>'
               + '<tr><td style="width:14rem" class="small">' + escHtml(t('p465.entry')) + '</td><td class="small"><code>'
               + updEsc(r.voce || t('p465.none')) + '</code>' + (r.line ? ' (' + escHtml(t('p465.line', { n: r.line })) + ')' : '') + '</td></tr>'
               + '<tr><td class="small">' + escHtml(t('p465.lineToAdd')) + '</td><td class="small"><code style="word-break:break-all">-o '
               + updEsc(r.restrizione) + '</code></td></tr>'
               + '<tr><td class="small">smtpd_delay_reject</td><td class="small">'
               + (r.sicuro
                  ? '<i class="fas fa-check-circle text-success me-1" aria-hidden="true"></i><code>' + updEsc(r.delayReject) + '</code>'
                    + ' &mdash; ' + escHtml(t('p465.safe'))
                  : '<i class="fas fa-times-circle text-danger me-1" aria-hidden="true"></i><code>' + updEsc(r.delayReject || '?')
                    + '</code> &mdash; ' + escHtml(t('p465.unsafe')))
               + '</td></tr></tbody></table>';

            if (state === 'AGGIUNTA')
                h += '<button class="btn btn-sm btn-outline-warning" onclick="upd465Applica()"'
                   + (r.sicuro ? '' : ' disabled')
                   + '><i class="fas fa-lock me-1" aria-hidden="true"></i>' + escHtml(t('p465.apply')) + '</button>';

            h += '<div id="upd-465-esito" class="mt-2"></div>';
            el.innerHTML = h;
        }

        async function upd465Applica() {
            if (!updConferma(t('p465.confirm'), t('p465.wApply'))) return;
            const el = document.getElementById('upd-465-esito');
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('p465.applying')) + '';
            const r = await updApi('porta465_apply', { confirm: 'APPLICA' });
            let h = '<div class="alert alert-' + (r.success ? 'success' : 'danger') + ' py-2 small mb-0">'
                  + updEsc(r.nota || r.error) + '</div>';
            if (r.ripristinato)
                h += '<div class="small text-muted mt-1">' + escHtml(t('p465.restored')) + '</div>';
            if (r.vocePostfix)
                h += '<div class="small text-muted mt-1">' + escHtml(t('p465.postfixView')) + '<pre class="small p-2 '
                   + 'border rounded mt-1 mb-0" style="max-height:12rem;overflow:auto">' + updEsc(r.vocePostfix)
                   + '</pre></div>';
            el.innerHTML = h;
            if (r.success) setTimeout(upd465, 1200);
        }
