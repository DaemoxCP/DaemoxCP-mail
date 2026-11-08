        // ---------- porta 465: sottomissione autenticata ----------
        async function upd465() {
            const el = document.getElementById('upd-465');
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('p465.reading')) + '';
            const r = await updApi('port465_status');
            if (!r.success) {
                el.innerHTML = '<div class="alert alert-danger py-2 small mb-0">' + updEsc(r.error) + '</div>';
                return;
            }
            const state = r.state;
            let color = state === 'ALREADY_PRESENT' ? 'success'
                       : state === 'ENTRY_MISSING' ? 'secondary' : 'warning';
            let h = '<div class="alert alert-' + color + ' py-2 small mb-2">'
                  + '<i class="fas fa-' + (state === 'ALREADY_PRESENT' ? 'check-circle' : 'triangle-exclamation')
                  + ' me-1" aria-hidden="true"></i>' + updEsc(r.note) + '</div>';

            h += '<table class="table table-sm mb-2"><tbody>'
               + '<tr><td data-style="width:14rem" class="small">' + escHtml(t('p465.entry')) + '</td><td class="small"><code>'
               + updEsc(r.entry || t('p465.none')) + '</code>' + (r.line ? ' (' + escHtml(t('p465.line', { n: r.line })) + ')' : '') + '</td></tr>'
               + '<tr><td class="small">' + escHtml(t('p465.lineToAdd')) + '</td><td class="small"><code data-style="word-break:break-all">-o '
               + updEsc(r.restriction) + '</code></td></tr>'
               + '<tr><td class="small">smtpd_delay_reject</td><td class="small">'
               + (r.safe
                  ? '<i class="fas fa-check-circle text-success me-1" aria-hidden="true"></i><code>' + updEsc(r.delayReject) + '</code>'
                    + ' &mdash; ' + escHtml(t('p465.safe'))
                  : '<i class="fas fa-times-circle text-danger me-1" aria-hidden="true"></i><code>' + updEsc(r.delayReject || '?')
                    + '</code> &mdash; ' + escHtml(t('p465.unsafe')))
               + '</td></tr></tbody></table>';

            if (state === 'ADDED')
                h += '<button class="btn btn-sm btn-outline-warning" data-on-click="upd465Apply()"'
                   + (r.safe ? '' : ' disabled')
                   + '><i class="fas fa-lock me-1" aria-hidden="true"></i>' + escHtml(t('p465.apply')) + '</button>';

            h += '<div id="upd-465-outcome" class="mt-2"></div>';
            el.innerHTML = h;
        }

        async function upd465Apply() {
            if (!await updConfirm(t('p465.confirm'), t('p465.wApply'))) return;
            const el = document.getElementById('upd-465-outcome');
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('p465.applying')) + '';
            const r = await updApi('port465_apply', { confirm: 'APPLY' });
            let h = '<div class="alert alert-' + (r.success ? 'success' : 'danger') + ' py-2 small mb-0">'
                  + updEsc(r.note || r.error) + '</div>';
            if (r.restored)
                h += '<div class="small text-muted mt-1">' + escHtml(t('p465.restored')) + '</div>';
            if (r.postfixEntry)
                h += '<div class="small text-muted mt-1">' + escHtml(t('p465.postfixView')) + '<pre class="small p-2 '
                   + 'border rounded mt-1 mb-0" data-style="max-height:12rem;overflow:auto">' + updEsc(r.postfixEntry)
                   + '</pre></div>';
            el.innerHTML = h;
            if (r.success) setTimeout(upd465, 1200);
        }
