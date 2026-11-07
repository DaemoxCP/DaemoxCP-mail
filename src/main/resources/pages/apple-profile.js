        // ---------- Profilo di configurazione per Apple Mail ----------
        // Le chiavi del profilo vengono dallo schema ufficiale Apple (com.apple.mail.managed);
        // il file generato passa la validazione di plutil, non e' stato guardato a occhio.
        async function paApi(actionItem, extra) {
            const r = await fetch('/api/apple-profile', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(Object.assign({ action: actionItem }, extra || {}))
            });
            return await r.json();
        }

        function paEsc(v) {
            const d = document.createElement('div');
            d.textContent = v === null || v === undefined ? '' : String(v);
            return d.innerHTML;
        }

        async function paLoad() {
            const el = document.getElementById('paBody');
            if (!el) return;
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + paEsc(t('pa.reading'));
            const r = await paApi('status');
            if (!r.success) {
                el.innerHTML = '<div class="alert alert-warning py-2 small mb-0">' + paEsc(r.error) + '</div>';
                return;
            }
            const mailboxes = r.mailboxes || [];
            if (!mailboxes.length) {
                el.innerHTML = '<div class="alert alert-info py-2 small mb-0">' + paEsc(t('pa.none')) + '</div>';
                return;
            }

            el.innerHTML =
                  '<div class="d-flex gap-2 align-items-end flex-wrap mb-2">'
                + '<div><label class="form-label small mb-1" for="paMailbox">' + paEsc(t('pa.mailbox')) + '</label>'
                + '<select class="form-select form-select-sm" id="paMailbox" data-style="min-width:18rem">'
                + mailboxes.map(c => '<option value="' + paEsc(c) + '">' + paEsc(c) + '</option>').join('')
                + '</select></div>'
                + '<button class="btn btn-sm btn-mail" data-on-click="paDownload()">'
                + '<i class="fas fa-download me-1" aria-hidden="true"></i>' + paEsc(t('pa.download')) + '</button>'
                + '<button class="btn btn-sm btn-outline-secondary" data-on-click="paPreview()">'
                + '<i class="fas fa-eye me-1" aria-hidden="true"></i>' + paEsc(t('pa.look')) + '</button>'
                + '</div>'
                + '<div class="small text-muted mb-2">' + t('pa.sets.html', { imap: paEsc(r.mailHost + ':' + r.imapPort), smtp: paEsc(r.mailHost + ':' + r.smtpPort) }) + '</div>'
                + '<div class="alert alert-secondary py-2 small mb-0">'
                + '<i class="fas fa-circle-info me-1" aria-hidden="true"></i>' + t('pa.after.html') + '</div>'
                + '<div id="paOutcome" class="mt-2"></div>';
        }

        function paDownload() {
            const sel = document.getElementById('paMailbox');
            if (!sel || !sel.value) return;
            window.location = '/apple-profile?email=' + encodeURIComponent(sel.value);
        }

        async function paPreview() {
            const sel = document.getElementById('paMailbox');
            const el = document.getElementById('paOutcome');
            if (!sel || !sel.value) return;
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + paEsc(t('pa.generating'));
            const r = await paApi('preview', { email: sel.value });
            if (!r.success) {
                el.innerHTML = '<div class="alert alert-danger py-2 small mb-0">' + paEsc(r.error) + '</div>';
                return;
            }
            el.innerHTML = '<pre class="small p-2 border rounded" data-style="max-height:24rem;overflow:auto">'
                         + paEsc(r.profile) + '</pre>';
        }
