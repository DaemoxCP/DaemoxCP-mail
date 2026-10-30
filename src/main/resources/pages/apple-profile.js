        // ---------- Profilo di configurazione per Apple Mail ----------
        // Le chiavi del profilo vengono dallo schema ufficiale Apple (com.apple.mail.managed);
        // il file generato passa la validazione di plutil, non e' stato guardato a occhio.
        async function paApi(azione, extra) {
            const r = await fetch('/api/profilo-apple', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(Object.assign({ action: azione }, extra || {}))
            });
            return await r.json();
        }

        function paEsc(v) {
            const d = document.createElement('div');
            d.textContent = v === null || v === undefined ? '' : String(v);
            return d.innerHTML;
        }

        async function paCarica() {
            const el = document.getElementById('paBody');
            if (!el) return;
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + paEsc(t('pa.reading'));
            const r = await paApi('status');
            if (!r.success) {
                el.innerHTML = '<div class="alert alert-warning py-2 small mb-0">' + paEsc(r.error) + '</div>';
                return;
            }
            const caselle = r.mailboxes || [];
            if (!caselle.length) {
                el.innerHTML = '<div class="alert alert-info py-2 small mb-0">' + paEsc(t('pa.none')) + '</div>';
                return;
            }

            el.innerHTML =
                  '<div class="d-flex gap-2 align-items-end flex-wrap mb-2">'
                + '<div><label class="form-label small mb-1" for="paCasella">' + paEsc(t('pa.mailbox')) + '</label>'
                + '<select class="form-select form-select-sm" id="paCasella" style="min-width:18rem">'
                + caselle.map(c => '<option value="' + paEsc(c) + '">' + paEsc(c) + '</option>').join('')
                + '</select></div>'
                + '<button class="btn btn-sm btn-mail" onclick="paScarica()">'
                + '<i class="fas fa-download me-1" aria-hidden="true"></i>' + paEsc(t('pa.download')) + '</button>'
                + '<button class="btn btn-sm btn-outline-secondary" onclick="paAnteprima()">'
                + '<i class="fas fa-eye me-1" aria-hidden="true"></i>' + paEsc(t('pa.look')) + '</button>'
                + '</div>'
                + '<div class="small text-muted mb-2">' + t('pa.sets.html', { imap: paEsc(r.mailHost + ':' + r.imapPort), smtp: paEsc(r.mailHost + ':' + r.smtpPort) }) + '</div>'
                + '<div class="alert alert-secondary py-2 small mb-0">'
                + '<i class="fas fa-circle-info me-1" aria-hidden="true"></i>' + t('pa.after.html') + '</div>'
                + '<div id="paOutcome" class="mt-2"></div>';
        }

        function paScarica() {
            const sel = document.getElementById('paCasella');
            if (!sel || !sel.value) return;
            window.location = '/profilo-apple?email=' + encodeURIComponent(sel.value);
        }

        async function paAnteprima() {
            const sel = document.getElementById('paCasella');
            const el = document.getElementById('paOutcome');
            if (!sel || !sel.value) return;
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + paEsc(t('pa.generating'));
            const r = await paApi('preview', { email: sel.value });
            if (!r.success) {
                el.innerHTML = '<div class="alert alert-danger py-2 small mb-0">' + paEsc(r.error) + '</div>';
                return;
            }
            el.innerHTML = '<pre class="small p-2 border rounded" style="max-height:24rem;overflow:auto">'
                         + paEsc(r.profile) + '</pre>';
        }
