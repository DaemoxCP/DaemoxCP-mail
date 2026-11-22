        // ---------- Profilo di configurazione per Apple Mail ----------
        // Sta nella finestra «Configurazione dei client» della casella, scheda iPhone/Mac: e' li' che si va a
        // configurare una casella (una scheda a parte in fondo alla pagina non la trovava nessuno, 22/11/2026).
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

        // All'apertura della finestra: i pulsanti si accendono solo se il profilo di questa casella si puo' fare
        // (nome del server di posta impostato, casella esistente); altrimenti si dice perche'.
        async function cfgAppleProfileState(email) {
            const btn = document.getElementById('cfgAppleProfileBtn');
            const look = document.getElementById('cfgAppleProfileLookBtn');
            const sets = document.getElementById('cfgAppleProfileSets');
            const signedLine = document.getElementById('cfgAppleProfileSigned');
            const out = document.getElementById('cfgAppleProfileOutcome');
            if (!btn || !look || !sets || !out) return;
            btn.disabled = true;
            look.disabled = true;
            sets.innerHTML = '';
            if (signedLine) signedLine.innerHTML = '';
            out.innerHTML = '';
            let r;
            try {
                r = await paApi('status');
            } catch (e) {
                r = { success: false, error: t('common.errorShort') };
            }
            // La finestra nel frattempo puo' essere stata riaperta per un'altra casella.
            if (email !== __cfgCurrentEmail) return;
            if (!r.success) {
                out.innerHTML = '<div class="alert alert-warning py-2 small mb-0">' + paEsc(r.error) + '</div>';
                return;
            }
            if (!(r.mailboxes || []).includes(email)) {
                out.innerHTML = '<div class="alert alert-warning py-2 small mb-0">' + paEsc(t('cfg.apUnavailable')) + '</div>';
                return;
            }
            sets.innerHTML = t('pa.sets.html', { imap: paEsc(r.mailHost + ':' + r.imapPort), smtp: paEsc(r.mailHost + ':' + r.smtpPort) });
            // Firmato o no (23/11/2026): un profilo non firmato l'iPhone lo mostra «Non verificato», e chi lo vede
            // deve sapere che e' previsto, e cosa manca perche' sia firmato. Con l'icona e la parola, non col colore.
            const s = r.signing || {};
            if (signedLine) {
                signedLine.innerHTML = s.signed
                    ? '<i class="fas fa-certificate text-success me-1" aria-hidden="true"></i>'
                      + t('pa.signed.html', { name: paEsc(s.name), until: paEsc(s.notAfter) })
                    : '<i class="fas fa-circle-exclamation text-warning me-1" aria-hidden="true"></i>'
                      + t('pa.unsigned.html', { why: paEsc(s.why || '') });
            }
            btn.disabled = false;
            look.disabled = false;
        }

        function cfgAppleProfile() {
            if (!__cfgCurrentEmail) return;
            window.location = '/apple-profile?email=' + encodeURIComponent(__cfgCurrentEmail);
        }

        async function cfgAppleProfilePreview() {
            const out = document.getElementById('cfgAppleProfileOutcome');
            if (!out || !__cfgCurrentEmail) return;
            out.innerHTML = '<i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + paEsc(t('pa.generating'));
            const r = await paApi('preview', { email: __cfgCurrentEmail });
            if (!r.success) {
                out.innerHTML = '<div class="alert alert-danger py-2 small mb-0">' + paEsc(r.error) + '</div>';
                return;
            }
            out.innerHTML = '<pre class="small p-2 border rounded" data-style="max-height:24rem;overflow:auto">'
                          + paEsc(r.profile) + '</pre>';
        }
