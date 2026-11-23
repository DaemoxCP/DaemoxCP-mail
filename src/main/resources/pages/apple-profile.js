        // ---------- Configuration profile for Apple Mail ----------
        // It lives in the mailbox's "Client configuration" window, iPhone/Mac tab: that is where one goes to
        // set up a mailbox (a separate card at the bottom of the page was found by nobody, 2026-11-22).
        // The profile's keys come from Apple's official schema (com.apple.mail.managed);
        // the generated file passes plutil validation, it was not checked by eye.
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

        // When the window opens: the buttons light up only if this mailbox's profile can be made
        // (mail server name set, mailbox existing); otherwise the reason is given.
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
            // In the meantime the window may have been reopened for another mailbox.
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
            // Signed or not (2026-11-23): the iPhone shows an unsigned profile as "Not Verified", and whoever
            // sees it must know that this is expected, and what is missing for it to be signed. With the icon and
            // the word, not with color.
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
