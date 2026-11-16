
        // ---------- acme.sh (reperto 247) ----------
        // Su un server installato da zero acme.sh non c'e': senza, nessun certificato Let's Encrypt (questa pagina e
        // «Set up everything» si fermavano con «acme.sh not installed»). La scheda compare quando manca acme.sh o il suo
        // account Let's Encrypt (un indirizzo rifiutato lascia il pacchetto senza account).
        function acmeShow(ready) {
            const card = document.getElementById('acmeCard');
            if (card) card.classList.toggle('d-none', !!ready);
        }

        async function acmeInstall() {
            const email = document.getElementById('acmeEmail').value.trim();
            const out = document.getElementById('acmeOutcome');
            if (!/^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,63}$/.test(email)) {
                out.innerHTML = '<div class="alert alert-danger py-2 small mb-0" role="alert">' + escHtml(t('acm.badEmail')) + '</div>';
                return;
            }
            const go = document.getElementById('acmeGo');
            go.disabled = true;
            out.innerHTML = '<i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('acm.installing'));
            try {
                const r = await fetch('/api/ssl', { method: 'POST', headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ action: 'install_acme', email: email }) }).then(x => x.json());
                out.innerHTML = '<div class="alert alert-' + (r.success ? 'success' : 'danger') + ' py-2 small mb-0">'
                    + escHtml(r.message || r.error || (r.success ? t('acm.done') : t('acm.failed'))) + '</div>';
                if (r.success) setTimeout(loadSslStatus, 800);
            } finally {
                go.disabled = false;
            }
        }
