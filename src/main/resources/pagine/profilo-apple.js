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

        function paEsc(t) {
            const d = document.createElement('div');
            d.textContent = t === null || t === undefined ? '' : String(t);
            return d.innerHTML;
        }

        async function paCarica() {
            const el = document.getElementById('paBody');
            if (!el) return;
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1"></i>Leggo le caselle...';
            const r = await paApi('status');
            if (!r.success) {
                el.innerHTML = '<div class="alert alert-warning py-2 small mb-0">' + paEsc(r.error) + '</div>';
                return;
            }
            const caselle = r.caselle || [];
            if (!caselle.length) {
                el.innerHTML = '<div class="alert alert-info py-2 small mb-0">Non c&rsquo;&egrave; ancora nessuna casella.</div>';
                return;
            }

            el.innerHTML =
                  '<div class="d-flex gap-2 align-items-end flex-wrap mb-2">'
                + '<div><label class="form-label small mb-1">Casella</label>'
                + '<select class="form-select form-select-sm" id="paCasella" style="min-width:18rem">'
                + caselle.map(c => '<option value="' + paEsc(c) + '">' + paEsc(c) + '</option>').join('')
                + '</select></div>'
                + '<button class="btn btn-sm btn-mail" onclick="paScarica()">'
                + '<i class="fas fa-download me-1"></i>Scarica il profilo</button>'
                + '<button class="btn btn-sm btn-outline-secondary" onclick="paAnteprima()">'
                + '<i class="fas fa-eye me-1"></i>Guarda cosa contiene</button>'
                + '</div>'
                + '<div class="small text-muted mb-2">Il profilo imposta IMAP su <code>' + paEsc(r.hostDiPosta)
                + ':' + paEsc(r.portaImap) + '</code> e SMTP su <code>' + paEsc(r.hostDiPosta) + ':'
                + paEsc(r.portaSmtp) + '</code>, entrambi in TLS diretto, con l&rsquo;indirizzo completo come '
                + 'nome utente. La 465 &egrave; scelta apposta: lo schema Apple ha un solo interruttore '
                + '&ldquo;usa SSL&rdquo; e non distingue STARTTLS, mentre su quella porta Postfix parla TLS '
                + 'dal primo byte &mdash; nessuna ambiguit&agrave;.</div>'
                + '<div class="alert alert-secondary py-2 small mb-0">'
                + '<i class="fas fa-circle-info me-1"></i><strong>Dopo aver scaricato:</strong> '
                + 'su <strong>Mac</strong> il file va aperto e poi confermato in Impostazioni di Sistema &rarr; '
                + 'Generali &rarr; VPN e gestione dispositivi. Su <strong>iPhone o iPad</strong> compare '
                + '&ldquo;Profilo scaricato&rdquo; in Impostazioni, in cima. Il profilo non &egrave; firmato, '
                + 'quindi viene indicato come non verificato: &egrave; normale per un profilo che ti sei '
                + 'generato da solo.</div>'
                + '<div id="paEsito" class="mt-2"></div>';
        }

        function paScarica() {
            const sel = document.getElementById('paCasella');
            if (!sel || !sel.value) return;
            window.location = '/profilo-apple?email=' + encodeURIComponent(sel.value);
        }

        async function paAnteprima() {
            const sel = document.getElementById('paCasella');
            const el = document.getElementById('paEsito');
            if (!sel || !sel.value) return;
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1"></i>Genero il profilo...';
            const r = await paApi('preview', { email: sel.value });
            if (!r.success) {
                el.innerHTML = '<div class="alert alert-danger py-2 small mb-0">' + paEsc(r.error) + '</div>';
                return;
            }
            el.innerHTML = '<pre class="small p-2 border rounded" style="max-height:24rem;overflow:auto">'
                         + paEsc(r.profilo) + '</pre>';
        }
