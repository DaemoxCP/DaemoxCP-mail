
        // ---------- lo stato del pannello, in Home ----------
        // Qui non ci sono pulsanti che AGISCONO: quelli stanno in Aggiornamenti, in un posto
        // solo. Due copie dello stesso comando divergono, e la copia che si preme di rado
        // resta indietro — e' il difetto che abbiamo tolto tutto il giorno. Qui si legge e si
        // rimanda.
        async function homeApi(action) {
            try {
                const res = await fetch('/api/updates', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ action: action,
                        csrf_token: document.getElementById('csrf_token').value })
                });
                return await res.json();
            } catch (e) {
                return { success: false, error: 'Errore di rete: ' + e.message };
            }
        }

        function homeEsc(t) {
            const d = document.createElement('div');
            d.textContent = t === null || t === undefined ? '' : String(t);
            return d.innerHTML;
        }

        // Si carica da sola: sono due comandi di shell, non pesa. Ed e' la cosa che conta di
        // piu', perche' dentro il server web vivono lo scheduler della rotazione DKIM, il
        // rinnovo dei certificati e il rapporto periodico: se il pannello non riparte, quelli
        // si fermano dove sono e nessuno lo segnala.
        async function homeStato() {
            const el = document.getElementById('home-avvio');
            el.innerHTML = '<span class="text-muted small"><i class="fas fa-spinner fa-spin me-1"></i>Leggo...</span>';
            const r = await homeApi('rc_stato');
            if (!r || r.success === false) {
                el.innerHTML = '<div class="alert alert-secondary py-2 small mb-0">'
                             + '<i class="fas fa-question-circle me-1"></i>'
                             + homeEsc((r && (r.motivo || r.error)) || 'non ho potuto controllare')
                             + '</div>';
                return;
            }
            const ok = r.attivo === true;
            el.innerHTML = '<div class="alert alert-' + (ok ? 'success' : 'warning') + ' py-2 small mb-0">'
                + '<i class="fas fa-' + (ok ? 'check-circle' : 'triangle-exclamation') + ' me-1"></i>'
                + '<strong>Dopo un riavvio del server il pannello ' + (ok ? 'torna su da solo' : 'resta spento') + '.</strong> '
                + homeEsc(r.motivo || '')
                + (ok ? '' : ' <a href="/updates" class="alert-link">Vai alla scheda Sistema operativo</a>')
                + '</div>';
        }

        // Questa NO: fa due scaricamenti da cloudflare.com e caricare la Home non deve
        // dipendere da una rete esterna. Si preme quando serve.
        async function homeFiducia() {
            const el = document.getElementById('home-fiducia');
            el.innerHTML = '<span class="text-muted small"><i class="fas fa-spinner fa-spin me-1"></i>'
                         + 'Confronto la lista di fiducia con quella ufficiale di Cloudflare...</span>';
            const r = await homeApi('cf_intervalli');
            if (!r || !r.success) {
                el.innerHTML = '<div class="alert alert-secondary py-2 small mb-0">'
                             + '<i class="fas fa-question-circle me-1"></i>'
                             + homeEsc((r && r.error) || 'controllo non riuscito') + '</div>';
                return;
            }
            const mancanti = r.mancanti || [], inPiu = r.inPiu || [];
            const cls = mancanti.length ? 'danger' : (inPiu.length ? 'warning' : 'success');
            el.innerHTML = '<div class="alert alert-' + cls + ' py-2 small mb-0">'
                + '<i class="fas fa-' + (cls === 'success' ? 'check-circle' : 'triangle-exclamation') + ' me-1"></i>'
                + homeEsc(r.nota) + ' <a href="/updates" class="alert-link">Vedi la lista</a></div>';
        }

        document.addEventListener('DOMContentLoaded', () => {
            if (document.getElementById('home-avvio')) {
                homeStato();
                const f = document.getElementById('home-fiducia');
                if (f) f.innerHTML = '<button class="btn btn-sm btn-outline-secondary" onclick="homeFiducia()">'
                    + '<i class="fas fa-user-shield me-1"></i>Controlla la lista di chi è riconosciuto come Cloudflare</button>'
                    + '<div class="small text-muted mt-1">Scarica le liste ufficiali: qualche secondo.</div>';
            }
        });
