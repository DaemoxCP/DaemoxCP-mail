        // ---------- Configurazione automatica dei client (file XML di Thunderbird) ----------
        async function acApi(azione, extra) {
            const r = await fetch('/api/autoconfig', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(Object.assign({ action: azione }, extra || {}))
            });
            return await r.json();
        }

        function acEsc(t) {
            const d = document.createElement('div');
            d.textContent = t === null || t === undefined ? '' : String(t);
            return d.innerHTML;
        }

        async function acCarica() {
            const el = document.getElementById('acBody');
            if (!el) return;
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1"></i>Leggo la configurazione del server...';
            const r = await acApi('status');
            if (!r.success || r.error) {
                el.innerHTML = '<div class="alert alert-warning py-2 small mb-0">' + acEsc(r.error || 'stato non leggibile') + '</div>';
                return;
            }

            let h = '';
            h += '<div class="alert alert-' + (r.pronto ? 'success' : 'warning') + ' py-2 small mb-2">'
               + '<i class="fas fa-' + (r.pronto ? 'check-circle' : 'triangle-exclamation') + ' me-1"></i>'
               + (r.pronto
                  ? 'nginx serve gi&agrave; il file: Thunderbird lo trover&agrave; da solo.'
                  : 'nginx <strong>non serve ancora il file</strong>: i client continuano a doversi configurare a mano.')
               + '</div>';

            h += '<div class="small text-muted mb-2">Configurazione letta da <code>' + acEsc(r.conf) + '</code>'
               + ' &middot; server di posta <code>' + acEsc(r.hostDiPosta) + '</code></div>';

            h += '<table class="table table-sm mb-2"><tbody>'
               + acRiga('nginx risponde per autoconfig.&lt;dominio&gt;', r.nomeCoperto,
                        'Senza, la richiesta non arriva nemmeno: nginx non riconosce quel nome.')
               + acRiga('la rotta del file &egrave; installata', r.rottaPresente,
                        'La richiesta viene girata al pannello, che costruisce l&rsquo;XML del dominio giusto.')
               + '</tbody></table>';

            if (r.domini && r.domini.length) {
                h += '<div class="small fw-bold mb-1">Dominio per dominio</div>'
                   + '<div class="table-responsive"><table class="table table-sm align-middle mb-2"><thead><tr>'
                   + '<th>Nome</th><th>Risolve in DNS</th><th>Certificato</th>'
                   + '<th>Il file arriva davvero</th></tr></thead><tbody>';
                r.domini.forEach(d => {
                    const p = d.prova || {};
                    h += '<tr><td><code class="small">' + acEsc(d.nome) + '</code></td>'
                       + '<td>' + acSpunta(d.dns) + '</td>'
                       + '<td>' + acSpunta(d.certificato) + '</td>'
                       + '<td>' + acSpunta(p.ok)
                       + (p.ok ? '' : '<div class="small text-muted">' + acEsc(p.errore || '') + '</div>')
                       + '</td></tr>';
                });
                h += '</tbody></table></div>'
                   + '<div class="small text-muted mb-2">L&rsquo;ultima colonna &egrave; quella che conta: il '
                   + 'pannello <strong>chiede il file come lo chiederebbe Thunderbird</strong> e guarda cosa '
                   + 'torna. Le prime due dicono cosa <em>dovrebbe</em> funzionare, l&rsquo;ultima dice cosa '
                   + 'funziona &mdash; e quando divergono ha ragione l&rsquo;ultima. Il CNAME lo crea la scheda '
                   + 'qui sopra; il certificato copre quel nome solo se era incluso all&rsquo;emissione, '
                   + 'altrimenti va rigenerato dalla sezione SSL.</div>';
            }

            h += '<div class="d-flex gap-2 flex-wrap">'
               + '<button class="btn btn-sm btn-outline-secondary" onclick="acAnteprima()">'
               + '<i class="fas fa-eye me-1"></i>Guarda il file</button>'
               + (r.pronto ? ''
                  : '<button class="btn btn-sm btn-outline-success" onclick="acInstalla()">'
                    + '<i class="fas fa-screwdriver-wrench me-1"></i>Configura nginx</button>')
               + '</div><div id="acEsito" class="mt-2"></div>';

            el.innerHTML = h;
        }

        function acSpunta(v) {
            return v ? '<i class="fas fa-check-circle text-success"></i>'
                     : '<i class="fas fa-times-circle text-danger"></i>';
        }

        function acRiga(cosa, ok, perche) {
            return '<tr><td style="width:2rem">' + acSpunta(ok) + '</td><td class="small">' + cosa
                 + '<div class="text-muted">' + perche + '</div></td></tr>';
        }

        async function acAnteprima() {
            const el = document.getElementById('acEsito');
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1"></i>Genero il file...';
            const r = await acApi('preview');
            if (!r.success) {
                el.innerHTML = '<div class="alert alert-danger py-2 small mb-0">' + acEsc(r.error) + '</div>';
                return;
            }
            el.innerHTML = '<div class="small text-muted mb-1">Esempio per <code>' + acEsc(r.dominio)
                         + '</code>. Il pannello ne genera uno per ciascuno dei ' + acEsc(r.quantiDomini)
                         + ' domini, con il proprio nome dentro.</div>'
                         + '<pre class="small p-2 border rounded" style="max-height:22rem;overflow:auto">'
                         + acEsc(r.xml) + '</pre>';
        }

        async function acInstalla() {
            if (prompt('Modificare la configurazione di nginx?\n\n'
                     + 'Il pannello fa prima una copia di sicurezza, poi aggiunge i nomi e la rotta,\n'
                     + 'poi esegue nginx -t. Se la validazione fallisce rimette la configurazione\n'
                     + 'di prima e NON ricarica niente.\n\n'
                     + 'Scrivi INSTALLA per confermare.') !== 'INSTALLA') return;
            const el = document.getElementById('acEsito');
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1"></i>Modifico e valido...';
            const r = await acApi('install', { confirm: 'INSTALLA' });
            el.innerHTML = '<div class="alert alert-' + (r.success ? 'success' : 'danger') + ' py-2 small mb-0">'
                         + acEsc(r.nota || r.error) + '</div>'
                         + (r.ripristinato ? '<div class="small text-muted mt-1">La configurazione precedente '
                            + '&egrave; stata rimessa: il sito non ha subito interruzioni.</div>' : '');
            if (r.success) setTimeout(acCarica, 1200);
        }
