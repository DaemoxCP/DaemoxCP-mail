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
                  ? 'Il file <strong>arriva</strong>: Thunderbird lo trover&agrave; da solo.'
                  : 'Il file <strong>non arriva</strong>: i client continuano a doversi configurare a mano.')
               // Il verdetto viene dallo scarico vero, e qui si dice perche'. Prima veniva da
               // una ricerca dentro nginx.conf del marcatore di questa scheda, e siccome la
               // rotta la installa la scheda della 443 in un altro file, la riga diceva "non
               // serve il file" mentre il file arrivava.
               + (r.perche ? '<div class="mt-1">' + acEsc(r.perche) + '</div>' : '')
               + '</div>';

            h += '<div class="small text-muted mb-2">Configurazione letta da <code>' + acEsc(r.conf) + '</code>'
               + ' &middot; server di posta <code>' + acEsc(r.hostDiPosta) + '</code></div>';

            // Queste due righe NON sono il verdetto e non sono requisiti: dicono solo se la
            // rotta sta in QUESTO file. Puo' benissimo stare in un altro — e sta in un altro,
            // quando la scheda della 443 ha installato la sua superficie pubblica. Mostrarle
            // con spunta e croce le faceva sembrare condizioni da soddisfare, e invitava a
            // premere un pulsante per aggiungere una rotta che c'era gia' altrove.
            h += '<div class="small text-muted mb-2">In questo file: il nome autoconfig '
               + (r.nomeCoperto ? '&egrave; dichiarato' : 'non &egrave; dichiarato')
               + ', la rotta ' + (r.rottaPresente ? '&egrave; presente' : 'non &egrave; presente')
               + '. &Egrave; un&rsquo;informazione, non un requisito: la rotta pu&ograve; stare '
               + '(e di norma sta) nel file della scheda <em>Porta 443</em>, che serve proprio '
               + 'questo XML e la politica MTA-STS.</div>';

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
               + ((r.pronto || r.superficie443) ? ''
                  : '<button class="btn btn-sm btn-outline-success" onclick="acInstalla()">'
                    + '<i class="fas fa-screwdriver-wrench me-1"></i>Configura nginx</button>')
               + '</div>'
               // Il pulsante sparisce anche quando il file NON arriva, se la superficie sulla
               // 443 e' installata: in quel caso la causa non e' nginx, e modificare nginx.conf
               // toglierebbe autoconfig.* e mta-sts.* al blocco protetto per darli alla webmail.
               + ((!r.pronto && r.superficie443)
                  ? '<div class="alert alert-warning py-2 small mt-2 mb-0">'
                    + '<i class="fas fa-circle-info me-1"></i>Qui non c&rsquo;&egrave; niente da '
                    + 'configurare: di <code>autoconfig.&lt;dominio&gt;</code> se ne occupa gi&agrave; '
                    + 'la scheda <strong>Porta 443</strong>. Se il file non arriva, la causa &egrave; '
                    + 'altrove &mdash; quasi sempre il server web del pannello, che &egrave; chi genera '
                    + 'l&rsquo;XML: un <code>502</code> dice esattamente quello.</div>'
                  : '')
               + '<div id="acEsito" class="mt-2"></div>';

            el.innerHTML = h;
        }

        function acSpunta(v) {
            return v ? '<i class="fas fa-check-circle text-success"></i>'
                     : '<i class="fas fa-times-circle text-danger"></i>';
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
