        // ---------- Cosa espone il web server ----------
        async function webDiag() {
            const el = document.getElementById('upd-web');
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1"></i>Leggo nginx, le porte in ascolto, pf e fail2ban...';
            const r = await updApi('web_diagnosi');
            if (!r.success) {
                el.innerHTML = '<div class="alert alert-danger py-2 small mb-0">' + updEsc(r.error || 'diagnosi fallita') + '</div>';
                return;
            }

            const grave = r.contenutiInChiaro;
            let h = '<div class="alert alert-' + (grave ? 'danger' : 'info') + ' py-2 small mb-3">'
                  + '<i class="fas fa-' + (grave ? 'triangle-exclamation' : 'circle-info') + ' me-1"></i>'
                  + updEsc(r.verdetto) + '</div>';

            if (!r.nginxLeggibile) {
                h += '<div class="alert alert-warning py-2 small mb-3">' + updEsc(r.nginxProblema) + '</div>';
            } else {
                h += '<div class="small fw-bold mb-1">I siti che nginx serve davvero</div>'
                   + '<div class="table-responsive"><table class="table table-sm align-middle mb-3"><thead><tr>'
                   + '<th>Ascolta</th><th>Nomi</th><th>Cosa serve</th><th>Esito</th></tr></thead><tbody>';
                (r.siti || []).forEach(s => {
                    let cosa = [];
                    if (s.servePhp) cosa.push('PHP');
                    if (s.serveFile) cosa.push('file da <code>' + updEsc(s.radice) + '</code>');
                    if (s.soloRedirect) cosa.push('solo un rimando');
                    if (!cosa.length) cosa.push('niente');
                    h += '<tr class="upd-cell"><td><code class="small">' + updEsc(s.ascolta) + '</code>'
                       + (s.cifrato ? ' <span class="badge bg-success">cifrato</span>'
                                    : ' <span class="badge bg-warning text-dark">in chiaro</span>') + '</td>'
                       + '<td class="small"><code>' + updEsc(s.nomi || '(nessuno)') + '</code></td>'
                       + '<td class="small">' + cosa.join(', ') + '</td>'
                       + '<td class="small">' + (s.inChiaro
                           ? '<i class="fas fa-times-circle text-danger"></i> <strong>serve contenuti senza '
                             + 'cifratura</strong>: chi lo usa manda tutto in chiaro'
                           : '<i class="fas fa-check-circle text-success"></i> a posto') + '</td></tr>';
                });
                h += '</tbody></table></div>';

                h += '<div class="table-responsive"><table class="table table-sm mb-3"><tbody>'
                   + webRiga('Limite di frequenza (<code>limit_req</code>)', r.limitReq,
                             'Senza, un solo indirizzo puo&rsquo; inondare di richieste finch&eacute; nginx cede.')
                   + webRiga('Limite di connessioni (<code>limit_conn</code>)', r.limitConn,
                             'Senza, un solo indirizzo puo&rsquo; tenere aperte tutte le connessioni disponibili.')
                   + webRiga('Jail fail2ban per nginx', r.fail2banLetto ? r.jailNginx : null,
                             r.fail2banLetto ? 'Chi insiste sulle porte web non viene bannato.'
                                             : 'Non ho potuto interrogare fail2ban.')
                   + webRiga('Regole di pf leggibili', r.pfLetto ? true : null,
                             r.pfLetto ? ('Regole totali: ' + updEsc(r.pfRegole)
                                        + (r.pfCita443 ? '. La 443 compare.' : '. La 443 non compare fra le regole.'))
                                       : 'Non ho potuto leggere pfctl: non so se le porte web siano filtrate.')
                   + '</tbody></table></div>';

                if (r.sslProtocols)
                    h += '<div class="small text-muted mb-1">Protocolli TLS: <code>' + updEsc(r.sslProtocols) + '</code></div>';
                if (r.workerConnections)
                    h += '<div class="small text-muted mb-2"><code>' + updEsc(r.workerConnections) + '</code></div>';
            }

            if (r.inAscoltoLetto && r.inAscolto)
                h += '<div class="small fw-bold mb-1">In ascolto sulle porte 80 e 443</div>'
                   + '<pre class="small p-2 border rounded mb-0">' + updEsc(r.inAscolto) + '</pre>';
            else
                h += '<div class="small text-muted">Non ho potuto elencare le porte in ascolto.</div>';

            el.innerHTML = h;
        }

        function webRiga(cosa, stato, nota) {
            const icona = stato === null || stato === undefined
                ? '<i class="fas fa-circle-question text-secondary"></i>'
                : (stato ? '<i class="fas fa-check-circle text-success"></i>'
                         : '<i class="fas fa-times-circle text-danger"></i>');
            return '<tr><td style="width:2rem">' + icona + '</td><td class="small">' + cosa
                 + '<div class="text-muted">' + nota + '</div></td></tr>';
        }
