        // ---------- MTA-STS: un pulsante solo ----------
        // La sequenza e' di sette passi e l'ordine conta: ogni passo e' il presupposto del
        // successivo. Farla fare a mano significa sbagliare l'ordine, quindi la conosce il
        // pannello, che sa anche a che punto e' e riparte da li'.
        async function amsPiano() {
            const el = document.getElementById('upd-ams');
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1"></i>Guardo a che punto siamo: nginx, certificato, DNS, e provo la politica da fuori...';
            const r = await updApi('mtasts_piano');
            if (!r.success) {
                el.innerHTML = '<div class="alert alert-danger py-2 small mb-0">' + updEsc(r.error) + '</div>';
                return;
            }
            let h = '<div class="alert alert-' + (r.completo ? 'success' : 'info') + ' py-2 small mb-2">'
                  + '<i class="fas fa-' + (r.completo ? 'check-circle' : 'circle-info') + ' me-1"></i>'
                  + updEsc(r.nota) + '</div>';

            h += '<div class="table-responsive"><table class="table table-sm align-middle mb-2"><tbody>';
            (r.passi || []).forEach((p, i) => {
                const fatto = p.stato === 'fatto';
                const incerto = p.stato === 'incerto';
                // "incerto" non e' verde: il pannello non ha potuto verificare, e mostrarlo
                // come fatto sarebbe la bugia che stiamo cercando di togliere dal pannello.
                h += '<tr class="upd-cell"><td style="width:2rem">'
                   + (fatto ? '<i class="fas fa-check-circle text-success"></i>'
                            : incerto
                              ? '<i class="fas fa-question-circle text-secondary" title="non verificabile"></i>'
                              : '<i class="fas fa-circle text-warning" style="font-size:.6rem"></i>')
                   + '</td><td class="small"><strong>' + (i + 1) + '. ' + updEsc(p.titolo) + '</strong>'
                   + (p.dettaglio ? '<div class="text-muted">' + updEsc(p.dettaglio) + '</div>' : '')
                   + (p.motivo ? '<div class="text-warning">' + updEsc(p.motivo) + '</div>' : '')
                   + '</td></tr>';
            });
            h += '</tbody></table></div>';

            if (!r.completo)
                h += '<button class="btn btn-sm btn-success" onclick="amsAttiva()">'
                   + '<i class="fas fa-play me-1"></i>Attiva MTA-STS su tutto</button>';
            h += '<div id="amsEsito" class="mt-2"></div>';
            el.innerHTML = h;
        }

        async function amsAttiva() {
            if (prompt('Attivare MTA-STS su tutti i domini?\n\n'
                     + 'Il pannello esegue nell\'ordine: riga di include in nginx, configurazione\n'
                     + 'della 443, jail fail2ban, un CNAME mta-sts per dominio, certificato che\n'
                     + 'copre quei nomi, prova della politica, e infine il record TXT.\n\n'
                     + 'Il record TXT viene pubblicato SOLO per i domini la cui politica risponde\n'
                     + 'davvero. Al primo passo che fallisce si ferma e spiega.\n\n'
                     + 'Il certificato viene riemesso: e\' il passo piu\' delicato.\n\n'
                     + 'Scrivi ATTIVA per confermare.') !== 'ATTIVA') return;
            const el = document.getElementById('amsEsito');
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1"></i>Eseguo la sequenza. '
                         + 'L&rsquo;emissione del certificato pu&ograve; richiedere un minuto...';
            const r = await updApi('mtasts_attiva', { confirm: 'ATTIVA' });
            if (!r.success || !r.jobId) {
                el.innerHTML = '<div class="alert alert-danger py-2 small mb-0">'
                             + updEsc(r.error || 'avvio non riuscito') + '</div>';
                return;
            }
            // La richiesta torna SUBITO con un identificativo: l'emissione del certificato
            // dura piu' del limite di tempo del proxy, e tenendo aperta la richiesta il
            // browser riceverebbe una pagina di errore mentre sul server l'operazione
            // continua — lasciando lo stato sconosciuto proprio mentre si tocca il
            // certificato di produzione.
            el.innerHTML = '<div class="alert alert-info py-2 small mb-2">'
                         + '<i class="fas fa-spinner fa-spin me-1"></i>Sequenza in corso. '
                         + 'Puoi anche chiudere la pagina: il lavoro prosegue sul server.</div>'
                         + '<pre id="amsLog" class="small p-2 border rounded mb-0" '
                         + 'style="max-height:26rem;overflow:auto"></pre>';
            amsSegui(r.jobId);
        }

        async function amsSegui(id) {
            const el = document.getElementById('amsEsito');
            const pre = document.getElementById('amsLog');
            const s = await updApi('job_status', { jobId: id });
            if (s.success && s.job) {
                if (pre) { pre.textContent = s.job.consoleLog || ''; pre.scrollTop = pre.scrollHeight; }
                if (s.job.status === 'completed' || s.job.status === 'error') {
                    const box = el.querySelector('.alert');
                    if (box) {
                        box.className = 'alert alert-' + (s.job.status === 'completed' ? 'success' : 'warning')
                                      + ' py-2 small mb-2';
                        box.innerHTML = (s.job.status === 'completed'
                                ? '<i class="fas fa-check-circle me-1"></i>Sequenza completata in '
                                  + updEsc(s.job.elapsedSeconds) + 's.'
                                : '<i class="fas fa-triangle-exclamation me-1"></i>Sequenza interrotta: '
                                  + updEsc(s.job.errorMessage) + ' Il registro qui sotto dice a che punto.')
                            + ' <button class="btn btn-sm btn-outline-primary ms-2" onclick="amsPiano()">'
                            + 'Aggiorna lo stato</button>';
                    }
                    return;
                }
            }
            setTimeout(() => amsSegui(id), 3000);
        }
