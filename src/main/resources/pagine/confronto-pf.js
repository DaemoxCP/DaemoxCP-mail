        // Confronto fra i ban che Fail2ban dichiara e le tabelle pf che li dovrebbero applicare.
        //
        // Le due differenze non sono simmetriche e non vanno mescolate: un indirizzo che sta
        // solo in Fail2ban e' un ban che non morde, uno che sta solo in pf e' un blocco rimasto
        // dopo lo sban. Il primo e' un buco, il secondo una scoria.
        function caricaConfrontoPf() {
            const corpo = document.getElementById('cpfBody');
            const badge = document.getElementById('cpfBadge');
            const btn = document.getElementById('btnCpf');
            if (btn) { btn.disabled = true; }
            corpo.innerHTML = '<p class="text-muted small mb-0"><i class="fas fa-spinner fa-spin me-1"></i>Leggo le tabelle di pf...</p>';
            badge.innerHTML = '';
            fetch('/api/fail2ban', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': document.getElementById('csrf_token').value },
                body: JSON.stringify({ action: 'confronto_pf' })
            })
            .then(r => r.json())
            .then(d => {
                if (btn) btn.disabled = false;
                if (!d.success) {
                    corpo.innerHTML = '<div class="alert alert-danger py-2 mb-0">Errore: ' + escapeHtml(d.error || d.message || 'sconosciuto') + '</div>';
                    return;
                }
                const jails = d.jails || [];
                const buchi = d.non_applicati || 0;
                const cieche = d.non_misurate || 0;

                const banCiechi = d.ban_non_verificati || 0;
                const senzaRegola = d.senza_regola || 0;
                // Un ban dichiarato e non verificato pesa piu' di una jail ferma non verificata:
                // c'e' un indirizzo che qualcuno crede bloccato e nessuno ha controllato.
                if (buchi > 0) badge.innerHTML = '<span class="badge bg-danger">' + buchi + ' ban non applicati</span>';
                else if (banCiechi > 0) badge.innerHTML = '<span class="badge bg-danger">' + banCiechi + ' ban non verificati</span>';
                else if (senzaRegola > 0) badge.innerHTML = '<span class="badge bg-danger">' + senzaRegola + ' tabelle senza regola</span>';
                else if (cieche > 0) badge.innerHTML = '<span class="badge bg-warning text-dark">' + cieche + ' jail non misurate</span>';
                else badge.innerHTML = '<span class="badge bg-success">Coerenti</span>';

                let h = '';
                if (buchi > 0) {
                    h += '<div class="alert alert-danger py-2"><i class="fas fa-triangle-exclamation me-1"></i><strong>' + buchi + ' indirizzi risultano bannati ma pf non li blocca.</strong> Fail2ban li conta fra i suoi ban e la pagina li mostra bannati: in realtà passano.</div>';
                } else if (banCiechi > 0) {
                    h += '<div class="alert alert-danger py-2"><i class="fas fa-triangle-exclamation me-1"></i><strong>' + banCiechi + ' indirizzi sono dichiarati bannati senza che io possa verificarlo.</strong> Non sto dicendo che passino: sto dicendo che nessuno ha controllato, e il comando che quelle jail eseguono è scritto qui sotto perché si possa guardare.</div>';
                } else if (senzaRegola > 0) {
                    h += '<div class="alert alert-danger py-2"><i class="fas fa-triangle-exclamation me-1"></i><strong>' + senzaRegola + ' jail hanno una tabella che nessuna regola pf legge.</strong> Fail2ban ci scrive dentro gli indirizzi e pf non li guarda: il ban risulta eseguito e non blocca. È il controllo che fa fail2ban stesso (<code>pfctl -sr</code>), e la causa tipica è una regola rifiutata all\'avvio dell\'azione.</div>';
                } else if (cieche > 0) {
                    h += '<div class="alert alert-warning py-2"><i class="fas fa-circle-question me-1"></i>Di ' + cieche + ' jail non ho potuto leggere la tabella: per quelle non sto dicendo che vada bene, sto dicendo che non lo so.</div>';
                }

                h += '<div class="table-responsive"><table class="table table-sm align-middle mb-0"><thead><tr>' +
                     '<th>Jail</th><th>Tabella pf</th><th class="text-end">Fail2ban</th><th class="text-end">In pf</th><th>Esito</th></tr></thead><tbody>';
                jails.forEach(j => {
                    const f2b = (j.creduti_bannati || []).length;
                    const inPf = (j.nel_firewall || []).length;
                    const mancanti = j.solo_in_fail2ban || [];
                    const residui = j.solo_in_pf || [];
                    let esito;
                    if (!j.letta) {
                        // Non verificata con ban attivi: rosso. Non verificata e ferma: grigio.
                        const grave = f2b > 0;
                        esito = '<span class="' + (grave ? 'text-danger' : 'text-muted') + ' small">'
                              + (grave ? '<i class="fas fa-circle-question me-1"></i><strong>' + f2b + ' ban non verificati.</strong> ' : '')
                              + escapeHtml(j.nota || 'non misurata') + '</span>';
                        if ((j.comandi_ban || []).length > 0)
                            esito += '<div class="small text-muted mt-1"><code>' + j.comandi_ban.map(escapeHtml).join('</code><br><code>') + '</code></div>';
                        // L'evidenza grezza, aperta a richiesta: cosa risponde fail2ban, cosa ha
                        // scritto nel log, e quali file definiscono questa jail. Serve a poterla
                        // leggere e a poterla incollare a qualcun altro senza passare da ssh.
                        const pezzi = [];
                        if (j.uscita_azioni) pezzi.push('$ fail2ban-client get ' + j.jail + ' actions\n' + j.uscita_azioni);
                        if (j.log) pezzi.push('/var/log/fail2ban.log\n' + j.log);
                        if (j.sezioni) pezzi.push('Sezioni [' + j.jail + '] nei file di configurazione\n' + j.sezioni);
                        if (pezzi.length)
                            esito += '<details class="small mt-2"><summary>Cosa vede fail2ban (da incollare)</summary>' +
                                     '<pre class="mt-1 mb-0" style="white-space:pre-wrap;max-height:400px;overflow:auto">' +
                                     escapeHtml(pezzi.join('\n\n')) + '</pre></details>';
                    } else if (j.tabella_mancante) {
                        esito = '<span class="text-danger"><i class="fas fa-times-circle me-1"></i>La tabella non esiste: ' + (f2b > 0 ? 'nessuno di questi ' + f2b + ' ban blocca niente' : 'il primo ban non bloccherebbe niente') + '</span>';
                    } else if (!j.regola_presente) {
                        esito = '<span class="text-danger"><i class="fas fa-times-circle me-1"></i>Nessuna regola pf legge questa tabella: gli indirizzi ci finiscono dentro e passano lo stesso' + (f2b > 0 ? ' (' + f2b + ' adesso)' : '') + '</span>';
                    } else if (mancanti.length > 0) {
                        esito = '<span class="text-danger"><i class="fas fa-times-circle me-1"></i>Non bloccati: ' + mancanti.map(escapeHtml).join(', ') + '</span>';
                    } else if (residui.length > 0) {
                        esito = '<span class="text-warning"><i class="fas fa-broom me-1"></i>Rimasti in pf dopo lo sban: ' + residui.map(escapeHtml).join(', ') + '</span>';
                    } else if (f2b === 0 && inPf === 0) {
                        esito = '<span class="text-success"><i class="fas fa-check me-1"></i>Nessun ban attivo; tabella e regola pf sono al loro posto</span>';
                    } else {
                        esito = '<span class="text-success"><i class="fas fa-check-circle me-1"></i>Tutti applicati davvero</span>';
                    }
                    h += '<tr><td><code>' + escapeHtml(j.jail) + '</code></td>' +
                         '<td class="small text-muted">' + (j.tabella ? escapeHtml(j.tabella) : '—') + '</td>' +
                         '<td class="text-end">' + f2b + '</td>' +
                         '<td class="text-end">' + (j.letta ? inPf : '?') + '</td>' +
                         '<td>' + esito + '</td></tr>';
                });
                h += '</tbody></table></div>';
                corpo.innerHTML = h;
            })
            .catch(e => {
                if (btn) btn.disabled = false;
                corpo.innerHTML = '<div class="alert alert-danger py-2 mb-0">Errore rete: ' + escapeHtml(e.message) + '</div>';
            });
        }
