        // Confronto fra i ban che Fail2ban dichiara e le tabelle pf che li dovrebbero applicare.
        //
        // Le due differenze non sono simmetriche e non vanno mescolate: un indirizzo che sta
        // solo in Fail2ban e' un ban che non morde, uno che sta solo in pf e' un blocco rimasto
        // dopo lo sban. Il primo e' un buco, il secondo una scoria.
        function loadPfComparison() {
            const corpo = document.getElementById('cpfBody');
            const badge = document.getElementById('cpfBadge');
            const btn = document.getElementById('btnCpf');
            if (btn) { btn.disabled = true; }
            corpo.innerHTML = '<p class="text-muted small mb-0"><i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('cpf.reading')) + '</p>';
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
                    corpo.innerHTML = '<div class="alert alert-danger py-2 mb-0">' + escHtml(t('common.error', { message: d.error || d.message || t('common.unknownError') })) + '</div>';
                    return;
                }
                const jails = d.jails || [];
                const buchi = d.non_applicati || 0;
                const cieche = d.non_misurate || 0;

                const banCiechi = d.ban_non_verificati || 0;
                const senzaRegola = d.senza_regola || 0;
                // Un ban dichiarato e non verificato pesa piu' di una jail ferma non verificata:
                // c'e' un indirizzo che qualcuno crede bloccato e nessuno ha controllato.
                if (buchi > 0) badge.innerHTML = '<span class="badge bg-danger">' + escHtml(tn('cpf.notApplied', buchi)) + '</span>';
                else if (banCiechi > 0) badge.innerHTML = '<span class="badge bg-danger">' + escHtml(tn('cpf.notVerified', banCiechi)) + '</span>';
                else if (senzaRegola > 0) badge.innerHTML = '<span class="badge bg-danger">' + escHtml(tn('cpf.noRule', senzaRegola)) + '</span>';
                else if (cieche > 0) badge.innerHTML = '<span class="badge bg-warning text-dark">' + escHtml(tn('cpf.notMeasured', cieche)) + '</span>';
                else badge.innerHTML = '<span class="badge bg-success">' + escHtml(t('cpf.consistent')) + '</span>';

                let h = '';
                if (buchi > 0) {
                    h += '<div class="alert alert-danger py-2"><i class="fas fa-triangle-exclamation me-1" aria-hidden="true"></i><strong>' + escHtml(tn('cpf.holes', buchi)) + '</strong> ' + escHtml(t('cpf.holesHint')) + '</div>';
                } else if (banCiechi > 0) {
                    h += '<div class="alert alert-danger py-2"><i class="fas fa-triangle-exclamation me-1" aria-hidden="true"></i><strong>' + escHtml(tn('cpf.blind', banCiechi)) + '</strong> ' + escHtml(t('cpf.blindHint')) + '</div>';
                } else if (senzaRegola > 0) {
                    h += '<div class="alert alert-danger py-2"><i class="fas fa-triangle-exclamation me-1" aria-hidden="true"></i><strong>' + escHtml(tn('cpf.ruleless', senzaRegola)) + '</strong> ' + escHtml(t('cpf.rulelessHint')) + '</div>';
                } else if (cieche > 0) {
                    h += '<div class="alert alert-warning py-2"><i class="fas fa-circle-question me-1" aria-hidden="true"></i>' + escHtml(tn('cpf.unread', cieche)) + '</div>';
                }

                h += '<div class="table-responsive"><table class="table table-sm align-middle mb-0"><thead><tr>' +
                     '<th scope="col">Jail</th><th scope="col">' + escHtml(t('cpf.table')) + '</th><th scope="col" class="text-end">Fail2ban</th><th scope="col" class="text-end">' + escHtml(t('cpf.inPf')) + '</th><th scope="col">' + escHtml(t('dns.colOutcome')) + '</th></tr></thead><tbody>';
                jails.forEach(j => {
                    const f2b = (j.creduti_bannati || []).length;
                    const inPf = (j.nel_firewall || []).length;
                    const mancanti = j.solo_in_fail2ban || [];
                    const residui = j.solo_in_pf || [];
                    let outcome;
                    if (!j.letta) {
                        // Non verificata con ban attivi: rosso. Non verificata e ferma: grigio.
                        const grave = f2b > 0;
                        outcome = '<span class="' + (grave ? 'text-danger' : 'text-muted') + ' small">'
                              + (grave ? '<i class="fas fa-circle-question me-1" aria-hidden="true"></i><strong>' + escHtml(tn('cpf.notVerified', f2b)) + '.</strong> ' : '')
                              + escapeHtml(j.nota || t('cpf.notMeasuredOne')) + '</span>';
                        if ((j.comandi_ban || []).length > 0)
                            outcome += '<div class="small text-muted mt-1"><code>' + j.comandi_ban.map(escapeHtml).join('</code><br><code>') + '</code></div>';
                        // L'evidenza grezza, aperta a richiesta: cosa risponde fail2ban, cosa ha
                        // scritto nel log, e quali file definiscono questa jail. Serve a poterla
                        // leggere e a poterla incollare a qualcun altro senza passare da ssh.
                        const pezzi = [];
                        if (j.uscita_azioni) pezzi.push('$ fail2ban-client get ' + j.jail + ' actions\n' + j.uscita_azioni);
                        if (j.log) pezzi.push('/var/log/fail2ban.log\n' + j.log);
                        if (j.sezioni) pezzi.push(t('cpf.sections', { jail: j.jail }) + '\n' + j.sezioni);
                        if (j.dump) pezzi.push('$ fail2ban-client --dp   (' + t('cpf.dumpHint') + ')\n' + j.dump);
                        if (pezzi.length)
                            // Aperto, non richiuso dietro un click: questa riga esiste perche' la
                            // misura NON e' riuscita, e l'evidenza che serve a capire perche' e'
                            // esattamente cio' che chi guarda deve avere sotto gli occhi.
                            outcome += '<details class="small mt-2" open><summary>' + escHtml(t('cpf.whatSees')) + '</summary>' +
                                     '<pre class="mt-1 mb-0" style="white-space:pre-wrap;max-height:400px;overflow:auto">' +
                                     escapeHtml(pezzi.join('\n\n')) + '</pre></details>';
                    } else if (j.tabella_mancante) {
                        outcome = '<span class="text-danger"><i class="fas fa-times-circle me-1" aria-hidden="true"></i>' + escHtml(f2b > 0 ? tn('cpf.noTableBans', f2b) : t('cpf.noTable')) + '</span>';
                    } else if (!j.regola_presente) {
                        outcome = '<span class="text-danger"><i class="fas fa-times-circle me-1" aria-hidden="true"></i>' + escHtml(f2b > 0 ? t('cpf.noRuleNow', { n: f2b }) : t('cpf.noRuleText')) + '</span>';
                    } else if (mancanti.length > 0) {
                        outcome = '<span class="text-danger"><i class="fas fa-times-circle me-1" aria-hidden="true"></i>' + escHtml(t('cpf.notBlocked')) + ' ' + mancanti.map(escapeHtml).join(', ') + '</span>';
                    } else if (residui.length > 0) {
                        outcome = '<span class="text-warning"><i class="fas fa-broom me-1" aria-hidden="true"></i>' + escHtml(t('cpf.leftover')) + ' ' + residui.map(escapeHtml).join(', ') + '</span>';
                    } else if (f2b === 0 && inPf === 0) {
                        outcome = '<span class="text-success"><i class="fas fa-check me-1" aria-hidden="true"></i>' + escHtml(t('cpf.noneActive')) + '</span>';
                    } else {
                        outcome = '<span class="text-success"><i class="fas fa-check-circle me-1" aria-hidden="true"></i>' + escHtml(t('cpf.allApplied')) + '</span>';
                    }
                    h += '<tr><td><code>' + escapeHtml(j.jail) + '</code></td>' +
                         '<td class="small text-muted">' + (j.tabella ? escapeHtml(j.tabella) : '—') + '</td>' +
                         '<td class="text-end">' + f2b + '</td>' +
                         '<td class="text-end">' + (j.letta ? inPf : '?') + '</td>' +
                         '<td>' + outcome + '</td></tr>';
                });
                h += '</tbody></table></div>';
                corpo.innerHTML = h;
            })
            .catch(e => {
                if (btn) btn.disabled = false;
                corpo.innerHTML = '<div class="alert alert-danger py-2 mb-0">' + escHtml(t('common.networkError', { message: e.message })) + '</div>';
            });
        }
