        // Comparison between the bans that Fail2ban declares and the pf tables that should enforce them.
        //
        // The two differences are not symmetric and must not be mixed: an address that is
        // only in Fail2ban is a ban that does not bite, one that is only in pf is a block left
        // over after the unban. The first is a hole, the second is debris.
        function loadPfComparison() {
            const bodyText = document.getElementById('cpfBody');
            const badge = document.getElementById('cpfBadge');
            const btn = document.getElementById('btnCpf');
            if (btn) { btn.disabled = true; }
            bodyText.innerHTML = '<p class="text-muted small mb-0"><i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('cpf.reading')) + '</p>';
            badge.innerHTML = '';
            fetch('/api/fail2ban', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': document.getElementById('csrf_token').value },
                body: JSON.stringify({ action: 'pf_comparison' })
            })
            .then(r => r.json())
            .then(d => {
                if (btn) btn.disabled = false;
                if (!d.success) {
                    bodyText.innerHTML = '<div class="alert alert-danger py-2 mb-0">' + escHtml(t('common.error', { message: d.error || d.message || t('common.unknownError') })) + '</div>';
                    return;
                }
                const jails = d.jails || [];
                const holes = d.not_applied || 0;
                const blindOnes = d.unmeasured || 0;

                const blindBans = d.unverified_bans || 0;
                const withoutRule = d.without_rule || 0;
                // A declared, unverified ban weighs more than a stopped, unverified jail:
                // there is an address that someone believes blocked and nobody has checked.
                if (holes > 0) badge.innerHTML = '<span class="badge bg-danger">' + escHtml(tn('cpf.notApplied', holes)) + '</span>';
                else if (blindBans > 0) badge.innerHTML = '<span class="badge bg-danger">' + escHtml(tn('cpf.notVerified', blindBans)) + '</span>';
                else if (withoutRule > 0) badge.innerHTML = '<span class="badge bg-danger">' + escHtml(tn('cpf.noRule', withoutRule)) + '</span>';
                else if (blindOnes > 0) badge.innerHTML = '<span class="badge bg-warning text-dark">' + escHtml(tn('cpf.notMeasured', blindOnes)) + '</span>';
                else badge.innerHTML = '<span class="badge bg-success">' + escHtml(t('cpf.consistent')) + '</span>';

                let h = '';
                if (holes > 0) {
                    h += '<div class="alert alert-danger py-2"><i class="fas fa-triangle-exclamation me-1" aria-hidden="true"></i><strong>' + escHtml(tn('cpf.holes', holes)) + '</strong> ' + escHtml(t('cpf.holesHint')) + '</div>';
                } else if (blindBans > 0) {
                    h += '<div class="alert alert-danger py-2"><i class="fas fa-triangle-exclamation me-1" aria-hidden="true"></i><strong>' + escHtml(tn('cpf.blind', blindBans)) + '</strong> ' + escHtml(t('cpf.blindHint')) + '</div>';
                } else if (withoutRule > 0) {
                    h += '<div class="alert alert-danger py-2"><i class="fas fa-triangle-exclamation me-1" aria-hidden="true"></i><strong>' + escHtml(tn('cpf.ruleless', withoutRule)) + '</strong> ' + escHtml(t('cpf.rulelessHint')) + '</div>';
                } else if (blindOnes > 0) {
                    h += '<div class="alert alert-warning py-2"><i class="fas fa-circle-question me-1" aria-hidden="true"></i>' + escHtml(tn('cpf.unread', blindOnes)) + '</div>';
                }

                h += '<div class="table-responsive"><table class="table table-sm align-middle mb-0"><thead><tr>' +
                     '<th scope="col">Jail</th><th scope="col">' + escHtml(t('cpf.table')) + '</th><th scope="col" class="text-end">Fail2ban</th><th scope="col" class="text-end">' + escHtml(t('cpf.inPf')) + '</th><th scope="col">' + escHtml(t('dns.colOutcome')) + '</th></tr></thead><tbody>';
                jails.forEach(j => {
                    const f2b = (j.believed_banned || []).length;
                    const inPf = (j.in_firewall || []).length;
                    const missingOnes = j.only_in_fail2ban || [];
                    const leftovers = j.only_in_pf || [];
                    let outcome;
                    if (!j.read) {
                        // Unverified with active bans: red. Unverified and stopped: grey.
                        const severe = f2b > 0;
                        outcome = '<span class="' + (severe ? 'text-danger' : 'text-muted') + ' small">'
                              + (severe ? '<i class="fas fa-circle-question me-1" aria-hidden="true"></i><strong>' + escHtml(tn('cpf.notVerified', f2b)) + '.</strong> ' : '')
                              + escapeHtml(j.note || t('cpf.notMeasuredOne')) + '</span>';
                        if ((j.ban_commands || []).length > 0)
                            outcome += '<div class="small text-muted mt-1"><code>' + j.ban_commands.map(escapeHtml).join('</code><br><code>') + '</code></div>';
                        // The raw evidence, opened on request: what fail2ban answers, what it has
                        // written in the log, and which files define this jail. It is there so that it
                        // can be read and pasted to someone else without going through ssh.
                        const pieces = [];
                        if (j.actions_output) pieces.push('$ fail2ban-client get ' + j.jail + ' actions\n' + j.actions_output);
                        if (j.log) pieces.push('/var/log/fail2ban.log\n' + j.log);
                        if (j.sections) pieces.push(t('cpf.sections', { jail: j.jail }) + '\n' + j.sections);
                        if (j.dump) pieces.push('$ fail2ban-client --dp   (' + t('cpf.dumpHint') + ')\n' + j.dump);
                        if (pieces.length)
                            // Open, not collapsed behind a click: this line exists because the
                            // measurement did NOT succeed, and the evidence needed to understand why
                            // is exactly what whoever looks must have in front of their eyes.
                            outcome += '<details class="small mt-2" open><summary>' + escHtml(t('cpf.whatSees')) + '</summary>' +
                                     '<pre class="mt-1 mb-0" data-style="white-space:pre-wrap;max-height:400px;overflow:auto">' +
                                     escapeHtml(pieces.join('\n\n')) + '</pre></details>';
                    } else if (j.missing_table) {
                        outcome = '<span class="text-danger"><i class="fas fa-times-circle me-1" aria-hidden="true"></i>' + escHtml(f2b > 0 ? tn('cpf.noTableBans', f2b) : t('cpf.noTable')) + '</span>';
                    } else if (!j.rule_present) {
                        outcome = '<span class="text-danger"><i class="fas fa-times-circle me-1" aria-hidden="true"></i>' + escHtml(f2b > 0 ? t('cpf.noRuleNow', { n: f2b }) : t('cpf.noRuleText')) + '</span>';
                    } else if (missingOnes.length > 0) {
                        outcome = '<span class="text-danger"><i class="fas fa-times-circle me-1" aria-hidden="true"></i>' + escHtml(t('cpf.notBlocked')) + ' ' + missingOnes.map(escapeHtml).join(', ') + '</span>';
                    } else if (leftovers.length > 0) {
                        outcome = '<span class="text-warning"><i class="fas fa-broom me-1" aria-hidden="true"></i>' + escHtml(t('cpf.leftover')) + ' ' + leftovers.map(escapeHtml).join(', ') + '</span>';
                    } else if (f2b === 0 && inPf === 0) {
                        outcome = '<span class="text-success"><i class="fas fa-check me-1" aria-hidden="true"></i>' + escHtml(t('cpf.noneActive')) + '</span>';
                    } else {
                        outcome = '<span class="text-success"><i class="fas fa-check-circle me-1" aria-hidden="true"></i>' + escHtml(t('cpf.allApplied')) + '</span>';
                    }
                    h += '<tr><td><code>' + escapeHtml(j.jail) + '</code></td>' +
                         '<td class="small text-muted">' + (j.table ? escapeHtml(j.table) : '—') + '</td>' +
                         '<td class="text-end">' + f2b + '</td>' +
                         '<td class="text-end">' + (j.read ? inPf : '?') + '</td>' +
                         '<td>' + outcome + '</td></tr>';
                });
                h += '</tbody></table></div>';
                bodyText.innerHTML = h;
            })
            .catch(e => {
                if (btn) btn.disabled = false;
                bodyText.innerHTML = '<div class="alert alert-danger py-2 mb-0">' + escHtml(t('common.networkError', { message: e.message })) + '</div>';
            });
        }
