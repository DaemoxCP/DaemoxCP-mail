        // ---------- MTA-STS: a single button ----------
        // The sequence has eight steps and the order matters: each step is the precondition of
        // the next. Having it done by hand means getting the order wrong, so the panel knows it,
        // and it also knows where it is and resumes from there.
        async function amsPlan() {
            const el = document.getElementById('upd-ams');
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('ams.reading')) + '';
            const r = await updApi('mtasts_plan');
            if (!r.success) {
                el.innerHTML = '<div class="alert alert-danger py-2 small mb-0">' + updEsc(r.error) + '</div>';
                return;
            }
            let h = '<div class="alert alert-' + (r.complete ? 'success' : 'info') + ' py-2 small mb-2">'
                  + '<i class="fas fa-' + (r.complete ? 'check-circle' : 'circle-info') + ' me-1" aria-hidden="true"></i>'
                  + updEsc(r.note) + '</div>';

            h += '<div class="table-responsive"><table class="table table-sm align-middle mb-2"><tbody>';
            (r.steps || []).forEach((p, i) => {
                const done = p.state === 'done';
                const uncertain = p.state === 'uncertain';
                // "uncertain" is not green: the panel could not verify, and showing it
                // as done would be the lie we are trying to remove from the panel.
                h += '<tr class="upd-cell"><td data-style="width:2rem">'
                   + (done ? '<i class="fas fa-check-circle text-success" aria-hidden="true"></i><span class="visually-hidden">' + escHtml(t('up.pDone')) + '</span>'
                            : uncertain
                              ? '<i class="fas fa-question-circle text-secondary" aria-hidden="true" title="' + escHtml(t('ams.unverifiable')) + '"></i><span class="visually-hidden">' + escHtml(t('ams.unverifiable')) + '</span>'
                              : '<i class="fas fa-circle text-warning" data-style="font-size:.6rem" aria-hidden="true"></i><span class="visually-hidden">' + escHtml(t('up.pTodo')) + '</span>')
                   + '</td><td class="small"><strong>' + (i + 1) + '. ' + updEsc(p.title) + '</strong>'
                   + (p.detail ? '<div class="text-muted">' + updEsc(p.detail) + '</div>' : '')
                   + (p.reason ? '<div class="text-warning">' + updEsc(p.reason) + '</div>' : '')
                   + '</td></tr>';
            });
            h += '</tbody></table></div>';

            if (!r.complete)
                h += '<button class="btn btn-sm btn-success" data-on-click="amsEnable()">'
                   + '<i class="fas fa-play me-1" aria-hidden="true"></i>' + escHtml(t('ams.run')) + '</button>';
            h += '<div id="amsOutcome" class="mt-2"></div>';
            el.innerHTML = h;
        }

        async function amsEnable() {
            if (!await updConfirm(t('ams.confirm'), t('w4.wEnable'))) return;
            const el = document.getElementById('amsOutcome');
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('ams.running')) + '';
            const r = await updApi('mtasts_enable', { confirm: 'ENABLE' });
            if (!r.success || !r.jobId) {
                el.innerHTML = '<div class="alert alert-danger py-2 small mb-0">'
                             + updEsc(r.error || t('ams.startFailed')) + '</div>';
                return;
            }
            // The request returns AT ONCE with an identifier: issuing the certificate
            // takes longer than the proxy's time limit, and keeping the request open the
            // browser would receive an error page while on the server the operation
            // goes on, leaving the state unknown precisely while the production
            // certificate is being touched.
            el.innerHTML = '<div class="alert alert-info py-2 small mb-2">'
                         + '<i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('ams.inProgress')) + '</div>'
                         + '<pre id="amsLog" class="small p-2 border rounded mb-0" '
                         + 'data-style="max-height:26rem;overflow:auto"></pre>';
            amsFollow(r.jobId);
        }

        async function amsFollow(id) {
            const el = document.getElementById('amsOutcome');
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
                                ? '<i class="fas fa-check-circle me-1" aria-hidden="true"></i>' + escHtml(t('ams.done', { s: s.job.elapsedSeconds }))
                                : '<i class="fas fa-triangle-exclamation me-1" aria-hidden="true"></i>' + escHtml(t('ams.stopped', { error: s.job.errorMessage })))
                            + ' <button class="btn btn-sm btn-outline-primary ms-2" data-on-click="amsPlan()">'
                            + escHtml(t('ams.refresh')) + '</button>';
                    }
                    return;
                }
            }
            setTimeout(() => amsFollow(id), 3000);
        }
