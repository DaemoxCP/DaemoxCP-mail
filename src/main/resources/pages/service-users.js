        // ---------- Con quale utente gira ogni servizio ----------
        async function svcUsersLoad() {
            const el = document.getElementById('upd-svc-users');
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('su.reading'));
            const r = await updApi('service_users');
            if (!r.success) {
                el.innerHTML = '<div class="alert alert-danger py-2 small mb-0" role="alert">' + updEsc(r.error || t('su.failed')) + '</div>';
                return;
            }

            const problems = r.problems || [];
            let h = '<div class="alert alert-' + (problems.length ? 'warning' : 'success') + ' py-2 small mb-3" role="status">'
                  + '<i class="fas fa-' + (problems.length ? 'triangle-exclamation' : 'check-circle') + ' me-1" aria-hidden="true"></i>'
                  + escHtml(problems.length ? t('su.warnings', { n: problems.length }) : t('su.none')) + '</div>';
            if (problems.length) {
                h += '<ul class="small mb-3">';
                problems.forEach(p => { h += '<li>' + updEsc(p.text) + '</li>'; });
                h += '</ul>';
            }

            h += '<div class="table-responsive"><table class="table table-sm align-middle mb-3">'
               + '<caption class="small">' + escHtml(t('su.caption')) + '</caption><thead><tr>'
               + '<th scope="col">' + escHtml(t('su.colService')) + '</th><th scope="col">' + escHtml(t('su.colUsers'))
               + '</th><th scope="col">' + escHtml(t('up.colResult')) + '</th></tr></thead><tbody>';
            (r.services || []).forEach(s => {
                h += '<tr class="upd-cell"><td class="small"><code>' + updEsc(s.service) + '</code></td>'
                   + '<td class="small"><code>' + updEsc((s.users || []).join(', ')) + '</code></td>'
                   + '<td class="small">' + (s.ok
                       ? '<i class="fas fa-check-circle text-success" aria-hidden="true"></i> ' + escHtml(t('su.ok'))
                       : '<i class="fas fa-triangle-exclamation text-warning" aria-hidden="true"></i> ' + escHtml(t('su.warn'))) + '</td></tr>';
            });
            h += '</tbody></table></div>';

            if ((r.pools || []).length) {
                h += '<div class="table-responsive"><table class="table table-sm align-middle mb-0">'
                   + '<caption class="small">' + escHtml(t('su.poolsCaption')) + '</caption><thead><tr>'
                   + '<th scope="col">' + escHtml(t('su.colPool')) + '</th><th scope="col">' + escHtml(t('su.colUser'))
                   + '</th><th scope="col">' + escHtml(t('su.colFile')) + '</th></tr></thead><tbody>';
                r.pools.forEach(p => {
                    h += '<tr class="upd-cell"><td class="small"><code>' + updEsc(p.pool) + '</code></td>'
                       + '<td class="small"><code>' + updEsc(p.user) + '</code></td>'
                       + '<td class="small"><code>' + updEsc(p.file) + '</code></td></tr>';
                });
                h += '</tbody></table></div>';
            }
            el.innerHTML = h;
        }
