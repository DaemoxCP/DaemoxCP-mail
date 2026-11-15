        // ---------- Con quale utente gira ogni servizio ----------
        // Ogni utente del servizio su una riga sua: il nome, i suoi processi e a che cosa serve (reperto 228). Un
        // server di prima, che non manda roles, mostra gli utenti in fila come allora.
        function svcUsersRoles(s) {
            const roles = s.roles || [];
            if (!roles.length) return '<code>' + updEsc((s.users || []).join(', ')) + '</code>';
            let h = '<ul class="list-unstyled mb-0">';
            roles.forEach(r => {
                h += '<li class="mb-1"><code>' + updEsc(r.user) + '</code>'
                   + ((r.processes || []).length ? ' <span class="text-body-secondary">(' + updEsc(r.processes.join(', ')) + ')</span>' : '')
                   + (r.purpose ? ': ' + updEsc(r.purpose) : '') + '</li>';
            });
            return h + '</ul>';
        }

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
                   + '<td class="small">' + svcUsersRoles(s)
                   + (s.rootWhy ? '<div class="text-body-secondary mt-1"><i class="fas fa-circle-info me-1" aria-hidden="true"></i>'
                       + '<span class="visually-hidden">' + escHtml(t('su.rootWhyLabel')) + ' </span>' + updEsc(s.rootWhy) + '</div>' : '')
                   + '</td>'
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

        // Si legge da solo quando la pagina che ha la scheda si apre: e' una sola lettura (ps, i file dei pool, il cron).
        // Dopo che la pagina e' tutta letta: le funzioni che usa (updApi, t) possono stare in script piu' avanti.
        function svcUsersAuto() { if (document.getElementById('upd-svc-users')) svcUsersLoad(); }
        if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', svcUsersAuto);
        else svcUsersAuto();
