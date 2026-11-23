        // ---------- Which user each service runs as ----------
        // Each user of the service on a line of its own: the name, its processes and what it is for (finding
        // 228). An older server, which does not send roles, shows the users in a row as before.
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

        // Whether the service runs something as root: only what must (and which processes), nothing, or something
        // that does not need it. Said in words, the icon only next to them.
        function svcUsersRoot(s) {
            const list = (s.rootProcesses || []).join(', ');
            if (s.root === 'needed')
                return '<i class="fas fa-shield-halved text-body-secondary me-1" aria-hidden="true"></i>' + escHtml(t('su.rootOnly', { processes: list }));
            if (s.root === 'needless')
                return '<i class="fas fa-triangle-exclamation text-warning me-1" aria-hidden="true"></i>' + escHtml(t('su.rootNeedless', { processes: list }));
            return '<i class="fas fa-user-check text-success me-1" aria-hidden="true"></i>' + escHtml(t('su.rootNone'));
        }

        // The official pages behind what the row says, in a new tab and without telling them where the click came
        // from (noreferrer: the panel's address stays private). The addresses come from the panel's code, and only
        // https ones are drawn.
        function svcUsersDocs(s) {
            const docs = (s.docs || []).filter(d => /^https:\/\/[A-Za-z0-9.-]+\/[^\s"'<>]*$/.test(d.url || ''));
            if (!docs.length) return '';
            let h = '<div class="mt-1"><span class="text-body-secondary">' + escHtml(t('su.docs')) + '</span>'
                  + '<ul class="list-unstyled mb-0 ms-3">';
            docs.forEach(d => {
                h += '<li><a href="' + escHtml(d.url) + '" target="_blank" rel="noopener noreferrer">' + escHtml(d.title)
                   + '<span class="visually-hidden"> ' + escHtml(t('su.newTab')) + '</span>'
                   + ' <i class="fas fa-arrow-up-right-from-square small" aria-hidden="true"></i></a></li>';
            });
            return h + '</ul></div>';
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

            // On phone and tablet the rows become cards (table-cards, the layout's): every cell says its column.
            const lab = k => ' data-label="' + escHtml(t(k)) + '"';
            h += '<div class="table-responsive"><table class="table table-sm align-middle mb-3 table-cards">'
               + '<caption class="small">' + escHtml(t('su.caption')) + '</caption><thead><tr>'
               + '<th scope="col">' + escHtml(t('su.colService')) + '</th><th scope="col">' + escHtml(t('su.colRoot'))
               + '</th><th scope="col">' + escHtml(t('su.colUsers'))
               + '</th><th scope="col">' + escHtml(t('up.colResult')) + '</th></tr></thead><tbody>';
            (r.services || []).forEach(s => {
                h += '<tr class="upd-cell"><td class="small"' + lab('su.colService') + '><code>' + updEsc(s.service) + '</code></td>'
                   + '<td class="small"' + lab('su.colRoot') + '>' + svcUsersRoot(s) + '</td>'
                   + '<td class="small"' + lab('su.colUsers') + '>' + svcUsersRoles(s)
                   + (s.rootWhy ? '<div class="text-body-secondary mt-1"><i class="fas fa-circle-info me-1" aria-hidden="true"></i>'
                       + '<span class="visually-hidden">' + escHtml(t('su.rootWhyLabel')) + ' </span>' + updEsc(s.rootWhy) + '</div>' : '')
                   + svcUsersDocs(s) + '</td>'
                   + '<td class="small"' + lab('up.colResult') + '>' + (s.ok
                       ? '<i class="fas fa-check-circle text-success" aria-hidden="true"></i> ' + escHtml(t('su.ok'))
                       : '<i class="fas fa-triangle-exclamation text-warning" aria-hidden="true"></i> ' + escHtml(t('su.warn'))) + '</td></tr>';
            });
            h += '</tbody></table></div>';

            if ((r.pools || []).length) {
                h += '<div class="table-responsive"><table class="table table-sm align-middle mb-0 table-cards">'
                   + '<caption class="small">' + escHtml(t('su.poolsCaption')) + '</caption><thead><tr>'
                   + '<th scope="col">' + escHtml(t('su.colPool')) + '</th><th scope="col">' + escHtml(t('su.colUser'))
                   + '</th><th scope="col">' + escHtml(t('su.colFile')) + '</th></tr></thead><tbody>';
                r.pools.forEach(p => {
                    h += '<tr class="upd-cell"><td class="small"' + lab('su.colPool') + '><code>' + updEsc(p.pool) + '</code></td>'
                       + '<td class="small"' + lab('su.colUser') + '><code>' + updEsc(p.user) + '</code></td>'
                       + '<td class="small"' + lab('su.colFile') + '><code>' + updEsc(p.file) + '</code></td></tr>';
                });
                h += '</tbody></table></div>';
            }
            el.innerHTML = h;
        }

        // It reads itself when the page that has the card opens: it is a single read (ps, the pool files, the
        // cron). After the whole page has been read: the functions it uses (updApi, t) can be in later scripts.
        function svcUsersAuto() { if (document.getElementById('upd-svc-users')) svcUsersLoad(); }
        if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', svcUsersAuto);
        else svcUsersAuto();
