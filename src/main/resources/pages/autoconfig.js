        // ---------- Automatic client configuration (Thunderbird's XML file) ----------
        async function acApi(actionItem, extra) {
            const r = await fetch('/api/autoconfig', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(Object.assign({ action: actionItem }, extra || {}))
            });
            return await r.json();
        }

        function acEsc(v) {
            const d = document.createElement('div');
            d.textContent = v === null || v === undefined ? '' : String(v);
            return d.innerHTML;
        }

        async function acLoad() {
            const el = document.getElementById('acBody');
            if (!el) return;
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('acf.reading'));
            const r = await acApi('status');
            if (!r.success || r.error) {
                el.innerHTML = '<div class="alert alert-warning py-2 small mb-0">' + acEsc(r.error || t('acf.unreadable')) + '</div>';
                return;
            }

            let h = '';
            h += '<div class="alert alert-' + (r.ready ? 'success' : 'warning') + ' py-2 small mb-2">'
               + '<i class="fas fa-' + (r.ready ? 'check-circle' : 'triangle-exclamation') + ' me-1" aria-hidden="true"></i>'
               + escHtml(r.ready ? t('acf.arrives') : t('acf.doesNotArrive'))
               // The verdict comes from the real download, and the reason is given here. Before, it came
               // from a search inside nginx.conf for this card's marker, and since the
               // route is installed by the 443 card in another file, the line said "the file
               // is not served" while the file was arriving.
               + (r.why ? '<div class="mt-1">' + acEsc(r.why) + '</div>' : '')
               + '</div>';

            h += '<div class="small text-muted mb-2">' + escHtml(t('acf.readFrom', { conf: r.conf, host: r.mailHost })) + '</div>';

            // These two lines are NOT the verdict and are not requirements: they only say whether the
            // route is in THIS file. It may well be in another one, and it is in another one
            // when the 443 card has installed its public surface. Showing them
            // with a tick and a cross made them look like conditions to meet, and invited
            // pressing a button to add a route that already existed elsewhere.
            h += '<div class="small text-muted mb-2">'
               + escHtml((r.coveredName ? t('acf.nameDeclared') : t('acf.nameNotDeclared')) + ' ' + (r.brokenPresent ? t('acf.routePresent') : t('acf.routeMissing')))
               + ' ' + escHtml(t('acf.infoOnly')) + '</div>';

            if (r.domains && r.domains.length) {
                h += '<div class="small fw-bold mb-1">' + escHtml(t('acf.perDomain')) + '</div>'
                   + '<div class="table-responsive"><table class="table table-sm align-middle mb-2"><thead><tr>'
                   + '<th scope="col">' + escHtml(t('acf.colName')) + '</th><th scope="col">' + escHtml(t('acf.colResolves')) + '</th><th scope="col">' + escHtml(t('acf.colCert')) + '</th>'
                   + '<th scope="col">' + escHtml(t('acf.colArrives')) + '</th></tr></thead><tbody>';
                r.domains.forEach(d => {
                    const p = d.test || {};
                    h += '<tr><td><code class="small">' + acEsc(d.name) + '</code></td>'
                       + '<td>' + acTick(d.dns) + '</td>'
                       + '<td>' + acTick(d.certificate) + '</td>'
                       + '<td>' + acTick(p.ok)
                       + (p.ok ? '' : '<div class="small text-muted">' + acEsc(p.error || '') + '</div>')
                       + '</td></tr>';
                });
                h += '</tbody></table></div>'
                   + '<div class="small text-muted mb-2">' + escHtml(t('acf.lastColumn')) + '</div>';
            }

            h += '<div class="d-flex gap-2 flex-wrap">'
               + '<button class="btn btn-sm btn-outline-secondary" data-on-click="acPreview()">'
               + '<i class="fas fa-eye me-1" aria-hidden="true"></i>' + escHtml(t('acf.viewFile')) + '</button>'
               + ((r.ready || r.surface443) ? ''
                  : '<button class="btn btn-sm btn-outline-success" data-on-click="acInstall()">'
                    + '<i class="fas fa-screwdriver-wrench me-1" aria-hidden="true"></i>' + escHtml(t('acf.setUpNginx')) + '</button>')
               + '</div>'
               // The button disappears also when the file does NOT arrive, if the surface on
               // 443 is installed: in that case the cause is not nginx, and editing nginx.conf
               // would take autoconfig.* and mta-sts.* away from the protected block to give
               // them to the webmail.
               + ((!r.ready && r.surface443)
                  ? '<div class="alert alert-warning py-2 small mt-2 mb-0">'
                    + '<i class="fas fa-circle-info me-1" aria-hidden="true"></i>' + escHtml(t('acf.handledBy443')) + '</div>'
                  : '')
               + '<div id="acOutcome" class="mt-2"></div>';

            el.innerHTML = h;
        }

        function acTick(v) {
            return v ? '<i class="fas fa-check-circle text-success" title="' + escHtml(t('dns.yes')) + '"></i><span class="visually-hidden">' + escHtml(t('dns.yes')) + '</span>'
                     : '<i class="fas fa-times-circle text-danger" title="' + escHtml(t('acf.no')) + '"></i><span class="visually-hidden">' + escHtml(t('acf.no')) + '</span>';
        }


        async function acPreview() {
            const el = document.getElementById('acOutcome');
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('acf.generating'));
            const r = await acApi('preview');
            if (!r.success) {
                el.innerHTML = '<div class="alert alert-danger py-2 small mb-0">' + acEsc(r.error) + '</div>';
                return;
            }
            el.innerHTML = '<div class="small text-muted mb-1">' + escHtml(t('acf.example', { domain: r.domain, n: r.domainCount })) + '</div>'
                         + '<pre class="small p-2 border rounded" data-style="max-height:22rem;overflow:auto">'
                         + acEsc(r.xml) + '</pre>';
        }

        async function acInstall() {
            if (!await adConfirm(t('acf.confirmInstall'), t('acf.wordInstall'))) return;
            const el = document.getElementById('acOutcome');
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('acf.installing'));
            const r = await acApi('install', { confirm: 'INSTALL' });
            el.innerHTML = '<div class="alert alert-' + (r.success ? 'success' : 'danger') + ' py-2 small mb-0">'
                         + acEsc(r.note || r.error) + '</div>'
                         + (r.restored ? '<div class="small text-muted mt-1">' + escHtml(t('acf.restored')) + '</div>' : '');
            if (r.success) setTimeout(acLoad, 1200);
        }
