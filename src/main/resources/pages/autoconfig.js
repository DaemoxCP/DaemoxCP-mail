        // ---------- Configurazione automatica dei client (file XML di Thunderbird) ----------
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
               // Il verdetto viene dallo scarico vero, e qui si dice perche'. Prima veniva da
               // una ricerca dentro nginx.conf del marcatore di questa scheda, e siccome la
               // rotta la installa la scheda della 443 in un altro file, la riga diceva "non
               // serve il file" mentre il file arrivava.
               + (r.why ? '<div class="mt-1">' + acEsc(r.why) + '</div>' : '')
               + '</div>';

            h += '<div class="small text-muted mb-2">' + escHtml(t('acf.readFrom', { conf: r.conf, host: r.mailHost })) + '</div>';

            // Queste due righe NON sono il verdetto e non sono requisiti: dicono solo se la
            // rotta sta in QUESTO file. Puo' benissimo stare in un altro — e sta in un altro,
            // quando la scheda della 443 ha installato la sua superficie pubblica. Mostrarle
            // con spunta e croce le faceva sembrare condizioni da soddisfare, e invitava a
            // premere un pulsante per aggiungere una rotta che c'era gia' altrove.
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
               + '<button class="btn btn-sm btn-outline-secondary" onclick="acPreview()">'
               + '<i class="fas fa-eye me-1" aria-hidden="true"></i>' + escHtml(t('acf.viewFile')) + '</button>'
               + ((r.ready || r.surface443) ? ''
                  : '<button class="btn btn-sm btn-outline-success" onclick="acInstall()">'
                    + '<i class="fas fa-screwdriver-wrench me-1" aria-hidden="true"></i>' + escHtml(t('acf.setUpNginx')) + '</button>')
               + '</div>'
               // Il pulsante sparisce anche quando il file NON arriva, se la superficie sulla
               // 443 e' installata: in quel caso la causa non e' nginx, e modificare nginx.conf
               // toglierebbe autoconfig.* e mta-sts.* al blocco protetto per darli alla webmail.
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
                         + '<pre class="small p-2 border rounded" style="max-height:22rem;overflow:auto">'
                         + acEsc(r.xml) + '</pre>';
        }

        async function acInstall() {
            if (!adConfirm(t('acf.confirmInstall'), t('acf.wordInstall'))) return;
            const el = document.getElementById('acOutcome');
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('acf.installing'));
            const r = await acApi('install', { confirm: 'INSTALL' });
            el.innerHTML = '<div class="alert alert-' + (r.success ? 'success' : 'danger') + ' py-2 small mb-0">'
                         + acEsc(r.note || r.error) + '</div>'
                         + (r.restored ? '<div class="small text-muted mt-1">' + escHtml(t('acf.restored')) + '</div>' : '');
            if (r.success) setTimeout(acLoad, 1200);
        }
