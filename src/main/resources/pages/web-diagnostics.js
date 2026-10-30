        // ---------- Cosa espone il web server ----------
        async function webDiag() {
            const el = document.getElementById('upd-web');
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('wd.reading')) + '';
            const r = await updApi('web_diagnosis');
            if (!r.success) {
                el.innerHTML = '<div class="alert alert-danger py-2 small mb-0">' + updEsc(r.error || t('wd.failed')) + '</div>';
                return;
            }

            const severe = r.plainContents;
            let h = '<div class="alert alert-' + (severe ? 'danger' : 'info') + ' py-2 small mb-3">'
                  + '<i class="fas fa-' + (severe ? 'triangle-exclamation' : 'circle-info') + ' me-1" aria-hidden="true"></i>'
                  + updEsc(r.verdict) + '</div>';

            if (!r.nginxReadable) {
                h += '<div class="alert alert-warning py-2 small mb-3">' + updEsc(r.nginxProblem) + '</div>';
            } else {
                h += '<div class="small fw-bold mb-1">' + escHtml(t('wd.sites')) + '</div>'
                   + '<div class="table-responsive"><table class="table table-sm align-middle mb-3"><thead><tr>'
                   + '<th scope="col">' + escHtml(t('wd.colListen')) + '</th><th scope="col">' + escHtml(t('wd.colNames')) + '</th><th scope="col">' + escHtml(t('wd.colServes')) + '</th><th scope="col">' + escHtml(t('up.colResult')) + '</th></tr></thead><tbody>';
                (r.sites || []).forEach(s => {
                    let whatItem = [];
                    if (s.servePhp) whatItem.push('PHP');
                    if (s.serveFile) whatItem.push(t('wd.filesFrom.html', { root: updEsc(s.root) }));
                    if (s.soloRedirect) whatItem.push(escHtml(t('wd.redirectOnly')));
                    if (!whatItem.length) whatItem.push(escHtml(t('wd.nothing')));
                    h += '<tr class="upd-cell"><td><code class="small">' + updEsc(s.listens) + '</code>'
                       + (s.encrypted ? ' <span class="badge bg-success">' + escHtml(t('wd.encrypted')) + '</span>'
                                    : ' <span class="badge bg-warning text-dark">' + escHtml(t('wd.clear')) + '</span>') + '</td>'
                       + '<td class="small"><code>' + updEsc(s.names || t('fw.none')) + '</code></td>'
                       + '<td class="small">' + whatItem.join(', ') + '</td>'
                       + '<td class="small">' + (s.inPlain
                           ? '<i class="fas fa-times-circle text-danger" aria-hidden="true"></i> ' + t('wd.servesClear.html')
                           : '<i class="fas fa-check-circle text-success" aria-hidden="true"></i> ' + escHtml(t('wd.ok')) + '') + '</td></tr>';
                });
                h += '</tbody></table></div>';

                h += '<div class="table-responsive"><table class="table table-sm mb-3"><tbody>'
                   + webLine(t('wd.limitReq.html'), r.limitReq, escHtml(t('wd.limitReqNote')))
                   + webLine(t('wd.limitConn.html'), r.limitConn, escHtml(t('wd.limitConnNote')))
                   + webLine(escHtml(t('wd.jail')), r.fail2banRead ? r.jailNginx : null,
                             escHtml(r.fail2banRead ? t('wd.jailNote') : t('wd.jailUnread')))
                   + webLine(escHtml(t('wd.pfReadable')), r.pfRead ? true : null,
                             escHtml(r.pfRead ? t('wd.pfRules', { n: r.pfRules }) + ' ' + (r.pfMentions443 ? t('wd.pf443') : t('wd.pfNo443'))
                                               : t('wd.pfUnread')))
                   + '</tbody></table></div>';

                if (r.sslProtocols)
                    h += '<div class="small text-muted mb-1">' + escHtml(t('wd.tlsProtocols')) + ' <code>' + updEsc(r.sslProtocols) + '</code></div>';
                if (r.workerConnections)
                    h += '<div class="small text-muted mb-2"><code>' + updEsc(r.workerConnections) + '</code></div>';
            }

            if (r.listeningRead && r.listening)
                h += '<div class="small fw-bold mb-1">' + escHtml(t('wd.listening')) + '</div>'
                   + '<pre class="small p-2 border rounded mb-0">' + updEsc(r.listening) + '</pre>';
            else
                h += '<div class="small text-muted">' + escHtml(t('wd.noListen')) + '</div>';

            el.innerHTML = h;
        }

        function webLine(whatItem, state, noteText) {
            const iconName = state === null || state === undefined
                ? '<i class="fas fa-circle-question text-secondary" aria-hidden="true"></i><span class="visually-hidden">' + escHtml(t('wd.unknown')) + '</span>'
                : (state ? '<i class="fas fa-check-circle text-success" aria-hidden="true"></i><span class="visually-hidden">' + escHtml(t('dns.yes')) + '</span>'
                         : '<i class="fas fa-times-circle text-danger" aria-hidden="true"></i><span class="visually-hidden">' + escHtml(t('acf.no')) + '</span>');
            return '<tr><td style="width:2rem">' + iconName + '</td><td class="small">' + whatItem
                 + '<div class="text-muted">' + noteText + '</div></td></tr>';
        }
