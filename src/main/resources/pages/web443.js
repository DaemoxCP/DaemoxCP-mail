        // ---------- Apertura protetta della porta 443 ----------
        async function w443Load() {
            const el = document.getElementById('upd-443');
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('w4.reading')) + '';
            // UNA ALLA VOLTA: updApi ha un lucchetto (updBusy) che serve a impedire due
            // operazioni contemporanee. Chiamandole in parallelo la seconda tornava subito
            // con "Operazione gia' in corso", e il riquadro restava vuoto senza spiegazione.
            const s = await updApi('web443_status');
            if (!s.success) {
                el.innerHTML = '<div class="alert alert-danger py-2 small mb-0">' + updEsc(s.error) + '</div>';
                return;
            }
            const c = await updApi('web443_config');
            const inc = s.include || {};
            let h = '<div class="alert alert-' + (s.ready ? 'success' : 'secondary') + ' py-2 small mb-2">'
                  + '<i class="fas fa-' + (s.ready ? 'check-circle' : 'circle-info') + ' me-1" aria-hidden="true"></i>'
                  + escHtml(s.ready ? t('w4.ready') : t('w4.notReady')) + '</div>';

            h += '<table class="table table-sm mb-2"><tbody>'
               + w443Line(escHtml(t('w4.nginxReads')), inc.ok, updEsc(inc.reason || ''))
               + w443Line(escHtml(t('w4.installed')), s.installed,
                          '<code>' + updEsc(s.file) + '</code>')
               + w443Line(escHtml(t('w4.policyWritten')), s.policyWritten,
                          '<code>' + updEsc(s.policyFile) + '</code> &mdash; ' + escHtml(t('w4.policyStatic')))
               + '</tbody></table>';

            // E se l'anteprima non arriva si DICE perche', invece di mostrare un riquadro
            // vuoto che sembra un difetto grafico.
            h += '<div class="small text-muted mb-2">' + escHtml(t('w4.whatInstalled')) + '</div>';
            if (c && c.success && c.configuration)
                h += '<pre class="small p-2 border rounded mb-2" style="max-height:22rem;overflow:auto">'
                   + updEsc(c.configuration) + '</pre>';
            else
                h += '<div class="alert alert-warning py-2 small mb-2">' + escHtml(t('w4.noPreview', { reason: (c && c.error) || t('w4.unknownReason') })) + '</div>';

            h += '<div class="d-flex gap-2 flex-wrap">'
               + (inc.ok ? '' : '<button class="btn btn-sm btn-warning" onclick="w443Include()">'
                              + '<i class="fas fa-plus me-1" aria-hidden="true"></i>' + escHtml(t('w4.addInclude')) + '</button>')
               + '<button class="btn btn-sm btn-outline-warning"'
               + (inc.ok ? '' : ' disabled title="' + escHtml(t('w4.includeFirst')) + '"')
               + ' onclick="w443Install()">'
               + '<i class="fas fa-screwdriver-wrench me-1" aria-hidden="true"></i>' + escHtml(s.installed ? t('w4.reinstall') : t('w4.open'))
               + '</button>'
               + '<button class="btn btn-sm btn-outline-secondary" onclick="w443Jail()">'
               + '<i class="fas fa-ban me-1" aria-hidden="true"></i>' + escHtml(t('w4.enableJail')) + '</button>'
               + '</div><div id="w443Outcome" class="mt-2"></div>';

            el.innerHTML = h;
        }

        function w443Line(whatItem, state, noteText) {
            const i = state === null || state === undefined
                ? '<i class="fas fa-circle-question text-secondary" aria-hidden="true"></i><span class="visually-hidden">' + escHtml(t('wd.unknown')) + '</span>'
                : (state ? '<i class="fas fa-check-circle text-success" aria-hidden="true"></i><span class="visually-hidden">' + escHtml(t('dns.yes')) + '</span>'
                         : '<i class="fas fa-times-circle text-danger" aria-hidden="true"></i><span class="visually-hidden">' + escHtml(t('acf.no')) + '</span>');
            return '<tr><td style="width:2rem">' + i + '</td><td class="small">' + whatItem
                 + '<div class="text-muted">' + noteText + '</div></td></tr>';
        }

        // Su questo server nginx tiene tutto nel file principale e non include cartelle:
        // senza questa riga, qualunque file aggiuntivo verrebbe ignorato.
        async function w443Include() {
            if (!updConfirm(t('w4.confirmInclude'), t('w4.wAdd'))) return;
            const el = document.getElementById('w443Outcome');
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('w4.changing')) + '';
            const r = await updApi('web443_include', { confirm: 'ADD' });
            let h = '<div class="alert alert-' + (r.success ? 'success' : 'danger') + ' py-2 small mb-0">'
                  + updEsc(r.note || r.error) + '</div>';
            if (r.restored)
                h += '<div class="small text-muted mt-1">' + escHtml(t('w4.restored')) + '</div>';
            el.innerHTML = h;
            if (r.success) setTimeout(w443Load, 1200);
        }

        async function w443Install() {
            if (!updConfirm(t('w4.confirmInstall'), t('w4.wOpen'))) return;
            const el = document.getElementById('w443Outcome');
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('w4.writing')) + '';
            const r = await updApi('web443_install', { confirm: 'OPEN' });
            let h = '<div class="alert alert-' + (r.success ? 'success' : 'danger') + ' py-2 small mb-0">'
                  + updEsc(r.note || r.error) + '</div>';
            if (r.restored)
                h += '<div class="small text-muted mt-1">' + escHtml(t('w4.restored')) + '</div>';
            el.innerHTML = h;
            if (r.success) setTimeout(w443Load, 1200);
        }

        async function w443Jail() {
            if (!updConfirm(t('w4.confirmJail'), t('w4.wEnable'))) return;
            const el = document.getElementById('w443Outcome');
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('w4.jailWriting')) + '';
            const r = await updApi('web443_jail', { confirm: 'ENABLE' });
            el.innerHTML = '<div class="alert alert-' + (r.success ? 'success' : 'danger') + ' py-2 small mb-0">'
                         + updEsc(r.note || r.error) + '</div>'
                         + (r.state ? '<pre class="small p-2 border rounded mt-1 mb-0">' + updEsc(r.state) + '</pre>' : '');
        }
