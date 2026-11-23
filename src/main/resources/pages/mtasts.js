        // ---------- MTA-STS ----------
        async function stsApi(actionItem, extra) {
            const bodyText = Object.assign({ action: actionItem, domain_id: parseInt(currentDomainId) }, extra || {});
            const r = await fetch('/api/autodns', {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(bodyText)
            });
            return await r.json();
        }

        function stsEsc(v) {
            const d = document.createElement('div');
            d.textContent = v === null || v === undefined ? '' : String(v);
            return d.innerHTML;
        }

        function stsTick(v) {
            return v ? '<i class="fas fa-check-circle text-success" title="' + escHtml(t('dns.yes')) + '"></i><span class="visually-hidden">' + escHtml(t('dns.yes')) + '</span>'
                     : '<i class="fas fa-times-circle text-danger" title="' + escHtml(t('acf.no')) + '"></i><span class="visually-hidden">' + escHtml(t('acf.no')) + '</span>';
        }

        async function stsLoad() {
            const el = document.getElementById('stsBody');
            if (!el) return;
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('sts.asking'));
            const r = await stsApi('mtasts_status');
            if (!r.success) {
                el.innerHTML = '<div class="alert alert-warning py-2 small mb-0">' + stsEsc(r.error) + '</div>';
                return;
            }

            const modes = [
                ['testing', 'testing — ' + t('sts.testing')],
                ['enforce', 'enforce — ' + t('sts.enforce')],
                ['none',    'none — ' + t('sts.none')]
            ];
            let h = '<div class="d-flex gap-2 align-items-end flex-wrap mb-3">'
                  + '<div><label class="form-label small mb-1" for="stsMode">' + escHtml(t('sts.mode')) + '</label>'
                  + '<select class="form-select form-select-sm" id="stsMode" data-style="min-width:min(26rem,100%)">'
                  + modes.map(m => '<option value="' + m[0] + '"' + (m[0] === r.mode ? ' selected' : '') + '>'
                                + stsEsc(m[1]) + '</option>').join('')
                  + '</select></div>'
                  + '<button class="btn btn-sm btn-outline-warning" data-on-click="stsChangeMode()">'
                  + '<i class="fas fa-pen me-1" aria-hidden="true"></i>' + escHtml(t('sts.changeMode')) + '</button></div>';

            h += '<div class="small text-muted mb-1">' + escHtml(t('sts.served')) + '</div>'
               + '<pre class="small p-2 border rounded mb-1">' + stsEsc(r.policy) + '</pre>'
               + '<div class="small text-muted mb-3">' + escHtml(t('sts.txt')) + ' <code>' + stsEsc(r.recordTxt)
               + '</code></div>';

            h += '<div class="table-responsive"><table class="table table-sm align-middle mb-2"><thead><tr>'
               + '<th scope="col">' + escHtml(t('st.colDomain')) + '</th><th scope="col">' + escHtml(t('sts.answers')) + '</th><th scope="col"><span class="visually-hidden">' + escHtml(t('home.colActions')) + '</span></th></tr></thead><tbody>';
            (r.domains || []).forEach(d => {
                const p = d.policyReachable || {};
                h += '<tr class="upd-cell"><td><code class="small">' + stsEsc(d.webName) + '</code>'
                   + '<div class="small text-muted">' + escHtml(t('sts.txtOn', { name: d.txtName })) + '</div></td>'
                   + '<td class="small">' + stsTick(p.ok)
                   + (p.ok ? ' ' + escHtml(t('sts.answersOk'))
                           : '<div class="text-muted">' + stsEsc(p.error || '') + '</div>') + '</td>'
                   + '<td class="text-end">' + (p.ok
                       ? '<button class="btn btn-sm btn-outline-success" data-on-click="stsPublish()">'
                         + '<i class="fas fa-cloud-arrow-up me-1" aria-hidden="true"></i>' + escHtml(t('sts.publish')) + '</button>'
                       : '<span class="small text-muted">' + escHtml(t('sts.mustAnswerFirst')) + '</span>') + '</td></tr>';
            });
            h += '</tbody></table></div>';

            // Here there was a manual procedure in four steps. The third sent people to press
            // "Set up nginx" in the automatic configuration card: a button that today must
            // not be pressed, because that route is installed by the 443 card and touching
            // nginx.conf would take autoconfig.* and mta-sts.* away from the protected block.
            // A sequence written in words diverges from the code as soon as the code changes,
            // and keeps teaching yesterday's order: the right place for the order is the
            // button that runs it.
            h += '<div class="alert alert-secondary py-2 small mb-0"><i class="fas fa-list-ol me-1" aria-hidden="true"></i>'
               + '<strong>' + escHtml(t('sts.noManualOrder')) + '</strong> ' + escHtml(t('sts.noManualOrderHint')) + '</div>'
               + '<div id="stsOutcome" class="mt-2"></div>';

            el.innerHTML = h;
        }

        async function stsChangeMode() {
            const sel = document.getElementById('stsMode');
            if (!sel) return;
            const modeValue = sel.value;
            const el = document.getElementById('stsOutcome');
            if (modeValue === 'enforce' && !await adConfirm(t('sts.confirmEnforce'), 'ENFORCE')) return;
            const r = await stsApi('mtasts_mode', { mode: modeValue });
            el.innerHTML = '<div class="alert alert-' + (r.success ? 'success' : 'danger') + ' py-2 small mb-0">'
                         + stsEsc(r.note || r.error) + '</div>';
            if (r.success) setTimeout(stsLoad, 900);
        }

        async function stsPublish() {
            const el = document.getElementById('stsOutcome');
            if (!await adConfirm(t('sts.confirmPublish'), t('ad.wordCreate'))) return;
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('sts.publishing'));
            const r = await stsApi('mtasts_txt', { confirm: 'CREATE' });
            el.innerHTML = '<div class="alert alert-' + (r.success ? 'success' : 'danger') + ' py-2 small mb-0">'
                         + stsEsc(r.note || r.error) + '</div>';
            if (r.success) setTimeout(stsLoad, 1200);
        }
