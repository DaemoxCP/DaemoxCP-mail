        // ---------- MTA-STS ----------
        async function stsApi(azione, extra) {
            const corpo = Object.assign({ action: azione, domain_id: parseInt(currentDomainId) }, extra || {});
            const r = await fetch('/api/autodns', {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(corpo)
            });
            return await r.json();
        }

        function stsEsc(v) {
            const d = document.createElement('div');
            d.textContent = v === null || v === undefined ? '' : String(v);
            return d.innerHTML;
        }

        function stsSpunta(v) {
            return v ? '<i class="fas fa-check-circle text-success" title="' + escHtml(t('dns.yes')) + '"></i><span class="visually-hidden">' + escHtml(t('dns.yes')) + '</span>'
                     : '<i class="fas fa-times-circle text-danger" title="' + escHtml(t('acf.no')) + '"></i><span class="visually-hidden">' + escHtml(t('acf.no')) + '</span>';
        }

        async function stsCarica() {
            const el = document.getElementById('stsBody');
            if (!el) return;
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('sts.asking'));
            const r = await stsApi('mtasts_status');
            if (!r.success) {
                el.innerHTML = '<div class="alert alert-warning py-2 small mb-0">' + stsEsc(r.error) + '</div>';
                return;
            }

            const modi = [
                ['testing', 'testing — ' + t('sts.testing')],
                ['enforce', 'enforce — ' + t('sts.enforce')],
                ['none',    'none — ' + t('sts.none')]
            ];
            let h = '<div class="d-flex gap-2 align-items-end flex-wrap mb-3">'
                  + '<div><label class="form-label small mb-1" for="stsModo">' + escHtml(t('sts.mode')) + '</label>'
                  + '<select class="form-select form-select-sm" id="stsModo" style="min-width:min(26rem,100%)">'
                  + modi.map(m => '<option value="' + m[0] + '"' + (m[0] === r.modo ? ' selected' : '') + '>'
                                + stsEsc(m[1]) + '</option>').join('')
                  + '</select></div>'
                  + '<button class="btn btn-sm btn-outline-warning" onclick="stsCambiaModo()">'
                  + '<i class="fas fa-pen me-1" aria-hidden="true"></i>' + escHtml(t('sts.changeMode')) + '</button></div>';

            h += '<div class="small text-muted mb-1">' + escHtml(t('sts.served')) + '</div>'
               + '<pre class="small p-2 border rounded mb-1">' + stsEsc(r.politica) + '</pre>'
               + '<div class="small text-muted mb-3">' + escHtml(t('sts.txt')) + ' <code>' + stsEsc(r.recordTxt)
               + '</code></div>';

            h += '<div class="table-responsive"><table class="table table-sm align-middle mb-2"><thead><tr>'
               + '<th scope="col">' + escHtml(t('st.colDomain')) + '</th><th scope="col">' + escHtml(t('sts.answers')) + '</th><th scope="col"><span class="visually-hidden">' + escHtml(t('home.colActions')) + '</span></th></tr></thead><tbody>';
            (r.domini || []).forEach(d => {
                const p = d.politicaRaggiungibile || {};
                h += '<tr class="upd-cell"><td><code class="small">' + stsEsc(d.nomeWeb) + '</code>'
                   + '<div class="small text-muted">' + escHtml(t('sts.txtOn', { name: d.nomeTxt })) + '</div></td>'
                   + '<td class="small">' + stsSpunta(p.ok)
                   + (p.ok ? ' ' + escHtml(t('sts.answersOk'))
                           : '<div class="text-muted">' + stsEsc(p.errore || '') + '</div>') + '</td>'
                   + '<td class="text-end">' + (p.ok
                       ? '<button class="btn btn-sm btn-outline-success" onclick="stsPubblica()">'
                         + '<i class="fas fa-cloud-arrow-up me-1" aria-hidden="true"></i>' + escHtml(t('sts.publish')) + '</button>'
                       : '<span class="small text-muted">' + escHtml(t('sts.mustAnswerFirst')) + '</span>') + '</td></tr>';
            });
            h += '</tbody></table></div>';

            // Qui c'era una procedura manuale in quattro passi. Il terzo mandava a premere
            // "Configura nginx" nella scheda della configurazione automatica: un pulsante che
            // oggi non va premuto, perche' quella rotta la installa la scheda della 443 e
            // toccare nginx.conf toglierebbe autoconfig.* e mta-sts.* al blocco protetto.
            // Una sequenza scritta a parole diverge dal codice appena il codice cambia, e
            // continua a insegnare l'ordine di ieri: il posto giusto per l'ordine e' il
            // pulsante che lo esegue.
            h += '<div class="alert alert-secondary py-2 small mb-0"><i class="fas fa-list-ol me-1" aria-hidden="true"></i>'
               + '<strong>' + escHtml(t('sts.noManualOrder')) + '</strong> ' + escHtml(t('sts.noManualOrderHint')) + '</div>'
               + '<div id="stsOutcome" class="mt-2"></div>';

            el.innerHTML = h;
        }

        async function stsCambiaModo() {
            const sel = document.getElementById('stsModo');
            if (!sel) return;
            const modo = sel.value;
            const el = document.getElementById('stsOutcome');
            if (modo === 'enforce' && !adConferma(t('sts.confirmEnforce'), 'ENFORCE')) return;
            const r = await stsApi('mtasts_mode', { modo: modo });
            el.innerHTML = '<div class="alert alert-' + (r.success ? 'success' : 'danger') + ' py-2 small mb-0">'
                         + stsEsc(r.nota || r.error) + '</div>';
            if (r.success) setTimeout(stsCarica, 900);
        }

        async function stsPubblica() {
            const el = document.getElementById('stsOutcome');
            if (!adConferma(t('sts.confirmPublish'), t('ad.wordCreate'))) return;
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('sts.publishing'));
            const r = await stsApi('mtasts_txt', { confirm: 'CREA' });
            el.innerHTML = '<div class="alert alert-' + (r.success ? 'success' : 'danger') + ' py-2 small mb-0">'
                         + stsEsc(r.nota || r.error) + '</div>';
            if (r.success) setTimeout(stsCarica, 1200);
        }
