        // ---------- MTA-STS ----------
        async function stsApi(azione, extra) {
            const corpo = Object.assign({ action: azione, domain_id: parseInt(currentDomainId) }, extra || {});
            const r = await fetch('/api/autodns', {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(corpo)
            });
            return await r.json();
        }

        function stsEsc(t) {
            const d = document.createElement('div');
            d.textContent = t === null || t === undefined ? '' : String(t);
            return d.innerHTML;
        }

        function stsSpunta(v) {
            return v ? '<i class="fas fa-check-circle text-success"></i>'
                     : '<i class="fas fa-times-circle text-danger"></i>';
        }

        async function stsCarica() {
            const el = document.getElementById('stsBody');
            if (!el) return;
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1"></i>Chiedo la politica come farebbe un server mittente...';
            const r = await stsApi('mtasts_status');
            if (!r.success) {
                el.innerHTML = '<div class="alert alert-warning py-2 small mb-0">' + stsEsc(r.error) + '</div>';
                return;
            }

            const modi = [
                ['testing', 'testing — segnala i problemi ma consegna (si comincia da qui)'],
                ['enforce', 'enforce — non consegnare se il TLS non riesce'],
                ['none',    'none — annulla una politica pubblicata prima']
            ];
            let h = '<div class="d-flex gap-2 align-items-end flex-wrap mb-3">'
                  + '<div><label class="form-label small mb-1">Modo della politica</label>'
                  + '<select class="form-select form-select-sm" id="stsModo" style="min-width:26rem">'
                  + modi.map(m => '<option value="' + m[0] + '"' + (m[0] === r.modo ? ' selected' : '') + '>'
                                + stsEsc(m[1]) + '</option>').join('')
                  + '</select></div>'
                  + '<button class="btn btn-sm btn-outline-warning" onclick="stsCambiaModo()">'
                  + '<i class="fas fa-pen me-1"></i>Cambia modo</button></div>';

            h += '<div class="small text-muted mb-1">La politica che il pannello serve, con l&rsquo;identificativo '
               + 'che i mittenti usano per accorgersi che &egrave; cambiata:</div>'
               + '<pre class="small p-2 border rounded mb-1">' + stsEsc(r.politica) + '</pre>'
               + '<div class="small text-muted mb-3">Record TXT corrispondente: <code>' + stsEsc(r.recordTxt)
               + '</code></div>';

            h += '<div class="table-responsive"><table class="table table-sm align-middle mb-2"><thead><tr>'
               + '<th>Dominio</th><th>La politica risponde</th><th></th></tr></thead><tbody>';
            (r.domini || []).forEach(d => {
                const p = d.politicaRaggiungibile || {};
                h += '<tr class="upd-cell"><td><code class="small">' + stsEsc(d.nomeWeb) + '</code>'
                   + '<div class="small text-muted">TXT su <code>' + stsEsc(d.nomeTxt) + '</code></div></td>'
                   + '<td class="small">' + stsSpunta(p.ok)
                   + (p.ok ? ' risponde correttamente'
                           : '<div class="text-muted">' + stsEsc(p.errore || '') + '</div>') + '</td>'
                   + '<td class="text-end">' + (p.ok
                       ? '<button class="btn btn-sm btn-outline-success" onclick="stsPubblica()">'
                         + '<i class="fas fa-cloud-arrow-up me-1"></i>Pubblica il TXT</button>'
                       : '<span class="small text-muted">prima deve rispondere</span>') + '</td></tr>';
            });
            h += '</tbody></table></div>';

            h += '<div class="alert alert-secondary py-2 small mb-0"><i class="fas fa-list-ol me-1"></i>'
               + '<strong>L&rsquo;ordine da seguire:</strong> 1) crea il CNAME <code>mta-sts</code> dalla scheda '
               + 'dei record opzionali qui sopra &middot; 2) rigenera il certificato dalla sezione SSL, cos&igrave; '
               + 'copre <code>mta-sts.&lt;dominio&gt;</code> &middot; 3) premi <em>Configura nginx</em> nella scheda '
               + 'della configurazione automatica &middot; 4) torna qui: quando la politica risponde, il pulsante '
               + 'per pubblicare il TXT si accende da solo.</div>'
               + '<div id="stsEsito" class="mt-2"></div>';

            el.innerHTML = h;
        }

        async function stsCambiaModo() {
            const sel = document.getElementById('stsModo');
            if (!sel) return;
            const modo = sel.value;
            const el = document.getElementById('stsEsito');
            if (modo === 'enforce' && prompt('Passare a "enforce"?\n\n'
                     + 'Da quel momento un server mittente che non riesce a stabilire una connessione\n'
                     + 'TLS valida con il tuo server NON consegna il messaggio.\n\n'
                     + 'Fallo solo dopo un periodo in "testing" senza problemi.\n'
                     + 'Scrivi ENFORCE per confermare.') !== 'ENFORCE') return;
            const r = await stsApi('mtasts_mode', { modo: modo });
            el.innerHTML = '<div class="alert alert-' + (r.success ? 'success' : 'danger') + ' py-2 small mb-0">'
                         + stsEsc(r.nota || r.error) + '</div>';
            if (r.success) setTimeout(stsCarica, 900);
        }

        async function stsPubblica() {
            const el = document.getElementById('stsEsito');
            if (prompt('Pubblicare il record TXT MTA-STS?\n\n'
                     + 'La politica risponde gia\', quindi la dichiarazione e\' mantenuta da subito.\n'
                     + 'Scrivi CREA per confermare.') !== 'CREA') return;
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1"></i>Pubblico su Cloudflare...';
            const r = await stsApi('mtasts_txt', { confirm: 'CREA' });
            el.innerHTML = '<div class="alert alert-' + (r.success ? 'success' : 'danger') + ' py-2 small mb-0">'
                         + stsEsc(r.nota || r.error) + '</div>';
            if (r.success) setTimeout(stsCarica, 1200);
        }
