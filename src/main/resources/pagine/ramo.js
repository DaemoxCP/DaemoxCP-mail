
        // ---------- ramo dei pacchetti: quarterly o latest (RamoPkg sul server) ----------
        // La scheda si legge da sola all'apertura: pkg -vv non va in rete e risponde subito.
        // Cambiare ramo invece scarica il catalogo nuovo, quindi e' un lavoro con il suo registro.
        let ramoDati = null, ramoVerso = '';

        function ramoEl(tag, classe, testo) {
            const e = document.createElement(tag);
            if (classe) e.className = classe;
            if (testo !== undefined && testo !== null) e.textContent = testo;
            return e;
        }

        async function ramoStato() {
            const box = document.getElementById('ramo-body');
            box.textContent = t('up.readingPkg');
            document.getElementById('ramo-anteprima').textContent = '';
            const r = await updApi('ramo_stato');
            box.textContent = '';
            if (!r.success) {
                box.appendChild(ramoEl('div', 'alert alert-secondary py-2 small mb-0', r.error || t('up.branchUnreadable')));
                return;
            }
            ramoDati = r;
            const testa = ramoEl('p', 'mb-1');
            if (r.ramo === 'quarterly' || r.ramo === 'latest') {
                testa.append(...tNodes('up.branchFrom', { branch: ramoEl('span', 'badge ' + (r.ramo === 'latest' ? 'bg-info text-dark' : 'bg-secondary') + ' fs-6', r.ramo) }));
            } else if (r.ramo === 'misti') {
                testa.appendChild(ramoEl('span', 'badge bg-warning text-dark fs-6', t('up.mixedBranches')));
            } else {
                testa.appendChild(ramoEl('span', 'badge bg-secondary fs-6', t('up.noOfficialBranch')));
            }
            box.appendChild(testa);
            box.appendChild(ramoEl('p', 'small mb-2', r.spiegazione));

            const tab = ramoEl('table', 'table table-sm align-middle mb-2 tabella-schede');
            tab.setAttribute('aria-label', t('up.pkgRepos'));
            const th = tab.createTHead().insertRow();
            const COL = [t('up.colRepo'), t('up.colWhatFor'), t('up.colBranch'), t('up.colEnabled'), t('up.colAddress')];
            COL.forEach(titolo => {
                const c = ramoEl('th', '', titolo);
                c.scope = 'col';
                th.appendChild(c);
            });
            const corpo = tab.createTBody();
            (r.repository || []).forEach(x => {
                const tr = corpo.insertRow();
                const celle = [[x.nome, COL[0]], [x.ruolo, COL[1]], [x.ramo || '-', COL[2]],
                               [x.acceso ? t('dns.yes') : t('acf.no'), COL[3]]];
                celle.forEach(([testo, etichetta]) => {
                    const td = ramoEl('td', '', testo);
                    td.setAttribute('data-label', etichetta);
                    tr.appendChild(td);
                });
                const ind = ramoEl('td', 'testo-lungo');
                ind.setAttribute('data-label', COL[4]);
                ind.appendChild(ramoEl('code', 'small', x.url));
                tr.appendChild(ind);
            });
            const riquadro = ramoEl('div', 'table-responsive');
            riquadro.appendChild(tab);
            box.appendChild(riquadro);

            const file = ramoEl('p', 'small text-muted mb-2');
            if (r.fileDelPannello) {
                file.append(...tNodes('up.branchByFile', { file: ramoEl('code', '', r.file) }));
            } else {
                file.textContent = t('up.noPanelFile');
            }
            box.appendChild(file);
            if (r.base) box.appendChild(ramoEl('p', 'small text-muted mb-2', r.base));

            if (!r.cambiabile) {
                box.appendChild(ramoEl('div', 'alert alert-secondary py-2 small mb-0', r.motivo));
                return;
            }
            const azioni = ramoEl('div', 'd-flex flex-wrap gap-2');
            (r.verso || []).forEach(v => {
                const b = ramoEl('button', 'btn btn-sm btn-outline-warning', t('up.switchTo', { branch: v }));
                b.type = 'button';
                b.addEventListener('click', () => ramoAnteprima(v));
                azioni.appendChild(b);
            });
            box.appendChild(azioni);
        }

        async function ramoAnteprima(verso) {
            const box = document.getElementById('ramo-anteprima');
            box.textContent = t('up.buildingPreview');
            document.getElementById('ramo-esito').textContent = '';
            const r = await updApi('ramo_anteprima', { verso: verso });
            box.textContent = '';
            if (!r.success) { box.appendChild(ramoEl('div', 'alert alert-danger py-2 small', r.error)); return; }
            if (!r.possibile) { box.appendChild(ramoEl('div', 'alert alert-secondary py-2 small', r.motivo)); return; }
            ramoVerso = verso;
            ramoDati.impronta = r.impronta;
            const card = ramoEl('div', 'border rounded p-3');
            card.appendChild(ramoEl('h6', 'mb-2', t('up.switchFromTo', { from: r.da, to: verso })));
            const cambi = ramoEl('ul', 'small mb-2');
            (r.cambi || []).forEach(c => {
                const li = ramoEl('li', 'testo-lungo');
                li.appendChild(ramoEl('strong', '', c.nome + ': '));
                li.append(...tNodes('up.becomes', { from: ramoEl('code', '', c.da), to: ramoEl('code', '', c.a) }));
                cambi.appendChild(li);
            });
            card.appendChild(cambi);
            const avvisi = ramoEl('ul', 'small testo-avviso mb-2');
            (r.avvisi || []).forEach(a => avvisi.appendChild(ramoEl('li', '', a)));
            card.appendChild(avvisi);
            const dove = ramoEl('p', 'small mb-1');
            dove.append(...tNodes('up.fileWritten', { file: ramoEl('code', '', r.file) }));
            card.appendChild(dove);
            card.appendChild(ramoEl('pre', 'small border rounded p-2 mb-1', r.contenuto));
            if (r.comeTorna) card.appendChild(ramoEl('p', 'small text-muted mb-2', r.comeTorna));
            const lab = ramoEl('label', 'form-label small mb-1', t('up.typeBranch', { branch: verso }));
            lab.htmlFor = 'ramo-conferma';
            card.appendChild(lab);
            const riga = ramoEl('div', 'd-flex flex-wrap gap-2 align-items-center');
            const inp = ramoEl('input', 'form-control form-control-sm');
            inp.id = 'ramo-conferma';
            inp.style.maxWidth = '14rem';
            inp.autocomplete = 'off';
            inp.spellcheck = false;
            const via = ramoEl('button', 'btn btn-sm btn-danger', t('up.changeBranch'));
            via.type = 'button';
            via.id = 'ramo-via';
            via.disabled = true;
            inp.addEventListener('input', () => { via.disabled = inp.value.trim() !== verso; });
            via.addEventListener('click', ramoCambia);
            const annulla = ramoEl('button', 'btn btn-sm btn-secondary', t('common.cancel'));
            annulla.type = 'button';
            annulla.addEventListener('click', () => { box.textContent = ''; });
            riga.append(inp, via, annulla);
            card.appendChild(riga);
            box.appendChild(card);
            inp.focus();
        }

        async function ramoCambia() {
            const inp = document.getElementById('ramo-conferma');
            const esito = document.getElementById('ramo-esito');
            if (!inp || inp.value.trim() !== ramoVerso) return;
            document.getElementById('ramo-via').disabled = true;
            const r = await updApi('ramo_cambia', { verso: ramoVerso, impronta: ramoDati.impronta, confirm: inp.value.trim() });
            if (!r.success) {
                esito.textContent = '';
                esito.appendChild(ramoEl('div', 'alert alert-danger py-2 small mb-0', r.error || t('up.changeNotStarted')));
                document.getElementById('ramo-via').disabled = false;
                return;
            }
            document.getElementById('ramo-anteprima').textContent = '';
            esito.textContent = t('up.changingBranch');
            const pre = document.getElementById('ramo-log');
            pre.style.display = 'block';
            pre.textContent = '';
            ramoSegui(r.jobId);
        }

        async function ramoSegui(id) {
            const s = await updApi('job_status', { jobId: id });
            const esito = document.getElementById('ramo-esito');
            const pre = document.getElementById('ramo-log');
            if (s.success && s.job) {
                pre.textContent = s.job.consoleLog || '';
                pre.scrollTop = pre.scrollHeight;
                if (s.job.status === 'completed' || s.job.status === 'error') {
                    esito.textContent = '';
                    const ok = s.job.status === 'completed';
                    esito.appendChild(ramoEl('div', 'alert ' + (ok ? 'alert-success' : 'alert-danger') + ' py-2 small mb-0',
                        ok ? (s.job.result || t('up.branchChanged')) : (s.job.errorMessage || t('up.branchChangeFailed'))));
                    ramoStato();
                    return;
                }
            }
            setTimeout(() => ramoSegui(id), 2000);
        }

        ramoStato();
