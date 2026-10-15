
        // ---------- ramo dei pacchetti: quarterly o latest (RamoPkg sul server) ----------
        // La scheda si legge da sola all'apertura: pkg -vv non va in rete e risponde subito.
        // Cambiare ramo invece scarica il catalogo nuovo, quindi e' un lavoro con il suo registro.
        let branchData = null, ramoVerso = '';

        function branchEl(tag, classe, testo) {
            const e = document.createElement(tag);
            if (classe) e.className = classe;
            if (testo !== undefined && testo !== null) e.textContent = testo;
            return e;
        }

        async function branchStatus() {
            const box = document.getElementById('ramo-body');
            box.textContent = t('up.readingPkg');
            document.getElementById('ramo-anteprima').textContent = '';
            const r = await updApi('ramo_stato');
            box.textContent = '';
            if (!r.success) {
                box.appendChild(branchEl('div', 'alert alert-secondary py-2 small mb-0', r.error || t('up.branchUnreadable')));
                return;
            }
            branchData = r;
            const testa = branchEl('p', 'mb-1');
            if (r.ramo === 'quarterly' || r.ramo === 'latest') {
                testa.append(...tNodes('up.branchFrom', { branch: branchEl('span', 'badge ' + (r.ramo === 'latest' ? 'bg-info text-dark' : 'bg-secondary') + ' fs-6', r.ramo) }));
            } else if (r.ramo === 'misti') {
                testa.appendChild(branchEl('span', 'badge bg-warning text-dark fs-6', t('up.mixedBranches')));
            } else {
                testa.appendChild(branchEl('span', 'badge bg-secondary fs-6', t('up.noOfficialBranch')));
            }
            box.appendChild(testa);
            box.appendChild(branchEl('p', 'small mb-2', r.explanation));

            const tab = branchEl('table', 'table table-sm align-middle mb-2 tabella-schede');
            tab.setAttribute('aria-label', t('up.pkgRepos'));
            const th = tab.createTHead().insertRow();
            const COL = [t('up.colRepo'), t('up.colWhatFor'), t('up.colBranch'), t('up.colEnabled'), t('up.colAddress')];
            COL.forEach(titolo => {
                const c = branchEl('th', '', titolo);
                c.scope = 'col';
                th.appendChild(c);
            });
            const corpo = tab.createTBody();
            (r.repository || []).forEach(x => {
                const tr = corpo.insertRow();
                const celle = [[x.nome, COL[0]], [x.ruolo, COL[1]], [x.ramo || '-', COL[2]],
                               [x.acceso ? t('dns.yes') : t('acf.no'), COL[3]]];
                celle.forEach(([testo, etichetta]) => {
                    const td = branchEl('td', '', testo);
                    td.setAttribute('data-label', etichetta);
                    tr.appendChild(td);
                });
                const ind = branchEl('td', 'testo-lungo');
                ind.setAttribute('data-label', COL[4]);
                ind.appendChild(branchEl('code', 'small', x.url));
                tr.appendChild(ind);
            });
            const riquadro = branchEl('div', 'table-responsive');
            riquadro.appendChild(tab);
            box.appendChild(riquadro);

            const file = branchEl('p', 'small text-muted mb-2');
            if (r.panelOwnedFile) {
                file.append(...tNodes('up.branchByFile', { file: branchEl('code', '', r.file) }));
            } else {
                file.textContent = t('up.noPanelFile');
            }
            box.appendChild(file);
            if (r.base) box.appendChild(branchEl('p', 'small text-muted mb-2', r.base));

            if (!r.changeable) {
                box.appendChild(branchEl('div', 'alert alert-secondary py-2 small mb-0', r.reason));
                return;
            }
            const azioni = branchEl('div', 'd-flex flex-wrap gap-2');
            (r.verso || []).forEach(v => {
                const b = branchEl('button', 'btn btn-sm btn-outline-warning', t('up.switchTo', { branch: v }));
                b.type = 'button';
                b.addEventListener('click', () => branchPreview(v));
                azioni.appendChild(b);
            });
            box.appendChild(azioni);
        }

        async function branchPreview(verso) {
            const box = document.getElementById('ramo-anteprima');
            box.textContent = t('up.buildingPreview');
            document.getElementById('ramo-esito').textContent = '';
            const r = await updApi('ramo_anteprima', { verso: verso });
            box.textContent = '';
            if (!r.success) { box.appendChild(branchEl('div', 'alert alert-danger py-2 small', r.error)); return; }
            if (!r.possibile) { box.appendChild(branchEl('div', 'alert alert-secondary py-2 small', r.reason)); return; }
            ramoVerso = verso;
            branchData.fingerprint = r.fingerprint;
            const card = branchEl('div', 'border rounded p-3');
            card.appendChild(branchEl('h6', 'mb-2', t('up.switchFromTo', { from: r.da, to: verso })));
            const changes = branchEl('ul', 'small mb-2');
            (r.changes || []).forEach(c => {
                const li = branchEl('li', 'testo-lungo');
                li.appendChild(branchEl('strong', '', c.nome + ': '));
                li.append(...tNodes('up.becomes', { from: branchEl('code', '', c.da), to: branchEl('code', '', c.a) }));
                changes.appendChild(li);
            });
            card.appendChild(changes);
            const warnings = branchEl('ul', 'small testo-avviso mb-2');
            (r.warnings || []).forEach(a => warnings.appendChild(branchEl('li', '', a)));
            card.appendChild(warnings);
            const dove = branchEl('p', 'small mb-1');
            dove.append(...tNodes('up.fileWritten', { file: branchEl('code', '', r.file) }));
            card.appendChild(dove);
            card.appendChild(branchEl('pre', 'small border rounded p-2 mb-1', r.contenuto));
            if (r.comeTorna) card.appendChild(branchEl('p', 'small text-muted mb-2', r.comeTorna));
            const lab = branchEl('label', 'form-label small mb-1', t('up.typeBranch', { branch: verso }));
            lab.htmlFor = 'ramo-conferma';
            card.appendChild(lab);
            const riga = branchEl('div', 'd-flex flex-wrap gap-2 align-items-center');
            const inp = branchEl('input', 'form-control form-control-sm');
            inp.id = 'ramo-conferma';
            inp.style.maxWidth = '14rem';
            inp.autocomplete = 'off';
            inp.spellcheck = false;
            const via = branchEl('button', 'btn btn-sm btn-danger', t('up.changeBranch'));
            via.type = 'button';
            via.id = 'ramo-via';
            via.disabled = true;
            inp.addEventListener('input', () => { via.disabled = inp.value.trim() !== verso; });
            via.addEventListener('click', branchChange);
            const annulla = branchEl('button', 'btn btn-sm btn-secondary', t('common.cancel'));
            annulla.type = 'button';
            annulla.addEventListener('click', () => { box.textContent = ''; });
            riga.append(inp, via, annulla);
            card.appendChild(riga);
            box.appendChild(card);
            inp.focus();
        }

        async function branchChange() {
            const inp = document.getElementById('ramo-conferma');
            const esito = document.getElementById('ramo-esito');
            if (!inp || inp.value.trim() !== ramoVerso) return;
            document.getElementById('ramo-via').disabled = true;
            const r = await updApi('ramo_cambia', { verso: ramoVerso, fingerprint: branchData.fingerprint, confirm: inp.value.trim() });
            if (!r.success) {
                esito.textContent = '';
                esito.appendChild(branchEl('div', 'alert alert-danger py-2 small mb-0', r.error || t('up.changeNotStarted')));
                document.getElementById('ramo-via').disabled = false;
                return;
            }
            document.getElementById('ramo-anteprima').textContent = '';
            esito.textContent = t('up.changingBranch');
            const pre = document.getElementById('ramo-log');
            pre.style.display = 'block';
            pre.textContent = '';
            branchFollow(r.jobId);
        }

        async function branchFollow(id) {
            const s = await updApi('job_status', { jobId: id });
            const esito = document.getElementById('ramo-esito');
            const pre = document.getElementById('ramo-log');
            if (s.success && s.job) {
                pre.textContent = s.job.consoleLog || '';
                pre.scrollTop = pre.scrollHeight;
                if (s.job.status === 'completed' || s.job.status === 'error') {
                    esito.textContent = '';
                    const ok = s.job.status === 'completed';
                    esito.appendChild(branchEl('div', 'alert ' + (ok ? 'alert-success' : 'alert-danger') + ' py-2 small mb-0',
                        ok ? (s.job.result || t('up.branchChanged')) : (s.job.errorMessage || t('up.branchChangeFailed'))));
                    branchStatus();
                    return;
                }
            }
            setTimeout(() => branchFollow(id), 2000);
        }

        branchStatus();
