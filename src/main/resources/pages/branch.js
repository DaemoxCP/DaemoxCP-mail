
        // ---------- ramo dei pacchetti: quarterly o latest (RamoPkg sul server) ----------
        // La scheda si legge da sola all'apertura: pkg -vv non va in rete e risponde subito.
        // Cambiare ramo invece scarica il catalogo nuovo, quindi e' un lavoro con il suo registro.
        let branchData = null, branchTarget = '';

        function branchEl(tag, classe, testo) {
            const e = document.createElement(tag);
            if (classe) e.className = classe;
            if (testo !== undefined && testo !== null) e.textContent = testo;
            return e;
        }

        async function branchStatus() {
            const box = document.getElementById('branch-body');
            box.textContent = t('up.readingPkg');
            document.getElementById('branch-preview').textContent = '';
            const r = await updApi('branch_status');
            box.textContent = '';
            if (!r.success) {
                box.appendChild(branchEl('div', 'alert alert-secondary py-2 small mb-0', r.error || t('up.branchUnreadable')));
                return;
            }
            branchData = r;
            const testa = branchEl('p', 'mb-1');
            if (r.branch === 'quarterly' || r.branch === 'latest') {
                testa.append(...tNodes('up.branchFrom', { branch: branchEl('span', 'badge ' + (r.branch === 'latest' ? 'bg-info text-dark' : 'bg-secondary') + ' fs-6', r.branch) }));
            } else if (r.branch === 'misti') {
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
                const celle = [[x.name, COL[0]], [x.role, COL[1]], [x.branch || '-', COL[2]],
                               [x.enabled ? t('dns.yes') : t('acf.no'), COL[3]]];
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
            (r.destination || []).forEach(v => {
                const b = branchEl('button', 'btn btn-sm btn-outline-warning', t('up.switchTo', { branch: v }));
                b.type = 'button';
                b.addEventListener('click', () => branchPreview(v));
                azioni.appendChild(b);
            });
            box.appendChild(azioni);
        }

        async function branchPreview(verso) {
            const box = document.getElementById('branch-preview');
            box.textContent = t('up.buildingPreview');
            document.getElementById('branch-outcome').textContent = '';
            const r = await updApi('branch_preview', { destination: verso });
            box.textContent = '';
            if (!r.success) { box.appendChild(branchEl('div', 'alert alert-danger py-2 small', r.error)); return; }
            if (!r.possible) { box.appendChild(branchEl('div', 'alert alert-secondary py-2 small', r.reason)); return; }
            branchTarget = verso;
            branchData.fingerprint = r.fingerprint;
            const card = branchEl('div', 'border rounded p-3');
            card.appendChild(branchEl('h6', 'mb-2', t('up.switchFromTo', { from: r.from, to: verso })));
            const changes = branchEl('ul', 'small mb-2');
            (r.changes || []).forEach(c => {
                const li = branchEl('li', 'testo-lungo');
                li.appendChild(branchEl('strong', '', c.name + ': '));
                li.append(...tNodes('up.becomes', { from: branchEl('code', '', c.from), to: branchEl('code', '', c.to) }));
                changes.appendChild(li);
            });
            card.appendChild(changes);
            const warnings = branchEl('ul', 'small testo-avviso mb-2');
            (r.warnings || []).forEach(a => warnings.appendChild(branchEl('li', '', a)));
            card.appendChild(warnings);
            const dove = branchEl('p', 'small mb-1');
            dove.append(...tNodes('up.fileWritten', { file: branchEl('code', '', r.file) }));
            card.appendChild(dove);
            card.appendChild(branchEl('pre', 'small border rounded p-2 mb-1', r.content));
            if (r.howToReturn) card.appendChild(branchEl('p', 'small text-muted mb-2', r.howToReturn));
            const lab = branchEl('label', 'form-label small mb-1', t('up.typeBranch', { branch: verso }));
            lab.htmlFor = 'branch-confirm';
            card.appendChild(lab);
            const line = branchEl('div', 'd-flex flex-wrap gap-2 align-items-center');
            const inp = branchEl('input', 'form-control form-control-sm');
            inp.id = 'branch-confirm';
            inp.style.maxWidth = '14rem';
            inp.autocomplete = 'off';
            inp.spellcheck = false;
            const via = branchEl('button', 'btn btn-sm btn-danger', t('up.changeBranch'));
            via.type = 'button';
            via.id = 'branch-go';
            via.disabled = true;
            inp.addEventListener('input', () => { via.disabled = inp.value.trim() !== verso; });
            via.addEventListener('click', branchChange);
            const cancel = branchEl('button', 'btn btn-sm btn-secondary', t('common.cancel'));
            cancel.type = 'button';
            cancel.addEventListener('click', () => { box.textContent = ''; });
            line.append(inp, via, cancel);
            card.appendChild(line);
            box.appendChild(card);
            inp.focus();
        }

        async function branchChange() {
            const inp = document.getElementById('branch-confirm');
            const outcome = document.getElementById('branch-outcome');
            if (!inp || inp.value.trim() !== branchTarget) return;
            document.getElementById('branch-go').disabled = true;
            const r = await updApi('branch_change', { destination: branchTarget, fingerprint: branchData.fingerprint, confirm: inp.value.trim() });
            if (!r.success) {
                outcome.textContent = '';
                outcome.appendChild(branchEl('div', 'alert alert-danger py-2 small mb-0', r.error || t('up.changeNotStarted')));
                document.getElementById('branch-go').disabled = false;
                return;
            }
            document.getElementById('branch-preview').textContent = '';
            outcome.textContent = t('up.changingBranch');
            const pre = document.getElementById('branch-log');
            pre.style.display = 'block';
            pre.textContent = '';
            branchFollow(r.jobId);
        }

        async function branchFollow(id) {
            const s = await updApi('job_status', { jobId: id });
            const outcome = document.getElementById('branch-outcome');
            const pre = document.getElementById('branch-log');
            if (s.success && s.job) {
                pre.textContent = s.job.consoleLog || '';
                pre.scrollTop = pre.scrollHeight;
                if (s.job.status === 'completed' || s.job.status === 'error') {
                    outcome.textContent = '';
                    const ok = s.job.status === 'completed';
                    outcome.appendChild(branchEl('div', 'alert ' + (ok ? 'alert-success' : 'alert-danger') + ' py-2 small mb-0',
                        ok ? (s.job.result || t('up.branchChanged')) : (s.job.errorMessage || t('up.branchChangeFailed'))));
                    branchStatus();
                    return;
                }
            }
            setTimeout(() => branchFollow(id), 2000);
        }

        branchStatus();
