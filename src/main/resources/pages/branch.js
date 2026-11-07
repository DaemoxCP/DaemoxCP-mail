
        // ---------- ramo dei pacchetti: quarterly o latest (RamoPkg sul server) ----------
        // La scheda si legge da sola all'apertura: pkg -vv non va in rete e risponde subito.
        // Cambiare ramo invece scarica il catalogo nuovo, quindi e' un lavoro con il suo registro.
        let branchData = null, branchTarget = '';

        function branchEl(tag, cssClass, textValue) {
            const e = document.createElement(tag);
            if (cssClass) e.className = cssClass;
            if (textValue !== undefined && textValue !== null) e.textContent = textValue;
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
            const head = branchEl('p', 'mb-1');
            if (r.branch === 'quarterly' || r.branch === 'latest') {
                head.append(...tNodes('up.branchFrom', { branch: branchEl('span', 'badge ' + (r.branch === 'latest' ? 'bg-info text-dark' : 'bg-secondary') + ' fs-6', r.branch) }));
            } else if (r.branch === 'mixed') {
                head.appendChild(branchEl('span', 'badge bg-warning text-dark fs-6', t('up.mixedBranches')));
            } else {
                head.appendChild(branchEl('span', 'badge bg-secondary fs-6', t('up.noOfficialBranch')));
            }
            box.appendChild(head);
            box.appendChild(branchEl('p', 'small mb-2', r.explanation));

            const tab = branchEl('table', 'table table-sm align-middle mb-2 table-cards');
            tab.setAttribute('aria-label', t('up.pkgRepos'));
            const th = tab.createTHead().insertRow();
            const COL = [t('up.colRepo'), t('up.colWhatFor'), t('up.colBranch'), t('up.colEnabled'), t('up.colAddress')];
            COL.forEach(titleText => {
                const c = branchEl('th', '', titleText);
                c.scope = 'col';
                th.appendChild(c);
            });
            const bodyText = tab.createTBody();
            (r.repository || []).forEach(x => {
                const tr = bodyText.insertRow();
                const cells = [[x.name, COL[0]], [x.role, COL[1]], [x.branch || '-', COL[2]],
                               [x.enabled ? t('dns.yes') : t('acf.no'), COL[3]]];
                cells.forEach(([textValue, labelText]) => {
                    const td = branchEl('td', '', textValue);
                    td.setAttribute('data-label', labelText);
                    tr.appendChild(td);
                });
                const urlCell = branchEl('td', 'text-long');
                urlCell.setAttribute('data-label', COL[4]);
                urlCell.appendChild(branchEl('code', 'small', x.url));
                tr.appendChild(urlCell);
            });
            const panelBox = branchEl('div', 'table-responsive');
            panelBox.appendChild(tab);
            box.appendChild(panelBox);

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
            const actionItems = branchEl('div', 'd-flex flex-wrap gap-2');
            (r.destination || []).forEach(v => {
                const b = branchEl('button', 'btn btn-sm btn-outline-warning', t('up.switchTo', { branch: v }));
                b.type = 'button';
                b.addEventListener('click', () => branchPreview(v));
                actionItems.appendChild(b);
            });
            box.appendChild(actionItems);
        }

        async function branchPreview(destination) {
            const box = document.getElementById('branch-preview');
            box.textContent = t('up.buildingPreview');
            document.getElementById('branch-outcome').textContent = '';
            const r = await updApi('branch_preview', { destination: destination });
            box.textContent = '';
            if (!r.success) { box.appendChild(branchEl('div', 'alert alert-danger py-2 small', r.error)); return; }
            if (!r.possible) { box.appendChild(branchEl('div', 'alert alert-secondary py-2 small', r.reason)); return; }
            branchTarget = destination;
            branchData.fingerprint = r.fingerprint;
            const card = branchEl('div', 'border rounded p-3');
            card.appendChild(branchEl('h6', 'mb-2', t('up.switchFromTo', { from: r.from, to: destination })));
            const changes = branchEl('ul', 'small mb-2');
            (r.changes || []).forEach(c => {
                const li = branchEl('li', 'text-long');
                li.appendChild(branchEl('strong', '', c.name + ': '));
                li.append(...tNodes('up.becomes', { from: branchEl('code', '', c.from), to: branchEl('code', '', c.to) }));
                changes.appendChild(li);
            });
            card.appendChild(changes);
            const warnings = branchEl('ul', 'small text-caution mb-2');
            (r.warnings || []).forEach(a => warnings.appendChild(branchEl('li', '', a)));
            card.appendChild(warnings);
            const where = branchEl('p', 'small mb-1');
            where.append(...tNodes('up.fileWritten', { file: branchEl('code', '', r.file) }));
            card.appendChild(where);
            card.appendChild(branchEl('pre', 'small border rounded p-2 mb-1', r.content));
            if (r.howToReturn) card.appendChild(branchEl('p', 'small text-muted mb-2', r.howToReturn));
            const lab = branchEl('label', 'form-label small mb-1', t('up.typeBranch', { branch: destination }));
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
            inp.addEventListener('input', () => { via.disabled = inp.value.trim() !== destination; });
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
                    const done = branchEl('div', 'alert ' + (ok ? 'alert-success' : 'alert-danger') + ' py-2 small mb-0',
                        ok ? (s.job.result || t('up.branchChanged')) : (s.job.errorMessage || t('up.branchChangeFailed')));
                    // Il passo dopo (reperto 187): il catalogo nuovo cambia cosa c'e' da aggiornare, e la scheda
                    // in cima lo rilegge e lo dice, coi suoi pulsanti.
                    if (ok && typeof ucLoad === 'function') {
                        const next = branchEl('button', 'btn btn-sm btn-outline-primary ms-2 touch-target', t('uc.afterBranch'));
                        next.type = 'button';
                        next.setAttribute('data-on-click', 'ucShow()');
                        done.appendChild(next);
                        ucLoad();
                        pkOverview();
                    }
                    outcome.appendChild(done);
                    branchStatus();
                    return;
                }
            }
            setTimeout(() => branchFollow(id), 2000);
        }

        branchStatus();
