
        // ---------- Aggiorna il server (reperti 186, 193) ----------
        // Un posto solo per sapere cosa c'e' da aggiornare e farlo. Ogni riga ha la sua testata (lo stato a parole e i
        // pulsanti), che si ridisegna quando arrivano i dati, e il suo pannello sotto, che resta dov'e': il pulsante lo
        // apre sul posto, senza mandare a un'altra scheda. Le righe di Java, Roundcube, MySQL e Python compaiono solo
        // quando il server dice che servono (packages_overview, «procedures»). I lavori sono quelli di sempre.
        const uc = { os: null, pk: null, branch: null, reboot: null, targets: null, jump: null, plainBlocked: false };

        function ucEl(tag, cls, text) {
            const e = document.createElement(tag);
            if (cls) e.className = cls;
            if (text !== undefined) e.textContent = text;
            return e;
        }

        function ucButton(cls, icon, label, action) {
            const b = ucEl('button', 'btn btn-sm touch-target ' + cls);
            b.type = 'button';
            const i = ucEl('i', 'fas ' + icon + ' me-1');
            i.setAttribute('aria-hidden', 'true');
            b.append(i, label);
            b.setAttribute('data-on-click', action);
            return b;
        }

        // La testata di una riga: lo stato a parole (mai solo col colore), un'icona, i pulsanti.
        function ucHead(key, kind, title, text, buttons, extra) {
            const li = document.getElementById('uc-' + key);
            if (!li) return;
            const head = li.querySelector('.uc-head');
            head.className = 'uc-head d-flex flex-wrap align-items-start gap-2';
            head.replaceChildren();
            const icon = ucEl('i', 'fas mt-1 ' + ({ ok: 'fa-circle-check text-success', todo: 'fa-circle-exclamation text-warning',
                info: 'fa-circle-info text-primary', error: 'fa-circle-xmark text-danger' }[kind] || 'fa-circle-info'));
            icon.setAttribute('aria-hidden', 'true');
            const body = ucEl('div', 'flex-grow-1');
            const name = ucEl('div', 'fw-semibold', title);
            // Le chiavi scritte per intero: I18nTest controlla che ogni testo usato esista nelle due lingue.
            const word = { ok: t('uc.kind.ok'), todo: t('uc.kind.todo'), info: t('uc.kind.info'), error: t('uc.kind.error') }[kind] || '';
            name.append(ucEl('span', 'visually-hidden', ' (' + word + ')'));
            body.append(name, ucEl('div', 'small', text));
            if (extra) body.append(extra);
            head.append(icon, body);
            if (buttons && buttons.length) {
                const box = ucEl('div', 'd-flex flex-wrap gap-2');
                buttons.forEach(b => box.append(b));
                head.append(box);
            }
            li.hidden = false;
        }

        function ucHide(key) {
            const li = document.getElementById('uc-' + key);
            if (li) li.hidden = true;
        }

        // Apre il pannello di una riga, sotto la riga. 'panel' e' un pezzo che si sposta (il piano dei pacchetti, uno
        // solo per due righe). Il fuoco va al pannello, che si vede senza scorrere altrove.
        function ucOpen(key, panel) {
            const detail = document.getElementById('uc-' + key + '-detail');
            if (!detail) return;
            if (panel) {
                const p = document.getElementById(panel);
                if (p) { if (p.parentElement !== detail) detail.appendChild(p); p.hidden = false; }
            }
            detail.hidden = false;
            detail.setAttribute('tabindex', '-1');
            detail.focus({ preventScroll: true });
            detail.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
        }

        function ucToggle(key) {
            const detail = document.getElementById('uc-' + key + '-detail');
            if (!detail) return;
            if (detail.hidden) ucOpen(key); else detail.hidden = true;
        }

        // Le azioni delle righe: aprono il pannello sotto la riga e partono da li'.
        function ucOsInstall() { ucOpen('os'); osShow('patch'); osInstall(); }
        // Aperto il pannello di una riga, il suo pulsante sta li' dentro: la testata si ridisegna senza (reperto 197).
        function ucOpened(key) {
            const d = document.getElementById('uc-' + key + '-detail');
            return !!(d && !d.hidden);
        }
        function ucJava() { ucOpen('java'); ucRender(); jvPre(); }
        function ucJavaReport() { ucOpen('java'); jvState(); }
        function ucRoundcube() { ucOpen('roundcube'); ucRender(); rcPre(); }
        function ucMysql() { ucOpen('mysql'); ucRender(); my84Pre(); }
        function ucPython() { ucOpen('python'); ucRender(); pyPre(); }
        function ucPythonLeftovers() { ucOpen('python'); pyLeftovers(); }
        function ucBranch() { ucToggle('branch'); }

        // Legge lo stato di FreeBSD; i pacchetti, il ramo e il riavvio arrivano dalle loro letture (eventi qui sotto):
        // rileggerli qui raddoppiava la lettura piu' pesante della pagina. «Rileggi» le rifa' tutte.
        async function ucLoad(all) {
            const state = document.getElementById('ucState');
            if (!state || !document.getElementById('ucList')) return;
            state.textContent = t('uc.reading');
            if (all) {
                // Rileggendo, il piano dei pacchetti si rifa': se prima non si poteva eseguire, adesso si vedra'.
                uc.plainBlocked = false;
                pkOverview();
                branchStatus();
                if (typeof panelRebootRefresh === 'function') panelRebootRefresh();
            }
            uc.os = await updApi('os_status');
            // Le release piu' nuove e lo stato di un passaggio cominciato: decidono cosa dice la riga di FreeBSD.
            uc.targets = await updApi('os_upgrade_targets');
            uc.jump = await updApi('jump_state');
            ucRender();
            state.textContent = '';
        }

        document.addEventListener('upd:packages', e => { uc.pk = e.detail; ucRender(); });
        document.addEventListener('upd:branch', e => { uc.branch = e.detail; ucRender(); });
        document.addEventListener('panel:reboot', e => { uc.reboot = e.detail; ucRender(); });

        function ucRender() {
            if (!document.getElementById('ucList')) return;
            const os = uc.os || {}, pk = uc.pk || {}, br = uc.branch || {}, rb = uc.reboot || {};
            const proc = pk.procedures || {};
            const rows = pk.packages || [];
            const reading = (key, title) => ucHead(key, 'info', title, t('uc.reading'));

            // 1. Il sistema di base, guidato (reperto 196): una frase e il pulsante del passo dopo. Prima un passaggio di
            //    release cominciato, poi un riavvio che manca, poi le patch pronte. Una release nuova solo se c'e'.
            // Col pannello della riga aperto, il pulsante del passo dopo sta li' dentro: in testata sarebbe un doppione.
            const osDetail = document.getElementById('uc-os-detail');
            const osOpen = !!(osDetail && !osDetail.hidden);
            const restart = () => document.getElementById('panelRebootModal') && !osOpen
                ? [ucButton('btn-warning', 'fa-rotate-right', t('osu.restartGo'), 'panelRebootOpen()')] : [];
            const moving = osMoving();
            if (!uc.os) reading('os', t('uc.os'));
            else if (!os.success) ucHead('os', 'error', t('uc.os'), os.error || t('common.errorShort'));
            else if (moving) {
                ucHead('os', 'todo', t('uc.os'), t('osu.moving', { target: osRelTarget(), n: osRelStep() }),
                    osOpen ? [] : [ucButton('btn-primary', 'fa-list-check', t('osu.openMove'), 'ucRelease()')]);
            } else if (os.restartNeeded) {
                ucHead('os', 'todo', t('uc.os'), t('osu.patchRestartRow', { now: os.userland, kernel: os.installedKernel }), restart());
            } else if (!os.updatableWithFreebsdUpdate) ucHead('os', 'info', t('uc.os'), os.updatesNote || '');
            else if (os.readyExist) {
                ucHead('os', 'todo', t('uc.os'), t('uc.osReady', { now: os.userland, target: os.readyTarget || '?' })
                    + (os.readyKernel ? ' ' + t('osp.readyKernel') : ''),
                    [ucButton('btn-primary', 'fa-download', t('osp.install'), 'ucOsInstall()')]);
            } else ucHead('os', 'ok', t('uc.os'), t('uc.osOk', { now: os.userland }));
            // Una release nuova: una riga in piu' con il suo pulsante, solo quando c'e' e niente altro e' in corso.
            const tv = (uc.targets && uc.targets.success && uc.targets.versions) || [];
            if (uc.os && os.success && !moving && !os.restartNeeded && tv.length) {
                const v = tv[tv.length - 1];
                const line = ucEl('div', 'd-flex flex-wrap align-items-center gap-2 mt-2 small');
                line.append(ucEl('span', '', t('osu.newRelease', { version: v.version, date: v.endOfSupport })),
                    ucButton('btn-outline-primary', 'fa-forward', t('osu.moveTo', { version: v.version }), 'ucRelease()'));
                document.querySelector('#uc-os .uc-head .flex-grow-1').append(line);
            }
            const releaseView = document.getElementById('os-release');
            if (releaseView && !releaseView.hidden) osReleaseRender();

            // Le procedure dedicate hanno la loro riga: qui sotto non si contano due volte.
            const own = p => p.javaFlow || (proc.roundcube && p.name === proc.roundcubePackage);

            // 2. I pacchetti, in una riga sola (reperto 202). Due modi di aggiornarli, perche' due rischi diversi:
            //    quelli fuori dal server di posta tutti insieme in un piano; quelli del server di posta, protetti, uno
            //    alla volta, ognuno col suo controllo e il riavvio dei servizi che lo usano (reperti 42, 197). La frase
            //    dice quanti per tipo; il pulsante e' UNO, il passo dopo: prima il piano, poi il prossimo della posta. Se
            //    il piano non si puo' eseguire (toglierebbe pacchetti), il passo dopo passa a quelli della posta.
            const sum = pk.summary || {};
            const stack = rows.filter(p => p.update && p.locked && !own(p));
            const plain = (sum.updates || 0) - rows.filter(p => p.update && p.locked).length;
            const ready = stack.filter(p => p.canUpdate);
            if (!uc.pk) reading('packages', t('uc.packages'));
            else if (!pk.success) ucHead('packages', 'error', t('uc.packages'), pk.error || t('common.errorShort'));
            else if (pk.catalogError) ucHead('packages', 'error', t('uc.packages'), t('pkgs.catalogError', { error: pk.catalogError }));
            else {
                const words = [];
                if (plain > 0) words.push(tn('uc.pkPlain', plain));
                if (stack.length) words.push(tn('uc.pkStack', stack.length) + (ready.length ? '' : ' ' + t('uc.stackHeld')));
                if (sum.fixable) words.push(tn('uc.packagesFix', sum.fixable));
                const open = (sum.vulnerable || 0) - (sum.fixable || 0);
                if (open > 0) words.push(tn('uc.pkVulnOpen', open));
                const extra = ucEl('div');
                if (stack.length) {
                    const items = ucEl('ul', 'list-unstyled small mb-0 mt-1');
                    stack.forEach(p => items.append(ucEl('li', '', p.name + ': ' + p.installed + ' → ' + p.available
                        + (p.canUpdate ? '' : ' (' + (p.whyNot || t('pkgs.heldBack')) + ')'))));
                    extra.append(items);
                }
                // Un pacchetto della posta senza protezione: il piano degli altri (pkg upgrade) lo cambierebbe senza i suoi
                // controlli. Proteggerli e' quindi il PRIMO passo, prima del piano: lo si dice qui, dove si guarda.
                if (sum.stackUnlocked > 0)
                    extra.append(ucEl('div', 'mt-2 small text-warning-emphasis', tn('pkgs.stackUnlocked', sum.stackUnlocked)));
                const buttons = [];
                if (sum.stackUnlocked > 0) {
                    buttons.push(ucButton('btn-primary', 'fa-lock', t('pkgs.bulk.lockAll'), 'updLockAll(true)'));
                } else if (!ucOpened('packages') && plain > 0 && !uc.plainBlocked) {
                    buttons.push(ucButton('btn-primary', 'fa-arrow-up', t('uc.packagesGo'), 'ucPackages()'));
                } else if (ready.length && (plain <= 0 || uc.plainBlocked)) {
                    const b = ucButton('btn-primary', 'fa-arrow-up', t('uc.stackNext', { name: ready[0].name, n: 1, total: ready.length }), 'pkUpdOpen(this.dataset.pkg)');
                    b.dataset.pkg = ready[0].name;
                    buttons.push(b);
                }
                if (words.length || sum.stackUnlocked > 0) ucHead('packages', 'todo', t('uc.packages'), words.join(' '), buttons, extra);
                else ucHead('packages', 'ok', t('uc.packages'), t('uc.pkOk'), buttons, extra);
            }

            // 3. Le procedure dedicate, solo quando servono
            const doneRow = (key, title) => gdDone[key] ? ucHead(key, 'ok', title, gdDone[key]) : ucHide(key);
            const jvm = rows.find(p => p.javaFlow);
            if (proc.java && jvm) {
                ucHead('java', 'todo', t('uc.java'), t('uc.javaTodo', { name: jvm.name, from: jvm.installed, to: jvm.available }),
                    ucOpened('java') ? [] : [ucButton('btn-primary', 'fa-clipboard-check', t('uc.prepare'), 'ucJava()')]);
            } else doneRow('java', t('uc.java'));
            const rc = rows.find(p => p.name === proc.roundcubePackage);
            if (proc.roundcube && rc) {
                ucHead('roundcube', 'todo', t('uc.roundcube'), t('uc.roundcubeTodo', { name: rc.name, from: rc.installed, to: rc.available }),
                    ucOpened('roundcube') ? [] : [ucButton('btn-primary', 'fa-clipboard-check', t('uc.prepare'), 'ucRoundcube()')]);
            } else doneRow('roundcube', t('uc.roundcube'));
            if (proc.mysql84) {
                ucHead('mysql', 'todo', t('uc.mysql'), t('uc.mysqlTodo'),
                    ucOpened('mysql') ? [] : [ucButton('btn-primary', 'fa-clipboard-check', t('uc.prepare'), 'ucMysql()')]);
            } else doneRow('mysql', t('uc.mysql'));
            if (proc.python) {
                ucHead('python', 'todo', t('uc.python'), t('uc.pythonTodo'),
                    ucOpened('python') ? [] : [ucButton('btn-primary', 'fa-clipboard-check', t('uc.prepare'), 'ucPython()')]);
            } else if (gdDone.python) {
                // Il passaggio fatto: il passo dopo e' togliere i resti della famiglia vecchia, con il suo pulsante.
                ucHead('python', 'ok', t('uc.python'), gdDone.python + ' ' + t('gd.pyNext'),
                    [ucButton('btn-outline-primary', 'fa-broom', t('up.leftovers'), 'ucPythonLeftovers()')]);
            } else ucHide('python');

            // 4. Il ramo: la scelta si apre qui sotto
            if (!uc.branch) reading('branch', t('uc.branch'));
            else if (br.success) {
                ucHead('branch', 'info', t('uc.branch'), t('uc.branchNow', { branch: br.branch || '?' }),
                    [ucButton('btn-outline-secondary', 'fa-code-branch', t('uc.branchGo'), 'ucBranch()')]);
            } else ucHead('branch', 'error', t('uc.branch'), br.error || t('up.branchUnreadable'));

            // 5. Il riavvio: la finestra del pannello, la stessa di ogni pagina
            if (!uc.reboot) reading('reboot', t('uc.reboot'));
            else if (rb.success && rb.state === 'needed' && os.restartNeeded) ucHide('reboot');
            else if (rb.success) {
                if (rb.state === 'needed' || rb.state === 'advised') {
                    ucHead('reboot', 'todo', t('uc.reboot'), rb.state === 'needed'
                        ? t('rb.needed', { installed: rb.installedKernel, running: rb.runningKernel }) : t('rb.advised'),
                        document.getElementById('panelRebootModal') ? [ucButton('btn-warning', 'fa-rotate-right', t('rb.open'), 'panelRebootOpen()')] : []);
                } else ucHead('reboot', 'ok', t('uc.reboot'), rb.scheduled ? t('rb.scheduled') : t('uc.rebootNo'));
            }
        }

        // Cerca: scarica cataloghi, vulnerabilita' e patch (non installa niente), poi rilegge tutto.
        async function ucSearch() {
            const pre = document.getElementById('uc-log');
            const state = document.getElementById('ucState');
            state.textContent = t('uc.searching');
            ucOutcome(true, '');
            osLogBox('uc-log-box', true);
            pre.textContent = '';
            const r = await updApi('updates_search', { confirm: 'SEARCH' });
            if (!r.success) { state.textContent = r.error || t('common.errorShort'); return; }
            ucFollow(r.jobId, () => { ucLoad(true); });
        }

        // L'esito di un lavoro: in un posto suo, che la rilettura della scheda non copre.
        function ucOutcome(ok, text) {
            const box = document.getElementById('ucOutcome');
            box.replaceChildren(text ? ucEl('div', 'alert py-2 small mb-2 ' + (ok ? 'alert-success' : 'alert-danger'), text) : '');
        }

        // Segue un lavoro nel registro della scheda, poi fa 'after'.
        async function ucFollow(id, after) {
            const pre = document.getElementById('uc-log');
            const state = document.getElementById('ucState');
            const s = await updApi('job_status', { jobId: id });
            if (s.success && s.job) {
                pre.textContent = s.job.consoleLog || '';
                pre.scrollTop = pre.scrollHeight;
                if (s.job.status === 'completed') {
                    state.textContent = '';
                    ucOutcome(true, s.job.result || t('up.opDone', { s: s.job.elapsedSeconds }));
                    after();
                    return;
                }
                if (s.job.status === 'error') {
                    state.textContent = '';
                    ucOutcome(false, t('up.opFailed') + ' ' + (s.job.errorMessage || ''));
                    return;
                }
            }
            setTimeout(() => ucFollow(id, after), 3000);
        }

        // I pacchetti fuori dal server di posta: il piano esatto, una conferma che lo mostra, e il lavoro che esegue quel
        // piano o niente (la firma). Se il piano toglierebbe o retrocederebbe pacchetti, il piano con le prove si apre
        // qui sotto, e non parte niente.
        async function ucPackages() {
            ucOpen('packages');
            ucRender();
            const box = document.getElementById('pk-run');
            const say = (cls, text) => { box.innerHTML = '<div class="alert ' + cls + ' py-2 mb-0">' + escHtml(text) + '</div>'; };
            box.innerHTML = '<i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(t('uc.planning'));
            const r = await updApi('updates_status');
            if (!r.success) { say('alert-danger', r.error || t('common.errorShort')); return; }
            const plan = r.plan || {};
            // Un piano che non si esegue (non misurato, vuoto, o che toglierebbe pacchetti): il passo dopo della riga
            // passa ai pacchetti del server di posta, che hanno ognuno il suo piano (reperto 202).
            const blocked = () => { uc.plainBlocked = true; ucRender(); };
            if (!plan.measured) { blocked(); say('alert-warning', t('up.planUnavailable') + ' ' + (plan.error || '')); return; }
            const changes = plan.changes || [];
            if (!changes.length) { blocked(); say('alert-success', t('up.planNoChange')); return; }
            if (changes.some(c => c.type === 'remove' || c.type === 'downgrade')) {
                blocked();
                say('alert-warning', t('uc.planRemoves'));
                ucOpen('packages', 'uc-updates-panel');
                updStatus();
                return;
            }
            box.innerHTML = '';
            const lines = changes.map(c => c.name + ': ' + (c.from || '-') + ' → ' + (c.to || '-')).join('\n');
            const yes = await panelAsk({ title: tn('uc.pkAskTitle', changes.length), text: t('uc.pkAskText') + '\n' + lines,
                confirm: tn('uc.pkAskGo', changes.length) });
            if (!yes) return;
            updUnprotectedSignature = r.signature;
            const a = await updApi('updates_apply', { confirm: 'UPDATE', signature: r.signature });
            if (!a.success) { say('alert-danger', a.error || t('common.errorShort')); return; }
            gdFollow('packages', 'pk-run', 'pk-log-box', 'pk-log', a.jobId, t('up.upgradingKeepOpen'));
        }

        // Dopo il cambio di ramo: si torna in cima a questa scheda, a vedere cosa c'e' da aggiornare adesso.
        function ucShow() {
            const title = document.getElementById('ucTitle');
            if (title) { title.focus({ preventScroll: true }); title.scrollIntoView({ block: 'nearest', behavior: 'smooth' }); }
        }

        document.addEventListener('DOMContentLoaded', () => { ucLoad(); });
