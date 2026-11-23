
        // ---------- the dedicated procedures, guided (finding 197) ----------
        // Java, Roundcube, MySQL and Python say the same things in the same way: after "Prepare" one line about
        // the checks, what must be known beforehand, the exact plan and ONE button; if something blocks, only the
        // blocking lines and what to do; all the checks collapsed below. The confirmation is the panel's window,
        // not the browser's. The job's log stays collapsed below (and on disk, Diagnostics); at the end the line
        // stays, with the outcome.

        // The outcome of the jobs finished on this page, per line: a line does not lose its outcome.
        const gdDone = {};

        function gdChecksTable(checks) {
            let h = '<div class="table-responsive"><table class="table table-sm align-middle mb-0"><thead><tr>'
                + '<th scope="col" data-style="width:8rem">' + escHtml(t('up.colResult')) + '</th><th scope="col" data-style="width:16rem">'
                + escHtml(t('up.colCheck')) + '</th><th scope="col">' + escHtml(t('up.colDetail')) + '</th></tr></thead><tbody>';
            (checks || []).forEach(c => {
                h += '<tr class="upd-cell"><td>' + updBadge(c.level === 'block' ? 'wait' : c.level) + '</td>'
                   + '<td><strong>' + updEsc(c.label) + '</strong></td><td>' + updEsc(c.detail) + '</td></tr>';
            });
            return h + '</tbody></table></div>';
        }

        function gdAllChecks(checks) {
            return (checks || []).length
                ? '<details class="mt-2"><summary class="small">' + escHtml(t('gd.allChecks', { n: checks.length })) + '</summary>'
                  + gdChecksTable(checks) + '</details>'
                : '';
        }

        // The result of the checks, guided.
        // o: { already, alreadyText, unknownText, extra (html), note (text), go: { label, action } }
        function gdReady(r, o) {
            const checks = r.checks || [];
            const stops = checks.filter(c => c.level === 'block');
            const warns = checks.filter(c => c.level === 'wait' || c.level === 'review' || c.level === 'warn');
            if (o.already) return '<div class="alert alert-success py-2 mb-0">' + escHtml(o.alreadyText) + '</div>' + gdAllChecks(checks);
            if (o.unknownText) return '<div class="alert alert-warning py-2 mb-0">' + escHtml(o.unknownText) + '</div>' + gdAllChecks(checks);
            if (r.blocked || stops.length) {
                let h = '<div class="alert alert-danger py-2 mb-0"><p class="mb-2"><strong>' + escHtml(t('gd.blocked')) + '</strong></p><ul class="mb-0">';
                stops.forEach(c => { h += '<li><strong>' + updEsc(c.label) + '</strong>: ' + updEsc(c.detail) + '</li>'; });
                return h + '</ul></div>' + gdAllChecks(checks);
            }
            let h = '<p class="mb-2"><i class="fas fa-circle-check text-success me-1" aria-hidden="true"></i>'
                + escHtml(tn('gd.allFine', checks.length)) + '</p>';
            if (warns.length) {
                h += '<div class="alert alert-warning py-2"><p class="mb-1"><strong>' + escHtml(t('gd.before')) + '</strong></p><ul class="mb-0">';
                warns.forEach(c => { h += '<li><strong>' + updEsc(c.label) + '</strong>: ' + updEsc(c.detail) + '</li>'; });
                h += '</ul></div>';
            }
            h += (o.extra || '') + (r.plan ? updPlanHtml(r.plan, r.signature) : '');
            if (o.note) h += '<div class="alert alert-info py-2">' + escHtml(o.note) + '</div>';
            h += '<button type="button" class="btn btn-primary touch-target" data-on-click="' + o.go.action + '">'
               + '<i class="fas fa-play me-1" aria-hidden="true"></i>' + escHtml(o.go.label) + '</button>';
            return h + gdAllChecks(checks);
        }

        // The plan in lines, for the confirmation: what changes, package by package.
        function gdPlanLines(r) {
            const c = (r && r.plan && r.plan.changes) || [];
            return c.map(x => x.name + ': ' + (x.from || '-') + ' → ' + (x.to || '-')).join('\n');
        }

        // Starts the job: the progress in one line in the box, the log collapsed below; at the end the outcome
        // stays in the line (gdDone) and the card reads itself again.
        function gdFollow(key, boxId, logBoxId, preId, jobId, runningText) {
            const el = document.getElementById(boxId), pre = document.getElementById(preId);
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1" aria-hidden="true"></i>' + escHtml(runningText);
            pre.textContent = '';
            pre.style.display = 'block';
            osLogBox(logBoxId, true);
            planPoll(jobId, el, pre, job => {
                const text = (job && job.result) || t('gd.done', { s: job ? job.elapsedSeconds : '?' });
                gdDone[key] = text;
                el.innerHTML = '<div class="alert alert-success py-2 mb-0"><strong>' + escHtml(t('gd.doneTitle')) + '</strong> ' + escHtml(text) + '</div>';
                if (document.getElementById('ucList')) ucLoad(true);
                if (typeof panelRebootRefresh === 'function') panelRebootRefresh();
            });
        }
