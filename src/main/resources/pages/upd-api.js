        // ---------- the calls to /api/updates, shared by every page that uses them ----------
        // Updates, Diagnostics, and the cards moved to DNS, Firewall and Settings (finding 193): a single copy.
        let updBusy = false;

        // The pkg operations touch the network and last tens of seconds, keeping one of the panel's
        // HTTP threads busy: two clicks or two tabs are enough to saturate it. The guard
        // is here, in a single place, instead of inside every function.
        async function updApi(action, extra) {
            // Light reads do not go through the guard. Before, the guard came before knowing whether
            // the action was slow: on page load branch_status and packages_overview start
            // first, and interruption_status came back "busy" without even asking. The notice of an
            // interrupted job (and the button to go back) never appeared (finding 176).
            const slow = action !== 'job_status' && action !== 'interruption_status';
            // Queued, not refused (finding 185): "System state" pressed while the page was loading
            // the packages answered "An operation is already running" and the card stayed empty. A request
            // waits for the one before to finish; the server has its own turns for jobs anyway.
            if (slow) {
                const before = updQueue;
                let done;
                updQueue = new Promise(resolve => { done = resolve; });
                await before;
                updBusy = true;
                try { return await updSend(action, extra); }
                finally { updBusy = false; done(); }
            }
            return updSend(action, extra);
        }

        let updQueue = Promise.resolve();

        async function updSend(action, extra) {
            try {
                const body = Object.assign({
                    action: action,
                    csrf_token: document.getElementById('csrf_token').value
                }, extra || {});
                const res = await fetch('/api/updates', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(body)
                });
                return await res.json();
            } catch (e) {
                return { success: false, error: t('common.networkError', { message: e.message }) };
            }
        }

        // The confirmation: the panel's window, with what happens and the button that says it (finding 197).
        // Before, it was the browser's window with a word to type: outside the panel's style, and it blocks
        // the page. The word still goes to the server, in the caller's code; and dangerous operations also
        // ask for the recent confirmation.
        function updConfirm(textValue, keyword) {
            return panelAsk({ title: t('gd.confirmTitle'), text: textValue || t('gd.confirmText'), confirm: t('gd.confirmGo') });
        }

        function updEsc(v) {
            const d = document.createElement('div');
            d.textContent = v === null || v === undefined ? '' : String(v);
            return d.innerHTML;
        }

