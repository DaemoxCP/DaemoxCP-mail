        // ---------- le chiamate a /api/updates, comuni a ogni pagina che le usa ----------
        // Updates, Diagnostica, e le schede spostate in DNS, Firewall e Impostazioni (reperto 193): una copia sola.
        let updBusy = false;

        // Le operazioni su pkg toccano la rete e durano decine di secondi, tenendo occupato
        // un thread HTTP del pannello: due click o due schede bastano a saturarlo. La guardia
        // sta qui, in un punto solo, invece che dentro ogni funzione.
        async function updApi(action, extra) {
            // Le letture leggere non passano dalla guardia. Prima la guardia veniva prima di sapere se
            // l'azione era lenta: al caricamento della pagina branch_status e packages_overview partono
            // per primi, e interruption_status tornava «occupato» senza nemmeno chiedere. L'avviso di un
            // lavoro interrotto (e il pulsante per tornare indietro) non compariva mai (reperto 176).
            const slow = action !== 'job_status' && action !== 'interruption_status';
            // In fila, non rifiutate (reperto 185): «Stato del sistema» premuto mentre la pagina caricava
            // i pacchetti rispondeva «Operazione già in corso» e la scheda restava vuota. Una richiesta
            // aspetta che finisca quella prima; il server ha comunque i suoi turni per i lavori.
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

        // La conferma: la finestra del pannello, con cosa succede e il pulsante che lo dice (reperto 197). Prima era la
        // finestra del browser con una parola da scrivere: fuori dallo stile del pannello, e ferma la pagina. Al server
        // la parola va comunque, nel codice di chi chiama; e le operazioni pericolose chiedono anche la conferma recente.
        function updConfirm(textValue, keyword) {
            return panelAsk({ title: t('gd.confirmTitle'), text: textValue || t('gd.confirmText'), confirm: t('gd.confirmGo') });
        }

        function updEsc(v) {
            const d = document.createElement('div');
            d.textContent = v === null || v === undefined ? '' : String(v);
            return d.innerHTML;
        }

