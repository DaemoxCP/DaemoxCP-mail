        // ---------- Apertura protetta della porta 443 ----------
        async function w443Carica() {
            const el = document.getElementById('upd-443');
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1"></i>Leggo lo stato...';
            // UNA ALLA VOLTA: updApi ha un lucchetto (updBusy) che serve a impedire due
            // operazioni contemporanee. Chiamandole in parallelo la seconda tornava subito
            // con "Operazione gia' in corso", e il riquadro restava vuoto senza spiegazione.
            const s = await updApi('web443_status');
            if (!s.success) {
                el.innerHTML = '<div class="alert alert-danger py-2 small mb-0">' + updEsc(s.error) + '</div>';
                return;
            }
            const c = await updApi('web443_config');
            const inc = s.include || {};
            let h = '<div class="alert alert-' + (s.pronto ? 'success' : 'secondary') + ' py-2 small mb-2">'
                  + '<i class="fas fa-' + (s.pronto ? 'check-circle' : 'circle-info') + ' me-1"></i>'
                  + (s.pronto
                     ? 'La configurazione pubblica sulla 443 &egrave; installata.'
                     : 'La 443 non &egrave; ancora configurata dal pannello.') + '</div>';

            h += '<table class="table table-sm mb-2"><tbody>'
               + w443Riga('nginx legge la cartella dove scriverei', inc.ok, updEsc(inc.motivo || ''))
               + w443Riga('Configurazione installata', s.installato,
                          '<code>' + updEsc(s.file) + '</code>')
               + w443Riga('Politica MTA-STS scritta su disco', s.politicaScritta,
                          '<code>' + updEsc(s.filePolitica) + '</code> &mdash; servita da nginx come file '
                          + 'statico: una richiesta l&igrave; non raggiunge mai il pannello.')
               + '</tbody></table>';

            // E se l'anteprima non arriva si DICE perche', invece di mostrare un riquadro
            // vuoto che sembra un difetto grafico.
            h += '<div class="small text-muted mb-2">Cosa verrebbe installato &mdash; guardalo prima:</div>';
            if (c && c.success && c.configurazione)
                h += '<pre class="small p-2 border rounded mb-2" style="max-height:22rem;overflow:auto">'
                   + updEsc(c.configurazione) + '</pre>';
            else
                h += '<div class="alert alert-warning py-2 small mb-2">Non sono riuscito a generare '
                   + 'l&rsquo;anteprima: ' + updEsc((c && c.error) || 'motivo sconosciuto') + '</div>';

            h += '<div class="d-flex gap-2 flex-wrap">'
               + (inc.ok ? '' : '<button class="btn btn-sm btn-warning" onclick="w443Include()">'
                              + '<i class="fas fa-plus me-1"></i>Aggiungi la riga di include a nginx</button>')
               + '<button class="btn btn-sm btn-outline-warning"'
               + (inc.ok ? '' : ' disabled title="Prima serve la riga di include"')
               + ' onclick="w443Installa()">'
               + '<i class="fas fa-screwdriver-wrench me-1"></i>' + (s.installato ? 'Reinstalla' : 'Apri la 443 protetta')
               + '</button>'
               + '<button class="btn btn-sm btn-outline-secondary" onclick="w443Jail()">'
               + '<i class="fas fa-ban me-1"></i>Attiva la jail fail2ban</button>'
               + '</div><div id="w443Esito" class="mt-2"></div>';

            el.innerHTML = h;
        }

        function w443Riga(cosa, stato, nota) {
            const i = stato === null || stato === undefined
                ? '<i class="fas fa-circle-question text-secondary"></i>'
                : (stato ? '<i class="fas fa-check-circle text-success"></i>'
                         : '<i class="fas fa-times-circle text-danger"></i>');
            return '<tr><td style="width:2rem">' + i + '</td><td class="small">' + cosa
                 + '<div class="text-muted">' + nota + '</div></td></tr>';
        }

        // Su questo server nginx tiene tutto nel file principale e non include cartelle:
        // senza questa riga, qualunque file aggiuntivo verrebbe ignorato.
        async function w443Include() {
            if (prompt('Aggiungere la riga di include alla configurazione principale di nginx?\n\n'
                     + 'Viene inserita in cima al blocco http, con copia di sicurezza.\n'
                     + 'Poi nginx -t: se boccia, il file di prima viene rimesso e non si ricarica.\n\n'
                     + 'Scrivi AGGIUNGI per confermare.') !== 'AGGIUNGI') return;
            const el = document.getElementById('w443Esito');
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1"></i>Modifico, valido e ricarico...';
            const r = await updApi('web443_include', { confirm: 'AGGIUNGI' });
            let h = '<div class="alert alert-' + (r.success ? 'success' : 'danger') + ' py-2 small mb-0">'
                  + updEsc(r.nota || r.error) + '</div>';
            if (r.ripristinato)
                h += '<div class="small text-muted mt-1">La configurazione precedente e&rsquo; stata '
                   + 'rimessa: nessuna interruzione.</div>';
            el.innerHTML = h;
            if (r.success) setTimeout(w443Carica, 1200);
        }

        async function w443Installa() {
            if (prompt('Installare la configurazione pubblica sulla porta 443?\n\n'
                     + 'Serve DUE file e nient\'altro: la politica MTA-STS e la configurazione\n'
                     + 'per Thunderbird. Ogni altro percorso riceve 404.\n\n'
                     + 'Il pannello fa una copia, esegue nginx -t e solo allora ricarica.\n'
                     + 'Se la validazione fallisce toglie tutto senza ricaricare: la webmail\n'
                     + 'sulla 8443 non viene toccata.\n\n'
                     + 'Scrivi APRI per confermare.') !== 'APRI') return;
            const el = document.getElementById('w443Esito');
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1"></i>Scrivo, valido e provo la porta...';
            const r = await updApi('web443_install', { confirm: 'APRI' });
            let h = '<div class="alert alert-' + (r.success ? 'success' : 'danger') + ' py-2 small mb-0">'
                  + updEsc(r.nota || r.error) + '</div>';
            if (r.ripristinato)
                h += '<div class="small text-muted mt-1">La configurazione precedente &egrave; stata '
                   + 'rimessa: nessuna interruzione.</div>';
            el.innerHTML = h;
            if (r.success) setTimeout(w443Carica, 1200);
        }

        async function w443Jail() {
            if (prompt('Attivare la jail fail2ban per la porta 443?\n\n'
                     + 'Banna per un\'ora chi raccoglie dieci risposte 404, 405 o 429 in dieci minuti.\n'
                     + 'Guarda solo il log di questo sito, non quello della webmail.\n\n'
                     + 'Scrivi ATTIVA per confermare.') !== 'ATTIVA') return;
            const el = document.getElementById('w443Esito');
            el.innerHTML = '<i class="fas fa-spinner fa-spin me-1"></i>Scrivo filtro e jail, ricarico fail2ban...';
            const r = await updApi('web443_jail', { confirm: 'ATTIVA' });
            el.innerHTML = '<div class="alert alert-' + (r.success ? 'success' : 'danger') + ' py-2 small mb-0">'
                         + updEsc(r.nota || r.error) + '</div>'
                         + (r.stato ? '<pre class="small p-2 border rounded mt-1 mb-0">' + updEsc(r.stato) + '</pre>' : '');
        }
