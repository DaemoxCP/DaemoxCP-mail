# Prove della logica MTA-STS

Non fanno parte della build: Maven non guarda questa cartella, il jar non le contiene.
Sono classi con un `main`, si compilano contro il jar gia' costruito e si eseguono a mano.

    mvn -o -q package -DskipTests
    javac -cp target/freebsd-mail-panel-1.0.jar -d prove prove/org/mail_panel/system/*.java
    java -cp "prove:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.ProvaMtaSts
    java -cp "prove:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.ProvaAttesa
    java -cp "prove:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.ProvaUnificazione
    java -cp "prove:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.ProvaAutoconfig
    java -cp "prove:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.ProvaVecchia
    java -cp "prove:target/freebsd-mail-panel-1.0.jar" org.mail_panel.security.ProvaSrv
    java -cp "prove:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.ProvaConsegnaRapporto
    java -cp "prove:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.ProvaPianoPacchetti
    java -cp "prove:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.ProvaTurnoPacchetti
    sh prove/prova-simulazione.sh

## Cosa provano

**ProvaMtaSts** — `ripartisci()`, cioe' come i domini finiscono nei passi del piano, e
`leggiTxt()` sull'uscita VERA di `dig` interrogando i domini veri. Copre il caso di
domain-d.test (nessun record, risponde un jolly proxato) e il caso di un record insieme
sbagliato e proxato.

**ProvaAttesa** — l'attesa della propagazione, con un orologio finto invece di sei minuti
veri. Verifica le tre proprieta' che devono valere: non si aspetta se i domini rispondono
gia', si smette appena rispondono, e si esce comunque alla scadenza invece di girare
per sempre.

**ProvaUnificazione** — i pezzi nati dall'unione delle due sequenze: `filtra()`, il filtro
per dominio (confronto esatto e senza maiuscole: "ake.net" non deve pescare "domain-d.test", e
un dominio inesistente deve dare lista vuota, che e' la guardia contro il falso successo), e
`comeVoci()`, che traduce l'esito nelle righe della pagina DNS senza perdere le righe rosse.

**ProvaAutoconfig** — il verdetto della scheda Autoconfig. Il caso che conta e' `pronto(true, 0, 0)`:
zero domini provati, zero riusciti, e senza la condizione `esaminati > 0` il conteggio direbbe
verde proprio quando non e' stato guardato niente.

**ProvaSrv** — il confronto di un record SRV, che faceva riscrivere in produzione due SRV
gia' giusti a ogni esecuzione. Cloudflare mette nel `content` di un SRV tre campi (peso,
porta, destinazione) e tiene la priorita' a parte; `analizzaSrv` ne pretende quattro perche'
e' scritta per l'uscita di `dig`, quindi tornava `null` — "non lo riconosco" — e il record
risultava sbagliato. La prova copre tutte e tre le forme e finisce riproducendo il difetto
sulla logica vecchia: se un giorno quell'ultimo controllo passa, la prova non verifica piu'
niente.

**ProvaConsegnaRapporto** — da quale sendmail parte il rapporto periodico e come il pannello
capisce com'e' andata. Il 25/09/2026 il rapporto partiva da /usr/sbin/sendmail, cioe'
mailwrapper, cioe' dma: arrivava in chiaro e senza firma DKIM, e il pannello scriveva
"riuscito". La prova verifica che mailwrapper non venga mai scelto (collegamento simbolico o
hard link che sia), e legge righe vere del log: consegnato con TLS, rimandato, respinto per
DMARC, rifiutato dal milter, formato RFC 5424, e le righe di dma, con le quali l'esito NON
deve diventare "consegnato" perche' Postfix quel messaggio non l'ha visto. Il TLS si prende solo
dalla riga del processo smtp che ha consegnato (stesso pid) e della connessione su cui e' partito:
un altro processo che apre una connessione cifrata verso lo stesso server, una connessione
precedente dello stesso processo, una riusata (conn_use) o il ripiego in chiaro dopo un TLS
caduto non devono far scrivere "con TLS" a un rapporto partito in chiaro.

**ProvaPianoPacchetti** — il piano esatto di un aggiornamento e la risposta a "la patch c'e'?".
Legge uscite di `pkg upgrade -n` e di `pkg audit -Rjson` con la forma che il sorgente di pkg
stampa (sezioni, totali in fondo, `(vulnerable!)`, intervalli di VuXML come ">= a : < b"), e
rifiuta di chiamare completo un piano con una riga che non capisce o con i conti che non tornano.
Dentro c'e' il caso che l'ha motivata: nginx 1.30.4,3 con il catalogo fermo alla stessa e VuXML
"< 1.30.5,3" — la correzione esiste, il ramo non ce l'ha, e il lock non c'entra.

**ProvaTurnoPacchetti** — un lavoro alla volta sui pacchetti, e l'elenco per riproteggerli
scritto davvero prima di sbloccarli. Nasce da una revisione sul pannello web, e il
difetto qui era lo stesso: due lavori partivano insieme e si sovrascrivevano l'elenco su disco, e
se l'elenco non si poteva scrivere il lavoro sbloccava lo stesso. La prova mette 64 thread a
chiedere il turno nello stesso istante (lo prende uno solo), controlla che il turno si liberi anche
quando il lavoro fallisce, che l'elenco di un lavoro interrotto non venga sovrascritto, che un
elenco non scritto venga detto, e che con quell'elenco su disco non parta nessun lavoro che
installa o aggiorna, mentre rimettere le protezioni resta possibile.

**prova-simulazione.sh** — la simulazione su COPIA del database di pkg, contro un pkg finto che
tiene i "lock" come file. Dimostra che lo sblocco avviene nella copia e non nel database vero,
che le dipendenze protette nominate da pkg vengono aggiunte solo se si possono sbloccare, e che
la copia sparisce alla fine.

**ProvaVecchia** — la logica di classificazione com'era prima della correzione, messa
davanti agli stessi due casi. Serve a dimostrare che i controlli di ProvaMtaSts non sono
decorativi: qui devono fallire. Se un giorno passa anche questa, vuol dire che la prova
non sta piu' verificando niente.
