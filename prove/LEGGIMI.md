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

**ProvaVecchia** — la logica di classificazione com'era prima della correzione, messa
davanti agli stessi due casi. Serve a dimostrare che i controlli di ProvaMtaSts non sono
decorativi: qui devono fallire. Se un giorno passa anche questa, vuol dire che la prova
non sta piu' verificando niente.
