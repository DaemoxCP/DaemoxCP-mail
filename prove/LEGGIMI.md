# Prove della logica MTA-STS

Non fanno parte della build: Maven non guarda questa cartella, il jar non le contiene.
Sono classi con un `main`, si compilano contro il jar gia' costruito e si eseguono a mano.

    mvn -o -q package -DskipTests
    javac -cp target/freebsd-mail-panel-1.0.jar -d prove prove/org/mail_panel/system/*.java
    java -cp "prove:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.ProvaMtaSts
    java -cp "prove:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.ProvaAttesa
    java -cp "prove:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.ProvaVecchia

## Cosa provano

**ProvaMtaSts** — `ripartisci()`, cioe' come i domini finiscono nei passi del piano, e
`leggiTxt()` sull'uscita VERA di `dig` interrogando i domini veri. Copre il caso di
domain-d.test (nessun record, risponde un jolly proxato) e il caso di un record insieme
sbagliato e proxato.

**ProvaAttesa** — l'attesa della propagazione, con un orologio finto invece di sei minuti
veri. Verifica le tre proprieta' che devono valere: non si aspetta se i domini rispondono
gia', si smette appena rispondono, e si esce comunque alla scadenza invece di girare
per sempre.

**ProvaVecchia** — la logica di classificazione com'era prima della correzione, messa
davanti agli stessi due casi. Serve a dimostrare che i controlli di ProvaMtaSts non sono
decorativi: qui devono fallire. Se un giorno passa anche questa, vuol dire che la prova
non sta piu' verificando niente.
