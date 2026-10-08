# Test del pannello

Non fanno parte della build: Maven non guarda questa cartella, il jar non le contiene.
Sono classi con un `main`, si compilano contro il jar gia' costruito e si eseguono a mano.

    mvn -o -q package -DskipTests
    javac -cp target/freebsd-mail-panel-1.0.jar -d tests tests/org/mail_panel/system/*.java
    javac -cp target/freebsd-mail-panel-1.0.jar -d tests tests/org/mail_panel/webserver/*.java
    javac -cp target/freebsd-mail-panel-1.0.jar -d tests tests/org/mail_panel/database/*.java
    javac -cp target/freebsd-mail-panel-1.0.jar -d tests tests/org/mail_panel/security/PasswordGeneratorTest.java
    javac -cp target/freebsd-mail-panel-1.0.jar -d tests tests/org/mail_panel/security/MtaStsRecordTest.java
    java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.MtaStsTest
    java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.PackageCatalogTest
    java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.security.MtaStsRecordTest
    java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.PropagationWaitTest
    java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.MtaStsSequenceTest
    java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.AutoconfigTest
    java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.MtaStsOldLogicTest
    java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.security.SrvRecordTest
    java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.ReportDeliveryTest
    java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.PackagePlanTest
    java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.PackageQueueTest
    java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.webserver.AliasMessagesTest
    java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.security.PasswordGeneratorTest
    java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.SoftwareVersionsTest
    java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.AddressConversionTest
    java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.PkgBranchTest
    java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.database.ResetDatabaseTest
    sh tests/pkg-simulation-test.sh

## Con un MySQL di prova

AddressConversionTest, SoftwareVersionsTest e ResetDatabaseTest hanno una parte che gira su un MySQL vero, e
senza le opzioni `-Dmysql.*` la saltano dicendolo. Serve il MySQL ufficiale 8.0, quello che il pannello installa
(mysql80-server), non MariaDB: su FreeBSD `pkg install mysql80-server`, su macOS
`brew install mysql@8.0`. Un server usa e getta, in una cartella di prova e solo su 127.0.0.1
(da root aggiungi `--user=root` alle due righe di mysqld):

    M=$(mktemp -d)
    mysqld --initialize-insecure --datadir=$M/dati
    mysqld --datadir=$M/dati --socket=$M/m.sock --port=33062 --bind-address=127.0.0.1 \
           --mysqlx=OFF --secure-file-priv= --pid-file=$M/m.pid &
    mysql -uroot -S $M/m.sock -e "CREATE DATABASE mailpanel_prova;
        CREATE USER 'mailpanel'@'127.0.0.1' IDENTIFIED BY 'password-di-prova';
        GRANT ALL ON mailpanel_prova.* TO 'mailpanel'@'127.0.0.1';"
    P="-Dmysql.porta=33062 -Dmysql.utente=mailpanel -Dmysql.password=password-di-prova -Dmysql.database=mailpanel_prova"
    java $P -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.AddressConversionTest
    java $P -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.SoftwareVersionsTest
    java $P -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.webserver.VersionsApiTest
    java $P -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.database.ResetDatabaseTest

**Mai sul database del pannello**: la parte di AddressConversionTest cancella e ricrea tutte le tabelle
del database che le si indica (VersionsApiTest usa le tabelle che lascia), e ResetDatabaseTest
lo svuota del tutto, tabelle non del pannello comprese. SoftwareVersionsTest invece
legge soltanto (SELECT VERSION()).

## Nel browser

Le pagine generate dal pannello in Chromium, con Playwright e il server simulato:

    D=$(mktemp -d)
    javac -cp target/freebsd-mail-panel-1.0.jar -d tests tests/org/mail_panel/content/PageGenerator.java
    java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.content.PageGenerator $D
    NODE_PATH=$(npm root -g) node tests/address-conversion-browser-test.js $D [cartella-per-le-foto]
    NODE_PATH=$(npm root -g) node tests/software-versions-browser-test.js $D [cartella-per-le-foto]
    NODE_PATH=$(npm root -g) node tests/pkg-branch-browser-test.js $D [cartella-per-le-foto]

## Cosa provano

**MtaStsTest** — `ripartisci()`, cioe' come i domini finiscono nei passi del piano, e la
lettura del record `_mta-sts`. Copre il caso di domain-d.test (nessun record, risponde un jolly
proxato) e il caso di un record insieme sbagliato e proxato. La lettura decide dallo stato
della risposta DNS: con NOERROR si contano i record v=STSv1 (nessuno e' ASSENTE, uno e'
PRESENTE, piu' d'uno e' TROPPI); NXDOMAIN e' ASSENTE; un errore (SERVFAIL, REFUSED) o nessuna
risposta e' NON_CHIESTO, con il motivo che il piano scrive accanto al dominio. Si prova in
due modi:
- `interpretaTxt()` con uscite di `dig` vere, registrate il 2/10/2026 (record pubblicato,
  SERVFAIL di dnssec-failed.org, NXDOMAIN, nome senza TXT, DNS che non risponde), piu'
  varianti costruite su quelle (record spezzato, accanto ad altri TXT, dietro un CNAME,
  REFUSED, due record v=STSv1 in varie forme). Vale ovunque, anche senza rete;
- `leggiTxt()` sul DNS vero. Se da qui `dig` raggiunge un DNS si esigono i fatti veri: su
  domain-d.test il record c'e', un nome inesistente non ce l'ha, e se il resolver convalida
  DNSSEC il SERVFAIL di dnssec-failed.org e' NON_CHIESTO. Se non lo raggiunge (`dig` assente
  o rete chiusa) si esige NON_CHIESTO, mai un ASSENTE inventato.
Prima la lettura usava `dig +short`, che per un SERVFAIL non stampa niente, come per un nome
senza record: il piano leggeva "assente" e proponeva di pubblicare un record che forse c'e'
gia'. Contro quella versione la prova fallisce in cinque punti. E prima ancora la prova dava
per scontato il DNS e falliva su ogni macchina che non ce l'aveva.
Prova anche `passiProvaETxt()`, dove il passo del record diventa "fatto": con due record
v=STSv1 non deve diventarlo, perche' per i mittenti due record valgono zero (RFC 8461 §3.1).
Prima la lettura prendeva il primo record: se era quello giusto, il passo risultava fatto.

**MtaStsRecordTest** — il record `_mta-sts` dal lato di Cloudflare e della pagina DNS, senza
rete. La regola comune (`RegoleDns.eMtaSts`: conta ogni record che almeno un mittente vero
conta, anche scritto in maiuscolo). La scrittura, `AutoDns.allineaTxtMtaSts()`, contro un
Cloudflare finto con la zona in memoria: crea, lascia stare, aggiorna, e con piu' record ne
lascia uno solo e giusto senza toccare gli altri TXT; con Cloudflare che rifiuta una
cancellazione o un aggiornamento lo dice; se la prima lettura della zona torna vuota per un
errore, la rilettura finale si accorge dei due record. La riga MTA-STS della pagina DNS,
`controlloMtaSts()`: due record non sono mai verdi, un SERVFAIL non e' "Non attivo". In fondo
rimette la scrittura di prima davanti ai due record, uno gia' giusto: diceva "invariato" e li
lasciava tutti e due, e la prova lo vede.

**PackageCatalogTest** — di quando e' il catalogo dei pacchetti (`CatalogoPkg`). Home e rapporto
dicevano "eta' sconosciuta" perche' guardavano `/var/db/pkg/repo-FreeBSD.sqlite`: il nome delle
versioni vecchie di pkg e del repository "FreeBSD" di prima di FreeBSD 15. Oggi il catalogo di
ogni repository e' `$PKG_DBDIR/repos/<nome>/db`, e pkg gli da' la data di pubblicazione sul
server (sorgente di pkg: `libpkg/repo/binary/common.c` e `update.c`). La prova legge un'uscita
di `pkg -vv` nella forma di `print_repository()` (anche "yes (overridden by pkg)"), costruisce
una cartella di pkg con date scelte da lei e controlla: solo i repository accesi, vale il piu'
vecchio, un acceso senza catalogo e' detto, senza cataloghi si dice dove si e' guardato,
repository tutti spenti non e' "non so", il nome vecchio e' ancora riconosciuto, un nome con
`../` non finisce in un percorso, un orologio indietro non da' eta' negative. Poi la riga vera
del rapporto, da `RapportoPeriodico.componi()`.

**PropagationWaitTest** — l'attesa della propagazione, con un orologio finto invece di sei minuti
veri. Verifica le tre proprieta' che devono valere: non si aspetta se i domini rispondono
gia', si smette appena rispondono, e si esce comunque alla scadenza invece di girare
per sempre.

**MtaStsSequenceTest** — i pezzi nati dall'unione delle due sequenze: `filtra()`, il filtro
per dominio (confronto esatto e senza maiuscole: "ake.net" non deve pescare "domain-d.test", e
un dominio inesistente deve dare lista vuota, che e' la guardia contro il falso successo), e
`comeVoci()`, che traduce l'esito nelle righe della pagina DNS senza perdere le righe rosse.

**AutoconfigTest** — il verdetto della scheda Autoconfig. Il caso che conta e' `pronto(true, 0, 0)`:
zero domini provati, zero riusciti, e senza la condizione `esaminati > 0` il conteggio direbbe
verde proprio quando non e' stato guardato niente.

**SrvRecordTest** — il confronto di un record SRV, che faceva riscrivere in produzione due SRV
gia' giusti a ogni esecuzione. Cloudflare mette nel `content` di un SRV tre campi (peso,
porta, destinazione) e tiene la priorita' a parte; `analizzaSrv` ne pretende quattro perche'
e' scritta per l'uscita di `dig`, quindi tornava `null` — "non lo riconosco" — e il record
risultava sbagliato. La prova copre tutte e tre le forme e finisce riproducendo il difetto
sulla logica vecchia: se un giorno quell'ultimo controllo passa, la prova non verifica piu'
niente.

**ReportDeliveryTest** — da quale sendmail parte il rapporto periodico e come il pannello
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

**PackagePlanTest** — il piano esatto di un aggiornamento e la risposta a "la patch c'e'?".
Legge uscite di `pkg upgrade -n` e di `pkg audit -Rjson` con la forma che il sorgente di pkg
stampa (sezioni, totali in fondo, `(vulnerable!)`, intervalli di VuXML come ">= a : < b"), e
rifiuta di chiamare completo un piano con una riga che non capisce o con i conti che non tornano.
Dentro c'e' il caso che l'ha motivata: nginx 1.30.4,3 con il catalogo fermo alla stessa e VuXML
"< 1.30.5,3" — la correzione esiste, il ramo non ce l'ha, e il lock non c'entra.

**PackageQueueTest** — un lavoro alla volta sui pacchetti, e l'elenco per riproteggerli
scritto davvero prima di sbloccarli. Nasce da una revisione sul pannello web, e il
difetto qui era lo stesso: due lavori partivano insieme e si sovrascrivevano l'elenco su disco, e
se l'elenco non si poteva scrivere il lavoro sbloccava lo stesso. La prova mette 64 thread a
chiedere il turno nello stesso istante (lo prende uno solo), controlla che il turno si liberi anche
quando il lavoro fallisce, che l'elenco di un lavoro interrotto non venga sovrascritto, che un
elenco non scritto venga detto, e che con quell'elenco su disco non parta nessun lavoro che
installa o aggiorna, mentre rimettere le protezioni resta possibile.

**AliasMessagesTest** — che cosa il pannello dice dopo aver creato, modificato, disattivato o eliminato
un alias. Postfix legge solo gli alias attivi e li applica prima delle caselle: una casella con un
inoltro attivo e senza "se stessa -> se stessa" attivo non riceve piu' niente, e un indirizzo che
non e' una casella esiste solo finche' ha un alias attivo (o il dominio un catch-all attivo). Da
quando un alias si puo' disattivare, la riga della copia puo' esserci ed essere spenta: la logica
di prima guardava la riga e non lo stato, e taceva proprio li'. La prova finisce riproducendo quel
silenzio sulla logica vecchia.

**PasswordGeneratorTest** — il generatore di password e la regola che il pannello applica alle
password delle caselle. Con "Tutti i caratteri" il generatore metteva anche < > / ~ e l'apice
inverso, che la regola rifiuta: la password proposta dal pannello veniva respinta dal pannello
stesso, sette volte su dieci. La prova genera migliaia di password per ogni tipo e combinazione e
pretende che passino tutte, controlla che la stima dell'entropia usi gli stessi insiemi, che la
regola sia rimasta quella di prima carattere per carattere, che le password delle caselle ne
vogliano almeno 12 (il login dell'admin resta com'era: alzarlo avrebbe chiuso fuori chi ha una
password piu' corta), e finisce riproducendo il rifiuto con i simboli vecchi.

**AddressConversionTest** — trasformare un alias in casella e una casella in alias (TrasformaIndirizzo
e MailDatabase), solo quando si puo' davvero. Senza database: i rifiuti (raccolta @dominio,
indirizzo che e' gia' una casella, dominio che non e' del pannello, nomi che uscirebbero da
/var/vmail, come "..@dominio"), le destinazioni (valide, esistenti se sono sui domini del pannello, al
massimo venti, nessun giro che torna all'indirizzo), la posta di una casella di prima trovata sul
disco (contata, messa da parte senza cancellarla, rimessa a posto se la trasformazione fallisce) e
l'impronta dell'anteprima, che cambia quando cambia lo stato. Su MySQL: le due transazioni,
guardate con le stesse query che usa Postfix; se l'ultimo passo fallisce il database torna
com'era; il vincolo UNIQUE rifiuta una seconda casella con lo stesso indirizzo; con la casella se
ne vanno risposta automatica, filtri, inoltri e limiti, e l'alias "se stessa -> se stessa"; andata
e ritorno.

**ResetDatabaseTest** — il reset del database del pannello (MailDatabase.dropAllTables, che Main
usa nel reset). Rifa' prima il reset vecchio, che cancellava le tabelle una alla volta: MySQL
rifiutava mailboxes, domains e panel_admin perche' altre tabelle ci puntano con una chiave esterna,
e restavano con i loro dati (insieme ad admin_passkeys, cloudflare_accounts e dkim_rotation_history,
che l'elenco non aveva) mentre il reset si diceva completato. Poi il nuovo: ogni tabella che
createSchema e le migrazioni creano e' nel suo elenco; con una riga in ognuna, e le virtual_* delle
versioni vecchie, non ne resta nessuna e una tabella d'altri accanto non si tocca; ricreate, sono
vuote; sul database gia' vuoto non da' errori; se una tabella d'altri punta a domains MySQL rifiuta,
non si cancella niente (un DROP solo, atomico) e l'errore dice cosa resta. Senza collegamento il
reset non parte.

**SoftwareVersionsTest** — le versioni della Home (VersioniSoftware). Un sistema finto risponde con le
uscite vere dei programmi su FreeBSD (postconf, dovecot, rspamd, redis-server, nginx, php-fpm,
openssl, freebsd-version, clamd, mysqld, pkg which, pkg query) e si controlla: ogni versione
riconosciuta; il pacchetto trovato dal binario anche quando si chiama postfix-mysql o
dovecot-mysql (per nome non si trovava); pkg chiamato due volte in tutto; "da riavviare" quando
il processo e' partito prima dell'installazione del pacchetto, o risponde con un'altra versione
(MySQL, ClamAV, la Java del pannello, il kernel), e mai quando non si sa (nessun pidfile, processo
sparito, PHP-FPM che si ricarica nello stesso processo). I casi storti: clamd che non risponde,
firme vecchie di diciannove giorni, MySQL irraggiungibile, programmi che rispondono con un errore
o con dell'HTML, che non passa mai come versione. Poi il socket di clamd, vero: un demone finto
che risponde e uno muto, dal quale la lettura si deve staccare in tre secondi.

**VersionsApiTest** — /api/versioni e /api/service sul server vero (SSLMailServer), via HTTPS,
con una sessione come quella del login: si accende solo il server HTTP con le sue rotte, non i
gestori che toccherebbero il sistema. Senza sessione 401; con la sessione le versioni, MySQL
letto dal server vero; la lettura tenuta trenta secondi e "fresco" che non rilegge prima di tre;
parametri e metodi sbagliati rifiutati. /api/service senza token CSRF, o con un token sbagliato,
e' 403 e finisce nel registro di audit; con il token giusto la richiesta passa; un'azione su un
servizio (redis, che qui non c'e': il comando fallisce senza toccare niente) va nel registro e fa
rileggere le versioni.

**PkgBranchTest** — il ramo dei pacchetti, quarterly o latest (RamoPkg). Il sistema finto fa
quello che fa pkg (libpkg/pkg_config.c, letto il 03/10/2026): parte dal /etc/pkg/FreeBSD.conf di
FreeBSD 15.0 RELEASE (quarterly, moduli del kernel con la versione minore, FreeBSD-base spento) e
legge i file di /usr/local/etc/pkg/repos in ordine alfabetico, con ogni blocco che sovrascrive i
campi del suo repository e le variabili di pkg espanse. Si prova: leggere i repository (ufficiali
o no, pacchetti, moduli, sistema base; i nomi di FreeBSD 14 e i moduli di -STABLE senza versione
minore), quando non si puo' cambiare (pacchetti da un repository proprio) e perche', i rami misti;
l'anteprima, che non tocca niente e scrive gli indirizzi con ${ABI} e ${VERSION_MINOR} invece dei
valori di oggi, e riscrive uguali priority e ip_version (un blocco li azzererebbe); il cambio
quarterly -> latest e ritorno, dove il file del pannello si toglie se il ramo di serie basta; il
FreeBSD.conf dell'utente mai toccato; e i ritorni indietro: un file letto dopo quello del pannello
che vince lui, un catalogo che non si scarica, una cartella non scrivibile, una configurazione
cambiata dopo l'anteprima. In fondo il file vero su disco: permessi rw-r--r--, nessun temporaneo
rimasto, i .conf elencati come li legge pkg.

**pkg-branch-browser-test.js** — la scheda "Ramo dei pacchetti" della pagina Aggiornamenti: si legge da
sola, nomi e indirizzi solo come testo, l'anteprima, il nome del ramo scritto a mano per
confermare, impronta e token CSRF nella richiesta, il lavoro seguito fino all'esito, l'errore di
un cambio che non parte; tema scuro e telefono.

**address-conversion-browser-test.js** — le finestre "Trasforma in casella" (pagina Alias) e "Trasforma
in alias" (pagina Caselle): l'anteprima, la password proposta dal generatore, la scelta
obbligatoria sulla posta di prima, l'indirizzo scritto per conferma, l'impronta e il token CSRF
nelle richieste, il token anche in "Elimina casella"; tema scuro e telefono.

**software-versions-browser-test.js** — la Home: la colonna Versione di "Servizi Mail" (con le righe
MySQL e Redis), "Altro software", le note "da riavviare", una versione con dentro HTML che resta
testo, i nomi dei pulsanti per i lettori di schermo, la domanda prima di fermare un servizio o
riavviare MySQL (annullata non parte niente), il token CSRF a /api/service, la rilettura dopo
ogni comando; tema scuro e telefono, dove le tabelle diventano schede.

**pkg-simulation-test.sh** — la simulazione su COPIA del database di pkg, contro un pkg finto che
tiene i "lock" come file. Dimostra che lo sblocco avviene nella copia e non nel database vero,
che le dipendenze protette nominate da pkg vengono aggiunte solo se si possono sbloccare, e che
la copia sparisce alla fine.

**MtaStsOldLogicTest** — la logica di classificazione com'era prima della correzione, messa
davanti agli stessi due casi. Serve a dimostrare che i controlli di MtaStsTest non sono
decorativi: qui devono fallire. Se un giorno passa anche questa, vuol dire che la prova
non sta piu' verificando niente.
