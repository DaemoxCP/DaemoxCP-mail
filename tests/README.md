# Test del pannello

Non fanno parte della build: Maven non guarda questa cartella, il jar non le contiene.
Sono classi con un `main`, si compilano contro il jar gia' costruito e si eseguono a mano.

Il jar e' compilato per Java 25 (`<release>25</release>` nel pom). Con un JDK piu' recente
sul Mac, le prove vanno compilate con `--release 25`, altrimenti sulla VM non partono:
«has been compiled by a more recent version of the Java Runtime (class file version 70.0),
this version ... recognizes class file versions up to 69.0». Il jar invece va bene, perche'
Maven la release la dichiara.

E l'esito di una prova e' il suo **codice di uscita**: `java ... | tail -4` restituisce
quello di `tail`, cioe' zero sempre. Una prova che non parte affatto, letta cosi', sembra
passata.

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
    java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.ChildStdinTest
    java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.HeldUpdatesReportTest
    java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.PlanDivergenceTest
    java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.PlanAfterFetchTest
    java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.ServiceFallTest
    java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.AuditReportTest
    java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.LockTraceTest
    java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.InstallSideEffectsTest
    java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.InstallScriptDriftTest
    java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.RestartServicesTest
    java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.database.ResetDatabaseTest
    javac -cp target/freebsd-mail-panel-1.0.jar -d tests tests/org/mail_panel/monitoring/*.java
    java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.monitoring.MailQueueTest
    javac -cp target/freebsd-mail-panel-1.0.jar -d tests tests/org/mail_panel/sqli/*.java
    java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.sqli.ConfigSecretsTest
    sh tests/pkg-simulation-test.sh

## Le prove dell'area aggiornamenti

`ChildStdinTest`, `HeldUpdatesReportTest`, `PlanDivergenceTest`, `PlanAfterFetchTest`,
`ServiceFallTest`, `AuditReportTest` e `LockTraceTest` vanno eseguite **sulla VM FreeBSD**,
non sul Mac: una parte di loro chiede a `pkg` com'e' fatta davvero la macchina (le chiavi che
`packagesStatus` mette, i pacchetti che `pkg audit` dice vulnerabili, i pacchetti bloccati) e
quella parte sul Mac **si salta dicendolo**, perche' una prova che si salta in silenzio conta
come verde senza aver provato niente.

Due di loro toccano il sistema e rimettono tutto com'era: `LockTraceTest` scrive
l'annotazione `mail_panel_lock` su un pacchetto e la rimuove, e scrive la nota dei blocchi in
una cartella temporanea (non in `/var/db`, come `PackageQueueTest` con il suo elenco).
`AuditReportTest` chiede a `pkg audit` dei pacchetti installati e non cambia niente. Vanno
bene su una macchina di prova, non su un server di posta vero.

`InstallScriptDriftTest` e' la prova del reperto 42 (lo script di installazione di postfix
che toglie IPv6 da main.cf) e ha due parti. La prima legge l'uscita vera di
quell'aggiornamento e gira ovunque. La seconda fa girare i tre lavori veri — aggiornamento
guidato, non protetti, manutenzione completa — su un pacchetto finto, `drift-probe`, che si
costruisce da sola con `pkg create`: si accende solo con `-De2e.vm=yes`, da root, su FreeBSD.
Per la durata della prova spegne i repository FreeBSD-ports e FreeBSD-ports-kmods (un file in
`/usr/local/etc/pkg/repos`), mette in ascolto un `nc` sulla porta 47425 di 127.0.0.1 e ::1, e
la manutenzione sblocca e riprotegge i pacchetti protetti come sempre; prima di ogni lavoro
controlla che il piano contenga solo `drift-probe`, e alla fine controlla che pacchetti,
protezioni e repository siano quelli di prima. Solo su una macchina di prova. Dura qualche
minuto: un indirizzo che manca si aspetta sessanta secondi prima di dirlo perso.

    java -De2e.vm=yes -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.InstallScriptDriftTest

`HeldUpdatesReportTest` e `AuditReportTest` hanno bisogno del database delle vulnerabilita'
(`pkg audit -F`): senza, dicono quali prove hanno saltato e perche'.

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
    java $P -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.webserver.LanguageRoutesTest
    java $P -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.webserver.QueueApiTest
    java $P -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.webserver.RateLimitsApiTest
    java $P -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.webserver.CsrfFilterTest
    java $P -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.webserver.RolesTest
    java $P -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.webserver.LoginRoutesTest
    java $P -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.webserver.MailboxPasswordTest
    java $P -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.security.LoginSecurityTest
    java $P -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.database.ResetDatabaseTest

**Mai sul database del pannello**: la parte di AddressConversionTest cancella e ricrea tutte le tabelle
del database che le si indica (VersionsApiTest, LanguageRoutesTest, QueueApiTest, RateLimitsApiTest, CsrfFilterTest
LoginRoutesTest e MailboxPasswordTest usano le tabelle che lascia), LoginSecurityTest le cancella e le ricrea come una
vecchia installazione con le password, e ResetDatabaseTest
lo svuota del tutto, tabelle non del pannello comprese. SoftwareVersionsTest invece
legge soltanto (SELECT VERSION()).

## Nel browser

Le pagine generate dal pannello in Chromium, con Playwright e il server simulato. PageGenerator le
scrive complete come le manda il server, con la cornice e i testi: nome.html in italiano e
nome.en.html in inglese, piu' i dizionari degli script in i18n/ (da servire come /i18n/it.js e
/i18n/en.js):

    D=$(mktemp -d)
    javac -cp target/freebsd-mail-panel-1.0.jar -d tests tests/org/mail_panel/content/PageGenerator.java
    java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.content.PageGenerator $D
    NODE_PATH=$(npm root -g) node tests/address-conversion-browser-test.js $D [cartella-per-le-foto]
    NODE_PATH=$(npm root -g) node tests/software-versions-browser-test.js $D [cartella-per-le-foto]
    NODE_PATH=$(npm root -g) node tests/pkg-branch-browser-test.js $D [cartella-per-le-foto]
    NODE_PATH=$(npm root -g) node tests/layout-browser-test.js $D [cartella-per-le-foto]
    NODE_PATH=$(npm root -g) node tests/queue-browser-test.js $D [cartella-per-le-foto]
    NODE_PATH=$(npm root -g) node tests/limits-statistics-browser-test.js $D [cartella-per-le-foto]
    NODE_PATH=$(npm root -g) node tests/english-pages-browser-test.js $D [cartella-per-le-foto]

L'accesso senza password invece gira sul server vero (LoginE2EServer), con il MySQL di prova, e
Chromium con un autenticatore virtuale. Il server parte da una cartella vuota con il jar dentro:

    D=$(mktemp -d) && cp target/freebsd-mail-panel-1.0.jar $D/
    MYSQL="$P" NODE_PATH=$(npm root -g) node tests/login-browser-test.js $D [cartella-per-le-foto]

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
rete. La regola comune (`DnsRules.eMtaSts`: conta ogni record che almeno un mittente vero
conta, anche scritto in maiuscolo). La scrittura, `AutoDns.allineaTxtMtaSts()`, contro un
Cloudflare finto con la zona in memoria: crea, lascia stare, aggiorna, e con piu' record ne
lascia uno solo e giusto senza toccare gli altri TXT; con Cloudflare che rifiuta una
cancellazione o un aggiornamento lo dice; se la prima lettura della zona torna vuota per un
errore, la rilettura finale si accorge dei due record. La riga MTA-STS della pagina DNS,
`controlloMtaSts()`: due record non sono mai verdi, un SERVFAIL non e' "Non attivo". In fondo
rimette la scrittura di prima davanti ai due record, uno gia' giusto: diceva "invariato" e li
lasciava tutti e due, e la prova lo vede.

**PackageCatalogTest** — di quando e' il catalogo dei pacchetti (`PkgCatalog`). Home e rapporto
dicevano "eta' sconosciuta" perche' guardavano `/var/db/pkg/repo-FreeBSD.sqlite`: il nome delle
versioni vecchie di pkg e del repository "FreeBSD" di prima di FreeBSD 15. Oggi il catalogo di
ogni repository e' `$PKG_DBDIR/repos/<nome>/db`, e pkg gli da' la data di pubblicazione sul
server (sorgente di pkg: `libpkg/repo/binary/common.c` e `update.c`). La prova legge un'uscita
di `pkg -vv` nella forma di `print_repository()` (anche "yes (overridden by pkg)"), costruisce
una cartella di pkg con date scelte da lei e controlla: solo i repository accesi, vale il piu'
vecchio, un acceso senza catalogo e' detto, senza cataloghi si dice dove si e' guardato,
repository tutti spenti non e' "non so", il nome vecchio e' ancora riconosciuto, un nome con
`../` non finisce in un percorso, un orologio indietro non da' eta' negative. Poi la riga vera
del rapporto, da `PeriodicReport.componi()`.

**PropagationWaitTest** — l'attesa della propagazione, con un orologio finto invece di sei minuti
veri. Verifica le tre proprieta' che devono valere: non si aspetta se i domini rispondono
gia', si smette appena rispondono, e si esce comunque alla scadenza invece di girare
per sempre.

**MtaStsSequenceTest** — i pezzi nati dall'unione delle due sequenze: `filtra()`, il filtro
per dominio (confronto esatto e senza maiuscole: "ake.net" non deve pescare "domain-d.test", e
un dominio inesistente deve dare lista vuota, che e' la guardia contro il falso successo), e
`comeVoci()`, che traduce l'esito nelle righe della pagina DNS senza perdere le righe rosse.

**AutoconfigTest** — il verdict della scheda Autoconfig. Il caso che conta e' `pronto(true, 0, 0)`:
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
mailwrapper, cioe' dma: arrivava in chiaro e senza signature DKIM, e il pannello scriveva
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
stampa (sezioni, totali in fondo, `(vulnerable!)`, ranges di VuXML come ">= a : < b"), e
rifiuta di chiamare completo un piano con una riga che non capisce o con i conti che non tornano.
Dentro c'e' il caso che l'ha motivata: nginx 1.30.4,3 con il catalogo fermo alla stessa e VuXML
"< 1.30.5,3" — la fix esiste, il ramo non ce l'ha, e il lock non c'entra.
In fondo le letture della scheda Pacchetti: le righe "<" di `pkg version -U -vRL=` (con righe vere
di FreeBSD 15.1: i "?" e i ">" non sono aggiornamenti, una versione con caratteri strani resta
fuori), `pkg query '%n\t%v\t%k'` con versione e blocco, il tipo di cambiamento nella lingua di
chi legge.

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

**AddressConversionTest** — trasformare un alias in casella e una casella in alias (AddressTransform
e MailDatabase), solo quando si puo' davvero. Senza database: i rifiuti (raccolta @dominio,
indirizzo che e' gia' una casella, dominio che non e' del pannello, nomi che uscirebbero da
/var/vmail, come "..@dominio"), le destinazioni (valide, esistenti se sono sui domini del pannello, al
massimo venti, nessun giro che torna all'indirizzo), la posta di una casella di prima trovata sul
disco (contata, messa da parte senza cancellarla, rimessa a posto se la trasformazione fallisce) e
l'fingerprint dell'anteprima, che cambia quando cambia lo stato. Su MySQL: le due transazioni,
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

**SoftwareVersionsTest** — le versioni della Home (SoftwareVersions). Un sistema finto risponde con le
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

**PkgBranchTest** — il ramo dei pacchetti, quarterly o latest (PkgBranch). Il sistema finto fa
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
confermare, fingerprint e token CSRF nella richiesta, il lavoro seguito fino all'esito, l'errore di
un cambio che non parte; tema scuro e telefono.

**packages-browser-test.js** — la scheda Pacchetti della pagina Aggiornamenti, con il server
simulato: si legge da sola; il riepilogo; l'avviso sui pacchetti dello stack non lockedPackages con il
pulsante per bloccarli; per ogni riga versione installata e del catalogo, verdict sulla
vulnerabilita' (testo, mai HTML), blocco; "Aggiorna" anche su un pacchetto bloccato, "trattenuto"
dove l'avvertenza dice di aspettare, il JDK del pannello che rimanda alla procedura di Java;
Blocca/Sblocca con nome e token CSRF. La finestra di aggiornamento: piano esatto, i passi in
chiaro, il pulsante spento finche' il nome del pacchetto non e' scritto giusto, la richiesta con
conferma e fingerprint, il lavoro seguito fino all'esito. E nella scheda Aggiornamenti l'intestazione
di una vulnerabilita' che dice lo stesso verdict del dettaglio (era "l'aggiornamento la corregge"
sopra un "l'aggiornamento non basta"), con il pulsante Aggiorna accanto.

**address-conversion-browser-test.js** — le finestre "Trasforma in casella" (pagina Alias) e "Trasforma
in alias" (pagina Caselle): l'anteprima, la password proposta dal generatore, la scelta
obbligatoria sulla posta di prima, l'indirizzo scritto per conferma, l'fingerprint e il token CSRF
nelle richieste, il token anche in "Elimina casella"; tema scuro e telefono.

**software-versions-browser-test.js** — la Home: la colonna Versione di "Servizi Mail" (con le righe
MySQL e Redis), "Altro software", le note "da riavviare", una versione con dentro HTML che resta
testo, i nomi dei pulsanti per i lettori di schermo, la domanda prima di fermare un servizio o
riavviare MySQL (annullata non parte niente), il token CSRF a /api/service, la rilettura dopo
ogni comando; tema scuro e telefono, dove le tabelle diventano schede.

**I18nTest** — le lingue dell'interfaccia (I18n) e la cornice delle pagine (Layout). I file di
lingua hanno le stesse chiavi, nessun testo vuoto e gli stessi {valori} in italiano e in inglese;
ogni {{t:chiave}} e ogni t('chiave') degli script esiste nelle due lingue; nessuno script nasconde
la funzione t dietro una variabile con lo stesso nome; una pagina completata non ha segnaposti
rimasti. Poi la lingua di una richiesta (Accept-Language con i pesi, il cookie) e la cornice: le
quattro sezioni, ogni pagina servita dal pannello nel menu, la pagina in cui ti trovi segnata.

**LanguageRoutesTest** — le lingue sul server vero (SSLMailServer), via HTTPS, con il MySQL di
prova: il dizionario /i18n/(lingua).js, la lingua della pagina di accesso (cookie prima del
browser, inglese per un browser che non chiede nessuna delle due), /api/language prima di entrare
(solo col token della pagina di accesso) e dopo (col token della sessione: si salva nell'account),
la scelta salvata che vince sul browser e il cookie riallineato, la cornice intorno alle pagine.

**LoginSecurityTest** — l'accesso senza password, con il MySQL di prova. La migrazione di una
vecchia installazione: via le colonne password_hash, totp_secret, totp_enabled e backup_codes, le
date in DATETIME convertite in UTC, il piu' vecchio amministratore superadmin se non ce n'era uno,
le passkey di prima legate al loro user handle e ancora buone per entrare; le chiavi in un file 600
fuori dal database. La cifratura AES-256-GCM (nonce casuale, un carattere cambiato e non si
decifra, un'altra chiave non decifra) e l'indice cieco. Le passkey firmate da un autenticatore
software (SoftAuthenticator): registrazione e login validi, e rifiutati con un'altra sessione,
un'altra origine, un altro rpId, senza verifica dell'utente, con il contatore all'indietro, con la
signature rovinata, con la sfida riusata o scaduta, con una chiave di nessuno o di un amministratore
disattivato; la conferma di un'operazione solo con la propria passkey e la propria sessione. I
codici monouso: solo l'HMAC nel database, una volta sola, cinque tentativi, dieci minuti, i limiti
per indirizzo, IP e sottorete, il codice della console, quello di conferma, il cambio dell'email
che vale solo quando torna il codice, e nel log mai un codice o un indirizzo. Le sessioni: solo
l'fingerprint del token, IP e browser cifrati, lo stesso browser, 30 minuti senza richieste e 12 ore
al massimo, la revoca (una, le altre, all'uscita, con l'amministratore), il token CSRF derivato.

**LoginRoutesTest** — le rotte dell'accesso sul server vero, via HTTPS: la pagina di accesso non
crea niente sul server e lega il suo token a un cookie; ogni richiesta prima del login vuole token e
cookie; chiedere un codice per un indirizzo di nessuno risponde come per uno vero (stato, testo,
tempo), e cosi' un codice sbagliato; codice giusto, codice della console e passkey aprono una
sessione nel database con il cookie __Host-; /api/account vuole il token della sessione; gli
amministratori hanno un'email e nessuna password; il vault vuole una conferma recente; l'uscita
chiude la sessione nel database; le vecchie rotte con password e TOTP non rispondono piu'.

**MailboxPasswordTest** — le password delle caselle si possono sempre rivedere, con il MySQL di
prova e il server vero. Ogni password e' salvata due volte, hash bcrypt e copia cifrata; se il vault
non cifra non si salva niente. "Rivela" mostra la copia solo se e' ancora la password (confronto con
l'hash): copia mancante, vecchia o illeggibile hanno ciascuna il suo messaggio. Le righe rimaste in
chiaro (il vecchio driver sql della webmail) si riconoscono e all'avvio diventano hash + copia.
/api/internal/mailbox-password (il cambio dalla webmail): solo da loopback, senza intestazioni di un
proxy, con la chiave della webmail; password attuale controllata, hash e copia insieme, tentativi
limitati, nel log nessuna password. /api/internal/mailbox-vault riempie una copia mancante dopo un
accesso alla webmail. La configurazione di Roundcube: via le righe del driver sql (con la password
MySQL del pannello), il blocco del pannello una volta sola, file non leggibile dagli altri utenti.
Con `-Droundcube.dir=<roundcubemail-1.6.x-complete scompattato>` e `php` fa girare anche il codice
vero di Roundcube (webmail-roundcube-test.php): il driver httpapi con il suo Guzzle e l'hook di
accesso del plugin mailpanel_sso, contro il pannello.

**ConfigSecretsTest** — la password MySQL e la chiave privata TLS escono dal database SQLite anche su
un server gia' avviato: al primo avvio passano nel file dei segreti (600, cartella 700) e le colonne
si svuotano; quello che il pannello salva dopo va nel file; un valore scritto da una versione vecchia
vince all'avvio dopo; la chiave PEM torna identica; con il file non scrivibile il valore resta in
SQLite e si legge lo stesso; database/ 700 e mail_panel.db 600.

**login-browser-test.js** — l'accesso in Chromium con un autenticatore virtuale, sul server vero:
il primo accesso con il codice della console (java ... Main --access-code), la passkey creata nella
pagina Account, l'email di accesso confermata con il suo codice, le sessioni aperte, la chiave del
vault (in Impostazioni) che chiede la conferma con la passkey, l'uscita e l'ingresso con la sola
passkey, un amministratore nuovo con l'email, l'ingresso con un codice via email (e uno sbagliato
rifiutato); poi i ruoli: l'amministratore nuovo (Lettore) entra con un codice e trova un menu
ridotto, "Sola lettura" e i rifiuti (password delle caselle, messaggi in coda), promosso a
Operatore puo' cambiare le caselle alla pagina dopo, eliminato esce subito. In fondo la pagina di
accesso su un telefono in italiano.

**layout-browser-test.js** — la cornice in Chromium: la barra laterale a quattro sezioni (con le
pagine Coda, Limiti di invio, Statistiche e Amministratori, che prima nessun link raggiungeva), la
voce della pagina in cui ti trovi, "Sezione › Pagina" nella barra in alto, "Vai al contenuto" col
primo Tab, il cambio di lingua (la richiesta col token CSRF, la pagina che torna in inglese, il
dizionario degli script inglese, e indietro), la scelta della lingua sulle pagine di accesso e di
installazione, il menu sul telefono (si apre, prende il fuoco, si chiude con Esc e con la X),
nessuno scorrimento di lato, il tema scuro.

**MailQueueTest** — la coda di Postfix (MailQueueManager) con un esecutore finto che registra i
comandi invece di lanciarli. L'identificativo di coda non arriva mai a una shell: ogni comando e'
una lista di argomenti, e un identificativo che non e' alfanumerico viene rifiutato prima di
lanciare qualsiasi cosa (prima finiva in "sh -c postcat -q <id>", e /api/queue?action=message&id=X;comando
eseguiva il comando). L'elenco letto da postqueue -j, con il motivo del rinvio per ogni destinatario
(postqueue -p lo metteva su una riga che il vecchio lettore prendeva per il destinatario: la colonna
Errore restava vuota e "Elimina falliti" non trovava mai niente); permanente solo un messaggio con
un 5xx per OGNI destinatario; si eliminano solo i messaggi confermati che hanno ancora un errore
permanente; i messaggi nella lingua della richiesta, le eccezioni in inglese.

**QueueApiTest** — /api/queue sul server vero, via HTTPS, con il MySQL di prova e l'esecutore finto:
senza sessione 401; l'elenco con il motivo del rinvio e l'arrivo in UTC; un identificativo con
caratteri di shell rifiutato senza lanciare niente; ogni POST senza token CSRF o con un token
sbagliato 403, senza lanciare niente e scritto nel registro di audit; con il token l'eliminazione
lancia postsuper con l'identificativo come unico argomento e finisce nel registro; l'eliminazione
dei falliti vuole gli identificativi visti e il loro numero, e tocca solo quelli.

**queue-browser-test.js** — la pagina Coda in Chromium, in italiano e in inglese: i quattro contatori
dai campi che il server manda davvero (prima leggeva inflight/tempfail/permfail, che il server non
ha mai mandato), mittente, oggetto, motivo del rinvio e testo con dentro HTML mostrati come testo e
mai eseguiti, il token CSRF in ogni POST, l'eliminazione di un messaggio dopo la conferma, quella
dei falliti solo scrivendone il numero, le date nella lingua della pagina, nessuno scorrimento di
lato sul telefono.

**RateLimitsApiTest** — /api/ratelimits sul server vero, con il MySQL di prova: senza sessione 401;
ogni POST senza token CSRF 403; zero e un limite giornaliero sotto quello orario rifiutati col
motivo; salvare di nuovo i limiti globali AGGIORNA l'unica riga globale (con target_id NULL
l'indice UNIQUE di MySQL lasciava aggiungere una riga a ogni salvataggio) e toglie le righe NULL
rimaste; il limite di una casella creato, aggiornato sul posto ed eliminato con i nomi e i campi
che la pagina manda (prima mandava create/update/id, che il server non conosceva); tutto nel
registro di audit.

**limits-statistics-browser-test.js** — Limiti di invio e Statistiche in Chromium, in italiano e
in inglese. Limiti: l'avviso che i limiti orari e giornalieri sono salvati ma non applicati, i
limiti globali salvati col token CSRF, il limite di una casella creato (save_mailbox), modificato
senza cambiare casella ed eliminato dopo la conferma, un indirizzo con dentro HTML che resta testo.
Statistiche: l'avviso che i conteggi di invio e ricezione non vengono raccolti, le schede da
"totals" e la tabella da "domains", i numeri di Rspamd letti dove il server li mette (prima li
cercava sotto "stats": sempre "-"), il periodo mandato come giorni, numeri e date nella lingua
della pagina; nessuno scorrimento di lato sul telefono.

**RolesTest** — ruoli e permessi con nome sul server vero, in HTTPS, col MySQL di prova. Prima
solo amministratori e vault erano del superadmin, e un Lettore poteva cambiare tutto il resto.
Controlla i permessi di ogni ruolo, la tabella delle rotte (ognuna dichiara il suo accesso, le
pubbliche sono solo quelle dell'accesso, di autoconfig, di MTA-STS e della webmail, ogni voce del
menu chiede lo stesso permesso della sua rotta) e il controllo davanti a ogni rotta per ogni ruolo:
302 e 401 senza sessione, 403 per la password di una casella, un messaggio in coda, la webmail di
una casella, un servizio, il riavvio, il vault, il firewall; il corpo rimesso al suo posto per il
gestore; il ruolo cambiato che vale subito; l'amministratore tolto che esce; i rifiuti nel registro.

**CsrfFilterTest** — il token CSRF controllato una volta per tutte le rotte (il filtro di
SSLMailServer.context), sul server vero. Venticinque rotte autenticate accettavano POST senza
chiederlo; la sonda e' una di quelle, /api/timezone-diag, con una richiesta che il gestore rifiuta
senza toccare niente: senza token 403, con l'intestazione X-CSRF-Token o col campo csrf_token
arriva al gestore, che legge lo stesso corpo; un'intestazione sbagliata vince su un token giusto
nel corpo; senza sessione risponde il gestore (401); GET e le rotte usate prima di entrare non si
toccano; ogni rifiuto nel registro di audit.

**english-pages-browser-test.js** — le pagine tradotte in Chromium, IN INGLESE, con un server
simulato che risponde a ogni API in modo plausibile (e in inglese). Per ogni pagina: gli script
girano senza errori, <html lang="en">, e il testo visibile dopo che gli script hanno riempito la
pagina, piu' title, aria-label e placeholder, non ha parole italiane rimaste. Per la pagina DNS si
scelgono un dominio, la verifica, la diagnostica dell'orario e le schede di autodns, autoconfig e
MTA-STS.

**pkg-simulation-test.sh** — la simulazione su COPIA del database di pkg, contro un pkg finto che
tiene i "lock" come file. Dimostra che lo sblocco avviene nella copia e non nel database vero,
che le dipendenze protette nominate da pkg vengono aggiunte solo se si possono sbloccare, e che
la copia sparisce alla fine.

**MtaStsOldLogicTest** — la logica di classificazione com'era prima della fix, messa
davanti agli stessi due casi. Serve a dimostrare che i controlli di MtaStsTest non sono
decorativi: qui devono fallire. Se un giorno passa anche questa, vuol dire che la prova
non sta piu' verificando niente.
