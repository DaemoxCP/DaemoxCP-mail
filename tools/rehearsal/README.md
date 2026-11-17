# La prova del passaggio da una versione vecchia

Strumenti per rifare sulla VM quello che succede su un server gia' avviato quando gli si mette
sopra il pannello nuovo. Usati la prima volta il 31/10/2026, col jar del server di posta vero
(commit 419b0a2, 11/10/2026): reperti, punto 112.

Non stanno in `tests/` perche' i due conduttori si compilano contro il jar VECCHIO: chiamano le sue
classi coi loro nomi di allora (`ProtezioneWeb`, `MtaSts.impostaModo`, ...), e la serie completa
compila tutto quello che trova in `tests/` contro il jar di adesso.

## I pezzi

- `src/org/mail_panel/RehearsalOldInstall.java`: l'installazione come la faceva il menu di
  quella versione. Argomenti: nome della posta, dominio di Roundcube.
- `src/org/mail_panel/RehearsalOldSetup.java`: quello che un server vero ha in piu':
  - il certificato del pannello e il primo amministratore;
  - un dominio con due caselle, con le loro credenziali di prova in `/root/rehearsal/mailboxes`,
    leggibile solo da root;
  - la superficie sulla 443 con MTA-STS in enforce, e la sua jail;
  - lo script di avvio.
- `check-state.sh DOMINIO`: lo stato da confrontare prima e dopo:
  - i nomi dei file;
  - lo script di avvio;
  - nginx e MTA-STS sulla 443;
  - fail2ban e pf;
  - Postfix come MTA locale;
  - i servizi;
  - l'accesso a una casella e una consegna.
- `upgrade-phase.sh JAR ETICHETTA DOMINIO`: il passaggio come lo fa una persona. Ferma il servizio,
  cambia il jar, riavvia con lo script che c'e', poi riavvia una seconda volta. Lo stato dei due
  avvii va in `/root/rehearsal/ETICHETTA`. Dal 05/11/2026 il passaggio si prova invece con lo
  script della produzione, `tools/upgrade/upgrade-panel.sh`, che fa lo stesso e si ferma da solo.
- `server-leftovers.sh`: quello che il server vero ha in piu' del banco: due certificati con la
  sfida DNS e i nomi italiani rimasti in `/var/db/mailpanel` (reperti, punto 135).
- `photo.sh take|restore`: la fotografia del banco, cioe' un boot environment con dentro le copie
  di `/home/panel` e `/var/log`, che stanno fuori dai boot environment.

## Come si fa (rifatto il 05/11/2026, reperti punto 135)

Dalla VM vergine che ripristina il committente si lavora su `default` (le copie vergini le tiene
lui). Tutto da root sulla VM, salvo la costruzione dei jar.

1. **Il jar vecchio.** Sul Mac, `git archive 419b0a2 | tar -x -C <cartella>` e
   `mvn -B -o -q package -DskipTests` (sha256 `957886b5...`; quello del server, `6303a647...`, ha
   in piu' solo le modifiche all'updater). Va in `/home/panel/freebsd-mail-panel-1.0.jar`.
2. **I conduttori e il certificato.** Solo i due `RehearsalOld*`: `RehearsalCurrentSetup` si compila
   contro il jar di `main` e non contro questo.

   ```sh
   javac --release 25 -cp /home/panel/freebsd-mail-panel-1.0.jar -d classes src/org/mail_panel/RehearsalOld*.java
   openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /usr/local/etc/ssl/mail/privkey.pem \
       -out /usr/local/etc/ssl/mail/fullchain.pem -subj "/CN=mail.rehearsal.test"
   ```
3. **L'installazione dell'11/10**, da `/home/panel`:
   `java -cp freebsd-mail-panel-1.0.jar:classes org.mail_panel.RehearsalOldInstall mail.rehearsal.test webmail.rehearsal.test`.

   Il conduttore cambia nello script due nomi di pacchetto, perche' sul catalogo di oggi:
   - `postfix-mysql` porta `mysql84-client`, che toglie `mysql80-server` gia' nella fase dei
     pacchetti, prima che MySQL sia mai partito. Lo script dice lo stesso «riuscita», ma il
     database non c'e'. Il 31/10 il server veniva tolto piu' tardi;
   - `dovecot-pigeonhole` lascia lmtp senza sieve.

   Il server vero ha `mysql84-server` e `dovecot-pigeonhole-mysql`, e sono le due righe cambiate.
4. **fail2ban e pf**, come li ha il server (la versione vecchia installava fail2ban dalla sua
   pagina). `/etc/pf.conf` e' quello che scrive l'installatore di oggi (tabella `<permaban>`,
   ancora `f2b/*`, `pass`), con `/var/db/mail-panel/permaban.list` vuota:

   ```sh
   pkg install -y py312-fail2ban && sysrc fail2ban_enable=YES pf_enable=YES
   service fail2ban start && service pf start
   ```
5. **`RehearsalOldSetup mail.rehearsal.test rehearsal.test`**, da `/home/panel` con lo stesso
   classpath.
6. **Come il server**, visto in sola lettura il 05/11/2026:
   - **i pacchetti protetti.** Gli stessi 40 del server, `pkg lock -y` su quelli installati:
     `clamav dovecot-mysql dovecot-pigeonhole-mysql mysql84-client mysql84-server nginx openjdk25
     php84 php84-ctype php84-curl php84-dom php84-exif php84-extensions php84-fileinfo
     php84-filter php84-gd php84-iconv php84-intl php84-ldap php84-mbstring php84-mysqli
     php84-opcache php84-pdo php84-pdo_mysql php84-pdo_sqlite php84-phar php84-posix php84-session
     php84-simplexml php84-sqlite3 php84-tokenizer php84-xml php84-xmlreader php84-xmlwriter
     php84-zip postfix-mysql py312-fail2ban redis roundcube-php84 rspamd`. Sul banco sono 39:
     `php84-ldap` non c'e';
   - **l'hash dell'utente master di Dovecot.** Sul server c'e', sulle installazioni di oggi no:

     ```sh
     K=$(head -1 /var/db/mailpanel/dovecot_master.key)
     printf "admin:%s\n" "$(printf "%s\n%s\n" "$K" "$K" | doveadm pw -s BLF-CRYPT)" > /usr/local/etc/dovecot/master-users.new
     chown root:dovecot /usr/local/etc/dovecot/master-users.new && chmod 640 /usr/local/etc/dovecot/master-users.new
     mv /usr/local/etc/dovecot/master-users.new /usr/local/etc/dovecot/master-users
     ```
   - **acme.sh da root**, come lo installava `get.acme.sh`. Il programma, con `dnsapi`,
     `deploy` e `notify`, si prende dal pacchetto senza installarlo
     (`pkg fetch -o DIR acme.sh`, poi `tar -xf` del `.pkg`). Poi:

     ```sh
     HOME=/root ./acme.sh --install --home /root/.acme.sh --accountemail admin@rehearsal.test
     /root/.acme.sh/acme.sh --home /root/.acme.sh --set-default-ca --server letsencrypt
     ```

     `--install` scrive anche la riga nel cron di root. Account e certificato si fanno in locale,
     perche' `mail.rehearsal.test` non si puo' validare:
     - `ca/acme-v02.api.letsencrypt.org/directory/` con `account.key` (EC), `account.json` e
       `ca.conf`;
     - `mail.rehearsal.test_ecc/` con chiave EC, `.csr`, `.cer` autofirmato, `ca.cer`,
       `fullchain.cer`, `.csr.conf` e la `.conf` coi campi `Le_*` che scrive acme.sh.

     Alla fine `acme.sh --list` deve elencare il certificato;
   - **`server-leftovers.sh`**: il secondo certificato, le sfide DNS e i nomi italiani rimasti.
7. **Lo stato di prima.** `service mailpanel start`, poi `check-state.sh rehearsal.test` e
   `roundcube-db-state.sh` (dalla #91).
8. **La fotografia:** `photo.sh take rehearsal-october-11`.
9. **Una fase per versione**, ognuna dalla fotografia:
   - `photo.sh restore rehearsal-october-11 <clone>`, poi `shutdown -r now`;
   - si aspetta di vedere il clone col flag `N` in `bectl list`: subito dopo il riavvio puo'
     rispondere ancora la macchina vecchia;
   - `tools/upgrade/upgrade-panel.sh -m alice@rehearsal.test -p <file> <jar> <sha256>`.

   Attenzione: `/root` sta dentro il boot environment. Gli strumenti e i jar copiati dopo la
   fotografia vanno tenuti fuori (`/var/tmp`) e rimessi in ogni clone.

## Attenzione: il banco non e' piu' «prima» (31/10/2026, superato dal banco del 05/11)

Dal 31/10/2026 sera `rehearsal-before-healthy` contiene gia' il passaggio della #89: c'e'
`/root/rehearsal/after-branch` (21:56), lo script di avvio scrive `panel.log`, nginx include
`mailpanel-public.conf`. Lo stato «11/10» sta solo nelle due cartelle condivise di `before2/`, e
messe sopra questo boot environment non tornano d'accordo (il jar vecchio su file gia' rinominati,
i log di nginx col nome vecchio accanto a quello nuovo: `BOTH_NAMES`).

Per una prova che riguarda altro va bene cosi', con il jar di `main` (73bfbcd) in `/home/panel`
come «prima» e senza rimettere i log di nginx: e' come la #84-#89 lascia il server vero. Cosi' e'
stata fatta la prova degli utenti dei servizi (reperti, punto 116). Per rifare il passaggio
dall'11/10 serve rifare il banco.

## Il banco col jar di adesso (05/11/2026)

Per le prove che non riguardano il passaggio dall'11/10, il «prima» si fa col jar di `main` su una
VM vergine (reperti, punto 124):
1. `InstallFromScratch` del commit di `main`, compilato contro il suo jar, in `/root/panel`;
2. `src/org/daemoxcp/mail/RehearsalCurrentSetup.java`, compilato contro lo stesso jar e lanciato da
   `/root/panel`: certificato, amministratore, `rehearsal.test` con alice e bob, lo script di avvio
   (punta a `/root/panel`, dentro il boot environment: niente da rimettere in `/home`);
3. `sysrc mailpanel_enable=YES` e `service mailpanel start`.

Due strumenti in piu':
- `roundcube-db-state.sh`: chi entra in MySQL per la webmail, gli account coi privilegi, chi legge
  cosa, la pagina d'accesso, un accesso vero di alice dal modulo e l'hash dell'utente master di
  Dovecot. Non stampa password: per ognuna dice di chi e';
- `roundcube-db-faults.sh plant|clear NOME`: i guasti piantati per RoundcubeDbUser. Due
  (`users-trigger`, `session-update`) non rompono la webmail, e la migrazione lo dice: sono
  rimasti come esempio di guasto che non lo era.

Attenzione: avviare il pannello protegge i pacchetti, e dopo l'installatore non li puo'
reinstallare. Per rifare un'installazione sopra il banco: `pkg unlock -a -y` prima.
