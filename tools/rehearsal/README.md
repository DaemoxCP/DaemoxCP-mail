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
  avvii va in `/root/rehearsal/ETICHETTA`.

## Come si fa

1. **Il clone vergine.** Un clone di `pulita-29ott`, con un nome inglese.
2. **Il jar vecchio** va in `/home/panel/freebsd-mail-panel-1.0.jar`, come sul server.
3. **I conduttori** si compilano contro quel jar
   (`javac --release 25 -cp server.jar -d classes src/org/mail_panel/*.java`) e si lanciano da
   `/home/panel`.
4. **Il certificato e i pacchetti.** Prima dell'installazione: un certificato autofirmato in
   `/usr/local/etc/ssl/mail/`. Sul catalogo di oggi l'installatore dell'11/10 ha tre difetti, che
   il server vero non ha: chiede `mysql80-server`, e un pacchetto dopo glielo toglie; lascia
   Dovecot senza sieve; non accende pf. Quindi si aggiungono a mano:
   - `mysql84-server` e il suo `my.cnf`;
   - `dovecot-pigeonhole-mysql`;
   - `py312-fail2ban`;
   - pf col `pf.conf` scritto dal pannello.
5. **La fotografia.** Si avvia il pannello vecchio come servizio, si prende lo stato e si
   fotografa: `bectl create`, piu' una copia di `/home/panel` e di `/var/log/nginx`, che stanno
   FUORI dai boot environment.
6. **Una fase per versione**, ognuna dalla stessa fotografia. Prima di passare alla fotografia si
   rimettono le due cartelle condivise, e si tolgono da `/var/log/nginx` i log avanzati da altre
   prove: un `mailpanel-public-access.log` del 30/10 fermava la rinomina.

## Attenzione: il banco non e' piu' «prima»

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
2. `src/org/mail_panel/RehearsalCurrentSetup.java`, compilato contro lo stesso jar e lanciato da
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
