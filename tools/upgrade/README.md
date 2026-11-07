# Il passaggio del pannello a una versione nuova, sul server

La procedura per mettere il jar di `main` sul server di posta vero (pannello dell'11/10 in
`/home/panel`). È stata provata sulla VM, su un banco uguale al server, e con dei guasti piantati
(reperti, punti 135-139). Il pannello dell'11/10 non sa aggiornarsi da dentro, quindi il primo
passaggio si fa a mano. Dopo, le migrazioni all'avvio sistemano il resto da sole.

Due script, da copiare sul server insieme al jar:

- `upgrade-panel.sh` fa il passaggio e si ferma al primo segnale storto;
- `rollback-panel.sh` riporta tutto a prima del passaggio, senza perdere la posta.

Sulla VM il passaggio intero dura meno di un minuto (46 s con `main`, 33 s con la #91). Il pannello
resta fermo una decina di secondi; la posta resta sempre accesa.

## Prima

1. **Il jar e la sua impronta.** Il jar si costruisce dal commit deciso, e l'impronta si prende
   sulla macchina dove è stato costruito, non sul server:

   ```sh
   tools/build-jar.sh -o
   ```

   Lo script costruisce col numero di build e il commit dentro il jar (la dashboard li mostra dietro
   l'occhio, reperto 183) e stampa l'impronta; con `mvn package` da solo il pannello dice «build non
   registrata». Se nei sorgenti ci sono modifiche fuori dal commit, il jar lo dice.

   Poi si copiano sul server il jar e i due script, per esempio in `/root/panel-upgrade/`. Prima di
   toccare qualsiasi cosa, lo script confronta l'impronta. Un jar arrivato a metà, o un altro jar,
   non passa: il jar troncato della prova l'ha fermato l'impronta e, con la sua impronta, il
   controllo dell'archivio.
2. **Una casella di prova (consigliato).** Con `-m` e `-p` lo script prova, prima e dopo:
   - l'accesso IMAP;
   - una consegna (il messaggio di prova poi lo cancella);
   - l'accesso alla webmail con mail e password.

   Conviene una casella creata apposta dal pannello vecchio, per esempio
   `upgrade-test@domain-b.test`, da togliere dopo. La password va in un file di root, `chmod 600`,
   su una riga.
3. **Quando.** Il passaggio ferma solo il pannello. Il primo avvio della versione nuova sposta
   però Roundcube nel suo pool e ricarica nginx, php-fpm e Postfix: per un istante la webmail può
   non rispondere. Sulla VM non l'ho misurato.

## Il passaggio

```sh
sh /root/panel-upgrade/upgrade-panel.sh -m upgrade-test@domain-b.test -p /root/panel-upgrade/test.pass \
    /root/panel-upgrade/freebsd-mail-panel-1.0.jar IMPRONTA
```

| Passo | Cosa fa | Si ferma se |
|---|---|---|
| 1 | i controlli | non è root; l'impronta non torna o l'archivio è rotto; il pannello non è acceso come servizio; manca il boot environment; c'è meno di 1 GiB libero; c'è un `pkg` in corso |
| 2 | la fotografia: servizi, porte, `nginx -t`, `postfix check`, `doveconf`, fail2ban, pannello, MTA-STS sulla 443, webmail, casella, pacchetti protetti | qualcosa è già spento o rifiutato: prima si sistema quello |
| 3 | ferma il pannello, `bectl create before-panel-upgrade-<data>`, copia di `/home/panel` | il pannello non si ferma, oppure falliscono `bectl` o la copia; in questi casi riaccende il pannello di prima |
| 4 | mette il jar nuovo e fa il primo avvio | il pannello si spegne; l'avvio non finisce in 15 minuti; il log ha un avviso, un errore o un'eccezione |
| 5 | confronta lo stato con la fotografia | una riga è diversa, oppure un pacchetto protetto non lo è più (quelli nuovi si elencano e basta) |
| 6 | fa il secondo avvio | il log ha una migrazione qualsiasi o un avviso: al secondo avvio non ci deve essere niente da fare |
| 7 | confronta di nuovo lo stato | come al passo 5 |

Lo script considera finito un avvio quando il log ha le due righe che `main` scrive alla fine:
- «Mail Panel server started on port», dopo le migrazioni del thread principale;
- «[ACME] Checking certificate status at startup», dopo `AcmeUser` e `ServiceUsers`.

Il log lo segue per inode: il primo avvio lo rinomina da `pannello.log` a `panel.log`.

Tutto quello che vede va in `/home/panel-upgrade-<data>/`, che sta fuori dal boot environment e
quindi resta anche tornando indietro:
- `summary.txt`;
- la fotografia e gli stati dopo i due avvii, coi loro `diff`;
- i due pezzi di log, con le migrazioni elencate;
- la copia della cartella del pannello e il jar di prima.

Con `--check-log FILE first|second` si rilegge un pezzo di log con le stesse regole.

## Cosa guardare nel log

Il primo avvio sul server deve scrivere queste righe, e nessun altro avviso. Le ha scritte così
sulla VM, con gli stessi nomi italiani del server:

```
INFO: Renamed /var/db/mailpanel/pannello.log to /var/db/mailpanel/panel.log
INFO: Renamed /var/db/mailpanel/riavvio.log to /var/db/mailpanel/reboot.log
INFO: Renamed /var/db/mailpanel/ssl-precedente to /var/db/mailpanel/ssl-previous
INFO: Renamed /var/db/mailpanel/nginx.conf-prima-di-include to /var/db/mailpanel/nginx.conf-before-include
INFO: Renamed /var/db/mailpanel/sistema to /var/db/mailpanel/system
INFO: Renamed /var/db/mailpanel/system/salto.json to /var/db/mailpanel/system/version-jump.json
INFO: [RcScriptRepair] DONE: /usr/local/etc/rc.d/mailpanel: [/var/db/mailpanel/pannello.log] now with the current names
INFO: [PublicSurfaceRename] DONE: moved /var/log/nginx/mailpanel-pubblico-access.log -> mailpanel-public-access.log; /var/db/mailpanel/pubblico -> public; ...
INFO: [PanelMarker] DONE: signature updated in /usr/local/etc/dovecot/dovecot.conf
WARNING: [LocalMta] myorigin mail.domain-b.test is not in mydestination: it becomes localhost first
INFO: [LocalMta] Postfix is now the local MTA (/usr/local/etc/mail/mailer.conf)
INFO: [RoundcubeUser] DONE: Roundcube runs in the pool roundcube as roundcube, nginx passes to /var/run/php-fpm-roundcube.sock (1 site), ...
INFO: [RoundcubeDbUser] DONE: ...                 (solo se la #91 e' nel jar)
INFO: [AcmeUser] DONE: acme.sh runs as acme from /var/db/acme/.acme.sh: 2 certificates moved to /var/db/acme/certs, root's crontab no longer runs it, ...
```

- **L'unico WARNING ammesso** è quello di `LocalMta`: annuncia il cambiamento di `myorigin` che
  la #60 aveva previsto per questo server, e la riga dopo dice che è fatto. Lo script lo conta
  fra le migrazioni.
- **Al secondo avvio** queste righe non devono esserci più. Restano solo i controlli che passano:
  «Alias map OK», «sendmail(8) already hands over to Postfix», «Roundcube SSO plugin
  installed/updated successfully».
- **Sul server ci sono probabilmente due righe in più rispetto alla VM:**
  - «Mail stack packages locked at startup: ...», se `main` trova pacchetti dello stack non
    ancora protetti;
  - la riga delle annotazioni `mail_panel_lock` («Lock marks: N added»).

  Sono ammesse al primo avvio. Sulla VM fail2ban scriveva in più `jail.d/mail.local`; sul server
  il file c'è già.

## Tornare indietro

**Dopo che il jar nuovo è partito, si torna indietro solo con `rollback-panel.sh`.** Rimettere il
jar di prima non basta. Provato sulla VM su un server già migrato, il jar dell'11/10 parte senza
avvisi, ma:
- **niente più SSO della webmail.** Il suo installatore del plugin riscrive
  `plugins/mailpanel_sso/config.inc.php` come `www:www 600`, e Roundcube, che adesso gira come
  `roundcube`, non lo legge più: «Failed to load config» a ogni richiesta;
- **niente più rinnovi.** Cerca acme.sh in `/root/.acme.sh`, che non c'è più, e lo considera non
  installato: i certificati scadrebbero.

Il jar di prima va bene solo se lo script si è fermato ai passi 1-3. Ma in quel caso il jar non è
stato cambiato, e basta `service mailpanel start` se il pannello è fermo.

Il ritorno completo:

```sh
sh /root/panel-upgrade/rollback-panel.sh /home/panel-upgrade-<data>
shutdown -r now
```

Cosa fa:
- **la posta di adesso nel boot environment di prima.** `/var/vmail` sta DENTRO il boot
  environment, sul server come sulla VM (visto in sola lettura), quindi un `bectl activate` nudo
  perderebbe la posta arrivata dopo il passaggio. Lo script ferma Postfix e Dovecot, monta il boot
  environment di prima, ci copia la posta di adesso (quella di allora resta accanto, in
  `/var/vmail.before-rollback-<data>`) e lo smonta;
- **`bectl activate` del boot environment** creato dal passaggio;
- **la cartella del pannello dalla copia.** `/home` sta fuori dal boot environment; quella di
  dopo resta accanto, in `/home/panel.after-upgrade-<data>`;
- **i log di nginx della 443 col nome di prima.** `/var/log` sta fuori dal boot environment, e
  con due nomi insieme il passaggio successivo si fermerebbe su `BOTH_NAMES`;
- **le caselle vuote di `/var/mail`** (`roundcube`, `acme`) degli utenti che prima non c'erano.

Cosa torna al momento del passaggio: tutto il sistema, compreso **MySQL**. Domini, caselle e
alias creati dopo vanno rifatti, quindi conviene decidere presto. La coda di Postfix, se non è
vuota, torna quella di prima, e lo script lo dice. Resta solo `/var/log/acme.sh.log`, di un
utente che non esiste più (uid 169): non fa danni.

Sulla VM il ritorno è stato provato cinque volte, e ogni volta lo stato tornava uguale alla
fotografia e la posta arrivata dopo c'era ancora:
- dopo un passaggio fermato al primo avvio;
- dopo un passaggio completo seguito dal jar di prima;
- col pannello che non partiva;
- dopo il jar senza la #89;
- dopo `BOTH_NAMES`.

Dopo un ritorno, il passaggio si rifà identico.

## Dopo

- **Un rinnovo del certificato a mano**, dalla pagina dei certificati del pannello. È l'unica cosa
  che il banco non può provare: sul server i due certificati usano la sfida DNS (`dns_cf` e `dns`)
  e adesso acme.sh gira come `acme`. Sulla VM `acme` vede entrambi i certificati con la sfida di
  prima, ma senza un DNS pubblico non c'è niente da rinnovare.
- **La scheda «Gli utenti dei servizi»** non deve avere avvisi. Sulla VM erano zero, sia con
  `main` sia con la #91.
- **I residui.** Il boot environment `before-panel-upgrade-<data>` e la cartella
  `/home/panel-upgrade-<data>` restano finché servono. Quando il pannello nuovo ha girato qualche
  giorno senza problemi:
  - `bectl destroy -o before-panel-upgrade-<data>`;
  - si toglie la cartella;
  - si toglie `/root/.acme.sh.moved-to-var-db-acme`, che `AcmeUser` lascia apposta.
- **La casella di prova** si toglie dal pannello.
- **La chiave d'ispezione** (`mail-server-inspection-october-31-2026`) va tolta da
  `/root/.ssh/authorized_keys` quando il committente lo dice.
