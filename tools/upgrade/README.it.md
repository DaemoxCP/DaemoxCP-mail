# Aggiornare il pannello

[English](README.md) · **Italiano**

Come sostituire il pannello che gira su un server con una release più nuova, e come tornare indietro. Gli script
sono due:

- `upgrade-panel.sh` mette il jar nuovo al suo posto e si ferma al primo segnale che qualcosa non va;
- `rollback-panel.sh` riporta il server com'era prima dell'aggiornamento, senza perdere la posta arrivata nel
  frattempo.

La posta funziona per tutto l'aggiornamento: si ferma solo il pannello, mentre riparte. Un aggiornamento riavvia
il pannello, quindi tutti devono rientrare. Alcune versioni, mentre partono, ricaricano anche nginx, PHP o Postfix, e la
webmail può non rispondere per un istante.

## Cosa serve

Lo script controlla tutto questo prima di cambiare qualsiasi cosa, e si ferma se manca qualcosa:

- un server installato come dice il [README](../../README.it.md) principale, col pannello acceso come servizio
  `daemoxcp_mail`;
- FreeBSD sui boot environment di ZFS (`bectl check` deve riuscire), con almeno 1 GiB libero nel pool;
- nessun `pkg` in corso nello stesso momento;
- una shell di root sul server.

## 1. Il jar e il suo SHA-256

- **Da una release**: scarica `daemoxcp-mail.jar` dalla [release](https://github.com/DaemoxCP/DaemoxCP-mail/releases) e
  prendi il suo SHA-256 dalle note di rilascio. Lo script li confronta, quindi lo SHA-256 deve venire dalle note
  di rilascio, mai dal file scaricato.
- **Costruito da te**: su un computer qualsiasi con Java 25 e Maven, dal repository al commit che vuoi:

  ```bash
  tools/build-jar.sh
  ```

  Scrive `target/daemoxcp-mail.jar`, con dentro il numero di build e il commit (la *Dashboard* li mostra), e
  stampa lo SHA-256 del jar. Prendi lo SHA-256 sul computer dove l'hai costruito, non sul server. Va bene anche un
  jar costruito con un semplice `mvn package`, ma allora la *Dashboard* dice che la build non è registrata.

## 2. Copiare il jar e i due script sul server

Usa i due script della stessa versione del jar: dal tag della release, o dalla tua copia del repository. Devono
stare nella stessa cartella, perché `upgrade-panel.sh` dice di lanciare `rollback-panel.sh` da lì.

Sul server:

```bash
install -d -m 700 /root/panel-upgrade
```

Dal tuo computer, nella cartella della tua copia del repository (scrivi `target/daemoxcp-mail.jar` se il jar l'hai
costruito tu):

```bash
scp daemoxcp-mail.jar tools/upgrade/upgrade-panel.sh tools/upgrade/rollback-panel.sh root@203.0.113.10:/root/panel-upgrade/
```

## 3. Una casella di prova (consigliata)

Con `-m` e `-p` lo script prova anche, prima e dopo l'aggiornamento:

- l'accesso alla casella;
- una consegna alla casella (il messaggio di prova poi lo cancella);
- l'accesso alla webmail con indirizzo e password.

Crea apposta una casella in *Caselle*, per esempio `upgrade-test@example.com`. Metti la sua password su una riga,
in un file che solo root può leggere:

```bash
install -m 600 /dev/null /root/panel-upgrade/test.pass
```

```bash
ee /root/panel-upgrade/test.pass
```

La password non esce mai da quel file: lo script la legge da lì e non la stampa.

## 4. L'aggiornamento

Da root, con lo SHA-256 del punto 1:

```bash
sh /root/panel-upgrade/upgrade-panel.sh -m upgrade-test@example.com -p /root/panel-upgrade/test.pass /root/panel-upgrade/daemoxcp-mail.jar <SHA-256>
```

Senza casella di prova:

```bash
sh /root/panel-upgrade/upgrade-panel.sh /root/panel-upgrade/daemoxcp-mail.jar <SHA-256>
```

Ci vogliono pochi minuti. Cosa fa, in ordine:

| Passo | Cosa fa | Si ferma se |
|---|---|---|
| 1 | i controlli | non è lanciato da root, o non su FreeBSD; lo SHA-256 del jar non è quello atteso, o il jar non è un archivio integro; il pannello non è acceso come servizio; questo jar gira già; non c'è un boot environment di ZFS, o c'è meno di 1 GiB libero; c'è un `pkg` in corso |
| 2 | la fotografia dello stato del server: i servizi accesi in `rc.conf`, MySQL, le porte in ascolto, `nginx -t`, `postfix check`, `doveconf`, fail2ban, il pannello sulla porta 2096, MTA-STS sulla 443, la pagina di accesso della webmail, la casella di prova, i pacchetti bloccati | qualcosa è già spento o rifiutato: prima si sistema quello |
| 3 | ferma il pannello, crea il boot environment `before-panel-upgrade-<data>`, copia la cartella del pannello | il pannello non si ferma, oppure falliscono `bectl` o la copia: riaccende il pannello di prima |
| 4 | mette il jar nuovo al suo posto e lo avvia, poi legge il log dell'avvio | il pannello si spegne mentre parte, l'avvio non finisce in 15 minuti, o il log ha un avviso, un errore o un'eccezione |
| 5 | confronta lo stato con la fotografia | una riga è cambiata, oppure un pacchetto bloccato non lo è più (quelli bloccati da adesso si elencano e basta) |
| 6 | riavvia il pannello | il log del secondo avvio ha una migrazione o un avviso: al secondo avvio non deve restare niente da fare |
| 7 | confronta di nuovo lo stato con la fotografia | come al passo 5 |

Il primo avvio di una versione nuova può fare le sue migrazioni: i cambiamenti che allineano un server già
installato alla versione nuova. Lo script le elenca. Devono riuscire tutte, e il secondo avvio non deve trovare
più niente da fare.

Alla fine scrive `DONE`, e cosa lascia per tornare indietro.

### Il registro dell'aggiornamento

Tutto quello che lo script vede va in una cartella accanto a quella del pannello, `/home/panel-upgrade-<data>/`
(la data è in UTC, e lo script stampa il nome della cartella quando comincia). `/home` sta fuori dai boot
environment, quindi la cartella resta anche tornando indietro. Contiene:

- `summary.txt`: i jar di prima e di dopo, il boot environment, l'esito e le migrazioni;
- la fotografia e lo stato dopo ogni avvio, con le differenze;
- il log di ogni avvio, e le migrazioni che ha fatto;
- la copia della cartella del pannello (`panel-dir.tar`) e il jar di prima.

Per rileggere un log con le stesse regole dello script:

```bash
sh /root/panel-upgrade/upgrade-panel.sh --check-log /home/panel-upgrade-<data>/first-start.log first
```

(`second` per il secondo avvio). Finisce con `outcome: go` oppure `outcome: STOPPED`.

### Se si ferma

Scrive `STOPPED`, il passo e il motivo, e poi come tornare indietro, coi nomi veri di questo aggiornamento:

- **ai passi da 1 a 3** il jar non è stato cambiato e non c'è niente da rimettere. Se il pannello è fermo:
  `service daemoxcp_mail start`;
- **dal passo 4 in poi** si torna indietro con `rollback-panel.sh`, come sotto.

## Tornare indietro

Dopo che il jar nuovo è partito, il jar di prima si rimette solo con `rollback-panel.sh`. Copiare il jar vecchio
sopra quello nuovo non è un modo di tornare indietro, perché le migrazioni della versione nuova possono aver
cambiato il sistema in modi che il pannello di prima non conosce.

Da root, con la cartella che l'aggiornamento ha stampato:

```bash
sh /root/panel-upgrade/rollback-panel.sh /home/panel-upgrade-<data>
```

```bash
shutdown -r now
```

Non riavvia da solo, così scegli tu il momento; Postfix e Dovecot restano fermi finché non riavvii. Cosa fa:

- **Tiene la posta.** `/var/vmail` sta dentro il boot environment, quindi un semplice `bectl activate`
  perderebbe la posta arrivata dopo l'aggiornamento. Lo script ferma Postfix e Dovecot e copia la posta di adesso
  nel boot environment di prima; la posta che c'era al momento dell'aggiornamento resta accanto, in
  `/var/vmail.before-rollback-<data>`.
- **Attiva il boot environment** creato dall'aggiornamento, per il prossimo avvio.
- **Rimette la cartella del pannello** dalla sua copia. Quella di dopo l'aggiornamento resta accanto, in
  `/home/panel.after-upgrade-<data>`.
- **Rimette quello che le migrazioni hanno cambiato fuori dal boot environment**: i nomi di alcuni log in
  `/var/log` e il proprietario di due di loro. Toglie anche le caselle di sistema vuote in `/var/mail` degli utenti
  che prima non c'erano.

Dopo il riavvio tutto il sistema torna com'era al momento dell'aggiornamento, **MySQL compreso**: domini, caselle
e alias creati dopo l'aggiornamento vanno rifatti, quindi conviene decidere presto. Se la coda di Postfix non è
vuota, torna quella di quel momento, e lo script lo dice.

Il ritorno indietro è stato provato più volte su una macchina di prova: ogni volta lo stato tornava uguale alla
fotografia e la posta arrivata dopo l'aggiornamento c'era ancora. Dopo essere tornati indietro, lo stesso
aggiornamento si può rifare.

## Dopo

- La *Dashboard* mostra la versione e la build nuove.
- *Diagnostica* → *Controlla tutto* non trova niente di nuovo.
- Nella pagina *Diagnostica*, *Gli utenti dei servizi* non ha avvisi.

Quando il pannello nuovo ha funzionato per qualche giorno, togli quello che l'aggiornamento ha lasciato per
tornare indietro:

```bash
bectl destroy -o before-panel-upgrade-<data>
```

```bash
rm -r /home/panel-upgrade-<data>
```

Poi togli la casella di prova in *Caselle*, e il file con la sua password:

```bash
rm /root/panel-upgrade/test.pass
```
