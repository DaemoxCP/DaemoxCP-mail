# Il passaggio del pannello a una versione nuova, sul server

La procedura per mettere il jar di `main` sul server di posta vero (203.0.113.77, pannello
dell'11/10 in `/home/panel`), provata sulla VM partendo da un banco uguale al server (reperti,
punto 127). Il pannello dell'11/10 non sa aggiornarsi da dentro: il primo passaggio si fa a mano,
e da li' le migrazioni all'avvio sistemano il resto da sole.

Due script, da copiare sul server insieme al jar:

- `upgrade-panel.sh`: il passaggio, che si ferma al primo segnale storto;
- `rollback-panel.sh`: il ritorno a prima del passaggio, posta compresa.

## Prima

1. **Il jar e la sua impronta.** Il jar si costruisce dal commit deciso (`mvn -B -o -q package
   -DskipTests`), e l'impronta si prende LI', dove e' stato costruito:

   ```sh
   shasum -a 256 target/freebsd-mail-panel-1.0.jar
   ```

   Poi si copia il jar sul server, per esempio in `/root/freebsd-mail-panel-NEW.jar`. Lo script
   confronta l'impronta prima di toccare qualsiasi cosa: un jar arrivato a meta' o un altro jar non
   passano.
2. **Una casella di prova (consigliato).** Con `-m` e `-p` lo script prova prima e dopo
   l'accesso IMAP, una consegna (il messaggio di prova poi lo cancella) e l'accesso alla webmail
   con mail e password. La password in un file di root, `chmod 600`, una riga.
3. **Quando.** Il passaggio ferma solo il pannello: la posta resta accesa. Il primo avvio della
   versione nuova pero' sposta Roundcube nel suo pool e ricarica nginx e php-fpm: qualche secondo
   in cui la webmail puo' rispondere 502.

## Il passaggio

```sh
sh upgrade-panel.sh -m casella@dominio -p /root/casella.pass /root/freebsd-mail-panel-NEW.jar IMPRONTA
```

Cosa fa, e dove si ferma:

| Passo | Cosa | Si ferma se |
|---|---|---|
| 1 | controlli | non e' root, l'impronta non torna, il pannello non e' acceso come servizio, niente boot environment, meno di 1 GiB libero, un `pkg` in corso |
| 2 | fotografia | gia' prima qualcosa e' spento o rifiutato: prima si sistema quello |
| 3 | pannello fermo, `bectl create before-panel-upgrade-...`, copia di `/home/panel` | il pannello non si ferma, `bectl` o la copia falliscono (in quel caso riaccende il pannello di prima) |
| 4 | jar nuovo, primo avvio | il pannello si spegne, l'avvio non finisce in 15 minuti, il log ha un avviso, un errore o un'eccezione |
| 5 | stato confrontato con la fotografia | qualcosa e' diverso, o un pacchetto protetto non lo e' piu' |
| 6 | secondo avvio | il log ha una qualsiasi migrazione o un avviso: al secondo avvio non ci deve essere niente da fare |
| 7 | stato di nuovo | come al passo 5 |

Tutto quello che vede va in `/home/panel-upgrade-<data>/` (fuori dal boot environment, quindi resta
anche tornando indietro): la fotografia, i due pezzi di log, le migrazioni, i confronti, la copia
della cartella del pannello e il jar di prima.

## Cosa guardare nel log

<!-- da riempire con le righe misurate sulla VM -->

## Tornare indietro

<!-- da riempire con le due strade misurate sulla VM -->

## Dopo

- Il boot environment `before-panel-upgrade-...` e la cartella `/home/panel-upgrade-...` restano
  finche' servono. Quando il pannello nuovo ha girato qualche giorno senza problemi:
  `bectl destroy -o before-panel-upgrade-...`.
- La chiave d'ispezione (`mail-server-inspection-october-31-2026`) va tolta da
  `/root/.ssh/authorized_keys` quando il committente lo dice.
