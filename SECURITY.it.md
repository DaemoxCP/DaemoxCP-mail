# Sicurezza

[English](SECURITY.md) · **Italiano**

## Segnalare una vulnerabilità

Per favore non aprire una issue pubblica per un problema di sicurezza: tutti potrebbero leggerla prima che esista una
correzione.

Segnalalo in privato su GitHub: nella pagina di [DaemoxCP/DaemoxCP-mail](https://github.com/DaemoxCP/DaemoxCP-mail), *Security*, poi
*Report a vulnerability*. La segnalazione la vede solo chi mantiene il progetto, e la conversazione resta lì finché
non esce la correzione.

Scrivi:

- la versione e la build, dalla *Dashboard* del pannello;
- cosa può fare un attaccante, e da dove: da internet, da una casella, dalla webmail, dal pannello, da un utente del
  server;
- i passi per riprodurlo. Provali solo su un server tuo, mai su quello di altri.

## Versioni supportate

| Versione | Correzioni di sicurezza |
|---|---|
| 1.0.x | sì |

Una correzione arriva come release nuova. Come installarla: [Tenerlo aggiornato](README.it.md#tenerlo-aggiornato).

## Cosa riguarda

- il pannello, tutte e due le sue parti;
- gli script di installazione e di aggiornamento;
- la configurazione che il pannello scrive per Postfix, Dovecot, Rspamd, ClamAV, Redis, MySQL, Roundcube, nginx,
  fail2ban e pf.

Una vulnerabilità di uno di quei programmi va segnalata al suo progetto. La pagina *Aggiornamenti* del pannello
installa le loro correzioni appena FreeBSD le pubblica nei pacchetti. Se la configurazione del pannello peggiora un
problema del genere, o espone qualcosa che non dovrebbe, segnalalo qui.
