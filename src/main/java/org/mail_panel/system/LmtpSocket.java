package org.mail_panel.system;

import org.mail_panel.Main;
import org.mail_panel.i18n.I18n;
import org.mail_panel.database.MailDatabase;
import org.mail_panel.util.Shell;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Duration;
import java.util.logging.Logger;

/**
 * Postfix consegna a Dovecot da un socket Unix nella sua coda, 0600 suo, e non piu' dalla porta 24 (reperto 234).
 *
 * <p>Prima Dovecot ascoltava LMTP su 127.0.0.1:24 (e Postfix consegnava li', lmtp:inet:127.0.0.1:24) e sul suo socket
 * /var/run/dovecot/lmtp, 0666: qualunque processo della macchina (la webmail, rspamd, un servizio bucato) poteva
 * consegnare in qualunque casella senza passare da Postfix ne' da rspamd. La guida di Dovecot «Postfix and Dovecot LMTP»
 * (2.3 e 2.4): unix_listener /var/spool/postfix/private/dovecot-lmtp, mode 0600, utente e gruppo postfix, e in Postfix
 * virtual_transport = lmtp:unix:private/dovecot-lmtp. Il socket di Dovecot in /var/run/dovecot resta, 0600 di root.
 * Con l'occasione last_valid_uid e last_valid_gid uguali a quelli di vmail (5000), come chiede la pagina sulla
 * sicurezza di Dovecot: tutta la posta e' di vmail.
 *
 * <p>Sui server installati prima, all'avvio, in tre tempi perche' la posta non resti mai senza strada:
 * <ol>
 *   <li>Dovecot apre il socket nuovo tenendo anche la porta 24 (ricaricato, il socket deve esserci, di postfix, 0600,
 *       e rispondere a una consegna fermata prima del messaggio);</li>
 *   <li>Postfix passa al socket (postconf -e, reload);</li>
 *   <li>Dovecot chiude la porta 24 e il socket 0666; poi la coda si svuota.</li>
 * </ol>
 * Un errore nei primi due tempi rimette tutto com'era; nel terzo resta lo stato di mezzo, che funziona (Dovecot ascolta
 * dalle due parti), e il prossimo avvio riprende da li'. Si cambia solo il blocco che il pannello stesso aveva scritto,
 * uguale riga per riga, e solo se Postfix consegna dove il pannello lo aveva messo.
 *
 * <p>Dopo ogni reload si aspetta che Dovecot abbia davvero cambiato i suoi listener, fino a {@link #SETTLE_SECONDS}
 * secondi: nel terzo tempo che la porta 24 sia chiusa, in entrambi che la consegna di prova risponda. Il reload di
 * Dovecot ritorna prima che il master abbia rifatto i listener, e nel terzo tempo il socket di Postfix c'e' gia' dal
 * primo, coi suoi permessi: un'unica prova subito dopo cadeva nel mezzo del cambio («Connection reset») e la migrazione
 * finiva INCOMPLETE con tutto gia' a posto (reperto 240, sulla VM installata dalla 587 e passata alla 632).
 */
public final class LmtpSocket {

    private static final Logger LOGGER = Logger.getLogger(LmtpSocket.class.getName());

    private LmtpSocket() {}

    static final String TRANSPORT = "lmtp:unix:private/dovecot-lmtp";
    static final String OLD_TRANSPORT = "lmtp:inet:127.0.0.1:24";
    static final String SOCKET = "/var/spool/postfix/private/dovecot-lmtp";

    /** Il blocco che il pannello scriveva per la 2.3 (identico sul server vero e sulla VM). */
    static final String OLD23 = """
            service lmtp {
              unix_listener lmtp {
                mode = 0666
                user = vmail
                group = vmail
              }
              # LMTP su porta 24 per Postfix (virtual_transport = lmtp:inet:127.0.0.1:24)
              inet_listener lmtp {
                address = 127.0.0.1
                port = 24
              }
            }
            """;

    /** E per la 2.4. */
    static final String OLD24 = """
            service lmtp {
              unix_listener lmtp {
                mode = 0666
                user = vmail
                group = vmail
              }
              # address non esiste piu' nei listener: si chiama listen (provato sulla 2.4.5 il 09/11/2026).
              inet_listener lmtp {
                listen = 127.0.0.1
                port = 24
              }
            }
            """;

    /** Il blocco di adesso, lo stesso che scrive DovecotConfig. */
    static final String NEW = """
            service lmtp {
              # Consegna solo Postfix: il socket sta nella sua coda, 0600 suo (doc.dovecot.org, «Postfix and Dovecot
              # LMTP»; virtual_transport = lmtp:unix:private/dovecot-lmtp). Niente piu' porta 24 su 127.0.0.1 ne'
              # socket 0666, da cui qualunque processo della macchina consegnava in qualunque casella (reperto 234).
              unix_listener /var/spool/postfix/private/dovecot-lmtp {
                mode = 0600
                user = postfix
                group = postfix
              }
              # Il socket di Dovecot in /var/run/dovecot e' 0666 per impostazione predefinita: solo root.
              unix_listener lmtp {
                mode = 0600
              }
            }
            """;

    /** Lo stato di mezzo: il blocco nuovo piu' la porta 24 di prima, nella sintassi della versione. */
    static String transition(boolean v24) {
        String inet = v24 ? """
                  # Solo mentre Postfix passa al socket: poi si toglie (LmtpSocket).
                  inet_listener lmtp {
                    listen = 127.0.0.1
                    port = 24
                  }
                """ : """
                  # Solo mentre Postfix passa al socket: poi si toglie (LmtpSocket).
                  inet_listener lmtp {
                    address = 127.0.0.1
                    port = 24
                  }
                """;
        return NEW.substring(0, NEW.lastIndexOf("}\n")) + inet + "}\n";
    }

    static final String UIDS = "first_valid_uid = 5000\nfirst_valid_gid = 5000\n";
    static final String UIDS_RANGE = UIDS + "last_valid_uid = 5000\nlast_valid_gid = 5000\n";

    /** dovecot.conf con last_valid_uid/gid, se ha le due righe del pannello e non li ha gia'; altrimenti com'e'. Pura. */
    static String withUidRange(String conf) {
        if (conf == null || conf.contains("last_valid_uid") || conf.contains("last_valid_gid")) return conf;
        int at = conf.indexOf(UIDS);
        if (at < 0 || conf.indexOf(UIDS, at + 1) >= 0) return conf;
        return conf.substring(0, at) + UIDS_RANGE + conf.substring(at + UIDS.length());
    }

    /** Quello che serve, per provarlo senza Postfix e Dovecot. */
    interface Services {
        String read(Path file) throws IOException;
        void write(Path file, String text) throws IOException;
        String transport();
        /** postconf -e e reload di Postfix; vero se adesso consegna li'. */
        boolean setTransport(String transport);
        /** doveconf -n senza errori. */
        boolean dovecotAccepts();
        /** Ricarica Dovecot e aspetta il socket di Postfix (di postfix, 0600); vero se c'e'. */
        boolean dovecotReload(boolean expectSocket);
        /** La consegna fermata prima del messaggio, sul socket; null se Dovecot risponde come deve. */
        String probe();
        boolean port24Listening();
        /** Il socket di Dovecot in /var/run/dovecot e' solo di root. */
        boolean baseSocketRootOnly();
        void flushQueue();
        /** Un secondo d'attesa, mentre Dovecot rifa' i suoi listener dopo un reload. */
        default void pause() {
            try {
                Thread.sleep(1000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }

    /** Quanto si aspetta dopo un reload che Dovecot ascolti come dice la configurazione scritta (reperto 240). */
    static final int SETTLE_SECONDS = 20;

    /**
     * La consegna di prova quando Dovecot ha finito il reload: se closing, prima si aspetta la porta 24 chiusa; poi la
     * prova, ripetuta finche' risponde. Null se risponde; altrimenti l'ultima risposta sbagliata. In tutto al piu'
     * {@link #SETTLE_SECONDS} secondi; la porta 24 ancora aperta la dice chi chiama.
     */
    static String settledProbe(Services sv, boolean closing) {
        int waited = 0;
        while (closing && waited < SETTLE_SECONDS && sv.port24Listening()) {
            sv.pause();
            waited++;
        }
        String p = sv.probe();
        while (p != null && waited < SETTLE_SECONDS) {
            sv.pause();
            waited++;
            p = sv.probe();
        }
        return p;
    }

    public enum Outcome { NOTHING, DONE, LEFT, ROLLED_BACK, INCOMPLETE }

    public record Result(Outcome outcome, String detail) {}

    static final Path MASTER_CONF = Path.of("/usr/local/etc/dovecot/conf.d/10-master.conf");
    static final Path DOVECOT_CONF = Path.of("/usr/local/etc/dovecot/dovecot.conf");

    /** Il passaggio, puro rispetto a {@link Services}. */
    static Result run(Services sv, Path master, Path main) {
        String m, d;
        try {
            m = sv.read(master);
            d = sv.read(main);
        } catch (IOException e) {
            return new Result(Outcome.LEFT, "Dovecot's configuration cannot be read: " + e.getClass().getSimpleName());
        }
        if (m == null) return new Result(Outcome.NOTHING, "");   // Dovecot non configurato dal pannello
        String transport = sv.transport();
        boolean v24 = d != null && d.contains("dovecot_config_version");
        String mid = transition(v24);

        if (m.contains(NEW) && TRANSPORT.equals(transport)) return new Result(Outcome.NOTHING, "");
        boolean fromOld = count(m, OLD23) + count(m, OLD24) == 1;
        boolean fromMid = count(m, mid) == 1;
        if (!fromOld && !fromMid)
            return new Result(Outcome.LEFT, "the lmtp service of conf.d/10-master.conf is not the one the panel writes: left as it is");
        if (!OLD_TRANSPORT.equals(transport) && !TRANSPORT.equals(transport))
            return new Result(Outcome.LEFT, "Postfix delivers with " + transport + ", not where the panel put it: left as it is");

        String old = fromOld ? (count(m, OLD23) == 1 ? OLD23 : OLD24) : mid;
        String dNew = withUidRange(d);
        try {
            // 1. Dovecot sul socket nuovo, con la porta 24 ancora aperta.
            if (fromOld) {
                sv.write(master, m.replace(old, mid));
                if (dNew != null && !dNew.equals(d)) sv.write(main, dNew);
                if (!sv.dovecotAccepts()) return back(sv, master, m, main, d, transport, "doveconf refuses the configuration with the socket");
                if (!sv.dovecotReload(true)) return back(sv, master, m, main, d, transport, "after the reload Dovecot has no socket " + SOCKET + " of postfix, 0600");
                String p = settledProbe(sv, false);
                if (p != null) return back(sv, master, m, main, d, transport, "the socket does not deliver: " + p);
            }
            // 2. Postfix sul socket.
            if (!TRANSPORT.equals(sv.transport()) && !sv.setTransport(TRANSPORT)) {
                sv.setTransport(transport);
                return back(sv, master, m, main, d, transport, "Postfix did not take " + TRANSPORT);
            }
        } catch (IOException e) {
            return back(sv, master, m, main, d, transport, "a file could not be written: " + e.getClass().getSimpleName());
        }
        // 3. Via la porta 24 e il socket 0666. Da qui lo stato di mezzo funziona: un errore lo lascia, l'avvio dopo riprende.
        String withMid;
        try {
            withMid = sv.read(master);
            sv.write(master, withMid.replace(mid, NEW));
        } catch (IOException e) {
            return new Result(Outcome.INCOMPLETE, "Postfix delivers through the socket, Dovecot still also listens on port 24: "
                    + e.getClass().getSimpleName());
        }
        if (!sv.dovecotAccepts() || !sv.dovecotReload(true)) {
            try { sv.write(master, withMid); } catch (IOException ignored) { }
            sv.dovecotReload(true);
            return new Result(Outcome.INCOMPLETE, "Postfix delivers through the socket; closing port 24 was refused by Dovecot,"
                    + " so it stays open until the next start");
        }
        String p = settledProbe(sv, true);
        boolean closed = !sv.port24Listening();
        boolean rootOnly = sv.baseSocketRootOnly();
        sv.flushQueue();
        if (p != null || !closed || !rootOnly)
            return new Result(Outcome.INCOMPLETE, "after closing port 24: delivery " + (p == null ? "ok" : p) + ", port 24 "
                    + (closed ? "closed" : "still open") + ", /var/run/dovecot/lmtp " + (rootOnly ? "root only" : "still open to others"));
        return new Result(Outcome.DONE, "Postfix delivers through " + SOCKET + " (postfix, 0600); port 24 and the 0666 socket are"
                + " closed" + (dNew != null && !dNew.equals(d) ? "; last_valid_uid/gid = 5000" : ""));
    }

    private static Result back(Services sv, Path master, String m, Path main, String d, String transport, String why) {
        boolean ok = true;
        try {
            sv.write(master, m);
            if (d != null) sv.write(main, d);
        } catch (IOException e) {
            ok = false;
        }
        if (!transport.equals(sv.transport())) ok &= sv.setTransport(transport);
        ok &= sv.dovecotReload(false);
        return new Result(ok ? Outcome.ROLLED_BACK : Outcome.INCOMPLETE,
                why + (ok ? ": everything as it was" : "; and putting it back failed"));
    }

    static int count(String s, String part) {
        int n = 0;
        for (int i = s.indexOf(part); i >= 0; i = s.indexOf(part, i + 1)) n++;
        return n;
    }

    // ===================== Il server vero =====================

    static Services real() {
        return new Services() {
            @Override public String read(Path file) throws IOException {
                return Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS) ? Files.readString(file, StandardCharsets.UTF_8) : null;
            }
            @Override public void write(Path file, String text) throws IOException {
                RoundcubeDbUser.write(file, text, RoundcubeDbUser.FileState.of(file, Files.readString(file, StandardCharsets.UTF_8)));
            }
            @Override public String transport() {
                return Shell.runShell(Duration.ofSeconds(20), "postconf -h virtual_transport 2>/dev/null").outputTrim();
            }
            @Override public boolean setTransport(String t) {
                if (!t.matches("lmtp:(unix:private/dovecot-lmtp|inet:127\\.0\\.0\\.1:24)")) return false;
                Shell.Result r = Shell.run(Duration.ofSeconds(30), "postconf", "-e", "virtual_transport=" + t);
                if (!r.success()) return false;
                Shell.Result running = Shell.run(Duration.ofSeconds(20), "service", "postfix", "status");
                if (running.success()) Shell.run(Duration.ofSeconds(60), "service", "postfix", "reload");
                return t.equals(transport());
            }
            @Override public boolean dovecotAccepts() {
                Shell.Result r = Shell.runShell(Duration.ofSeconds(30), "doveconf -n 2>&1 >/dev/null");
                return r.success() && r.outputTrim().isEmpty();
            }
            @Override public boolean dovecotReload(boolean expectSocket) {
                Shell.run(Duration.ofSeconds(60), "doveadm", "reload");
                if (!expectSocket) return true;
                if (waitSocket(15)) return true;
                // Sulla 2.4 un reload non crea tutto (misurato col POP3): una volta il riavvio.
                Shell.run(Duration.ofSeconds(120), "service", "dovecot", "restart");
                return waitSocket(30);
            }
            private boolean waitSocket(int seconds) {
                for (int i = 0; i < seconds * 2; i++) {
                    if (socketReady()) return true;
                    try { Thread.sleep(500); } catch (InterruptedException e) { Thread.currentThread().interrupt(); return false; }
                }
                return false;
            }
            private boolean socketReady() {
                try {
                    Path s = Path.of(SOCKET);
                    if (!Files.exists(s, LinkOption.NOFOLLOW_LINKS)) return false;
                    PosixFileAttributes a = Files.readAttributes(s, PosixFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
                    return a.isOther() && "postfix".equals(a.owner().getName())
                            && PosixFilePermissions.toString(a.permissions()).equals("rw-------");
                } catch (IOException e) {
                    return false;
                }
            }
            @Override public String probe() {
                String mailbox = anActiveMailbox();
                return mailbox == null ? MailProbes.lmtpHello(Path.of(SOCKET), 15_000)
                        : MailProbes.lmtpRecipient(Path.of(SOCKET), mailbox, 15_000);
            }
            @Override public boolean port24Listening() {
                return Shell.runShell(Duration.ofSeconds(20), "sockstat -46lq -p 24 2>/dev/null").outputTrim().length() > 0;
            }
            @Override public boolean baseSocketRootOnly() {
                try {
                    PosixFileAttributes a = Files.readAttributes(Path.of("/var/run/dovecot/lmtp"), PosixFileAttributes.class,
                            LinkOption.NOFOLLOW_LINKS);
                    return "root".equals(a.owner().getName()) && PosixFilePermissions.toString(a.permissions()).equals("rw-------");
                } catch (IOException e) {
                    return true;   // non c'e': nessuno ci consegna
                }
            }
            @Override public void flushQueue() {
                Shell.run(Duration.ofSeconds(60), "postqueue", "-f");
            }
        };
    }

    private static String anActiveMailbox() {
        try {
            MailDatabase db = Main.mailDatabase;
            if (db == null || !Main.mysqlAvailable) return null;
            for (MailDatabase.Mailbox m : db.getAllMailboxes()) if (m.active) return m.email;
        } catch (Exception e) {
            // nessuna casella da provare: basta il saluto
        }
        return null;
    }

    /** All'avvio della parte root, dopo MailDbUsers e DovecotHome. */
    public static void ensureAtBoot() {
        try {
            Result r = run(real(), MASTER_CONF, DOVECOT_CONF);
            switch (r.outcome()) {
                case NOTHING -> { }
                case DONE -> LOGGER.info("[LmtpSocket] DONE: " + r.detail());
                case LEFT -> LOGGER.info("[LmtpSocket] left as it is: " + r.detail());
                default -> LOGGER.warning("[LmtpSocket] " + r.outcome() + ": " + r.detail());
            }
        } catch (Throwable t) {
            LOGGER.warning("[LmtpSocket] failed: " + t.getClass().getName());
        }
    }

    /**
     * Dopo che il pannello ha riscritto la configurazione di Dovecot (rigenerazione, passaggio alla 2.4) col blocco
     * nuovo: Postfix sul socket, se consegnava ancora sulla porta 24, e la coda svuotata. Il testo per il registro.
     */
    public static String alignPostfix() {
        Services sv = real();
        try {
            String m = sv.read(MASTER_CONF);
            String t = sv.transport();
            if (m == null || !m.contains(NEW) || TRANSPORT.equals(t)) return "";
            if (!OLD_TRANSPORT.equals(t)) return I18n.tr("server.lmtp.otherTransport", java.util.Map.of("transport", t));
            if (!sv.setTransport(TRANSPORT)) return I18n.tr("server.lmtp.notTaken", java.util.Map.of("transport", TRANSPORT));
            sv.flushQueue();
            return I18n.tr("server.lmtp.aligned", java.util.Map.of("socket", SOCKET));
        } catch (IOException e) {
            return I18n.tr("server.lmtp.unreadable");
        }
    }
}
