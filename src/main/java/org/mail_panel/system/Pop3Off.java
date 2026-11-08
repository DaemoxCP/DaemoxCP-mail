package org.mail_panel.system;

import org.mail_panel.util.Shell;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * POP3 spento (deciso dal committente l'08/11/2026).
 *
 * <p>Misurato sul server vero: negli 8 giorni di registro della posta, 0 accessi POP3 riusciti e da 28 a
 * 149 connessioni al giorno sulle porte 110 e 995 senza nessun login (scansioni e tentativi). IMAP ha
 * centinaia di accessi al giorno. Una porta che nessuno usa e' solo una porta da attaccare.
 *
 * <p>L'installatore non accende piu' POP3 (DovecotConfig). Sui server installati prima Dovecot ha in
 * dovecot.conf la riga che il pannello scriveva, {@code protocols = imap pop3 lmtp sieve}: qui si toglie
 * {@code pop3} da quella riga, e nient'altro (i servizi pop3-login in conf.d senza il protocollo non
 * partono). Prima si prova con doveconf, poi si ricarica Dovecot e si controlla: 110 e 995 non ascoltano
 * piu', IMAP (993) si'. Se qualcosa non torna si rimette il file com'era e si ricarica. Al secondo avvio
 * non fa niente.
 */
public final class Pop3Off {

    private static final Logger LOGGER = Logger.getLogger(Pop3Off.class.getName());

    static final String DOVECOT_CONF = "/usr/local/etc/dovecot/dovecot.conf";
    static final String DOVECONF = "/usr/local/bin/doveconf";
    private static final Pattern PROTOCOLS = Pattern.compile("(?m)^(\\s*protocols\\s*=\\s*)(.*)$");

    private Pop3Off() {}

    /**
     * dovecot.conf senza pop3 nella riga protocols, o null se non c'e' niente da togliere (o la riga
     * protocols non c'e' o ce n'e' piu' d'una: allora non e' il file che scriveva il pannello).
     */
    static String withoutPop3(String conf) {
        if (conf == null) return null;
        Matcher m = PROTOCOLS.matcher(conf);
        if (!m.find()) return null;
        int start = m.start(), end = m.end();
        String prefix = m.group(1), value = m.group(2);
        if (m.find()) return null;
        List<String> kept = new ArrayList<>();
        boolean had = false;
        for (String p : value.trim().split("\\s+")) {
            if (p.equals("pop3")) had = true;
            else if (!p.isEmpty()) kept.add(p);
        }
        if (!had || kept.isEmpty()) return null;
        return conf.substring(0, start) + prefix + String.join(" ", kept) + conf.substring(end);
    }

    /** Le porte TCP in ascolto, dall'uscita di sockstat -46l -P tcp. */
    static boolean listens(String sockstat, int port) {
        if (sockstat == null) return false;
        for (String line : sockstat.split("\n")) {
            String[] f = line.trim().split("\\s+");
            if (f.length >= 6 && f[5].endsWith(":" + port)) return true;
        }
        return false;
    }

    public static void ensureAtBoot() {
        try {
            Path conf = Path.of(DOVECOT_CONF);
            if (!Files.isRegularFile(conf) || !Files.isExecutable(Path.of(DOVECONF))) return;
            String current = Files.readString(conf, StandardCharsets.UTF_8);
            String next = withoutPop3(current);
            if (next == null) return;
            if (!Shell.run(Duration.ofSeconds(15), "service", "dovecot", "status").success()) {
                LOGGER.info("[Pop3Off] Dovecot is not running: POP3 left as it is, retrying at the next start");
                return;
            }
            apply(conf, current, next);
        } catch (Exception e) {
            LOGGER.warning("[Pop3Off] not applied: " + e.getMessage());
        }
    }

    private static void apply(Path conf, String current, String next) throws Exception {
        Path tmp = conf.resolveSibling(".dovecot.conf.pop3off");
        Files.copy(conf, tmp, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.COPY_ATTRIBUTES);
        Files.writeString(tmp, next, StandardCharsets.UTF_8);
        Files.move(tmp, conf, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        Shell.Result check = Shell.run(Duration.ofSeconds(15), DOVECONF, "-n");
        if (!check.success()) {
            Files.writeString(conf, current, StandardCharsets.UTF_8);
            LOGGER.warning("[Pop3Off] ROLLED_BACK: doveconf refuses dovecot.conf without pop3, nothing changed");
            return;
        }
        String problem = reloadAndCheck();
        if (problem != null) {
            Files.writeString(conf, current, StandardCharsets.UTF_8);
            Shell.run(Duration.ofSeconds(60), "service", "dovecot", "restart");
            LOGGER.warning("[Pop3Off] ROLLED_BACK: " + problem + "; dovecot.conf put back and Dovecot restarted");
            return;
        }
        LOGGER.info("[Pop3Off] DONE: POP3 off (protocols without pop3 in " + DOVECOT_CONF
                + "): ports 110 and 995 closed, IMAP still answers");
    }

    /** Ricarica, poi 110 e 995 chiuse e 993 aperta; un restart se il reload non basta. Null se va. */
    private static String reloadAndCheck() throws InterruptedException {
        for (String how : new String[]{"reload", "restart"}) {
            if (!Shell.run(Duration.ofSeconds(60), "service", "dovecot", how).success()) continue;
            for (int i = 0; i < 20; i++) {
                Thread.sleep(500);
                String s = Shell.run(Duration.ofSeconds(15), "sockstat", "-46l", "-P", "tcp").output();
                if (!listens(s, 110) && !listens(s, 995) && listens(s, 993)) return null;
            }
        }
        return "after a reload and a restart, ports 110/995 were still open or IMAP (993) was not";
    }
}
