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
 * POP3 acceso o spento, come sceglie l'amministratore nelle Impostazioni; spento finche' non sceglie
 * (deciso dal committente l'08/11/2026).
 *
 * <p>Misurato sul server vero: negli 8 giorni di registro della posta, 0 accessi POP3 riusciti e da 28 a
 * 149 connessioni al giorno sulle porte 110 e 995 senza nessun login (scansioni e tentativi), mentre IMAP
 * ha centinaia di accessi al giorno. Una porta che nessuno usa e' solo una porta da attaccare: per questo
 * il predefinito e' spento. Chi ha un programma di posta che vuole POP3 lo accende dal pannello.
 *
 * <p>La scelta sta in panel_settings ({@link #SETTING}, "1" o "0"). Il pannello la applica a Dovecot con
 * la sola riga {@code protocols} di dovecot.conf, quella che scriveva lui: aggiunge o toglie {@code pop3}
 * e nient'altro (i servizi pop3-login, predefiniti o in conf.d, senza il protocollo non partono). Prima
 * prova con doveconf, poi ricarica Dovecot e controlla le porte: spento, 110 e 995 non ascoltano; acceso,
 * ascoltano; IMAP (993) sempre. Se qualcosa non torna rimette il file com'era. Le porte di pf
 * (PfPolicy) e delle regole dei paesi (PfFirewallManager) seguono la stessa scelta.
 */
public final class Pop3 {

    private static final Logger LOGGER = Logger.getLogger(Pop3.class.getName());

    /** La scelta, in panel_settings: "1" acceso, altrimenti spento. */
    public static final String SETTING = "pop3_enabled";
    static final String DOVECOT_CONF = "/usr/local/etc/dovecot/dovecot.conf";
    static final String DOVECONF = "/usr/local/bin/doveconf";
    private static final Pattern PROTOCOLS = Pattern.compile("(?m)^(\\s*protocols\\s*=\\s*)(.*)$");

    private Pop3() {}

    /** Quello che ha scelto l'amministratore; spento se non ha scelto o il database non risponde. */
    public static boolean wanted() {
        org.mail_panel.database.MailDatabase db = org.mail_panel.Main.mailDatabase;
        return db != null && "1".equals(db.getSetting(SETTING, "0"));
    }

    /**
     * dovecot.conf con pop3 acceso o spento nella riga protocols, o null se non c'e' niente da cambiare
     * (o la riga protocols non c'e', o ce n'e' piu' d'una: allora non e' il file che scriveva il pannello,
     * o spegnerlo lascerebbe Dovecot senza protocolli).
     */
    static String withPop3(String conf, boolean on) {
        if (conf == null) return null;
        Matcher m = PROTOCOLS.matcher(conf);
        if (!m.find()) return null;
        int start = m.start(), end = m.end();
        String prefix = m.group(1), value = m.group(2);
        if (m.find()) return null;
        List<String> protocols = new ArrayList<>();
        for (String p : value.trim().split("\\s+")) if (!p.isEmpty()) protocols.add(p);
        boolean has = protocols.contains("pop3");
        if (has == on) return null;
        if (on) protocols.add(protocols.contains("imap") ? protocols.indexOf("imap") + 1 : protocols.size(), "pop3");
        else protocols.removeIf("pop3"::equals);
        if (protocols.isEmpty()) return null;
        return conf.substring(0, start) + prefix + String.join(" ", protocols) + conf.substring(end);
    }

    /** Vero se la porta TCP ascolta, dall'uscita di sockstat -46l -P tcp. */
    static boolean listens(String sockstat, int port) {
        if (sockstat == null) return false;
        for (String line : sockstat.split("\n")) {
            String[] f = line.trim().split("\\s+");
            if (f.length >= 6 && f[5].endsWith(":" + port)) return true;
        }
        return false;
    }

    /** All'avvio della parte root: Dovecot come la scelta (spento se non c'e'). Al secondo avvio non fa niente. */
    public static void ensureAtBoot() {
        String problem = align(wanted());
        if (problem != null) LOGGER.warning("[Pop3] " + problem);
    }

    /**
     * La scelta dell'amministratore dalle Impostazioni: la salva, la applica a Dovecot e alle porte di pf.
     * Null se e' fatto; altrimenti il motivo, e la scelta di prima resta (salvata e applicata).
     */
    public static synchronized String choose(boolean on) {
        org.mail_panel.database.MailDatabase db = org.mail_panel.Main.mailDatabase;
        if (db == null) return "the panel's database does not answer";
        String before = db.getSetting(SETTING, "0");
        db.setSetting(SETTING, on ? "1" : "0");
        String problem = align(on);
        if (problem != null) {
            db.setSetting(SETTING, before);
            return problem;
        }
        org.mail_panel.security.PfPolicy.ensureAtBoot();
        return null;
    }

    /** Dovecot acceso o spento come richiesto. Null se e' gia' cosi', o se e' fatto. */
    private static synchronized String align(boolean on) {
        try {
            Path conf = Path.of(DOVECOT_CONF);
            if (!Files.isRegularFile(conf) || !Files.isExecutable(Path.of(DOVECONF))) return null;
            String current = Files.readString(conf, StandardCharsets.UTF_8);
            String next = withPop3(current, on);
            if (next == null) return null;
            if (!Shell.run(Duration.ofSeconds(15), "service", "dovecot", "status").success()) {
                LOGGER.info("[Pop3] Dovecot is not running: POP3 left as it is, retrying at the next start");
                return null;
            }
            return apply(conf, current, next, on);
        } catch (Exception e) {
            return "not applied: " + e.getMessage();
        }
    }

    private static String apply(Path conf, String current, String next, boolean on) throws Exception {
        Path tmp = conf.resolveSibling(".dovecot.conf.pop3");
        Files.copy(conf, tmp, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.COPY_ATTRIBUTES);
        Files.writeString(tmp, next, StandardCharsets.UTF_8);
        Files.move(tmp, conf, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        Shell.Result check = Shell.run(Duration.ofSeconds(15), DOVECONF, "-n");
        if (!check.success()) {
            Files.writeString(conf, current, StandardCharsets.UTF_8);
            return "ROLLED_BACK: doveconf refuses dovecot.conf with POP3 " + (on ? "on" : "off") + ", nothing changed";
        }
        if (!reloadAndCheck(on)) {
            Files.writeString(conf, current, StandardCharsets.UTF_8);
            Shell.run(Duration.ofSeconds(60), "service", "dovecot", "restart");
            return "ROLLED_BACK: after a reload and a restart, ports 110/995 were not " + (on ? "open" : "closed")
                    + " or IMAP (993) was not open; dovecot.conf put back and Dovecot restarted";
        }
        LOGGER.info("[Pop3] DONE: POP3 " + (on ? "on (ports 110 and 995 open)" : "off (ports 110 and 995 closed)")
                + " in " + DOVECOT_CONF + "; IMAP still answers");
        return null;
    }

    /** Ricarica, poi 110 e 995 come richiesto e 993 aperta; un restart se il reload non basta. */
    private static boolean reloadAndCheck(boolean on) throws InterruptedException {
        for (String how : new String[]{"reload", "restart"}) {
            if (!Shell.run(Duration.ofSeconds(60), "service", "dovecot", how).success()) continue;
            for (int i = 0; i < 20; i++) {
                Thread.sleep(500);
                String s = Shell.run(Duration.ofSeconds(15), "sockstat", "-46l", "-P", "tcp").output();
                if (listens(s, 110) == on && listens(s, 995) == on && listens(s, 993)) return true;
            }
        }
        return false;
    }
}
