package org.daemoxcp.mail.system;

import org.daemoxcp.mail.util.Shell;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFileAttributes;
import java.time.Duration;
import java.util.logging.Logger;
import java.util.regex.Pattern;

/**
 * inet_protocols scritto in chiaro in main.cf, col valore che Postfix usa gia'.
 *
 * Lo script di installazione di ogni aggiornamento di postfix (/usr/local/libexec/postfix/post-install, letto
 * sulla VM il 09/11/2026) fa questo: se il predefinito non e' ipv4 e main.cf non dice inet_protocols, scrive
 * {@code inet_protocols = ipv4}. Su FreeBSD il predefinito e' all, quindi lo scrive ogni volta che manca, e al
 * riavvio postfix smette di ascoltare in IPv6 (reperto 42). Il pannello lo vede e non riavvia (InstallSideEffects),
 * ma il passo si ferma: nella prova di «Aggiorna tutto» sulla VM (reperto 207) la catena si e' fermata al passo
 * di postfix-mysql per questo. L'installazione completa non scriveva la riga; quella dello stack e PostfixScript
 * si'.
 *
 * Qui la riga si scrive col valore di adesso, quello che {@code postconf -h} legge: niente cambia in quello che
 * Postfix fa, quindi non serve ricaricarlo, e lo script non ha piu' niente da scrivere. Un valore gia' scritto,
 * qualunque sia, resta: e' una scelta di qualcuno (sul server vero ipv4, senza indirizzi IPv6). Dopo si controlla
 * che main.cf dica il valore giusto e che {@code postfix check} passi; se no main.cf torna com'era, byte per byte.
 * Al secondo avvio non fa niente.
 */
public final class PostfixInetProtocols {

    private static final Logger LOGGER = Logger.getLogger(PostfixInetProtocols.class.getName());

    static final String POSTCONF = "/usr/local/sbin/postconf";
    static final String POSTFIX = "/usr/local/sbin/postfix";

    /** I valori che Postfix accetta: all, oppure ipv4 e ipv6, da soli o insieme. Nient'altro va in main.cf. */
    private static final Pattern VALUE = Pattern.compile("all|ipv4|ipv6|ipv4[ ,]+ipv6|ipv6[ ,]+ipv4");

    private PostfixInetProtocols() {}

    enum Action { NOTHING, WRITE, LEFT_ALONE }

    record Decision(Action action, String value, String reason) {}

    /**
     * Funzione pura: se Postfix c'e', il valore scritto in main.cf ({@code postconf -nh}, vuoto se non c'e') e
     * quello in uso ({@code postconf -h}).
     */
    static Decision decide(boolean installed, String explicit, String effective) {
        if (!installed) return new Decision(Action.NOTHING, "", "Postfix is not installed");
        String set = explicit == null ? "" : explicit.trim();
        if (!set.isEmpty())
            return new Decision(Action.NOTHING, set, "main.cf already says inet_protocols = " + set);
        String now = effective == null ? "" : effective.trim().replaceAll("\\s+", " ");
        if (!VALUE.matcher(now).matches())
            return new Decision(Action.LEFT_ALONE, "", "inet_protocols in use is '" + now + "', not a value written here: left as it is");
        return new Decision(Action.WRITE, now, "main.cf does not say inet_protocols: the update of postfix would write ipv4");
    }

    public static void ensureAtBoot() {
        try {
            boolean installed = Files.isExecutable(Path.of(POSTCONF));
            String explicit = "", effective = "";
            if (installed) {
                explicit = postconf("-n", "-h", "inet_protocols");
                effective = postconf("-h", "inet_protocols");
            }
            Decision d = decide(installed, explicit, effective);
            switch (d.action()) {
                case NOTHING -> { return; }
                case LEFT_ALONE -> { LOGGER.warning("[PostfixInetProtocols] " + d.reason()); return; }
                case WRITE -> write(d);
            }
        } catch (Throwable t) {
            LOGGER.warning("[PostfixInetProtocols] ensureAtBoot exception: " + t.getMessage());
        }
    }

    private static void write(Decision d) throws Exception {
        Path mainCf = Path.of(postconf("-h", "config_directory"), "main.cf");
        if (!Files.isRegularFile(mainCf)) {
            LOGGER.warning("[PostfixInetProtocols] " + mainCf + " not found: left as it is");
            return;
        }
        byte[] before = Files.readAllBytes(mainCf);
        PosixFileAttributes attrs = Files.readAttributes(mainCf, PosixFileAttributes.class);
        // Un controllo che non passava gia' prima non e' colpa di questa riga: conta solo se passava.
        boolean checkedBefore = Shell.run(Duration.ofSeconds(60), POSTFIX, "check").success();
        Shell.Result r = Shell.run(Duration.ofSeconds(30), POSTCONF, "-e", "inet_protocols=" + d.value());
        String problem = !r.success() ? "postconf -e failed (exit " + r.exitCode() + "): " + r.outputTrim() : verify(d.value(), checkedBefore);
        if (problem != null) {
            Files.write(mainCf, before);
            PosixFileAttributeView view = Files.getFileAttributeView(mainCf, PosixFileAttributeView.class);
            view.setOwner(attrs.owner());
            view.setGroup(attrs.group());
            view.setPermissions(attrs.permissions());
            LOGGER.warning("[PostfixInetProtocols] ROLLED_BACK: " + problem + "; main.cf back as it was");
            return;
        }
        LOGGER.info("[PostfixInetProtocols] DONE: inet_protocols = " + d.value() + " written in " + mainCf
                + " (the value already in use: nothing changes, no reload)");
    }

    /** main.cf dice il valore, quello in uso e' lo stesso, e la configurazione passa ancora il controllo di Postfix. */
    private static String verify(String value, boolean checkedBefore) {
        String now = postconf("-n", "-h", "inet_protocols").trim().replaceAll("\\s+", " ");
        if (!now.equals(value)) return "main.cf says '" + now + "' instead of '" + value + "'";
        String inUse = postconf("-h", "inet_protocols").trim().replaceAll("\\s+", " ");
        if (!inUse.equals(value)) return "inet_protocols in use is now '" + inUse + "' instead of '" + value + "'";
        Shell.Result check = Shell.run(Duration.ofSeconds(60), POSTFIX, "check");
        if (checkedBefore && !check.success()) return "postfix check failed (exit " + check.exitCode() + "): " + check.outputTrim();
        return null;
    }

    private static String postconf(String... args) {
        String[] cmd = new String[args.length + 1];
        cmd[0] = POSTCONF;
        System.arraycopy(args, 0, cmd, 1, args.length);
        Shell.Result r = Shell.run(Duration.ofSeconds(15), cmd);
        return r.success() ? r.outputTrim() : "";
    }
}
