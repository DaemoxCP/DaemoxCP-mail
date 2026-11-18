package org.daemoxcp.mail.system;

import org.daemoxcp.mail.util.Shell;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFileAttributes;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;
import java.util.regex.Pattern;

/**
 * La mappa di Postfix che rende sicuro il catch-all: ogni casella punta a se stessa, dopo gli alias.
 *
 * <p>Un catch-all e' un alias con sorgente {@code @dominio} (tabella aliases). Postfix cerca un indirizzo nelle
 * virtual_alias_maps prima nella forma {@code nome@dominio}, in tutte le tabelle e nel loro ordine, e solo dopo nella
 * forma {@code @dominio}. Con la sola tabella degli alias, la posta per una casella che non ha un alias suo finirebbe
 * al catch-all: la casella non riceverebbe piu' niente, e una casella come destinazione del catch-all farebbe un giro
 * senza fine. Con questa mappa dopo gli alias:
 * <ul>
 *   <li>un alias esplicito vince ancora (viene prima): copie e inoltri restano come sono;</li>
 *   <li>una casella che riceve si trova da sola, e la sua posta va a lei;</li>
 *   <li>solo un indirizzo che non e' ne' alias ne' casella che riceve arriva a {@code @dominio}: anche una casella
 *       spenta o che non riceve, la cui posta senza catch-all viene rifiutata.</li>
 * </ul>
 * Solo le caselle che ricevono, con la stessa condizione di virtual_mailbox_maps: Postfix prende per valido ogni
 * indirizzo che trova nelle virtual_alias_maps, e con tutte le caselle una casella che non riceve avrebbe accettato
 * posta dall'esterno anche senza catch-all (misurato sulla VM il 18/11/2026). Cosi', senza catch-all, non cambia
 * niente: un indirizzo che punta a se stesso e' quello che Postfix fa gia'.
 *
 * <p>La mappa usa la stessa connessione di {@value #ALIASES} (utente di Postfix, MailDbUsers: SELECT su
 * mailboxes.email c'e' gia') e la sua domanda (scripts.PostfixMaps). Le installazioni nuove la scrivono da sole; sui
 * server installati prima la scrive {@link #ensureAtBoot()}, dopo MailDbUsers:
 * <ol>
 *   <li>il file, con proprietario, gruppo e permessi di {@value #ALIASES};</li>
 *   <li>postmap -q: una chiave che non c'e' risponde vuoto, una casella risponde se stessa;</li>
 *   <li>virtual_alias_maps con la mappa dopo gli alias, solo se diceva esattamente la mappa degli alias del
 *       pannello (una configurazione scritta a mano resta com'e', e il catch-all non si crea);</li>
 *   <li>postfix check e reload. Se una prova non torna, main.cf torna com'era byte per byte, il file nuovo si
 *       toglie, e Postfix si ricarica.</li>
 * </ol>
 * Al secondo avvio non fa niente.
 */
public final class MailboxAddressMap {

    private static final Logger LOGGER = Logger.getLogger(MailboxAddressMap.class.getName());

    static final String POSTCONF = "/usr/local/sbin/postconf";
    static final String POSTFIX = "/usr/local/sbin/postfix";
    static final String POSTMAP = "/usr/local/sbin/postmap";

    /** La mappa degli alias del pannello. */
    static final String ALIASES = "mysql-virtual-aliases.cf";
    /** Questa mappa. */
    public static final String FILE = org.daemoxcp.mail.scripts.PostfixMaps.MAILBOX_ADDRESSES_FILE;
    /** Ogni casella, attiva o no, e' se stessa: cosi' un catch-all non le prende la posta. */
    public static final String QUERY = org.daemoxcp.mail.scripts.PostfixMaps.MAILBOX_ADDRESSES_QUERY;

    private static final Pattern QUERY_LINE = Pattern.compile("^\\s*query\\s*=.*$");
    private static final Pattern SEPARATORS = Pattern.compile("[\\s,]+");

    private MailboxAddressMap() {}

    enum Action { NOTHING, ADD, REWRITE, LEFT_ALONE }

    record Decision(Action action, String newValue, String reason) {}

    /** Le tabelle di virtual_alias_maps, nell'ordine. */
    static List<String> tables(String value) {
        List<String> l = new ArrayList<>();
        if (value == null) return l;
        for (String s : SEPARATORS.split(value.trim())) if (!s.isEmpty()) l.add(s);
        return l;
    }

    /**
     * Funzione pura: che cosa fare con virtual_alias_maps ({@code postconf -h}) e la cartella di Postfix.
     *
     * @param aliasesFile se {@value #ALIASES} esiste: senza, Postfix non e' quello del pannello
     */
    static Decision decide(boolean installed, String configDirectory, String virtualAliasMaps, boolean aliasesFile) {
        return decide(installed, configDirectory, virtualAliasMaps, aliasesFile, true);
    }

    /**
     * Come sopra, sapendo anche se il file della mappa dice gia' il testo atteso ({@link #mapText}): uno diverso (una
     * domanda di prima, una connessione cambiata) si riscrive, con le stesse prove.
     */
    static Decision decide(boolean installed, String configDirectory, String virtualAliasMaps, boolean aliasesFile, boolean fileCurrent) {
        if (!installed) return new Decision(Action.NOTHING, null, "Postfix is not installed");
        if (!aliasesFile) return new Decision(Action.NOTHING, null, "no " + ALIASES + ": not the panel's Postfix");
        String aliases = "mysql:" + configDirectory + "/" + ALIASES, own = "mysql:" + configDirectory + "/" + FILE;
        List<String> t = tables(virtualAliasMaps);
        if (t.equals(List.of(aliases, own)))
            return fileCurrent ? new Decision(Action.NOTHING, null, "already in place")
                    : new Decision(Action.REWRITE, null, FILE + " does not say what the panel writes");
        if (t.equals(List.of(aliases))) return new Decision(Action.ADD, aliases + ", " + own, "virtual_alias_maps has only the aliases");
        return new Decision(Action.LEFT_ALONE, null, "virtual_alias_maps is '" + String.join(", ", t)
                + "', not the panel's: left as it is, and no catch-all can be created");
    }

    /**
     * Il testo della mappa, dalla mappa degli alias: la stessa connessione, la domanda {@link #QUERY}. Null se il
     * file degli alias non ha esattamente una riga query (non e' quello che scrive il pannello).
     */
    static String mapText(String aliasesText) {
        if (aliasesText == null) return null;
        StringBuilder out = new StringBuilder();
        int queries = 0;
        for (String line : aliasesText.split("\n", -1)) {
            if (QUERY_LINE.matcher(line).matches()) {
                queries++;
                out.append("query = ").append(QUERY);
            } else {
                out.append(line);
            }
            out.append('\n');
        }
        if (queries != 1) return null;
        String s = out.toString();
        return s.endsWith("\n\n") ? s.substring(0, s.length() - 1) : s;
    }

    /**
     * Se un catch-all si puo' creare: null se si', altrimenti il perche' (in inglese, per il registro e la pagina, che
     * lo mette dentro un suo testo). Funzione pura sul valore di virtual_alias_maps.
     */
    static String notReady(String configDirectory, String virtualAliasMaps) {
        String aliases = "mysql:" + configDirectory + "/" + ALIASES, own = "mysql:" + configDirectory + "/" + FILE;
        List<String> t = tables(virtualAliasMaps);
        int a = t.indexOf(aliases), o = t.indexOf(own);
        if (o < 0) return "Postfix's virtual_alias_maps does not have " + FILE;
        if (a < 0 || o < a) return "in Postfix's virtual_alias_maps " + FILE + " does not come after " + ALIASES;
        return null;
    }

    /** {@link #notReady(String, String)} su questo server. */
    public static String notReady() {
        if (!Files.isExecutable(Path.of(POSTCONF))) return "Postfix is not installed";
        return notReady(postconf("-h", "config_directory"), postconf("-h", "virtual_alias_maps"));
    }

    public static void ensureAtBoot() {
        try {
            boolean installed = Files.isExecutable(Path.of(POSTCONF));
            String dir = installed ? postconf("-h", "config_directory") : "";
            String maps = installed ? postconf("-h", "virtual_alias_maps") : "";
            boolean aliasesFile = installed && !dir.isEmpty() && Files.isRegularFile(Path.of(dir, ALIASES), LinkOption.NOFOLLOW_LINKS);
            boolean fileCurrent = true;
            if (aliasesFile) {
                Path own = Path.of(dir, FILE);
                String expected = mapText(Files.readString(Path.of(dir, ALIASES), StandardCharsets.UTF_8));
                fileCurrent = expected == null || (Files.isRegularFile(own, LinkOption.NOFOLLOW_LINKS)
                        && expected.equals(Files.readString(own, StandardCharsets.UTF_8)));
            }
            Decision d = decide(installed, dir, maps, aliasesFile, fileCurrent);
            switch (d.action()) {
                case NOTHING -> { return; }
                case LEFT_ALONE -> { LOGGER.warning("[MailboxAddressMap] " + d.reason()); return; }
                case ADD, REWRITE -> add(Path.of(dir), d);
            }
        } catch (Throwable t) {
            LOGGER.warning("[MailboxAddressMap] ensureAtBoot exception: " + t.getMessage());
        }
    }

    private static void add(Path dir, Decision d) throws Exception {
        Path aliases = dir.resolve(ALIASES), file = dir.resolve(FILE), mainCf = dir.resolve("main.cf");
        String text = mapText(Files.readString(aliases, StandardCharsets.UTF_8));
        if (text == null) {
            LOGGER.warning("[MailboxAddressMap] " + aliases + " does not have exactly one query line: left as it is, and no catch-all can be created");
            return;
        }
        if (!Files.isRegularFile(mainCf, LinkOption.NOFOLLOW_LINKS)) {
            LOGGER.warning("[MailboxAddressMap] " + mainCf + " not found: left as it is");
            return;
        }
        byte[] mainBefore = Files.readAllBytes(mainCf);
        PosixFileAttributes mainAttrs = Files.readAttributes(mainCf, PosixFileAttributes.class);
        boolean existed = Files.exists(file, LinkOption.NOFOLLOW_LINKS);
        byte[] fileBefore = existed ? Files.readAllBytes(file) : null;
        PosixFileAttributes fileAttrs = existed ? Files.readAttributes(file, PosixFileAttributes.class) : null;
        boolean checkedBefore = Shell.run(Duration.ofSeconds(60), POSTFIX, "check").success();

        String problem = null;
        try {
            writeLike(file, text, Files.readAttributes(aliases, PosixFileAttributes.class));
            problem = probe(file);
            if (problem == null && d.newValue() != null) {
                Shell.Result r = Shell.run(Duration.ofSeconds(30), POSTCONF, "-e", "virtual_alias_maps = " + d.newValue());
                if (!r.success()) problem = "postconf -e failed (exit " + r.exitCode() + "): " + r.outputTrim();
            }
            if (problem == null && d.newValue() != null) {
                String now = String.join(", ", tables(postconf("-h", "virtual_alias_maps")));
                if (!now.equals(d.newValue())) problem = "virtual_alias_maps is now '" + now + "' instead of '" + d.newValue() + "'";
            }
            if (problem == null) {
                Shell.Result check = Shell.run(Duration.ofSeconds(60), POSTFIX, "check");
                if (checkedBefore && !check.success()) problem = "postfix check failed (exit " + check.exitCode() + "): " + check.outputTrim();
            }
            if (problem == null) {
                Shell.Result reload = Shell.run(Duration.ofSeconds(60), POSTFIX, "reload");
                if (!reload.success()) problem = "postfix reload failed (exit " + reload.exitCode() + "): " + reload.outputTrim();
            }
        } catch (Exception e) {
            problem = e.getClass().getSimpleName() + ": " + e.getMessage();
        }
        if (problem != null) {
            Files.write(mainCf, mainBefore);
            restoreAttributes(mainCf, mainAttrs);
            if (existed) {
                Files.write(file, fileBefore);
                restoreAttributes(file, fileAttrs);
            } else {
                Files.deleteIfExists(file);
            }
            Shell.run(Duration.ofSeconds(60), POSTFIX, "reload");
            LOGGER.warning("[MailboxAddressMap] ROLLED_BACK: " + problem + "; main.cf and " + FILE + " back as they were");
            return;
        }
        LOGGER.info("[MailboxAddressMap] DONE: " + file + (d.newValue() == null ? " rewritten with the panel's text (" + d.reason() + ")"
                : " written and added after the aliases (virtual_alias_maps = " + d.newValue() + ")")
                + ": every mailbox that receives keeps its mail when its domain has a catch-all");
    }

    /**
     * postmap -q su una chiave che non c'e': MySQL risponde vuoto (uscita 1, niente scritto); un errore scrive sempre
     * qualcosa. Poi, se c'e' una casella, la casella risponde se stessa.
     */
    private static String probe(Path file) {
        Shell.Result r = Shell.run(Duration.ofSeconds(30), POSTMAP, "-q", MailDbUsers.PROBE, "mysql:" + file);
        if (!MailDbUsers.postmapAnswered(r)) return "postmap -q fails on " + FILE + " (exit " + r.exitCode() + "): " + r.outputTrim();
        String mailbox = anyMailbox();
        if (mailbox == null) return null;
        Shell.Result m = Shell.run(Duration.ofSeconds(30), POSTMAP, "-q", mailbox, "mysql:" + file);
        if (!m.success() || !m.outputTrim().equals(mailbox))
            return "postmap -q on a mailbox does not answer the mailbox itself (exit " + m.exitCode() + ")";
        return null;
    }

    /** Una casella qualunque, per la prova; null se non ce n'e' o il database non risponde. */
    private static String anyMailbox() {
        try {
            if (org.daemoxcp.mail.Main.mailDatabase == null) return null;
            for (var m : org.daemoxcp.mail.Main.mailDatabase.getAllMailboxes()) if (m.email != null && !m.email.isEmpty()) return m.email;
        } catch (Exception ignored) { }
        return null;
    }

    /** Scrittura atomica, con proprietario, gruppo e permessi di un altro file (la mappa degli alias). */
    private static void writeLike(Path file, String text, PosixFileAttributes like) throws Exception {
        Path tmp = file.resolveSibling("." + file.getFileName() + ".tmp");
        Files.deleteIfExists(tmp);
        Files.writeString(tmp, text, StandardCharsets.UTF_8);
        restoreAttributes(tmp, like);
        Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
    }

    private static void restoreAttributes(Path f, PosixFileAttributes attrs) throws Exception {
        PosixFileAttributeView view = Files.getFileAttributeView(f, PosixFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
        view.setOwner(attrs.owner());
        view.setGroup(attrs.group());
        view.setPermissions(attrs.permissions());
    }

    private static String postconf(String... args) {
        String[] cmd = new String[args.length + 1];
        cmd[0] = POSTCONF;
        System.arraycopy(args, 0, cmd, 1, args.length);
        Shell.Result r = Shell.run(Duration.ofSeconds(15), cmd);
        return r.success() ? r.outputTrim() : "";
    }
}
