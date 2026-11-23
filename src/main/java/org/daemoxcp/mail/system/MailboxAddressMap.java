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
 * The Postfix map that makes the catch-all safe: every mailbox points to itself, after the aliases.
 *
 * <p>A catch-all is an alias with source {@code @domain} (aliases table). Postfix looks up an address in the
 * virtual_alias_maps first in the form {@code name@domain}, in all the tables and in their order, and only
 * afterwards in the form {@code @domain}. With the aliases table alone, mail for a mailbox that has no alias of its
 * own would end up at the catch-all: the mailbox would no longer receive anything, and a mailbox as destination of
 * the catch-all would loop endlessly. With this map after the aliases:
 * <ul>
 *   <li>an explicit alias still wins (it comes first): copies and forwards stay as they are;</li>
 *   <li>a mailbox that receives finds itself, and its mail goes to it;</li>
 *   <li>only an address that is neither an alias nor a receiving mailbox reaches {@code @domain}: this includes a
 *       mailbox that is disabled or does not receive, whose mail without a catch-all is rejected.</li>
 * </ul>
 * Only the mailboxes that receive, with the same condition as virtual_mailbox_maps: Postfix takes as valid every
 * address it finds in the virtual_alias_maps, and with all the mailboxes a mailbox that does not receive would have
 * accepted mail from outside even without a catch-all (measured on the VM on 2026-11-18). So, without a catch-all,
 * nothing changes: an address that points to itself is what Postfix already does.
 *
 * <p>The map uses the same connection as {@value #ALIASES} (the Postfix user, MailDbUsers: SELECT on
 * mailboxes.email is already there) and its query (scripts.PostfixMaps). New installations write it on their own;
 * on servers installed before, {@link #ensureAtBoot()} writes it, after MailDbUsers:
 * <ol>
 *   <li>the file, with the owner, group and permissions of {@value #ALIASES};</li>
 *   <li>postmap -q: a key that does not exist answers empty, a mailbox answers itself;</li>
 *   <li>virtual_alias_maps with the map after the aliases, only if it said exactly the panel's aliases map (a
 *       configuration written by hand stays as it is, and the catch-all is not created);</li>
 *   <li>postfix check and reload. If a test does not match, main.cf goes back as it was byte for byte, the new
 *       file is removed, and Postfix is reloaded.</li>
 * </ol>
 * At the second startup it does nothing.
 */
public final class MailboxAddressMap {

    private static final Logger LOGGER = Logger.getLogger(MailboxAddressMap.class.getName());

    static final String POSTCONF = "/usr/local/sbin/postconf";
    static final String POSTFIX = "/usr/local/sbin/postfix";
    static final String POSTMAP = "/usr/local/sbin/postmap";

    /** The panel's aliases map. */
    static final String ALIASES = "mysql-virtual-aliases.cf";
    /** This map. */
    public static final String FILE = org.daemoxcp.mail.scripts.PostfixMaps.MAILBOX_ADDRESSES_FILE;
    /** Every mailbox, active or not, is itself: so a catch-all does not take its mail. */
    public static final String QUERY = org.daemoxcp.mail.scripts.PostfixMaps.MAILBOX_ADDRESSES_QUERY;

    private static final Pattern QUERY_LINE = Pattern.compile("^\\s*query\\s*=.*$");
    private static final Pattern SEPARATORS = Pattern.compile("[\\s,]+");

    private MailboxAddressMap() {}

    enum Action { NOTHING, ADD, REWRITE, LEFT_ALONE }

    record Decision(Action action, String newValue, String reason) {}

    /** The tables of virtual_alias_maps, in order. */
    static List<String> tables(String value) {
        List<String> l = new ArrayList<>();
        if (value == null) return l;
        for (String s : SEPARATORS.split(value.trim())) if (!s.isEmpty()) l.add(s);
        return l;
    }

    /**
     * Pure function: what to do with virtual_alias_maps ({@code postconf -h}) and the Postfix folder.
     *
     * @param aliasesFile whether {@value #ALIASES} exists: without it, Postfix is not the panel's
     */
    static Decision decide(boolean installed, String configDirectory, String virtualAliasMaps, boolean aliasesFile) {
        return decide(installed, configDirectory, virtualAliasMaps, aliasesFile, true);
    }

    /**
     * As above, also knowing whether the map file already says the expected text ({@link #mapText}): a different one
     * (an earlier query, a changed connection) is rewritten, with the same tests.
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
     * The map text, from the aliases map: the same connection, the query {@link #QUERY}. Null if the aliases file does
     * not have exactly one query line (it is not the one the panel writes).
     */
    static String mapText(String aliasesText) {
        return mapText(aliasesText, QUERY);
    }

    /** The same with another query: the connection of the aliases map (SenderLoginMap). */
    static String mapText(String aliasesText, String query) {
        if (aliasesText == null) return null;
        StringBuilder out = new StringBuilder();
        int queries = 0;
        for (String line : aliasesText.split("\n", -1)) {
            if (QUERY_LINE.matcher(line).matches()) {
                queries++;
                out.append("query = ").append(query);
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
     * Whether a catch-all can be created: null if yes, otherwise the reason (in English, for the log and the page,
     * which puts it inside a text of its own). Pure function on the value of virtual_alias_maps.
     */
    static String notReady(String configDirectory, String virtualAliasMaps) {
        String aliases = "mysql:" + configDirectory + "/" + ALIASES, own = "mysql:" + configDirectory + "/" + FILE;
        List<String> t = tables(virtualAliasMaps);
        int a = t.indexOf(aliases), o = t.indexOf(own);
        if (o < 0) return "Postfix's virtual_alias_maps does not have " + FILE;
        if (a < 0 || o < a) return "in Postfix's virtual_alias_maps " + FILE + " does not come after " + ALIASES;
        return null;
    }

    /** {@link #notReady(String, String)} on this server. */
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
     * postmap -q on a key that does not exist: MySQL answers empty (exit 1, nothing written); an error always writes
     * something. Then, if there is a mailbox, the mailbox answers itself.
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

    /** Any mailbox, for the test; null if there is none or the database does not answer. */
    static String anyMailbox() {
        try {
            if (org.daemoxcp.mail.Main.mailDatabase == null) return null;
            for (var m : org.daemoxcp.mail.Main.mailDatabase.getAllMailboxes()) if (m.email != null && !m.email.isEmpty()) return m.email;
        } catch (Exception ignored) { }
        return null;
    }

    /** Atomic write, with the owner, group and permissions of another file (the aliases map). */
    static void writeLike(Path file, String text, PosixFileAttributes like) throws Exception {
        Path tmp = file.resolveSibling("." + file.getFileName() + ".tmp");
        Files.deleteIfExists(tmp);
        Files.writeString(tmp, text, StandardCharsets.UTF_8);
        restoreAttributes(tmp, like);
        Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
    }

    static void restoreAttributes(Path f, PosixFileAttributes attrs) throws Exception {
        PosixFileAttributeView view = Files.getFileAttributeView(f, PosixFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
        view.setOwner(attrs.owner());
        view.setGroup(attrs.group());
        view.setPermissions(attrs.permissions());
    }

    static String postconf(String... args) {
        String[] cmd = new String[args.length + 1];
        cmd[0] = POSTCONF;
        System.arraycopy(args, 0, cmd, 1, args.length);
        Shell.Result r = Shell.run(Duration.ofSeconds(15), cmd);
        return r.success() ? r.outputTrim() : "";
    }
}
