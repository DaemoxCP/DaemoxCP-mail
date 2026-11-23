package org.daemoxcp.mail.system;

import org.daemoxcp.mail.integration.SieveGenerator;
import org.daemoxcp.mail.security.RootOnlyPath;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFileAttributes;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Predicate;
import java.util.logging.Logger;
import java.util.stream.Stream;

/**
 * The explicit keep that the panel put at the end of its Sieve rules, removed from the scripts already
 * written (finding 216).
 *
 * Until 2026-11-09 SieveGenerator closed every script with "# Default action" and "keep;". So the message
 * always stayed in the INBOX: "Move" left it in the folder AND in the INBOX, "Forward" without a copy kept
 * one, "Delete" deleted nothing. Now SieveGenerator no longer writes it; here it is removed from the scripts it
 * had already written, in /var/mail/sieve/domain/name/.dovecot.sieve, and they are recompiled with sievec (the
 * folder belongs to root: Dovecot, which delivers as vmail, could not save the compiled file by itself). sievec
 * runs as the sievec user, not as root, and root installs only the compiled file (SieveCompiler, finding 218).
 *
 * Only a panel script is touched: a real file (a link is made by ManageSieve, not by the panel), which starts
 * with one of the two require lines the panel wrote (before and after adding "date") and ends with that exact
 * tail. Only the tail is removed: the rest stays byte for byte, and the result is what SieveGenerator writes
 * now for the same rules. The new file has the owner and permissions of the old one; if sievec rejects it, it
 * goes back to how it was. At the second startup it finds nothing to do. Root reads and writes without
 * following links and only where nobody else can change the path (RootOnlyPath, finding 221).
 */
public final class SieveForcedKeep {

    private static final Logger LOGGER = Logger.getLogger(SieveForcedKeep.class.getName());

    static final Path PANEL_RULES = Path.of("/var/mail/sieve");
    static final String SCRIPT = ".dovecot.sieve";

    /** The require line the panel wrote before adding "date" (same tail, same rest). */
    static final String REQUIRE_WITHOUT_DATE = SieveGenerator.REQUIRE_BEFORE_MAILBOX.replace(", \"date\"];", "];");

    private SieveForcedKeep() {}

    /** The script without the forced keep, or null if it is not a panel script with that tail. Pure function. */
    static String fixed(String script) {
        if (script == null || !script.endsWith(SieveGenerator.OLD_FORCED_KEEP)) return null;
        // The require lines the panel wrote with the forced keep: without date and with date. The current one
        // (with mailbox, finding 229) never had the forced keep.
        if (!script.startsWith(SieveGenerator.REQUIRE_BEFORE_MAILBOX) && !script.startsWith(REQUIRE_WITHOUT_DATE)) return null;
        return script.substring(0, script.length() - SieveGenerator.OLD_FORCED_KEEP.length());
    }

    /** The panel's scripts: root/domain/name/.dovecot.sieve, only real files (Files.walk does not follow links). */
    static List<Path> panelScripts(Path root) {
        List<Path> out = new ArrayList<>();
        if (!Files.isDirectory(root, LinkOption.NOFOLLOW_LINKS)) return out;
        try (Stream<Path> s = Files.walk(root, 3)) {
            s.filter(p -> root.relativize(p).getNameCount() == 3 && p.getFileName().toString().equals(SCRIPT)
                    && Files.isRegularFile(p, LinkOption.NOFOLLOW_LINKS)).sorted().forEach(out::add);
        } catch (IOException e) {
            LOGGER.warning("[SieveForcedKeep] cannot read " + root + ": " + e.getMessage());
        }
        return out;
    }

    /**
     * The result of a pass: how many scripts were fixed, those left as they were because sievec did not accept
     * them, and those not touched because a folder from / to the script can be changed by someone else
     * (RootOnlyPath, finding 221).
     */
    record Outcome(int fixed, List<Path> putBack, List<String> unsafe) {}

    /** A panel script is small: Pigeonhole rejects scripts over 1 MB. */
    static final int MAX_SCRIPT = 1 << 20;

    /**
     * Removes the tail from every panel script under root and recompiles it with compile (true if sievec
     * accepted it). If compile says no, the script goes back to how it was and that one is recompiled. Root reads
     * and writes without following links, and only where nobody else can change the path.
     */
    static Outcome repair(Path root, Predicate<Path> compile) throws IOException {
        int done = 0;
        List<Path> putBack = new ArrayList<>();
        List<String> unsafe = new ArrayList<>();
        for (Path script : panelScripts(root)) {
            String why = RootOnlyPath.problem(script.getParent());
            if (why != null) {
                unsafe.add(script + ": " + why);
                continue;
            }
            PosixFileAttributes like = Files.readAttributes(script, PosixFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
            String before = new String(RootOnlyPath.read(script, MAX_SCRIPT), StandardCharsets.UTF_8);
            String after = fixed(before);
            if (after == null) continue;
            replace(script, after, like);
            if (compile.test(script)) {
                done++;
            } else {
                replace(script, before, like);
                compile.test(script);
                putBack.add(script);
            }
        }
        return new Outcome(done, putBack, unsafe);
    }

    /**
     * Rewrites the file in one go (a new file beside it with the previous owner, group and permissions, then
     * rename): whoever delivers does not see it half written, and a link in its place is not followed.
     */
    private static void replace(Path script, String content, PosixFileAttributes like) throws IOException {
        RootOnlyPath.replace(script.getParent(), SCRIPT, content.getBytes(StandardCharsets.UTF_8), like.owner(), like.group(),
                like.permissions());
    }

    /** At the start of the root part. */
    public static void ensureAtBoot() {
        try {
            SieveGenerator compiler = new SieveGenerator();
            Outcome o = repair(PANEL_RULES, p -> compiler.compileScript(p.toString()));
            if (o.fixed() > 0)
                LOGGER.info("[SieveForcedKeep] DONE: " + o.fixed() + " Sieve script(s) of the panel without the forced keep at"
                        + " the end, recompiled: move, forward without a copy and delete now do what they say");
            for (Path p : o.putBack())
                LOGGER.warning("[SieveForcedKeep] LEFT AS IT WAS: sievec refuses " + p + " without the forced keep");
            for (String u : o.unsafe())
                LOGGER.warning("[SieveForcedKeep] LEFT AS IT WAS, root does not write where others can change the path: " + u);
        } catch (Throwable t) {
            LOGGER.warning("[SieveForcedKeep] failed: " + t);
        }
    }
}
