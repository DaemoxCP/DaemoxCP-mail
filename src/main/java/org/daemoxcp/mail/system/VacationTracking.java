package org.daemoxcp.mail.system;

import org.daemoxcp.mail.integration.SieveGenerator;
import org.daemoxcp.mail.security.SafeNames;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Predicate;
import java.util.logging.Logger;

/**
 * The memory of a mailbox's automatic replies, and how to reset it without breaking anything (finding 219).
 *
 * <p>Pigeonhole remembers whom it has already answered in Dovecot's duplicate database, the .dovecot.lda-dupes file in
 * the mailbox home. The Pigeonhole documentation (2.3, "Sieve Usage", on the automatic reply): "List of
 * autoreplied senders is stored in '.dovecot.lda-dupes' file in user's home directory", and to try again "try
 * deleting this file". To reset it, removing that file is enough:
 * <ul>
 *   <li>the compiled .dovecot.svbin next to the panel's rules is the script's code, it knows nothing about the
 *       replies sent. Until 2026-11-10 the reset removed it "to force recompilation", but the folder belongs to
 *       root (finding 214) and Dovecot, which delivers as vmail, cannot save it: from then on every delivery to that
 *       mailbox recompiled the rules and wrote to the maillog "Error: sieve: binary ...: save: failed to create
 *       temporary file ... Permission denied (euid=5000(vmail))", until the panel saved the rules again (measured on
 *       the VM on 2026-11-10). The rules do not change: recompiling them is pointless;</li>
 *   <li>Dovecot does not keep the memory in memory: LMTP rereads it from the file at every delivery. The reset ran
 *       {@code service dovecot restart}, which stops and restarts all of Dovecot (main process, authentication, LMTP,
 *       the IMAP listener), and it was not needed: right after the reset, without a restart, the next delivery gets
 *       the reply again (measured). An IMAP session already logged in at the restart survived (Dovecot 2.3.21,
 *       measured);</li>
 *   <li>.dovecot.sieve.db, which the reset removed in /var/mail/sieve, is neither written nor read by anyone: no
 *       library of Dovecot 2.3.21 and Pigeonhole 0.5.21 contains that name (measured), .dovecot.lda-dupes does.</li>
 * </ul>
 *
 * <p>The mailbox comes from MySQL, where the web part of the separated panel also writes, and root turns it into a
 * path: it must have the shape of an address, and the file must stay under /var/vmail (as in
 * SieveGenerator.saveSieveScript).
 *
 * <p>At boot {@link #ensureAtBoot()} restores the compiled file for the panel's rules that lack it, or whose compiled
 * file is older than the script: that is what the previous reset left behind.
 */
public final class VacationTracking {

    private static final Logger LOGGER = Logger.getLogger(VacationTracking.class.getName());

    /**
     * The root of the mailboxes. The Dovecot home of each one is its home/ folder (home=/var/vmail/%d/%n/home,
     * finding 217, DovecotHome); before, it was the root itself.
     */
    static final Path HOMES = Path.of("/var/vmail");
    /** Dovecot's duplicate database, where Pigeonhole remembers the automatic replies it has sent. */
    public static final String DUPLICATES = ".dovecot.lda-dupes";

    static final Path PANEL_RULES = Path.of("/var/mail/sieve");
    static final String BINARY = ".dovecot.svbin";

    private VacationTracking() {}

    /**
     * Resets the memory of the mailbox's automatic replies: the next delivery from a sender already answered
     * gets the reply again. It does not touch the rules or the compiled file, and does not restart Dovecot. False if
     * the address does not have the shape of an address.
     */
    public static boolean reset(String email) throws IOException {
        return reset(HOMES, email);
    }

    static boolean reset(Path homes, String email) throws IOException {
        Path duplicates = duplicatesOf(homes, email);
        if (duplicates == null) return false;
        Files.deleteIfExists(duplicates);
        // Before finding 217 the memory was in the mailbox root: if DovecotHome has not moved it into the
        // home yet (or Dovecot rewrote it there before the migration), that one is removed too.
        Files.deleteIfExists(duplicates.getParent().resolveSibling(DUPLICATES));
        return true;
    }

    /** homes/domain/name/home/.dovecot.lda-dupes, or null if the address is not an address. Pure. */
    static Path duplicatesOf(Path homes, String email) {
        if (!SafeNames.address(email)) return null;
        int at = email.indexOf('@');
        return SafeNames.under(homes, email.substring(at + 1), email.substring(0, at), DovecotHome.DIR, DUPLICATES);
    }

    // ===================== At boot: the compiled file that the previous reset removed =====================

    /** True if next to the script there is no real compiled file that is strictly newer, as Pigeonhole wants it. */
    static boolean stale(Path script) throws IOException {
        Path binary = script.resolveSibling(BINARY);
        if (!Files.isRegularFile(binary, LinkOption.NOFOLLOW_LINKS)) return true;
        FileTime b = Files.getLastModifiedTime(binary, LinkOption.NOFOLLOW_LINKS);
        FileTime s = Files.getLastModifiedTime(script, LinkOption.NOFOLLOW_LINKS);
        return b.compareTo(s) <= 0;
    }

    /** The result of a run: the scripts recompiled, and those that could not be recompiled. */
    record Outcome(List<Path> compiled, List<Path> notCompiled) {}

    /**
     * Recompiles with compile (true if the compiled file is in place) every panel rule under root without a newer
     * compiled file. The others are not touched: on the second run there is nothing to do.
     */
    static Outcome repair(Path root, Predicate<Path> compile) throws IOException {
        List<Path> compiled = new ArrayList<>(), notCompiled = new ArrayList<>();
        for (Path script : SieveForcedKeep.panelScripts(root)) {
            if (!stale(script)) continue;
            if (compile.test(script) && !stale(script)) compiled.add(script);
            else notCompiled.add(script);
        }
        return new Outcome(compiled, notCompiled);
    }

    /** At the boot of the root part, after SieveForcedKeep (which already recompiles what changes). */
    public static void ensureAtBoot() {
        try {
            if (SieveCompiler.sievec() == null) return;
            SieveGenerator compiler = new SieveGenerator();
            Outcome o = repair(PANEL_RULES, p -> compiler.compileScript(p.toString()));
            if (!o.compiled().isEmpty())
                LOGGER.info("[VacationTracking] DONE: " + o.compiled().size() + " Sieve script(s) of the panel compiled again:"
                        + " their binary was missing or older, and Dovecot compiled them at each delivery");
            for (Path p : o.notCompiled())
                LOGGER.warning("[VacationTracking] NOT COMPILED: " + p + " (Dovecot compiles it at each delivery)");
        } catch (Throwable t) {
            LOGGER.warning("[VacationTracking] failed: " + t);
        }
    }
}
