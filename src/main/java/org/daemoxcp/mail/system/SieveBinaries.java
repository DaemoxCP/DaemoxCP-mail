package org.daemoxcp.mail.system;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;

/**
 * The panel's Sieve rules compiled by the Pigeonhole that is installed now (finding 241).
 *
 * <p>The compiled file (.svbin) beside each panel rule is made by the panel with sievec (SieveCompiler, finding
 * 218): Dovecot delivers as vmail and cannot write it in root's folder. When Pigeonhole changes format, as in the
 * switch from 2.3 to 2.4 (header 02 versus 03, measured on the VM), the previous compiled file is no longer
 * valid: Dovecot recompiles the rule in memory for every message, the mail arrives and the rules work, but for
 * every message it writes two errors in the log ("binary ... save: failed to create temporary file", "The LDA
 * Sieve plugin does not have permission to save global Sieve script binaries"). The text of the rules does not
 * change, so SieveRulesRefresh did not rewrite anything, and neither the switch to Dovecot 2.4 nor the panel
 * restart noticed it.
 *
 * <p>Here every panel rule (/var/mail/sieve/domain/name/.dovecot.sieve that starts with the panel's require
 * lines: a hand-made script stays as it is) is compiled with the installed sievec, and the compiled file is
 * replaced only if it is different. The compiled file is deterministic (measured: two 2.4.5 compilations equal
 * byte for byte), so the second time round nothing is written. It is done at the start of the root part after
 * SieveRulesRefresh; in the switch to Dovecot 2.4 as soon as 2.4 has started; and again if the switch goes back
 * to 2.3. The folders are walked without following links; compiling and writing is SieveCompiler (sievec as the
 * sievec user, RootOnlyPath). In the log only the counts, never the addresses.
 */
public final class SieveBinaries {

    private static final Logger LOGGER = Logger.getLogger(SieveBinaries.class.getName());

    private SieveBinaries() {}

    static final Path ROOT = Path.of("/var/mail/sieve");
    static final String SCRIPT = ".dovecot.sieve";
    /** A panel rules file is small: a bigger one is not the panel's. */
    static final long MAX_SCRIPT = 64 << 10;

    /** What is needed, to test it without sievec or /var/mail. */
    interface Compiler {
        /** The panel's rules; empty if Pigeonhole is not there. */
        List<Path> scripts() throws IOException;
        /** Compiles and replaces the compiled file only if it is different (SieveCompiler.refresh). */
        SieveCompiler.Outcome refresh(Path script);
    }

    /** How many recompiled, how many already right, and the state of those that did not compile. */
    public record Result(int recompiled, int unchanged, List<String> failed) {}

    /** Pure with respect to {@link Compiler}. */
    static Result run(Compiler c) {
        List<Path> scripts;
        try {
            scripts = c.scripts();
        } catch (IOException e) {
            return new Result(0, 0, List.of("the rules could not be listed: " + e.getClass().getSimpleName()));
        }
        int recompiled = 0, unchanged = 0;
        List<String> failed = new ArrayList<>();
        for (Path s : scripts) {
            SieveCompiler.Outcome o = c.refresh(s);
            switch (o.status()) {
                case COMPILED -> recompiled++;
                case UNCHANGED -> unchanged++;
                default -> failed.add(o.status().name().toLowerCase());
            }
        }
        return new Result(recompiled, unchanged, failed);
    }

    /** The panel's rules on the server, with the installed sievec. */
    public static Result refreshNow() {
        return run(real());
    }

    /** At the start of the root part, after SieveRulesRefresh. */
    public static void ensureAtBoot() {
        try {
            Result r = refreshNow();
            if (r.recompiled() > 0)
                LOGGER.info("[SieveBinaries] DONE: " + r.recompiled() + " Sieve rule file(s) of the panel compiled again by the"
                        + " Pigeonhole installed now (the compiled ones were of another version: Dovecot compiled them again at"
                        + " every message and logged errors); " + r.unchanged() + " already right");
            if (!r.failed().isEmpty())
                LOGGER.warning("[SieveBinaries] " + r.failed().size() + " Sieve rule file(s) of the panel not compiled ("
                        + String.join(", ", r.failed()) + "): Dovecot compiles them at every message");
        } catch (Throwable t) {
            LOGGER.warning("[SieveBinaries] failed: " + t);
        }
    }

    // ===================== The production server =====================

    static Compiler real() {
        return new Compiler() {
            @Override public List<Path> scripts() throws IOException {
                if (SieveCompiler.sievec() == null) return List.of();
                return panelScripts(ROOT);
            }
            @Override public SieveCompiler.Outcome refresh(Path script) {
                return SieveCompiler.refresh(script);
            }
        };
    }

    /** domain/name/.dovecot.sieve under root, without following links, only those the panel has written. */
    static List<Path> panelScripts(Path root) throws IOException {
        List<Path> out = new ArrayList<>();
        if (!Files.isDirectory(root, LinkOption.NOFOLLOW_LINKS)) return out;
        try (DirectoryStream<Path> domains = Files.newDirectoryStream(root)) {
            for (Path d : domains) {
                if (!Files.isDirectory(d, LinkOption.NOFOLLOW_LINKS)) continue;
                try (DirectoryStream<Path> names = Files.newDirectoryStream(d)) {
                    for (Path n : names) {
                        if (!Files.isDirectory(n, LinkOption.NOFOLLOW_LINKS)) continue;
                        Path s = n.resolve(SCRIPT);
                        if (!Files.isRegularFile(s, LinkOption.NOFOLLOW_LINKS) || Files.size(s) > MAX_SCRIPT) continue;
                        if (SieveRulesRefresh.panelScript(Files.readString(s, StandardCharsets.UTF_8))) out.add(s);
                    }
                }
            }
        }
        out.sort(null);
        return out;
    }
}
