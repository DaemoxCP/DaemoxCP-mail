package org.daemoxcp.mail.system;

import org.daemoxcp.mail.util.Shell;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFileAttributes;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;

/**
 * Whoever authenticates sends only from their own addresses.
 *
 * <p>Measured on the VM on 2026-11-20, a clean install from the README: Postfix had no smtpd_sender_login_maps,
 * so a mailbox authenticated on 587 (or from the webmail) could set any address as sender: another mailbox of
 * the same server, which Rspamd then signed with the domain's DKIM key, or anybody else's address. The Postfix
 * documentation (SASL_README, "Envelope sender address authorization"; postconf(5),
 * reject_authenticated_sender_login_mismatch) closes it with a table of the owners of the addresses: an
 * authenticated client whose name does not own the MAIL FROM address is rejected (553 5.7.1). An address that
 * has no owners, for example one of another domain, is owned by nobody: rejected as well.
 *
 * <p>The table (scripts.PostfixMaps): a mailbox owns its address, and an alias belongs to its destination;
 * Postfix looks up name@domain and then @domain, so a catch-all gives its mailbox the addresses of the domain
 * that are neither mailboxes nor aliases, the same ones whose mail it receives. It uses the same connection as
 * the aliases map (Postfix's user, MailDbUsers: it already has the columns it reads).
 *
 * <p>The check applies only to whoever authenticates (reject_authenticated_..., not
 * reject_sender_login_mismatch): the mail arriving from other servers on 25, the system mail (sendmail, without
 * smtpd) and Sieve's automatic replies and forwards do not change. It sits on the submission ports, 587 and 465
 * (-o smtpd_sender_restrictions in master.cf), at the top, before permit_mynetworks: the webmail sends from
 * 127.0.0.1, authenticated, on 587, and it must apply to it too. Not in main.cf: since 2026-11-20 port 25 no
 * longer offers authentication (PostfixSubmissionAuth) and there Postfix, for every incoming message, wrote
 * "restriction `reject_authenticated_sender_login_mismatch' ignored: no SASL support" (production server,
 * 20 November after build 816).
 *
 * <p>The installers write it themselves; on servers installed earlier {@link #ensureAtBoot()} writes it, after
 * MailDbUsers and MailboxAddressMap: the file with the owner, group and permissions of the aliases map,
 * postmap -q (a key that does not exist answers empty, a mailbox answers itself), the settings only if they say
 * what the panel writes or used to write (a hand-written configuration stays as it is), postfix check and
 * reload. Whoever had the check in main.cf (builds 795-818) sees it moved to the submission ports. If a test
 * does not add up, main.cf, master.cf and the file go back to how they were byte for byte and Postfix reloads.
 * At the second startup it does nothing.
 */
public final class SenderLoginMap {

    private static final Logger LOGGER = Logger.getLogger(SenderLoginMap.class.getName());

    public static final String FILE = org.daemoxcp.mail.scripts.PostfixMaps.SENDER_LOGIN_FILE;
    public static final String QUERY = org.daemoxcp.mail.scripts.PostfixMaps.SENDER_LOGIN_QUERY;
    public static final String CHECK = "reject_authenticated_sender_login_mismatch";
    /** smtpd_sender_restrictions in main.cf, as the installers write it (and wrote it before the check). */
    static final List<String> PANEL_SENDER = List.of("permit_mynetworks", "permit_sasl_authenticated",
            "reject_non_fqdn_sender", "reject_unknown_sender_domain");
    /**
     * On the submission ports, in master.cf: the same, with the check in front (in main.cf from build 795 to
     * 818).
     */
    static final List<String> WANTED_SENDER = MailboxAddressMap.tables(org.daemoxcp.mail.scripts.PostfixMaps.SUBMISSION_SENDER_RESTRICTIONS);
    /** The master.cf services on which clients authenticate: submission (587) and smtps (465). */
    static final List<String> SUBMISSION_SERVICES = List.of("submission/inet", "smtps/inet");

    private SenderLoginMap() {}

    enum Action { NOTHING, APPLY, LEFT_ALONE }

    record Decision(Action action, String reason) {}

    /**
     * Pure function: what to do, from smtpd_sender_login_maps and smtpd_sender_restrictions of main.cf ({@code postconf
     * -h}) and of submission and smtps in master.cf ({@code postconf -Ph}; empty if master.cf does not set it).
     *
     * @param aliasesFile whether the panel's aliases map exists: without it, Postfix is not the panel's
     * @param fileCurrent whether the table file already says the expected text
     */
    static Decision decide(boolean installed, String configDirectory, boolean aliasesFile, boolean fileCurrent,
                           String loginMaps, String senderRestrictions, String submission, String smtps) {
        if (!installed) return new Decision(Action.NOTHING, "Postfix is not installed");
        if (!aliasesFile) return new Decision(Action.NOTHING, "no " + MailboxAddressMap.ALIASES + ": not the panel's Postfix");
        String own = "mysql:" + configDirectory + "/" + FILE;
        List<String> maps = MailboxAddressMap.tables(loginMaps), main = MailboxAddressMap.tables(senderRestrictions);
        List<String> sub = MailboxAddressMap.tables(submission), ssl = MailboxAddressMap.tables(smtps);
        boolean mapsOurs = maps.equals(List.of(own));
        boolean portsOurs = sub.equals(WANTED_SENDER) && ssl.equals(WANTED_SENDER);
        if (mapsOurs && main.equals(PANEL_SENDER) && portsOurs)
            return fileCurrent ? new Decision(Action.NOTHING, "already in place") : new Decision(Action.APPLY, FILE + " does not say what the panel writes");
        boolean portsFree = (sub.isEmpty() || sub.equals(WANTED_SENDER)) && (ssl.isEmpty() || ssl.equals(WANTED_SENDER));
        if ((maps.isEmpty() || mapsOurs) && portsFree) {
            if (main.equals(WANTED_SENDER))
                return new Decision(Action.APPLY, "the check was in main.cf, so on port 25 too, where nobody signs in and Postfix"
                        + " logged «ignored: no SASL support» for every incoming message: moved to the submission ports");
            if (main.equals(PANEL_SENDER)) return new Decision(Action.APPLY, "no sender ownership check");
        }
        return new Decision(Action.LEFT_ALONE, "smtpd_sender_login_maps is '" + String.join(", ", maps)
                + "', smtpd_sender_restrictions '" + String.join(", ", main) + "' (submission: '" + String.join(", ", sub)
                + "', smtps: '" + String.join(", ", ssl) + "'), not the panel's: left as they are, and authenticated clients"
                + " can still send from any address");
    }

    /** smtpd_sender_restrictions of a master.cf service; empty if master.cf does not set it. */
    static String masterSetting(String service) {
        Shell.Result r = Shell.run(Duration.ofSeconds(15), MailboxAddressMap.POSTCONF, "-Ph", service + "/smtpd_sender_restrictions");
        return masterValue(r.success() ? r.outputTrim() : "");
    }

    /**
     * The output of postconf -Ph: "postconf: warning: unmatched request" (on stderr, merged here) means not set.
     * The name in front is the one postconf was launched with: from the panel "/usr/local/sbin/postconf:" (measured
     * on the VM on 2026-11-21: with only "postconf: " the repair took the warning for a hand-written value).
     */
    static String masterValue(String out) {
        StringBuilder b = new StringBuilder();
        for (String line : out.split("\n")) if (!POSTCONF_MESSAGE.matcher(line).lookingAt()) b.append(line).append('\n');
        return b.toString().trim();
    }

    private static final java.util.regex.Pattern POSTCONF_MESSAGE = java.util.regex.Pattern.compile("\\S*postconf: ");

    public static void ensureAtBoot() {
        try {
            boolean installed = Files.isExecutable(Path.of(MailboxAddressMap.POSTCONF));
            String dir = installed ? MailboxAddressMap.postconf("-h", "config_directory") : "";
            boolean aliasesFile = installed && !dir.isEmpty()
                    && Files.isRegularFile(Path.of(dir, MailboxAddressMap.ALIASES), LinkOption.NOFOLLOW_LINKS);
            boolean fileCurrent = true;
            if (aliasesFile) {
                String expected = MailboxAddressMap.mapText(Files.readString(Path.of(dir, MailboxAddressMap.ALIASES), StandardCharsets.UTF_8), QUERY);
                Path own = Path.of(dir, FILE);
                fileCurrent = expected != null && Files.isRegularFile(own, LinkOption.NOFOLLOW_LINKS)
                        && expected.equals(Files.readString(own, StandardCharsets.UTF_8));
            }
            Decision d = decide(installed, dir, aliasesFile, fileCurrent,
                    installed ? MailboxAddressMap.postconf("-h", "smtpd_sender_login_maps") : "",
                    installed ? MailboxAddressMap.postconf("-h", "smtpd_sender_restrictions") : "",
                    installed ? masterSetting(SUBMISSION_SERVICES.get(0)) : "",
                    installed ? masterSetting(SUBMISSION_SERVICES.get(1)) : "");
            switch (d.action()) {
                case NOTHING -> { return; }
                case LEFT_ALONE -> { LOGGER.warning("[SenderLoginMap] " + d.reason()); return; }
                case APPLY -> apply(Path.of(dir), d);
            }
        } catch (Throwable t) {
            LOGGER.warning("[SenderLoginMap] ensureAtBoot exception: " + t.getMessage());
        }
    }

    private static void apply(Path dir, Decision d) throws Exception {
        Path aliases = dir.resolve(MailboxAddressMap.ALIASES), file = dir.resolve(FILE), mainCf = dir.resolve("main.cf"),
                masterCf = dir.resolve("master.cf");
        String text = MailboxAddressMap.mapText(Files.readString(aliases, StandardCharsets.UTF_8), QUERY);
        if (text == null) {
            LOGGER.warning("[SenderLoginMap] " + aliases + " does not have exactly one query line: left as it is");
            return;
        }
        if (!Files.isRegularFile(mainCf, LinkOption.NOFOLLOW_LINKS) || !Files.isRegularFile(masterCf, LinkOption.NOFOLLOW_LINKS)) {
            LOGGER.warning("[SenderLoginMap] " + mainCf + " or " + masterCf + " not found: left as they are");
            return;
        }
        if (!Shell.run(Duration.ofSeconds(15), "service", "postfix", "status").success()) {
            LOGGER.info("[SenderLoginMap] Postfix is not running: sender check left as it is, retrying at the next start");
            return;
        }
        byte[] mainBefore = Files.readAllBytes(mainCf), masterBefore = Files.readAllBytes(masterCf);
        PosixFileAttributes mainAttrs = Files.readAttributes(mainCf, PosixFileAttributes.class);
        PosixFileAttributes masterAttrs = Files.readAttributes(masterCf, PosixFileAttributes.class);
        boolean existed = Files.exists(file, LinkOption.NOFOLLOW_LINKS);
        byte[] fileBefore = existed ? Files.readAllBytes(file) : null;
        PosixFileAttributes fileAttrs = existed ? Files.readAttributes(file, PosixFileAttributes.class) : null;
        boolean checkedBefore = Shell.run(Duration.ofSeconds(60), MailboxAddressMap.POSTFIX, "check").success();
        String own = "mysql:" + dir + "/" + FILE;

        String problem = null;
        try {
            MailboxAddressMap.writeLike(file, text, Files.readAttributes(aliases, PosixFileAttributes.class));
            problem = probe(file);
            if (problem == null) problem = set("smtpd_sender_login_maps", own);
            // First the submission ports, then main.cf: at no moment is whoever authenticates left unchecked.
            for (String service : SUBMISSION_SERVICES) if (problem == null) problem = setMaster(service);
            if (problem == null) problem = set("smtpd_sender_restrictions", String.join(", ", PANEL_SENDER));
            if (problem == null) {
                Shell.Result check = Shell.run(Duration.ofSeconds(60), MailboxAddressMap.POSTFIX, "check");
                if (checkedBefore && !check.success()) problem = "postfix check failed (exit " + check.exitCode() + "): " + check.outputTrim();
            }
            if (problem == null) {
                Shell.Result reload = Shell.run(Duration.ofSeconds(60), MailboxAddressMap.POSTFIX, "reload");
                if (!reload.success()) problem = "postfix reload failed (exit " + reload.exitCode() + "): " + reload.outputTrim();
            }
        } catch (Exception e) {
            problem = e.getClass().getSimpleName() + ": " + e.getMessage();
        }
        if (problem != null) {
            Files.write(mainCf, mainBefore);
            MailboxAddressMap.restoreAttributes(mainCf, mainAttrs);
            Files.write(masterCf, masterBefore);
            MailboxAddressMap.restoreAttributes(masterCf, masterAttrs);
            if (existed) {
                Files.write(file, fileBefore);
                MailboxAddressMap.restoreAttributes(file, fileAttrs);
            } else {
                Files.deleteIfExists(file);
            }
            Shell.run(Duration.ofSeconds(60), MailboxAddressMap.POSTFIX, "reload");
            LOGGER.warning("[SenderLoginMap] ROLLED_BACK: " + problem + "; main.cf, master.cf and " + FILE + " back as they were");
            return;
        }
        LOGGER.info("[SenderLoginMap] DONE: an authenticated client sends only from its own addresses (its mailbox, the"
                + " aliases that point to it): " + file + ", " + CHECK + " first in smtpd_sender_restrictions of the"
                + " submission ports 587 and 465, not on port 25 (" + d.reason() + ")");
    }

    /** postconf -P for a master.cf service and the re-read: it must say the list with the check in front. */
    private static String setMaster(String service) {
        String name = service + "/smtpd_sender_restrictions";
        String value = String.join(",", WANTED_SENDER);
        Shell.Result r = Shell.run(Duration.ofSeconds(30), MailboxAddressMap.POSTCONF, "-P", name + "=" + value);
        if (!r.success()) return "postconf -P " + name + " failed (exit " + r.exitCode() + "): " + r.outputTrim();
        List<String> now = MailboxAddressMap.tables(masterSetting(service));
        return now.equals(WANTED_SENDER) ? null : name + " is now '" + String.join(", ", now) + "' instead of '" + value + "'";
    }

    /** postconf -e and the re-read: the value must be the one written. Null if so. */
    private static String set(String name, String value) {
        Shell.Result r = Shell.run(Duration.ofSeconds(30), MailboxAddressMap.POSTCONF, "-e", name + " = " + value);
        if (!r.success()) return "postconf -e " + name + " failed (exit " + r.exitCode() + "): " + r.outputTrim();
        String now = String.join(", ", MailboxAddressMap.tables(MailboxAddressMap.postconf("-h", name)));
        String want = String.join(", ", MailboxAddressMap.tables(value));
        return now.equals(want) ? null : name + " is now '" + now + "' instead of '" + want + "'";
    }

    /** A key that does not exist answers empty; a mailbox answers itself (among its owners). */
    private static String probe(Path file) {
        Shell.Result r = Shell.run(Duration.ofSeconds(30), MailboxAddressMap.POSTMAP, "-q", MailDbUsers.PROBE, "mysql:" + file);
        if (!MailDbUsers.postmapAnswered(r)) return "postmap -q fails on " + FILE + " (exit " + r.exitCode() + "): " + r.outputTrim();
        String mailbox = MailboxAddressMap.anyMailbox();
        if (mailbox == null) return null;
        Shell.Result m = Shell.run(Duration.ofSeconds(30), MailboxAddressMap.POSTMAP, "-q", mailbox, "mysql:" + file);
        List<String> owners = new ArrayList<>(MailboxAddressMap.tables(m.outputTrim()));
        if (!m.success() || !owners.contains(mailbox))
            return "postmap -q on a mailbox does not answer the mailbox itself (exit " + m.exitCode() + ")";
        return null;
    }
}
