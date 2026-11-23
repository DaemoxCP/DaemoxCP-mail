package org.daemoxcp.mail.system;

import org.daemoxcp.mail.scripts.DovecotConfig;
import org.daemoxcp.mail.util.Shell;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;
import java.util.stream.Stream;

/**
 * The user's Sieve scripts in their mail folder, and the panel's rules before them, on servers installed
 * earlier (finding 214). The new configuration is written by DovecotConfig (SIEVE23, SIEVE24): here only the
 * Sieve block that the panel itself had written, identical line by line, is changed in conf.d/10-master.conf.
 *
 * Before: the panel's rules and the user's scripts were the same file, /var/mail/sieve/domain/name, owned by
 * root. ManageSieve, the webmail "Filters" and doveadm sieve could not save anything ("mkdir_parents_chgrp(...)
 * failed: Permission denied"). After: the panel's rules stay there, owned by root, and run first; the user's
 * scripts are in ~/sieve, already owned by vmail. No permission is widened.
 *
 * Before touching anything: if in /var/mail/sieve there is already an active script made by ManageSieve (a
 * link, which the panel never writes), someone made it work by hand, and it is left as it is. After: doveconf
 * must accept the file, Dovecot must reload, and doveadm sieve list must really open the scripts of a mailbox;
 * if a single thing does not add up, the file goes back to how it was and Dovecot reloads. At the second
 * startup it finds nothing to do.
 */
public final class SieveStorage {

    private static final Logger LOGGER = Logger.getLogger(SieveStorage.class.getName());

    static final Path MASTER_CONF = Path.of("/usr/local/etc/dovecot/conf.d/10-master.conf");
    static final Path PANEL_RULES = Path.of("/var/mail/sieve");
    static final Path VMAIL = Path.of("/var/vmail");
    static final String DOVECONF = "/usr/local/bin/doveconf";
    static final String DOVEADM = "/usr/local/bin/doveadm";

    /** The 2.3 block, inside plugin {}, as the panel wrote it. */
    static final String OLD23 = "  sieve = /var/mail/sieve/%d/%n/.dovecot.sieve\n"
                              + "  sieve_dir = /var/mail/sieve/%d/%n/\n";

    /** The 2.4 block as the panel wrote it. */
    static final String OLD24 = "sieve_script personal {\n"
                              + "  type = personal\n"
                              + "  driver = file\n"
                              + "  path = /var/mail/sieve/%{user | domain}/%{user | username}\n"
                              + "  active_path = /var/mail/sieve/%{user | domain}/%{user | username}/.dovecot.sieve\n"
                              + "}\n";

    private SieveStorage() {}

    /**
     * conf.d/10-master.conf with the new Sieve block, or null if there is nothing to change: already done, or
     * the block is not the one the panel wrote (then it is not the panel's, and it stays as it is). Pure function.
     */
    static String migrated(String conf) {
        if (conf == null) return null;
        if (count(conf, OLD23) == 1) return conf.replace(OLD23, DovecotConfig.SIEVE23.stripTrailing() + "\n");
        if (count(conf, OLD24) == 1) return conf.replace(OLD24, DovecotConfig.SIEVE24);
        return null;
    }

    private static int count(String s, String part) {
        int n = 0;
        for (int i = s.indexOf(part); i >= 0; i = s.indexOf(part, i + part.length())) n++;
        return n;
    }

    /** The .dovecot.sieve links under /var/mail/sieve: ManageSieve makes them, the panel writes only files. */
    static List<Path> manageSieveLinks(Path root) {
        List<Path> out = new ArrayList<>();
        if (!Files.isDirectory(root, LinkOption.NOFOLLOW_LINKS)) return out;
        try (Stream<Path> s = Files.walk(root, 3)) {
            s.filter(p -> p.getFileName().toString().equals(".dovecot.sieve") && Files.isSymbolicLink(p)).forEach(out::add);
        } catch (IOException e) {
            LOGGER.warning("[SieveStorage] cannot read " + root + ": " + e.getMessage());
        }
        return out;
    }

    /** A mailbox to test on: the first /var/vmail/domain/name folder, as an address; null if there is none. */
    static String someMailbox(Path vmail) {
        if (!Files.isDirectory(vmail)) return null;
        try (Stream<Path> domains = Files.list(vmail)) {
            for (Path d : domains.sorted().toList()) {
                if (!Files.isDirectory(d, LinkOption.NOFOLLOW_LINKS)) continue;
                try (Stream<Path> users = Files.list(d)) {
                    for (Path u : users.sorted().toList()) {
                        String a = u.getFileName() + "@" + d.getFileName();
                        if (Files.isDirectory(u, LinkOption.NOFOLLOW_LINKS) && MailProbes.MAILBOX.matcher(a).matches()) return a;
                    }
                }
            }
        } catch (IOException e) {
            return null;
        }
        return null;
    }

    /** At the start of the root part. */
    public static void ensureAtBoot() {
        try {
            String problem = ensure();
            if (problem != null) LOGGER.warning("[SieveStorage] " + problem);
        } catch (Throwable t) {
            LOGGER.warning("[SieveStorage] failed: " + t);
        }
    }

    /** Null if there was nothing to do or if it is done; otherwise why it stayed as it was. */
    static synchronized String ensure() throws Exception {
        if (!Files.isRegularFile(MASTER_CONF, LinkOption.NOFOLLOW_LINKS) || !Files.isExecutable(Path.of(DOVECONF))) return null;
        String current = Files.readString(MASTER_CONF, StandardCharsets.UTF_8);
        String next = migrated(current);
        if (next == null) return null;
        List<Path> links = manageSieveLinks(PANEL_RULES);
        if (!links.isEmpty())
            return "left as it is: " + links.get(0) + " is a ManageSieve link, so scripts were made to work there by hand";
        Path tmp = MASTER_CONF.resolveSibling(".10-master.conf.sieve");
        Files.copy(MASTER_CONF, tmp, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.COPY_ATTRIBUTES);
        Files.writeString(tmp, next, StandardCharsets.UTF_8);
        Files.move(tmp, MASTER_CONF, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        if (!Shell.run(Duration.ofSeconds(15), DOVECONF, "-n").success())
            return putBack(current, "doveconf refuses the new Sieve settings");
        boolean running = Shell.run(Duration.ofSeconds(15), "service", "dovecot", "status").success();
        if (running) {
            if (!Shell.run(Duration.ofSeconds(60), "service", "dovecot", "reload").success())
                return putBack(current, "Dovecot did not reload");
            String mailbox = someMailbox(VMAIL);
            if (mailbox != null) {
                Shell.Result list = Shell.run(Duration.ofSeconds(30), DOVEADM, "sieve", "list", "-u", mailbox);
                if (!list.success() || list.outputTrim().contains("Error"))
                    return putBack(current, "doveadm sieve list -u " + mailbox + " still fails: " + first(list.outputTrim()));
            }
        }
        LOGGER.info("[SieveStorage] DONE: users' Sieve scripts (ManageSieve, the webmail's filters) in their mail folder,"
                + " the panel's rules run before them" + (running ? "; Dovecot reloaded" : "; Dovecot not running, it reads it at the start"));
        return null;
    }

    private static String putBack(String before, String why) throws IOException {
        Files.writeString(MASTER_CONF, before, StandardCharsets.UTF_8);
        if (Shell.run(Duration.ofSeconds(15), "service", "dovecot", "status").success())
            Shell.run(Duration.ofSeconds(60), "service", "dovecot", "reload");
        return "ROLLED_BACK: " + why + "; " + MASTER_CONF + " put back as it was";
    }

    private static String first(String s) {
        int i = s.indexOf('\n');
        String t = i < 0 ? s : s.substring(0, i);
        return t.length() > 200 ? t.substring(0, 200) : t;
    }
}
