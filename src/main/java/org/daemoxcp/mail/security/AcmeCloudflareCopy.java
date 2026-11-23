package org.daemoxcp.mail.security;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFileAttributes;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The plaintext copy of the Cloudflare token that acme.sh keeps for itself: removed.
 *
 * When the challenge goes through Cloudflare (dns_cf), acme.sh saves the token it receives (SAVED_CF_Token, and
 * SAVED_CF_Account_ID) in its account.conf, for the renewals it would do on its own. But acme.sh renews nothing on
 * its own: its cron is removed by AcmeUser, and every issuance and renewal is launched by the panel, which passes it
 * the token every time (CF_Token, decrypted from MySQL: CloudflareTokens). That copy was only useful to whoever found
 * it: a token that writes the DNS of all the zones of the account, in plaintext on disk. Seen on the production
 * server on 2026-11-17, in /var/db/acme/.acme.sh/account.conf, after the one in the database had been encrypted.
 *
 * Only the SAVED_CF_ lines are removed; the rest of the file stays as it was, with owner and permissions, written
 * alongside and renamed into place. An account.conf that is a link, or a file with several names, is left alone
 * and reported.
 */
public final class AcmeCloudflareCopy {

    private static final Logger LOGGER = Logger.getLogger(AcmeCloudflareCopy.class.getName());

    /** A line of account.conf with a copy saved by the Cloudflare module. */
    static final Pattern SAVED = Pattern.compile("(?m)^SAVED_CF_([A-Za-z_]+)=.*(?:\\r?\\n|$)");

    enum Outcome { NOTHING, DONE, LEFT }

    record Report(Outcome outcome, String detail) {}

    private AcmeCloudflareCopy() {}

    static Report forget(Path accountConf) throws IOException {
        if (!Files.exists(accountConf, LinkOption.NOFOLLOW_LINKS)) return new Report(Outcome.NOTHING, "");
        if (!SafeOwnership.safeToChange(accountConf) || Files.isDirectory(accountConf, LinkOption.NOFOLLOW_LINKS))
            return new Report(Outcome.LEFT, accountConf + " is a link or has more than one name: left as it is");
        String text = Files.readString(accountConf, StandardCharsets.UTF_8);
        Matcher m = SAVED.matcher(text);
        List<String> keys = new ArrayList<>();
        while (m.find()) keys.add("SAVED_CF_" + m.group(1));
        if (keys.isEmpty()) return new Report(Outcome.NOTHING, "");
        Path next = accountConf.resolveSibling("." + accountConf.getFileName() + ".panel-new");
        try {
            Files.deleteIfExists(next);
            Files.writeString(next, SAVED.matcher(text).replaceAll(""), StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
            PosixFileAttributes a = Files.readAttributes(accountConf, PosixFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
            PosixFileAttributeView v = Files.getFileAttributeView(next, PosixFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
            v.setPermissions(a.permissions());
            v.setOwner(a.owner());
            v.setGroup(a.group());
            Files.move(next, accountConf, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        } finally {
            Files.deleteIfExists(next);
        }
        return new Report(Outcome.DONE, accountConf + ": removed " + keys);
    }

    /** After every acme.sh run to which the panel passed the token. */
    static void afterRun(AcmeUser.Layout l) {
        if (l != null) report(Path.of(l.home(), "account.conf"));
    }

    /** At startup: the copies written before this version. */
    public static void ensureAtBoot() {
        AcmeUser.Layout l = AcmeUser.layout();
        if (l != null) report(Path.of(l.home(), "account.conf"));
    }

    private static void report(Path accountConf) {
        try {
            Report r = forget(accountConf);
            if (r.outcome() == Outcome.NOTHING) return;
            String line = "[AcmeCloudflareCopy] " + r.outcome() + ": " + r.detail();
            if (r.outcome() == Outcome.DONE) LOGGER.info(line); else LOGGER.warning(line);
        } catch (Throwable t) {
            LOGGER.warning("[AcmeCloudflareCopy] " + accountConf + ": " + t);
        }
    }
}
