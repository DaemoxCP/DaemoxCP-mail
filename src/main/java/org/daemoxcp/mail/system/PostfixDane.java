package org.daemoxcp.mail.system;

import org.daemoxcp.mail.util.Shell;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.logging.Logger;

/**
 * DANE for outgoing mail: smtp_tls_security_level = dane and smtp_dns_support_level = dnssec.
 *
 * Before, Postfix sent with opportunistic TLS (may): encrypted if the destination server offers it, but without
 * checking whose certificate it was, and an attacker on the path could strip STARTTLS or present one of their own.
 * With DANE (RFC 7672, Postfix's TLS_README), if the destination domain publishes DNSSEC-signed TLSA records,
 * Postfix requires TLS and a matching certificate; where there are none, it stays as before (may). Gmail and
 * Outlook do not publish TLSA: for them nothing changes.
 *
 * It needs a resolver that validates DNSSEC on the machine itself: local_unbound, which the panel configures (the
 * only thing Postfix trusts is the AD flag of a resolver on 127.0.0.1). Measured on 2026-11-20: on the VM and on
 * the production server /etc/resolv.conf says nameserver 127.0.0.1, local_unbound answers with the ad flag, and
 * posttls-finger with smtp_dns_support_level = dnssec looks up the TLSA of the MXs of ietf.org, posteo.de and
 * mailbox.org (Postfix looks them up only after validated MX and addresses). A resolver that does not validate
 * would only make everything fall back to may; a resolver that is not local is another matter: then nothing is
 * changed here.
 *
 * The installer writes it into main.cf; on the servers installed earlier this boot repair does it, only if the
 * two values are those of the earlier installer (may and the default): a value written by hand stays.
 * postconf -e, postfix check, reload, and the verification: the two values as read by Postfix, Postfix running,
 * the resolver still validating. If something does not add up it puts the previous values back. On the second
 * startup it does nothing.
 */
public final class PostfixDane {

    private static final Logger LOGGER = Logger.getLogger(PostfixDane.class.getName());

    public static final String LEVEL = "smtp_tls_security_level";
    public static final String DNS = "smtp_dns_support_level";
    static final String POSTCONF = PostfixVrfy.POSTCONF;

    private PostfixDane() {}

    enum Action { NOTHING, APPLY, LEFT_ALONE, NO_RESOLVER }

    /**
     * What to do. level, dns: Postfix's values (postconf -h); localResolver: the first nameserver of
     * /etc/resolv.conf is 127.0.0.1 or ::1; validates: that resolver validates DNSSEC. Pure function.
     */
    static Action decide(String level, String dns, boolean localResolver, boolean validates) {
        String l = level == null ? "" : level.trim(), d = dns == null ? "" : dns.trim();
        if (l.equals("dane") && d.equals("dnssec")) return Action.NOTHING;
        if (!(l.equals("may") || l.isEmpty()) || !(d.isEmpty() || d.equals("enabled"))) return Action.LEFT_ALONE;
        return localResolver && validates ? Action.APPLY : Action.NO_RESOLVER;
    }

    /** The first nameserver in resolv.conf is the machine itself. Pure function. */
    static boolean localResolver(String resolvConf) {
        if (resolvConf == null) return false;
        for (String line : resolvConf.split("\n")) {
            String[] f = line.trim().split("\\s+");
            if (f.length >= 2 && f[0].equals("nameserver")) return f[1].equals("127.0.0.1") || f[1].equals("::1");
        }
        return false;
    }

    /** The output of drill -D says that the answer is validated: the ad flag. Pure function. */
    static boolean authenticated(String drill) {
        if (drill == null) return false;
        for (String line : drill.split("\n"))
            if (line.startsWith(";; flags:")) return (" " + line.substring(9).split(";")[0] + " ").contains(" ad ");
        return false;
    }

    /** The machine's resolver validates: the root (always signed) comes back with the ad flag. */
    static boolean validates() {
        return authenticated(Shell.run(Duration.ofSeconds(20), "drill", "-D", ".", "DNSKEY", "@127.0.0.1").output());
    }

    public static void ensureAtBoot() {
        try {
            if (!Files.isExecutable(Path.of(POSTCONF))) return;
            Shell.Result level = Shell.run(Duration.ofSeconds(15), POSTCONF, "-h", LEVEL);
            Shell.Result dns = Shell.run(Duration.ofSeconds(15), POSTCONF, "-h", DNS);
            if (!level.success() || !dns.success()) return;
            Path resolv = Path.of("/etc/resolv.conf");
            boolean local = Files.isRegularFile(resolv) && localResolver(Files.readString(resolv, StandardCharsets.UTF_8));
            Action a = decide(level.outputTrim(), dns.outputTrim(), local, local && validates());
            switch (a) {
                case NOTHING -> { }
                case LEFT_ALONE -> LOGGER.info("[PostfixDane] " + LEVEL + " = " + level.outputTrim() + ", " + DNS + " = "
                        + dns.outputTrim() + " were set by hand: left as they are");
                case NO_RESOLVER -> LOGGER.info("[PostfixDane] DANE for outgoing mail needs a DNSSEC-validating resolver on this"
                        + " machine (local_unbound, 127.0.0.1 first in /etc/resolv.conf): left as it is");
                case APPLY -> apply(level.outputTrim(), dns.outputTrim());
            }
        } catch (Throwable t) {
            LOGGER.warning("[PostfixDane] ensureAtBoot exception: " + t.getMessage());
        }
    }

    static void apply(String levelBefore, String dnsBefore) {
        if (!Shell.run(Duration.ofSeconds(15), "service", "postfix", "status").success()) {
            LOGGER.info("[PostfixDane] Postfix is not running: DANE left as it is, retrying at the next start");
            return;
        }
        boolean levelExplicit = explicit(LEVEL), dnsExplicit = explicit(DNS);
        Shell.Result set = Shell.run(Duration.ofSeconds(30), POSTCONF, "-e", DNS + "=dnssec", LEVEL + "=dane");
        Shell.Result check = Shell.run(Duration.ofSeconds(60), "postfix", "check");
        if (!set.success() || !check.success()) {
            putBack(levelExplicit, levelBefore, dnsExplicit, dnsBefore, false);
            LOGGER.warning("[PostfixDane] ROLLED_BACK: " + (set.success() ? "postfix check: " + check.outputTrim() : set.outputTrim()));
            return;
        }
        Shell.run(Duration.ofSeconds(30), "postfix", "reload");
        String problem = null;
        if (!"dane".equals(Shell.run(Duration.ofSeconds(15), POSTCONF, "-h", LEVEL).outputTrim())
                || !"dnssec".equals(Shell.run(Duration.ofSeconds(15), POSTCONF, "-h", DNS).outputTrim())) problem = "Postfix does not read the new values";
        else if (!Shell.run(Duration.ofSeconds(15), "service", "postfix", "status").success()) problem = "Postfix is not running after the reload";
        else if (!validates()) problem = "the local resolver no longer validates DNSSEC";
        if (problem != null) {
            putBack(levelExplicit, levelBefore, dnsExplicit, dnsBefore, true);
            LOGGER.warning("[PostfixDane] ROLLED_BACK: " + problem + "; the values of before put back");
            return;
        }
        LOGGER.info("[PostfixDane] DONE: outgoing mail checks DANE (" + LEVEL + " = dane, " + DNS + " = dnssec): where the"
                + " destination publishes DNSSEC-signed TLSA records, TLS and a matching certificate are required; elsewhere"
                + " TLS stays opportunistic, as before");
    }

    private static boolean explicit(String setting) {
        return Shell.run(Duration.ofSeconds(15), POSTCONF, "-n", setting).outputTrim().startsWith(setting);
    }

    private static void putBack(boolean levelExplicit, String levelBefore, boolean dnsExplicit, String dnsBefore, boolean reload) {
        if (levelExplicit) Shell.run(Duration.ofSeconds(30), POSTCONF, "-e", LEVEL + "=" + levelBefore);
        else Shell.run(Duration.ofSeconds(30), POSTCONF, "-X", LEVEL);
        if (dnsExplicit) Shell.run(Duration.ofSeconds(30), POSTCONF, "-e", DNS + "=" + dnsBefore);
        else Shell.run(Duration.ofSeconds(30), POSTCONF, "-X", DNS);
        if (reload) Shell.run(Duration.ofSeconds(30), "postfix", "reload");
    }
}
