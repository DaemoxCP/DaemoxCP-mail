package org.daemoxcp.mail.system;

import org.daemoxcp.mail.util.Shell;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.logging.Logger;

/**
 * DANE per la posta in uscita: smtp_tls_security_level = dane e smtp_dns_support_level = dnssec.
 *
 * Prima Postfix spediva con TLS opportunistico (may): cifrato se il server di destinazione lo offre, ma senza controllare
 * di chi fosse il certificato, e un attaccante sulla strada poteva togliere STARTTLS o presentarne uno suo. Con DANE
 * (RFC 7672, il TLS_README di Postfix), se il dominio di destinazione pubblica record TLSA firmati DNSSEC, Postfix
 * pretende TLS e un certificato che corrisponda; dove non ci sono, resta come prima (may). Gmail e Outlook non
 * pubblicano TLSA: per loro non cambia niente.
 *
 * Serve un risolutore che convalidi DNSSEC sulla macchina stessa: local_unbound, che il pannello configura (la sola
 * cosa di cui Postfix si fida e' il flag AD di un risolutore su 127.0.0.1). Misurato il 20/11/2026: sulla VM e sul server
 * vero /etc/resolv.conf dice nameserver 127.0.0.1, local_unbound risponde con il flag ad, e posttls-finger con
 * smtp_dns_support_level = dnssec cerca i TLSA degli MX di ietf.org, posteo.de e mailbox.org (Postfix li cerca solo
 * dopo MX e indirizzi convalidati). Un risolutore che non convalida farebbe solo tornare tutto a may; ma un risolutore
 * che non e' locale no: qui non si cambia niente.
 *
 * L'installatore lo scrive in main.cf; sui server installati prima lo fa questa riparazione all'avvio, solo se i due
 * valori sono quelli dell'installatore di prima (may e il predefinito): un valore scritto a mano resta. postconf -e,
 * postfix check, reload, e la verifica: i due valori letti da Postfix, Postfix acceso, il risolutore che convalida
 * ancora. Se qualcosa non torna rimette i valori di prima. Al secondo avvio non fa niente.
 */
public final class PostfixDane {

    private static final Logger LOGGER = Logger.getLogger(PostfixDane.class.getName());

    public static final String LEVEL = "smtp_tls_security_level";
    public static final String DNS = "smtp_dns_support_level";
    static final String POSTCONF = PostfixVrfy.POSTCONF;

    private PostfixDane() {}

    enum Action { NOTHING, APPLY, LEFT_ALONE, NO_RESOLVER }

    /**
     * Che cosa fare. level, dns: i valori di Postfix (postconf -h); localResolver: il primo nameserver di
     * /etc/resolv.conf e' 127.0.0.1 o ::1; validates: quel risolutore convalida DNSSEC. Funzione pura.
     */
    static Action decide(String level, String dns, boolean localResolver, boolean validates) {
        String l = level == null ? "" : level.trim(), d = dns == null ? "" : dns.trim();
        if (l.equals("dane") && d.equals("dnssec")) return Action.NOTHING;
        if (!(l.equals("may") || l.isEmpty()) || !(d.isEmpty() || d.equals("enabled"))) return Action.LEFT_ALONE;
        return localResolver && validates ? Action.APPLY : Action.NO_RESOLVER;
    }

    /** Il primo nameserver di resolv.conf e' la macchina stessa. Funzione pura. */
    static boolean localResolver(String resolvConf) {
        if (resolvConf == null) return false;
        for (String line : resolvConf.split("\n")) {
            String[] f = line.trim().split("\\s+");
            if (f.length >= 2 && f[0].equals("nameserver")) return f[1].equals("127.0.0.1") || f[1].equals("::1");
        }
        return false;
    }

    /** L'uscita di drill -D dice che la risposta e' convalidata: il flag ad. Funzione pura. */
    static boolean authenticated(String drill) {
        if (drill == null) return false;
        for (String line : drill.split("\n"))
            if (line.startsWith(";; flags:")) return (" " + line.substring(9).split(";")[0] + " ").contains(" ad ");
        return false;
    }

    /** Il risolutore della macchina convalida: la radice (sempre firmata) torna col flag ad. */
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
