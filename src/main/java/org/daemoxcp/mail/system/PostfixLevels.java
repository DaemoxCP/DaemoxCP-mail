package org.daemoxcp.mail.system;

import java.util.ArrayList;
import java.util.List;

/**
 * The Postfix compatibility levels the panel has examined, and what changes at each one.
 *
 * Since 3.0, when a default value changes in an incompatible way, Postfix does not apply it as long as
 * compatibility_level stays below the level that introduces it: it is its safety net. Moving up a level means
 * accepting the new values of the parameters left at their default. That is why the panel moves up only to a
 * level listed here, where each one comes with the list of what changes: Diagnostics reads it
 * (UpdateManager.postfixCompatibility) to say what would change, and the installation (PostfixLevelScript) to
 * move up to the level the installed Postfix asks for. A new level, not yet here, is not taken blindly.
 *
 * Each entry: level, key of the text that describes it, parameters that change. "name@gate=value": the parameter
 * counts only if the gate has that value (the TLS-RPT report applies only with smtp_tlsrpt_enable = yes).
 *
 * Source: Postfix's COMPATIBILITY_README, read on 2026-09-01 on postfix.org and on 2026-11-16 in the 3.11.7
 * package on the VM, together with `postconf -d`, where the defaults that depend on the level read as
 * "${{$compatibility_level} <level {N} ? {old} : {new}}" (PostfixLevelTest compares them with this list).
 * smtpd_relay_before_recipient_restrictions (3.6) was missing: the description mentioned it, the list did not.
 */
public final class PostfixLevels {

    private PostfixLevels() {}

    static final String[][] ALL = {
        {"1", "server.um.maskCredentials.1",
         "append_dot_mydomain smtpd_relay_restrictions smtputf8_enable"},
        {"2", "server.um.maskCredentials.2",
         "mynetworks_style relay_domains"},
        {"3.6", "server.um.maskCredentials.3",
         "smtpd_tls_fingerprint_digest smtp_tls_fingerprint_digest lmtp_tls_fingerprint_digest respectful_logging "
         + "smtpd_relay_before_recipient_restrictions"},
        {"3.11", "server.um.maskCredentials.4",
         "smtp_tlsrpt_skip_reused_handshakes@smtp_tlsrpt_enable=yes smtp_tls_security_level"},
    };

    /** The levels examined, from the lowest. */
    public static List<String> reviewed() {
        List<String> out = new ArrayList<>();
        for (String[] l : ALL) out.add(l[0]);
        return out;
    }

    /** The parameters that change at that level (with the "@gate=value", if any), or an empty list. */
    public static List<String> parameters(String level) {
        for (String[] l : ALL)
            if (l[0].equals(level)) return List.of(l[2].trim().split("\\s+"));
        return List.of();
    }
}
