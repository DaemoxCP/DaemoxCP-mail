package org.mail_panel.system;

import java.util.ArrayList;
import java.util.List;

/**
 * I livelli di compatibilita' di Postfix esaminati dal pannello, e cosa cambia a ognuno.
 *
 * Dalla 3.0, quando cambia un valore predefinito in modo incompatibile, Postfix non lo applica finche'
 * compatibility_level resta sotto il livello che lo introduce: e' la sua rete di sicurezza. Salire di livello
 * significa accettare i valori nuovi dei parametri lasciati al predefinito. Per questo il pannello sale solo a un
 * livello che sta qui, dove per ognuno c'e' l'elenco di quello che cambia: lo legge la Diagnostica
 * (UpdateManager.postfixCompatibility) per dire cosa cambierebbe, e l'installazione (PostfixLevelScript) per salire al
 * livello che il Postfix installato chiede. Un livello nuovo, non ancora qui, non si prende alla cieca.
 *
 * Ogni voce: livello, chiave del testo che lo descrive, parametri che cambiano. "nome@gate=valore": il parametro conta
 * solo se il gate ha quel valore (il resoconto TLS-RPT vale solo con smtp_tlsrpt_enable = yes).
 *
 * Fonte: COMPATIBILITY_README di Postfix, letto il 01/09/2026 su postfix.org e il 16/11/2026 nel pacchetto 3.11.7
 * sulla VM, insieme a `postconf -d`, dove i predefiniti che dipendono dal livello si leggono come
 * "${{$compatibility_level} <level {N} ? {vecchio} : {nuovo}}" (PostfixLevelTest li confronta con questo elenco).
 * smtpd_relay_before_recipient_restrictions (3.6) mancava: la descrizione lo diceva, l'elenco no.
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

    /** I livelli esaminati, dal piu' basso. */
    public static List<String> reviewed() {
        List<String> out = new ArrayList<>();
        for (String[] l : ALL) out.add(l[0]);
        return out;
    }

    /** I parametri che cambiano a quel livello (con l'eventuale "@gate=valore"), o un elenco vuoto. */
    public static List<String> parameters(String level) {
        for (String[] l : ALL)
            if (l[0].equals(level)) return List.of(l[2].trim().split("\\s+"));
        return List.of();
    }
}
