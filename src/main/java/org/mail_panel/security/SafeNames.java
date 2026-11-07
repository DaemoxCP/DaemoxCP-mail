package org.mail_panel.security;

import java.nio.file.Path;
import java.util.regex.Pattern;

/**
 * I nomi che la parte root legge da MySQL prima di metterli in un comando, in un percorso o in un file di
 * configurazione.
 *
 * <p>Col pannello separato MySQL lo scrive anche la parte web, che ha l'utente MySQL del pannello. Quello
 * che vi legge la root non e' quindi piu' un dato suo: chi bucasse la parte web potrebbe scrivere un dominio
 * come {@code x; comando} e aspettare che la root lo metta in uno script di shell (lo faceva
 * ConfigRegeneratorScript), o una casella come {@code ..} e farle scrivere un file fuori dalla sua cartella
 * (lo faceva SieveGenerator). Il pannello controlla questi nomi quando li riceve da una pagina, ma la root
 * non deve contare su chi li ha scritti: li ricontrolla qui, nel punto in cui li usa, e un nome che non
 * passa non si usa.
 *
 * <p>Le forme sono strette apposta: lettere, cifre e pochi segni, mai una barra, mai un carattere che la
 * shell o un file di configurazione legge in modo speciale.
 */
public final class SafeNames {

    private SafeNames() {}

    /** Un dominio: etichette di lettere, cifre e trattini, separate da punti (RFC 1035 e RFC 5890 per xn--). */
    private static final Pattern DOMAIN = Pattern.compile(
            "(?=.{3,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\\.)+[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?");
    /**
     * La parte prima della @ di una casella: i caratteri che SecurityUtils accetta per un indirizzo, senza il
     * punto all'inizio e senza due punti di fila, cosi' non e' mai {@code .} o {@code ..} in un percorso.
     */
    private static final Pattern LOCAL_PART = Pattern.compile("[A-Za-z0-9_%+-](?:[A-Za-z0-9._%+-]{0,63})");
    /** Un selettore DKIM come quelli che genera il pannello (mail, r20261107, r20261107-2). */
    private static final Pattern SELECTOR = Pattern.compile("[A-Za-z0-9](?:[A-Za-z0-9_-]{0,62})");

    public static boolean domain(String s) {
        return s != null && DOMAIN.matcher(s).matches();
    }

    public static boolean localPart(String s) {
        return s != null && LOCAL_PART.matcher(s).matches() && !s.contains("..") && !s.endsWith(".");
    }

    /** Un indirizzo completo: una parte locale valida, una sola @, un dominio valido. */
    public static boolean address(String s) {
        if (s == null) return false;
        int at = s.indexOf('@');
        return at > 0 && at == s.lastIndexOf('@') && localPart(s.substring(0, at)) && domain(s.substring(at + 1));
    }

    public static boolean selector(String s) {
        return s != null && SELECTOR.matcher(s).matches();
    }

    /**
     * Un percorso dentro una cartella: i pezzi si aggiungono alla base e il risultato, normalizzato, deve
     * restare sotto la base. Un pezzo con una barra, {@code ..} o vuoto non passa nemmeno da qui.
     *
     * @throws IllegalArgumentException se il percorso uscirebbe dalla base
     */
    public static Path under(Path base, String... parts) {
        Path b = base.normalize();
        Path p = b;
        for (String part : parts) {
            if (part == null || part.isEmpty() || part.contains("/") || part.equals(".") || part.equals(".."))
                throw new IllegalArgumentException("invalid path piece");
            p = p.resolve(part);
        }
        p = p.normalize();
        if (!p.startsWith(b) || p.equals(b)) throw new IllegalArgumentException("path outside " + b);
        return p;
    }
}
