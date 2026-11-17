package org.daemoxcp.mail.system;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.time.ZoneId;
import java.util.regex.Pattern;

/**
 * Il fuso orario del sistema, scelto da chi installa (reperto 242).
 *
 * <p>La voce 1 del menu copiava sempre Europe/Rome in /etc/localtime: andava bene per il server di chi ha scritto il
 * pannello, non per chiunque altro. Adesso il menu chiede il fuso, proponendo quello che il sistema ha gia'
 * (/var/db/zoneinfo, scritto da tzsetup), e lo script lo riceve come argomento. Il nome si controlla due volte, qui e
 * nello script: identificatore IANA (lettere, cifre, _ + -, segmenti separati da /, quindi niente «..»), conosciuto da
 * Java e presente in /usr/share/zoneinfo come file normale.
 *
 * <p>Per le date dei dati il pannello usa UTC comunque (r13): il fuso del sistema e' quello che si legge nei registri
 * e nell'ora del server.
 */
public final class SystemTimeZone {

    private SystemTimeZone() {}

    static final Path ZONEINFO = Path.of("/usr/share/zoneinfo");
    static final Path CURRENT = Path.of("/var/db/zoneinfo");
    static final Pattern NAME = Pattern.compile("^[A-Za-z0-9_+-]{1,32}(/[A-Za-z0-9_+-]{1,32}){0,3}$");

    /** Il fuso che il sistema ha adesso, o UTC se non si sa. */
    public static String current() {
        return current(CURRENT);
    }

    static String current(Path file) {
        try {
            if (Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS) && Files.size(file) < 256) {
                String s = Files.readString(file, StandardCharsets.US_ASCII).trim();
                if (NAME.matcher(s).matches()) return s;
            }
        } catch (IOException ignored) {
            // si propone UTC
        }
        return "UTC";
    }

    /** Null se il fuso si puo' usare; altrimenti perche' no, da mostrare a chi lo ha scritto. */
    public static String problem(String name) {
        return problem(name, ZONEINFO);
    }

    static String problem(String name, Path zoneinfo) {
        if (name == null || name.isBlank()) return "Write a time zone, for example Europe/Rome or UTC.";
        if (!NAME.matcher(name).matches())
            return "\"" + printable(name) + "\" is not a time zone name: letters, digits, _ + - and / only, like Europe/Rome.";
        if (!ZoneId.getAvailableZoneIds().contains(name))
            return "\"" + name + "\" is not a known time zone. Examples: Europe/Rome, Europe/London, America/New_York, UTC.";
        if (!Files.isRegularFile(zoneinfo.resolve(name), LinkOption.NOFOLLOW_LINKS))
            return "\"" + name + "\" is not in " + zoneinfo + " on this system.";
        return null;
    }

    private static String printable(String s) {
        StringBuilder b = new StringBuilder();
        for (char c : s.toCharArray()) {
            if (b.length() >= 40) { b.append('…'); break; }
            b.append(c >= 0x20 && c <= 0x7e ? c : '?');
        }
        return b.toString();
    }
}
