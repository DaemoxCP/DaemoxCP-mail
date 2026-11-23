package org.daemoxcp.mail.system;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.time.ZoneId;
import java.util.regex.Pattern;

/**
 * The system time zone, chosen by whoever installs (finding 242).
 *
 * <p>Menu option 1 always copied Europe/Rome into /etc/localtime: that was fine for the server of the person who
 * wrote the panel, not for anyone else. Now the menu asks for the time zone, proposing the one the system already
 * has (/var/db/zoneinfo, written by tzsetup), and the script receives it as an argument. The name is checked twice,
 * here and in the script: an IANA identifier (letters, digits, _ + -, segments separated by /, hence no ".."),
 * known to Java and present in /usr/share/zoneinfo as a regular file.
 *
 * <p>For the dates in the data the panel uses UTC anyway (r13): the system time zone is the one you read in the
 * logs and in the server's clock.
 */
public final class SystemTimeZone {

    private SystemTimeZone() {}

    static final Path ZONEINFO = Path.of("/usr/share/zoneinfo");
    static final Path CURRENT = Path.of("/var/db/zoneinfo");
    static final Pattern NAME = Pattern.compile("^[A-Za-z0-9_+-]{1,32}(/[A-Za-z0-9_+-]{1,32}){0,3}$");

    /** The time zone the system has now, or UTC if it is not known. */
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
            // UTC is proposed
        }
        return "UTC";
    }

    /** Null if the time zone can be used; otherwise why not, to be shown to whoever entered it. */
    public static String problem(String name) {
        return problem(name, ZONEINFO);
    }

    static String problem(String name, Path zoneinfo) {
        if (name == null || name.isBlank()) return org.daemoxcp.mail.i18n.I18n.tr("console.tz.empty");
        if (!NAME.matcher(name).matches())
            return org.daemoxcp.mail.i18n.I18n.tr("console.tz.badName", java.util.Map.of("name", printable(name)));
        if (!ZoneId.getAvailableZoneIds().contains(name))
            return org.daemoxcp.mail.i18n.I18n.tr("console.tz.unknown", java.util.Map.of("name", name));
        if (!Files.isRegularFile(zoneinfo.resolve(name), LinkOption.NOFOLLOW_LINKS))
            return org.daemoxcp.mail.i18n.I18n.tr("console.tz.notHere", java.util.Map.of("name", name, "dir", String.valueOf(zoneinfo)));
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
