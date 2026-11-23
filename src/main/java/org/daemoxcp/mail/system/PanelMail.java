package org.daemoxcp.mail.system;

import org.daemoxcp.mail.Main;
import org.daemoxcp.mail.i18n.I18n;
import org.daemoxcp.mail.util.Shell;

import java.nio.charset.StandardCharsets;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * The envelope and the look shared by all the panel's emails: the periodic report and the codes
 * (access, confirmation of an operation, change of the login email).
 *
 * Why a single place. Until 2026-11-05 every email was a bare text with the sender
 * "Control panel" and, in the report's subject, the result of hostname(1): on the production
 * server "freebsd". Whoever received "[freebsd] 1 thing to do" from "Control panel" knew
 * neither which panel, nor which server, nor what there was to do. Here are the three things
 * every email must have the same:
 *
 *  1. WHO WRITES: "Mail control panel (mail.example.org)". The server name is the one the
 *     mail server introduces itself with (mail_hostname, then Postfix's myhostname), not
 *     hostname(1), which on a server installed from an image is often a generic name.
 *  2. THE MIME ENVELOPE: multipart/alternative with a text part and an HTML part, both in
 *     UTF-8 and quoted-printable (no line over 76 characters, whatever is in the text),
 *     Date, Message-ID, Content-Language, and the headers saying that the message is
 *     automatic (Auto-Submitted, X-Auto-Response-Suppress): an automatic responder must
 *     not reply to a panel.
 *  3. THE LOOK: a single HTML template, with the styles written inside the elements because
 *     Gmail and several other mail programs strip style sheets. No image, no external
 *     font, no link: the message reads the same everywhere and does not look like a
 *     message asking you to click.
 *
 * The texts are in the language files (mail.*); here there are only the form and the encoding.
 */
public final class PanelMail {

    private PanelMail() {}

    /** A ready email: subject, plain text and HTML, in the language it is written in. */
    public record Message(String subject, String text, String html, String lang) {}

    // ===================== who writes =====================

    /**
     * The mail server's name: the value saved by the installation (mail_hostname), then Postfix's
     * myhostname, and only at the end hostname(1). On the production server hostname(1) gives
     * "freebsd", myhostname "mail.domain-b.test": it is the second one that says which server it is.
     */
    public static String serverName() {
        String name = "";
        try { if (Main.mailDatabase != null) name = Main.mailDatabase.getSetting("mail_hostname", ""); }
        catch (Exception ignored) { }
        if (!validHost(name))
            name = Shell.runShell(java.time.Duration.ofSeconds(10), "postconf -h myhostname 2>/dev/null").outputTrim();
        if (!validHost(name))
            name = Shell.runShell(java.time.Duration.ofSeconds(10), "hostname").outputTrim();
        return validHost(name) ? name.toLowerCase(Locale.ROOT) : "";
    }

    /** A host name that may end up in a header: only letters, digits, dots and hyphens. */
    static boolean validHost(String h) {
        return h != null && h.length() <= 253 && h.matches("[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?");
    }

    /** The sender's display name, with the server if it is known. */
    static String senderName(String lang, String server) {
        return server == null || server.isEmpty()
                ? I18n.t(lang, "mail.common.senderNameBare")
                : I18n.t(lang, "mail.common.senderName", Map.of("server", server));
    }

    /** The long date in the email's language: "5 November 2026", `5 novembre 2026`. */
    static String longDate(String lang, ZonedDateTime when) {
        return when.format(DateTimeFormatter.ofPattern(I18n.t(lang, "mail.common.datePattern"), localeOf(lang)));
    }

    /** Date and time with the time zone, in the email's language: "5 November 2026 at 20:15 UTC". */
    static String longDateTime(String lang, ZonedDateTime when) {
        return when.format(DateTimeFormatter.ofPattern(I18n.t(lang, "mail.common.dateTimePattern"), localeOf(lang)));
    }

    static Locale localeOf(String lang) {
        return Locale.forLanguageTag(I18n.normalize(lang));
    }

    // ===================== the envelope =====================

    /**
     * The complete message, as sendmail -t wants it: headers, empty line, body.
     * Lines end with CRLF; sendmail accepts them and Postfix rewrites them as it prefers.
     */
    static String compose(String fromName, String from, String to, Message m, String messageId, ZonedDateTime date) {
        String boundary = "=_mcp_" + randomHex(12);
        StringBuilder b = new StringBuilder(m.text().length() * 2 + m.html().length() * 2 + 1024);
        // The sender's name with the server can exceed 78 characters: the line is broken before the
        // address, which is the point where every mail program expects it.
        String fromLine = "From: " + address(fromName, from);
        if (fromLine.length() > 78 && fromLine.endsWith(" <" + from + ">"))
            fromLine = fromLine.substring(0, fromLine.length() - from.length() - 3) + "\r\n <" + from + ">";
        b.append(fromLine).append("\r\n")
         .append("To: ").append(to).append("\r\n")
         .append(fold("Subject: " + encodeHeader(m.subject(), "Subject: ".length()))).append("\r\n")
         .append("Date: ").append(date.format(DateTimeFormatter.ofPattern("EEE, d MMM yyyy HH:mm:ss Z", Locale.ROOT))).append("\r\n")
         .append("Message-ID: <").append(messageId).append(">\r\n")
         .append("MIME-Version: 1.0\r\n")
         .append("Content-Language: ").append(I18n.normalize(m.lang())).append("\r\n")
         // It is not mail written by a person: automatic responders (RFC 3834) and Outlook
         // (X-Auto-Response-Suppress) must not reply.
         .append("Auto-Submitted: auto-generated\r\n")
         .append("X-Auto-Response-Suppress: All\r\n")
         .append("X-Mailer: ").append(I18n.tr("brand.name")).append("\r\n")
         .append("Content-Type: multipart/alternative; boundary=\"").append(boundary).append("\"\r\n")
         .append("\r\n")
         .append("--").append(boundary).append("\r\n")
         .append("Content-Type: text/plain; charset=UTF-8\r\n")
         .append("Content-Transfer-Encoding: quoted-printable\r\n")
         .append("\r\n")
         .append(quotedPrintable(m.text())).append("\r\n")
         .append("--").append(boundary).append("\r\n")
         .append("Content-Type: text/html; charset=UTF-8\r\n")
         .append("Content-Transfer-Encoding: quoted-printable\r\n")
         .append("\r\n")
         .append(quotedPrintable(m.html())).append("\r\n")
         .append("--").append(boundary).append("--\r\n");
        return b.toString();
    }

    /**
     * "Name" <address>: in quotes if it is ASCII and the sender line fits; otherwise in RFC 2047
     * encoded words, which can be broken onto new lines between one and the next (the reader
     * joins them without spaces). A long quoted name cannot be split without relying on
     * programs that join folded quotes correctly.
     */
    static String address(String name, String address) {
        if (name == null || name.isBlank()) return address;
        String quoted = "\"" + name.replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
        if (isPrintableAscii(name) && "From: ".length() + quoted.length() <= 78)
            return quoted + " <" + address + ">";
        return encodeWords(name) + " <" + address + ">";
    }

    /**
     * A header according to RFC 2047 if it contains non-ASCII characters.
     *
     * Every encoded word stays within the 75 characters the standard imposes, and never splits a
     * UTF-8 character in half: the previous version put the whole subject in a single word,
     * which with a long subject exceeded the limit. The following words go on a new line with a
     * space in front (folding), which the reader does not see.
     */
    static String encodeHeader(String s, int alreadyUsed) {
        if (s == null) return "";
        String clean = s.replace("\r", " ").replace("\n", " ");
        if (isPrintableAscii(clean)) return clean;
        return encodeWords(clean);
    }

    /** The text in encoded words "=?UTF-8?B?...?=", one per line, each within 77 characters with the header name. */
    static String encodeWords(String s) {
        String clean = s.replace("\r", " ").replace("\n", " ");
        StringBuilder out = new StringBuilder();
        StringBuilder chunk = new StringBuilder();
        int chunkBytes = 0;
        final int maxBytes = 42;       // 42 bytes = 56 base64 characters: with =?UTF-8?B?, ?= and "Subject: " they make 77
        for (int i = 0; i < clean.length(); ) {
            int cp = clean.codePointAt(i);
            String c = new String(Character.toChars(cp));
            int n = c.getBytes(StandardCharsets.UTF_8).length;
            if (chunkBytes + n > maxBytes) {
                appendWord(out, chunk.toString());
                chunk.setLength(0);
                chunkBytes = 0;
            }
            chunk.append(c);
            chunkBytes += n;
            i += Character.charCount(cp);
        }
        if (chunk.length() > 0) appendWord(out, chunk.toString());
        return out.toString();
    }

    private static void appendWord(StringBuilder out, String text) {
        if (out.length() > 0) out.append("\r\n ");
        out.append("=?UTF-8?B?").append(Base64.getEncoder().encodeToString(text.getBytes(StandardCharsets.UTF_8))).append("?=");
    }

    /**
     * A long ASCII header is broken before a space, within the 78 characters the standard
     * recommends (RFC 5322, 2.1.1): the reader removes the line break and finds the whole line again.
     * The parts already folded (the encoded words) are left as they are.
     */
    static String fold(String header) {
        StringBuilder out = new StringBuilder();
        for (String seg : header.split("\r\n", -1)) {
            if (out.length() > 0) out.append("\r\n");
            String line = seg;
            while (line.length() > 78) {
                int cut = line.lastIndexOf(' ', 78);
                if (cut <= 1) break;
                out.append(line, 0, cut).append("\r\n");
                line = line.substring(cut);
            }
            out.append(line);
        }
        return out.toString();
    }

    private static boolean isPrintableAscii(String s) {
        return s.chars().allMatch(c -> c >= 32 && c < 127);
    }

    /**
     * Quoted-printable (RFC 2045, 6.7): printable ASCII stays as it is, the rest becomes =XX,
     * and no line exceeds 76 characters. The long HTML lines and the accented letters thus
     * arrive intact through any server, even one that does not accept 8 bit.
     */
    static String quotedPrintable(String text) {
        StringBuilder out = new StringBuilder(text.length() + text.length() / 3);
        String[] lines = text.replace("\r\n", "\n").replace('\r', '\n').split("\n", -1);
        for (int li = 0; li < lines.length; li++) {
            byte[] bytes = lines[li].getBytes(StandardCharsets.UTF_8);
            int col = 0;
            for (int i = 0; i < bytes.length; i++) {
                int b = bytes[i] & 0xff;
                boolean last = i == bytes.length - 1;
                String piece;
                if ((b >= 33 && b <= 126 && b != '=') || ((b == ' ' || b == '\t') && !last))
                    piece = String.valueOf((char) b);
                else
                    piece = String.format("=%02X", b);
                // Room for the piece and, if the line continues, for the "=" of the split line.
                int room = last ? 76 : 75;
                if (col + piece.length() > room) {
                    out.append("=\r\n");
                    col = 0;
                }
                out.append(piece);
                col += piece.length();
            }
            if (li < lines.length - 1) out.append("\r\n");
        }
        return out.toString();
    }

    private static String randomHex(int bytes) {
        byte[] r = new byte[bytes];
        new java.security.SecureRandom().nextBytes(r);
        return java.util.HexFormat.of().formatHex(r);
    }

    // ===================== the look =====================

    /** The shades of the things to do: background, border and text. Text contrast >= 4.5:1 on the background. */
    public enum Tone {
        NOW("#fef2f2", "#b91c1c", "#991b1b"),
        URGENT("#fff7ed", "#c2410c", "#9a3412"),
        TODO("#eff6ff", "#1d4ed8", "#1e40af"),
        LATER("#f3f4f6", "#6b7280", "#374151"),
        GOOD("#f0fdf4", "#15803d", "#166534");

        final String background, border, text;
        Tone(String background, String border, String text) {
            this.background = background; this.border = border; this.text = text;
        }

        /** The shade of a thing to do, from its urgency (0 right away ... 3 when possible). */
        public static Tone of(int urgency) {
            return switch (urgency) { case 0 -> NOW; case 1 -> URGENT; case 2 -> TODO; default -> LATER; };
        }
    }

    static final String FONT = "-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif";
    static final String MONO = "ui-monospace,SFMono-Regular,Menlo,Consolas,'Liberation Mono',monospace";
    private static final String TEXT = "#111827", MUTED = "#4b5563", LINE = "#e5e7eb";

    public static String esc(String s) { return I18n.escapeHtml(s == null ? "" : s); }

    /**
     * The whole page: header with the panel's and the server's name, the content, the footer.
     * "preheader" is the line that Gmail and Apple Mail show in the list next to the subject:
     * if it is missing, they show the start of the body, which here would be the panel's name.
     */
    static String page(String lang, String title, String preheader, String server, String content, String footer) {
        String l = I18n.normalize(lang);
        return "<!DOCTYPE html>\n"
             + "<html lang=\"" + l + "\">\n<head>\n"
             + "<meta charset=\"UTF-8\">\n"
             + "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
             // Light only: without this declaration some programs in dark mode invert the
             // colours their own way, and the urgency colours become unreadable.
             + "<meta name=\"color-scheme\" content=\"light\">\n"
             + "<meta name=\"supported-color-schemes\" content=\"light\">\n"
             + "<title>" + esc(title) + "</title>\n"
             + "</head>\n"
             + "<body style=\"margin:0;padding:0;background-color:#f3f4f6;color:" + TEXT + ";font-family:" + FONT + ";\">\n"
             + "<div style=\"display:none;max-height:0;overflow:hidden;opacity:0;color:transparent;font-size:1px;line-height:1px;\">"
             + esc(preheader) + "</div>\n"
             + "<table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\" style=\"background-color:#f3f4f6;\">\n"
             + "<tr><td align=\"center\" style=\"padding:24px 12px;\">\n"
             + "<table role=\"presentation\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\" style=\"width:100%;max-width:640px;background-color:#ffffff;border:1px solid " + LINE + ";border-radius:8px;\">\n"
             + "<tr><td style=\"padding:20px 28px;border-bottom:1px solid " + LINE + ";\">"
             + "<p style=\"margin:0;font-family:" + FONT + ";font-size:12px;line-height:16px;font-weight:700;letter-spacing:1px;text-transform:uppercase;color:" + MUTED + ";\">"
             + esc(I18n.t(l, "mail.common.product")) + "</p>"
             + (server == null || server.isEmpty() ? ""
                : "<p style=\"margin:4px 0 0;font-family:" + FONT + ";font-size:18px;line-height:24px;font-weight:600;color:" + TEXT + ";\">" + esc(server) + "</p>")
             + "</td></tr>\n"
             + "<tr><td style=\"padding:24px 28px;font-family:" + FONT + ";font-size:15px;line-height:22px;color:" + TEXT + ";\">\n"
             + content
             + "</td></tr>\n"
             + "<tr><td style=\"padding:16px 28px;border-top:1px solid " + LINE + ";background-color:#f9fafb;border-radius:0 0 8px 8px;font-family:" + FONT + ";font-size:12px;line-height:18px;color:" + MUTED + ";\">\n"
             + footer
             + "</td></tr>\n"
             + "</table>\n"
             + "</td></tr>\n</table>\n"
             + "</body>\n</html>\n";
    }

    static String h1(String text) {
        return "<h1 style=\"margin:0 0 4px;font-family:" + FONT + ";font-size:22px;line-height:28px;font-weight:700;color:" + TEXT + ";\">" + esc(text) + "</h1>\n";
    }

    static String h2(String text) {
        return "<h2 style=\"margin:28px 0 10px;font-family:" + FONT + ";font-size:17px;line-height:24px;font-weight:700;color:" + TEXT + ";\">" + esc(text) + "</h2>\n";
    }

    static String h3(String text) {
        return "<h3 style=\"margin:20px 0 6px;font-family:" + FONT + ";font-size:14px;line-height:20px;font-weight:700;color:" + TEXT + ";\">" + esc(text) + "</h3>\n";
    }

    static String p(String text) {
        return "<p style=\"margin:0 0 12px;\">" + esc(text) + "</p>\n";
    }

    static String muted(String text) {
        return "<p style=\"margin:0 0 12px;font-size:13px;line-height:20px;color:" + MUTED + ";\">" + esc(text) + "</p>\n";
    }

    /** A highlighted status line: bold title and a sentence below. Colour is never the only signal. */
    static String banner(Tone tone, String title, String detail) {
        return "<table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\" style=\"margin:16px 0 4px;\">"
             + "<tr><td style=\"padding:14px 16px;background-color:" + tone.background + ";border-left:4px solid " + tone.border + ";border-radius:4px;\">"
             + "<p style=\"margin:0;font-size:16px;line-height:22px;font-weight:700;color:" + tone.text + ";\">" + esc(title) + "</p>"
             + (detail == null || detail.isEmpty() ? ""
                : "<p style=\"margin:4px 0 0;font-size:14px;line-height:20px;color:" + TEXT + ";\">" + esc(detail) + "</p>")
             + "</td></tr></table>\n";
    }

    /** A thing to do: the urgency label in words, the title, the explanation and where to do it in the panel. */
    static String item(Tone tone, String label, String title, String detail, String whereLabel, String where) {
        StringBuilder b = new StringBuilder();
        b.append("<table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\" style=\"margin:0 0 12px;border:1px solid ").append(LINE)
         .append(";border-left:4px solid ").append(tone.border).append(";border-radius:4px;\">")
         .append("<tr><td style=\"padding:12px 16px;\">")
         .append("<p style=\"margin:0 0 6px;\"><span style=\"display:inline-block;padding:1px 8px;border-radius:10px;background-color:")
         .append(tone.background).append(";color:").append(tone.text).append(";font-size:12px;line-height:18px;font-weight:700;\">")
         .append(esc(label)).append("</span></p>")
         .append("<p style=\"margin:0 0 4px;font-size:16px;line-height:22px;font-weight:700;color:").append(TEXT).append(";\">").append(esc(title)).append("</p>");
        if (detail != null && !detail.isEmpty() && !detail.equals(title))
            b.append("<p style=\"margin:0 0 6px;font-size:14px;line-height:20px;color:#374151;\">").append(esc(detail)).append("</p>");
        if (where != null && !where.isEmpty())
            b.append("<p style=\"margin:0;font-size:13px;line-height:18px;color:").append(MUTED).append(";\">")
             .append(esc(whereLabel)).append(" <strong style=\"color:").append(TEXT).append(";\">").append(esc(where)).append("</strong></p>");
        b.append("</td></tr></table>\n");
        return b.toString();
    }

    /** A two-column data table: name and value. The first column is the row header. */
    static String facts(String caption, List<String[]> rows) {
        StringBuilder b = new StringBuilder();
        b.append("<table cellpadding=\"0\" cellspacing=\"0\" border=\"0\" width=\"100%\" style=\"border-collapse:collapse;margin:0 0 4px;font-size:14px;line-height:20px;\">");
        if (caption != null && !caption.isEmpty())
            b.append("<caption style=\"text-align:left;padding:0 0 6px;font-size:14px;line-height:20px;font-weight:700;color:").append(TEXT).append(";\">")
             .append(esc(caption)).append("</caption>");
        for (String[] r : rows) {
            b.append("<tr><th scope=\"row\" style=\"text-align:left;vertical-align:top;font-weight:400;color:").append(MUTED)
             .append(";padding:5px 12px 5px 0;border-top:1px solid ").append(LINE).append(";width:40%;\">").append(esc(r[0])).append("</th>")
             .append("<td style=\"vertical-align:top;color:").append(TEXT).append(";padding:5px 0;border-top:1px solid ").append(LINE)
             .append(";word-break:break-word;\">").append(esc(r[1])).append("</td></tr>");
        }
        b.append("</table>\n");
        return b.toString();
    }

    /** A bulleted list of ready-made lines (packages, vulnerabilities). */
    static String list(List<String> lines) {
        if (lines.isEmpty()) return "";
        StringBuilder b = new StringBuilder("<ul style=\"margin:4px 0 12px;padding:0 0 0 20px;font-size:13px;line-height:20px;color:#374151;\">");
        for (String l : lines)
            b.append("<li style=\"margin:0 0 2px;font-family:").append(MONO).append(";\">").append(esc(l)).append("</li>");
        return b.append("</ul>\n").toString();
    }

    /** The one-time code, large and in fixed-width characters, easy to read and to copy. */
    static String code(String code) {
        return "<table role=\"presentation\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\" style=\"margin:16px 0;\">"
             + "<tr><td style=\"padding:14px 22px;background-color:#f3f4f6;border:1px solid " + LINE + ";border-radius:6px;"
             + "font-family:" + MONO + ";font-size:30px;line-height:36px;font-weight:700;letter-spacing:6px;color:" + TEXT + ";\">"
             + esc(code) + "</td></tr></table>\n";
    }

    static String footerLine(String text) {
        return "<p style=\"margin:0 0 6px;\">" + esc(text) + "</p>\n";
    }

    // ===================== the plain text =====================

    /** The title of a plain-text section, underlined. */
    static String textHeading(String title) {
        return title + "\n" + "-".repeat(Math.min(60, Math.max(3, title.length()))) + "\n";
    }

    /**
     * Wraps at 72 columns, keeping the indentation: the plain text is read in a terminal
     * or in a program that does not show HTML, and a 300-character line there becomes a
     * strip to scroll.
     */
    static String wrap(String text, int width, String indent) {
        return wrap(text, width, indent, indent);
    }

    /** Like wrap, with one indentation for the first line and another for the following ones (lists: "- " then aligned). */
    static String wrap(String text, int width, String first, String rest) {
        StringBuilder out = new StringBuilder();
        boolean firstLine = true;
        for (String paragraph : text.split("\n", -1)) {
            StringBuilder line = new StringBuilder(firstLine ? first : rest);
            firstLine = false;
            boolean empty = true;
            for (String word : paragraph.split(" ")) {
                if (word.isEmpty()) continue;
                if (!empty && line.length() + 1 + word.length() > width) {
                    out.append(line).append('\n');
                    line = new StringBuilder(rest);
                    empty = true;
                }
                if (!empty) line.append(' ');
                line.append(word);
                empty = false;
            }
            out.append(empty ? "" : line).append('\n');
        }
        return out.toString();
    }
}
