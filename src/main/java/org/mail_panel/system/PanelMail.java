package org.mail_panel.system;

import org.mail_panel.Main;
import org.mail_panel.i18n.I18n;
import org.mail_panel.util.Shell;

import java.nio.charset.StandardCharsets;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * La busta e l'aspetto comuni a tutte le email del pannello: il rapporto periodico e i codici
 * (accesso, conferma di un'operazione, cambio dell'email di accesso).
 *
 * Perche' un posto solo. Fino al 05/11/2026 ogni email era un testo nudo con il mittente
 * "Control panel" e, nell'oggetto del rapporto, il risultato di hostname(1): sul server vero
 * "freebsd". Chi riceveva "[freebsd] 1 thing to do" da "Control panel" non sapeva ne' quale
 * pannello, ne' quale server, ne' che cosa ci fosse da fare. Qui stanno le tre cose che ogni
 * email deve avere uguali:
 *
 *  1. CHI SCRIVE: "Mail control panel (mail.example.org)". Il nome del server e' quello con
 *     cui il server di posta si presenta (mail_hostname, poi myhostname di Postfix), non
 *     hostname(1), che su un server installato da un'immagine e' spesso un nome generico.
 *  2. LA BUSTA MIME: multipart/alternative con una parte di testo e una HTML, tutte e due in
 *     UTF-8 e quoted-printable (nessuna riga oltre i 76 caratteri, qualunque cosa ci sia nel
 *     testo), Date, Message-ID, Content-Language, e le intestazioni che dicono che il
 *     messaggio e' automatico (Auto-Submitted, X-Auto-Response-Suppress): un risponditore
 *     automatico non deve rispondere a un pannello.
 *  3. L'ASPETTO: un solo modello HTML, con gli stili scritti dentro gli elementi perche' Gmail
 *     e diversi altri programmi di posta tolgono i fogli di stile. Nessuna immagine, nessun
 *     carattere esterno, nessun collegamento: il messaggio si legge uguale ovunque e non
 *     somiglia a un messaggio che chiede di cliccare.
 *
 * I testi stanno nei file di lingua (mail.*); qui ci sono solo la forma e la codifica.
 */
public final class PanelMail {

    private PanelMail() {}

    /** Un'email pronta: oggetto, testo semplice e HTML, nella lingua in cui e' scritta. */
    public record Message(String subject, String text, String html, String lang) {}

    // ===================== chi scrive =====================

    /**
     * Il nome del server di posta: il valore salvato dall'installazione (mail_hostname), poi
     * myhostname di Postfix, e solo alla fine hostname(1). Sul server vero hostname(1) da'
     * "freebsd", myhostname "mail.domain-b.test": e' il secondo che dice quale server e'.
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

    /** Un nome di host che puo' finire in un'intestazione: solo lettere, cifre, punti e trattini. */
    static boolean validHost(String h) {
        return h != null && h.length() <= 253 && h.matches("[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?");
    }

    /** Il nome visualizzato del mittente, con il server se lo si conosce. */
    static String senderName(String lang, String server) {
        return server == null || server.isEmpty()
                ? I18n.t(lang, "mail.common.senderNameBare")
                : I18n.t(lang, "mail.common.senderName", Map.of("server", server));
    }

    /** La data lunga nella lingua dell'email: "5 November 2026", "5 novembre 2026". */
    static String longDate(String lang, ZonedDateTime when) {
        return when.format(DateTimeFormatter.ofPattern(I18n.t(lang, "mail.common.datePattern"), localeOf(lang)));
    }

    /** Data e ora con il fuso, nella lingua dell'email: "5 November 2026 at 20:15 UTC". */
    static String longDateTime(String lang, ZonedDateTime when) {
        return when.format(DateTimeFormatter.ofPattern(I18n.t(lang, "mail.common.dateTimePattern"), localeOf(lang)));
    }

    static Locale localeOf(String lang) {
        return Locale.forLanguageTag(I18n.normalize(lang));
    }

    // ===================== la busta =====================

    /**
     * Il messaggio completo, come lo vuole sendmail -t: intestazioni, riga vuota, corpo.
     * Le righe finiscono con CRLF; sendmail le accetta e Postfix le riscrive come preferisce.
     */
    static String compose(String fromName, String from, String to, Message m, String messageId, ZonedDateTime date) {
        String boundary = "=_mcp_" + randomHex(12);
        StringBuilder b = new StringBuilder(m.text().length() * 2 + m.html().length() * 2 + 1024);
        // Il nome del mittente con il server puo' superare i 78 caratteri: si va a capo prima
        // dell'indirizzo, che e' il punto in cui ogni programma di posta se lo aspetta.
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
         // Non e' posta scritta da una persona: i risponditori automatici (RFC 3834) e Outlook
         // (X-Auto-Response-Suppress) non devono rispondere.
         .append("Auto-Submitted: auto-generated\r\n")
         .append("X-Auto-Response-Suppress: All\r\n")
         .append("X-Mailer: FreeBSD Mail Panel\r\n")
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

    /** "Nome" <indirizzo>: tra virgolette se e' ASCII, in RFC 2047 se non lo e'. */
    static String address(String name, String address) {
        if (name == null || name.isBlank()) return address;
        if (isPrintableAscii(name))
            return "\"" + name.replace("\\", "\\\\").replace("\"", "\\\"") + "\" <" + address + ">";
        return encodeHeader(name, "From: ".length()) + " <" + address + ">";
    }

    /**
     * Un'intestazione ASCII lunga va a capo prima di uno spazio, entro i 78 caratteri che la
     * norma raccomanda (RFC 5322, 2.1.1): chi la legge toglie l'a capo e ritrova la riga intera.
     * Le parti gia' piegate (le parole codificate) si lasciano come sono.
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
     * Un'intestazione secondo RFC 2047 se contiene caratteri non ASCII.
     *
     * Ogni parola codificata sta entro i 75 caratteri che la norma impone, e non spezza mai un
     * carattere UTF-8 a meta': la versione di prima metteva tutto l'oggetto in una sola parola,
     * che con un oggetto lungo superava il limite. Le parole successive vanno a capo con uno
     * spazio davanti (folding), che chi legge non vede.
     */
    static String encodeHeader(String s, int alreadyUsed) {
        if (s == null) return "";
        String clean = s.replace("\r", " ").replace("\n", " ");
        if (isPrintableAscii(clean)) return clean;
        StringBuilder out = new StringBuilder();
        StringBuilder chunk = new StringBuilder();
        int chunkBytes = 0;
        final int maxBytes = 42;       // 42 byte = 56 caratteri base64: con =?UTF-8?B?, ?= e "Subject: " fanno 77
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
     * Quoted-printable (RFC 2045, 6.7): l'ASCII stampabile resta com'e', il resto diventa =XX,
     * e nessuna riga supera i 76 caratteri. Le righe lunghe dell'HTML e le lettere accentate
     * arrivano cosi' intatte attraverso qualunque server, anche uno che non accetta 8 bit.
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
                // Spazio per il pezzo e, se la riga continua, per il "=" della riga spezzata.
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

    // ===================== l'aspetto =====================

    /** Le tonalita' delle cose da fare: sfondo, bordo e testo. Contrasto del testo >= 4.5:1 sullo sfondo. */
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

        /** La tonalita' di una cosa da fare, dalla sua urgenza (0 subito ... 3 quando si puo'). */
        public static Tone of(int urgency) {
            return switch (urgency) { case 0 -> NOW; case 1 -> URGENT; case 2 -> TODO; default -> LATER; };
        }
    }

    static final String FONT = "-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif";
    static final String MONO = "ui-monospace,SFMono-Regular,Menlo,Consolas,'Liberation Mono',monospace";
    private static final String TEXT = "#111827", MUTED = "#4b5563", LINE = "#e5e7eb";

    public static String esc(String s) { return I18n.escapeHtml(s == null ? "" : s); }

    /**
     * La pagina intera: intestazione con il nome del pannello e del server, il contenuto, il
     * piede. "preheader" e' la riga che Gmail e Apple Mail mostrano nell'elenco accanto
     * all'oggetto: se manca, mostrano l'inizio del corpo, che qui sarebbe il nome del pannello.
     */
    static String page(String lang, String title, String preheader, String server, String content, String footer) {
        String l = I18n.normalize(lang);
        return "<!DOCTYPE html>\n"
             + "<html lang=\"" + l + "\">\n<head>\n"
             + "<meta charset=\"UTF-8\">\n"
             + "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
             // Solo chiaro: senza questa dichiarazione alcuni programmi in modalita' scura
             // invertono i colori a modo loro, e i colori delle urgenze diventano illeggibili.
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

    /** Una riga di stato in evidenza: titolo in grassetto e una frase sotto. Il colore non e' mai l'unico segnale. */
    static String banner(Tone tone, String title, String detail) {
        return "<table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\" style=\"margin:16px 0 4px;\">"
             + "<tr><td style=\"padding:14px 16px;background-color:" + tone.background + ";border-left:4px solid " + tone.border + ";border-radius:4px;\">"
             + "<p style=\"margin:0;font-size:16px;line-height:22px;font-weight:700;color:" + tone.text + ";\">" + esc(title) + "</p>"
             + (detail == null || detail.isEmpty() ? ""
                : "<p style=\"margin:4px 0 0;font-size:14px;line-height:20px;color:" + TEXT + ";\">" + esc(detail) + "</p>")
             + "</td></tr></table>\n";
    }

    /** Una cosa da fare: l'etichetta d'urgenza scritta, il titolo, la spiegazione e dove farla nel pannello. */
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

    /** Una tabella di dati a due colonne: nome e valore. La prima colonna e' l'intestazione della riga. */
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

    /** Un elenco puntato di righe gia' fatte (pacchetti, vulnerabilita'). */
    static String list(List<String> lines) {
        if (lines.isEmpty()) return "";
        StringBuilder b = new StringBuilder("<ul style=\"margin:4px 0 12px;padding:0 0 0 20px;font-size:13px;line-height:20px;color:#374151;\">");
        for (String l : lines)
            b.append("<li style=\"margin:0 0 2px;font-family:").append(MONO).append(";\">").append(esc(l)).append("</li>");
        return b.append("</ul>\n").toString();
    }

    /** Il codice monouso, grande e in caratteri a larghezza fissa, facile da leggere e da copiare. */
    static String code(String code) {
        return "<table role=\"presentation\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\" style=\"margin:16px 0;\">"
             + "<tr><td style=\"padding:14px 22px;background-color:#f3f4f6;border:1px solid " + LINE + ";border-radius:6px;"
             + "font-family:" + MONO + ";font-size:30px;line-height:36px;font-weight:700;letter-spacing:6px;color:" + TEXT + ";\">"
             + esc(code) + "</td></tr></table>\n";
    }

    static String footerLine(String text) {
        return "<p style=\"margin:0 0 6px;\">" + esc(text) + "</p>\n";
    }

    // ===================== il testo semplice =====================

    /** Il titolo di una sezione del testo semplice, sottolineato. */
    static String textHeading(String title) {
        return title + "\n" + "-".repeat(Math.min(60, Math.max(3, title.length()))) + "\n";
    }

    /**
     * Va a capo a 72 colonne, mantenendo il rientro: il testo semplice si legge in un
     * terminale o in un programma che non mostra l'HTML, e una riga di 300 caratteri li'
     * diventa una striscia da scorrere.
     */
    static String wrap(String text, int width, String indent) {
        return wrap(text, width, indent, indent);
    }

    /** Come wrap, con un rientro per la prima riga e un altro per le seguenti (gli elenchi: "- " poi allineato). */
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
