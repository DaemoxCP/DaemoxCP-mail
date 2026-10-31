package org.mail_panel.system;

import org.mail_panel.util.Shell;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFileAttributes;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.logging.Logger;

/**
 * Le firme con cui il pannello riconosce i file che ha scritto lui, e il loro passaggio
 * all'inglese sui server gia' installati (r26, 30/10/2026).
 *
 * <p>Il pannello mette una riga di commento nei file che scrive per intero, e la rilegge prima
 * di toccarli: un file senza firma e' di qualcun altro e non si sovrascrive. Fino a fine ottobre
 * 2026 le firme erano in italiano. Adesso sono in inglese, e quelle di prima stanno in
 * legacy-names.json: chi rilegge riconosce l'una e le altre, cosi' un server installato prima
 * non perde la proprieta' dei suoi file.
 *
 * <p>All'avvio, nei file che portano ancora una firma di prima, la firma diventa quella di
 * adesso, e il file torna uguale a quello che il codice di adesso scriverebbe. Si cambiano SOLO
 * le righe di commento, e lo si controlla prima di scrivere: tolti i commenti, il file nuovo e
 * il vecchio devono essere identici, altrimenti non si scrive. Un commento non cambia quello che
 * il servizio fa, quindi non servono nginx -t ne' reload. La scrittura e' atomica (file
 * temporaneo accanto, stessi permessi e proprietario, rename): nginx e fail2ban possono rileggere
 * il file in qualunque momento.
 *
 * <p>Quali file: i tre della superficie pubblica sulla 443 (il file di nginx, filtro e jail di
 * fail2ban; sezione "panelSignature") e dovecot.conf (sezione "dovecotSignature": e' la riga che
 * la manutenzione cerca per sapere se la configurazione viene dalla sorgente unica). Il filtro
 * di mail-panel-auth lo riscrive gia' Fail2banAutoSetup quando non e' uguale a quello di adesso;
 * il blocco di autoconfig sta dentro un file di nginx che non e' del pannello, e non si tocca.
 */
public final class PanelMarker {

    private static final Logger LOGGER = Logger.getLogger(PanelMarker.class.getName());

    /** La firma dei file che il pannello scrive per intero. */
    public static final String WRITTEN = "Written by the mail panel";
    static final String SIGNATURE = "panelSignature";
    static final String DOVECOT = "dovecotSignature";

    private PanelMarker() {}

    /** Il marcatore di adesso, poi quelli che ha avuto prima. */
    public static List<String> forms(String section, String current) {
        List<String> out = new ArrayList<>();
        out.add(current);
        out.addAll(LegacyNames.oldNamesOf(section, current));
        return out;
    }

    /** Il file l'ha scritto il pannello: c'e' la firma di adesso o una di prima. */
    public static boolean writtenByPanel(String content) {
        if (content == null) return false;
        for (String f : forms(SIGNATURE, WRITTEN)) if (content.contains(f)) return true;
        return false;
    }

    /**
     * Lo stesso testo con i marcatori di adesso al posto di quelli di prima, nelle sole righe di
     * commento. Le coppie si applicano nell'ordine del file: la piu' lunga prima, perche' una firma
     * di prima puo' contenerne un'altra.
     */
    public static String current(String content, String section) {
        List<String[]> pairs = LegacyNames.pairs(section);
        if (content == null || pairs.isEmpty()) return content;
        String[] lines = content.split("\n", -1);
        for (int i = 0; i < lines.length; i++) {
            if (!comment(lines[i])) continue;
            for (String[] p : pairs) lines[i] = lines[i].replace(p[0], p[1]);
        }
        return String.join("\n", lines);
    }

    static boolean comment(String line) {
        return line.stripLeading().startsWith("#");
    }

    /** Il testo senza le righe di commento: quello che il servizio legge davvero. */
    static String withoutComments(String content) {
        StringBuilder b = new StringBuilder();
        for (String l : content.split("\n", -1)) if (!comment(l)) b.append(l).append('\n');
        return b.toString();
    }

    // ===================== la migrazione all'avvio =====================

    enum Outcome { NOTHING, DONE, PARTIAL, NGINX_UNREADABLE }

    record Report(Outcome outcome, String detail) {}

    /** Dove stanno i file: fissi sul server, cartelle temporanee nella prova. */
    record Places(Path f2bDir, Path defaultNginxFolder, Path dovecotConf) {}

    /** Le cartelle che nginx include (nginx -T): vuota senza nginx, null se nginx non risponde. */
    interface Services {
        List<String> nginxFolders();
    }

    public static void ensureAtBoot() {
        try {
            Places at = new Places(Path.of(WebProtection.F2B_DIR), Path.of(WebProtection.PROPOSED_FOLDER),
                    Path.of("/usr/local/etc/dovecot/dovecot.conf"));
            Report r = migrate(at, () -> {
                if (Shell.resolve("nginx") == null) return List.of();
                Shell.Result t = Shell.run(Duration.ofSeconds(20), "nginx", "-T");
                return t.success() ? WebProtection.includedFolders(t.output()) : null;
            });
            if (r.outcome() == Outcome.NOTHING) return;
            String line = "[PanelMarker] " + r.outcome() + ": " + r.detail();
            if (r.outcome() == Outcome.DONE) LOGGER.info(line); else LOGGER.warning(line);
        } catch (Throwable t) {
            LOGGER.warning("[PanelMarker] failed: " + t);
        }
    }

    static Report migrate(Places at, Services sv) {
        Path filter = at.f2bDir().resolve("filter.d").resolve(WebProtection.FILE_NAME);
        Path jail = at.f2bDir().resolve("jail.d").resolve(WebProtection.FILE_NAME);
        Path defaultConf = at.defaultNginxFolder().resolve(WebProtection.FILE_NAME);
        boolean surface = stale(filter, SIGNATURE) || stale(jail, SIGNATURE) || stale(defaultConf, SIGNATURE);
        boolean dovecot = stale(at.dovecotConf(), DOVECOT);
        if (!surface && !dovecot) return new Report(Outcome.NOTHING, "");

        List<String> done = new ArrayList<>(), problems = new ArrayList<>();
        if (dovecot) rewrite(at.dovecotConf(), DOVECOT, done, problems);

        boolean unreadable = false;
        if (surface) {
            // Il file di nginx sta in una delle cartelle che nginx include: si chiede a nginx quali.
            // La jail per ultima: finche' ha la firma di prima, al prossimo avvio si riprova tutto.
            List<String> folders = sv.nginxFolders();
            if (folders == null) {
                unreadable = true;
            } else {
                Set<Path> order = new LinkedHashSet<>();
                for (String f : folders) order.add(Path.of(f).resolve(WebProtection.FILE_NAME));
                order.add(defaultConf);
                order.add(filter);
                order.add(jail);
                for (Path p : order) {
                    if (!stale(p, SIGNATURE)) continue;
                    if (!rewrite(p, SIGNATURE, done, problems)) break;
                }
            }
        }

        String detail = (done.isEmpty() ? "" : "signature updated in " + String.join(", ", done))
                + (problems.isEmpty() ? "" : (done.isEmpty() ? "" : "; ") + String.join("; ", problems));
        if (unreadable)
            return new Report(Outcome.NGINX_UNREADABLE, "nginx -T failed: the 443 surface keeps the old signature,"
                    + " retrying at the next start" + (detail.isEmpty() ? "" : "; " + detail));
        return new Report(problems.isEmpty() ? Outcome.DONE : Outcome.PARTIAL, detail);
    }

    /** Il file c'e' e ha ancora un marcatore di prima in una riga di commento. */
    static boolean stale(Path p, String section) {
        try {
            if (!Files.isRegularFile(p)) return false;
            String s = Files.readString(p, StandardCharsets.UTF_8);
            return !current(s, section).equals(s);
        } catch (IOException e) {
            return false;
        }
    }

    private static boolean rewrite(Path p, String section, List<String> done, List<String> problems) {
        try {
            // Un collegamento si segue: il file del pannello e' quello a cui punta.
            Path real = p.toRealPath();
            String before = Files.readString(real, StandardCharsets.UTF_8);
            String after = current(before, section);
            if (after.equals(before)) return true;
            if (!withoutComments(after).equals(withoutComments(before))) {
                problems.add(p + ": more than comments would change, not touched");
                return false;
            }
            replaceKeeping(real, after);
            done.add(p.toString());
            return true;
        } catch (IOException | RuntimeException e) {
            problems.add(p + ": " + e.getMessage());
            return false;
        }
    }

    /** Scrive accanto e sostituisce con un rename, con permessi, proprietario e gruppo di prima. */
    static void replaceKeeping(Path p, String content) throws IOException {
        // Il temporaneo comincia con un punto e non finisce in .conf: ne' nginx ne' fail2ban lo
        // leggerebbero, se restasse li'.
        Path tmp = p.resolveSibling("." + p.getFileName() + ".mailpanel.tmp");
        Files.deleteIfExists(tmp);
        try {
            Files.writeString(tmp, content, StandardCharsets.UTF_8);
            try {
                PosixFileAttributes a = Files.readAttributes(p, PosixFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
                Files.setPosixFilePermissions(tmp, a.permissions());
                try {
                    Files.setOwner(tmp, a.owner());
                    Files.setAttribute(tmp, "posix:group", a.group());
                } catch (IOException ignored) {
                    // Senza permesso di cambiare proprietario resta quello del pannello, che e' root.
                }
            } catch (UnsupportedOperationException ignored) {
                // File system senza permessi POSIX: solo nelle prove.
            }
            Files.move(tmp, p, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } finally {
            Files.deleteIfExists(tmp);
        }
    }
}
