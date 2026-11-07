package org.mail_panel.system;

import org.mail_panel.util.Shell;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.logging.Logger;

/**
 * La posta in /var/vmail leggibile solo da vmail, anche dentro.
 *
 * Misurato il 07/11/2026 sul server vero: /var/vmail e' 0770 vmail:vmail e nel gruppo vmail non c'e'
 * nessuno, quindi gli altri utenti non ci entrano. Dentro pero' 17 cartelle erano 0755 e 349 file
 * leggibili da tutti: le cartelle dei domini le creava root (umask 022), e Dovecot fa le cose nuove
 * con i permessi della cartella radice della casella. Il manuale di Dovecot 2.3
 * (admin_manual/filesystem_permission): "Dovecot copies the permissions from the mailbox root
 * directory", e "Dovecot never modifies permissions for existing mail files or directories". Con un
 * solo utente (mail_uid = vmail) e la consegna che passa da Dovecot (LMTP), 0700 per le cartelle e
 * 0600 per i file e' quello giusto: e' una seconda difesa, se un giorno /var/vmail si aprisse.
 *
 * Si tolgono i permessi di gruppo e degli altri solo a cio' che e' di vmail; quello che non e' suo non
 * si tocca (Dovecot potrebbe leggerlo proprio grazie a quei permessi) e lo si conta nel log. Dopo, vmail
 * deve poter ancora entrare in ogni casella.
 */
public final class VmailPermissions {

    private static final Logger LOGGER = Logger.getLogger(VmailPermissions.class.getName());

    static Path root = Path.of("/var/vmail");

    /** Il pezzo di shell che fa lo stesso, per gli script che creano le cartelle delle caselle. */
    public static final String SHELL =
            "find /var/vmail -mindepth 1 -user vmail -perm +077 -exec chmod go-rwx {} + 2>/dev/null || true\n";

    private VmailPermissions() {}

    static int count(String findArgs) {
        Shell.Result r = Shell.runShell(Duration.ofSeconds(300), "find " + root + " -mindepth 1 " + findArgs + " 2>/dev/null | wc -l");
        try { return Integer.parseInt(r.outputTrim().trim()); } catch (NumberFormatException e) { return -1; }
    }

    public static void ensureAtBoot() {
        try {
            if (!Files.isDirectory(root) || Shell.run(Duration.ofSeconds(10), "id", "-u", "vmail").exitCode() != 0) return;
            int open = count("-user vmail -perm +077");
            if (open <= 0) return;
            int dirs = count("-user vmail -type d -perm +077");
            Shell.Result r = Shell.runShell(Duration.ofSeconds(600),
                    "find " + root + " -mindepth 1 -user vmail -perm +077 -exec chmod go-rwx {} +");
            int left = count("-user vmail -perm +077");
            int foreign = count("! -user vmail");
            String unreadable = unreadableByVmail();
            if (left != 0 || unreadable != null) {
                LOGGER.warning("[VmailPermissions] NOT_APPLIED: chmod exit " + r.exitCode() + ", still open: " + left
                        + (unreadable != null ? ", " + unreadable : ""));
                return;
            }
            LOGGER.info("[VmailPermissions] DONE: " + open + " entries under " + root + " (" + dirs + " folders) readable"
                    + " only by vmail now" + (foreign > 0 ? "; " + foreign + " entries not owned by vmail left as they are" : ""));
        } catch (Throwable t) {
            LOGGER.warning("[VmailPermissions] ensureAtBoot exception: " + t.getMessage());
        }
    }

    /** vmail entra ancora in ogni dominio e in ogni casella? null se si', altrimenti la prima che non va. */
    static String unreadableByVmail() {
        Shell.Result r = Shell.runShell(Duration.ofSeconds(120),
                "find " + root + " -mindepth 1 -maxdepth 2 -type d -print0 | xargs -0 -n 50 su -m vmail -c 'for d; do [ -r \"$d\" ] && [ -x \"$d\" ] || echo \"$d\"; done' sh");
        String out = r.outputTrim();
        return out.isEmpty() ? null : "vmail cannot enter " + out.split("\n")[0];
    }
}
