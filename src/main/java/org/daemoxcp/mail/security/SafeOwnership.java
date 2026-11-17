package org.daemoxcp.mail.security;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;

/**
 * Dare a un utente una cartella e tutto quello che contiene, da root, senza dargli anche file di altri.
 *
 * Un collegamento simbolico lo si sapeva gia' (non si segue). Ma anche un collegamento fisso: su FreeBSD chiunque
 * puo' fare un hard link a un file di un altro utente sullo stesso file system (security.bsd.hardlink_check_uid e' 0
 * per impostazione predefinita), e il link E' quel file. /var/vmail sta nello stesso file system di /etc (nel boot
 * environment, sul server vero come sulla VM): vmail faceva un hard link a un file di root dentro /var/vmail, e il
 * «chown -R vmail:vmail /var/vmail» che root esegue a ogni rigenerazione delle cartelle della posta gli dava quel
 * file. Con /etc/master.passwd, root. Misurato sulla VM il 17/11/2026 con un file di prova (reperto 252).
 *
 * Quindi si cambia il proprietario solo di cartelle e di file regolari con un solo nome; un file con piu' nomi non e'
 * solo di quella cartella e resta com'e', detto nel registro. Le cartelle non possono avere hard link.
 */
public final class SafeOwnership {

    private SafeOwnership() {}

    /** Vero se root puo' cambiare proprietario e permessi di p senza toccare altro: cartella, o file con un solo nome. */
    public static boolean safeToChange(Path p) throws IOException {
        BasicFileAttributes a = Files.readAttributes(p, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        if (a.isSymbolicLink()) return false;
        if (a.isDirectory()) return true;
        if (!a.isRegularFile()) return false;
        Object n = Files.getAttribute(p, "unix:nlink", LinkOption.NOFOLLOW_LINKS);
        return n instanceof Integer i && i == 1;
    }

    /**
     * Il pezzo di script che da' dir e il suo contenuto a owner:group: solo cartelle e file con un solo nome, sullo
     * stesso file system, mai attraverso un collegamento (find non li segue). I file con piu' nomi non suoi si
     * contano e si dicono. dir, owner e group sono nomi del pannello, mai valori arrivati da fuori.
     */
    public static String shell(String dir, String owner, String group) {
        check(dir, owner, group);
        String target = owner + ":" + group;
        return "find '" + dir + "' -xdev \\( -type d -o \\( -type f -links 1 \\) \\) ! \\( -user " + owner + " -group "
                + group + " \\) -exec chown " + target + " {} + 2>/dev/null\n"
             + "SAFE_OWNERSHIP_LEFT=$(find '" + dir + "' -xdev ! -type d ! -type l -links +1 ! -user " + owner
                + " 2>/dev/null | wc -l | tr -d ' ')\n"
             + "[ \"$SAFE_OWNERSHIP_LEFT\" = 0 ] || echo \"WARNING: $SAFE_OWNERSHIP_LEFT file(s) in " + dir
                + " with more than one name were not given to " + owner + ": look at them (find " + dir
                + " -links +1 ! -user " + owner + ")\"\n";
    }

    private static void check(String dir, String owner, String group) {
        if (!dir.matches("/[A-Za-z0-9._/-]+") || dir.contains(".."))
            throw new IllegalArgumentException("not a panel folder: " + dir);
        if (!owner.matches("[a-z_][a-z0-9_-]*") || !group.matches("[a-z_][a-z0-9_-]*"))
            throw new IllegalArgumentException("not a user or group name: " + owner + ":" + group);
    }
}
