package org.mail_panel.security;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFileAttributes;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * La copia in chiaro del token di Cloudflare che acme.sh si tiene: tolta.
 *
 * Quando la sfida passa da Cloudflare (dns_cf), acme.sh salva il token che riceve (SAVED_CF_Token, e
 * SAVED_CF_Account_ID) nel suo account.conf, per i rinnovi che farebbe da se'. Ma acme.sh da se' non rinnova niente:
 * il suo cron lo toglie AcmeUser, e ogni emissione e rinnovo li lancia il pannello, che il token glielo passa ogni
 * volta (CF_Token, decifrato da MySQL: CloudflareTokens). Quella copia serviva solo a chi la trovava: un token che
 * scrive i DNS di tutte le zone dell'account, in chiaro su disco. Vista sul server vero il 17/11/2026, in
 * /var/db/acme/.acme.sh/account.conf, dopo aver cifrato quella nel database.
 *
 * Si tolgono solo le righe SAVED_CF_; il resto del file resta com'era, con proprietario e permessi, scritto accanto e
 * rinominato al suo posto. Un account.conf che e' un collegamento, o un file con piu' nomi, si lascia e si dice.
 */
public final class AcmeCloudflareCopy {

    private static final Logger LOGGER = Logger.getLogger(AcmeCloudflareCopy.class.getName());

    /** Una riga di account.conf con una copia salvata dal modulo di Cloudflare. */
    static final Pattern SAVED = Pattern.compile("(?m)^SAVED_CF_([A-Za-z_]+)=.*(?:\\r?\\n|$)");

    enum Outcome { NOTHING, DONE, LEFT }

    record Report(Outcome outcome, String detail) {}

    private AcmeCloudflareCopy() {}

    static Report forget(Path accountConf) throws IOException {
        if (!Files.exists(accountConf, LinkOption.NOFOLLOW_LINKS)) return new Report(Outcome.NOTHING, "");
        if (!SafeOwnership.safeToChange(accountConf) || Files.isDirectory(accountConf, LinkOption.NOFOLLOW_LINKS))
            return new Report(Outcome.LEFT, accountConf + " is a link or has more than one name: left as it is");
        String text = Files.readString(accountConf, StandardCharsets.UTF_8);
        Matcher m = SAVED.matcher(text);
        List<String> keys = new ArrayList<>();
        while (m.find()) keys.add("SAVED_CF_" + m.group(1));
        if (keys.isEmpty()) return new Report(Outcome.NOTHING, "");
        Path next = accountConf.resolveSibling("." + accountConf.getFileName() + ".panel-new");
        try {
            Files.deleteIfExists(next);
            Files.writeString(next, SAVED.matcher(text).replaceAll(""), StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
            PosixFileAttributes a = Files.readAttributes(accountConf, PosixFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
            PosixFileAttributeView v = Files.getFileAttributeView(next, PosixFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
            v.setPermissions(a.permissions());
            v.setOwner(a.owner());
            v.setGroup(a.group());
            Files.move(next, accountConf, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        } finally {
            Files.deleteIfExists(next);
        }
        return new Report(Outcome.DONE, accountConf + ": removed " + keys);
    }

    /** Dopo ogni acme.sh a cui il pannello ha passato il token. */
    static void afterRun(AcmeUser.Layout l) {
        if (l != null) report(Path.of(l.home(), "account.conf"));
    }

    /** All'avvio: le copie scritte prima di questa versione. */
    public static void ensureAtBoot() {
        AcmeUser.Layout l = AcmeUser.layout();
        if (l != null) report(Path.of(l.home(), "account.conf"));
    }

    private static void report(Path accountConf) {
        try {
            Report r = forget(accountConf);
            if (r.outcome() == Outcome.NOTHING) return;
            String line = "[AcmeCloudflareCopy] " + r.outcome() + ": " + r.detail();
            if (r.outcome() == Outcome.DONE) LOGGER.info(line); else LOGGER.warning(line);
        } catch (Throwable t) {
            LOGGER.warning("[AcmeCloudflareCopy] " + accountConf + ": " + t);
        }
    }
}
