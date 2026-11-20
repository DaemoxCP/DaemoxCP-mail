package org.daemoxcp.mail.system;

import org.daemoxcp.mail.util.Shell;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFileAttributes;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;

/**
 * Chi si autentica spedisce solo dai suoi indirizzi.
 *
 * <p>Misurato sulla VM il 20/11/2026, installata da zero dal README: Postfix non aveva smtpd_sender_login_maps, quindi
 * una casella autenticata sulla 587 (o dalla webmail) poteva mettere come mittente qualunque indirizzo: un'altra casella
 * dello stesso server, che Rspamd poi firmava con la chiave DKIM del dominio, o un indirizzo di chiunque altro. La
 * documentazione di Postfix (SASL_README, «Envelope sender address authorization»; postconf(5),
 * reject_authenticated_sender_login_mismatch) lo chiude con una tabella dei proprietari degli indirizzi: un client
 * autenticato il cui nome non possiede l'indirizzo del MAIL FROM viene rifiutato (553 5.7.1). Un indirizzo che non ha
 * proprietari, per esempio di un altro dominio, non lo possiede nessuno: rifiutato anche quello.
 *
 * <p>La tabella (scripts.PostfixMaps): una casella possiede il suo indirizzo, e un alias appartiene alla sua
 * destinazione; Postfix cerca nome@dominio e poi @dominio, quindi un catch-all da' alla sua casella gli indirizzi del
 * dominio che non sono ne' caselle ne' alias, gli stessi di cui riceve la posta. Usa la stessa connessione della mappa
 * degli alias (utente di Postfix, MailDbUsers: le colonne che legge le ha gia').
 *
 * <p>Il controllo vale solo per chi si autentica (reject_authenticated_..., non reject_sender_login_mismatch): la posta
 * che arriva dagli altri server sulla 25, quella di sistema (sendmail, senza smtpd) e le risposte automatiche e gli
 * inoltri di Sieve non cambiano. Sta in testa a smtpd_sender_restrictions, prima di permit_mynetworks: la webmail
 * spedisce da 127.0.0.1, autenticata, e deve valere anche per lei.
 *
 * <p>Gli installatori lo scrivono da soli; sui server installati prima lo scrive {@link #ensureAtBoot()}, dopo
 * MailDbUsers e MailboxAddressMap: il file con proprietario, gruppo e permessi della mappa degli alias, postmap -q (una
 * chiave che non c'e' risponde vuoto, una casella risponde se stessa), le due impostazioni solo se dicono quello che
 * scrive il pannello (una configurazione scritta a mano resta com'e'), postfix check e reload. Se una prova non torna
 * main.cf e il file tornano com'erano byte per byte e Postfix si ricarica. Al secondo avvio non fa niente.
 */
public final class SenderLoginMap {

    private static final Logger LOGGER = Logger.getLogger(SenderLoginMap.class.getName());

    public static final String FILE = org.daemoxcp.mail.scripts.PostfixMaps.SENDER_LOGIN_FILE;
    public static final String QUERY = org.daemoxcp.mail.scripts.PostfixMaps.SENDER_LOGIN_QUERY;
    public static final String CHECK = "reject_authenticated_sender_login_mismatch";
    /** smtpd_sender_restrictions come la scrivevano gli installatori prima di questo controllo. */
    static final List<String> PANEL_SENDER = List.of("permit_mynetworks", "permit_sasl_authenticated",
            "reject_non_fqdn_sender", "reject_unknown_sender_domain");
    /** E come la scrivono adesso: lo stesso, col controllo davanti. */
    static final List<String> WANTED_SENDER = MailboxAddressMap.tables(org.daemoxcp.mail.scripts.PostfixMaps.SENDER_RESTRICTIONS);

    private SenderLoginMap() {}

    enum Action { NOTHING, APPLY, LEFT_ALONE }

    record Decision(Action action, String reason) {}

    /**
     * Funzione pura: che cosa fare, da smtpd_sender_login_maps e smtpd_sender_restrictions ({@code postconf -h}).
     *
     * @param aliasesFile se la mappa degli alias del pannello esiste: senza, Postfix non e' quello del pannello
     * @param fileCurrent se il file della tabella dice gia' il testo atteso
     */
    static Decision decide(boolean installed, String configDirectory, boolean aliasesFile, boolean fileCurrent,
                           String loginMaps, String senderRestrictions) {
        if (!installed) return new Decision(Action.NOTHING, "Postfix is not installed");
        if (!aliasesFile) return new Decision(Action.NOTHING, "no " + MailboxAddressMap.ALIASES + ": not the panel's Postfix");
        String own = "mysql:" + configDirectory + "/" + FILE;
        List<String> maps = MailboxAddressMap.tables(loginMaps), restrictions = MailboxAddressMap.tables(senderRestrictions);
        boolean mapsOurs = maps.equals(List.of(own)), restrictionsOurs = restrictions.equals(WANTED_SENDER);
        if (mapsOurs && restrictionsOurs)
            return fileCurrent ? new Decision(Action.NOTHING, "already in place") : new Decision(Action.APPLY, FILE + " does not say what the panel writes");
        if ((maps.isEmpty() || mapsOurs) && (restrictions.equals(PANEL_SENDER) || restrictionsOurs))
            return new Decision(Action.APPLY, "no sender ownership check");
        return new Decision(Action.LEFT_ALONE, "smtpd_sender_login_maps is '" + String.join(", ", maps)
                + "' and smtpd_sender_restrictions '" + String.join(", ", restrictions)
                + "', not the panel's: left as they are, and authenticated clients can still send from any address");
    }

    public static void ensureAtBoot() {
        try {
            boolean installed = Files.isExecutable(Path.of(MailboxAddressMap.POSTCONF));
            String dir = installed ? MailboxAddressMap.postconf("-h", "config_directory") : "";
            boolean aliasesFile = installed && !dir.isEmpty()
                    && Files.isRegularFile(Path.of(dir, MailboxAddressMap.ALIASES), LinkOption.NOFOLLOW_LINKS);
            boolean fileCurrent = true;
            if (aliasesFile) {
                String expected = MailboxAddressMap.mapText(Files.readString(Path.of(dir, MailboxAddressMap.ALIASES), StandardCharsets.UTF_8), QUERY);
                Path own = Path.of(dir, FILE);
                fileCurrent = expected != null && Files.isRegularFile(own, LinkOption.NOFOLLOW_LINKS)
                        && expected.equals(Files.readString(own, StandardCharsets.UTF_8));
            }
            Decision d = decide(installed, dir, aliasesFile, fileCurrent,
                    installed ? MailboxAddressMap.postconf("-h", "smtpd_sender_login_maps") : "",
                    installed ? MailboxAddressMap.postconf("-h", "smtpd_sender_restrictions") : "");
            switch (d.action()) {
                case NOTHING -> { return; }
                case LEFT_ALONE -> { LOGGER.warning("[SenderLoginMap] " + d.reason()); return; }
                case APPLY -> apply(Path.of(dir), d);
            }
        } catch (Throwable t) {
            LOGGER.warning("[SenderLoginMap] ensureAtBoot exception: " + t.getMessage());
        }
    }

    private static void apply(Path dir, Decision d) throws Exception {
        Path aliases = dir.resolve(MailboxAddressMap.ALIASES), file = dir.resolve(FILE), mainCf = dir.resolve("main.cf");
        String text = MailboxAddressMap.mapText(Files.readString(aliases, StandardCharsets.UTF_8), QUERY);
        if (text == null) {
            LOGGER.warning("[SenderLoginMap] " + aliases + " does not have exactly one query line: left as it is");
            return;
        }
        if (!Files.isRegularFile(mainCf, LinkOption.NOFOLLOW_LINKS)) {
            LOGGER.warning("[SenderLoginMap] " + mainCf + " not found: left as it is");
            return;
        }
        if (!Shell.run(Duration.ofSeconds(15), "service", "postfix", "status").success()) {
            LOGGER.info("[SenderLoginMap] Postfix is not running: sender check left as it is, retrying at the next start");
            return;
        }
        byte[] mainBefore = Files.readAllBytes(mainCf);
        PosixFileAttributes mainAttrs = Files.readAttributes(mainCf, PosixFileAttributes.class);
        boolean existed = Files.exists(file, LinkOption.NOFOLLOW_LINKS);
        byte[] fileBefore = existed ? Files.readAllBytes(file) : null;
        PosixFileAttributes fileAttrs = existed ? Files.readAttributes(file, PosixFileAttributes.class) : null;
        boolean checkedBefore = Shell.run(Duration.ofSeconds(60), MailboxAddressMap.POSTFIX, "check").success();
        String own = "mysql:" + dir + "/" + FILE;

        String problem = null;
        try {
            MailboxAddressMap.writeLike(file, text, Files.readAttributes(aliases, PosixFileAttributes.class));
            problem = probe(file);
            if (problem == null) problem = set("smtpd_sender_login_maps", own);
            if (problem == null) problem = set("smtpd_sender_restrictions", String.join(", ", WANTED_SENDER));
            if (problem == null) {
                Shell.Result check = Shell.run(Duration.ofSeconds(60), MailboxAddressMap.POSTFIX, "check");
                if (checkedBefore && !check.success()) problem = "postfix check failed (exit " + check.exitCode() + "): " + check.outputTrim();
            }
            if (problem == null) {
                Shell.Result reload = Shell.run(Duration.ofSeconds(60), MailboxAddressMap.POSTFIX, "reload");
                if (!reload.success()) problem = "postfix reload failed (exit " + reload.exitCode() + "): " + reload.outputTrim();
            }
        } catch (Exception e) {
            problem = e.getClass().getSimpleName() + ": " + e.getMessage();
        }
        if (problem != null) {
            Files.write(mainCf, mainBefore);
            MailboxAddressMap.restoreAttributes(mainCf, mainAttrs);
            if (existed) {
                Files.write(file, fileBefore);
                MailboxAddressMap.restoreAttributes(file, fileAttrs);
            } else {
                Files.deleteIfExists(file);
            }
            Shell.run(Duration.ofSeconds(60), MailboxAddressMap.POSTFIX, "reload");
            LOGGER.warning("[SenderLoginMap] ROLLED_BACK: " + problem + "; main.cf and " + FILE + " back as they were");
            return;
        }
        LOGGER.info("[SenderLoginMap] DONE: an authenticated client sends only from its own addresses (its mailbox, the"
                + " aliases that point to it): " + file + ", " + CHECK + " first in smtpd_sender_restrictions (" + d.reason() + ")");
    }

    /** postconf -e e la rilettura: il valore deve essere quello scritto. Null se e' cosi'. */
    private static String set(String name, String value) {
        Shell.Result r = Shell.run(Duration.ofSeconds(30), MailboxAddressMap.POSTCONF, "-e", name + " = " + value);
        if (!r.success()) return "postconf -e " + name + " failed (exit " + r.exitCode() + "): " + r.outputTrim();
        String now = String.join(", ", MailboxAddressMap.tables(MailboxAddressMap.postconf("-h", name)));
        String want = String.join(", ", MailboxAddressMap.tables(value));
        return now.equals(want) ? null : name + " is now '" + now + "' instead of '" + want + "'";
    }

    /** Una chiave che non c'e' risponde vuoto; una casella risponde se stessa (fra i suoi proprietari). */
    private static String probe(Path file) {
        Shell.Result r = Shell.run(Duration.ofSeconds(30), MailboxAddressMap.POSTMAP, "-q", MailDbUsers.PROBE, "mysql:" + file);
        if (!MailDbUsers.postmapAnswered(r)) return "postmap -q fails on " + FILE + " (exit " + r.exitCode() + "): " + r.outputTrim();
        String mailbox = MailboxAddressMap.anyMailbox();
        if (mailbox == null) return null;
        Shell.Result m = Shell.run(Duration.ofSeconds(30), MailboxAddressMap.POSTMAP, "-q", mailbox, "mysql:" + file);
        List<String> owners = new ArrayList<>(MailboxAddressMap.tables(m.outputTrim()));
        if (!m.success() || !owners.contains(mailbox))
            return "postmap -q on a mailbox does not answer the mailbox itself (exit " + m.exitCode() + ")";
        return null;
    }
}
