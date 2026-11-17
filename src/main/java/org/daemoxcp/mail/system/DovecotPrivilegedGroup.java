package org.daemoxcp.mail.system;

import org.daemoxcp.mail.security.RootOnlyPath;
import org.daemoxcp.mail.util.Shell;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFileAttributes;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;
import java.util.regex.Pattern;

/**
 * I processi delle caselle di Dovecot senza il gruppo mail (reperto 221).
 *
 * <p>Il pannello scriveva {@code mail_privileged_group = mail} in dovecot.conf, 2.3 e 2.4. Con quello ogni processo di
 * una casella (imap, pop3, lmtp, managesieve: quelli che parlano con la rete) tiene il gruppo mail come gruppo salvato e
 * se lo puo' riprendere quando vuole: misurato sulla VM, {@code procstat -s} di un imap di vmail da' SVGID 6. Il gruppo
 * mail scrive in /var/mail, dove stanno le regole Sieve del pannello.
 *
 * <p>Non serviva: la documentazione di Dovecot (2.3, wiki MailLocation.mbox, QuickConfiguration, BasicConfiguration) lo
 * usa solo per creare la INBOX e i file di blocco delle caselle mbox in /var/mail. Il pannello tiene la posta in
 * Maildir sotto /var/vmail. Misurato sulla VM senza la riga: accesso IMAP, SMTP AUTH, ManageSieve e consegna con le
 * regole del pannello tutti a posto, e l'imap con SVGID 5000 invece di 6. Sulla 2.4 non misurato.
 *
 * <p>L'installatore non la scrive piu' (DovecotConfig); sui server installati prima la toglie questo passaggio, solo se
 * e' la riga esatta del pannello, in un dovecot.conf scritto dal pannello, e se Dovecot non tiene posta in mbox. Dopo:
 * doveconf deve accettare il file e non dare piu' il gruppo, Dovecot ricaricarsi, e un imap vero di una casella entrare
 * e girare senza il gruppo mail. Se una cosa sola non torna, il file torna com'era e Dovecot si ricarica. Le sessioni gia'
 * aperte tengono il gruppo finche' non si ricollegano. Al secondo avvio non trova niente da fare.
 */
public final class DovecotPrivilegedGroup {

    private static final Logger LOGGER = Logger.getLogger(DovecotPrivilegedGroup.class.getName());

    static final Path CONF = Path.of("/usr/local/etc/dovecot/dovecot.conf");
    static final String LINE = "mail_privileged_group = mail\n";
    /** La prima riga del dovecot.conf che scrive il pannello, 2.3 e 2.4 (DovecotConfig). */
    static final List<String> HEADERS = headers();

    /** Le due prime righe (2.3 e 2.4) con la firma di adesso e con quelle di prima (sezione "dovecotSignature"). */
    private static List<String> headers() {
        List<String> out = new java.util.ArrayList<>();
        for (String s : PanelMarker.forms("dovecotSignature", org.daemoxcp.mail.scripts.DovecotConfig.SIGNATURE)) {
            out.add("# Dovecot — " + s + "\n");
            out.add("# Dovecot 2.4 — " + s + "\n");
        }
        return List.copyOf(out);
    }
    static final String DOVECONF = "/usr/local/bin/doveconf";
    static final String DOVEADM = "/usr/local/bin/doveadm";
    static final String PROCSTAT = "/usr/bin/procstat";
    static final Path GROUPS = Path.of("/etc/group");
    static final Path VMAIL = Path.of("/var/vmail");

    private DovecotPrivilegedGroup() {}

    // ===================== Funzioni pure =====================

    /**
     * dovecot.conf senza la riga del pannello, o null se non c'e' niente da fare: non e' il file del pannello, la riga
     * non c'e' (gia' fatto), c'e' due volte o scritta in un altro modo (allora non e' sua, e resta com'e').
     */
    static String migrated(String conf) {
        if (conf == null || HEADERS.stream().noneMatch(conf::startsWith)) return null;
        String line = "\n" + LINE;
        int at = conf.indexOf(line);
        if (at < 0 || conf.indexOf(line, at + 1) >= 0) return null;
        return conf.substring(0, at + 1) + conf.substring(at + line.length());
    }

    private static final Pattern MBOX = Pattern.compile(
            "(?m)^\\s*(mail_location\\s*=\\s*mbox:|mail_driver\\s*=\\s*mbox\\s*$|mail_inbox_path\\s*=)|INBOX=/var/mail");

    /** Vero se, secondo `doveconf -n`, Dovecot tiene posta in mbox: li' il gruppo mail serve per /var/mail. */
    static boolean usesMbox(String doveconfN) {
        return doveconfN != null && MBOX.matcher(doveconfN).find();
    }

    /** Il numero del gruppo dal testo di /etc/group, o -1. */
    static int gidOf(String groupFile, String name) {
        if (groupFile == null) return -1;
        for (String l : groupFile.split("\n")) {
            String[] f = l.split(":", -1);
            if (f.length >= 3 && f[0].equals(name) && f[2].matches("\\d{1,9}")) return Integer.parseInt(f[2]);
        }
        return -1;
    }

    /**
     * Vero se la riga di `procstat -s` (PID COMM EUID RUID SVUID EGID RGID SVGID UMASK FLAGS GROUPS) ha il gruppo fra
     * effettivo, reale, salvato o aggiuntivi.
     */
    static boolean keepsGroup(String procstatLine, int gid) {
        String[] t = procstatLine.trim().split("\\s+");
        if (t.length < 11) return true;
        String g = Integer.toString(gid);
        if (t[5].equals(g) || t[6].equals(g) || t[7].equals(g)) return true;
        for (String x : t[t.length - 1].split(",")) if (x.equals(g)) return true;
        return false;
    }

    // ===================== All'avvio =====================

    /** All'avvio della parte root. */
    public static void ensureAtBoot() {
        try {
            String r = ensure();
            if (r == null) return;
            if (r.startsWith("DONE")) LOGGER.info("[DovecotPrivilegedGroup] " + r);
            else LOGGER.warning("[DovecotPrivilegedGroup] " + r);
        } catch (Throwable t) {
            LOGGER.warning("[DovecotPrivilegedGroup] failed: " + t);
        }
    }

    /** Null se non c'era niente da fare; altrimenti com'e' andata (DONE, ROLLED_BACK, o perche' resta com'e'). */
    static synchronized String ensure() throws Exception {
        if (!Files.isRegularFile(CONF, LinkOption.NOFOLLOW_LINKS) || !Files.isExecutable(Path.of(DOVECONF))) return null;
        String before = new String(RootOnlyPath.read(CONF, 1 << 20), StandardCharsets.UTF_8);
        String after = migrated(before);
        if (after == null) return null;
        Shell.Result n = Shell.run(Duration.ofSeconds(15), DOVECONF, "-n");
        if (!n.success()) return "left as it is: doveconf does not accept the configuration as it is (" + first(n.outputTrim()) + ")";
        if (usesMbox(n.output())) return "left as it is: Dovecot keeps mail in mbox, where the group mail is needed for /var/mail";
        PosixFileAttributes like = Files.readAttributes(CONF, PosixFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        write(after, like);
        if (!Shell.run(Duration.ofSeconds(15), DOVECONF, "-n").success())
            return putBack(before, like, false, "doveconf refuses the configuration without the line");
        Shell.Result g = Shell.run(Duration.ofSeconds(15), DOVECONF, "-h", "mail_privileged_group");
        if (!g.success() || !g.outputTrim().isEmpty())
            return putBack(before, like, false, "doveconf still gives mail_privileged_group = " + first(g.outputTrim()));
        String done = "DONE: Dovecot's mail processes no longer keep the group mail (" + LINE.trim() + " served only mbox"
                + " INBOXes in /var/mail; the mail is Maildir under " + VMAIL + ")";
        if (!running()) return done + "; Dovecot is not running, it reads it at the start";
        if (!reload()) return putBack(before, like, true, "Dovecot did not reload");
        String mailbox = SieveStorage.someMailbox(VMAIL);
        if (mailbox == null) return done + "; Dovecot reloaded, no mailbox to try a login with";
        String why = verify(mailbox, gidOf(Files.readString(GROUPS), "mail"));
        if (why != null) return putBack(before, like, true, why);
        return done + "; Dovecot reloaded, an imap of " + mailbox + " logs in without it; sessions already open keep it until"
                + " they reconnect";
    }

    /** Dopo il reload: un imap vero della casella entra, e gira senza il gruppo. Riprova per 10 s: auth si riavvia. */
    static String verify(String mailbox, int gid) throws Exception {
        if (gid < 0) return "the group mail is not in " + GROUPS;
        String last = "";
        for (int i = 0; i < 10; i++) {
            String[] p = userProcess(mailbox);
            if (p[0] != null) return keepsGroup(p[0], gid) ? "an imap of " + mailbox + " still has the group mail: " + p[0].trim() : null;
            last = p[1];
            Thread.sleep(1000);
        }
        return "doveadm exec imap -u " + mailbox + " does not log in after the reload (" + first(last) + ")";
    }

    /**
     * Un imap vero della casella, come lo fa partire Dovecot con la sua configurazione: {@code doveadm exec imap -u}, che
     * diventa imap (stesso pid). Appena dice PREAUTH, la sua riga di `procstat -s`; poi LOGOUT. {riga o null, uscita}.
     */
    static String[] userProcess(String mailbox) throws Exception {
        ProcessBuilder pb = new ProcessBuilder(DOVEADM, "exec", "imap", "-u", mailbox).redirectErrorStream(true);
        Process p = pb.start();
        StringBuilder out = new StringBuilder();
        CountDownLatch in = new CountDownLatch(1);
        Thread reader = Thread.ofVirtual().start(() -> {
            try (BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8))) {
                for (String l; (l = r.readLine()) != null; ) {
                    synchronized (out) { if (out.length() < 4096) out.append(l).append('\n'); }
                    if (l.startsWith("* PREAUTH")) in.countDown();
                }
            } catch (IOException ignored) {
                // il processo e' finito
            }
        });
        String line = null;
        try {
            if (in.await(15, TimeUnit.SECONDS)) {
                Shell.Result s = Shell.run(Duration.ofSeconds(10), PROCSTAT, "-s", Long.toString(p.pid()));
                String[] rows = s.outputTrim().split("\n");
                if (s.success() && rows.length >= 2) line = rows[rows.length - 1];
            }
            try (OutputStream o = p.getOutputStream()) {
                o.write("a LOGOUT\r\n".getBytes(StandardCharsets.US_ASCII));
            } catch (IOException ignored) {
                // gia' uscito
            }
            if (!p.waitFor(10, TimeUnit.SECONDS)) p.destroyForcibly();
            reader.join(Duration.ofSeconds(5));
        } finally {
            if (p.isAlive()) p.destroyForcibly();
        }
        synchronized (out) { return new String[]{line, out.toString()}; }
    }

    // ===================== I pezzi =====================

    static boolean running() {
        return Shell.run(Duration.ofSeconds(15), "service", "dovecot", "status").success();
    }

    static boolean reload() throws InterruptedException {
        boolean ok = Shell.run(Duration.ofSeconds(60), "service", "dovecot", "reload").success();
        Thread.sleep(1000);
        return ok;
    }

    private static void write(String content, PosixFileAttributes like) throws IOException {
        RootOnlyPath.replace(CONF.getParent(), CONF.getFileName().toString(), content.getBytes(StandardCharsets.UTF_8),
                like.owner(), like.group(), like.permissions());
    }

    private static String putBack(String before, PosixFileAttributes like, boolean reload, String why) throws Exception {
        write(before, like);
        if (reload && running()) reload();
        return "ROLLED_BACK: " + why + "; " + CONF + " put back as it was";
    }

    private static String first(String s) {
        int i = s.indexOf('\n');
        String t = i < 0 ? s : s.substring(0, i);
        return t.length() > 200 ? t.substring(0, 200) : t;
    }
}
