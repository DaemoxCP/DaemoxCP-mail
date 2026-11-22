package org.daemoxcp.mail.system;

import org.daemoxcp.mail.util.Shell;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Duration;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * ManageSieve (la porta 4190) solo sulla macchina stessa.
 *
 * Misurato il 20/11/2026 installando da zero dal README sulla VM: Dovecot ascoltava la 4190 su tutte le interfacce
 * (`*:4190`), anche dopo il primo avvio del pannello. Da fuori la fermava pf, che non la apre, ma il README la da' per
 * «solo locale», ed e' l'unico che la usa: Roundcube, col plugin managesieve, su 127.0.0.1:4190 (RoundcubeScript). Un
 * servizio che nessuno deve raggiungere da fuori non deve nemmeno essere in ascolto fuori: se un giorno pf venisse
 * spento o riscritto a mano, la porta resterebbe chiusa lo stesso.
 *
 * Il file conf.d/10-managesieve-local.conf aggiunge al listener «sieve» di managesieve-login l'indirizzo 127.0.0.1;
 * la porta resta quella del file principale, perche' Dovecot unisce i blocchi con lo stesso nome. Nella 2.3 la riga si
 * chiama address, nella 2.4 listen (la 2.4 rifiuta address: «Unknown setting», visto sul listener LMTP). L'installatore
 * lo scrive da adesso (DovecotConfig); sui server installati prima lo scrive questa riparazione all'avvio, con lo stesso
 * contenuto. Prima di toccare qualcosa controlla che l'autenticazione funzioni; dopo, che Dovecot giri, che
 * l'autenticazione funzioni ancora, che IMAP sia in ascolto e che la 4190 risponda su 127.0.0.1 e solo li'. Se
 * qualcosa non torna toglie il file e riavvia: Dovecot torna com'era. Al secondo avvio non fa niente.
 */
public final class ManageSieveLocal {

    private static final Logger LOGGER = Logger.getLogger(ManageSieveLocal.class.getName());

    public static final String FILE_NAME = "10-managesieve-local.conf";
    static final String DOVECOT = "/usr/local/sbin/dovecot";
    static final String ADDRESS = "127.0.0.1";
    static final int PORT = 4190;

    private static final Pattern VERSION = Pattern.compile("^(\\d+)\\.(\\d+)");

    private ManageSieveLocal() {}

    /** Il contenuto del file: lo stesso per l'installatore (DovecotConfig) e per la riparazione. */
    public static String fileContent(boolean dovecot24) {
        return "# " + PanelMarker.WRITTEN + ".\n"
             + "# ManageSieve (4190) only on the machine itself: only the webmail uses it, on " + ADDRESS + ".\n"
             + "service managesieve-login {\n"
             + "  inet_listener sieve {\n"
             + "    " + (dovecot24 ? "listen" : "address") + " = " + ADDRESS + "\n"
             + "  }\n"
             + "}\n";
    }

    /** Vero per Dovecot 2.4 e successivi, dall'uscita di `dovecot --version` («2.4.5 (...)»); falso se non si capisce. */
    static boolean is24(String version) {
        Matcher m = VERSION.matcher(version == null ? "" : version.trim());
        if (!m.find()) return false;
        int major = Integer.parseInt(m.group(1)), minor = Integer.parseInt(m.group(2));
        return major > 2 || (major == 2 && minor >= 4);
    }

    /**
     * Gli indirizzi su cui Dovecot ascolta la 4190, dall'uscita di `sockstat -46l -P tcp -p 4190`: per esempio
     * «*:4190» oppure «127.0.0.1:4190». Funzione pura, per provarla.
     */
    static java.util.List<String> listening(String sockstat) {
        java.util.List<String> out = new java.util.ArrayList<>();
        if (sockstat == null) return out;
        for (String line : sockstat.split("\n")) {
            String[] f = line.trim().split("\\s+");
            if (f.length < 6 || !f[1].startsWith("dovecot")) continue;
            if (f[5].endsWith(":" + PORT)) out.add(f[5]);
        }
        return out;
    }

    /** Solo su 127.0.0.1: nessun altro indirizzo in ascolto sulla 4190. */
    static boolean onlyLocal(java.util.List<String> addresses) {
        return !addresses.isEmpty() && addresses.stream().allMatch((ADDRESS + ":" + PORT)::equals);
    }

    public static void ensureAtBoot() {
        try {
            if (!Files.isExecutable(Path.of(DovecotAuthWorker.DOVECONF)) || !Files.isExecutable(Path.of(DOVECOT))) return;
            Path file = Path.of(DovecotAuthWorker.CONF_D, FILE_NAME);
            Shell.Result version = Shell.run(Duration.ofSeconds(15), DOVECOT, "--version");
            if (!version.success()) return;
            String wanted = fileContent(is24(version.outputTrim()));
            if (Files.isRegularFile(file) && wanted.equals(Files.readString(file, StandardCharsets.UTF_8))) return;
            if (!Shell.run(Duration.ofSeconds(15), DovecotAuthWorker.DOVECONF, "-n").output().contains("managesieve-login")) return;
            apply(file, wanted);
        } catch (Throwable t) {
            LOGGER.warning("[ManageSieveLocal] ensureAtBoot exception: " + t.getMessage());
        }
    }

    static boolean apply(Path file, String content) throws Exception {
        if (!DovecotAuthWorker.running()) {
            LOGGER.info("[ManageSieveLocal] Dovecot is not running: ManageSieve left as it is, retrying at the next start");
            return false;
        }
        int before = DovecotAuthWorker.lookup();
        if (!DovecotAuthWorker.LOOKUP_OK.contains(before)) {
            LOGGER.warning("[ManageSieveLocal] authentication already fails before any change (doveadm auth lookup exit "
                    + before + "): ManageSieve left as it is");
            return false;
        }
        Path saved = Files.exists(file) ? Files.createTempFile(file.getParent().getParent(), ".managesieve-", ".saved") : null;
        if (saved != null) Files.copy(file, saved, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.COPY_ATTRIBUTES);
        try {
            write(file, content);
            Shell.Result check = Shell.run(Duration.ofSeconds(15), DovecotAuthWorker.DOVECONF, "-n");
            if (!check.success()) {
                putBack(file, saved, false);
                LOGGER.warning("[ManageSieveLocal] ROLLED_BACK: doveconf refuses the setting (" + firstLine(check.outputTrim())
                        + "): nothing changed");
                return false;
            }
            // Un listener che cambia indirizzo si riapre solo col riavvio: con il reload Dovecot tiene quello aperto.
            restart();
            String problem = verify();
            if (problem != null) {
                putBack(file, saved, true);
                LOGGER.warning("[ManageSieveLocal] ROLLED_BACK: " + problem + "; everything put back");
                return false;
            }
            LOGGER.info("[ManageSieveLocal] DONE: ManageSieve (" + PORT + ") listens only on " + ADDRESS
                    + ", where the webmail reaches it (" + file + ")");
            return true;
        } finally {
            if (saved != null) Files.deleteIfExists(saved);
        }
    }

    /** Dopo il riavvio: Dovecot gira, l'autenticazione passa, IMAP ascolta, la 4190 risponde solo su 127.0.0.1. */
    static String verify() throws InterruptedException {
        String last = "Dovecot did not come back";
        for (int i = 0; i < 20; i++) {
            Thread.sleep(500);
            if (!DovecotAuthWorker.running()) { last = "Dovecot is not running after the restart"; continue; }
            int rc = DovecotAuthWorker.lookup();
            if (!DovecotAuthWorker.LOOKUP_OK.contains(rc)) { last = "doveadm auth lookup fails (exit " + rc + ")"; continue; }
            String socks = Shell.run(Duration.ofSeconds(15), "sockstat", "-46l", "-P", "tcp").output();
            if (!socks.contains(":993") && !socks.contains(":143")) { last = "IMAP is not listening"; continue; }
            java.util.List<String> sieve = listening(socks);
            if (!onlyLocal(sieve)) { last = "port " + PORT + " listens on " + sieve; continue; }
            if (!greets()) { last = "ManageSieve does not answer on " + ADDRESS + ":" + PORT; continue; }
            return null;
        }
        return last;
    }

    /** La 4190 su 127.0.0.1 saluta come ManageSieve: una riga che comincia con «"IMPLEMENTATION"». */
    static boolean greets() {
        try (Socket s = new Socket()) {
            s.connect(new InetSocketAddress(ADDRESS, PORT), 3000);
            s.setSoTimeout(3000);
            BufferedReader in = new BufferedReader(new InputStreamReader(s.getInputStream(), StandardCharsets.UTF_8));
            String first = in.readLine();
            return first != null && first.startsWith("\"IMPLEMENTATION\"");
        } catch (Exception e) {
            return false;
        }
    }

    static void restart() throws InterruptedException {
        Shell.run(Duration.ofSeconds(60), "service", "dovecot", "restart");
        Thread.sleep(1000);
    }

    private static void write(Path file, String content) throws Exception {
        Path tmp = file.resolveSibling("." + file.getFileName() + ".tmp");
        Files.writeString(tmp, content, StandardCharsets.UTF_8);
        Files.setPosixFilePermissions(tmp, PosixFilePermissions.fromString("rw-r--r--"));
        Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
    }

    private static void putBack(Path file, Path saved, boolean restart) throws Exception {
        if (saved != null) Files.copy(saved, file, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.COPY_ATTRIBUTES);
        else Files.deleteIfExists(file);
        if (restart) restart();
    }

    private static String firstLine(String s) {
        if (s == null) return "";
        int i = s.indexOf('\n');
        return i < 0 ? s : s.substring(0, i);
    }
}
