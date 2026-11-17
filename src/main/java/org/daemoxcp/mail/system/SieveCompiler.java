package org.daemoxcp.mail.system;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.PosixFilePermissions;
import java.nio.file.attribute.UserPrincipalLookupService;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * sievec di Pigeonhole senza root (reperto 218).
 *
 * <p>Le regole Sieve del pannello stanno in /var/mail/sieve/dominio/nome/.dovecot.sieve, di root apposta (reperto 214):
 * Dovecot, che consegna come vmail, le legge e non le puo' riscrivere. Per la stessa ragione non puo' salvarne il
 * compilato accanto, e senza compilato le ricompila a ogni messaggio: la documentazione di Pigeonhole (2.3 e 2.4) dice
 * che gli script di tipo «before» li precompila l'amministratore con sievec. Fino al 10/11/2026 il pannello lanciava
 * sievec da root, e root analizzava un testo fatto di quello che un amministratore scrive nei filtri e nella risposta
 * automatica, che col pannello separato arriva da MySQL, dove scrive anche la parte web. A sievec root non serve (il
 * manuale: «performed manually by an authorized user»): serviva solo perche' il compilato finisce in una cartella di
 * root.
 *
 * <p>Adesso:
 * <ul>
 *   <li>sievec gira con l'utente sievec (PanelUser: senza password, shell ne' casa, un gruppo suo e nessun altro
 *       dentro), con l'ambiente vuoto e una configurazione minima passata con -c. Quella di Dovecot contiene segreti e
 *       nessun utente qualunque la legge (misurato: doveconf si ferma su auth-sql.conf.ext). La minima ha solo le due
 *       righe di versione che la 2.4 pretende, prese da dovecot.conf; per la 2.3 e' vuota. Le estensioni restano
 *       quelle predefinite di Pigeonhole, che sono anche quelle della configurazione del pannello (nella 2.3 la sua
 *       riga sieve_extensions aggiunge con + solo estensioni gia' predefinite, nella 2.4 non c'e'). Misurato sulla
 *       VM: il compilato e' identico byte per byte a quello di root con la configurazione vera, sulla 2.3.21 e sulla
 *       2.4.5 (questa in un clone del boot environment, con la configurazione 2.4 del pannello). Nella 2.4 -c /dev/null
 *       e le righe date con -o non bastano («dovecot_storage_version setting must be set»): servono nel file; e
 *       doveconf, da un utente qualunque, scrive un suo file temporaneo in /tmp;</li>
 *   <li>non vmail: chi consegna potrebbe allora mettere le mani sul compilato che root installa, e riscrivere cosi'
 *       le regole del pannello, proprio quello che il reperto 214 gli toglie;</li>
 *   <li>sievec compila lo script al suo percorso vero, perche' il compilato lo porta scritto dentro («location», e la
 *       2.4 lo confronta), e lo salva in una cartella sua dentro una cartella di lavoro di root che lui non puo'
 *       cambiare;</li>
 *   <li>root il compilato non lo apre: lo legge sievec stesso con cat, cosi' un collegamento a un file che sievec non
 *       puo' leggere non diventa un compilato leggibile da tutti. Root lo scrive accanto allo script con proprietario,
 *       gruppo e permessi dello script, come li dava sievec di root salvando accanto allo script, e lo mette al suo
 *       posto con un rename, senza seguire collegamenti e solo se nessun altro puo' cambiare le cartelle da / allo
 *       script (RootOnlyPath, reperto 221). Il compilato nasce dopo lo script, quindi e' piu' nuovo, come Pigeonhole vuole (confronta
 *       i tempi al nanosecondo, e se sono uguali ricompila);</li>
 *   <li>se l'utente non si puo' avere, se sievec non legge lo script, o se dice 0 ma il compilato non c'e' (sievec
 *       esce 0 anche quando non riesce a salvarlo: misurato), il compilato non si installa: Dovecot ricompila a ogni
 *       consegna, lento ma giusto. Mai root al suo posto.</li>
 * </ul>
 */
public final class SieveCompiler {

    private static final Logger LOGGER = Logger.getLogger(SieveCompiler.class.getName());

    /** L'utente e il gruppo con cui gira sievec. */
    public static final String USER = "sievec";
    static final PanelUser COMPILER_USER = new PanelUser(USER, "Mail panel Sieve compiler");

    static final String CHROOT = "/usr/sbin/chroot";
    static final String CAT = "/bin/cat";
    static final String FIND = "/usr/bin/find";
    static final List<String> SIEVEC_PLACES = List.of("/usr/local/bin/sievec", "/usr/bin/sievec", "/usr/local/libexec/dovecot/sievec");
    static final Path DOVECOT_CONF = Path.of("/usr/local/etc/dovecot/dovecot.conf");
    /**
     * Dove nasce la cartella di lavoro: /tmp, non java.io.tmpdir. sievec deve poterci passare, e una java.io.tmpdir
     * spostata con mailpanel_opts in una cartella chiusa fermerebbe ogni compilazione senza dire perche'.
     */
    static final Path WORK_BASE = Path.of("/tmp");

    /** Nella cartella di lavoro: la configurazione minima, lo script da validare, la cartella di sievec e il suo compilato. */
    static final String CONF = "dovecot.conf";
    static final String TEXT = "script.sieve";
    static final String OUT = "out";
    static final String BINARY = "compiled.svbin";

    static final Duration TIMEOUT = Duration.ofSeconds(60);
    /** Un compilato piu' grande non e' delle regole del pannello (Pigeonhole rifiuta script oltre 1 MB). */
    static final int MAX_BINARY = 16 << 20;
    static final int MAX_TEXT = 64 << 10;

    private SieveCompiler() {}

    /** COMPILED: fatto. REFUSED: lo script ha errori (sievec li dice riga per riga). NOT_COMPILED: non si e' potuto. */
    /** UNCHANGED: compilato, ed era gia' uguale a quello accanto allo script (SieveBinaries, reperto 241). */
    public enum Status { COMPILED, UNCHANGED, REFUSED, NOT_COMPILED }

    /** L'esito, col testo di sievec o il motivo. */
    public record Outcome(Status status, String message) {
        public boolean refused() { return status == Status.REFUSED; }
    }

    private static Outcome notCompiled(String why) {
        return new Outcome(Status.NOT_COMPILED, why);
    }

    /** Dove sta sievec, o null se Pigeonhole non e' installato. */
    public static String sievec() {
        for (String p : SIEVEC_PLACES) if (Files.isExecutable(Path.of(p))) return p;
        return null;
    }

    // ===================== Compilare e validare =====================

    /**
     * Compila lo script al suo percorso e installa il compilato accanto (nome.sieve -> nome.svbin), come lo farebbe
     * sievec di root, ma con sievec che gira come {@link #USER}.
     */
    public static Outcome compile(Path script) {
        return compile(script, false);
    }

    /**
     * Come {@link #compile(Path)}, ma il compilato accanto allo script si sostituisce solo se e' diverso da quello che il
     * sievec installato fa adesso: UNCHANGED se era gia' quello (reperto 241). Il compilato e' deterministico.
     */
    public static Outcome refresh(Path script) {
        return compile(script, true);
    }

    private static Outcome compile(Path script, boolean onlyIfDifferent) {
        String sievec = sievec();
        if (sievec == null) return notCompiled("sievec is not installed");
        Path s = script.toAbsolutePath().normalize();
        Path binary = binaryFor(s);
        if (binary == null) return notCompiled(s + " is not a .sieve script");
        PosixFileAttributes like;
        try {
            like = Files.readAttributes(s, PosixFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        } catch (IOException e) {
            return notCompiled("cannot read " + s + ": " + e.getMessage());
        }
        if (!like.isRegularFile()) return notCompiled(s + " is not a regular file");
        String folder = org.daemoxcp.mail.security.RootOnlyPath.problem(s.getParent());
        if (folder != null) return notCompiled(folder);
        String user = ensureUser();
        if (user != null) return notCompiled(user);

        Path work = null;
        try {
            work = workDir();
            Path compiled = work.resolve(OUT).resolve(BINARY);
            Run c = run(asCompiler(sievec, "-c", work.resolve(CONF).toString(), s.toString(), compiled.toString()), MAX_TEXT, true);
            if (c.timedOut()) return notCompiled("sievec did not finish in " + TIMEOUT.toSeconds() + " s");
            if (c.exit() != 0) return failed(c.text());
            Run cat = run(asCompiler(CAT, compiled.toString()), MAX_BINARY, false);
            if (cat.exit() != 0 || cat.out().length == 0)
                return notCompiled("sievec saved no binary" + (c.text().isBlank() ? "" : ": " + c.text().strip()));
            // La cartella e' solo di root (RootOnlyPath, sopra): il compilato che c'e' lo legge root senza seguire collegamenti.
            if (onlyIfDifferent && Files.isRegularFile(binary, LinkOption.NOFOLLOW_LINKS)
                    && Files.size(binary) == cat.out().length && java.util.Arrays.equals(Files.readAllBytes(binary), cat.out()))
                return new Outcome(Status.UNCHANGED, "");
            install(binary, cat.out(), like);
            return new Outcome(Status.COMPILED, c.text().strip());
        } catch (IOException e) {
            return notCompiled("compiling " + s + " failed: " + e.getMessage());
        } finally {
            if (work != null) cleanUp(work);
        }
    }

    /** Controlla un testo Sieve senza installare niente: sievec, come {@link #USER}, lo compila e butta il risultato. */
    public static Outcome validate(String text) {
        String sievec = sievec();
        if (sievec == null) return notCompiled("sievec is not installed");
        String user = ensureUser();
        if (user != null) return notCompiled(user);
        Path work = null;
        try {
            work = workDir();
            Path s = work.resolve(TEXT);
            Files.writeString(s, text, StandardCharsets.UTF_8, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
            Files.setPosixFilePermissions(s, PosixFilePermissions.fromString("rw-r--r--"));
            // -d: invece del compilato, il suo dump; su /dev/null, cioe' niente su disco.
            Run c = run(asCompiler(sievec, "-c", work.resolve(CONF).toString(), "-d", s.toString(), "/dev/null"), MAX_TEXT, true);
            if (c.timedOut()) return notCompiled("sievec did not finish in " + TIMEOUT.toSeconds() + " s");
            return c.exit() == 0 ? new Outcome(Status.COMPILED, c.text().strip()) : failed(c.text());
        } catch (IOException e) {
            return notCompiled("validating failed: " + e.getMessage());
        } finally {
            if (work != null) cleanUp(work);
        }
    }

    /** Un errore a una riga dello script («nome: line 2: error: ...») e' un rifiuto; tutto il resto e' un impedimento. */
    private static final Pattern SCRIPT_ERROR = Pattern.compile(": line \\d+: error: ");

    static Outcome failed(String text) {
        String t = text.strip();
        return new Outcome(SCRIPT_ERROR.matcher(t).find() ? Status.REFUSED : Status.NOT_COMPILED, t.isEmpty() ? "sievec failed" : t);
    }

    // ===================== I pezzi =====================

    /** nome.sieve -> nome.svbin nella stessa cartella, come lo cerca Pigeonhole; null se non e' un .sieve. Pura. */
    static Path binaryFor(Path script) {
        Path name = script.getFileName();
        if (name == null || script.getParent() == null) return null;
        String n = name.toString();
        if (!n.endsWith(".sieve") || n.length() == ".sieve".length()) return null;
        return script.resolveSibling(n.substring(0, n.length() - ".sieve".length()) + ".svbin");
    }

    /** L'utente sievec, creato se manca; null se c'e' ed e' quello del pannello, altrimenti il motivo. */
    static String ensureUser() {
        PanelUser.Ensured e = COMPILER_USER.ensure();
        if (e.problem() != null) {
            LOGGER.warning("[SieveCompiler] Sieve scripts not precompiled (Dovecot compiles them at each delivery): " + e.problem());
            return e.problem();
        }
        if (e.created()) LOGGER.info("[SieveCompiler] DONE: user and group " + USER + " created (no password, no shell, home "
                + PanelUser.HOME + "): the panel's Sieve rules are compiled with it, not as root");
        return null;
    }

    /**
     * La configurazione minima di sievec: per la 2.4 le due righe di versione di dovecot.conf (la 2.4 non parte senza,
     * e devono essere le prime), per la 2.3 niente. Solo numeri e punti: il resto non passa. Pura.
     */
    static String minimalConfig(String dovecotConf) {
        if (dovecotConf == null) return "";
        String config = version(dovecotConf, "dovecot_config_version");
        if (config == null) return "";
        String storage = version(dovecotConf, "dovecot_storage_version");
        return "dovecot_config_version = " + config + "\n" + (storage == null ? "" : "dovecot_storage_version = " + storage + "\n");
    }

    private static String version(String conf, String key) {
        Matcher m = Pattern.compile("(?m)^[ \\t]*" + key + "[ \\t]*=[ \\t]*([0-9]{1,4}(?:\\.[0-9]{1,4}){1,3})[ \\t]*$").matcher(conf);
        return m.find() ? m.group(1) : null;
    }

    /**
     * La cartella di lavoro: di root, 0711 (sievec ci passa ma non la elenca ne' la cambia), con la configurazione
     * minima di root 0644 e la cartella out di sievec, 0700, dove lui salva il compilato.
     */
    static Path workDir() throws IOException {
        Path work = Files.createTempDirectory(WORK_BASE, "sievec-");
        boolean ready = false;
        try {
            Files.setPosixFilePermissions(work, PosixFilePermissions.fromString("rwx--x--x"));
            String conf = "";
            try {
                if (Files.isRegularFile(DOVECOT_CONF)) conf = minimalConfig(Files.readString(DOVECOT_CONF, StandardCharsets.UTF_8));
            } catch (IOException e) {
                LOGGER.warning("[SieveCompiler] cannot read " + DOVECOT_CONF + ": " + e.getMessage());
            }
            Path c = work.resolve(CONF);
            Files.writeString(c, conf, StandardCharsets.UTF_8, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
            Files.setPosixFilePermissions(c, PosixFilePermissions.fromString("rw-r--r--"));
            Path out = Files.createDirectory(work.resolve(OUT), PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
            PosixFileAttributeView v = Files.getFileAttributeView(out, PosixFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
            UserPrincipalLookupService names = out.getFileSystem().getUserPrincipalLookupService();
            v.setOwner(names.lookupPrincipalByName(USER));
            v.setGroup(names.lookupPrincipalByGroupName(USER));
            ready = true;
            return work;
        } finally {
            if (!ready) cleanUp(work);
        }
    }

    /**
     * Il compilato accanto allo script, con proprietario, gruppo e permessi dello script: un file nuovo e poi rename sul
     * nome vero, che chi consegna vede tutto o niente, senza mai seguire un collegamento e solo se nessun altro puo'
     * cambiare le cartelle da / fin li' (RootOnlyPath, reperto 221; prima si guardava solo la cartella dello script).
     */
    static void install(Path binary, byte[] bytes, PosixFileAttributes like) throws IOException {
        org.daemoxcp.mail.security.RootOnlyPath.replace(binary.getParent(), binary.getFileName().toString(), bytes,
                like.owner(), like.group(), like.permissions());
    }

    /**
     * Via la cartella di lavoro. Quello che c'e' nella cartella di sievec lo toglie sievec stesso (find -delete non segue
     * i collegamenti): root non scende in una cartella che un altro utente controlla. Poi root toglie la cartella vuota
     * e i suoi file; se sievec vi ha lasciato qualcosa, la cartella resta e lo si dice.
     */
    static void cleanUp(Path work) {
        Path out = work.resolve(OUT);
        try {
            if (Files.isDirectory(out, LinkOption.NOFOLLOW_LINKS)) {
                run(asCompiler(FIND, out.toString(), "-mindepth", "1", "-delete"), MAX_TEXT, true);
                Files.deleteIfExists(out);
            }
            Files.deleteIfExists(work.resolve(CONF));
            Files.deleteIfExists(work.resolve(TEXT));
            Files.deleteIfExists(work);
        } catch (IOException e) {
            LOGGER.warning("[SieveCompiler] left " + work + ": " + e.getMessage());
        }
    }

    /**
     * Un comando come sievec: chroot(8) con radice /, senza shell ne' PAM, e solo il gruppo sievec (-G: senza, il
     * comando terrebbe i gruppi aggiuntivi di root, wheel e operator; misurato per mailpanel il 07/11/2026). Pura.
     */
    static List<String> asCompiler(String... cmd) {
        List<String> c = new ArrayList<>(List.of(CHROOT, "-u", USER, "-g", USER, "-G", USER, "/"));
        c.addAll(List.of(cmd));
        return c;
    }

    /** L'ambiente di sievec: niente di quello di root, solo questo. */
    static final Map<String, String> ENVIRONMENT = Map.of("PATH", "/usr/bin:/bin:/usr/local/bin", "HOME", PanelUser.HOME,
            "USER", USER, "LOGNAME", USER);

    /** Com'e' andato un comando: uscita, quello che ha scritto (fino a un limite), se e' scaduto il tempo. */
    record Run(int exit, byte[] out, boolean timedOut) {
        String text() { return new String(out, StandardCharsets.UTF_8); }
    }

    /**
     * Lancia il comando con l'ambiente di sievec e lo standard input chiuso. Con merge l'errore va insieme all'uscita
     * (testo per l'amministratore); senza, l'uscita sono i byte del compilato e l'errore si butta. Oltre limit byte
     * l'uscita conta come fallita.
     */
    static Run run(List<String> cmd, int limit, boolean merge) throws IOException {
        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.environment().clear();
        pb.environment().putAll(ENVIRONMENT);
        pb.redirectInput(ProcessBuilder.Redirect.from(new File("/dev/null")));
        if (merge) pb.redirectErrorStream(true);
        else pb.redirectError(ProcessBuilder.Redirect.DISCARD);
        Process p = pb.start();
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        boolean[] tooMuch = {false};
        Thread reader = Thread.ofVirtual().start(() -> {
            try (InputStream in = p.getInputStream()) {
                byte[] b = new byte[8192];
                for (int n; (n = in.read(b)) > 0; ) {
                    if (buf.size() + n > limit) { tooMuch[0] = true; continue; }
                    buf.write(b, 0, n);
                }
            } catch (IOException ignored) {
                // il processo e' finito o e' stato fermato
            }
        });
        try {
            if (!p.waitFor(TIMEOUT.toMillis(), TimeUnit.MILLISECONDS)) {
                p.destroyForcibly();
                p.waitFor(5, TimeUnit.SECONDS);
                reader.join(Duration.ofSeconds(5));
                return new Run(-1, buf.toByteArray(), true);
            }
            reader.join(Duration.ofSeconds(5));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            p.destroyForcibly();
            return new Run(-1, buf.toByteArray(), true);
        }
        return new Run(tooMuch[0] ? -2 : p.exitValue(), buf.toByteArray(), false);
    }
}
