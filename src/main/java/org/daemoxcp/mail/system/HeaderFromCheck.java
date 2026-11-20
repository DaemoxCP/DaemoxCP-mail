package org.daemoxcp.mail.system;

import org.daemoxcp.mail.util.Shell;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Duration;
import java.util.logging.Logger;
import java.util.regex.Pattern;

/**
 * Chi si autentica scrive nell'intestazione From solo un indirizzo suo.
 *
 * Postfix controlla l'indirizzo della busta (SenderLoginMap): una casella spedisce solo dai suoi indirizzi. Ma
 * l'intestazione From, quella che il programma di posta mostra e che DMARC allinea alla firma DKIM, Postfix non la
 * guarda: misurato sulla VM il 20/11/2026, una casella autenticata sulla 587 con la sua busta e «From: boss@» dello
 * stesso dominio passava, firmata con la chiave del dominio.
 *
 * Una regola Lua di Rspamd la chiude. Rspamd sta dietro Postfix come milter, e dal milter sa chi si e' autenticato
 * (la macro {auth_authen}, task:get_user()): misurato attraverso la 587, il From giusto passa e quello di un altro
 * indirizzo prende «554 5.7.1» col messaggio di qui. Per un client autenticato il From deve contenere un indirizzo
 * solo, in un'intestazione sola, e deve essere l'indirizzo della busta (che Postfix ha gia' controllato) o la casella
 * stessa; con la busta vuota, solo la casella. Il rifiuto arriva prima di ogni altro controllo (prefilter,
 * set_pre_result, come i moduli di Rspamd che rifiutano: spamtrap, force_actions). Quello che non si autentica non
 * lo guarda: la posta che arriva da fuori, quella che il pannello manda con sendmail, le risposte automatiche.
 *
 * Il file e' lua.local.d/daemoxcp-header-from.lua: rules/rspamd.lua di Rspamd (4.1 sulla VM, 4.2 sul server vero)
 * carica da solo ogni lua.local.d/*.lua, senza toccare rspamd.local.lua, che resta dell'amministratore. L'installatore
 * lo scrive (FullMailServerScript); sui server installati prima lo scrive questa riparazione all'avvio, con lo stesso
 * contenuto. Prima di toccare qualcosa controlla che Rspamd analizzi; dopo, che rspamadm configtest lo accetti e che,
 * ricaricato, Rspamd rifiuti un From non suo e lasci passare quello giusto (due scansioni vere, con un utente finto, sul
 * worker normale). Se qualcosa non torna rimette il file di prima (o lo toglie) e ricarica. Un file con lo stesso nome
 * scritto a mano resta com'e'. Al secondo avvio non fa niente.
 */
public final class HeaderFromCheck {

    private static final Logger LOGGER = Logger.getLogger(HeaderFromCheck.class.getName());

    static final Path DIR = Path.of("/usr/local/etc/rspamd/lua.local.d");
    public static final String FILE_NAME = "daemoxcp-header-from.lua";
    public static final String PATH = DIR + "/" + FILE_NAME;
    static final Path PROXY = Path.of("/usr/local/etc/rspamd/local.d/worker-proxy.inc");
    public static final String SYMBOL = "DAEMOXCP_FROM_NOT_SENDER";
    public static final String REPLY = "The From header must be the sender address of the signed-in mailbox";
    static final Pattern MILTER = Pattern.compile("(?m)^\\s*milter\\s*=\\s*(yes|true)\\b");

    /** L'utente finto delle prove: nessuna casella vera, nessun messaggio consegnato (rspamc analizza e basta). */
    static final String PROBE_USER = "probe@daemoxcp-mail.invalid";
    static final String PROBE_OTHER = "other@daemoxcp-mail.invalid";

    private HeaderFromCheck() {}

    /** Il contenuto del file: lo stesso per l'installatore (FullMailServerScript) e per la riparazione. */
    public static String content() {
        return "-- " + PanelMarker.WRITTEN + ", which rewrites it: do not edit (HeaderFromCheck).\n"
             + "-- A client that signs in writes in the From header only the envelope sender, which Postfix already\n"
             + "-- checked as its own (smtpd_sender_login_maps), or its own mailbox. Mail that does not sign in is not\n"
             + "-- looked at.\n"
             + "local SYMBOL = '" + SYMBOL + "'\n"
             + "\n"
             + "local function check(task)\n"
             + "  local user = task:get_user()\n"
             + "  if not user or user == '' then return false end\n"
             + "  user = user:lower()\n"
             + "  local env = task:get_from('smtp')\n"
             + "  local envelope = ((env and env[1] and env[1].addr) or ''):lower()\n"
             + "  local headers = task:get_header_full('From') or {}\n"
             + "  local from = task:get_from('mime')\n"
             + "  local why\n"
             + "  if #headers ~= 1 then\n"
             + "    why = 'one From header expected, found ' .. #headers\n"
             + "  elseif not (from and #from == 1 and from[1].addr and from[1].addr ~= '') then\n"
             + "    why = 'one address expected in the From header'\n"
             + "  else\n"
             + "    local addr = from[1].addr:lower()\n"
             + "    if addr ~= user and (envelope == '' or addr ~= envelope) then\n"
             + "      why = 'From ' .. addr .. ' is not the sender'\n"
             + "    end\n"
             + "  end\n"
             + "  if not why then return false end\n"
             + "  task:insert_result(SYMBOL, 1.0, why)\n"
             + "  task:set_pre_result{action = 'reject', module = 'daemoxcp',\n"
             + "    message = '" + REPLY + "'}\n"
             + "  return true\n"
             + "end\n"
             + "\n"
             + "rspamd_config:register_symbol{\n"
             + "  name = SYMBOL,\n"
             + "  type = 'prefilter',\n"
             + "  callback = check,\n"
             + "  score = 0.0,\n"
             + "  group = 'policies',\n"
             + "  description = 'Signed-in client: the From header is neither the envelope sender nor the mailbox',\n"
             + "}\n";
    }

    enum Action { NOTHING, APPLY, LEFT_ALONE }

    /**
     * Che cosa fare. installed: c'e' rspamadm; proxy: il worker-proxy.inc di local.d (null se non c'e'); current: il
     * file di adesso (null se non c'e'). Solo sul Rspamd del pannello, quello che sta dietro Postfix come milter.
     * Funzione pura.
     */
    static Action decide(boolean installed, String proxy, String current) {
        if (!installed || proxy == null || !MILTER.matcher(proxy).find()) return Action.NOTHING;
        if (current == null) return Action.APPLY;
        if (current.equals(content())) return Action.NOTHING;
        return current.contains(PanelMarker.WRITTEN) ? Action.APPLY : Action.LEFT_ALONE;
    }

    /** Un messaggio di prova con quell'intestazione From. */
    static String message(String from) {
        return "From: " + from + "\r\nTo: <" + PROBE_OTHER + ">\r\nSubject: daemoxcp-mail header from probe\r\n"
             + "Message-ID: <header-from-" + System.nanoTime() + "@daemoxcp-mail.invalid>\r\n\r\nprobe\r\n";
    }

    /** Quello che rspamc dice di un messaggio di un client autenticato come PROBE_USER; null se non risponde. */
    static String scan(String headerFrom) {
        Shell.Result r = Shell.runWithInput(Duration.ofSeconds(60), message(headerFrom), RspamdUser.RSPAMC,
                "-h", "127.0.0.1:11333", "--user", PROBE_USER, "--from", PROBE_USER, "--rcpt", PROBE_OTHER,
                "--ip", "127.0.0.1", "symbols");
        return r.success() && r.output().contains("Action:") ? r.output() : null;
    }

    /** Il From giusto passa senza il simbolo, quello di un altro indirizzo e' rifiutato col simbolo. Funzione pura. */
    static String judge(String own, String other) {
        if (own == null || other == null) return "Rspamd does not answer a scan";
        if (own.contains(SYMBOL)) return "the sender's own From is refused";
        if (!other.contains(SYMBOL) || !other.contains("Action: reject")) return "a From of another address is not refused";
        return null;
    }

    public static void ensureAtBoot() {
        try {
            Path file = DIR.resolve(FILE_NAME);
            boolean installed = Files.isExecutable(Path.of(RspamdController.RSPAMADM)) && Files.isExecutable(Path.of(RspamdUser.RSPAMC));
            String proxy = Files.isRegularFile(PROXY, LinkOption.NOFOLLOW_LINKS) ? Files.readString(PROXY, StandardCharsets.UTF_8) : null;
            String current = Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS) ? Files.readString(file, StandardCharsets.UTF_8)
                    : Files.exists(file, LinkOption.NOFOLLOW_LINKS) ? "" : null;
            switch (decide(installed, proxy, current)) {
                case NOTHING -> { }
                case LEFT_ALONE -> LOGGER.info("[HeaderFromCheck] " + file + " was not written by the panel: left as it is");
                case APPLY -> apply(file, current);
            }
        } catch (Throwable t) {
            LOGGER.warning("[HeaderFromCheck] ensureAtBoot exception: " + t.getMessage());
        }
    }

    static boolean apply(Path file, String previous) throws Exception {
        if (!Shell.run(Duration.ofSeconds(30), "service", "rspamd", "status").success()) {
            LOGGER.info("[HeaderFromCheck] Rspamd is not running: the From check is not added, retrying at the next start");
            return false;
        }
        if (scan("<" + PROBE_USER + ">") == null) {
            LOGGER.warning("[HeaderFromCheck] Rspamd does not answer a scan before any change: the From check is not added");
            return false;
        }
        Files.createDirectories(DIR);
        write(file, content());
        Shell.Result test = Shell.run(Duration.ofSeconds(60), RspamdController.RSPAMADM, "configtest");
        if (!test.success()) {
            putBack(file, previous, false);
            LOGGER.warning("[HeaderFromCheck] ROLLED_BACK: rspamadm configtest refuses the rule: nothing changed");
            return false;
        }
        reload();
        String problem = "Rspamd does not answer a scan";
        for (int i = 0; i < 30 && problem != null; i++) {
            Thread.sleep(1000);
            problem = judge(scan("Probe <" + PROBE_USER + ">"), scan("Other <" + PROBE_OTHER + ">"));
        }
        if (problem != null) {
            putBack(file, previous, true);
            LOGGER.warning("[HeaderFromCheck] ROLLED_BACK: " + problem + "; everything put back");
            return false;
        }
        LOGGER.info("[HeaderFromCheck] DONE: a client that signs in writes in the From header only its own sender address"
                + " (the envelope Postfix checked, or the mailbox), otherwise 554 (" + file + ")");
        return true;
    }

    static void reload() throws InterruptedException {
        Shell.run(Duration.ofSeconds(120), "service", "rspamd", "reload");
        Thread.sleep(1000);
    }

    private static void write(Path file, String content) throws Exception {
        Path tmp = file.resolveSibling("." + file.getFileName() + ".tmp");
        Files.writeString(tmp, content, StandardCharsets.UTF_8);
        Files.setPosixFilePermissions(tmp, PosixFilePermissions.fromString("rw-r--r--"));
        Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
    }

    private static void putBack(Path file, String previous, boolean reload) throws Exception {
        if (previous != null && !previous.isEmpty()) write(file, previous);
        else Files.deleteIfExists(file);
        if (reload) reload();
    }
}
