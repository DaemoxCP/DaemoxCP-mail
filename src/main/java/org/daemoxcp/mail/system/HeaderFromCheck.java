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
 * Whoever authenticates writes only an address of their own in the From header.
 *
 * Postfix checks the envelope address (SenderLoginMap): a mailbox sends only from its own addresses. But Postfix
 * does not look at the From header, the one the mail program shows and that DMARC aligns with the DKIM signature:
 * measured on the VM on 2026-11-20, a mailbox authenticated on 587 with its own envelope and "From: boss@" of the
 * same domain went through, signed with the domain's key.
 *
 * A Lua rule in Rspamd closes the gap. Rspamd sits behind Postfix as a milter, and from the milter it knows who
 * authenticated (the {auth_authen} macro, task:get_user()): measured through 587, the right From goes through and
 * one with another address gets "554 5.7.1" with the message from here. For an authenticated client the From must
 * contain a single address, in a single header, and it must be the envelope address (which Postfix has already
 * checked) or the mailbox itself; with an empty envelope, only the mailbox. The rejection comes before any other
 * check (prefilter, set_pre_result, like the Rspamd modules that reject: spamtrap, force_actions). It does not look
 * at whoever does not authenticate: mail arriving from outside, the mail the panel sends with sendmail, automatic
 * replies.
 *
 * The file is lua.local.d/daemoxcp-header-from.lua: Rspamd's rules/rspamd.lua (4.1 on the VM, 4.2 on the
 * production server) loads every lua.local.d/*.lua by itself, without touching rspamd.local.lua, which stays the
 * administrator's. The installer writes it (FullMailServerScript); on servers installed earlier this boot repair
 * writes it, with the same content. Before touching anything it checks that Rspamd scans; afterwards, that rspamadm
 * configtest accepts it and that, once reloaded, Rspamd rejects a From that is not the sender's own and lets the
 * right one through (two real scans, with a fake user, on the normal worker). If something does not add up it puts
 * the previous file back (or removes it) and reloads. A file with the same name written by hand stays as it is. At
 * the second startup it does nothing.
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

    /** The fake user of the tests: no real mailbox, no message delivered (rspamc just scans). */
    static final String PROBE_USER = "probe@daemoxcp-mail.invalid";
    static final String PROBE_OTHER = "other@daemoxcp-mail.invalid";

    private HeaderFromCheck() {}

    /** The content of the file: the same for the installer (FullMailServerScript) and for the repair. */
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
     * What to do. installed: rspamadm is there; proxy: the worker-proxy.inc of local.d (null if it is not
     * there); current: the current file (null if it is not there). Only on the panel's Rspamd, the one behind
     * Postfix as a milter. A pure function.
     */
    static Action decide(boolean installed, String proxy, String current) {
        if (!installed || proxy == null || !MILTER.matcher(proxy).find()) return Action.NOTHING;
        if (current == null) return Action.APPLY;
        if (current.equals(content())) return Action.NOTHING;
        return current.contains(PanelMarker.WRITTEN) ? Action.APPLY : Action.LEFT_ALONE;
    }

    /** A test message with that From header. */
    static String message(String from) {
        return "From: " + from + "\r\nTo: <" + PROBE_OTHER + ">\r\nSubject: daemoxcp-mail header from probe\r\n"
             + "Message-ID: <header-from-" + System.nanoTime() + "@daemoxcp-mail.invalid>\r\n\r\nprobe\r\n";
    }

    /** What rspamc says about a message from a client authenticated as PROBE_USER; null if it does not answer. */
    static String scan(String headerFrom) {
        Shell.Result r = Shell.runWithInput(Duration.ofSeconds(60), message(headerFrom), RspamdUser.RSPAMC,
                "-h", "127.0.0.1:11333", "--user", PROBE_USER, "--from", PROBE_USER, "--rcpt", PROBE_OTHER,
                "--ip", "127.0.0.1", "symbols");
        return r.success() && r.output().contains("Action:") ? r.output() : null;
    }

    /**
     * The right From goes through without the symbol, one with another address is rejected with the symbol.
     * A pure function.
     */
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
