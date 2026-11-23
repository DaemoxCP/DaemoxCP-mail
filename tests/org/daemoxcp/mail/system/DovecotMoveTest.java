package org.daemoxcp.mail.system;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.function.Function;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import org.daemoxcp.mail.i18n.I18n;
import org.daemoxcp.mail.scripts.DovecotConfig;

/**
 * The guided move to Dovecot 2.4 (finding 213): what can be proven without a Dovecot.
 *
 *  1. The 2.4 configuration has the two lines a real 2.4.5 refused (ssl_server_prefer_ciphers = yes, a listener with
 *     address) written the way it accepts them, and the script asks pkg for the 2.4 port and its Pigeonhole too.
 *  2. What is installed (by origin) and what replaces it: the same MySQL flavor, Pigeonhole only if it was there;
 *     anything else is refused. The protected dependencies the new package wants as they are get unlocked for pkg, and
 *     a plan with a second MySQL client is named.
 *  3. Where Postfix delivers with LMTP: only a TCP address on this machine is tested.
 *  4. Before against after: a failed test, a port lost or new, a Sieve extension gone, a test not run, the password
 *     process back to root: each stops the move; the same state, or more Sieve extensions, does not.
 *  5. The probes, against servers on this machine: IMAP on TLS only with the pinned certificate, LOGIN and EXAMINE (never
 *     SELECT), the password quoted; LMTP stops before DATA; POP3's greeting, and a port that accepts and closes at
 *     once (pop3-login dying on 2.4 after a reload) is not POP3; ManageSieve's extensions; the authentication socket's
 *     greeting, a silent one and a missing one.
 */
public class DovecotMoveTest {

    private static int failures = 0;

    public static void main(String[] args) throws Exception {
        I18n.setCurrent("en");
        Path work = Files.createTempDirectory("dovecot-move-test");
        try {
            configuration();
            packages();
            lmtpTarget();
            beforeAndAfter();
            probes(work);
        } finally {
            new ProcessBuilder("rm", "-rf", work.toString()).start().waitFor();
        }
        System.out.println(failures == 0 ? "\nALL OK" : "\n" + failures + " CHECKS FAILED");
        System.exit(failures == 0 ? 0 : 1);
    }

    static void configuration() {
        System.out.println("== 1. The configuration for 2.4 ==");
        StringBuilder all = new StringBuilder();
        for (DovecotConfig.FileConf f : DovecotConfig.file24()) all.append(f.content()).append('\n');
        String c = all.toString();
        check("ssl_server_prefer_ciphers = server (2.4.5 refuses \"yes\")", c.contains("ssl_server_prefer_ciphers = server")
                && !c.matches("(?s).*\\n\\s*ssl_server_prefer_ciphers\\s*=\\s*yes.*"));
        // Since finding 234 Postfix delivers through a socket in its own queue: no TCP listener for LMTP at all.
        check("LMTP only on Postfix's socket (0600 postfix), no TCP listener, no address line (2.4.5 refuses it)",
                c.contains(LmtpSocket.NEW) && !c.contains("inet_listener lmtp") && !c.matches("(?s).*\\n\\s*address\\s*=.*"));
        String fragment = DovecotConfig.fromPanelConfig().scriptFragment();
        check("the script asks pkg for the 2.4 port (mail/dovecot24) too", fragment.contains("%o = \"mail/dovecot24\""));
        check("  and for 2.4's Pigeonhole, or ManageSieve would be dropped on 2.4", fragment.contains("'dovecot24-pigeonhole*'"));
        check("Diagnostics looks for 2.3's single-letter variables outside comments only (2.4's own file explains %d in one)",
                UpdateManager.SINGLE_LETTER_VARS.startsWith("^[^#]*") && UpdateManager.outsideComments("imap[-_]zlib").equals("^[^#]*(imap[-_]zlib)")
                && UpdateManager.outsideComments("^[[:space:]]*ssl_dh").equals("^[[:space:]]*ssl_dh"));
        check("  with grep, as it runs: a comment with %d is not found, a 2.3 line is, a 2.4 line is not", grepFinds(UpdateManager.SINGLE_LETTER_VARS,
                "# %d -> %{user | domain}\nmail_path = /var/vmail/%{user | domain}/%{user | username}\n") == false
                && grepFinds(UpdateManager.SINGLE_LETTER_VARS, "mail_location = maildir:/var/vmail/%d/%n\n"));
    }

    static void packages() {
        System.out.println("\n== 2. What is installed, and what replaces it ==");
        var m = UpdateManager.dovecotPackages("databases/mysql84-client mysql84-client 8.4.13\n"
                + "mail/dovecot dovecot-mysql 2.3.21.1_3\nmail/dovecot-pigeonhole dovecot-pigeonhole-mysql 0.5.21.1_1\n"
                + "mail/dovecot-fts-xapian dovecot-fts-xapian 1.9\nmail/postfix postfix-mysql 3.11.7\n");
        check("by origin: the 2.3 server and its Pigeonhole, nothing else (" + m.keySet() + ")",
                m.keySet().equals(Set.of("mail/dovecot", "mail/dovecot-pigeonhole")) && m.get("mail/dovecot")[0].equals("dovecot-mysql")
                && m.get("mail/dovecot-pigeonhole")[1].equals("0.5.21.1_1"));
        var m24 = UpdateManager.dovecotPackages("mail/dovecot24 dovecot24-mysql 2.4.5_2\nmail/dovecot24-pigeonhole dovecot24-pigeonhole-mysql 2.4.5\n");
        check("  and the 2.4 ones", m24.keySet().equals(Set.of("mail/dovecot24", "mail/dovecot24-pigeonhole")));
        check("dovecot-mysql + dovecot-pigeonhole-mysql -> dovecot24-mysql + dovecot24-pigeonhole-mysql",
                List.of("dovecot24-mysql", "dovecot24-pigeonhole-mysql").equals(UpdateManager.dovecot24Targets("dovecot-mysql", "dovecot-pigeonhole-mysql")));
        check("  without Pigeonhole, without Pigeonhole", List.of("dovecot24-mysql").equals(UpdateManager.dovecot24Targets("dovecot-mysql", "")));
        // On the VM, 09/11/2026: dovecot24-mysql wants mysql84-client 8.4.13, the one installed and protected; with the
        // lock, pkg's plan installed mysql267-client next to it.
        List<String> asTheyAre = UpdateManager.dependenciesAsTheyAre("mysql84-client 8.4.13\nlua54 5.4.8\nzstd 1.5.7_2\nperl5 5.42.4\n",
                Set.of("mysql84-client", "perl5", "postfix-mysql"), java.util.Map.of("mysql84-client", "8.4.13", "lua54", "5.4.8", "perl5", "5.42.3"));
        check("the protected dependencies the new package wants exactly as they are: unlocked for pkg (" + asTheyAre + ")",
                asTheyAre.equals(List.of("mysql84-client")));
        org.json.JSONObject plan = new org.json.JSONObject().put("changes", new org.json.JSONArray()
                .put(new org.json.JSONObject().put("type", "install").put("name", "dovecot24-mysql").put("to", "2.4.5_2"))
                .put(new org.json.JSONObject().put("type", "install").put("name", "mysql267-client").put("to", "26.7.0")));
        check("a plan that puts another MySQL client next to the installed one: named, so the preflight stops it",
                UpdateManager.otherMysqlInPlan(plan, Set.of("mysql84-client", "mysql84-server", "dovecot-mysql")).equals(List.of("mysql267-client 26.7.0"))
                && UpdateManager.otherMysqlInPlan(plan, Set.of("dovecot-mysql")).isEmpty());
        check("  another flavor, or a Pigeonhole of another flavor: refused",
                UpdateManager.dovecot24Targets("dovecot-pgsql", "") == null && UpdateManager.dovecot24Targets("dovecot", "") == null
                && UpdateManager.dovecot24Targets("dovecot-mysql", "dovecot-pigeonhole") == null && UpdateManager.dovecot24Targets(null, null) == null);
    }

    static void lmtpTarget() {
        System.out.println("\n== 3. Where Postfix delivers ==");
        check("lmtp:inet:127.0.0.1:24", "127.0.0.1:24".equals(join(UpdateManager.lmtpTarget("lmtp:inet:127.0.0.1:24"))));
        check("lmtp:localhost:24 -> 127.0.0.1", "127.0.0.1:24".equals(join(UpdateManager.lmtpTarget("lmtp:localhost:24"))));
        check("lmtp:inet:[::1]:24", "::1:24".equals(join(UpdateManager.lmtpTarget("lmtp:inet:[::1]:24"))));
        check("the panel's socket, relative to the queue (reperto 234)", java.nio.file.Path.of("/var/spool/postfix/private/dovecot-lmtp")
                .equals(UpdateManager.lmtpSocket("lmtp:unix:private/dovecot-lmtp", "/var/spool/postfix"))
                && java.nio.file.Path.of("/var/run/x.sock").equals(UpdateManager.lmtpSocket("lmtp:unix:/var/run/x.sock", "/var/spool/postfix")));
        check("  not a socket, a path that climbs out, a queue that is not a path: none", UpdateManager.lmtpSocket("lmtp:inet:127.0.0.1:24", "/q") == null
                && UpdateManager.lmtpSocket("lmtp:unix:private/../../etc/x", "/var/spool/postfix") == null
                && UpdateManager.lmtpSocket("lmtp:unix:private/x", "relative") == null && UpdateManager.lmtpSocket(null, null) == null);
        check("a socket, another machine, another transport: no TCP target", UpdateManager.lmtpTarget("lmtp:unix:private/dovecot-lmtp") == null
                && UpdateManager.lmtpTarget("lmtp:inet:mail.example.com:24") == null && UpdateManager.lmtpTarget("virtual") == null
                && UpdateManager.lmtpTarget("") == null && UpdateManager.lmtpTarget(null) == null);
    }

    static void beforeAndAfter() {
        System.out.println("\n== 4. Before against after ==");
        UpdateManager.MailState before = state(null, Set.of("tcp4 *:993", "tcp4 127.0.0.1:24", "tcp4 *:4190"), Set.of("fileinto", "vacation"));
        check("the same state: nothing stops", UpdateManager.mailStateProblems(before, before).isEmpty());
        check("  more Sieve extensions after: nothing stops", UpdateManager.mailStateProblems(before,
                state(null, before.listeners(), Set.of("fileinto", "vacation", "vnd.dovecot.testsuite"))).isEmpty());
        List<String> p = UpdateManager.mailStateProblems(before, state("IMAP LOGIN: a1 NO [AUTHENTICATIONFAILED]",
                before.listeners(), before.sieve()));
        check("a failed test stops it, named: " + p, p.size() == 1 && p.get(0).startsWith("IMAP login on 993: IMAP LOGIN: a1 NO"));
        p = UpdateManager.mailStateProblems(before, state(null, Set.of("tcp4 127.0.0.1:24", "tcp4 *:4190", "tcp4 *:110"), before.sieve()));
        check("a port lost and a port new: both stop it: " + p, p.size() == 2 && p.get(0).contains("no longer listens on tcp4 *:993")
                && p.get(1).contains("listens on tcp4 *:110, which it did not before"));
        p = UpdateManager.mailStateProblems(before, state(null, before.listeners(), Set.of("fileinto")));
        check("a Sieve extension gone stops it: " + p, p.size() == 1 && p.get(0).contains("vacation"));
        LinkedHashMap<String, String> fewer = new LinkedHashMap<>(before.results());
        fewer.remove("IMAP login on 993");
        p = UpdateManager.mailStateProblems(before, new UpdateManager.MailState(fewer, before.listeners(), before.sieve(), "dovecot"));
        check("a test of before that did not run after stops it: " + p, p.size() == 1 && p.get(0).contains("IMAP login on 993"));
        p = UpdateManager.mailStateProblems(before, new UpdateManager.MailState(before.results(), before.listeners(), before.sieve(), ""));
        check("the password process back to root stops it: " + p, p.size() == 1 && p.get(0).contains("ran as dovecot and now as root"));
        check("  one that ran as root before is not made worse", UpdateManager.mailStateProblems(
                new UpdateManager.MailState(before.results(), before.listeners(), before.sieve(), ""),
                new UpdateManager.MailState(before.results(), before.listeners(), before.sieve(), "")).isEmpty());
    }

    static UpdateManager.MailState state(String imapFailure, Set<String> listeners, Set<String> sieve) {
        LinkedHashMap<String, String> r = new LinkedHashMap<>();
        r.put("doveconf -n", null);
        r.put("IMAP login on 993", imapFailure);
        r.put("ManageSieve 4190", null);
        return new UpdateManager.MailState(r, new TreeSet<>(listeners), sieve == null ? null : new TreeSet<>(sieve), "dovecot");
    }

    static void probes(Path work) throws Exception {
        System.out.println("\n== 5. The probes, against servers on this machine ==");
        String keytool = Path.of(System.getProperty("java.home"), "bin", "keytool").toString();
        Path ks = work.resolve("dovecot.p12"), other = work.resolve("other.p12"), pem = work.resolve("cert.pem"), otherPem = work.resolve("other.pem");
        for (Path k : List.of(ks, other))
            run(keytool, "-genkeypair", "-alias", "t", "-keyalg", "EC", "-groupname", "secp256r1", "-keystore", k.toString(),
                    "-storetype", "PKCS12", "-storepass", "testpass", "-dname", "CN=mail.example.test", "-validity", "2");
        run(keytool, "-exportcert", "-rfc", "-alias", "t", "-keystore", ks.toString(), "-storepass", "testpass", "-file", pem.toString());
        run(keytool, "-exportcert", "-rfc", "-alias", "t", "-keystore", other.toString(), "-storepass", "testpass", "-file", otherPem.toString());
        X509Certificate cert = MailProbes.leafCertificate(pem), wrong = MailProbes.leafCertificate(otherPem);

        String password = "p\"w\\d";
        List<String> imapSeen = Collections.synchronizedList(new ArrayList<>());
        try (SSLServerSocket imap = tlsServer(ks)) {
            serve(imap, (line) -> {
                imapSeen.add(line);
                if (line.equals("a1 LOGIN \"info@example.test*admin\" \"p\\\"w\\\\d\"")) return "a1 OK Logged in";
                if (line.startsWith("a1 LOGIN")) return "a1 NO [AUTHENTICATIONFAILED] Authentication failed.";
                if (line.equals("a2 EXAMINE INBOX")) return "* 3 EXISTS\r\na2 OK [READ-ONLY] Examine completed.";
                if (line.startsWith("a3 LOGOUT")) return "* BYE Logging out\r\na3 OK Logout completed.";
                return line.split(" ")[0] + " BAD unknown";
            }, "* OK [CAPABILITY IMAP4rev1] Dovecot ready.");
            int port = imap.getLocalPort();
            String ok = MailProbes.imapLogin("127.0.0.1", port, cert, "info@example.test*admin", password, 5000);
            check("IMAP: the right master login gets in and opens INBOX read-only (" + ok + ")", ok == null);
            check("  with EXAMINE, never SELECT, and the password quoted (a quote and a backslash in it): " + imapSeen,
                    imapSeen.contains("a2 EXAMINE INBOX") && imapSeen.stream().noneMatch(l -> l.contains("SELECT")));
            String no = MailProbes.imapLogin("127.0.0.1", port, cert, "info@example.test*admin", "wrong", 5000);
            check("  a wrong password: the answer of the server, without the password: " + no,
                    no != null && no.contains("AUTHENTICATIONFAILED") && !no.contains("wrong"));
            String pinned = MailProbes.imapLogin("127.0.0.1", port, wrong, "info@example.test*admin", password, 5000);
            check("  another certificate than Dovecot's: refused before any LOGIN: " + pinned, pinned != null && pinned.contains("certificate"));
            check("  a password with a line break: not sent", MailProbes.imapLogin("127.0.0.1", port, cert, "x", "a\r\nb", 5000) != null
                    && MailProbes.imapQuoted("a\nb") == null && "\"a\\\"b\"".equals(MailProbes.imapQuoted("a\"b")));
        }

        List<String> lmtpSeen = Collections.synchronizedList(new ArrayList<>());
        try (ServerSocket lmtp = new ServerSocket(0, 5, InetAddress.getLoopbackAddress())) {
            serve(lmtp, (line) -> {
                lmtpSeen.add(line);
                if (line.startsWith("LHLO")) return "250-freebsdlocal\r\n250-8BITMIME\r\n250 PIPELINING";
                if (line.equals("MAIL FROM:<>")) return "250 2.1.0 OK";
                if (line.equals("RCPT TO:<info@example.test>")) return "250 2.1.5 OK";
                if (line.startsWith("RCPT")) return "550 5.1.1 <nobody@example.test> User doesn't exist";
                if (line.equals("RSET")) return "250 2.0.0 OK";
                if (line.equals("QUIT")) return "221 2.0.0 Bye";
                return "500 5.5.2 unknown";
            }, "220 freebsdlocal Dovecot ready.");
            int port = lmtp.getLocalPort();
            String delivered = MailProbes.lmtpRecipient("127.0.0.1", port, "info@example.test", 5000);
            check("LMTP: a mailbox that exists gets 250, and nothing is delivered (no DATA): " + lmtpSeen, delivered == null
                    && lmtpSeen.contains("RCPT TO:<info@example.test>") && lmtpSeen.stream().noneMatch(l -> l.startsWith("DATA")));
            String unknown = MailProbes.lmtpRecipient("127.0.0.1", port, "nobody@example.test", 5000);
            check("  one that does not: the answer of the server: " + unknown, unknown != null && unknown.contains("550 5.1.1"));
            int seen = lmtpSeen.size();
            check("  an address that is not one: refused without connecting", MailProbes.lmtpRecipient("127.0.0.1", port, "a b@c>", 5000) != null
                    && lmtpSeen.size() == seen);
        }

        try (ServerSocket pop = new ServerSocket(0, 5, InetAddress.getLoopbackAddress())) {
            serve(pop, line -> "+OK Logging out.", "+OK Dovecot ready.");
            check("POP3: the greeting, then QUIT, without credentials", MailProbes.pop3Greeting("127.0.0.1", pop.getLocalPort(), 5000) == null);
        }
        try (ServerSocket deadLogin = new ServerSocket(0, 5, InetAddress.getLoopbackAddress())) {
            // As pop3-login on 2.4 after a reload: the port accepts, the process dies at once.
            Thread t = new Thread(() -> { while (!deadLogin.isClosed()) try { deadLogin.accept().close(); } catch (Exception e) { return; } });
            t.setDaemon(true);
            t.start();
            String dead = MailProbes.pop3Greeting("127.0.0.1", deadLogin.getLocalPort(), 3000);
            check("  a port that accepts and closes at once: not POP3 (" + dead + ")", dead != null);
        }
        try (ServerSocket sieve = new ServerSocket(0, 5, InetAddress.getLoopbackAddress())) {
            serve(sieve, line -> "OK \"Logout completed.\"", "\"IMPLEMENTATION\" \"Dovecot Pigeonhole\"\r\n\"SIEVE\" \"fileinto reject envelope vacation\"\r\n"
                    + "\"NOTIFY\" \"mailto\"\r\n\"SASL\" \"PLAIN\"\r\n\"STARTTLS\"\r\n\"VERSION\" \"1.0\"\r\nOK \"Dovecot ready.\"");
            Set<String> ext = MailProbes.sieveExtensions("127.0.0.1", sieve.getLocalPort(), 5000);
            check("ManageSieve: the extensions of the greeting, sorted: " + ext, Set.of("envelope", "fileinto", "reject", "vacation").equals(ext));
        }
        try (ServerSocket notSieve = new ServerSocket(0, 5, InetAddress.getLoopbackAddress())) {
            serve(notSieve, line -> "", "* OK IMAP ready\r\n* BYE");
            check("  something that is not ManageSieve: no answer", MailProbes.sieveExtensions("127.0.0.1", notSieve.getLocalPort(), 3000) == null);
        }

        Path socket = work.resolve("auth");
        try (ServerSocketChannel auth = ServerSocketChannel.open(StandardProtocolFamily.UNIX)) {
            auth.bind(UnixDomainSocketAddress.of(socket));
            Thread t = new Thread(() -> {
                try (SocketChannel c = auth.accept()) {
                    c.write(ByteBuffer.wrap("VERSION\t1\t2\nMECH\tPLAIN\tplaintext\nMECH\tLOGIN\tplaintext\nSPID\t42\nCUID\t1\nCOOKIE\tabc\nDONE\n"
                            .getBytes(StandardCharsets.US_ASCII)));
                    c.read(ByteBuffer.allocate(256));
                } catch (Exception ignored) {}
            });
            t.setDaemon(true);
            t.start();
            String a = MailProbes.authSocket(socket, 5000);
            check("the authentication socket: greeting up to DONE, with a mechanism (" + a + ")", a == null);
        }
        Files.deleteIfExists(socket);
        try (ServerSocketChannel silent = ServerSocketChannel.open(StandardProtocolFamily.UNIX)) {
            silent.bind(UnixDomainSocketAddress.of(socket));
            Thread t = new Thread(() -> {
                try (SocketChannel c = silent.accept()) { Thread.sleep(4000); } catch (Exception ignored) {}
            });
            t.setDaemon(true);
            t.start();
            long t0 = System.currentTimeMillis();
            String s = MailProbes.authSocket(socket, 1500);
            check("  one that says nothing: gives up in time (" + (System.currentTimeMillis() - t0) + " ms): " + s,
                    s != null && s.contains("did not answer") && System.currentTimeMillis() - t0 < 3500);
        }
        check("  one that is not there: says so", String.valueOf(MailProbes.authSocket(work.resolve("none"), 1000)).contains("does not exist"));

        Set<String> l = MailProbes.dovecotListeners("USER     COMMAND    PID   FD  PROTO  LOCAL ADDRESS         FOREIGN ADDRESS\n"
                + "root     dovecot    95405 21  tcp4   *:993                 *:*\n"
                + "root     dovecot    95405 22  tcp6   *:993                 *:*\n"
                + "root     dovecot    95405 30  tcp4   127.0.0.1:24          *:*\n"
                + "root     sshd       880   4   tcp4   *:22                  *:*\n"
                + "dovecot  dovecot    95406 8   udp4   *:5000                *:*\n");
        check("Dovecot's TCP listeners from sockstat, nobody else's: " + l, l.equals(Set.of("tcp4 *:993", "tcp6 *:993", "tcp4 127.0.0.1:24")));
    }

    /** A TLS server with the key of the keystore, on 127.0.0.1. */
    static SSLServerSocket tlsServer(Path keystore) throws Exception {
        KeyStore k = KeyStore.getInstance("PKCS12");
        try (var in = Files.newInputStream(keystore)) { k.load(in, "testpass".toCharArray()); }
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(k, "testpass".toCharArray());
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(kmf.getKeyManagers(), null, null);
        return (SSLServerSocket) ctx.getServerSocketFactory().createServerSocket(0, 5, InetAddress.getLoopbackAddress());
    }

    /** Answers every line with the function's reply (its lines separated by CRLF), after a greeting; one thread per connection. */
    static void serve(ServerSocket server, Function<String, String> answer, String greeting) {
        Thread t = new Thread(() -> {
            while (!server.isClosed()) {
                try {
                    Socket s = server.accept();
                    Thread c = new Thread(() -> {
                        try (s) {
                            BufferedReader in = new BufferedReader(new InputStreamReader(s.getInputStream(), StandardCharsets.UTF_8));
                            OutputStream out = s.getOutputStream();
                            out.write((greeting + "\r\n").getBytes(StandardCharsets.UTF_8));
                            out.flush();
                            String line;
                            while ((line = in.readLine()) != null) {
                                String r = answer.apply(line);
                                if (!r.isEmpty()) { out.write((r + "\r\n").getBytes(StandardCharsets.UTF_8)); out.flush(); }
                                if (line.startsWith("QUIT") || line.contains("LOGOUT")) break;
                            }
                        } catch (Exception ignored) {}
                    });
                    c.setDaemon(true);
                    c.start();
                } catch (Exception e) {
                    return;
                }
            }
        });
        t.setDaemon(true);
        t.start();
    }

    static void run(String... cmd) throws Exception {
        Process p = new ProcessBuilder(cmd).redirectErrorStream(true).start();
        String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        if (p.waitFor() != 0) throw new IllegalStateException(String.join(" ", cmd) + ": " + out);
    }

    /** grep -E on a temporary file, as Diagnostics runs it on Dovecot's files. */
    static boolean grepFinds(String re, String text) {
        try {
            Path f = Files.createTempFile("dovecot-conf", ".conf");
            Files.writeString(f, text);
            Process p = new ProcessBuilder("grep", "-qE", re, f.toString()).start();
            boolean found = p.waitFor() == 0;
            Files.delete(f);
            return found;
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    static String join(String[] a) { return a == null ? null : a[0] + ":" + a[1]; }

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK     " : "  FAILED ") + what);
        if (!ok) failures++;
    }
}
