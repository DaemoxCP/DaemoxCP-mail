package org.daemoxcp.mail.system;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/**
 * The real mail tests, from this machine towards its services: logging into a mailbox with IMAP, delivering
 * (without delivering) with LMTP, the ManageSieve greeting, the authentication socket Postfix uses for sending, the
 * addresses Dovecot listens on.
 *
 * They are used by the move to Dovecot 2.4, before and after (finding 213). "The service is running" does not say
 * that a mailbox can log in: on 2026-10-24 an installation had Dovecot running, the configuration accepted and the
 * ports open, and no mailbox could log in ("Support not compiled in for passdb driver 'sql'").
 *
 * None of them changes anything: IMAP opens the mailbox read-only (EXAMINE), LMTP stops before DATA, ManageSieve
 * and the authentication socket just exchange greetings. Every test gives null if it passed, otherwise the reason
 * in one line, never with the password.
 */
final class MailProbes {
    private MailProbes() {}

    /** An address that ends up in a protocol command: no spaces, newlines or strange characters. */
    static final java.util.regex.Pattern MAILBOX = java.util.regex.Pattern.compile("[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}");

    /**
     * The certificate Dovecot presents, read from the file in its configuration: the IMAP test accepts only that one.
     * It trusts no authority and does not skip the check: it is stricter than a normal verification, and it also works
     * with a self-signed certificate (the VM) or with a name that is not 127.0.0.1.
     */
    static X509Certificate leafCertificate(Path pem) throws IOException, CertificateException {
        try (InputStream in = Files.newInputStream(pem)) {
            Collection<? extends java.security.cert.Certificate> all = CertificateFactory.getInstance("X.509").generateCertificates(in);
            for (java.security.cert.Certificate c : all) if (c instanceof X509Certificate x) return x;
        }
        throw new CertificateException("no certificate in " + pem);
    }

    /** A quoted string for IMAP (RFC 3501, quoted): null if it contains a newline or NUL, which cannot go there. */
    static String imapQuoted(String s) {
        if (s == null || s.indexOf('\r') >= 0 || s.indexOf('\n') >= 0 || s.indexOf('\0') >= 0) return null;
        return "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
    }

    /**
     * Logs into a mailbox over IMAP with TLS (993) and opens it read-only: LOGIN, EXAMINE INBOX, LOGOUT. With the
     * master user ("mailbox*admin") it is the same path Roundcube takes; it goes through passdb and userdb and the mail
     * folder, that is, through everything the new configuration rewrites.
     */
    static String imapLogin(String host, int port, X509Certificate pinned, String login, String password, int timeoutMs) {
        String user = imapQuoted(login), pass = imapQuoted(password);
        if (user == null || pass == null) return "the login or the password cannot be written in an IMAP command";
        try (SSLSocket s = (SSLSocket) pinnedContext(pinned).getSocketFactory().createSocket()) {
            s.connect(new InetSocketAddress(host, port), timeoutMs);
            s.setSoTimeout(timeoutMs);
            s.startHandshake();
            BufferedReader in = reader(s.getInputStream());
            OutputStream out = s.getOutputStream();
            String hello = in.readLine();
            if (hello == null || !hello.startsWith("* OK")) return "IMAP greeting: " + shown(hello);
            send(out, "a1 LOGIN " + user + " " + pass);
            String r = tagged(in, "a1");
            if (!r.startsWith("a1 OK")) return "IMAP LOGIN: " + shown(r);
            send(out, "a2 EXAMINE INBOX");
            r = tagged(in, "a2");
            if (!r.startsWith("a2 OK")) return "IMAP EXAMINE INBOX: " + shown(r);
            send(out, "a3 LOGOUT");
            return null;
        } catch (Exception e) {
            return "IMAP on " + host + ":" + port + ": " + e.getMessage();
        }
    }

    /**
     * The delivery as Postfix does it, stopped before the message: LHLO, MAIL FROM:<>, RCPT TO:<mailbox>. The 250 on
     * the recipient means that Dovecot found the mailbox with its userdb; nothing arrives in the mailbox.
     */
    static String lmtpRecipient(String host, int port, String recipient, int timeoutMs) {
        if (recipient == null || !MAILBOX.matcher(recipient).matches()) return "the mailbox address is not valid";
        try (Socket s = new Socket()) {
            s.connect(new InetSocketAddress(host, port), timeoutMs);
            s.setSoTimeout(timeoutMs);
            return lmtpDialog(reader(s.getInputStream()), s.getOutputStream(), recipient);
        } catch (Exception e) {
            return "LMTP on " + host + ":" + port + ": " + e.getMessage();
        }
    }

    /**
     * The same on the Unix socket Postfix delivers through (lmtp:unix:private/dovecot-lmtp, finding 234). The socket
     * is 0600 owned by postfix: root runs this test.
     */
    static String lmtpRecipient(Path socket, String recipient, int timeoutMs) {
        if (recipient == null || !MAILBOX.matcher(recipient).matches()) return "the mailbox address is not valid";
        return lmtpUnix(socket, recipient, timeoutMs);
    }

    /** Only the greeting and LHLO, on the socket: when there is no mailbox to test yet. */
    static String lmtpHello(Path socket, int timeoutMs) {
        return lmtpUnix(socket, null, timeoutMs);
    }

    private static String lmtpUnix(Path socket, String recipient, int timeoutMs) {
        if (!Files.exists(socket)) return socket + " does not exist";
        ExecutorService ex = Executors.newSingleThreadExecutor(r -> {
            Thread t = new Thread(r, "lmtp-socket-probe");
            t.setDaemon(true);
            return t;
        });
        SocketChannel[] ch = new SocketChannel[1];
        try {
            Future<String> f = ex.submit(() -> {
                try (SocketChannel c = SocketChannel.open(StandardProtocolFamily.UNIX)) {
                    ch[0] = c;
                    c.connect(UnixDomainSocketAddress.of(socket));
                    return lmtpDialog(reader(java.nio.channels.Channels.newInputStream(c)),
                            java.nio.channels.Channels.newOutputStream(c), recipient);
                }
            });
            return f.get(timeoutMs, TimeUnit.MILLISECONDS);
        } catch (java.util.concurrent.TimeoutException e) {
            try { if (ch[0] != null) ch[0].close(); } catch (IOException ignored) {}
            return "LMTP on " + socket + ": no answer in " + (timeoutMs / 1000) + " s";
        } catch (Exception e) {
            Throwable c = e.getCause() != null ? e.getCause() : e;
            return "LMTP on " + socket + ": " + c.getMessage();
        } finally {
            ex.shutdownNow();
        }
    }

    /**
     * The dialogue, the same on both transports: null if Dovecot accepts the recipient (without a recipient: only
     * LHLO).
     */
    private static String lmtpDialog(BufferedReader in, OutputStream out, String recipient) throws IOException {
        String r = reply(in);
        if (!r.startsWith("220")) return "LMTP greeting: " + shown(r);
        send(out, "LHLO localhost");
        r = reply(in);
        if (!r.startsWith("250")) return "LMTP LHLO: " + shown(r);
        if (recipient == null) {
            send(out, "QUIT");
            return null;
        }
        send(out, "MAIL FROM:<>");
        r = reply(in);
        if (!r.startsWith("250")) return "LMTP MAIL FROM: " + shown(r);
        send(out, "RCPT TO:<" + recipient + ">");
        r = reply(in);
        if (!r.startsWith("250")) return "LMTP RCPT TO: " + shown(r);
        send(out, "RSET");
        reply(in);
        send(out, "QUIT");
        return null;
    }

    /**
     * The plain-text POP3 greeting (110): "+OK", then QUIT, without credentials. On 2.4 a reload that turns POP3 on
     * leaves the port open but pop3-login dies at every connection
     * ("net_listen_unix(/var/run/dovecot/srv.pop3-login/...) failed", measured on the VM on 2026-11-09): the listening
     * port is not enough, the greeting is needed.
     */
    static String pop3Greeting(String host, int port, int timeoutMs) {
        try (Socket s = new Socket()) {
            s.connect(new InetSocketAddress(host, port), timeoutMs);
            s.setSoTimeout(timeoutMs);
            BufferedReader in = reader(s.getInputStream());
            String hello = in.readLine();
            if (hello == null || !hello.startsWith("+OK")) return "POP3 greeting: " + shown(hello);
            send(s.getOutputStream(), "QUIT");
            return null;
        } catch (Exception e) {
            return "POP3 on " + host + ":" + port + ": " + e.getMessage();
        }
    }

    /**
     * The Sieve extensions ManageSieve announces in its greeting, sorted: the rules users have written use them, and
     * one that disappeared after the move would break them. Null if it does not answer like ManageSieve.
     */
    static Set<String> sieveExtensions(String host, int port, int timeoutMs) {
        try (Socket s = new Socket()) {
            s.connect(new InetSocketAddress(host, port), timeoutMs);
            s.setSoTimeout(timeoutMs);
            BufferedReader in = reader(s.getInputStream());
            Set<String> ext = null;
            for (int i = 0; i < 50; i++) {
                String l = in.readLine();
                if (l == null) return null;
                if (l.startsWith("\"SIEVE\"")) {
                    ext = new TreeSet<>();
                    String v = l.substring("\"SIEVE\"".length()).trim().replace("\"", "");
                    for (String x : v.split("\\s+")) if (!x.isEmpty()) ext.add(x);
                }
                if (l.startsWith("OK")) {
                    send(s.getOutputStream(), "LOGOUT");
                    return ext;
                }
                if (l.startsWith("NO") || l.startsWith("BYE")) return null;
            }
            return null;
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * The Dovecot authentication socket Postfix uses for sending (smtpd_sasl_path): it connects and reads the
     * authentication protocol greeting up to DONE, with at least one mechanism. Without this socket nobody can send
     * from 587, even with IMAP working.
     */
    static String authSocket(Path socket, int timeoutMs) {
        if (!Files.exists(socket)) return socket + " does not exist";
        ExecutorService ex = Executors.newSingleThreadExecutor(r -> {
            Thread t = new Thread(r, "auth-socket-probe");
            t.setDaemon(true);
            return t;
        });
        SocketChannel[] ch = new SocketChannel[1];
        try {
            Future<String> f = ex.submit(() -> {
                try (SocketChannel c = SocketChannel.open(StandardProtocolFamily.UNIX)) {
                    ch[0] = c;
                    c.connect(UnixDomainSocketAddress.of(socket));
                    c.write(ByteBuffer.wrap(("VERSION\t1\t2\nCPID\t" + ProcessHandle.current().pid() + "\n")
                            .getBytes(StandardCharsets.US_ASCII)));
                    StringBuilder got = new StringBuilder();
                    ByteBuffer b = ByteBuffer.allocate(4096);
                    while (got.length() < 65536) {
                        b.clear();
                        int n = c.read(b);
                        if (n < 0) break;
                        got.append(new String(b.array(), 0, n, StandardCharsets.US_ASCII));
                        if (got.indexOf("\nDONE\n") >= 0 || got.toString().startsWith("DONE\n")) break;
                    }
                    String all = got.toString();
                    if (!all.contains("DONE")) return "the authentication socket did not finish its greeting";
                    if (!all.contains("MECH\t")) return "the authentication socket offers no mechanism";
                    return null;
                }
            });
            return f.get(timeoutMs, TimeUnit.MILLISECONDS);
        } catch (java.util.concurrent.TimeoutException e) {
            try { if (ch[0] != null) ch[0].close(); } catch (IOException ignored) {}
            return "the authentication socket did not answer in " + (timeoutMs / 1000) + " s";
        } catch (Exception e) {
            Throwable c = e.getCause() != null ? e.getCause() : e;
            return "authentication socket " + socket + ": " + c.getMessage();
        } finally {
            ex.shutdownNow();
        }
    }

    /**
     * The TCP addresses Dovecot listens on, from "sockstat -46lq -P tcp": "tcp4 *:993", "tcp4 127.0.0.1:24". The
     * move requires the same ones before and after: one fewer is a lost service, one more is an open port nobody asked
     * for.
     */
    static Set<String> dovecotListeners(String sockstat) {
        Set<String> out = new TreeSet<>();
        if (sockstat == null) return out;
        for (String line : sockstat.split("\n")) {
            String[] c = line.trim().split("\\s+");
            // USER COMMAND PID FD PROTO LOCAL FOREIGN
            if (c.length >= 6 && "dovecot".equals(c[1]) && c[4].startsWith("tcp")) out.add(c[4] + " " + c[5]);
        }
        return out;
    }

    private static SSLContext pinnedContext(X509Certificate pinned) throws Exception {
        X509TrustManager tm = new X509TrustManager() {
            @Override public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                throw new CertificateException("no client certificates here");
            }
            @Override public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                if (pinned == null || chain == null || chain.length == 0 || !pinned.equals(chain[0]))
                    throw new CertificateException("the server did not present the certificate Dovecot is configured with");
            }
            @Override public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
        };
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(null, new TrustManager[]{tm}, null);
        return ctx;
    }

    private static BufferedReader reader(InputStream in) {
        return new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8));
    }

    private static void send(OutputStream out, String line) throws IOException {
        out.write((line + "\r\n").getBytes(StandardCharsets.UTF_8));
        out.flush();
    }

    /** The tagged response of an IMAP command, skipping the "*" lines that come before it. */
    private static String tagged(BufferedReader in, String tag) throws IOException {
        for (int i = 0; i < 200; i++) {
            String l = in.readLine();
            if (l == null) return "connection closed";
            if (l.startsWith(tag + " ")) return l;
        }
        return "no answer to " + tag;
    }

    /**
     * An SMTP/LMTP response, even over several lines (250-...): the last one, the one with the code followed by a
     * space.
     */
    private static String reply(BufferedReader in) throws IOException {
        for (int i = 0; i < 100; i++) {
            String l = in.readLine();
            if (l == null) return "connection closed";
            if (l.length() < 4 || l.charAt(3) != '-') return l;
        }
        return "reply too long";
    }

    private static String shown(String s) {
        if (s == null) return "connection closed";
        return s.length() > 200 ? s.substring(0, 200) : s;
    }
}
