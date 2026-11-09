package org.mail_panel.system;

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
 * Le prove vere della posta, da questa macchina verso i suoi servizi: entrare in una casella con IMAP, consegnare (senza
 * consegnare) con LMTP, il saluto di ManageSieve, il socket di autenticazione che Postfix usa per l'invio, gli
 * indirizzi su cui Dovecot ascolta.
 *
 * Le usa il passaggio a Dovecot 2.4 prima e dopo (reperto 213). «Il servizio gira» non dice che una casella entra: il
 * 24/10/2026 un'installazione aveva Dovecot acceso, la configurazione accettata e le porte aperte, e nessuna casella
 * entrava («Support not compiled in for passdb driver 'sql'»).
 *
 * Nessuna cambia niente: IMAP apre la casella in sola lettura (EXAMINE), LMTP si ferma prima di DATA, ManageSieve e il
 * socket di autenticazione si salutano e basta. Ogni prova da' null se e' passata, altrimenti il perche' in una riga,
 * senza mai la password.
 */
final class MailProbes {
    private MailProbes() {}

    /** Un indirizzo che finisce in un comando di protocollo: niente spazi, a capo o caratteri strani. */
    static final java.util.regex.Pattern MAILBOX = java.util.regex.Pattern.compile("[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}");

    /**
     * Il certificato che Dovecot presenta, letto dal file della sua configurazione: la prova IMAP accetta solo quello.
     * Non si fida di nessuna autorita' e non lo salta: e' piu' stretto di una verifica normale, e funziona anche con un
     * certificato fatto da se' (la VM) o con un nome che non e' 127.0.0.1.
     */
    static X509Certificate leafCertificate(Path pem) throws IOException, CertificateException {
        try (InputStream in = Files.newInputStream(pem)) {
            Collection<? extends java.security.cert.Certificate> all = CertificateFactory.getInstance("X.509").generateCertificates(in);
            for (java.security.cert.Certificate c : all) if (c instanceof X509Certificate x) return x;
        }
        throw new CertificateException("no certificate in " + pem);
    }

    /** Una stringa fra virgolette per IMAP (RFC 3501, quoted): null se contiene a capo o NUL, che li' non possono stare. */
    static String imapQuoted(String s) {
        if (s == null || s.indexOf('\r') >= 0 || s.indexOf('\n') >= 0 || s.indexOf('\0') >= 0) return null;
        return "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
    }

    /**
     * Entra in una casella su IMAP con TLS (993) e la apre in sola lettura: LOGIN, EXAMINE INBOX, LOGOUT. Con l'utente
     * principale («casella*admin») e' la stessa strada di Roundcube; passa da passdb e userdb e dalla cartella della
     * posta, cioe' da tutto cio' che la configurazione nuova riscrive.
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
     * La consegna come la fa Postfix, fermata prima del messaggio: LHLO, MAIL FROM:<>, RCPT TO:<casella>. Il 250 sul
     * destinatario vuol dire che Dovecot ha trovato la casella con il suo userdb; niente arriva nella casella.
     */
    static String lmtpRecipient(String host, int port, String recipient, int timeoutMs) {
        if (recipient == null || !MAILBOX.matcher(recipient).matches()) return "the mailbox address is not valid";
        try (Socket s = new Socket()) {
            s.connect(new InetSocketAddress(host, port), timeoutMs);
            s.setSoTimeout(timeoutMs);
            BufferedReader in = reader(s.getInputStream());
            OutputStream out = s.getOutputStream();
            String r = reply(in);
            if (!r.startsWith("220")) return "LMTP greeting: " + shown(r);
            send(out, "LHLO localhost");
            r = reply(in);
            if (!r.startsWith("250")) return "LMTP LHLO: " + shown(r);
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
        } catch (Exception e) {
            return "LMTP on " + host + ":" + port + ": " + e.getMessage();
        }
    }

    /**
     * Il saluto di POP3 in chiaro (110): «+OK», poi QUIT, senza credenziali. Sulla 2.4 un reload che accende POP3 lascia
     * la porta aperta ma pop3-login muore a ogni connessione («net_listen_unix(/var/run/dovecot/srv.pop3-login/...)
     * failed», misurato sulla VM il 09/11/2026): la porta in ascolto non basta, serve il saluto.
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
     * Le estensioni Sieve che ManageSieve annuncia nel saluto, ordinate: le regole che gli utenti hanno scritto le
     * usano, e una che sparisse dopo il passaggio le romperebbe. Null se non risponde come ManageSieve.
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
     * Il socket di autenticazione di Dovecot che Postfix usa per l'invio (smtpd_sasl_path): ci si collega e si legge il
     * saluto del protocollo di autenticazione fino a DONE, con almeno un meccanismo. Senza questo socket nessuno
     * spedisce dalla 587, anche con IMAP che funziona.
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
     * Gli indirizzi TCP su cui ascolta Dovecot, da «sockstat -46lq -P tcp»: «tcp4 *:993», «tcp4 127.0.0.1:24». Il
     * passaggio pretende gli stessi prima e dopo: uno in meno e' un servizio perso, uno in piu' una porta aperta che
     * nessuno ha chiesto.
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

    /** La risposta etichettata di un comando IMAP, saltando le righe «*» che vengono prima. */
    private static String tagged(BufferedReader in, String tag) throws IOException {
        for (int i = 0; i < 200; i++) {
            String l = in.readLine();
            if (l == null) return "connection closed";
            if (l.startsWith(tag + " ")) return l;
        }
        return "no answer to " + tag;
    }

    /** Una risposta SMTP/LMTP, anche su piu' righe (250-...): l'ultima, quella col codice seguito da uno spazio. */
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
