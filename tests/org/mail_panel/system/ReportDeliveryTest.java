package org.mail_panel.system;

import org.json.JSONObject;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.List;

/**
 * Da quale sendmail parte il rapporto, e come il pannello capisce com'e' andata.
 *
 * Il difetto del 25/09/2026: il sendmail si cercava nel PATH, si trovava /usr/sbin/sendmail,
 * cioe' mailwrapper, cioe' dma. dma consegnava da solo, in chiaro e senza signature DKIM, e il
 * pannello scriveva "riuscito" perche' guardava solo il codice di uscita. Qui si prova che
 * mailwrapper non viene mai scelto, e che con le righe di dma nel log l'esito NON diventa
 * "consegnato": Postfix quel messaggio non l'ha visto.
 */
public class ReportDeliveryTest {

    private static int failed = 0;

    private static final String ID = "rapporto.20260925155210.0f3a9c1d2b4e5f60718293a4b5c6d7e8@domain-b.test";
    private static final String A = "owner@example.com";

    public static void main(String[] args) throws Exception {
        // --- Consegnato a Gmail, con TLS: quello che deve succedere dopo la fix ---
        // In mezzo ci sono le righe di un altro messaggio, che non devono confondere niente.
        List<String> gmail = List.of(
            "Sep 25 17:52:10 mail postfix/pickup[81234]: 4hB2Kq3Xz9zB6: uid=0 from=<noreply-mailserver@domain-b.test>",
            "Sep 25 17:52:10 mail postfix/cleanup[81240]: 4hB2Kq3Xz9zB6: message-id=<" + ID + ">",
            "Sep 25 17:52:10 mail postfix/qmgr[1022]: 4hB2Kq3Xz9zB6: from=<noreply-mailserver@domain-b.test>, size=4211, nrcpt=1 (queue active)",
            "Sep 25 17:52:11 mail postfix/smtpd[81250]: 4hB2Kr0ABCzB7: client=mail-wr1-f41.google.com[209.85.221.41]",
            "Sep 25 17:52:11 mail postfix/cleanup[81240]: 4hB2Kr0ABCzB7: message-id=<CAF=abc123@mail.gmail.com>",
            "Sep 25 17:52:11 mail postfix/lmtp[81255]: 4hB2Kr0ABCzB7: to=<info@domain-b.test>, relay=127.0.0.1[127.0.0.1]:24, delay=0.2, delays=0.1/0/0/0.1, dsn=2.0.0, status=sent (250 2.0.0 <info@domain-b.test> xyz Saved)",
            "Sep 25 17:52:11 mail postfix/smtp[81242]: Trusted TLS connection established to gmail-smtp-in.l.google.com[142.250.102.27]:25: TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits) key-exchange X25519 server-signature ECDSA (P-256) server-digest SHA256",
            "Sep 25 17:52:12 mail postfix/smtp[81242]: 4hB2Kq3Xz9zB6: to=<owner@example.com>, relay=gmail-smtp-in.l.google.com[142.250.102.27]:25, delay=1.6, delays=0.1/0.01/0.52/0.97, dsn=2.0.0, status=sent (250 2.0.0 OK  1727279532 5b1f17b1804b1-42cb5a5ba8esi12345f9.123 - gsmtp)",
            "Sep 25 17:52:12 mail postfix/qmgr[1022]: 4hB2Kq3Xz9zB6: removed");
        JSONObject e = PeriodicReport.outcomeInLog(gmail, ID, A);
        real("gmail: trova il numero di coda dal Message-ID", "4hB2Kq3Xz9zB6".equals(e.optString("queue")));
        real("gmail: consegnato", "delivered".equals(e.optString("state")));
        real("gmail: relay giusto", "gmail-smtp-in.l.google.com[142.250.102.27]:25".equals(e.optString("relay")));
        real("gmail: risposta del server", e.optString("answer").startsWith("250 2.0.0 OK"));
        real("gmail: TLS letto dalla riga di smtp", "TLSv1.3 (TLS_AES_256_GCM_SHA384)".equals(e.optString("tls")));
        real("gmail: le righe dell'altro messaggio restano fuori",
            !e.getJSONArray("lines").toString().contains("4hB2Kr0ABCzB7"));
        JSONObject v = PeriodicReport.verdict(e);
        real("gmail: verdict riuscito e senza avviso", v.optBoolean("success") && !v.optBoolean("warning"));
        real("gmail: l'esito registrato dice dove e con quale TLS",
            v.optString("outcome").startsWith("consegnato a gmail-smtp-in.l.google.com") && v.optString("outcome").contains("TLSv1.3"));

        // --- Il TLS si prende solo dal processo smtp che ha consegnato ---
        // Revisione: con il solo relay, la riga TLS di un ALTRO processo smtp verso lo
        // stesso server veniva attribuita al rapporto, e un rapporto partito in chiaro risultava
        // "con TLS". Qui il processo 501 consegna in chiaro mentre il 500 apre una sua connessione
        // cifrata verso lo stesso Gmail per un altro messaggio.
        String R = "gmail-smtp-in.l.google.com[142.250.102.27]:25";
        String opening13 = "Trusted TLS connection established to " + R + ": TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits) key-exchange X25519 server-signature ECDSA (P-256) server-digest SHA256";
        String opening12 = "Untrusted TLS connection established to " + R + ": TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits)";
        String cleanup = "Sep 25 19:00:00 mail postfix/cleanup[1]: 4TLS00001: message-id=<" + ID + ">";
        String delivered = "4TLS00001: to=<owner@example.com>, relay=" + R + ", delay=1, delays=0/0/0.5/0.5, dsn=2.0.0, status=sent (250 2.0.0 OK - gsmtp)";
        List<String> otherProcess = List.of(
            cleanup,
            "Sep 25 19:00:01 mail postfix/smtp[500]: " + opening13,
            "Sep 25 19:00:02 mail postfix/smtp[501]: " + delivered,
            "Sep 25 19:00:02 mail postfix/smtp[500]: 4ALTRO0001: to=<altro@gmail.com>, relay=" + R + ", delay=1, delays=0/0/0.5/0.5, dsn=2.0.0, status=sent (250 2.0.0 OK - gsmtp)");
        real("tls: la prova contiene davvero un'apertura TLS verso lo stesso relay",
            otherProcess.get(1).contains("TLS connection established to " + R + ": "));
        e = PeriodicReport.outcomeInLog(otherProcess, ID, A);
        real("tls di un altro processo: consegnato", "delivered".equals(e.optString("state")));
        real("tls di un altro processo: NON attribuito al rapporto", !e.has("tls"));
        v = PeriodicReport.verdict(e);
        real("tls di un altro processo: l'esito non dice TLS", !v.optString("outcome").contains("TLS"));
        real("tls di un altro processo: la sua riga resta fuori dall'estratto",
            !e.getJSONArray("lines").toString().contains("smtp[500]"));

        // Le due aperture si intrecciano: vale quella del processo che ha consegnato.
        List<String> interleaved = List.of(
            cleanup,
            "Sep 25 19:00:01 mail postfix/smtp[81242]: " + opening13,
            "Sep 25 19:00:01 mail postfix/smtp[81243]: " + opening12,
            "Sep 25 19:00:02 mail postfix/smtp[81242]: " + delivered);
        real("tls intrecciati: vale quello del processo che ha consegnato",
            "TLSv1.3 (TLS_AES_256_GCM_SHA384)".equals(PeriodicReport.outcomeInLog(interleaved, ID, A).optString("tls")));
        List<String> interleavedBackwards = List.of(
            cleanup,
            "Sep 25 19:00:01 mail postfix/smtp[81243]: " + opening12,
            "Sep 25 19:00:01 mail postfix/smtp[81242]: " + opening13,
            "Sep 25 19:00:02 mail postfix/smtp[81243]: " + delivered);
        real("tls intrecciati, al contrario: vale ancora quello di chi ha consegnato",
            "TLSv1.2 (ECDHE-RSA-AES128-GCM-SHA256)".equals(PeriodicReport.outcomeInLog(interleavedBackwards, ID, A).optString("tls")));

        // Stesso processo: prima un altro messaggio su una connessione cifrata, poi il rapporto su
        // una connessione nuova, in chiaro (senza conn_use). L'apertura e' della connessione di prima.
        List<String> connectionBefore = List.of(
            cleanup,
            "Sep 25 19:00:01 mail postfix/smtp[600]: " + opening13,
            "Sep 25 19:00:01 mail postfix/smtp[600]: 4ALTRO0002: to=<altro@gmail.com>, relay=" + R + ", delay=1, delays=0/0/0.5/0.5, dsn=2.0.0, status=sent (250 2.0.0 OK - gsmtp)",
            "Sep 25 19:00:02 mail postfix/smtp[600]: " + delivered);
        real("stesso processo, connessione precedente: niente TLS", !PeriodicReport.outcomeInLog(connectionBefore, ID, A).has("tls"));

        // Connessione riusata: e' stata aperta prima, per un altro messaggio.
        List<String> reused = List.of(
            cleanup,
            "Sep 25 19:00:01 mail postfix/smtp[700]: " + opening13,
            "Sep 25 19:00:02 mail postfix/smtp[700]: " + delivered.replace(", delay=1,", ", conn_use=2, delay=1,"));
        real("connessione riusata (conn_use): niente TLS", !PeriodicReport.outcomeInLog(reused, ID, A).has("tls"));

        // TLS caduto a meta' e ripiego in chiaro verso lo STESSO server (smtp_tls_security_level=may):
        // l'apertura c'e', il relay e' lo stesso, ma il messaggio e' partito sulla connessione dopo.
        List<String> fallback = List.of(
            cleanup,
            "Sep 25 19:00:01 mail postfix/smtp[800]: " + opening13,
            "Sep 25 19:00:02 mail postfix/smtp[800]: 4TLS00001: lost connection with " + R.substring(0, R.lastIndexOf(':')) + " while sending end of data -- message may be sent more than once",
            "Sep 25 19:00:03 mail postfix/smtp[800]: " + delivered);
        real("ripiego in chiaro dopo un TLS caduto: niente TLS", !PeriodicReport.outcomeInLog(fallback, ID, A).has("tls"));

        // Primo MX cifrato che rifiuta, secondo MX in chiaro: l'apertura e' verso un altro relay.
        List<String> otherMx = List.of(
            cleanup,
            "Sep 25 19:00:01 mail postfix/smtp[900]: Trusted TLS connection established to alt1.gmail-smtp-in.l.google.com[142.250.150.27]:25: TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)",
            "Sep 25 19:00:01 mail postfix/smtp[900]: 4TLS00001: host alt1.gmail-smtp-in.l.google.com[142.250.150.27] said: 421 4.7.0 Try again later (in reply to MAIL FROM command)",
            "Sep 25 19:00:02 mail postfix/smtp[900]: " + delivered);
        real("apertura verso un altro MX: niente TLS", !PeriodicReport.outcomeInLog(otherMx, ID, A).has("tls"));

        // smtp_tls_loglevel 2: dopo l'apertura il processo scrive righe della sessione TLS, e il
        // messaggio va anche a un secondo destinatario sulla stessa connessione. La prova regge.
        List<String> loglevel2 = List.of(
            cleanup,
            "Sep 25 19:00:01 mail postfix/smtp[1000]: " + opening13,
            "Sep 25 19:00:01 mail postfix/smtp[1000]: SSL_connect:SSL negotiation finished successfully",
            "Sep 25 19:00:01 mail postfix/smtp[1000]: save session smtp&gmail.com&gmail-smtp-in.l.google.com&142.250.102.27&&3C7A5B to smtp cache",
            "Sep 25 19:00:02 mail postfix/smtp[1000]: 4TLS00001: to=<altro@gmail.com>, relay=" + R + ", delay=1, delays=0/0/0.5/0.5, dsn=2.0.0, status=sent (250 2.0.0 OK - gsmtp)",
            "Sep 25 19:00:02 mail postfix/smtp[1000]: " + delivered);
        e = PeriodicReport.outcomeInLog(loglevel2, ID, A);
        real("loglevel 2 e due destinatari: TLS riconosciuto", "TLSv1.3 (TLS_AES_256_GCM_SHA384)".equals(e.optString("tls")));
        real("loglevel 2: l'apertura e' nell'estratto", e.getJSONArray("lines").toString().contains("TLS connection established"));

        // RFC 5424: il pid e' un campo a se'. Stesso pid, TLS; pid diverso, niente.
        String t5424 = "<22>1 2026-09-25T19:00:01.000001+02:00 mail postfix/smtp ";
        List<String> tls5424 = List.of(
            "<22>1 2026-09-25T19:00:00.000001+02:00 mail postfix/cleanup 1 - - 4TLS00001: message-id=<" + ID + ">",
            t5424 + "81242 - - " + opening13,
            t5424 + "81242 - - " + delivered);
        real("rfc 5424, stesso pid: TLS", "TLSv1.3 (TLS_AES_256_GCM_SHA384)".equals(PeriodicReport.outcomeInLog(tls5424, ID, A).optString("tls")));
        List<String> tls5424other = List.of(tls5424.get(0), t5424 + "81243 - - " + opening13, tls5424.get(2));
        real("rfc 5424, pid diverso: niente TLS", !PeriodicReport.outcomeInLog(tls5424other, ID, A).has("tls"));
        PeriodicReport.Row rr = PeriodicReport.line("Sep  5 07:02:11 mail postfix/smtp[81242]: " + delivered);
        real("riga classica con il giorno a una cifra: processo e testo",
            rr != null && "postfix/smtp[81242]".equals(rr.process()) && delivered.equals(rr.text()));

        // --- Il caso di produzione: il messaggio e' passato da dma, non da Postfix ---
        // Il vecchio codice qui diceva "riuscito". Il nuovo non deve dire "consegnato".
        List<String> dma = List.of(
            "Sep 25 17:40:01 mail dma[2c1a4]: new mail from user=root uid=0 envelope_from=<noreply-mailserver@domain-b.test>",
            "Sep 25 17:40:01 mail dma[2c1a4]: mail to=<owner@example.com> queued as 2c1a4.2a0b5c048000",
            "Sep 25 17:40:01 mail dma[2c1a4.2a0b5c048000]: <owner@example.com> trying delivery",
            "Sep 25 17:40:01 mail dma[2c1a4.2a0b5c048000]: trying remote delivery to gmail-smtp-in.l.google.com [142.250.102.27] pref 5",
            "Sep 25 17:40:02 mail dma[2c1a4.2a0b5c048000]: <owner@example.com> delivery successful");
        e = PeriodicReport.outcomeInLog(dma, ID, A);
        real("dma: Postfix non l'ha visto", e.optString("state").isEmpty() && !e.has("queue"));
        v = PeriodicReport.verdict(e);
        real("dma: il verdict e' un avviso, non 'consegnato'",
            v.optBoolean("warning") && !v.optString("outcome").startsWith("delivered"));

        // --- Rimandato: Postfix riprova da solo, il pannello non deve rimandarlo ---
        List<String> postponed = List.of(
            "Sep 25 18:00:00 mail postfix/cleanup[1]: 4ABCDEF123: message-id=<" + ID + ">",
            "Sep 25 18:00:30 mail postfix/smtp[2]: 4ABCDEF123: to=<owner@example.com>, relay=none, delay=30, delays=0.02/0.01/30/0, dsn=4.4.1, status=deferred (connect to gmail-smtp-in.l.google.com[142.250.102.27]:25: Connection timed out)");
        e = PeriodicReport.outcomeInLog(postponed, ID, A);
        real("rimandato: stato", "deferred".equals(e.optString("state")));
        real("rimandato: motivo", e.optString("answer").contains("Connection timed out"));
        v = PeriodicReport.verdict(e);
        real("rimandato: riuscito con avviso, cosi' lo scheduler non lo rimanda",
            v.optBoolean("success") && v.optBoolean("warning"));

        // --- Rimandato e poi consegnato: vale l'ultima riga ---
        List<String> thenDelivered = new java.util.ArrayList<>(postponed);
        thenDelivered.add("Sep 25 18:05:00 mail postfix/smtp[3]: 4ABCDEF123: to=<owner@example.com>, relay=alt1.gmail-smtp-in.l.google.com[142.250.150.27]:25, delay=300, delays=299/0/0.4/0.6, dsn=2.0.0, status=sent (250 2.0.0 OK - gsmtp)");
        real("rimandato e poi consegnato: consegnato",
            "delivered".equals(PeriodicReport.outcomeInLog(thenDelivered, ID, A).optString("state")));

        // --- Respinto da Gmail per DMARC: la risposta ha parentesi dentro le parentesi ---
        List<String> rejected = List.of(
            "Sep 25 18:10:00 mail postfix/cleanup[1]: 4ABCDEF124: message-id=<" + ID + ">",
            "Sep 25 18:10:01 mail postfix/smtp[2]: 4ABCDEF124: to=<owner@example.com>, relay=gmail-smtp-in.l.google.com[142.250.102.27]:25, delay=1.1, delays=0.05/0/0.4/0.6, dsn=5.7.26, status=bounced (host gmail-smtp-in.l.google.com[142.250.102.27] said: 550-5.7.26 Unauthenticated email from domain-b.test is not accepted due to domain's 550-5.7.26 DMARC policy. (in reply to end of DATA command))",
            "Sep 25 18:10:01 mail postfix/bounce[3]: 4ABCDEF124: sender non-delivery notification: 4ABCDEF125");
        e = PeriodicReport.outcomeInLog(rejected, ID, A);
        real("respinto: stato", "rejected".equals(e.optString("state")));
        real("respinto: risposta intera, parentesi comprese", e.optString("answer").endsWith("(in reply to end of DATA command)"));
        v = PeriodicReport.verdict(e);
        real("respinto: NON riuscito", !v.optBoolean("success"));
        real("respinto: l'errore dice da chi", v.optString("error").startsWith("respinto da gmail-smtp-in.l.google.com"));
        v = PeriodicReport.verdict(new JSONObject().put("state", "rejected").put("relay", "none").put("answer", "x"));
        real("respinto senza relay: niente 'da none'", "respinto: x".equals(v.optString("error")));

        // --- Rifiutato dal milter prima di partire; se il codice e' 4.x.x, e' solo rimandato ---
        List<String> milter5 = List.of(
            "Sep 25 18:20:00 mail postfix/cleanup[1]: 4ABCDEF126: message-id=<" + ID + ">",
            "Sep 25 18:20:00 mail postfix/cleanup[1]: 4ABCDEF126: milter-reject: END-OF-MESSAGE from localhost[127.0.0.1]: 5.7.1 Spam message rejected; from=<noreply-mailserver@domain-b.test> to=<owner@example.com>");
        e = PeriodicReport.outcomeInLog(milter5, ID, A);
        real("milter 5.7.1: rifiutato", "refused".equals(e.optString("state")));
        real("milter 5.7.1: NON riuscito", !PeriodicReport.verdict(e).optBoolean("success"));
        List<String> milter4 = List.of(milter5.get(0), milter5.get(1).replace("5.7.1 Spam message rejected", "4.7.1 Try again later"));
        real("milter 4.7.1: rimandato", "deferred".equals(PeriodicReport.outcomeInLog(milter4, ID, A).optString("state")));

        // --- Visto da Postfix, esito non ancora scritto ---
        e = PeriodicReport.outcomeInLog(gmail.subList(0, 3), ID, A);
        real("in coda: stato", "queued".equals(e.optString("state")));
        v = PeriodicReport.verdict(e);
        real("in coda: riuscito con avviso e il comando per cercarlo",
            v.optBoolean("success") && v.optBoolean("warning") && v.optString("note").contains("grep 4hB2Kq3Xz9zB6"));

        // --- Alias e copia nascosta: conta la riga del destinatario del rapporto ---
        String mine = "owner@domain-b.test";
        List<String> alias = List.of(
            "Sep 25 18:30:00 mail postfix/cleanup[1]: 4ABCDEF127: message-id=<" + ID + ">",
            "Sep 25 18:30:02 mail postfix/smtp[2]: 4ABCDEF127: to=<owner@example.com>, orig_to=<owner@domain-b.test>, relay=gmail-smtp-in.l.google.com[142.250.102.27]:25, delay=2, delays=0.1/0/1/0.9, dsn=2.0.0, status=sent (250 2.0.0 OK - gsmtp)",
            "Sep 25 18:30:02 mail postfix/lmtp[3]: 4ABCDEF127: to=<archivio@domain-b.test>, relay=127.0.0.1[127.0.0.1]:24, delay=2, delays=0.1/0/0/0.1, dsn=4.2.2, status=deferred (host 127.0.0.1[127.0.0.1] said: 452 4.2.2 Mailbox is full (in reply to end of DATA command))");
        e = PeriodicReport.outcomeInLog(alias, ID, mine);
        real("alias: conta orig_to, non la copia per l'archivio", "delivered".equals(e.optString("state")));

        // --- Formato RFC 5424, se syslogd lo usa ---
        List<String> rfc5424 = List.of(
            "<22>1 2026-09-25T17:52:10.123456+02:00 mail postfix/cleanup 81240 - - 4hB2Kq3Xz9zB6: message-id=<" + ID + ">",
            "<22>1 2026-09-25T17:52:12.654321+02:00 mail postfix/smtp 81242 - - 4hB2Kq3Xz9zB6: to=<owner@example.com>, relay=gmail-smtp-in.l.google.com[142.250.102.27]:25, delay=1.6, delays=0.1/0.01/0.52/0.97, dsn=2.0.0, status=sent (250 2.0.0 OK - gsmtp)");
        real("rfc 5424: consegnato", "delivered".equals(PeriodicReport.outcomeInLog(rfc5424, ID, A).optString("state")));

        // --- Confronti letterali, non espressioni regolari ---
        // Nel Message-ID il punto e' un punto: "rapportoX..." non e' il nostro messaggio.
        List<String> almost = List.of(
            "Sep 25 18:40:00 mail postfix/cleanup[1]: 4ABCDEF128: message-id=<" + ID.replace("rapporto.", "rapportoX") + ">",
            "Sep 25 18:40:01 mail postfix/smtp[2]: 4ABCDEF128: to=<owner@example.com>, relay=x[1.2.3.4]:25, delay=1, delays=0/0/0/1, dsn=2.0.0, status=sent (250 ok)");
        real("un Message-ID quasi uguale non e' il nostro", PeriodicReport.outcomeInLog(almost, ID, A).optString("state").isEmpty());
        // Un numero di coda che finisce come il nostro non e' il nostro.
        List<String> suffix = List.of(
            "Sep 25 18:50:00 mail postfix/cleanup[1]: 4ABC12: message-id=<" + ID + ">",
            "Sep 25 18:50:01 mail postfix/smtp[2]: X4ABC12: to=<owner@example.com>, relay=x[1.2.3.4]:25, delay=1, delays=0/0/0/1, dsn=5.0.0, status=bounced (no)");
        real("un numero di coda che finisce come il nostro non conta",
            "queued".equals(PeriodicReport.outcomeInLog(suffix, ID, A).optString("state")));

        // --- Il Message-ID che il pannello genera ---
        String id1 = PeriodicReport.newMessageId("noreply-mailserver@domain-b.test");
        String id2 = PeriodicReport.newMessageId("noreply-mailserver@domain-b.test");
        real("Message-ID: forma", id1.matches("rapporto\\.\\d{14}\\.[0-9a-f]{32}@domain-b\\.test"));
        real("Message-ID: due invii, due identificativi", !id1.equals(id2));

        // --- Quale sendmail ---
        Path d = Files.createTempDirectory("prova-sendmail");
        Path mw = runnable(d.resolve("mailwrapper"));
        Path postfix = runnable(d.resolve("postfix-sendmail"));
        Path other = runnable(d.resolve("altro-sendmail"));
        Path symbolic = Files.createSymbolicLink(d.resolve("sendmail-simbolico"), mw);
        Path physical = Files.createLink(d.resolve("sendmail-fisico"), mw);
        Path stopped = Files.writeString(d.resolve("non-runnable"), "x");
        String nobody = d.resolve("non-esiste").toString();

        JSONObject s = PeriodicReport.sendmailChoice(symbolic.toString(), postfix.toString(), mw.toString());
        real("sendmail_path che punta a mailwrapper: si usa quello del port",
            s.optBoolean("success") && postfix.toString().equals(s.optString("path")));
        s = PeriodicReport.sendmailChoice(other.toString(), postfix.toString(), mw.toString());
        real("vale quello che dice postconf", other.toString().equals(s.optString("path")));
        s = PeriodicReport.sendmailChoice("", postfix.toString(), mw.toString());
        real("postconf muto: si usa quello del port", postfix.toString().equals(s.optString("path")));
        s = PeriodicReport.sendmailChoice("postconf: warning: /usr/local/etc/postfix/main.cf: unused parameter", postfix.toString(), mw.toString());
        real("postconf che dice altro: ignorato", postfix.toString().equals(s.optString("path")));
        s = PeriodicReport.sendmailChoice(symbolic.toString(), physical.toString(), mw.toString());
        real("solo mailwrapper disponibile: errore, nessun ripiego",
            !s.optBoolean("success") && s.optString("error").contains("mailwrapper"));
        s = PeriodicReport.sendmailChoice(stopped.toString(), nobody, mw.toString());
        real("non runnable e inesistente: errore", !s.optBoolean("success") && s.optString("error").contains("non c'è"));
        real("hard link a mailwrapper: riconosciuto", PeriodicReport.notPostfix(physical.toString(), mw.toString()) != null);
        real("un sendmail vero: accettato", PeriodicReport.notPostfix(postfix.toString(), mw.toString()) == null);
        real("mailwrapper assente (non FreeBSD): non blocca",
            PeriodicReport.notPostfix(postfix.toString(), nobody) == null);

        System.out.println(failed == 0 ? "\nTUTTO OK" : "\n" + failed + " PROVE FALLITE");
        if (failed > 0) System.exit(1);
    }

    private static Path runnable(Path p) throws Exception {
        Files.writeString(p, "#!/bin/sh\n");
        Files.setPosixFilePermissions(p, PosixFilePermissions.fromString("rwxr-xr-x"));
        return p;
    }

    private static void real(String name, boolean ok) {
        System.out.println((ok ? "  ok   " : "  NO   ") + name);
        if (!ok) failed++;
    }
}
