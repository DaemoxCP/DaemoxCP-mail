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
 * cioe' mailwrapper, cioe' dma. dma consegnava da solo, in chiaro e senza firma DKIM, e il
 * pannello scriveva "riuscito" perche' guardava solo il codice di uscita. Qui si prova che
 * mailwrapper non viene mai scelto, e che con le righe di dma nel log l'esito NON diventa
 * "consegnato": Postfix quel messaggio non l'ha visto.
 */
public class ProvaConsegnaRapporto {

    private static int falliti = 0;

    private static final String ID = "rapporto.20260925155210.0f3a9c1d2b4e5f60718293a4b5c6d7e8@domain-b.test";
    private static final String A = "owner@example.com";

    public static void main(String[] args) throws Exception {
        // --- Consegnato a Gmail, con TLS: quello che deve succedere dopo la correzione ---
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
        JSONObject e = RapportoPeriodico.esitoNelLog(gmail, ID, A);
        vero("gmail: trova il numero di coda dal Message-ID", "4hB2Kq3Xz9zB6".equals(e.optString("coda")));
        vero("gmail: consegnato", "consegnato".equals(e.optString("stato")));
        vero("gmail: relay giusto", "gmail-smtp-in.l.google.com[142.250.102.27]:25".equals(e.optString("relay")));
        vero("gmail: risposta del server", e.optString("risposta").startsWith("250 2.0.0 OK"));
        vero("gmail: TLS letto dalla riga di smtp", "TLSv1.3 (TLS_AES_256_GCM_SHA384)".equals(e.optString("tls")));
        vero("gmail: le righe dell'altro messaggio restano fuori",
            !e.getJSONArray("righe").toString().contains("4hB2Kr0ABCzB7"));
        JSONObject v = RapportoPeriodico.verdetto(e);
        vero("gmail: verdetto riuscito e senza avviso", v.optBoolean("success") && !v.optBoolean("avviso"));
        vero("gmail: l'esito registrato dice dove e con quale TLS",
            v.optString("esito").startsWith("consegnato a gmail-smtp-in.l.google.com") && v.optString("esito").contains("TLSv1.3"));

        // --- Il caso di produzione: il messaggio e' passato da dma, non da Postfix ---
        // Il vecchio codice qui diceva "riuscito". Il nuovo non deve dire "consegnato".
        List<String> dma = List.of(
            "Sep 25 17:40:01 mail dma[2c1a4]: new mail from user=root uid=0 envelope_from=<noreply-mailserver@domain-b.test>",
            "Sep 25 17:40:01 mail dma[2c1a4]: mail to=<owner@example.com> queued as 2c1a4.2a0b5c048000",
            "Sep 25 17:40:01 mail dma[2c1a4.2a0b5c048000]: <owner@example.com> trying delivery",
            "Sep 25 17:40:01 mail dma[2c1a4.2a0b5c048000]: trying remote delivery to gmail-smtp-in.l.google.com [142.250.102.27] pref 5",
            "Sep 25 17:40:02 mail dma[2c1a4.2a0b5c048000]: <owner@example.com> delivery successful");
        e = RapportoPeriodico.esitoNelLog(dma, ID, A);
        vero("dma: Postfix non l'ha visto", e.optString("stato").isEmpty() && !e.has("coda"));
        v = RapportoPeriodico.verdetto(e);
        vero("dma: il verdetto e' un avviso, non 'consegnato'",
            v.optBoolean("avviso") && !v.optString("esito").startsWith("consegnato"));

        // --- Rimandato: Postfix riprova da solo, il pannello non deve rimandarlo ---
        List<String> rimandato = List.of(
            "Sep 25 18:00:00 mail postfix/cleanup[1]: 4ABCDEF123: message-id=<" + ID + ">",
            "Sep 25 18:00:30 mail postfix/smtp[2]: 4ABCDEF123: to=<owner@example.com>, relay=none, delay=30, delays=0.02/0.01/30/0, dsn=4.4.1, status=deferred (connect to gmail-smtp-in.l.google.com[142.250.102.27]:25: Connection timed out)");
        e = RapportoPeriodico.esitoNelLog(rimandato, ID, A);
        vero("rimandato: stato", "rimandato".equals(e.optString("stato")));
        vero("rimandato: motivo", e.optString("risposta").contains("Connection timed out"));
        v = RapportoPeriodico.verdetto(e);
        vero("rimandato: riuscito con avviso, cosi' lo scheduler non lo rimanda",
            v.optBoolean("success") && v.optBoolean("avviso"));

        // --- Rimandato e poi consegnato: vale l'ultima riga ---
        List<String> poiConsegnato = new java.util.ArrayList<>(rimandato);
        poiConsegnato.add("Sep 25 18:05:00 mail postfix/smtp[3]: 4ABCDEF123: to=<owner@example.com>, relay=alt1.gmail-smtp-in.l.google.com[142.250.150.27]:25, delay=300, delays=299/0/0.4/0.6, dsn=2.0.0, status=sent (250 2.0.0 OK - gsmtp)");
        vero("rimandato e poi consegnato: consegnato",
            "consegnato".equals(RapportoPeriodico.esitoNelLog(poiConsegnato, ID, A).optString("stato")));

        // --- Respinto da Gmail per DMARC: la risposta ha parentesi dentro le parentesi ---
        List<String> respinto = List.of(
            "Sep 25 18:10:00 mail postfix/cleanup[1]: 4ABCDEF124: message-id=<" + ID + ">",
            "Sep 25 18:10:01 mail postfix/smtp[2]: 4ABCDEF124: to=<owner@example.com>, relay=gmail-smtp-in.l.google.com[142.250.102.27]:25, delay=1.1, delays=0.05/0/0.4/0.6, dsn=5.7.26, status=bounced (host gmail-smtp-in.l.google.com[142.250.102.27] said: 550-5.7.26 Unauthenticated email from domain-b.test is not accepted due to domain's 550-5.7.26 DMARC policy. (in reply to end of DATA command))",
            "Sep 25 18:10:01 mail postfix/bounce[3]: 4ABCDEF124: sender non-delivery notification: 4ABCDEF125");
        e = RapportoPeriodico.esitoNelLog(respinto, ID, A);
        vero("respinto: stato", "respinto".equals(e.optString("stato")));
        vero("respinto: risposta intera, parentesi comprese", e.optString("risposta").endsWith("(in reply to end of DATA command)"));
        v = RapportoPeriodico.verdetto(e);
        vero("respinto: NON riuscito", !v.optBoolean("success"));
        vero("respinto: l'errore dice da chi", v.optString("error").startsWith("respinto da gmail-smtp-in.l.google.com"));
        v = RapportoPeriodico.verdetto(new JSONObject().put("stato", "respinto").put("relay", "none").put("risposta", "x"));
        vero("respinto senza relay: niente 'da none'", "respinto: x".equals(v.optString("error")));

        // --- Rifiutato dal milter prima di partire; se il codice e' 4.x.x, e' solo rimandato ---
        List<String> milter5 = List.of(
            "Sep 25 18:20:00 mail postfix/cleanup[1]: 4ABCDEF126: message-id=<" + ID + ">",
            "Sep 25 18:20:00 mail postfix/cleanup[1]: 4ABCDEF126: milter-reject: END-OF-MESSAGE from localhost[127.0.0.1]: 5.7.1 Spam message rejected; from=<noreply-mailserver@domain-b.test> to=<owner@example.com>");
        e = RapportoPeriodico.esitoNelLog(milter5, ID, A);
        vero("milter 5.7.1: rifiutato", "rifiutato".equals(e.optString("stato")));
        vero("milter 5.7.1: NON riuscito", !RapportoPeriodico.verdetto(e).optBoolean("success"));
        List<String> milter4 = List.of(milter5.get(0), milter5.get(1).replace("5.7.1 Spam message rejected", "4.7.1 Try again later"));
        vero("milter 4.7.1: rimandato", "rimandato".equals(RapportoPeriodico.esitoNelLog(milter4, ID, A).optString("stato")));

        // --- Visto da Postfix, esito non ancora scritto ---
        e = RapportoPeriodico.esitoNelLog(gmail.subList(0, 3), ID, A);
        vero("in coda: stato", "in coda".equals(e.optString("stato")));
        v = RapportoPeriodico.verdetto(e);
        vero("in coda: riuscito con avviso e il comando per cercarlo",
            v.optBoolean("success") && v.optBoolean("avviso") && v.optString("nota").contains("grep 4hB2Kq3Xz9zB6"));

        // --- Alias e copia nascosta: conta la riga del destinatario del rapporto ---
        String mio = "owner@domain-b.test";
        List<String> alias = List.of(
            "Sep 25 18:30:00 mail postfix/cleanup[1]: 4ABCDEF127: message-id=<" + ID + ">",
            "Sep 25 18:30:02 mail postfix/smtp[2]: 4ABCDEF127: to=<owner@example.com>, orig_to=<owner@domain-b.test>, relay=gmail-smtp-in.l.google.com[142.250.102.27]:25, delay=2, delays=0.1/0/1/0.9, dsn=2.0.0, status=sent (250 2.0.0 OK - gsmtp)",
            "Sep 25 18:30:02 mail postfix/lmtp[3]: 4ABCDEF127: to=<archivio@domain-b.test>, relay=127.0.0.1[127.0.0.1]:24, delay=2, delays=0.1/0/0/0.1, dsn=4.2.2, status=deferred (host 127.0.0.1[127.0.0.1] said: 452 4.2.2 Mailbox is full (in reply to end of DATA command))");
        e = RapportoPeriodico.esitoNelLog(alias, ID, mio);
        vero("alias: conta orig_to, non la copia per l'archivio", "consegnato".equals(e.optString("stato")));

        // --- Formato RFC 5424, se syslogd lo usa ---
        List<String> rfc5424 = List.of(
            "<22>1 2026-09-25T17:52:10.123456+02:00 mail postfix/cleanup 81240 - - 4hB2Kq3Xz9zB6: message-id=<" + ID + ">",
            "<22>1 2026-09-25T17:52:12.654321+02:00 mail postfix/smtp 81242 - - 4hB2Kq3Xz9zB6: to=<owner@example.com>, relay=gmail-smtp-in.l.google.com[142.250.102.27]:25, delay=1.6, delays=0.1/0.01/0.52/0.97, dsn=2.0.0, status=sent (250 2.0.0 OK - gsmtp)");
        vero("rfc 5424: consegnato", "consegnato".equals(RapportoPeriodico.esitoNelLog(rfc5424, ID, A).optString("stato")));

        // --- Confronti letterali, non espressioni regolari ---
        // Nel Message-ID il punto e' un punto: "rapportoX..." non e' il nostro messaggio.
        List<String> quasi = List.of(
            "Sep 25 18:40:00 mail postfix/cleanup[1]: 4ABCDEF128: message-id=<" + ID.replace("rapporto.", "rapportoX") + ">",
            "Sep 25 18:40:01 mail postfix/smtp[2]: 4ABCDEF128: to=<owner@example.com>, relay=x[1.2.3.4]:25, delay=1, delays=0/0/0/1, dsn=2.0.0, status=sent (250 ok)");
        vero("un Message-ID quasi uguale non e' il nostro", RapportoPeriodico.esitoNelLog(quasi, ID, A).optString("stato").isEmpty());
        // Un numero di coda che finisce come il nostro non e' il nostro.
        List<String> suffisso = List.of(
            "Sep 25 18:50:00 mail postfix/cleanup[1]: 4ABC12: message-id=<" + ID + ">",
            "Sep 25 18:50:01 mail postfix/smtp[2]: X4ABC12: to=<owner@example.com>, relay=x[1.2.3.4]:25, delay=1, delays=0/0/0/1, dsn=5.0.0, status=bounced (no)");
        vero("un numero di coda che finisce come il nostro non conta",
            "in coda".equals(RapportoPeriodico.esitoNelLog(suffisso, ID, A).optString("stato")));

        // --- Il Message-ID che il pannello genera ---
        String id1 = RapportoPeriodico.nuovoMessageId("noreply-mailserver@domain-b.test");
        String id2 = RapportoPeriodico.nuovoMessageId("noreply-mailserver@domain-b.test");
        vero("Message-ID: forma", id1.matches("rapporto\\.\\d{14}\\.[0-9a-f]{32}@domain-b\\.test"));
        vero("Message-ID: due invii, due identificativi", !id1.equals(id2));

        // --- Quale sendmail ---
        Path d = Files.createTempDirectory("prova-sendmail");
        Path mw = eseguibile(d.resolve("mailwrapper"));
        Path postfix = eseguibile(d.resolve("postfix-sendmail"));
        Path altro = eseguibile(d.resolve("altro-sendmail"));
        Path simbolico = Files.createSymbolicLink(d.resolve("sendmail-simbolico"), mw);
        Path fisico = Files.createLink(d.resolve("sendmail-fisico"), mw);
        Path fermo = Files.writeString(d.resolve("non-eseguibile"), "x");
        String nessuno = d.resolve("non-esiste").toString();

        JSONObject s = RapportoPeriodico.sceltaSendmail(simbolico.toString(), postfix.toString(), mw.toString());
        vero("sendmail_path che punta a mailwrapper: si usa quello del port",
            s.optBoolean("success") && postfix.toString().equals(s.optString("percorso")));
        s = RapportoPeriodico.sceltaSendmail(altro.toString(), postfix.toString(), mw.toString());
        vero("vale quello che dice postconf", altro.toString().equals(s.optString("percorso")));
        s = RapportoPeriodico.sceltaSendmail("", postfix.toString(), mw.toString());
        vero("postconf muto: si usa quello del port", postfix.toString().equals(s.optString("percorso")));
        s = RapportoPeriodico.sceltaSendmail("postconf: warning: /usr/local/etc/postfix/main.cf: unused parameter", postfix.toString(), mw.toString());
        vero("postconf che dice altro: ignorato", postfix.toString().equals(s.optString("percorso")));
        s = RapportoPeriodico.sceltaSendmail(simbolico.toString(), fisico.toString(), mw.toString());
        vero("solo mailwrapper disponibile: errore, nessun ripiego",
            !s.optBoolean("success") && s.optString("error").contains("mailwrapper"));
        s = RapportoPeriodico.sceltaSendmail(fermo.toString(), nessuno, mw.toString());
        vero("non eseguibile e inesistente: errore", !s.optBoolean("success") && s.optString("error").contains("non c'e'"));
        vero("hard link a mailwrapper: riconosciuto", RapportoPeriodico.nonEPostfix(fisico.toString(), mw.toString()) != null);
        vero("un sendmail vero: accettato", RapportoPeriodico.nonEPostfix(postfix.toString(), mw.toString()) == null);
        vero("mailwrapper assente (non FreeBSD): non blocca",
            RapportoPeriodico.nonEPostfix(postfix.toString(), nessuno) == null);

        System.out.println(falliti == 0 ? "\nTUTTO OK" : "\n" + falliti + " PROVE FALLITE");
        if (falliti > 0) System.exit(1);
    }

    private static Path eseguibile(Path p) throws Exception {
        Files.writeString(p, "#!/bin/sh\n");
        Files.setPosixFilePermissions(p, PosixFilePermissions.fromString("rwxr-xr-x"));
        return p;
    }

    private static void vero(String nome, boolean ok) {
        System.out.println((ok ? "  ok   " : "  NO   ") + nome);
        if (!ok) falliti++;
    }
}
