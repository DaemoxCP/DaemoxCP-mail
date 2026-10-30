package org.mail_panel.system;

import org.mail_panel.util.Shell;

import java.util.List;

/**
 * Prova la logica che il piano MTA-STS usa per decidere, con i casi veri del server.
 * Non prova che il codice compili: prova che dica il vero.
 *
 * La lettura del record TXT si prova in due modi. Il significato di ogni uscita di dig, con
 * uscite vere registrate (piu' varianti costruite su di loro): vale ovunque, anche senza rete.
 * Poi il DNS vero: se da qui si raggiunge si esigono i fatti veri (su domain-d.test il record
 * c'e', un SERVFAIL non e' "assente"), altrimenti si esige che la lettura dica NON_CHIESTO e
 * mai un ASSENTE inventato. Prima la prova dava per scontato il DNS e falliva su ogni macchina
 * che non ce l'aveva, con la lettura che rispondeva il giusto.
 *
 * Due record v=STSv1 sullo stesso nome valgono zero per i mittenti (RFC 8461 §3.1): la
 * lettura deve dire TROPPI, e il passo del record nel piano non deve risultare fatto.
 */
public class MtaStsTest {

    static int failed = 0;

    static void require(String what, boolean condition) {
        System.out.println((condition ? "  OK   " : "  FALLITO ") + what);
        if (!condition) failed++;
    }

    static void randomBytes(String what, int digOutput, String printed, MtaStsSetup.TxtOutcome outcome, String content) {
        MtaStsSetup.TxtReading l = MtaStsSetup.parseTxt(digOutput, printed);
        require(what + " -> " + l.outcome + (l.content.isEmpty() ? "" : " \"" + l.content + "\""),
                l.outcome == outcome && l.content.equals(content));
    }

    /** Lo stato della risposta di dig per un TXT (NOERROR, NXDOMAIN, SERVFAIL...), o "". */
    static String digState(String name) {
        try {
            ProcessBuilder pb = new ProcessBuilder("dig", "+noall", "+comments", "+time=3", "+tries=1", "TXT", name);
            Shell.applyPath(pb);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            String out = new String(p.getInputStream().readAllBytes());
            p.waitFor();
            java.util.regex.Matcher m = java.util.regex.Pattern.compile("status:\\s*([A-Z]+)").matcher(out);
            return m.find() ? m.group(1) : "";
        } catch (Exception e) {
            return "";
        }
    }

    /** Da qui dig arriva a un DNS? Si chiede chi serve la radice, con poca pazienza. */
    static boolean digAnswers() {
        try {
            ProcessBuilder pb = new ProcessBuilder("dig", "+short", "+time=3", "+tries=1", ".", "NS");
            Shell.applyPath(pb);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            String out = new String(p.getInputStream().readAllBytes()).trim();
            return p.waitFor() == 0 && !out.isEmpty();
        } catch (Exception e) {
            return false;   // dig che non c'e'
        }
    }

    /** Il passo "txt" fra quelli che testAndTxtSteps() restituisce. */
    static MtaStsSetup.Step txtStep(List<MtaStsSetup.TxtReview> reviews, String expected) {
        for (MtaStsSetup.Step p : MtaStsSetup.testAndTxtSteps(reviews, expected))
            if ("txt".equals(p.key)) return p;
        throw new IllegalStateException("manca il passo txt");
    }

    static MtaStsSetup.NameReview e(String d, MtaStsSetup.NameState s, String m,
                                    boolean resolves, boolean proxy, boolean crooked) {
        return new MtaStsSetup.NameReview(d, s, m, resolves, proxy, crooked);
    }

    public static void main(String[] a) throws Exception {

        System.out.println("\n== ripartisci(): il caso vero di domain-d.test ==");
        // Nella zona non c'e' mta-sts.domain-d.test; risponde il jolly *.domain-d.test, proxato.
        var rip = MtaStsSetup.split(List.of(
                e("domain-d.test", MtaStsSetup.NameState.ABSENT, "nella zona non c'e'", true, true, false)));
        require("il dominio finisce fra gli assenti", rip.absent.size() == 1);
        require("e ANCHE fra quelli che passano dal proxy (era il falso verde)", rip.proxied.size() == 1);
        require("il piano sa che il proxy viene da un jolly", rip.proxyDaJolly);
        require("la riga del proxy nomina il jolly", rip.proxied.get(0).contains("*.domain-d.test"));

        System.out.println("\n== ripartisci(): record insieme SBAGLIATO e PROXATO ==");
        // Prima finiva nel solo conto del proxy, perche' il motivo conteneva "Cloudflare":
        // il passo dei CNAME dichiarava "tutti presenti e giusti" un record che puntava altrove.
        rip = MtaStsSetup.split(List.of(
                e("x.it", MtaStsSetup.NameState.TO_FIX,
                  "punta a \"altro.host\" invece che a \"mail.domain-b.test\"; passa da Cloudflare",
                  true, true, true)));
        require("compare fra gli storti", rip.crooked.size() == 1);
        require("compare ANCHE fra i proxati", rip.proxied.size() == 1);
        require("il proxy non viene da un jolly", !rip.proxyDaJolly);

        System.out.println("\n== ripartisci(): record giusto ma proxato ==");
        rip = MtaStsSetup.split(List.of(
                e("y.it", MtaStsSetup.NameState.TO_FIX, "passa da Cloudflare", true, true, false)));
        require("non e' storto", rip.crooked.isEmpty());
        require("e' proxato", rip.proxied.size() == 1);

        System.out.println("\n== ripartisci(): cieco, propagazione, tutto a posto ==");
        rip = MtaStsSetup.split(List.of(
                e("c.it", MtaStsSetup.NameState.BLIND, "zona non visibile", false, false, false),
                e("p.it", MtaStsSetup.NameState.RIGHT, "punta dritto", false, false, false),
                e("ok.it", MtaStsSetup.NameState.RIGHT, "punta dritto", true, false, false)));
        require("il cieco resta cieco", rip.blind.size() == 1);
        require("il giusto che non risolve ancora e' in propagazione", rip.propagating.size() == 1);
        require("il giusto che risolve non compare da nessuna parte",
                rip.absent.isEmpty() && rip.crooked.isEmpty() && rip.proxied.isEmpty());

        System.out.println("\n== interpretaTxt(): cosa vuol dire ogni uscita di dig ==");
        // Uscite VERE di "dig +noall +comments +answer TXT _mta-sts.<dominio>", registrate il
        // 2/10/2026 con BIND 9.18 e il resolver 8.8.8.8 (che convalida DNSSEC).
        String domainD = ";; Got answer:\n;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 32535\n;; flags: qr rd ra ad; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1\n\n;; OPT PSEUDOSECTION:\n; EDNS: version: 0, flags:; udp: 512\n;; ANSWER SECTION:\n_mta-sts.domain-d.test.\t3498\tIN\tTXT\t\"v=STSv1; id=0fec393151a7c577266a\"\n\n";
        String servfail = ";; Got answer:\n;; ->>HEADER<<- opcode: QUERY, status: SERVFAIL, id: 37005\n;; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1\n\n;; OPT PSEUDOSECTION:\n; EDNS: version: 0, flags:; udp: 512\n; EDE: 9 (DNSKEY Missing): (No DNSKEY matches DS RRs of dnssec-failed.org)\n";
        String nxdomain = ";; Got answer:\n;; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 2902\n;; flags: qr rd ra ad; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 1\n\n;; OPT PSEUDOSECTION:\n; EDNS: version: 0, flags:; udp: 512\n";
        String withoutTxt = ";; Got answer:\n;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 19074\n;; flags: qr rd ra ad; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 1\n\n;; OPT PSEUDOSECTION:\n; EDNS: version: 0, flags:; udp: 512\n";
        String unreachable = ";; communications error to 192.0.2.1#53: connection refused\n;; no servers could be reached\n";
        randomBytes("domain-d.test, record pubblicato", 0, domainD,
                MtaStsSetup.TxtOutcome.PRESENT, "v=STSv1; id=0fec393151a7c577266a");
        randomBytes("dnssec-failed.org, SERVFAIL: il DNS non dice che cosa c'e'", 0, servfail,
                MtaStsSetup.TxtOutcome.NOT_ASKED, "");
        randomBytes("nome inesistente (NXDOMAIN)", 0, nxdomain, MtaStsSetup.TxtOutcome.ABSENT, "");
        randomBytes("example.com, il nome c'e' ma senza TXT", 0, withoutTxt, MtaStsSetup.TxtOutcome.ABSENT, "");
        randomBytes("DNS che non risponde (dig esce con 9)", 9, unreachable, MtaStsSetup.TxtOutcome.NOT_ASKED, "");
        // Il piano scrive il perche' accanto al dominio: un SERVFAIL si cerca nella zona, un
        // DNS che non risponde nella rete di questo server.
        String why = MtaStsSetup.parseTxt(0, servfail).reason;
        require("il piano dice che il DNS ha risposto SERVFAIL: \"" + why + "\"", why.contains("SERVFAIL"));
        why = MtaStsSetup.parseTxt(9, unreachable).reason;
        require("e che nessun DNS ha risposto: \"" + why + "\"", why.equals("nessun DNS risponde"));
        // Varianti costruite sulla risposta vera di domain-d.test.
        String line = "_mta-sts.domain-d.test.\t3498\tIN\tTXT\t\"v=STSv1; id=0fec393151a7c577266a\"";
        randomBytes("record spezzato in due stringhe", 0,
                domainD.replace(line, "_mta-sts.domain-d.test.\t3498\tIN\tTXT\t\"v=STSv1; \" \"id=0fec393151a7c577266a\""),
                MtaStsSetup.TxtOutcome.PRESENT, "v=STSv1; id=0fec393151a7c577266a");
        randomBytes("accanto a un altro TXT sullo stesso nome", 0,
                domainD.replace(line, "_mta-sts.domain-d.test.\t3498\tIN\tTXT\t\"google-site-verification=abc\"\n" + line),
                MtaStsSetup.TxtOutcome.PRESENT, "v=STSv1; id=0fec393151a7c577266a");
        randomBytes("dietro un CNAME", 0,
                domainD.replace(line, "_mta-sts.domain-d.test.\t300\tIN\tCNAME\t_mta-sts.other.net.\n_mta-sts.other.net.\t300\tIN\tTXT\t\"v=STSv1; id=7\""),
                MtaStsSetup.TxtOutcome.PRESENT, "v=STSv1; id=7");
        randomBytes("maiuscole", 0, domainD.replace("v=STSv1; id=0fec393151a7c577266a", "V=STSV1; id=2"),
                MtaStsSetup.TxtOutcome.PRESENT, "V=STSV1; id=2");
        randomBytes("solo altri TXT", 0, domainD.replace(line, "_mta-sts.domain-d.test.\t3498\tIN\tTXT\t\"google-site-verification=abc\""),
                MtaStsSetup.TxtOutcome.ABSENT, "");
        randomBytes("REFUSED", 0, servfail.replace("SERVFAIL", "REFUSED"), MtaStsSetup.TxtOutcome.NOT_ASKED, "");
        randomBytes("uscita senza lo stato della risposta", 0, "qualcosa che non e' dig\n", MtaStsSetup.TxtOutcome.NOT_ASKED, "");
        // Con "dig +short" (com'era) SERVFAIL e NXDOMAIN stampano la stessa cosa, cioe' niente:
        // per questo la lettura chiede lo stato della risposta.
        randomBytes("l'uscita di dig +short di un SERVFAIL non basta a dire ASSENTE", 0, "", MtaStsSetup.TxtOutcome.NOT_ASKED, "");

        System.out.println("\n== interpretaTxt(): due record v=STSv1 sullo stesso nome ==");
        // Per i mittenti valgono zero (RFC 8461 §3.1). Prima la lettura prendeva il primo e
        // diceva PRESENTE: qui il primo e' proprio quello giusto, il caso piu' ingannevole.
        String old = "_mta-sts.domain-d.test.\t3498\tIN\tTXT\t\"v=STSv1; id=1700000000000\"";
        String due = domainD.replace(line, line + "\n" + old);
        randomBytes("il giusto e uno con l'id vecchio", 0, due, MtaStsSetup.TxtOutcome.TOO_MANY, "");
        MtaStsSetup.TxtReading l2 = MtaStsSetup.parseTxt(0, due);
        require("e li riporta tutti e due: " + l2.values,
                l2.values.equals(List.of("v=STSv1; id=0fec393151a7c577266a", "v=STSv1; id=1700000000000")));
        randomBytes("uno scritto in maiuscolo (mailauth lo conta)", 0,
                domainD.replace(line, line + "\n_mta-sts.domain-d.test.\t3498\tIN\tTXT\t\"V=STSV1; id=2\""),
                MtaStsSetup.TxtOutcome.TOO_MANY, "");
        randomBytes("due record e un TXT che non c'entra", 0,
                domainD.replace(line, "_mta-sts.domain-d.test.\t3498\tIN\tTXT\t\"google-site-verification=abc\"\n"
                        + line + "\n" + old),
                MtaStsSetup.TxtOutcome.TOO_MANY, "");
        randomBytes("stesso testo, ma due record (uno spezzato): sono due", 0,
                domainD.replace(line, line + "\n_mta-sts.domain-d.test.\t3498\tIN\tTXT\t\"v=STSv1; \" \"id=0fec393151a7c577266a\""),
                MtaStsSetup.TxtOutcome.TOO_MANY, "");
        randomBytes("due record dietro un CNAME", 0,
                domainD.replace(line, "_mta-sts.domain-d.test.\t300\tIN\tCNAME\t_mta-sts.other.net.\n"
                        + "_mta-sts.other.net.\t300\tIN\tTXT\t\"v=STSv1; id=7\"\n"
                        + "_mta-sts.other.net.\t300\tIN\tTXT\t\"v=STSv1; id=8\""),
                MtaStsSetup.TxtOutcome.TOO_MANY, "");

        System.out.println("\n== passiProvaETxt(): il passo del record nel piano ==");
        String expected = "v=STSv1; id=0fec393151a7c577266a";
        MtaStsSetup.TxtReading one = MtaStsSetup.parseTxt(0, domainD);
        MtaStsSetup.Step p = txtStep(List.of(
                new MtaStsSetup.TxtReview("domain-d.test", true, one)), expected);
        require("un record giusto e la politica che risponde: fatto (" + p.detail + ")", "fatto".equals(p.state));
        p = txtStep(List.of(new MtaStsSetup.TxtReview("domain-d.test", true, l2)), expected);
        require("due record, anche col primo giusto: NON fatto -> " + p.state + " (" + p.detail + ")",
                "da fare".equals(p.state));
        require("il dettaglio nomina tutti e due i record",
                p.detail.contains("id=0fec393151a7c577266a") && p.detail.contains("id=1700000000000"));
        require("e il motivo dice perche' conta", p.reason != null && p.reason.contains("RFC 8461"));
        p = txtStep(List.of(new MtaStsSetup.TxtReview("domain-d.test", true, l2),
                             new MtaStsSetup.TxtReview("domain-a.test", true, one)), expected);
        require("un dominio a posto non copre quello con due record: " + p.state, "da fare".equals(p.state));
        p = txtStep(List.of(new MtaStsSetup.TxtReview("domain-d.test", false, l2)), expected);
        require("due record e la politica che non risponde: segnalati come non mantenuti (" + p.detail + ")",
                "da fare".equals(p.state) && p.detail.contains("NON mantenuto"));
        p = txtStep(List.of(new MtaStsSetup.TxtReview("domain-d.test", true,
                MtaStsSetup.parseTxt(0, servfail))), expected);
        require("un SERVFAIL resta incerto, col motivo (" + p.detail + ")",
                "incerto".equals(p.state) && p.detail.contains("SERVFAIL"));

        System.out.println("\n== leggiTxt(): il DNS vero, sui domini veri ==");
        if (digAnswers()) {
            for (String d : new String[]{"domain-d.test", "domain-a.test", "domain-b.test",
                                         "nome-che-non-esiste-99887.invalid"}) {
                MtaStsSetup.TxtReading l = MtaStsSetup.readTxt(d);
                System.out.println("  " + d + " -> " + l.outcome + "  \"" + l.content + "\"");
                if (d.equals("domain-d.test")) {
                    require("su domain-d.test il TXT viene VISTO (prima il piano non ci arrivava)",
                            l.outcome == MtaStsSetup.TxtOutcome.PRESENT);
                    require("e se ne legge il contenuto", l.content.startsWith("v=STSv1"));
                }
                if (d.endsWith(".invalid"))
                    require("un nome inesistente e' ASSENTE, non NON_CHIESTO",
                            l.outcome == MtaStsSetup.TxtOutcome.ABSENT);
            }
            // dnssec-failed.org ha il DNSSEC rotto apposta: un resolver che lo convalida risponde
            // SERVFAIL. Se questo lo fa, la lettura deve dire NON_CHIESTO, non ASSENTE.
            if (digState("_mta-sts.dnssec-failed.org").equals("SERVFAIL")) {
                MtaStsSetup.TxtReading l = MtaStsSetup.readTxt("dnssec-failed.org");
                System.out.println("  dnssec-failed.org -> " + l.outcome + " (" + l.reason + ")");
                require("un SERVFAIL e' NON_CHIESTO, non ASSENTE", l.outcome == MtaStsSetup.TxtOutcome.NOT_ASKED);
            } else {
                System.out.println("  (il resolver di questa macchina non convalida DNSSEC: SERVFAIL provato solo qui sopra)");
            }
        } else {
            // dig assente o rete chiusa: non si e' chiesto niente a nessuno, e la lettura deve
            // dirlo. Un ASSENTE qui farebbe proporre di pubblicare un record che forse c'e' gia'.
            System.out.println("  da qui dig non arriva a un DNS: la lettura deve dire NON_CHIESTO");
            for (String d : new String[]{"domain-d.test", "nome-che-non-esiste-99887.invalid"}) {
                MtaStsSetup.TxtReading l = MtaStsSetup.readTxt(d);
                require(d + " -> " + l.outcome + ", non ASSENTE ne' PRESENTE",
                        l.outcome == MtaStsSetup.TxtOutcome.NOT_ASKED);
            }
        }

        System.out.println("\n" + (failed == 0 ? "TUTTO VERDE" : failed + " CONTROLLI FALLITI"));
        if (failed > 0) System.exit(1);
    }
}
