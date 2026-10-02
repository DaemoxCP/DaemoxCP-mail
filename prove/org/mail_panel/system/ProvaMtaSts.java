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
public class ProvaMtaSts {

    static int falliti = 0;

    static void esigi(String cosa, boolean condizione) {
        System.out.println((condizione ? "  OK   " : "  FALLITO ") + cosa);
        if (!condizione) falliti++;
    }

    static void caso(String cosa, int uscitaDig, String stampato, AttivaMtaSts.EsitoTxt esito, String contenuto) {
        AttivaMtaSts.LetturaTxt l = AttivaMtaSts.interpretaTxt(uscitaDig, stampato);
        esigi(cosa + " -> " + l.esito + (l.contenuto.isEmpty() ? "" : " \"" + l.contenuto + "\""),
                l.esito == esito && l.contenuto.equals(contenuto));
    }

    /** Lo stato della risposta di dig per un TXT (NOERROR, NXDOMAIN, SERVFAIL...), o "". */
    static String statoDig(String nome) {
        try {
            ProcessBuilder pb = new ProcessBuilder("dig", "+noall", "+comments", "+time=3", "+tries=1", "TXT", nome);
            Shell.applicaPath(pb);
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
    static boolean digRisponde() {
        try {
            ProcessBuilder pb = new ProcessBuilder("dig", "+short", "+time=3", "+tries=1", ".", "NS");
            Shell.applicaPath(pb);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            String out = new String(p.getInputStream().readAllBytes()).trim();
            return p.waitFor() == 0 && !out.isEmpty();
        } catch (Exception e) {
            return false;   // dig che non c'e'
        }
    }

    /** Il passo "txt" fra quelli che passiProvaETxt() restituisce. */
    static AttivaMtaSts.Passo passoTxt(List<AttivaMtaSts.EsameTxt> esami, String atteso) {
        for (AttivaMtaSts.Passo p : AttivaMtaSts.passiProvaETxt(esami, atteso))
            if ("txt".equals(p.chiave)) return p;
        throw new IllegalStateException("manca il passo txt");
    }

    static AttivaMtaSts.EsameNome e(String d, AttivaMtaSts.StatoNome s, String m,
                                    boolean risolve, boolean proxy, boolean storto) {
        return new AttivaMtaSts.EsameNome(d, s, m, risolve, proxy, storto);
    }

    public static void main(String[] a) throws Exception {

        System.out.println("\n== ripartisci(): il caso vero di domain-d.test ==");
        // Nella zona non c'e' mta-sts.domain-d.test; risponde il jolly *.domain-d.test, proxato.
        var rip = AttivaMtaSts.ripartisci(List.of(
                e("domain-d.test", AttivaMtaSts.StatoNome.ASSENTE, "nella zona non c'e'", true, true, false)));
        esigi("il dominio finisce fra gli assenti", rip.assenti.size() == 1);
        esigi("e ANCHE fra quelli che passano dal proxy (era il falso verde)", rip.proxati.size() == 1);
        esigi("il piano sa che il proxy viene da un jolly", rip.proxyDaJolly);
        esigi("la riga del proxy nomina il jolly", rip.proxati.get(0).contains("*.domain-d.test"));

        System.out.println("\n== ripartisci(): record insieme SBAGLIATO e PROXATO ==");
        // Prima finiva nel solo conto del proxy, perche' il motivo conteneva "Cloudflare":
        // il passo dei CNAME dichiarava "tutti presenti e giusti" un record che puntava altrove.
        rip = AttivaMtaSts.ripartisci(List.of(
                e("x.it", AttivaMtaSts.StatoNome.DA_CORREGGERE,
                  "punta a \"altro.host\" invece che a \"mail.domain-b.test\"; passa da Cloudflare",
                  true, true, true)));
        esigi("compare fra gli storti", rip.storti.size() == 1);
        esigi("compare ANCHE fra i proxati", rip.proxati.size() == 1);
        esigi("il proxy non viene da un jolly", !rip.proxyDaJolly);

        System.out.println("\n== ripartisci(): record giusto ma proxato ==");
        rip = AttivaMtaSts.ripartisci(List.of(
                e("y.it", AttivaMtaSts.StatoNome.DA_CORREGGERE, "passa da Cloudflare", true, true, false)));
        esigi("non e' storto", rip.storti.isEmpty());
        esigi("e' proxato", rip.proxati.size() == 1);

        System.out.println("\n== ripartisci(): cieco, propagazione, tutto a posto ==");
        rip = AttivaMtaSts.ripartisci(List.of(
                e("c.it", AttivaMtaSts.StatoNome.CIECO, "zona non visibile", false, false, false),
                e("p.it", AttivaMtaSts.StatoNome.GIUSTO, "punta dritto", false, false, false),
                e("ok.it", AttivaMtaSts.StatoNome.GIUSTO, "punta dritto", true, false, false)));
        esigi("il cieco resta cieco", rip.ciechi.size() == 1);
        esigi("il giusto che non risolve ancora e' in propagazione", rip.inPropagazione.size() == 1);
        esigi("il giusto che risolve non compare da nessuna parte",
                rip.assenti.isEmpty() && rip.storti.isEmpty() && rip.proxati.isEmpty());

        System.out.println("\n== interpretaTxt(): cosa vuol dire ogni uscita di dig ==");
        // Uscite VERE di "dig +noall +comments +answer TXT _mta-sts.<dominio>", registrate il
        // 2/10/2026 con BIND 9.18 e il resolver 8.8.8.8 (che convalida DNSSEC).
        String domainD = ";; Got answer:\n;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 32535\n;; flags: qr rd ra ad; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1\n\n;; OPT PSEUDOSECTION:\n; EDNS: version: 0, flags:; udp: 512\n;; ANSWER SECTION:\n_mta-sts.domain-d.test.\t3498\tIN\tTXT\t\"v=STSv1; id=0fec393151a7c577266a\"\n\n";
        String servfail = ";; Got answer:\n;; ->>HEADER<<- opcode: QUERY, status: SERVFAIL, id: 37005\n;; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1\n\n;; OPT PSEUDOSECTION:\n; EDNS: version: 0, flags:; udp: 512\n; EDE: 9 (DNSKEY Missing): (No DNSKEY matches DS RRs of dnssec-failed.org)\n";
        String nxdomain = ";; Got answer:\n;; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 2902\n;; flags: qr rd ra ad; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 1\n\n;; OPT PSEUDOSECTION:\n; EDNS: version: 0, flags:; udp: 512\n";
        String senzaTxt = ";; Got answer:\n;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 19074\n;; flags: qr rd ra ad; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 1\n\n;; OPT PSEUDOSECTION:\n; EDNS: version: 0, flags:; udp: 512\n";
        String irraggiungibile = ";; communications error to 192.0.2.1#53: connection refused\n;; no servers could be reached\n";
        caso("domain-d.test, record pubblicato", 0, domainD,
                AttivaMtaSts.EsitoTxt.PRESENTE, "v=STSv1; id=0fec393151a7c577266a");
        caso("dnssec-failed.org, SERVFAIL: il DNS non dice che cosa c'e'", 0, servfail,
                AttivaMtaSts.EsitoTxt.NON_CHIESTO, "");
        caso("nome inesistente (NXDOMAIN)", 0, nxdomain, AttivaMtaSts.EsitoTxt.ASSENTE, "");
        caso("example.com, il nome c'e' ma senza TXT", 0, senzaTxt, AttivaMtaSts.EsitoTxt.ASSENTE, "");
        caso("DNS che non risponde (dig esce con 9)", 9, irraggiungibile, AttivaMtaSts.EsitoTxt.NON_CHIESTO, "");
        // Il piano scrive il perche' accanto al dominio: un SERVFAIL si cerca nella zona, un
        // DNS che non risponde nella rete di questo server.
        String perche = AttivaMtaSts.interpretaTxt(0, servfail).motivo;
        esigi("il piano dice che il DNS ha risposto SERVFAIL: \"" + perche + "\"", perche.contains("SERVFAIL"));
        perche = AttivaMtaSts.interpretaTxt(9, irraggiungibile).motivo;
        esigi("e che nessun DNS ha risposto: \"" + perche + "\"", perche.equals("nessun DNS risponde"));
        // Varianti costruite sulla risposta vera di domain-d.test.
        String riga = "_mta-sts.domain-d.test.\t3498\tIN\tTXT\t\"v=STSv1; id=0fec393151a7c577266a\"";
        caso("record spezzato in due stringhe", 0,
                domainD.replace(riga, "_mta-sts.domain-d.test.\t3498\tIN\tTXT\t\"v=STSv1; \" \"id=0fec393151a7c577266a\""),
                AttivaMtaSts.EsitoTxt.PRESENTE, "v=STSv1; id=0fec393151a7c577266a");
        caso("accanto a un altro TXT sullo stesso nome", 0,
                domainD.replace(riga, "_mta-sts.domain-d.test.\t3498\tIN\tTXT\t\"google-site-verification=abc\"\n" + riga),
                AttivaMtaSts.EsitoTxt.PRESENTE, "v=STSv1; id=0fec393151a7c577266a");
        caso("dietro un CNAME", 0,
                domainD.replace(riga, "_mta-sts.domain-d.test.\t300\tIN\tCNAME\t_mta-sts.altro.net.\n_mta-sts.altro.net.\t300\tIN\tTXT\t\"v=STSv1; id=7\""),
                AttivaMtaSts.EsitoTxt.PRESENTE, "v=STSv1; id=7");
        caso("maiuscole", 0, domainD.replace("v=STSv1; id=0fec393151a7c577266a", "V=STSV1; id=2"),
                AttivaMtaSts.EsitoTxt.PRESENTE, "V=STSV1; id=2");
        caso("solo altri TXT", 0, domainD.replace(riga, "_mta-sts.domain-d.test.\t3498\tIN\tTXT\t\"google-site-verification=abc\""),
                AttivaMtaSts.EsitoTxt.ASSENTE, "");
        caso("REFUSED", 0, servfail.replace("SERVFAIL", "REFUSED"), AttivaMtaSts.EsitoTxt.NON_CHIESTO, "");
        caso("uscita senza lo stato della risposta", 0, "qualcosa che non e' dig\n", AttivaMtaSts.EsitoTxt.NON_CHIESTO, "");
        // Con "dig +short" (com'era) SERVFAIL e NXDOMAIN stampano la stessa cosa, cioe' niente:
        // per questo la lettura chiede lo stato della risposta.
        caso("l'uscita di dig +short di un SERVFAIL non basta a dire ASSENTE", 0, "", AttivaMtaSts.EsitoTxt.NON_CHIESTO, "");

        System.out.println("\n== interpretaTxt(): due record v=STSv1 sullo stesso nome ==");
        // Per i mittenti valgono zero (RFC 8461 §3.1). Prima la lettura prendeva il primo e
        // diceva PRESENTE: qui il primo e' proprio quello giusto, il caso piu' ingannevole.
        String vecchio = "_mta-sts.domain-d.test.\t3498\tIN\tTXT\t\"v=STSv1; id=1700000000000\"";
        String due = domainD.replace(riga, riga + "\n" + vecchio);
        caso("il giusto e uno con l'id vecchio", 0, due, AttivaMtaSts.EsitoTxt.TROPPI, "");
        AttivaMtaSts.LetturaTxt l2 = AttivaMtaSts.interpretaTxt(0, due);
        esigi("e li riporta tutti e due: " + l2.valori,
                l2.valori.equals(List.of("v=STSv1; id=0fec393151a7c577266a", "v=STSv1; id=1700000000000")));
        caso("uno scritto in maiuscolo (mailauth lo conta)", 0,
                domainD.replace(riga, riga + "\n_mta-sts.domain-d.test.\t3498\tIN\tTXT\t\"V=STSV1; id=2\""),
                AttivaMtaSts.EsitoTxt.TROPPI, "");
        caso("due record e un TXT che non c'entra", 0,
                domainD.replace(riga, "_mta-sts.domain-d.test.\t3498\tIN\tTXT\t\"google-site-verification=abc\"\n"
                        + riga + "\n" + vecchio),
                AttivaMtaSts.EsitoTxt.TROPPI, "");
        caso("stesso testo, ma due record (uno spezzato): sono due", 0,
                domainD.replace(riga, riga + "\n_mta-sts.domain-d.test.\t3498\tIN\tTXT\t\"v=STSv1; \" \"id=0fec393151a7c577266a\""),
                AttivaMtaSts.EsitoTxt.TROPPI, "");
        caso("due record dietro un CNAME", 0,
                domainD.replace(riga, "_mta-sts.domain-d.test.\t300\tIN\tCNAME\t_mta-sts.altro.net.\n"
                        + "_mta-sts.altro.net.\t300\tIN\tTXT\t\"v=STSv1; id=7\"\n"
                        + "_mta-sts.altro.net.\t300\tIN\tTXT\t\"v=STSv1; id=8\""),
                AttivaMtaSts.EsitoTxt.TROPPI, "");

        System.out.println("\n== passiProvaETxt(): il passo del record nel piano ==");
        String atteso = "v=STSv1; id=0fec393151a7c577266a";
        AttivaMtaSts.LetturaTxt uno = AttivaMtaSts.interpretaTxt(0, domainD);
        AttivaMtaSts.Passo p = passoTxt(List.of(
                new AttivaMtaSts.EsameTxt("domain-d.test", true, uno)), atteso);
        esigi("un record giusto e la politica che risponde: fatto (" + p.dettaglio + ")", "fatto".equals(p.stato));
        p = passoTxt(List.of(new AttivaMtaSts.EsameTxt("domain-d.test", true, l2)), atteso);
        esigi("due record, anche col primo giusto: NON fatto -> " + p.stato + " (" + p.dettaglio + ")",
                "da fare".equals(p.stato));
        esigi("il dettaglio nomina tutti e due i record",
                p.dettaglio.contains("id=0fec393151a7c577266a") && p.dettaglio.contains("id=1700000000000"));
        esigi("e il motivo dice perche' conta", p.motivo != null && p.motivo.contains("RFC 8461"));
        p = passoTxt(List.of(new AttivaMtaSts.EsameTxt("domain-d.test", true, l2),
                             new AttivaMtaSts.EsameTxt("domain-a.test", true, uno)), atteso);
        esigi("un dominio a posto non copre quello con due record: " + p.stato, "da fare".equals(p.stato));
        p = passoTxt(List.of(new AttivaMtaSts.EsameTxt("domain-d.test", false, l2)), atteso);
        esigi("due record e la politica che non risponde: segnalati come non mantenuti (" + p.dettaglio + ")",
                "da fare".equals(p.stato) && p.dettaglio.contains("NON mantenuto"));
        p = passoTxt(List.of(new AttivaMtaSts.EsameTxt("domain-d.test", true,
                AttivaMtaSts.interpretaTxt(0, servfail))), atteso);
        esigi("un SERVFAIL resta incerto, col motivo (" + p.dettaglio + ")",
                "incerto".equals(p.stato) && p.dettaglio.contains("SERVFAIL"));

        System.out.println("\n== leggiTxt(): il DNS vero, sui domini veri ==");
        if (digRisponde()) {
            for (String d : new String[]{"domain-d.test", "domain-a.test", "domain-b.test",
                                         "nome-che-non-esiste-99887.invalid"}) {
                AttivaMtaSts.LetturaTxt l = AttivaMtaSts.leggiTxt(d);
                System.out.println("  " + d + " -> " + l.esito + "  \"" + l.contenuto + "\"");
                if (d.equals("domain-d.test")) {
                    esigi("su domain-d.test il TXT viene VISTO (prima il piano non ci arrivava)",
                            l.esito == AttivaMtaSts.EsitoTxt.PRESENTE);
                    esigi("e se ne legge il contenuto", l.contenuto.startsWith("v=STSv1"));
                }
                if (d.endsWith(".invalid"))
                    esigi("un nome inesistente e' ASSENTE, non NON_CHIESTO",
                            l.esito == AttivaMtaSts.EsitoTxt.ASSENTE);
            }
            // dnssec-failed.org ha il DNSSEC rotto apposta: un resolver che lo convalida risponde
            // SERVFAIL. Se questo lo fa, la lettura deve dire NON_CHIESTO, non ASSENTE.
            if (statoDig("_mta-sts.dnssec-failed.org").equals("SERVFAIL")) {
                AttivaMtaSts.LetturaTxt l = AttivaMtaSts.leggiTxt("dnssec-failed.org");
                System.out.println("  dnssec-failed.org -> " + l.esito + " (" + l.motivo + ")");
                esigi("un SERVFAIL e' NON_CHIESTO, non ASSENTE", l.esito == AttivaMtaSts.EsitoTxt.NON_CHIESTO);
            } else {
                System.out.println("  (il resolver di questa macchina non convalida DNSSEC: SERVFAIL provato solo qui sopra)");
            }
        } else {
            // dig assente o rete chiusa: non si e' chiesto niente a nessuno, e la lettura deve
            // dirlo. Un ASSENTE qui farebbe proporre di pubblicare un record che forse c'e' gia'.
            System.out.println("  da qui dig non arriva a un DNS: la lettura deve dire NON_CHIESTO");
            for (String d : new String[]{"domain-d.test", "nome-che-non-esiste-99887.invalid"}) {
                AttivaMtaSts.LetturaTxt l = AttivaMtaSts.leggiTxt(d);
                esigi(d + " -> " + l.esito + ", non ASSENTE ne' PRESENTE",
                        l.esito == AttivaMtaSts.EsitoTxt.NON_CHIESTO);
            }
        }

        System.out.println("\n" + (falliti == 0 ? "TUTTO VERDE" : falliti + " CONTROLLI FALLITI"));
        if (falliti > 0) System.exit(1);
    }
}
