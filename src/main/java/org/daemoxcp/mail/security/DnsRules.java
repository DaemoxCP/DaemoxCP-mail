package org.daemoxcp.mail.security;

import java.util.ArrayList;
import org.daemoxcp.mail.i18n.I18n;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;

/**
 * Le regole che i record SPF, DMARC e MTA-STS devono rispettare, prese dalle specifiche in
 * vigore e scritte come funzioni pure: nessuna rete, nessun processo, nessun database. Cosi'
 * si possono provare con dei valori a mano, che e' l'unico modo di sapere se dicono il vero.
 *
 * Fonti (verificate, non a memoria):
 *  - SPF:     RFC 7208
 *  - DMARC:   RFC 9989 (maggio 2026, sostituisce RFC 7489) e RFC 9990 per i rapporti
 *  - MTA-STS: RFC 8461 §3.1, confrontata con due mittenti veri (vedi onlyMtaSts)
 *
 * Tre regole valgono da sole tutto questo file, perche' descrivono guasti silenziosi:
 *
 *  1. SPF, §4.5: se a un nome ci sono DUE record che cominciano per "v=spf1", il risultato
 *     non e' "vince il primo": e' "permerror". SPF smette di funzionare del tutto.
 *  2. DMARC, §4: se a un nome ci sono due record DMARC validi, vengono scartati TUTTI.
 *     La politica sparisce, e nessuno avvisa nessuno.
 *  3. MTA-STS, §3.1: se su _mta-sts ci sono due record v=STSv1, i mittenti fanno come se
 *     MTA-STS non ci fosse. La politica resta servita, e non la legge nessuno.
 *
 * In tutti e tre i casi la posta continua a passare e chi guarda non vede niente di rotto:
 * con SPF e DMARC finche' un giorno comincia a finire nello spam, con MTA-STS mai, perche'
 * l'unico effetto e' che la posta in arrivo perde la protezione: chi sta in mezzo puo' di
 * nuovo toglierle il TLS. Per questo il pannello deve saperli riconoscere prima di creare un
 * record, non dopo.
 */
public final class DnsRules {

    private DnsRules() {}

    /* ===================================================================
     * Record TXT grezzi
     * =================================================================== */

    /**
     * Trasforma l'uscita di {@code dig +short TXT <nome>} in un record per elemento.
     *
     * Due dettagli che sembrano pignoleria e non lo sono:
     *  - ogni RIGA e' un record distinto (a un nome possono essercene molti);
     *  - dentro una riga, un record lungo e' spezzato in piu' stringhe fra virgolette, e
     *    RFC 7208 §3.3 dice che vanno unite SENZA aggiungere spazi. Chi le unisce con uno
     *    spazio rompe le chiavi DKIM lunghe e non se ne accorge, perche' il record continua
     *    a "sembrare" giusto.
     */
    public static List<String> recordTxt(String digOutput) {
        List<String> outside = new ArrayList<>();
        if (digOutput == null) return outside;
        for (String line : digOutput.split("\n")) {
            String t = line.trim();
            if (t.isEmpty()) continue;
            StringBuilder joined = new StringBuilder();
            boolean inside = false, seen = false;
            for (int i = 0; i < t.length(); i++) {
                char c = t.charAt(i);
                if (c == '\\' && inside && i + 1 < t.length()) { joined.append(t.charAt(++i)); continue; }
                if (c == '"') { inside = !inside; seen = true; continue; }
                if (inside) joined.append(c);
            }
            String r = seen ? joined.toString() : t;
            if (!r.isEmpty()) outside.add(r);
        }
        return outside;
    }

    /**
     * Il contenuto di un record come lo restituisce l'API di Cloudflare, ridotto al valore
     * vero. Cloudflare a volte consegna il TXT gia' nudo e a volte avvolto fra virgolette,
     * a seconda di come e' stato creato.
     *
     * Non e' un dettaglio estetico: se le virgolette restano, "\"v=spf1 ...\"" non comincia
     * per "v=spf1", il pannello conclude che un SPF non c'e', e ne aggiunge un secondo.
     * Due SPF sullo stesso nome danno "permerror": il controllo pensato per evitare il
     * guasto lo avrebbe causato.
     *
     * Si riusa recordTxt, che gia' sa unire le stringhe multiple e togliere le virgolette:
     * due funzioni che fanno la stessa cosa sono due funzioni che un giorno divergono.
     */
    public static String cloudflareContent(String raw) {
        List<String> l = recordTxt(raw);
        return l.isEmpty() ? "" : l.get(0);
    }

    /* ===================================================================
     * SPF - RFC 7208
     * =================================================================== */

    /**
     * I soli record che contano come SPF. §4.5: il record deve cominciare con la sezione di
     * versione esattamente "v=spf1", terminata da uno spazio o dalla fine del record.
     * Quindi "v=spf10 ..." NON e' un record SPF e va scartato, non accettato per somiglianza.
     *
     * Il confronto e' insensibile alle maiuscole: l'ABNF di RFC 7208 usa stringhe letterali
     * semplici, che in ABNF (RFC 5234) sono insensibili salvo prefisso %s. DMARC invece usa
     * %s"DMARC1", ed e' per questo che piu' sotto il confronto e' sensibile: non e' una
     * distrazione, e' la differenza fra le due specifiche.
     */
    public static List<String> onlySpf(List<String> record) {
        List<String> outside = new ArrayList<>();
        if (record == null) return outside;
        for (String r : record) {
            if (r == null) continue;
            String s = r.trim();
            String b = s.toLowerCase(Locale.ROOT);
            if (b.equals("v=spf1") || b.startsWith("v=spf1 ")) outside.add(s);
        }
        return outside;
    }

    /** I termini di un record SPF, saltata la versione. */
    public static List<String> terms(String spf) {
        List<String> outside = new ArrayList<>();
        if (spf == null) return outside;
        boolean first = true;
        for (String t : spf.trim().split("\\s+")) {
            if (t.isEmpty()) continue;
            if (first) { first = false; continue; } // "v=spf1"
            outside.add(t);
        }
        return outside;
    }

    /** Toglie il qualificatore iniziale (+ - ~ ?), che non fa parte del nome. */
    public static String withoutQualifier(String term) {
        if (term == null || term.isEmpty()) return "";
        char q = term.charAt(0);
        return (q == '+' || q == '-' || q == '~' || q == '?') ? term.substring(1) : term;
    }

    /** Il nome del meccanismo o modificatore: la parte prima di ':', '=' o '/'. */
    public static String mechanismName(String term) {
        String t = withoutQualifier(term);
        for (int i = 0; i < t.length(); i++) {
            char c = t.charAt(i);
            if (c == ':' || c == '=' || c == '/') return t.substring(0, i).toLowerCase(Locale.ROOT);
        }
        return t.toLowerCase(Locale.ROOT);
    }

    /** Il valore dopo ':' o '=', vuoto se il termine non ne ha. */
    public static String mechanismValue(String term) {
        String t = withoutQualifier(term);
        for (int i = 0; i < t.length(); i++) {
            char c = t.charAt(i);
            if (c == ':' || c == '=') return t.substring(i + 1);
        }
        return "";
    }

    /** I termini che costano una ricerca DNS, §4.6.4. */
    private static boolean costsALookup(String name) {
        return name.equals("include") || name.equals("a") || name.equals("mx")
            || name.equals("ptr") || name.equals("exists") || name.equals("redirect");
    }

    /**
     * Quante ricerche DNS costa QUESTO record, senza entrare negli "include".
     *
     * Il nome dice "dirette" apposta: §4.6.4 fissa il limite di 10 sull'intera valutazione,
     * e ogni "include" ne porta dentro altre che si conoscono solo risolvendole. Quindi
     * questo numero e' un MINIMO, e va presentato come tale. Un conteggio che si spacciasse
     * per totale direbbe "6 su 10, tutto bene" davanti a un record che in realta' e' gia'
     * oltre il limite: una verifica che rassicura sul falso e' peggio di nessuna verifica.
     */
    public static int directDnsLookups(String spf) {
        int n = 0;
        for (String t : terms(spf)) if (costsALookup(mechanismName(t))) n++;
        return n;
    }

    /** Quanti termini portano dentro altre ricerche non conoscibili da qui. */
    public static int includeCount(String spf) {
        int n = 0;
        for (String t : terms(spf)) {
            String name = mechanismName(t);
            if (name.equals("include") || name.equals("redirect")) n++;
        }
        return n;
    }

    /** Il meccanismo c'e' come termine vero, non come pezzo di un'altra parola. */
    public static boolean hasMechanism(String spf, String name) {
        for (String t : terms(spf)) if (mechanismName(t).equals(name)) return true;
        return false;
    }

    /** Come si chiude il record: "-all", "~all", "?all", "+all" o null se non si chiude. */
    public static String closing(String spf) {
        String found = null;
        for (String t : terms(spf)) {
            if (mechanismName(t).equals("all")) {
                char q = t.isEmpty() ? '+' : t.charAt(0);
                found = (q == '-' || q == '~' || q == '?' || q == '+') ? (q + "all") : "+all";
            }
        }
        return found;
    }

    /**
     * L'indirizzo sta dentro la specifica ip4, tenendo conto del prefisso.
     * Senza questo, "ip4:203.0.113.0/24" risulterebbe non contenere 203.0.113.7 e il
     * pannello direbbe "SPF non autorizza il server" davanti a un SPF perfettamente giusto.
     */
    public static boolean ip4Covers(String spec, String ip) {
        if (spec == null || ip == null) return false;
        String network = spec, bit = "32";
        int s = spec.indexOf('/');
        if (s >= 0) { network = spec.substring(0, s); bit = spec.substring(s + 1); }
        long r = toNumber(network), a = toNumber(ip);
        if (r < 0 || a < 0) return false;
        int p;
        try { p = Integer.parseInt(bit.trim()); } catch (Exception e) { return false; }
        if (p < 0 || p > 32) return false;
        if (p == 0) return true;
        long mask = (0xFFFFFFFFL << (32 - p)) & 0xFFFFFFFFL;
        return (r & mask) == (a & mask);
    }

    private static long toNumber(String ip) {
        if (ip == null) return -1;
        String[] p = ip.trim().split("\\.");
        if (p.length != 4) return -1;
        long v = 0;
        for (String x : p) {
            if (x.isEmpty() || x.length() > 3) return -1;
            for (int i = 0; i < x.length(); i++) if (!Character.isDigit(x.charAt(i))) return -1;
            int n = Integer.parseInt(x);
            if (n > 255) return -1;
            v = (v << 8) | n;
        }
        return v;
    }

    /** L'SPF autorizza quell'IP con un ip4 esplicito (prefissi compresi). */
    public static boolean authorizeIp4(String spf, String ip) {
        if (ip == null || ip.isBlank()) return false;
        for (String t : terms(spf)) {
            if (!mechanismName(t).equals("ip4")) continue;
            if (ip4Covers(mechanismValue(t), ip)) return true;
        }
        return false;
    }

    public static class SpfOutcome {
        public int howMany;
        public boolean valid;
        public String record;
        public String problem;
        public boolean explicitAuthorization, viaMx, viaA;
        public int directLookups, include;
        public String closing;
        public final List<String> warnings = new ArrayList<>();
    }

    public static SpfOutcome analyzeSpf(List<String> recordTxt, String ipServer) {
        SpfOutcome e = new SpfOutcome();
        List<String> spf = onlySpf(recordTxt);
        e.howMany = spf.size();

        if (e.howMany == 0) {
            e.valid = false;
            e.problem = I18n.tr("server.dnsrules.spfNone");
            return e;
        }
        if (e.howMany > 1) {
            e.valid = false;
            e.problem = I18n.tr("server.dnsrules.spfMany", java.util.Map.of("n", String.valueOf(e.howMany)));
            e.record = String.join("  ||  ", spf);
            return e;
        }

        e.valid = true;
        e.record = spf.get(0);
        e.explicitAuthorization = authorizeIp4(e.record, ipServer);
        e.viaMx = hasMechanism(e.record, "mx");
        e.viaA = hasMechanism(e.record, "a");
        e.directLookups = directDnsLookups(e.record);
        e.include = includeCount(e.record);
        e.closing = closing(e.record);

        if (e.directLookups > 10)
            e.warnings.add(I18n.tr("server.dnsrules.spfLookups", java.util.Map.of("n", String.valueOf(e.directLookups))));
        else if (e.include > 0)
            e.warnings.add(e.include == 1
                       ? I18n.tr("server.dnsrules.spfDirect.one", java.util.Map.of("n", String.valueOf(e.directLookups)))
                       : I18n.tr("server.dnsrules.spfDirect.other", java.util.Map.of("n", String.valueOf(e.directLookups), "includes", String.valueOf(e.include))));

        if (e.closing == null)
            e.warnings.add(I18n.tr("server.dnsrules.spfNoAll"));
        else if (e.closing.equals("+all"))
            e.warnings.add(I18n.tr("server.dnsrules.spfPlusAll"));

        return e;
    }

    /* ===================================================================
     * MTA-STS - RFC 8461
     * =================================================================== */

    /**
     * I record del nome _mta-sts che almeno un mittente conta come MTA-STS.
     *
     * §3.1: "records that do not begin with "v=STSv1;" are discarded. If the number of
     * resulting records is not one [...] senders MUST assume the recipient domain does not
     * have an available MTA-STS Policy". Con due record non vale il primo: per i mittenti
     * MTA-STS non c'e', e la politica servita non la legge nessuno. E' lo stesso guasto
     * silenzioso dei due SPF e dei due DMARC.
     *
     * Il filtro e' il piu' largo fra quelli dei mittenti veri, che non contano allo stesso
     * modo: postfix-mta-sts-resolver tiene i record che cominciano per "v=STSv1" con le
     * maiuscole esatte; mailauth (Nodemailer) di norma ignora maiuscole e spazi ai bordi e
     * vuole il ";". Un record che anche uno solo di loro conta, qui conta: se per qualche
     * mittente i record sono due, il pannello non puo' dire che MTA-STS e' attivo.
     */
    public static boolean eMtaSts(String r) {
        return r != null && r.trim().toLowerCase(Locale.ROOT).startsWith("v=stsv1");
    }

    public static List<String> onlyMtaSts(List<String> record) {
        List<String> outside = new ArrayList<>();
        if (record == null) return outside;
        for (String r : record) if (eMtaSts(r)) outside.add(r.trim());
        return outside;
    }

    /* ===================================================================
     * Nomi e record SRV
     * =================================================================== */

    /**
     * Due nomi DNS indicano lo stesso host.
     *
     * Il confronto e' ESATTO, non per contenimento: "xmail.esempio.it".contains("mail.esempio.it")
     * e' vero, e un controllo scritto cosi' promuove un record che punta altrove. E' lo stesso
     * errore che sull'SPF faceva passare per buono un record che non autorizzava il server.
     * Il punto finale del nome assoluto e le maiuscole non contano.
     */
    public static boolean sameName(String a, String b) {
        if (a == null || b == null) return false;
        String x = a.trim().toLowerCase(Locale.ROOT).replaceAll("\\.$", "");
        String y = b.trim().toLowerCase(Locale.ROOT).replaceAll("\\.$", "");
        return !x.isEmpty() && x.equals(y);
    }

    /** I quattro campi di un record SRV: priorita', peso, porta, destinazione. */
    public static class Srv {
        public int priority, weight, port;
        public String destination;
    }

    /** Legge "0 1 993 mail.esempio.it." Restituisce null se la riga non ha quella forma. */
    public static Srv analyzeSrv(String line) {
        if (line == null) return null;
        String[] p = line.trim().split("\\s+");
        if (p.length < 4) return null;
        try {
            Srv s = new Srv();
            s.priority = Integer.parseInt(p[0]);
            s.weight = Integer.parseInt(p[1]);
            s.port = Integer.parseInt(p[2]);
            s.destination = p[3].trim();
            return s;
        } catch (Exception e) {
            return null;
        }
    }

    /* ===================================================================
     * DMARC - RFC 9989 / RFC 9990
     * =================================================================== */

    /** Tag tolti da RFC 9989: se sono ancora nel record, non fanno piu' nulla. */
    public static final String[] REMOVED_TAGS = { "pct", "ri", "rf" };

    /** I tag che RFC 9989 definisce. Whitelist, non lista di cose vietate. */
    public static final String[] KNOWN_TAGS = {
        "v", "p", "sp", "np", "adkim", "aspf", "rua", "ruf", "fo", "psd", "t"
    };

    /**
     * E' un record DMARC. §4: il tag "v" deve essere il PRIMO, e il suo valore e' sensibile
     * alle maiuscole ("%s'DMARC1'" nell'ABNF). Se non e' primo, manca, o il valore e'
     * diverso, l'intero record va ignorato.
     */
    public static boolean eDmarc(String r) {
        if (r == null) return false;
        String s = r.trim();
        int pv = s.indexOf(';');
        String first = (pv < 0 ? s : s.substring(0, pv)).trim();
        int eq = first.indexOf('=');
        if (eq < 0) return false;
        return first.substring(0, eq).trim().equalsIgnoreCase("v")
            && first.substring(eq + 1).trim().equals("DMARC1");
    }

    public static List<String> onlyDmarc(List<String> record) {
        List<String> outside = new ArrayList<>();
        if (record == null) return outside;
        for (String r : record) if (eDmarc(r)) outside.add(r.trim());
        return outside;
    }

    /**
     * I tag di un record scritto come "nome=valore; nome=valore".
     * La sintassi e' la stessa per DMARC e per le chiavi DKIM, quindi il parser e' uno solo:
     * due parser identici sono due parser che un giorno si comportano diversamente.
     */
    public static LinkedHashMap<String, String> tag(String r) {
        return tagDmarc(r);
    }

    /**
     * I record che sono chiavi DKIM. Il criterio e' la presenza del tag "p=", che contiene la
     * chiave: RFC 6376 §3.6.1 rende il tag "v=" soltanto RACCOMANDATO, con "DKIM1" come
     * valore predefinito, quindi pretenderlo escluderebbe record validi.
     */
    public static List<String> onlyDkim(List<String> record) {
        List<String> outside = new ArrayList<>();
        if (record == null) return outside;
        for (String r : record) {
            if (r == null || r.isBlank()) continue;
            LinkedHashMap<String, String> t = tagDmarc(r);
            if (t.containsKey("p")) outside.add(r.trim());
        }
        return outside;
    }

    /** La chiave pubblica dichiarata nel record, senza spazi: alcuni server DNS ne inseriscono. */
    public static String dkimKey(String record) {
        String p = tagDmarc(record).get("p");
        return p == null ? null : p.replaceAll("\\s+", "");
    }

    /** I tag del record, nell'ordine in cui compaiono. Nomi in minuscolo. */
    public static LinkedHashMap<String, String> tagDmarc(String r) {
        LinkedHashMap<String, String> m = new LinkedHashMap<>();
        if (r == null) return m;
        for (String piece : r.split(";")) {
            String p = piece.trim();
            if (p.isEmpty()) continue;
            int eq = p.indexOf('=');
            if (eq <= 0) continue;
            m.put(p.substring(0, eq).trim().toLowerCase(Locale.ROOT), p.substring(eq + 1).trim());
        }
        return m;
    }

    /** Gli indirizzi mailto: dichiarati in un tag rua o ruf, senza il limite di dimensione. */
    public static List<String> reportAddresses(String tagValue) {
        List<String> outside = new ArrayList<>();
        if (tagValue == null) return outside;
        for (String u : tagValue.split(",")) {
            String s = u.trim();
            if (s.toLowerCase(Locale.ROOT).startsWith("mailto:")) s = s.substring(7);
            int b = s.indexOf('!');            // "!10m": limite di dimensione, non fa parte dell'indirizzo
            if (b >= 0) s = s.substring(0, b);
            s = s.trim();
            if (!s.isEmpty()) outside.add(s);
        }
        return outside;
    }

    /** La parte dopo la chiocciola. */
    public static String hostOf(String address) {
        if (address == null) return "";
        int a = address.lastIndexOf('@');
        return a < 0 ? "" : address.substring(a + 1).trim().toLowerCase(Locale.ROOT);
    }

    /**
     * Il nome da interrogare per sapere se il dominio di destinazione accetta i rapporti di
     * un altro dominio. RFC 9990 §4: si prende l'host di destinazione, gli si antepone
     * "_report._dmarc", e davanti ancora il dominio che ha pubblicato la politica.
     * Esempio della specifica: blue.example.com._report._dmarc.red.example.net
     */
    public static String reportAuthorizationName(String policyDomain, String destinationHost) {
        return policyDomain.toLowerCase(Locale.ROOT) + "._report._dmarc."
             + destinationHost.toLowerCase(Locale.ROOT);
    }

    /**
     * Serve l'autorizzazione esterna? RFC 9990 §4 la richiede quando il dominio della
     * politica e quello dell'indirizzo NON coincidono. Qui si risponde "no" solo quando la
     * coincidenza e' certa: stesso nome, o uno sottodominio dell'altro. Negli altri casi si
     * risponde "si'", e il pannello va a controllare se il record c'e'.
     *
     * La prudenza e' voluta: dire "non serve" quando invece serve significa lasciare che i
     * rapporti non arrivino mai, senza che nessun controllo lo segnali.
     */
    public static boolean needsAuthorization(String policyDomain, String destinationHost) {
        if (policyDomain == null || destinationHost == null) return true;
        String a = policyDomain.trim().toLowerCase(Locale.ROOT).replaceAll("\\.$", "");
        String b = destinationHost.trim().toLowerCase(Locale.ROOT).replaceAll("\\.$", "");
        if (a.isEmpty() || b.isEmpty()) return true;
        if (a.equals(b)) return false;
        return !(a.endsWith("." + b) || b.endsWith("." + a));
    }

    /**
     * Cambia SOLO il valore del tag "p", lasciando intatto tutto il resto del record.
     *
     * Non si ricostruisce il record da zero: se qualcuno ci ha aggiunto "sp=", "fo=" o un
     * secondo indirizzo in "rua", riscrivendolo da capo quelle parti sparirebbero senza che
     * nessuno se ne accorga. Qui si sostituisce un valore e basta, conservando anche la
     * spaziatura originale, cosi' il confronto prima/dopo mostra una differenza sola.
     *
     * Se il tag "p" non c'e', viene inserito subito dopo "v=DMARC1", che e' il posto giusto:
     * la specifica vuole "v" per primo, e non dice nulla sull'ordine degli altri.
     *
     * Restituisce null se il record non e' un DMARC valido: meglio non fare niente che
     * produrre una stringa a caso.
     */
    public static String changePolicy(String record, String fresh) {
        if (record == null || fresh == null) return null;
        String n = fresh.trim().toLowerCase(Locale.ROOT);
        if (!List.of("none", "quarantine", "reject").contains(n)) return null;
        if (!eDmarc(record)) return null;

        String[] pieces = record.split(";", -1);
        for (int i = 0; i < pieces.length; i++) {
            String piece = pieces[i];
            int eq = piece.indexOf('=');
            if (eq < 0) continue;
            if (!piece.substring(0, eq).trim().equalsIgnoreCase("p")) continue;
            // Si conserva lo spazio che precede il tag, se c'era.
            String before = piece.substring(0, eq + 1);
            pieces[i] = before + n;
            return String.join(";", pieces);
        }

        // Nessun tag "p": lo si aggiunge dopo la versione, imitando la spaziatura del record.
        // Si imita la spaziatura del record se ce n'e' una da imitare; quando non c'e'
        // nulla da cui dedurla si sceglie la forma leggibile, che e' quella che il pannello
        // usa quando scrive un record da zero.
        String separator = !record.contains(";") ? "; " : (record.contains("; ") ? "; " : ";");
        int endV = record.indexOf(';');
        if (endV < 0) return record.trim() + separator + "p=" + n;
        String rest = record.substring(endV + 1);
        return record.substring(0, endV) + separator + "p=" + n
             + (rest.trim().isEmpty() ? "" : ";" + rest);
    }

    public static class DmarcOutcome {
        public int howMany;
        public boolean valid;
        public String record;
        public String problem;
        public String policy, subdomainPolicy, nonexistentPolicy, test;
        public LinkedHashMap<String, String> tag = new LinkedHashMap<>();
        public final List<String> rua = new ArrayList<>();
        public final List<String> toAuthorize = new ArrayList<>();
        public final List<String> warnings = new ArrayList<>();
    }

    public static DmarcOutcome analyzeDmarc(List<String> recordTxt, String domain) {
        DmarcOutcome e = new DmarcOutcome();
        List<String> dm = onlyDmarc(recordTxt);
        e.howMany = dm.size();

        if (e.howMany == 0) {
            e.valid = false;
            e.problem = I18n.tr("server.dnsrules.dmarcNone");
            return e;
        }
        if (e.howMany > 1) {
            e.valid = false;
            e.problem = I18n.tr("server.dnsrules.dmarcMany", java.util.Map.of("n", String.valueOf(e.howMany)));
            e.record = String.join("  ||  ", dm);
            return e;
        }

        e.valid = true;
        e.record = dm.get(0);
        e.tag = tagDmarc(e.record);
        e.policy = e.tag.get("p");
        e.subdomainPolicy = e.tag.get("sp");
        e.nonexistentPolicy = e.tag.get("np");
        e.test = e.tag.get("t");

        if (e.policy == null)
            e.warnings.add(I18n.tr("server.dnsrules.dmarcNoP"));
        else if (!java.util.List.of("none", "quarantine", "reject").contains(e.policy.toLowerCase(Locale.ROOT)))
            e.warnings.add(I18n.tr("server.dnsrules.dmarcBadP", java.util.Map.of("p", String.valueOf(e.policy))));

        for (String dead : REMOVED_TAGS)
            if (e.tag.containsKey(dead))
                e.warnings.add(I18n.tr("server.dnsrules.dmarcRemovedTag", java.util.Map.of("tag", String.valueOf(dead + "=" + e.tag.get(dead))))
                           + ("pct".equals(dead) ? " " + I18n.tr("server.dnsrules.dmarcPct") : ""));

        for (String tag : e.tag.keySet()) {
            boolean known = false;
            for (String n : KNOWN_TAGS) if (n.equals(tag)) { known = true; break; }
            boolean removed = false;
            for (String n : REMOVED_TAGS) if (n.equals(tag)) { removed = true; break; }
            if (!known && !removed)
                e.warnings.add(I18n.tr("server.dnsrules.dmarcUnknownTag", java.util.Map.of("tag", String.valueOf(tag))));
        }

        String rua = e.tag.get("rua");
        if (rua == null || rua.isBlank()) {
            e.warnings.add(I18n.tr("server.dnsrules.dmarcNoRua"));
        } else {
            for (String ind : reportAddresses(rua)) {
                e.rua.add(ind);
                String host = hostOf(ind);
                if (host.isEmpty()) {
                    e.warnings.add(I18n.tr("server.dnsrules.ruaNoDomain", java.util.Map.of("addr", String.valueOf(ind))));
                } else if (needsAuthorization(domain, host)) {
                    e.toAuthorize.add(reportAuthorizationName(domain, host));
                }
            }
        }

        if (e.test != null && e.test.equalsIgnoreCase("y"))
            e.warnings.add(I18n.tr("server.dnsrules.dmarcTest"));

        return e;
    }
}
