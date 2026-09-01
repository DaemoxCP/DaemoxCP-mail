package org.mail_panel.security;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;

/**
 * Le regole che i record SPF e DMARC devono rispettare, prese dalle specifiche in vigore e
 * scritte come funzioni pure: nessuna rete, nessun processo, nessun database. Cosi' si
 * possono provare con dei valori a mano, che e' l'unico modo di sapere se dicono il vero.
 *
 * Fonti (verificate, non a memoria):
 *  - SPF:   RFC 7208
 *  - DMARC: RFC 9989 (maggio 2026, sostituisce RFC 7489) e RFC 9990 per i rapporti
 *
 * Due regole valgono da sole tutto questo file, perche' descrivono guasti silenziosi:
 *
 *  1. SPF, §4.5: se a un nome ci sono DUE record che cominciano per "v=spf1", il risultato
 *     non e' "vince il primo": e' "permerror". SPF smette di funzionare del tutto.
 *  2. DMARC, §4: se a un nome ci sono due record DMARC validi, vengono scartati TUTTI.
 *     La politica sparisce, e nessuno avvisa nessuno.
 *
 * In entrambi i casi il dominio continua a spedire e chi guarda non vede niente di rotto,
 * finche' un giorno la posta comincia a finire nello spam. Per questo il pannello deve
 * saperli riconoscere prima di creare un record, non dopo.
 */
public final class RegoleDns {

    private RegoleDns() {}

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
    public static List<String> recordTxt(String uscitaDig) {
        List<String> fuori = new ArrayList<>();
        if (uscitaDig == null) return fuori;
        for (String riga : uscitaDig.split("\n")) {
            String t = riga.trim();
            if (t.isEmpty()) continue;
            StringBuilder unito = new StringBuilder();
            boolean dentro = false, viste = false;
            for (int i = 0; i < t.length(); i++) {
                char c = t.charAt(i);
                if (c == '\\' && dentro && i + 1 < t.length()) { unito.append(t.charAt(++i)); continue; }
                if (c == '"') { dentro = !dentro; viste = true; continue; }
                if (dentro) unito.append(c);
            }
            String r = viste ? unito.toString() : t;
            if (!r.isEmpty()) fuori.add(r);
        }
        return fuori;
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
    public static String contenutoCloudflare(String grezzo) {
        List<String> l = recordTxt(grezzo);
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
    public static List<String> soloSpf(List<String> record) {
        List<String> fuori = new ArrayList<>();
        if (record == null) return fuori;
        for (String r : record) {
            if (r == null) continue;
            String s = r.trim();
            String b = s.toLowerCase(Locale.ROOT);
            if (b.equals("v=spf1") || b.startsWith("v=spf1 ")) fuori.add(s);
        }
        return fuori;
    }

    /** I termini di un record SPF, saltata la versione. */
    public static List<String> termini(String spf) {
        List<String> fuori = new ArrayList<>();
        if (spf == null) return fuori;
        boolean primo = true;
        for (String t : spf.trim().split("\\s+")) {
            if (t.isEmpty()) continue;
            if (primo) { primo = false; continue; } // "v=spf1"
            fuori.add(t);
        }
        return fuori;
    }

    /** Toglie il qualificatore iniziale (+ - ~ ?), che non fa parte del nome. */
    public static String senzaQualificatore(String termine) {
        if (termine == null || termine.isEmpty()) return "";
        char q = termine.charAt(0);
        return (q == '+' || q == '-' || q == '~' || q == '?') ? termine.substring(1) : termine;
    }

    /** Il nome del meccanismo o modificatore: la parte prima di ':', '=' o '/'. */
    public static String nomeMeccanismo(String termine) {
        String t = senzaQualificatore(termine);
        for (int i = 0; i < t.length(); i++) {
            char c = t.charAt(i);
            if (c == ':' || c == '=' || c == '/') return t.substring(0, i).toLowerCase(Locale.ROOT);
        }
        return t.toLowerCase(Locale.ROOT);
    }

    /** Il valore dopo ':' o '=', vuoto se il termine non ne ha. */
    public static String valoreMeccanismo(String termine) {
        String t = senzaQualificatore(termine);
        for (int i = 0; i < t.length(); i++) {
            char c = t.charAt(i);
            if (c == ':' || c == '=') return t.substring(i + 1);
        }
        return "";
    }

    /** I termini che costano una ricerca DNS, §4.6.4. */
    private static boolean costaUnaRicerca(String nome) {
        return nome.equals("include") || nome.equals("a") || nome.equals("mx")
            || nome.equals("ptr") || nome.equals("exists") || nome.equals("redirect");
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
    public static int ricercheDnsDirette(String spf) {
        int n = 0;
        for (String t : termini(spf)) if (costaUnaRicerca(nomeMeccanismo(t))) n++;
        return n;
    }

    /** Quanti termini portano dentro altre ricerche non conoscibili da qui. */
    public static int quantiInclude(String spf) {
        int n = 0;
        for (String t : termini(spf)) {
            String nome = nomeMeccanismo(t);
            if (nome.equals("include") || nome.equals("redirect")) n++;
        }
        return n;
    }

    /** Il meccanismo c'e' come termine vero, non come pezzo di un'altra parola. */
    public static boolean haMeccanismo(String spf, String nome) {
        for (String t : termini(spf)) if (nomeMeccanismo(t).equals(nome)) return true;
        return false;
    }

    /** Come si chiude il record: "-all", "~all", "?all", "+all" o null se non si chiude. */
    public static String chiusura(String spf) {
        String trovata = null;
        for (String t : termini(spf)) {
            if (nomeMeccanismo(t).equals("all")) {
                char q = t.isEmpty() ? '+' : t.charAt(0);
                trovata = (q == '-' || q == '~' || q == '?' || q == '+') ? (q + "all") : "+all";
            }
        }
        return trovata;
    }

    /**
     * L'indirizzo sta dentro la specifica ip4, tenendo conto del prefisso.
     * Senza questo, "ip4:203.0.113.0/24" risulterebbe non contenere 203.0.113.7 e il
     * pannello direbbe "SPF non autorizza il server" davanti a un SPF perfettamente giusto.
     */
    public static boolean ip4Copre(String spec, String ip) {
        if (spec == null || ip == null) return false;
        String rete = spec, bit = "32";
        int s = spec.indexOf('/');
        if (s >= 0) { rete = spec.substring(0, s); bit = spec.substring(s + 1); }
        long r = aNumero(rete), a = aNumero(ip);
        if (r < 0 || a < 0) return false;
        int p;
        try { p = Integer.parseInt(bit.trim()); } catch (Exception e) { return false; }
        if (p < 0 || p > 32) return false;
        if (p == 0) return true;
        long maschera = (0xFFFFFFFFL << (32 - p)) & 0xFFFFFFFFL;
        return (r & maschera) == (a & maschera);
    }

    private static long aNumero(String ip) {
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
    public static boolean autorizzaIp4(String spf, String ip) {
        if (ip == null || ip.isBlank()) return false;
        for (String t : termini(spf)) {
            if (!nomeMeccanismo(t).equals("ip4")) continue;
            if (ip4Copre(valoreMeccanismo(t), ip)) return true;
        }
        return false;
    }

    public static class EsitoSpf {
        public int quanti;
        public boolean valido;
        public String record;
        public String problema;
        public boolean autorizzaEsplicito, viaMx, viaA;
        public int ricercheDirette, include;
        public String chiusura;
        public final List<String> avvisi = new ArrayList<>();
    }

    public static EsitoSpf analizzaSpf(List<String> recordTxt, String ipServer) {
        EsitoSpf e = new EsitoSpf();
        List<String> spf = soloSpf(recordTxt);
        e.quanti = spf.size();

        if (e.quanti == 0) {
            e.valido = false;
            e.problema = "Nessun record SPF: il dominio non dichiara chi puo' spedire per lui.";
            return e;
        }
        if (e.quanti > 1) {
            e.valido = false;
            e.problema = "Ci sono " + e.quanti + " record SPF sullo stesso nome. RFC 7208 §4.5 dice "
                       + "che in questo caso il risultato e' \"permerror\": SPF non fallisce a meta', "
                       + "smette di funzionare del tutto. Va lasciato UN SOLO record, unendo a mano "
                       + "cio' che serve dei due.";
            e.record = String.join("  ||  ", spf);
            return e;
        }

        e.valido = true;
        e.record = spf.get(0);
        e.autorizzaEsplicito = autorizzaIp4(e.record, ipServer);
        e.viaMx = haMeccanismo(e.record, "mx");
        e.viaA = haMeccanismo(e.record, "a");
        e.ricercheDirette = ricercheDnsDirette(e.record);
        e.include = quantiInclude(e.record);
        e.chiusura = chiusura(e.record);

        if (e.ricercheDirette > 10)
            e.avvisi.add("Il record fa gia' " + e.ricercheDirette + " ricerche DNS da solo: il limite "
                       + "di RFC 7208 §4.6.4 e' 10, oltre il quale il risultato e' \"permerror\".");
        else if (e.include > 0)
            e.avvisi.add("Ricerche DNS dirette: " + e.ricercheDirette + " su 10. Il conto vero e' piu' "
                       + "alto, perche' " + e.include + (e.include == 1 ? " termine porta" : " termini portano")
                       + " dentro altre ricerche che si contano solo risolvendole.");

        if (e.chiusura == null)
            e.avvisi.add("Il record non si chiude con \"all\": chi non e' elencato non riceve alcun "
                       + "giudizio, e SPF non serve piu' a niente.");
        else if (e.chiusura.equals("+all"))
            e.avvisi.add("Il record si chiude con \"+all\": autorizza chiunque a spedire per questo "
                       + "dominio. E' come non avere SPF, ma con l'aria di averlo.");

        return e;
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
    public static boolean stessoNome(String a, String b) {
        if (a == null || b == null) return false;
        String x = a.trim().toLowerCase(Locale.ROOT).replaceAll("\\.$", "");
        String y = b.trim().toLowerCase(Locale.ROOT).replaceAll("\\.$", "");
        return !x.isEmpty() && x.equals(y);
    }

    /** I quattro campi di un record SRV: priorita', peso, porta, destinazione. */
    public static class Srv {
        public int priorita, peso, porta;
        public String destinazione;
    }

    /** Legge "0 1 993 mail.esempio.it." Restituisce null se la riga non ha quella forma. */
    public static Srv analizzaSrv(String riga) {
        if (riga == null) return null;
        String[] p = riga.trim().split("\\s+");
        if (p.length < 4) return null;
        try {
            Srv s = new Srv();
            s.priorita = Integer.parseInt(p[0]);
            s.peso = Integer.parseInt(p[1]);
            s.porta = Integer.parseInt(p[2]);
            s.destinazione = p[3].trim();
            return s;
        } catch (Exception e) {
            return null;
        }
    }

    /* ===================================================================
     * DMARC - RFC 9989 / RFC 9990
     * =================================================================== */

    /** Tag tolti da RFC 9989: se sono ancora nel record, non fanno piu' nulla. */
    public static final String[] TAG_RIMOSSI = { "pct", "ri", "rf" };

    /** I tag che RFC 9989 definisce. Whitelist, non lista di cose vietate. */
    public static final String[] TAG_NOTI = {
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
        String primo = (pv < 0 ? s : s.substring(0, pv)).trim();
        int eq = primo.indexOf('=');
        if (eq < 0) return false;
        return primo.substring(0, eq).trim().equalsIgnoreCase("v")
            && primo.substring(eq + 1).trim().equals("DMARC1");
    }

    public static List<String> soloDmarc(List<String> record) {
        List<String> fuori = new ArrayList<>();
        if (record == null) return fuori;
        for (String r : record) if (eDmarc(r)) fuori.add(r.trim());
        return fuori;
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
    public static List<String> soloDkim(List<String> record) {
        List<String> fuori = new ArrayList<>();
        if (record == null) return fuori;
        for (String r : record) {
            if (r == null || r.isBlank()) continue;
            LinkedHashMap<String, String> t = tagDmarc(r);
            if (t.containsKey("p")) fuori.add(r.trim());
        }
        return fuori;
    }

    /** La chiave pubblica dichiarata nel record, senza spazi: alcuni server DNS ne inseriscono. */
    public static String chiaveDkim(String record) {
        String p = tagDmarc(record).get("p");
        return p == null ? null : p.replaceAll("\\s+", "");
    }

    /** I tag del record, nell'ordine in cui compaiono. Nomi in minuscolo. */
    public static LinkedHashMap<String, String> tagDmarc(String r) {
        LinkedHashMap<String, String> m = new LinkedHashMap<>();
        if (r == null) return m;
        for (String pezzo : r.split(";")) {
            String p = pezzo.trim();
            if (p.isEmpty()) continue;
            int eq = p.indexOf('=');
            if (eq <= 0) continue;
            m.put(p.substring(0, eq).trim().toLowerCase(Locale.ROOT), p.substring(eq + 1).trim());
        }
        return m;
    }

    /** Gli indirizzi mailto: dichiarati in un tag rua o ruf, senza il limite di dimensione. */
    public static List<String> indirizziRapporti(String valoreTag) {
        List<String> fuori = new ArrayList<>();
        if (valoreTag == null) return fuori;
        for (String u : valoreTag.split(",")) {
            String s = u.trim();
            if (s.toLowerCase(Locale.ROOT).startsWith("mailto:")) s = s.substring(7);
            int b = s.indexOf('!');            // "!10m": limite di dimensione, non fa parte dell'indirizzo
            if (b >= 0) s = s.substring(0, b);
            s = s.trim();
            if (!s.isEmpty()) fuori.add(s);
        }
        return fuori;
    }

    /** La parte dopo la chiocciola. */
    public static String hostDi(String indirizzo) {
        if (indirizzo == null) return "";
        int a = indirizzo.lastIndexOf('@');
        return a < 0 ? "" : indirizzo.substring(a + 1).trim().toLowerCase(Locale.ROOT);
    }

    /**
     * Il nome da interrogare per sapere se il dominio di destinazione accetta i rapporti di
     * un altro dominio. RFC 9990 §4: si prende l'host di destinazione, gli si antepone
     * "_report._dmarc", e davanti ancora il dominio che ha pubblicato la politica.
     * Esempio della specifica: blue.example.com._report._dmarc.red.example.net
     */
    public static String nomeAutorizzazioneRapporti(String dominioPolitica, String hostDestinazione) {
        return dominioPolitica.toLowerCase(Locale.ROOT) + "._report._dmarc."
             + hostDestinazione.toLowerCase(Locale.ROOT);
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
    public static boolean serveAutorizzazione(String dominioPolitica, String hostDestinazione) {
        if (dominioPolitica == null || hostDestinazione == null) return true;
        String a = dominioPolitica.trim().toLowerCase(Locale.ROOT).replaceAll("\\.$", "");
        String b = hostDestinazione.trim().toLowerCase(Locale.ROOT).replaceAll("\\.$", "");
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
    public static String cambiaPolitica(String record, String nuova) {
        if (record == null || nuova == null) return null;
        String n = nuova.trim().toLowerCase(Locale.ROOT);
        if (!List.of("none", "quarantine", "reject").contains(n)) return null;
        if (!eDmarc(record)) return null;

        String[] pezzi = record.split(";", -1);
        for (int i = 0; i < pezzi.length; i++) {
            String pezzo = pezzi[i];
            int eq = pezzo.indexOf('=');
            if (eq < 0) continue;
            if (!pezzo.substring(0, eq).trim().equalsIgnoreCase("p")) continue;
            // Si conserva lo spazio che precede il tag, se c'era.
            String prima = pezzo.substring(0, eq + 1);
            pezzi[i] = prima + n;
            return String.join(";", pezzi);
        }

        // Nessun tag "p": lo si aggiunge dopo la versione, imitando la spaziatura del record.
        // Si imita la spaziatura del record se ce n'e' una da imitare; quando non c'e'
        // nulla da cui dedurla si sceglie la forma leggibile, che e' quella che il pannello
        // usa quando scrive un record da zero.
        String separatore = !record.contains(";") ? "; " : (record.contains("; ") ? "; " : ";");
        int fineV = record.indexOf(';');
        if (fineV < 0) return record.trim() + separatore + "p=" + n;
        String resto = record.substring(fineV + 1);
        return record.substring(0, fineV) + separatore + "p=" + n
             + (resto.trim().isEmpty() ? "" : ";" + resto);
    }

    public static class EsitoDmarc {
        public int quanti;
        public boolean valido;
        public String record;
        public String problema;
        public String politica, politicaSottodomini, politicaInesistenti, prova;
        public LinkedHashMap<String, String> tag = new LinkedHashMap<>();
        public final List<String> rua = new ArrayList<>();
        public final List<String> daAutorizzare = new ArrayList<>();
        public final List<String> avvisi = new ArrayList<>();
    }

    public static EsitoDmarc analizzaDmarc(List<String> recordTxt, String dominio) {
        EsitoDmarc e = new EsitoDmarc();
        List<String> dm = soloDmarc(recordTxt);
        e.quanti = dm.size();

        if (e.quanti == 0) {
            e.valido = false;
            e.problema = "Nessun record DMARC valido. Senza, chiunque puo' scrivere questo dominio nel "
                       + "campo Da: e nessuno ha istruzioni su cosa farne.";
            return e;
        }
        if (e.quanti > 1) {
            e.valido = false;
            e.problema = "Ci sono " + e.quanti + " record DMARC sullo stesso nome. RFC 9989 dice che in "
                       + "questo caso vengono scartati TUTTI: la politica non e' \"la prima delle due\", "
                       + "non c'e' proprio. Va lasciato un solo record.";
            e.record = String.join("  ||  ", dm);
            return e;
        }

        e.valido = true;
        e.record = dm.get(0);
        e.tag = tagDmarc(e.record);
        e.politica = e.tag.get("p");
        e.politicaSottodomini = e.tag.get("sp");
        e.politicaInesistenti = e.tag.get("np");
        e.prova = e.tag.get("t");

        if (e.politica == null)
            e.avvisi.add("Manca il tag \"p\". RFC 9989 lo tratta come \"none\", cioe' nessuna azione: "
                       + "meglio scriverlo, cosi' si sa cosa si sta chiedendo.");
        else if (!java.util.List.of("none", "quarantine", "reject").contains(e.politica.toLowerCase(Locale.ROOT)))
            e.avvisi.add("Il tag \"p\" vale \"" + e.politica + "\", che non e' un valore previsto: "
                       + "i valori sono none, quarantine o reject.");

        for (String morto : TAG_RIMOSSI)
            if (e.tag.containsKey(morto))
                e.avvisi.add("Il record contiene \"" + morto + "=" + e.tag.get(morto) + "\", che RFC 9989 "
                           + "ha rimosso: oggi non fa piu' nulla."
                           + ("pct".equals(morto) ? " Chi voleva applicare la politica a poco a poco ora usa "
                                                  + "\"t=y\", che la applica un livello piu' blanda." : ""));

        for (String tag : e.tag.keySet()) {
            boolean noto = false;
            for (String n : TAG_NOTI) if (n.equals(tag)) { noto = true; break; }
            boolean rimosso = false;
            for (String n : TAG_RIMOSSI) if (n.equals(tag)) { rimosso = true; break; }
            if (!noto && !rimosso)
                e.avvisi.add("Tag \"" + tag + "\" non previsto da RFC 9989. La specifica dice di ignorare "
                           + "i tag sconosciuti, quindi non rompe niente, ma non fa neanche niente.");
        }

        String rua = e.tag.get("rua");
        if (rua == null || rua.isBlank()) {
            e.avvisi.add("Manca il tag \"rua\": senza, non arriva alcun rapporto e non c'e' modo di "
                       + "sapere chi spedisce a nome di questo dominio. RFC 9989 §5.1.4 parte proprio "
                       + "da qui, prima ancora di scegliere una politica.");
        } else {
            for (String ind : indirizziRapporti(rua)) {
                e.rua.add(ind);
                String host = hostDi(ind);
                if (host.isEmpty()) {
                    e.avvisi.add("L'indirizzo \"" + ind + "\" in rua non ha un dominio.");
                } else if (serveAutorizzazione(dominio, host)) {
                    e.daAutorizzare.add(nomeAutorizzazioneRapporti(dominio, host));
                }
            }
        }

        if (e.prova != null && e.prova.equalsIgnoreCase("y"))
            e.avvisi.add("C'e' \"t=y\": la politica dichiarata viene applicata un livello piu' blanda "
                       + "(reject diventa quarantine, quarantine diventa none). E' la modalita' di prova, "
                       + "va tolta quando si vuole che la politica valga davvero.");

        return e;
    }
}
