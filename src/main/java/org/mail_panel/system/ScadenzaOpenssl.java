package org.mail_panel.system;

import org.json.JSONArray;
import org.json.JSONObject;
import org.mail_panel.util.Shell;

import java.time.LocalDate;
import java.time.temporal.ChronoUnit;

/**
 * Quale OpenSSL usa davvero questo server, e per quanto tempo ancora riceve correzioni.
 *
 * Il motivo per cui la domanda non si risponde leggendo le note di rilascio: le note dicono
 * cosa c'era il giorno della release, non cosa gira adesso su QUESTA macchina. Un port
 * installato, un aggiornamento a meta', un sistema piu' vecchio di quel che si crede: sono
 * tutte cose che si vedono solo chiedendo al binario che versione ha.
 *
 * Le date sono quelle della strategia di rilascio ufficiale di OpenSSL, lette il 01/09/2026.
 * Non sono calcolate: sono trascritte, perche' inventare una regola ("ogni LTS dura 5 anni")
 * produrrebbe date plausibili e sbagliate.
 *
 * Attenzione a una distinzione che cambia il verdetto: **OpenSSL della base non e' il port.**
 * Quello della base lo mantiene il progetto FreeBSD, che pubblica correzioni per le release
 * supportate; il port segue il calendario di upstream. Confonderli fa suonare un allarme che
 * non c'e', o tacere uno che c'e'.
 */
public class ScadenzaOpenssl {

    /** ramo -> fine del supporto upstream. Trascritte da openssl-library.org. */
    private static final String[][] SCADENZE = {
        { "4.0",   "2027-05-14", "no"  },
        { "3.6",   "2026-11-01", "no"  },
        { "3.5",   "2030-04-08", "si"  },
        { "3.4",   "2026-10-22", "no"  },
        { "3.3",   "2026-04-09", "no"  },
        { "3.2",   "2025-11-23", "no"  },
        { "3.1",   "2025-03-14", "no"  },
        { "3.0",   "2026-09-07", "si"  },
        { "1.1.1", "2023-09-11", "si"  },
        { "1.0.2", "2019-12-31", "si"  },
    };

    private ScadenzaOpenssl() {}

    /* ===================================================================
     * Parte pura, provabile senza server
     * =================================================================== */

    /** Il ramo di una versione: "3.5.6" -> "3.5", "1.1.1w" -> "1.1.1". */
    public static String ramo(String versione) {
        if (versione == null) return null;
        String v = versione.trim();
        if (v.startsWith("1.1.1")) return "1.1.1";
        if (v.startsWith("1.0.2")) return "1.0.2";
        String[] p = v.split("\\.");
        if (p.length < 2) return null;
        String a = soloCifre(p[0]), b = soloCifre(p[1]);
        if (a.isEmpty() || b.isEmpty()) return null;
        return a + "." + b;
    }

    private static String soloCifre(String s) {
        StringBuilder sb = new StringBuilder();
        for (char c : s.toCharArray()) { if (!Character.isDigit(c)) break; sb.append(c); }
        return sb.toString();
    }

    /** La data di fine supporto di quel ramo, o null se il ramo non e' in tabella. */
    public static String fineSupporto(String versione) {
        String r = ramo(versione);
        if (r == null) return null;
        for (String[] s : SCADENZE) if (s[0].equals(r)) return s[1];
        return null;
    }

    public static boolean eLts(String versione) {
        String r = ramo(versione);
        if (r == null) return false;
        for (String[] s : SCADENZE) if (s[0].equals(r)) return "si".equals(s[2]);
        return false;
    }

    /** Giorni che mancano. Negativi se la data e' passata. "oggi" si passa: cosi' si prova. */
    public static Long giorniRimasti(String versione, LocalDate oggi) {
        String f = fineSupporto(versione);
        if (f == null || oggi == null) return null;
        try {
            return ChronoUnit.DAYS.between(oggi, LocalDate.parse(f));
        } catch (Exception e) {
            return null;
        }
    }

    /** 0 = a posto, 1 = scade presto (entro 90 giorni), 2 = scaduto, 3 = non lo so. */
    public static int urgenza(String versione, LocalDate oggi) {
        Long g = giorniRimasti(versione, oggi);
        if (g == null) return 3;
        if (g < 0) return 2;
        if (g <= 90) return 1;
        return 0;
    }

    /** La versione dentro l'uscita di "openssl version": "OpenSSL 3.5.6 30 Sep 2025" -> 3.5.6 */
    public static String estraiVersione(String uscita) {
        if (uscita == null) return null;
        for (String riga : uscita.split("\n")) {
            String t = riga.trim();
            if (!t.startsWith("OpenSSL") && !t.startsWith("LibreSSL")) continue;
            String[] p = t.split("\\s+");
            if (p.length >= 2 && !p[1].isEmpty() && Character.isDigit(p[1].charAt(0))) return p[1];
        }
        return null;
    }

    /* ===================================================================
     * Parte che interroga il server
     * =================================================================== */

    public static JSONObject stato() {
        JSONObject r = new JSONObject().put("success", true);
        LocalDate oggi = LocalDate.now();
        r.put("oggi", oggi.toString());

        JSONArray trovati = new JSONArray();
        trovati.put(esamina("base", "/usr/bin/openssl", oggi,
                "Fa parte del sistema FreeBSD. Lo mantiene il progetto FreeBSD, che pubblica "
                + "correzioni (avvisi SA/EN) finche' la release e' supportata: non segue "
                + "automaticamente il calendario di upstream."));
        trovati.put(esamina("port", "/usr/local/bin/openssl", oggi,
                "Il pacchetto installato a parte. Questo segue il calendario di upstream: "
                + "quando il ramo esce dal supporto, smette di ricevere correzioni."));
        r.put("installazioni", trovati);

        // Chi vince nel PATH del pannello: e' quello che finirebbe negli script.
        Ris quale = esegui("sh", "-c", "command -v openssl");
        r.put("nelPath", quale.codice == 0 ? quale.uscita.trim() : "");

        Ris fv = esegui("freebsd-version", "-k");
        if (fv.codice == 0) r.put("freebsd", fv.uscita.trim());

        // Il verdetto guarda solo cio' che c'e' davvero.
        int peggiore = 0;
        boolean qualcosa = false;
        for (int i = 0; i < trovati.length(); i++) {
            JSONObject o = trovati.getJSONObject(i);
            if (!o.optBoolean("presente", false)) continue;
            qualcosa = true;
            peggiore = Math.max(peggiore, o.optInt("urgenza", 3));
        }
        r.put("urgenza", qualcosa ? peggiore : 3);
        r.put("nota", !qualcosa
                ? "Non ho trovato nessun binario openssl da interrogare: senza, non posso dire "
                  + "che versione gira, e non voglio dedurlo dalle note di rilascio."
                : peggiore == 0 ? "Tutto quello che e' installato riceve ancora correzioni."
                : peggiore == 1 ? "Qualcosa esce dal supporto entro tre mesi: da programmare, non da rincorrere."
                : peggiore == 2 ? "Qualcosa e' gia' fuori supporto upstream: va guardato subito."
                : "Non riconosco una delle versioni trovate: la tabella delle scadenze va aggiornata.");
        return r;
    }

    private static JSONObject esamina(String tipo, String percorso, LocalDate oggi, String cosaSignifica) {
        JSONObject o = new JSONObject().put("tipo", tipo).put("percorso", percorso)
                .put("cosaSignifica", cosaSignifica);
        Ris v = esegui(percorso, "version");
        if (v.codice != 0) return o.put("presente", false);

        String versione = estraiVersione(v.uscita);
        o.put("presente", true).put("uscita", v.uscita.trim()).put("versione", versione == null ? "" : versione);
        if (versione == null)
            return o.put("urgenza", 3)
                    .put("commento", "Risponde, ma non riesco a leggere il numero di versione da: "
                            + v.uscita.trim());

        String fine = fineSupporto(versione);
        Long giorni = giorniRimasti(versione, oggi);
        int u = urgenza(versione, oggi);
        o.put("ramo", ramo(versione)).put("lts", eLts(versione)).put("urgenza", u);
        if (fine == null)
            return o.put("commento", "Il ramo " + ramo(versione) + " non e' nella tabella delle scadenze: "
                    + "la tabella e' ferma alle date lette il 01/09/2026 e va aggiornata.");

        o.put("fineSupporto", fine).put("giorni", giorni);
        o.put("commento", u == 2
                ? "Fuori supporto upstream dal " + fine + " (" + (-giorni) + " giorni fa)."
                : u == 1 ? "Esce dal supporto il " + fine + ": mancano " + giorni + " giorni."
                : "Supportato fino al " + fine + (eLts(versione) ? " (LTS)" : "") + ": mancano "
                  + giorni + " giorni.");
        return o;
    }

    private record Ris(int codice, String uscita) {}

    private static Ris esegui(String... cmd) {
        try {
            ProcessBuilder pb = new ProcessBuilder(cmd);
            Shell.applicaPath(pb);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            String out = new String(p.getInputStream().readAllBytes());
            return new Ris(p.waitFor(), out);
        } catch (Exception e) {
            return new Ris(-1, String.valueOf(e.getMessage()));
        }
    }
}
