package org.mail_panel.security;

import org.mail_panel.webserver.SecurityUtils;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.regex.Pattern;

/**
 * Il generatore di password e la regola che il pannello applica alle password delle caselle.
 *
 * Il generatore aveva simboli suoi: con "Tutti i caratteri" metteva anche < > / ~ e l'apice
 * inverso, che isValidPassword rifiuta. La password proposta dal pannello veniva respinta dal
 * pannello stesso ("Password non valida" creando una casella, avviso e niente cambio
 * modificandola). Qui si generano migliaia di password per ogni tipo e combinazione e si
 * pretende che passino tutte, e si controlla che la regola sia rimasta quella di prima.
 */
public class ProvaGeneratorePassword {

    static int falliti = 0;
    static void esigi(String cosa, boolean ok) {
        System.out.println((ok ? "  OK   " : "  FALLITO ") + cosa);
        if (!ok) falliti++;
    }

    public static void main(String[] a) throws Exception {
        // La chiave non serve a generare: niente getInstance(), che leggerebbe o creerebbe
        // /usr/local/etc/mail-panel/master.key.
        var costruttore = PasswordVault.class.getDeclaredConstructor(SecretKey.class);
        costruttore.setAccessible(true);
        PasswordVault vault = costruttore.newInstance(new SecretKeySpec(new byte[32], "AES"));

        System.out.println("\n== ogni password generata passa la regola del pannello ==");
        String[] tipi = { "easy_to_say", "easy_to_read", "all_chars", "sconosciuto", null };
        int[] lunghezze = { 8, 20, 64, 128 };
        for (String tipo : tipi) {
            int generate = 0, respinte = 0, lunghezzaSbagliata = 0, insiemeMancante = 0;
            for (int combo = 0; combo < 16; combo++) {
                boolean lo = (combo & 1) != 0, up = (combo & 2) != 0, nu = (combo & 4) != 0, sy = (combo & 8) != 0;
                var attivi = PasswordVault.insiemi(tipo, lo, up, nu, sy);
                for (int len : lunghezze) {
                    for (int i = 0; i < 150; i++) {
                        String pw = vault.generatePassword(len, tipo, lo, up, nu, sy);
                        generate++;
                        if (!SecurityUtils.isValidPassword(pw)) respinte++;
                        if (pw.length() != len) lunghezzaSbagliata++;
                        for (String insieme : attivi) {
                            boolean c = false;
                            for (char ch : pw.toCharArray()) if (insieme.indexOf(ch) >= 0) { c = true; break; }
                            if (!c) { insiemeMancante++; break; }
                        }
                    }
                }
            }
            esigi(String.format("%-13s %6d password: %d respinte, %d di lunghezza sbagliata, %d senza un insieme scelto",
                    tipo, generate, respinte, lunghezzaSbagliata, insiemeMancante),
                    respinte == 0 && lunghezzaSbagliata == 0 && insiemeMancante == 0);
        }

        System.out.println("\n== lunghezza fuori dai limiti: si riporta dentro ==");
        esigi("3 diventa 8", vault.generatePassword(3, "all_chars", true, true, true, true).length() == 8);
        esigi("500 diventa 128", vault.generatePassword(500, "all_chars", true, true, true, true).length() == 128);

        System.out.println("\n== la stima dell'entropia usa gli stessi insiemi del generatore ==");
        esigi("all_chars, tutto: 26+26+10+24 = 86", PasswordVault.dimensionePool("all_chars", true, true, true, true) == 86);
        esigi("easy_to_read, tutto: 24+24+8+21 = 77", PasswordVault.dimensionePool("easy_to_read", true, true, true, true) == 77);
        esigi("easy_to_say ignora cifre e simboli: 52", PasswordVault.dimensionePool("easy_to_say", true, true, true, true) == 52);
        esigi("nessuna scelta: si ripiega su tutto (86)", PasswordVault.dimensionePool("all_chars", false, false, false, false) == 86);

        System.out.println("\n== la regola non e' cambiata: stessa risposta della vecchia espressione ==");
        Pattern vecchia = Pattern.compile("^[a-zA-Z0-9!@#$%^&*()_+\\-=\\[\\]{}|;:,.?]{4,128}$");
        int diverse = 0;
        for (char c = 0x20; c < 0x7F; c++) {
            String s = String.valueOf(c).repeat(4);
            if (vecchia.matcher(s).matches() != SecurityUtils.isValidPassword(s)) diverse++;
        }
        for (char c : new char[] { 'è', 'é', '€', '\t', '\n', ' ' }) {
            String s = "Abc1" + c;
            if (vecchia.matcher(s).matches() != SecurityUtils.isValidPassword(s)) diverse++;
        }
        esigi("ogni carattere ASCII stampabile, accenti, tab, a capo, spazio unificatore: " + diverse + " differenze", diverse == 0);
        esigi("3 caratteri no, 4 si'", !SecurityUtils.isValidPassword("Ab1") && SecurityUtils.isValidPassword("Ab1!"));
        esigi("128 caratteri si', 129 no", SecurityUtils.isValidPassword("a".repeat(128)) && !SecurityUtils.isValidPassword("a".repeat(129)));
        esigi("la classe per la pagina e' quella attesa",
                SecurityUtils.PASSWORD_CARATTERI.equals("[a-zA-Z0-9!@#$%\\^&*()_+\\-=\\[\\]{}|;:,.?]"));

        System.out.println("\n== e con i simboli di prima il pannello rifiutava la propria proposta ==");
        String vecchiSimboli = "!@#$%^&*()_-+=[]{}|;:,.<>?/~`";
        String vecchioPool = "abcdefghijklmnopqrstuvwxyz" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ" + "0123456789" + vecchiSimboli;
        SecureRandom rnd = new SecureRandom();
        int prove = 10000, rifiutate = 0;
        for (int i = 0; i < prove; i++) {
            // Come il vecchio generatore: un simbolo garantito, il resto dal pool intero.
            StringBuilder sb = new StringBuilder();
            sb.append(vecchiSimboli.charAt(rnd.nextInt(vecchiSimboli.length())));
            for (int k = 1; k < 20; k++) sb.append(vecchioPool.charAt(rnd.nextInt(vecchioPool.length())));
            if (!SecurityUtils.isValidPassword(sb.toString())) rifiutate++;
        }
        esigi(String.format("vecchio \"Tutti i caratteri\", 20 caratteri: rifiutate %.0f%% (se un giorno passano, la prova non distingue piu')",
                100.0 * rifiutate / prove), rifiutate > prove / 2);

        System.out.println("\n" + (falliti == 0 ? "TUTTO VERDE" : falliti + " CONTROLLI FALLITI"));
        if (falliti > 0) System.exit(1);
    }
}
