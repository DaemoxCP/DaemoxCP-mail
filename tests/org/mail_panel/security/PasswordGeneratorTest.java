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
public class PasswordGeneratorTest {

    static int failed = 0;
    static void require(String what, boolean ok) {
        System.out.println((ok ? "  OK   " : "  FALLITO ") + what);
        if (!ok) failed++;
    }

    public static void main(String[] a) throws Exception {
        // La chiave non serve a generare: niente getInstance(), che leggerebbe o creerebbe
        // /usr/local/etc/mail-panel/master.key.
        var constructor = PasswordVault.class.getDeclaredConstructor(SecretKey.class);
        constructor.setAccessible(true);
        PasswordVault vault = constructor.newInstance(new SecretKeySpec(new byte[32], "AES"));

        System.out.println("\n== ogni password generata passa la regola del pannello ==");
        String[] kinds = { "easy_to_say", "easy_to_read", "all_chars", "sconosciuto", null };
        int[] lengths = { 12, 20, 64, 128 };
        for (String type : kinds) {
            int generate = 0, rejected = 0, wrongLength = 0, missingSet = 0;
            for (int combo = 0; combo < 16; combo++) {
                boolean lo = (combo & 1) != 0, up = (combo & 2) != 0, nu = (combo & 4) != 0, sy = (combo & 8) != 0;
                var active = PasswordVault.sets(type, lo, up, nu, sy);
                for (int len : lengths) {
                    for (int i = 0; i < 150; i++) {
                        String pw = vault.generatePassword(len, type, lo, up, nu, sy);
                        generate++;
                        if (!SecurityUtils.isValidMailboxPassword(pw) || !SecurityUtils.isValidPassword(pw)) rejected++;
                        if (pw.length() != len) wrongLength++;
                        for (String set : active) {
                            boolean c = false;
                            for (char ch : pw.toCharArray()) if (set.indexOf(ch) >= 0) { c = true; break; }
                            if (!c) { missingSet++; break; }
                        }
                    }
                }
            }
            require(String.format("%-13s %6d password: %d respinte, %d di lunghezza sbagliata, %d senza un insieme scelto",
                    type, generate, rejected, wrongLength, missingSet),
                    rejected == 0 && wrongLength == 0 && missingSet == 0);
        }

        System.out.println("\n== lunghezza fuori dai limiti: si riporta dentro (minimo delle caselle: 12) ==");
        require("3 diventa 12", vault.generatePassword(3, "all_chars", true, true, true, true).length() == 12);
        require("8 (il vecchio minimo del generatore) diventa 12", vault.generatePassword(8, "easy_to_read", true, true, true, true).length() == 12);
        require("500 diventa 128", vault.generatePassword(500, "all_chars", true, true, true, true).length() == 128);

        System.out.println("\n== la stima dell'entropia usa gli stessi insiemi del generatore ==");
        require("all_chars, tutto: 26+26+10+24 = 86", PasswordVault.poolSize("all_chars", true, true, true, true) == 86);
        require("easy_to_read, tutto: 24+24+8+21 = 77", PasswordVault.poolSize("easy_to_read", true, true, true, true) == 77);
        require("easy_to_say ignora cifre e simboli: 52", PasswordVault.poolSize("easy_to_say", true, true, true, true) == 52);
        require("nessuna scelta: si ripiega su tutto (86)", PasswordVault.poolSize("all_chars", false, false, false, false) == 86);

        System.out.println("\n== la regola non e' cambiata: stessa risposta della vecchia espressione ==");
        Pattern old = Pattern.compile("^[a-zA-Z0-9!@#$%^&*()_+\\-=\\[\\]{}|;:,.?]{4,128}$");
        int diverse = 0;
        for (char c = 0x20; c < 0x7F; c++) {
            String s = String.valueOf(c).repeat(4);
            if (old.matcher(s).matches() != SecurityUtils.isValidPassword(s)) diverse++;
        }
        for (char c : new char[] { 'è', 'é', '€', '\t', '\n', ' ' }) {
            String s = "Abc1" + c;
            if (old.matcher(s).matches() != SecurityUtils.isValidPassword(s)) diverse++;
        }
        require("ogni carattere ASCII stampabile, accenti, tab, a capo, spazio unificatore: " + diverse + " differenze", diverse == 0);
        require("3 caratteri no, 4 si'", !SecurityUtils.isValidPassword("Ab1") && SecurityUtils.isValidPassword("Ab1!"));
        require("128 caratteri si', 129 no", SecurityUtils.isValidPassword("a".repeat(128)) && !SecurityUtils.isValidPassword("a".repeat(129)));
        require("la classe per la pagina e' quella attesa",
                SecurityUtils.PASSWORD_CHARACTERS.equals("[a-zA-Z0-9!@#$%\\^&*()_+\\-=\\[\\]{}|;:,.?]"));

        System.out.println("\n== password delle caselle: almeno 12 caratteri, stessi caratteri dell'admin ==");
        require("11 caratteri no, 12 si'", !SecurityUtils.isValidMailboxPassword("Ab1!Ab1!Ab1") && SecurityUtils.isValidMailboxPassword("Ab1!Ab1!Ab1!"));
        require("128 si', 129 no", SecurityUtils.isValidMailboxPassword("a".repeat(128)) && !SecurityUtils.isValidMailboxPassword("a".repeat(129)));
        require("null no", !SecurityUtils.isValidMailboxPassword(null));
        int differentMailbox = 0;
        for (char c = 0x20; c < 0x7F; c++) {
            String s = String.valueOf(c).repeat(12);
            if (old.matcher(s).matches() != SecurityUtils.isValidMailboxPassword(s)) differentMailbox++;
        }
        require("a 12 caratteri accetta esattamente i caratteri di prima: " + differentMailbox + " differenze", differentMailbox == 0);
        require("il login dell'admin non cambia: 4 caratteri restano validi", SecurityUtils.isValidPassword("Ab1!"));

        System.out.println("\n== e con i simboli di prima il pannello rifiutava la propria proposta ==");
        String oldSymbols = "!@#$%^&*()_-+=[]{}|;:,.<>?/~`";
        String oldPool = "abcdefghijklmnopqrstuvwxyz" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ" + "0123456789" + oldSymbols;
        SecureRandom random = new SecureRandom();
        int tests = 10000, refused = 0;
        for (int i = 0; i < tests; i++) {
            // Come il vecchio generatore: un simbolo garantito, il resto dal pool intero.
            StringBuilder sb = new StringBuilder();
            sb.append(oldSymbols.charAt(random.nextInt(oldSymbols.length())));
            for (int k = 1; k < 20; k++) sb.append(oldPool.charAt(random.nextInt(oldPool.length())));
            if (!SecurityUtils.isValidPassword(sb.toString())) refused++;
        }
        require(String.format("vecchio \"Tutti i caratteri\", 20 caratteri: rifiutate %.0f%% (se un giorno passano, la prova non distingue piu')",
                100.0 * refused / tests), refused > tests / 2);

        System.out.println("\n" + (failed == 0 ? "TUTTO VERDE" : failed + " CONTROLLI FALLITI"));
        if (failed > 0) System.exit(1);
    }
}
