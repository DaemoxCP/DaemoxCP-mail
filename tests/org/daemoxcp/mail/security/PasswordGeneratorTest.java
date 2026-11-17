package org.daemoxcp.mail.security;

import org.daemoxcp.mail.webserver.SecurityUtils;

import java.security.SecureRandom;
import java.util.regex.Pattern;

/**
 * The password generator and the rule the panel applies to mailbox passwords.
 *
 * The generator had symbols of its own: with "All characters" it also put < > / ~ and the
 * backtick, which isValidPassword rejects. The password proposed by the panel was rejected by the
 * panel itself ("Invalid password" when creating a mailbox, a warning and no change when editing
 * it). Here thousands of passwords are generated for every kind and combination and all of them
 * must pass, and the rule is checked to be the same as before.
 */
public class PasswordGeneratorTest {

    static int failed = 0;
    static void require(String what, boolean ok) {
        System.out.println((ok ? "  OK   " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    public static void main(String[] a) throws Exception {
        // No key is needed to generate: the vault's keys are read only to encrypt or decrypt a copy.
        PasswordVault vault = PasswordVault.getInstance();

        System.out.println("\n== every generated password passes the panel's rule ==");
        String[] kinds = { "easy_to_say", "easy_to_read", "all_chars", "unknown", null };
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
            require(String.format("%-13s %6d passwords: %d rejected, %d of the wrong length, %d without a chosen set",
                    type, generate, rejected, wrongLength, missingSet),
                    rejected == 0 && wrongLength == 0 && missingSet == 0);
        }

        System.out.println("\n== length outside the limits: brought back inside (mailbox minimum: 12) ==");
        require("3 becomes 12", vault.generatePassword(3, "all_chars", true, true, true, true).length() == 12);
        require("8 (the generator's old minimum) becomes 12", vault.generatePassword(8, "easy_to_read", true, true, true, true).length() == 12);
        require("500 becomes 128", vault.generatePassword(500, "all_chars", true, true, true, true).length() == 128);

        System.out.println("\n== the entropy estimate uses the same sets as the generator ==");
        require("all_chars, everything: 26+26+10+24 = 86", PasswordVault.poolSize("all_chars", true, true, true, true) == 86);
        require("easy_to_read, everything: 24+24+8+21 = 77", PasswordVault.poolSize("easy_to_read", true, true, true, true) == 77);
        require("easy_to_say ignores digits and symbols: 52", PasswordVault.poolSize("easy_to_say", true, true, true, true) == 52);
        require("no choice: it falls back on everything (86)", PasswordVault.poolSize("all_chars", false, false, false, false) == 86);

        System.out.println("\n== the rule has not changed: same answer as the old expression ==");
        Pattern old = Pattern.compile("^[a-zA-Z0-9!@#$%^&*()_+\\-=\\[\\]{}|;:,.?]{4,128}$");
        int different = 0;
        for (char c = 0x20; c < 0x7F; c++) {
            String s = String.valueOf(c).repeat(4);
            if (old.matcher(s).matches() != SecurityUtils.isValidPassword(s)) different++;
        }
        for (char c : new char[] { 'è', 'é', '€', '\t', '\n', ' ' }) {
            String s = "Abc1" + c;
            if (old.matcher(s).matches() != SecurityUtils.isValidPassword(s)) different++;
        }
        require("every printable ASCII character, accents, tab, newline, non-breaking space: " + different + " differences", different == 0);
        require("3 characters no, 4 yes", !SecurityUtils.isValidPassword("Ab1") && SecurityUtils.isValidPassword("Ab1!"));
        require("128 characters yes, 129 no", SecurityUtils.isValidPassword("a".repeat(128)) && !SecurityUtils.isValidPassword("a".repeat(129)));
        require("the class for the page is the expected one",
                SecurityUtils.PASSWORD_CHARACTERS.equals("[a-zA-Z0-9!@#$%\\^&*()_+\\-=\\[\\]{}|;:,.?]"));

        System.out.println("\n== mailbox passwords: at least 12 characters, the same characters as the admin's ==");
        require("11 characters no, 12 yes", !SecurityUtils.isValidMailboxPassword("Ab1!Ab1!Ab1") && SecurityUtils.isValidMailboxPassword("Ab1!Ab1!Ab1!"));
        require("128 yes, 129 no", SecurityUtils.isValidMailboxPassword("a".repeat(128)) && !SecurityUtils.isValidMailboxPassword("a".repeat(129)));
        require("null no", !SecurityUtils.isValidMailboxPassword(null));
        int differentMailbox = 0;
        for (char c = 0x20; c < 0x7F; c++) {
            String s = String.valueOf(c).repeat(12);
            if (old.matcher(s).matches() != SecurityUtils.isValidMailboxPassword(s)) differentMailbox++;
        }
        require("at 12 characters it accepts exactly the old characters: " + differentMailbox + " differences", differentMailbox == 0);
        require("the admin's login does not change: 4 characters stay valid", SecurityUtils.isValidPassword("Ab1!"));

        System.out.println("\n== and with the old symbols the panel refused its own proposal ==");
        String oldSymbols = "!@#$%^&*()_-+=[]{}|;:,.<>?/~`";
        String oldPool = "abcdefghijklmnopqrstuvwxyz" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ" + "0123456789" + oldSymbols;
        SecureRandom random = new SecureRandom();
        int tests = 10000, refused = 0;
        for (int i = 0; i < tests; i++) {
            // Like the old generator: one guaranteed symbol, the rest from the whole pool.
            StringBuilder sb = new StringBuilder();
            sb.append(oldSymbols.charAt(random.nextInt(oldSymbols.length())));
            for (int k = 1; k < 20; k++) sb.append(oldPool.charAt(random.nextInt(oldPool.length())));
            if (!SecurityUtils.isValidPassword(sb.toString())) refused++;
        }
        require(String.format("old \"All characters\", 20 characters: %.0f%% refused (if one day they pass, the test no longer tells them apart)",
                100.0 * refused / tests), refused > tests / 2);

        System.out.println("\n" + (failed == 0 ? "ALL GREEN" : failed + " CHECKS FAILED"));
        if (failed > 0) System.exit(1);
    }
}
