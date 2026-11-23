package org.daemoxcp.mail.security;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.logging.Logger;

/**
 * The encrypted copy of the mailbox passwords, for "Show password".
 *
 * <p>With an asymmetric key: the web part encrypts the copies of new passwords with the public key, which is in
 * its secrets file, and reads none of them; only the root part reads them, being the only one with the private key (in
 * the root secrets file). Whoever took over the web part would not carry away the mailbox passwords, not even those that
 * pass through there afterwards.
 *
 * <p>The format (v2): {@code "v2:" + base64(version 0x02 || wrapped AES key || nonce || ciphertext and tag)}.
 * For each copy a new AES-256 key, taken from the cryptographic generator, wrapped with RSA-OAEP (SHA-256 and
 * MGF1 with SHA-256) in the 3072-bit RSA public key; the password encrypted with AES-256-GCM, a random 12-byte
 * nonce, and the version and the wrapped key bound to the tag (additional data): nobody can swap them.
 *
 * <p>The old copies (v1) are AES-256-GCM with the symmetric key of {@code master.key}: the root part re-encrypts them to
 * v2 at startup ({@link #reencryptOldCopies}); the file stays, root only, for a copy that could not be
 * re-encrypted.
 */
public class PasswordVault {
    private static final Logger LOGGER = Logger.getLogger(PasswordVault.class.getName());

    /** The symmetric key of the old copies (tests move it with -Ddaemoxcp.mail.vault.key=...). */
    private static final String KEY_FILE = System.getProperty("daemoxcp.mail.vault.key", "/usr/local/etc/daemoxcp-mail/master.key");

    /** The marker of the asymmetric-key copies. Base64 does not contain ':', so no v1 copy starts like this. */
    static final String V2_PREFIX = "v2:";
    private static final byte V2 = 2;
    private static final int RSA_BITS = 3072;
    private static final int WRAPPED_LEN = RSA_BITS / 8;
    private static final int GCM_IV_LEN = 12;
    private static final int GCM_TAG_BITS = 128;
    private static final OAEPParameterSpec OAEP = new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256,
            PSource.PSpecified.DEFAULT);

    private static volatile PasswordVault INSTANCE;
    private final SecureRandom rng = new SecureRandom();

    private PasswordVault() {}

    public static PasswordVault getInstance() {
        PasswordVault local = INSTANCE;
        if (local == null) {
            synchronized (PasswordVault.class) {
                if (INSTANCE == null) INSTANCE = new PasswordVault();
                local = INSTANCE;
            }
        }
        return local;
    }

    private static boolean runningAsRoot() {
        return "root".equals(System.getProperty("user.name"));
    }

    // ===================== The keys =====================

    /**
     * The root part, at startup and before switching on the web part: the key pair exists, and the public key in the
     * web file matches the private one. If the private key is missing it generates it; if the public one is missing or
     * does not match, it rewrites it from the private one (a copy restored by hand, for example). True if it changed
     * something.
     */
    public static synchronized boolean ensureKeyPair() {
        if (!runningAsRoot()) return false;
        String priv = PanelSecrets.text(PanelSecrets.VAULT_PRIVATE_KEY);
        boolean generated = false;
        if (priv.isEmpty()) {
            try {
                KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
                g.initialize(RSA_BITS, new SecureRandom());
                KeyPair pair = g.generateKeyPair();
                priv = Base64.getEncoder().encodeToString(pair.getPrivate().getEncoded());
            } catch (Exception e) {
                throw new IllegalStateException("Vault key pair not generated: " + e.getMessage(), e);
            }
            PanelSecrets.setText(PanelSecrets.VAULT_PRIVATE_KEY, priv);
            if (!priv.equals(PanelSecrets.reread(PanelSecrets.VAULT_PRIVATE_KEY)))
                throw new IllegalStateException("Vault private key not saved in " + PanelSecrets.location(PanelSecrets.VAULT_PRIVATE_KEY));
            generated = true;
        }
        String pub = Base64.getEncoder().encodeToString(publicOf(privateKey(priv)).getEncoded());
        if (!pub.equals(PanelSecrets.text(PanelSecrets.VAULT_PUBLIC_KEY))) {
            PanelSecrets.setText(PanelSecrets.VAULT_PUBLIC_KEY, pub);
            if (!generated) LOGGER.info("[PasswordVault] DONE: the vault's public key written again from the private one");
        }
        if (generated)
            LOGGER.info("[PasswordVault] DONE: new vault key pair (RSA " + RSA_BITS + "): the private key only in root's secrets file, "
                    + "the public one in the web part's");
        return generated;
    }

    static PrivateKey privateKey(String base64) {
        try {
            return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(base64.trim())));
        } catch (Exception e) {
            throw new IllegalStateException("Vault private key unreadable: " + e.getMessage(), e);
        }
    }

    static PublicKey publicKey(String base64) {
        try {
            return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(base64.trim())));
        } catch (Exception e) {
            throw new IllegalStateException("Vault public key unreadable: " + e.getMessage(), e);
        }
    }

    /** The public key of an RSA private key (modulus and exponent are also in the private key). */
    static PublicKey publicOf(PrivateKey key) {
        try {
            RSAPrivateCrtKey k = (RSAPrivateCrtKey) key;
            return KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(k.getModulus(), k.getPublicExponent()));
        } catch (Exception e) {
            throw new IllegalStateException("Vault public key not derived: " + e.getMessage(), e);
        }
    }

    /** The public key to encrypt with: from the web file (the root part puts it there at startup). */
    private static PublicKey currentPublicKey() {
        String pub = PanelSecrets.text(PanelSecrets.VAULT_PUBLIC_KEY);
        if (pub.isEmpty() && runningAsRoot()) {
            // The root part without a key pair yet (a new installation, a test): it creates it here.
            ensureKeyPair();
            pub = PanelSecrets.text(PanelSecrets.VAULT_PUBLIC_KEY);
        }
        if (pub.isEmpty()) throw org.daemoxcp.mail.util.ShownException.of("server.vault.noPublicKey");
        return publicKey(pub);
    }

    /** Where the private key is, to tell whoever makes a copy of it. */
    public static String privateKeyLocation() {
        return PanelSecrets.location(PanelSecrets.VAULT_PRIVATE_KEY);
    }

    /**
     * The private key in base64 (PKCS#8), for the backup copy: with it all the password copies can be
     * read. Root part only. To put it back: in the root secrets file, under the vault_private_key entry; the root part
     * rewrites the public key at the next startup.
     */
    public String exportPrivateKeyBase64() {
        if (!runningAsRoot()) throw new IllegalStateException("Only the root part has the vault's private key");
        String priv = PanelSecrets.text(PanelSecrets.VAULT_PRIVATE_KEY);
        if (priv.isEmpty()) throw org.daemoxcp.mail.util.ShownException.of("server.vault.noPrivateKey");
        return priv;
    }

    // ===================== Cifrare e decifrare =====================

    /** Encrypts a password with the public key (v2 format): the web part and the root part. */
    public String encrypt(String plaintext) {
        return encryptWith(plaintext, currentPublicKey());
    }

    String encryptWith(String plaintext, PublicKey publicKey) {
        if (plaintext == null) return null;
        try {
            byte[] aes = new byte[32];
            rng.nextBytes(aes);
            Cipher rsa = Cipher.getInstance("RSA/ECB/OAEPPadding");
            rsa.init(Cipher.ENCRYPT_MODE, publicKey, OAEP, rng);
            byte[] wrapped = rsa.doFinal(aes);
            if (wrapped.length != WRAPPED_LEN) throw new IllegalStateException("the vault's public key is not RSA " + RSA_BITS);
            byte[] iv = new byte[GCM_IV_LEN];
            rng.nextBytes(iv);
            Cipher gcm = Cipher.getInstance("AES/GCM/NoPadding");
            gcm.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(aes, "AES"), new GCMParameterSpec(GCM_TAG_BITS, iv));
            gcm.updateAAD(new byte[]{V2});
            gcm.updateAAD(wrapped);
            byte[] ct = gcm.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
            java.util.Arrays.fill(aes, (byte) 0);
            byte[] out = new byte[1 + wrapped.length + iv.length + ct.length];
            out[0] = V2;
            System.arraycopy(wrapped, 0, out, 1, wrapped.length);
            System.arraycopy(iv, 0, out, 1 + wrapped.length, iv.length);
            System.arraycopy(ct, 0, out, 1 + wrapped.length + iv.length, ct.length);
            return V2_PREFIX + Base64.getEncoder().encodeToString(out);
        } catch (Exception e) {
            throw new RuntimeException("PasswordVault encrypt failed: " + e.getMessage(), e);
        }
    }

    /** True if the copy is already in the asymmetric-key format. */
    public static boolean isCurrentFormat(String encoded) {
        return encoded != null && encoded.startsWith(V2_PREFIX);
    }

    /**
     * Decrypts a copy: v2 with the private key (and, if that does not work, with the one from before the rotation), v1 with
     * master.key. Root part only: in the web part there is nothing to decrypt with.
     */
    public String decrypt(String encoded) {
        if (encoded == null || encoded.isEmpty()) return null;
        if (!runningAsRoot()) throw new IllegalStateException("Only the root part reads the vault");
        if (!isCurrentFormat(encoded)) return decryptOld(encoded);
        String priv = PanelSecrets.text(PanelSecrets.VAULT_PRIVATE_KEY);
        if (priv.isEmpty()) throw org.daemoxcp.mail.util.ShownException.of("server.vault.noPrivateKey");
        try {
            return decryptWith(encoded, privateKey(priv));
        } catch (RuntimeException current) {
            String previous = PanelSecrets.text(PanelSecrets.VAULT_PREVIOUS_PRIVATE_KEY);
            if (previous.isEmpty()) throw current;
            return decryptWith(encoded, privateKey(previous));
        }
    }

    String decryptWith(String encoded, PrivateKey privateKey) {
        try {
            byte[] data = Base64.getDecoder().decode(encoded.substring(V2_PREFIX.length()));
            if (data.length < 1 + WRAPPED_LEN + GCM_IV_LEN + GCM_TAG_BITS / 8 || data[0] != V2)
                throw new IllegalArgumentException("not a vault copy of version 2");
            byte[] wrapped = java.util.Arrays.copyOfRange(data, 1, 1 + WRAPPED_LEN);
            byte[] iv = java.util.Arrays.copyOfRange(data, 1 + WRAPPED_LEN, 1 + WRAPPED_LEN + GCM_IV_LEN);
            byte[] ct = java.util.Arrays.copyOfRange(data, 1 + WRAPPED_LEN + GCM_IV_LEN, data.length);
            Cipher rsa = Cipher.getInstance("RSA/ECB/OAEPPadding");
            rsa.init(Cipher.DECRYPT_MODE, privateKey, OAEP);
            byte[] aes = rsa.doFinal(wrapped);
            Cipher gcm = Cipher.getInstance("AES/GCM/NoPadding");
            gcm.init(Cipher.DECRYPT_MODE, new SecretKeySpec(aes, "AES"), new GCMParameterSpec(GCM_TAG_BITS, iv));
            java.util.Arrays.fill(aes, (byte) 0);
            gcm.updateAAD(new byte[]{V2});
            gcm.updateAAD(wrapped);
            return new String(gcm.doFinal(ct), StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new RuntimeException("PasswordVault decrypt failed: " + e.getMessage(), e);
        }
    }

    /** An old copy (v1: base64 of nonce || ciphertext and tag), with the master.key key. */
    private static String decryptOld(String encoded) {
        try {
            byte[] key = oldKey();
            byte[] data = Base64.getDecoder().decode(encoded);
            if (data.length <= GCM_IV_LEN) throw new IllegalArgumentException("blob too short");
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"),
                    new GCMParameterSpec(GCM_TAG_BITS, java.util.Arrays.copyOfRange(data, 0, GCM_IV_LEN)));
            return new String(cipher.doFinal(data, GCM_IV_LEN, data.length - GCM_IV_LEN), StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new RuntimeException("PasswordVault decrypt failed (old copy): " + e.getMessage(), e);
        }
    }

    /** The 32 bytes of the old key: base64 (the form written by the panel) or raw bytes. */
    private static byte[] oldKey() throws java.io.IOException {
        Path keyPath = Paths.get(KEY_FILE);
        if (!Files.exists(keyPath)) throw new java.io.IOException("no " + KEY_FILE + " for the copies of before");
        byte[] raw = Files.readAllBytes(keyPath);
        byte[] keyBytes;
        try {
            keyBytes = Base64.getDecoder().decode(new String(raw, StandardCharsets.UTF_8).trim());
        } catch (IllegalArgumentException notBase64) {
            keyBytes = raw;
        }
        if (keyBytes.length != 32) throw new java.io.IOException("the old master key has " + keyBytes.length + " bytes, not 32");
        return keyBytes;
    }

    // ===================== Re-encrypting =====================

    /** How a re-encryption went: how many copies, how many re-encrypted, how many not. */
    public record Reencrypted(int total, int reencrypted, int failed) {}

    /**
     * At root part startup: the old copies (v1, master.key) re-encrypted with the public key. Only those: the others
     * stay as they are, and on the second startup there is nothing to do. A copy that cannot be decrypted stays as it
     * is, and the log says so.
     */
    public static Reencrypted reencryptOldCopies(org.daemoxcp.mail.database.MailDatabase db) throws java.sql.SQLException {
        PasswordVault vault = getInstance();
        PublicKey pub = currentPublicKey();
        int total = 0, done = 0, failed = 0;
        for (Object[] row : db.listMailboxesWithEncryptedPasswordAndBlob()) {
            String blob = (String) row[1];
            if (isCurrentFormat(blob)) continue;
            total++;
            try {
                db.setMailboxEncryptedPasswordOnly((int) row[0], vault.encryptWith(decryptOld(blob), pub));
                done++;
            } catch (RuntimeException e) {
                failed++;
                LOGGER.warning("[PasswordVault] the copy of mailbox " + row[0] + " is not readable with " + KEY_FILE + ": left as it is");
            }
        }
        if (done > 0) LOGGER.info("[PasswordVault] DONE: " + done + " password copies of before encrypted again with the public key");
        return new Reencrypted(total, done, failed);
    }

    /**
     * The rotation ("Administrators" -> "vault"): a new pair, all the copies re-encrypted with its public key, then the
     * pair saved. The previous private key stays in the root file (vault_previous_private_key) for the copies that
     * could not be re-encrypted. If none is re-encrypted but there were some, the new pair is not saved.
     */
    public synchronized Reencrypted rotate(org.daemoxcp.mail.database.MailDatabase db) throws java.sql.SQLException {
        if (!runningAsRoot()) throw new IllegalStateException("Only the root part rotates the vault's keys");
        KeyPair pair;
        try {
            KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
            g.initialize(RSA_BITS, new SecureRandom());
            pair = g.generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException("Vault key pair not generated: " + e.getMessage(), e);
        }
        java.util.List<Object[]> rows = db.listMailboxesWithEncryptedPasswordAndBlob();
        java.util.List<Object[]> fresh = new java.util.ArrayList<>();
        int failed = 0;
        for (Object[] row : rows) {
            try {
                fresh.add(new Object[]{row[0], encryptWith(decrypt((String) row[1]), pair.getPublic())});
            } catch (RuntimeException e) {
                failed++;
                LOGGER.warning("[PasswordVault] rotation: the copy of mailbox " + row[0] + " is not readable: left as it is");
            }
        }
        if (fresh.isEmpty() && !rows.isEmpty()) return new Reencrypted(rows.size(), 0, failed);
        // Keys first (the new private key in the root file, the old one next to it), then the copies: halfway through every
        // copy can be read with one or the other.
        String before = PanelSecrets.text(PanelSecrets.VAULT_PRIVATE_KEY);
        if (!before.isEmpty()) PanelSecrets.setText(PanelSecrets.VAULT_PREVIOUS_PRIVATE_KEY, before);
        String priv = Base64.getEncoder().encodeToString(pair.getPrivate().getEncoded());
        PanelSecrets.setText(PanelSecrets.VAULT_PRIVATE_KEY, priv);
        if (!priv.equals(PanelSecrets.reread(PanelSecrets.VAULT_PRIVATE_KEY)))
            throw new IllegalStateException("Vault private key not saved in " + privateKeyLocation());
        PanelSecrets.setText(PanelSecrets.VAULT_PUBLIC_KEY, Base64.getEncoder().encodeToString(pair.getPublic().getEncoded()));
        for (Object[] row : fresh) db.setMailboxEncryptedPasswordOnly((int) row[0], (String) row[1]);
        return new Reencrypted(rows.size(), fresh.size(), failed);
    }

    // ===================== The password generator =====================

    /**
     * Generates a secure password: 20 characters from all the sets ("all_chars"), that is letters,
     * digits and the symbols that SecurityUtils.isValidMailboxPassword accepts.
     */
    public String generatePassword() {
        return generatePassword(20);
    }

    public String generatePassword(int length) {
        return generatePassword(length, "all_chars", true, true, true, true);
    }

    // The generator's character sets. The symbols of "all_chars" are the ones that
    // SecurityUtils.isValidPassword accepts, taken from there. They used to be written here, with in addition
    // < > / ~ and the backtick: a password generated with "All characters" was rejected by the panel itself
    // on creation ("Invalid password") or discarded on edit, on average seven
    // times out of ten. tests/.../PasswordGeneratorTest checks it for every type and combination.
    private static final String LOWERCASE = "abcdefghijklmnopqrstuvwxyz";
    private static final String UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private static final String DIGITS = "0123456789";
    private static final String SYMBOLS = org.daemoxcp.mail.webserver.SecurityUtils.PASSWORD_SYMBOLS;
    // "easy_to_read": no characters that get confused (0/O, 1/l/I), symbols convenient for shell/JSON/CSV.
    private static final String CLEAR_LOWERCASE = "abcdefghijkmnpqrstuvwxyz";    // no l, o
    private static final String CLEAR_UPPERCASE = "ABCDEFGHJKLMNPQRSTUVWXYZ";    // no I, O
    private static final String CLEAR_DIGITS = "23456789";                        // no 0, 1
    private static final String CLEAR_SYMBOLS = "!@#%^*()_-+=[]{}:;,.?";

    /**
     * The active character sets for a type and a set of choices, in the order in which the generator
     * guarantees at least one of each. Both the generator and the entropy estimate use it,
     * so the two can no longer tell different sets.
     *
     * @param type "easy_to_say" (letters only: digits and symbols ignored), "easy_to_read"
     *             (no ambiguous characters) or "all_chars"; any other value counts as "easy_to_read"
     */
    static java.util.List<String> sets(String type, boolean includeLower, boolean includeUpper,
                                          boolean includeDigits, boolean includeSymbols) {
        if (type == null) type = "easy_to_read";
        String lower, upper, digits, symbols;
        switch (type) {
            case "easy_to_say" -> {
                lower = LOWERCASE; upper = UPPERCASE; digits = ""; symbols = "";
                includeDigits = false;
                includeSymbols = false;
            }
            case "all_chars" -> { lower = LOWERCASE; upper = UPPERCASE; digits = DIGITS; symbols = SYMBOLS; }
            default -> { lower = CLEAR_LOWERCASE; upper = CLEAR_UPPERCASE; digits = CLEAR_DIGITS; symbols = CLEAR_SYMBOLS; }
        }
        // No category chosen: a reasonable fallback, all those the type allows.
        if (!includeLower && !includeUpper && !includeDigits && !includeSymbols) {
            includeLower = includeUpper = true;
            if (!"easy_to_say".equals(type)) { includeDigits = includeSymbols = true; }
        }
        java.util.List<String> active = new java.util.ArrayList<>();
        if (includeLower)   active.add(lower);
        if (includeUpper)   active.add(upper);
        if (includeDigits)  active.add(digits);
        if (includeSymbols) active.add(symbols);
        return active;
    }

    /** How many different characters a password with these choices can contain (for the entropy estimate). */
    public static int poolSize(String type, boolean includeLower, boolean includeUpper,
                                     boolean includeDigits, boolean includeSymbols) {
        int n = 0;
        for (String s : sets(type, includeLower, includeUpper, includeDigits, includeSymbols)) n += s.length();
        return n;
    }

    /**
     * Configurable password generator.
     *
     * @param length      desired length, brought within SecurityUtils.MAILBOX_PASSWORD_MIN..128: the
     *                    generator is for mailboxes, and the panel would not accept a shorter password
     * @param type        "easy_to_say"  -> letters only (lowercase+uppercase), no digits/symbols - easy to dictate aloud
     *                    "easy_to_read" -> "safe" characters (no ambiguous 0/O/1/l/I, no troublesome symbols)
     *                    "all_chars"    -> all the letters and digits and all the symbols the panel accepts
     *                    (any other value is treated as "easy_to_read")
     * @param includeLower include lowercase characters
     * @param includeUpper include uppercase characters
     * @param includeDigits include digits (ignored if type=easy_to_say)
     * @param includeSymbols include symbols (ignored if type=easy_to_say)
     */
    public String generatePassword(int length, String type, boolean includeLower, boolean includeUpper,
                                    boolean includeDigits, boolean includeSymbols) {
        if (length < org.daemoxcp.mail.webserver.SecurityUtils.MAILBOX_PASSWORD_MIN)
            length = org.daemoxcp.mail.webserver.SecurityUtils.MAILBOX_PASSWORD_MIN;
        if (length > org.daemoxcp.mail.webserver.SecurityUtils.PASSWORD_MAX) length = org.daemoxcp.mail.webserver.SecurityUtils.PASSWORD_MAX;

        // Active sets (at least one, guaranteed by sets()) and full pool
        java.util.List<String> activeSets = sets(type, includeLower, includeUpper, includeDigits, includeSymbols);
        String allPool = String.join("", activeSets);

        char[] chars = new char[length];
        // Guarantee at least 1 of each active category
        int filled = 0;
        for (String set : activeSets) {
            if (filled >= length) break;
            chars[filled++] = set.charAt(rng.nextInt(set.length()));
        }
        // Fill the rest drawing from the full pool
        for (int i = filled; i < length; i++) {
            chars[i] = allPool.charAt(rng.nextInt(allPool.length()));
        }
        // Fisher-Yates shuffle so that the first N positions are not fixed by category
        for (int i = chars.length - 1; i > 0; i--) {
            int j = rng.nextInt(i + 1);
            char tmp = chars[i]; chars[i] = chars[j]; chars[j] = tmp;
        }
        return new String(chars);
    }

    /**
     * Estimates the password entropy (bits) from the length and the pool size.
     * Approximation: log2(poolSize) * length.
     */
    public static double estimateEntropy(int length, int poolSize) {
        if (length <= 0 || poolSize <= 1) return 0.0;
        return (Math.log(poolSize) / Math.log(2)) * length;
    }
}
