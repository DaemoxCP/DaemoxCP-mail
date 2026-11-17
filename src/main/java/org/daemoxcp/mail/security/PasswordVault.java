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
 * La copia cifrata delle password delle caselle, per «Mostra password».
 *
 * <p>A chiave asimmetrica: la parte web cifra le copie delle password nuove con la chiave pubblica, che sta nel
 * suo file dei segreti, e non ne legge nessuna; le legge solo la parte root, che sola ha la chiave privata (nel
 * file dei segreti di root). Chi prendesse la web non porta via le password delle caselle, nemmeno quelle che
 * passano di li' dopo.
 *
 * <p>Il formato (v2): {@code "v2:" + base64(versione 0x02 || chiave AES avvolta || nonce || testo cifrato e tag)}.
 * Per ogni copia una chiave AES-256 nuova, presa dal generatore crittografico, avvolta con RSA-OAEP (SHA-256 e
 * MGF1 con SHA-256) nella chiave pubblica RSA da 3072 bit; la password cifrata con AES-256-GCM, nonce di 12 byte a
 * caso, e la versione e la chiave avvolta legate al tag (dati aggiuntivi): nessuno puo' scambiarle.
 *
 * <p>Le copie di prima (v1) sono AES-256-GCM con la chiave simmetrica di {@code master.key}: la root le ricifra in
 * v2 all'avvio ({@link #reencryptOldCopies}); il file resta, solo di root, per una copia che non si fosse potuta
 * ricifrare.
 */
public class PasswordVault {
    private static final Logger LOGGER = Logger.getLogger(PasswordVault.class.getName());

    /** La chiave simmetrica delle copie di prima (i test la spostano con -Dmailpanel.vault.key=...). */
    private static final String KEY_FILE = System.getProperty("mailpanel.vault.key", "/usr/local/etc/mail-panel/master.key");

    /** Il segno delle copie a chiave asimmetrica. Il base64 non contiene ':', quindi nessuna copia v1 comincia cosi'. */
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

    // ===================== Le chiavi =====================

    /**
     * La parte root, all'avvio e prima di accendere la web: la coppia di chiavi c'e', e la chiave pubblica nel file
     * della web e' quella della privata. Se manca la privata la genera; se la pubblica manca o non corrisponde, la
     * riscrive da quella privata (una copia ripristinata a mano, per esempio). Vero se ha cambiato qualcosa.
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

    /** La chiave pubblica di una privata RSA (modulo ed esponente stanno anche nella privata). */
    static PublicKey publicOf(PrivateKey key) {
        try {
            RSAPrivateCrtKey k = (RSAPrivateCrtKey) key;
            return KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(k.getModulus(), k.getPublicExponent()));
        } catch (Exception e) {
            throw new IllegalStateException("Vault public key not derived: " + e.getMessage(), e);
        }
    }

    /** La chiave pubblica con cui cifrare: dal file della web (la root la mette li' all'avvio). */
    private static PublicKey currentPublicKey() {
        String pub = PanelSecrets.text(PanelSecrets.VAULT_PUBLIC_KEY);
        if (pub.isEmpty() && runningAsRoot()) {
            // La root senza ancora una coppia (un'installazione nuova, una prova): la crea qui.
            ensureKeyPair();
            pub = PanelSecrets.text(PanelSecrets.VAULT_PUBLIC_KEY);
        }
        if (pub.isEmpty()) throw new IllegalStateException("The vault has no public key yet");
        return publicKey(pub);
    }

    /** Dove sta la chiave privata, da dire a chi ne fa la copia. */
    public static String privateKeyLocation() {
        return PanelSecrets.location(PanelSecrets.VAULT_PRIVATE_KEY);
    }

    /**
     * La chiave privata in base64 (PKCS#8), per la copia di sicurezza: con questa si leggono tutte le copie delle
     * password. Solo la root. Per rimetterla: nel file dei segreti di root, alla voce vault_private_key; la root
     * riscrive la pubblica al prossimo avvio.
     */
    public String exportPrivateKeyBase64() {
        if (!runningAsRoot()) throw new IllegalStateException("Only the root part has the vault's private key");
        String priv = PanelSecrets.text(PanelSecrets.VAULT_PRIVATE_KEY);
        if (priv.isEmpty()) throw new IllegalStateException("The vault has no private key yet");
        return priv;
    }

    // ===================== Cifrare e decifrare =====================

    /** Cifra una password con la chiave pubblica (formato v2): la web e la root. */
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

    /** Vero se la copia e' gia' nel formato a chiave asimmetrica. */
    public static boolean isCurrentFormat(String encoded) {
        return encoded != null && encoded.startsWith(V2_PREFIX);
    }

    /**
     * Decifra una copia: v2 con la chiave privata (e, se non torna, con quella di prima della rotazione), v1 con
     * master.key. Solo la parte root: nella web non c'e' niente con cui decifrare.
     */
    public String decrypt(String encoded) {
        if (encoded == null || encoded.isEmpty()) return null;
        if (!runningAsRoot()) throw new IllegalStateException("Only the root part reads the vault");
        if (!isCurrentFormat(encoded)) return decryptOld(encoded);
        String priv = PanelSecrets.text(PanelSecrets.VAULT_PRIVATE_KEY);
        if (priv.isEmpty()) throw new IllegalStateException("The vault has no private key");
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

    /** Una copia di prima (v1: base64 di nonce || testo cifrato e tag), con la chiave di master.key. */
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

    /** I 32 byte della chiave di prima: base64 (la forma scritta dal pannello) o byte grezzi. */
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

    // ===================== Ricifrare =====================

    /** Com'e' andata una ricifratura: quante copie, quante ricifrate, quante no. */
    public record Reencrypted(int total, int reencrypted, int failed) {}

    /**
     * All'avvio della root: le copie di prima (v1, master.key) ricifrate con la chiave pubblica. Solo quelle: le altre
     * restano come sono, e al secondo avvio non c'e' niente da fare. Una copia che non si decifra resta com'e', e il
     * registro lo dice.
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
     * La rotazione (Amministratori → cassaforte): una coppia nuova, tutte le copie ricifrate con la sua pubblica, poi
     * la coppia salvata. La privata di prima resta nel file di root (vault_previous_private_key) per le copie che non si
     * fossero potute ricifrare. Se non se ne ricifra nessuna ma ce n'erano, la coppia nuova non si salva.
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
        // Prima le chiavi (la privata nuova nel file di root, la vecchia accanto), poi le copie: a meta' strada ogni
        // copia si legge con l'una o con l'altra.
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

    // ===================== Il generatore di password =====================

    /**
     * Genera una password sicura: 20 caratteri da tutti gli insiemi ("all_chars"), cioe' lettere,
     * cifre e i simboli che SecurityUtils.isValidMailboxPassword accetta.
     */
    public String generatePassword() {
        return generatePassword(20);
    }

    public String generatePassword(int length) {
        return generatePassword(length, "all_chars", true, true, true, true);
    }

    // Gli insiemi di caratteri del generatore. I simboli di "all_chars" sono quelli che
    // SecurityUtils.isValidPassword accetta, presi da li'. Prima erano scritti qui, con in piu'
    // < > / ~ e l'apice inverso: una password generata con "Tutti i caratteri" il pannello stesso
    // la rifiutava in creazione ("Password non valida") o la scartava in modifica, in media sette
    // volte su dieci. tests/.../PasswordGeneratorTest lo verifica per ogni tipo e combinazione.
    private static final String LOWERCASE = "abcdefghijklmnopqrstuvwxyz";
    private static final String UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private static final String DIGITS = "0123456789";
    private static final String SYMBOLS = org.daemoxcp.mail.webserver.SecurityUtils.PASSWORD_SYMBOLS;
    // "easy_to_read": niente caratteri che si confondono (0/O, 1/l/I), simboli comodi per shell/JSON/CSV.
    private static final String CLEAR_LOWERCASE = "abcdefghijkmnpqrstuvwxyz";    // no l, o
    private static final String CLEAR_UPPERCASE = "ABCDEFGHJKLMNPQRSTUVWXYZ";    // no I, O
    private static final String CLEAR_DIGITS = "23456789";                        // no 0, 1
    private static final String CLEAR_SYMBOLS = "!@#%^*()_-+=[]{}:;,.?";

    /**
     * Gli insiemi di caratteri attivi per un tipo e delle scelte, nell'ordine in cui il generatore
     * ne garantisce almeno uno ciascuno. Lo usano sia il generatore sia la stima dell'entropia,
     * cosi' i due non possono piu' raccontare insiemi diversi.
     *
     * @param type "easy_to_say" (solo lettere: cifre e simboli ignorati), "easy_to_read"
     *             (niente caratteri ambigui) o "all_chars"; qualsiasi altro valore vale "easy_to_read"
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
        // Nessuna categoria scelta: ripiego ragionevole, tutte quelle che il tipo ammette.
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

    /** Quanti caratteri diversi puo' contenere una password con queste scelte (per la stima dell'entropia). */
    public static int poolSize(String type, boolean includeLower, boolean includeUpper,
                                     boolean includeDigits, boolean includeSymbols) {
        int n = 0;
        for (String s : sets(type, includeLower, includeUpper, includeDigits, includeSymbols)) n += s.length();
        return n;
    }

    /**
     * Generatore password configurabile.
     *
     * @param length      lunghezza desiderata, riportata dentro SecurityUtils.MAILBOX_PASSWORD_MIN..128: il
     *                    generatore serve alle caselle, e una password piu' corta il pannello non la accetterebbe
     * @param type        "easy_to_say"  → solo lettere (lowercase+uppercase), no numeri/simboli — facile da dettare a voce
     *                    "easy_to_read" → caratteri "safe" (no ambigui 0/O/1/l/I, no simboli problematici)
     *                    "all_chars"    → tutte le lettere e cifre e tutti i simboli che il pannello accetta
     *                    (qualsiasi altro valore viene trattato come "easy_to_read")
     * @param includeLower include caratteri minuscoli
     * @param includeUpper include caratteri maiuscoli
     * @param includeDigits include cifre (ignorato se type=easy_to_say)
     * @param includeSymbols include simboli (ignorato se type=easy_to_say)
     */
    public String generatePassword(int length, String type, boolean includeLower, boolean includeUpper,
                                    boolean includeDigits, boolean includeSymbols) {
        if (length < org.daemoxcp.mail.webserver.SecurityUtils.MAILBOX_PASSWORD_MIN)
            length = org.daemoxcp.mail.webserver.SecurityUtils.MAILBOX_PASSWORD_MIN;
        if (length > org.daemoxcp.mail.webserver.SecurityUtils.PASSWORD_MAX) length = org.daemoxcp.mail.webserver.SecurityUtils.PASSWORD_MAX;

        // Insiemi attivi (almeno uno, garantito da sets()) e pool completo
        java.util.List<String> activeSets = sets(type, includeLower, includeUpper, includeDigits, includeSymbols);
        String allPool = String.join("", activeSets);

        char[] chars = new char[length];
        // Garantisci almeno 1 di ogni categoria attiva
        int filled = 0;
        for (String set : activeSets) {
            if (filled >= length) break;
            chars[filled++] = set.charAt(rng.nextInt(set.length()));
        }
        // Riempi il resto pescando dal pool completo
        for (int i = filled; i < length; i++) {
            chars[i] = allPool.charAt(rng.nextInt(allPool.length()));
        }
        // Fisher-Yates shuffle per non avere le prime N posizioni categoria-fissate
        for (int i = chars.length - 1; i > 0; i--) {
            int j = rng.nextInt(i + 1);
            char tmp = chars[i]; chars[i] = chars[j]; chars[j] = tmp;
        }
        return new String(chars);
    }

    /**
     * Stima l'entropia della password (bit) in funzione di lunghezza e dimensione del pool.
     * Approssimazione: log2(poolSize) * length.
     */
    public static double estimateEntropy(int length, int poolSize) {
        if (length <= 0 || poolSize <= 1) return 0.0;
        return (Math.log(poolSize) / Math.log(2)) * length;
    }
}
