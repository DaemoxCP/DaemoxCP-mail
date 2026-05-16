package org.mail_panel.security;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.logging.Logger;

/**
 * Vault per password mailbox: AES-256-GCM con chiave master in file root-only.
 *
 * Workflow:
 *  - Al primo avvio genera una chiave master (32 byte random) e la salva su disco
 *    con permessi 600 in {@link #KEY_FILE}.
 *  - In RAM mantiene la chiave per cifrare/decifrare.
 *  - Cifratura AES-256-GCM con IV random per ogni chiamata (12 byte IV + 16 byte auth tag).
 *  - Output base64: 12 byte IV | ciphertext+tag — un blob auto-contenuto.
 *
 * Trade-off di sicurezza:
 *  - Le password mailbox restano comunque BCrypt-hashate nel campo principale
 *    (per Dovecot/Postfix auth). Il blob cifrato è SOLO un copia recuperabile lato pannello.
 *  - Se un attaccante prende sia il DB sia il filesystem (root access), può decifrare
 *    le password mailbox. Ma con root access farebbe ben di peggio comunque.
 *  - La feature aumenta l'usabilità (recovery, sharing controllato) accettando
 *    questo trade-off di "se sei root puoi tutto".
 */
public class PasswordVault {
    private static final Logger LOGGER = Logger.getLogger(PasswordVault.class.getName());

    /** Dove va a finire la chiave master sul disco. */
    private static final String KEY_FILE = "/usr/local/etc/mail-panel/master.key";

    private static final int KEY_SIZE_BYTES   = 32; // AES-256
    private static final int GCM_IV_LEN       = 12; // standard per GCM
    private static final int GCM_TAG_BITS     = 128;

    /** Singleton lazy: la chiave viene caricata/generata alla prima invocazione. */
    private static volatile PasswordVault INSTANCE;

    private final SecretKey key;
    private final SecureRandom rng = new SecureRandom();

    private volatile SecretKey activeKey;

    private PasswordVault(SecretKey key) {
        this.key = key;
        this.activeKey = key;
    }

    /** Restituisce la path del file chiave master (per il backup). */
    public static String getKeyFilePath() {
        return KEY_FILE;
    }

    /**
     * Esporta la chiave master come stringa base64. Da usare SOLO per backup
     * controllato — l'output è il valore di sicurezza più sensibile dell'applicazione.
     */
    public String exportKeyBase64() {
        return Base64.getEncoder().encodeToString(activeKey.getEncoded());
    }

    /**
     * Rotazione della chiave master.
     *
     *  - Genera una nuova chiave random
     *  - L'esecuzione del re-encrypt dei blob esistenti è responsabilità del CHIAMANTE
     *    (vedi {@code MailDatabase.bulkReencryptPasswords}), che chiamerà decrypt() (vecchia chiave)
     *    + encrypt() (nuova chiave) per ogni record.
     *  - Per supportare quel flow esponiamo {@link #setActiveKey(byte[])} e
     *    {@link #decryptWithKey(String, byte[])} che permettono di passare la chiave esplicitamente.
     *  - Al termine il chiamante deve invocare {@link #persistNewKey(byte[])} che
     *    salva la nuova chiave su disco con backup della vecchia.
     */
    public byte[] generateNewKeyBytes() {
        byte[] newKey = new byte[KEY_SIZE_BYTES];
        new SecureRandom().nextBytes(newKey);
        return newKey;
    }

    /** Cifra con una chiave esplicita (usato durante la rotazione: cifra coi nuovi bytes). */
    public String encryptWithKey(String plaintext, byte[] keyBytes) {
        if (plaintext == null) return null;
        try {
            byte[] iv = new byte[GCM_IV_LEN];
            rng.nextBytes(iv);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(keyBytes, "AES"),
                new GCMParameterSpec(GCM_TAG_BITS, iv));
            byte[] ct = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
            byte[] out = new byte[iv.length + ct.length];
            System.arraycopy(iv, 0, out, 0, iv.length);
            System.arraycopy(ct, 0, out, iv.length, ct.length);
            return Base64.getEncoder().encodeToString(out);
        } catch (Exception e) {
            throw new RuntimeException("encryptWithKey failed: " + e.getMessage(), e);
        }
    }

    /**
     * Salva la nuova chiave su disco e la rende attiva in RAM.
     * Fa anche un backup della precedente in master.key.bak.<timestamp>
     */
    public synchronized void persistNewKey(byte[] newKeyBytes) {
        try {
            Path keyPath = Paths.get(KEY_FILE);
            if (Files.exists(keyPath)) {
                Path backup = Paths.get(KEY_FILE + ".bak." + System.currentTimeMillis());
                Files.copy(keyPath, backup);
                try {
                    Files.setPosixFilePermissions(backup, PosixFilePermissions.fromString("rw-------"));
                } catch (Exception ignored) {}
                LOGGER.info("[PasswordVault] Backup vecchia chiave in " + backup);
            }
            String b64 = Base64.getEncoder().encodeToString(newKeyBytes);
            Files.writeString(keyPath, b64, StandardCharsets.UTF_8,
                StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
            try {
                Files.setPosixFilePermissions(keyPath, PosixFilePermissions.fromString("rw-------"));
            } catch (Exception ignored) {}
            this.activeKey = new SecretKeySpec(newKeyBytes, "AES");
            LOGGER.info("[PasswordVault] Nuova chiave master attiva e salvata in " + KEY_FILE);
        } catch (Exception e) {
            throw new RuntimeException("persistNewKey failed: " + e.getMessage(), e);
        }
    }

    public static PasswordVault getInstance() {
        PasswordVault local = INSTANCE;
        if (local == null) {
            synchronized (PasswordVault.class) {
                if (INSTANCE == null) {
                    INSTANCE = loadOrCreate();
                }
                local = INSTANCE;
            }
        }
        return local;
    }

    /**
     * Cifra una password in plaintext. Ritorna una stringa base64 auto-contenuta
     * (IV + ciphertext + GCM auth tag). Sicura per essere salvata in TEXT su DB.
     */
    public String encrypt(String plaintext) {
        if (plaintext == null) return null;
        try {
            byte[] iv = new byte[GCM_IV_LEN];
            rng.nextBytes(iv);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, activeKey, new GCMParameterSpec(GCM_TAG_BITS, iv));
            byte[] ct = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
            // Concatena IV || ciphertext+tag
            byte[] out = new byte[iv.length + ct.length];
            System.arraycopy(iv, 0, out, 0, iv.length);
            System.arraycopy(ct, 0, out, iv.length, ct.length);
            return Base64.getEncoder().encodeToString(out);
        } catch (Exception e) {
            throw new RuntimeException("PasswordVault encrypt failed: " + e.getMessage(), e);
        }
    }

    /**
     * Decifra una password con la chiave attiva. Input atteso: output di {@link #encrypt}.
     * Lancia RuntimeException se il blob è corrotto o cifrato con un'altra chiave.
     */
    public String decrypt(String encoded) {
        return decryptWithKey(encoded, activeKey.getEncoded());
    }

    /** Decifra con una chiave esplicita (usato durante la rotazione: decripta con la vecchia chiave). */
    public String decryptWithKey(String encoded, byte[] keyBytes) {
        if (encoded == null || encoded.isEmpty()) return null;
        try {
            byte[] data = Base64.getDecoder().decode(encoded);
            if (data.length <= GCM_IV_LEN) throw new IllegalArgumentException("blob troppo corto");
            byte[] iv = new byte[GCM_IV_LEN];
            byte[] ct = new byte[data.length - GCM_IV_LEN];
            System.arraycopy(data, 0, iv, 0, GCM_IV_LEN);
            System.arraycopy(data, GCM_IV_LEN, ct, 0, ct.length);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(keyBytes, "AES"),
                new GCMParameterSpec(GCM_TAG_BITS, iv));
            byte[] pt = cipher.doFinal(ct);
            return new String(pt, StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new RuntimeException("PasswordVault decrypt failed: " + e.getMessage(), e);
        }
    }

    /**
     * Genera una password sicura: 20 caratteri, mix di maiuscole/minuscole/cifre/simboli
     * (esclusi caratteri facilmente confondibili come 0/O, 1/l/I, e simboli problematici
     * per shell/url come " ' ` $ \ ` & |).
     */
    public String generatePassword() {
        return generatePassword(20);
    }

    public String generatePassword(int length) {
        return generatePassword(length, "all_chars", true, true, true, true);
    }

    /**
     * Generatore password configurabile.
     *
     * @param length      lunghezza desiderata (clamped 8..128)
     * @param type        "easy_to_say"  → solo lettere (lowercase+uppercase), no numeri/simboli — facile da dettare a voce
     *                    "easy_to_read" → caratteri "safe" (no ambigui 0/O/1/l/I, no simboli problematici)
     *                    "all_chars"    → set completo, anche simboli "rischiosi" come ?/=/&/$ → max entropia
     *                    (qualsiasi altro valore viene trattato come "easy_to_read")
     * @param includeLower include caratteri minuscoli
     * @param includeUpper include caratteri maiuscoli
     * @param includeDigits include cifre (ignorato se type=easy_to_say)
     * @param includeSymbols include simboli (ignorato se type=easy_to_say)
     */
    public String generatePassword(int length, String type, boolean includeLower, boolean includeUpper,
                                    boolean includeDigits, boolean includeSymbols) {
        if (length < 8) length = 8;
        if (length > 128) length = 128;
        if (type == null) type = "easy_to_read";

        // Set di caratteri in base al type
        String lower, upper, digits, symbols;
        switch (type) {
            case "easy_to_say":
                // Solo lettere; ignora digits/symbols anche se richiesti
                lower  = "abcdefghijklmnopqrstuvwxyz";
                upper  = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
                digits = "";
                symbols = "";
                includeDigits = false;
                includeSymbols = false;
                break;
            case "all_chars":
                // Set completo, massima entropia (anche simboli "rischiosi")
                lower   = "abcdefghijklmnopqrstuvwxyz";
                upper   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
                digits  = "0123456789";
                symbols = "!@#$%^&*()_-+=[]{}|;:,.<>?/~`";
                break;
            case "easy_to_read":
            default:
                // No ambigui (0/O, 1/l/I) + simboli "safe" per shell/JSON/CSV
                lower   = "abcdefghijkmnpqrstuvwxyz";          // no l, o
                upper   = "ABCDEFGHJKLMNPQRSTUVWXYZ";           // no I, O
                digits  = "23456789";                            // no 0, 1
                symbols = "!@#%^*()_-+=[]{}:;,.?";              // safe per shell/JSON
                break;
        }

        // Almeno una categoria deve essere selezionata
        if (!includeLower && !includeUpper && !includeDigits && !includeSymbols) {
            // Fallback ragionevole: tutto attivo
            includeLower = includeUpper = true;
            if (!"easy_to_say".equals(type)) { includeDigits = includeSymbols = true; }
        }

        // Costruisci il pool effettivo e la lista di sets attivi (per garantire almeno 1 di ogni)
        StringBuilder pool = new StringBuilder();
        java.util.List<String> activeSets = new java.util.ArrayList<>();
        if (includeLower)   { pool.append(lower);   activeSets.add(lower); }
        if (includeUpper)   { pool.append(upper);   activeSets.add(upper); }
        if (includeDigits)  { pool.append(digits);  activeSets.add(digits); }
        if (includeSymbols) { pool.append(symbols); activeSets.add(symbols); }
        String allPool = pool.toString();

        if (allPool.isEmpty()) {
            // Edge case impossibile dopo il fallback sopra, ma defensive
            allPool = "abcdefghijklmnopqrstuvwxyz";
            activeSets.add(allPool);
        }

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

    // ============ KEY LOADING / GENERATION ============

    private static PasswordVault loadOrCreate() {
        try {
            Path keyPath = Paths.get(KEY_FILE);
            if (Files.exists(keyPath)) {
                byte[] raw = Files.readAllBytes(keyPath);
                // Il file può essere base64 (preferred) o raw bytes
                byte[] keyBytes;
                String content = new String(raw, StandardCharsets.UTF_8).trim();
                try {
                    keyBytes = Base64.getDecoder().decode(content);
                } catch (IllegalArgumentException notBase64) {
                    keyBytes = raw;
                }
                if (keyBytes.length != KEY_SIZE_BYTES) {
                    throw new RuntimeException("Master key file ha dimensione errata: "
                        + keyBytes.length + " bytes (atteso: " + KEY_SIZE_BYTES + ")");
                }
                LOGGER.info("[PasswordVault] Chiave master caricata da " + KEY_FILE);
                return new PasswordVault(new SecretKeySpec(keyBytes, "AES"));
            }

            // Genera nuova chiave
            Path parent = keyPath.getParent();
            if (parent != null && !Files.isDirectory(parent)) {
                Files.createDirectories(parent);
                try {
                    Files.setPosixFilePermissions(parent, PosixFilePermissions.fromString("rwx------"));
                } catch (Exception ignored) {}
            }
            byte[] newKey = new byte[KEY_SIZE_BYTES];
            new SecureRandom().nextBytes(newKey);
            // Salva in base64 con header esplicativo
            String fileContent = Base64.getEncoder().encodeToString(newKey);
            Files.writeString(keyPath, fileContent, StandardCharsets.UTF_8,
                StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
            try {
                // 600 = solo root può leggere
                Files.setPosixFilePermissions(keyPath, PosixFilePermissions.fromString("rw-------"));
            } catch (Exception ignored) {}
            LOGGER.warning("[PasswordVault] NUOVA chiave master generata in " + KEY_FILE +
                " — fai un backup sicuro di questo file! Senza, le password cifrate sono perse.");
            return new PasswordVault(new SecretKeySpec(newKey, "AES"));

        } catch (Exception e) {
            throw new RuntimeException("PasswordVault init failed: " + e.getMessage(), e);
        }
    }
}
