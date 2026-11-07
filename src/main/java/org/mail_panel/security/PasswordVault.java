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

    /** Dove va a finire la chiave master sul disco (i test la spostano con -Dmailpanel.vault.key=...). */
    private static final String KEY_FILE = System.getProperty("mailpanel.vault.key", "/usr/local/etc/mail-panel/master.key");

    private static final int KEY_SIZE_BYTES   = 32; // AES-256
    private static final int GCM_IV_LEN       = 12; // standard per GCM
    private static final int GCM_TAG_BITS     = 128;

    /** Singleton lazy: la chiave viene caricata/generata alla prima invocazione. */
    private static volatile PasswordVault INSTANCE;

    private final SecretKey key;
    private final SecureRandom rng = new SecureRandom();

    private volatile SecretKey activeKey;
    /** Data, dimensione e inode del file da cui viene activeKey: se cambiano, la chiave si rilegge. */
    private volatile String keyStamp = stamp();

    private PasswordVault(SecretKey key) {
        this.key = key;
        this.activeKey = key;
    }

    /**
     * La chiave attiva, riletta se il file e' cambiato. Col pannello separato la usano due processi (la
     * parte root cifra le caselle nuove, la web decifra per la webmail) e la rotazione la fa uno solo: senza
     * rileggere, l'altro continuerebbe con la chiave vecchia, e una casella cifrata cosi' non si
     * decifrerebbe piu'. Costa uno stat del file a operazione.
     */
    private SecretKey activeKey() {
        String now = stamp();
        if (!now.equals(keyStamp) && !now.isEmpty()) {
            synchronized (this) {
                if (!now.equals(keyStamp)) {
                    try {
                        activeKey = new SecretKeySpec(readKeyFile(Paths.get(KEY_FILE)), "AES");
                        LOGGER.info("[PasswordVault] master key changed on disk: reloaded from " + KEY_FILE);
                    } catch (Exception e) {
                        LOGGER.warning("[PasswordVault] master key changed on disk but unreadable, keeping the one in memory: " + e.getMessage());
                    }
                    keyStamp = now;
                }
            }
        }
        return activeKey;
    }

    private static String stamp() {
        try {
            java.nio.file.attribute.BasicFileAttributes a = Files.readAttributes(Paths.get(KEY_FILE),
                    java.nio.file.attribute.BasicFileAttributes.class);
            return a.lastModifiedTime().toMillis() + ":" + a.size() + ":" + a.fileKey();
        } catch (Exception e) {
            return "";
        }
    }

    /** I 32 byte della chiave dal file: base64 (la forma scritta dal pannello) o byte grezzi. */
    private static byte[] readKeyFile(Path keyPath) throws java.io.IOException {
        byte[] raw = Files.readAllBytes(keyPath);
        byte[] keyBytes;
        String content = new String(raw, StandardCharsets.UTF_8).trim();
        try {
            keyBytes = Base64.getDecoder().decode(content);
        } catch (IllegalArgumentException notBase64) {
            keyBytes = raw;
        }
        if (keyBytes.length != KEY_SIZE_BYTES) {
            throw new RuntimeException("Master key file has the wrong size: "
                + keyBytes.length + " bytes (expected: " + KEY_SIZE_BYTES + ")");
        }
        return keyBytes;
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
        return Base64.getEncoder().encodeToString(activeKey().getEncoded());
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
                // La copia nasce gia' 0600 e col gruppo di root: Files.copy la creava coi permessi
                // dell'umask (0644) e solo dopo la chiudeva, e su FreeBSD col gruppo della cartella.
                try {
                    Files.createFile(backup, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
                    if (PanelSecrets.webGroup(backup))
                        Files.getFileAttributeView(backup, java.nio.file.attribute.PosixFileAttributeView.class).setGroup(
                                backup.getFileSystem().getUserPrincipalLookupService().lookupPrincipalByGroupName("wheel"));
                } catch (UnsupportedOperationException noPosix) {
                    Files.createFile(backup);
                }
                Files.write(backup, Files.readAllBytes(keyPath), StandardOpenOption.TRUNCATE_EXISTING);
                LOGGER.info("[PasswordVault] Old key backed up to " + backup);
            }
            String b64 = Base64.getEncoder().encodeToString(newKeyBytes);
            // Un file nuovo e un rename, non una riscrittura sul posto: l'altra parte del pannello separato
            // legge la chiave in ogni momento, e a meta' scrittura avrebbe trovato un file vuoto. Il nuovo
            // prende il gruppo e i permessi del vecchio: col pannello separato e' 0640 root:mailpanel.
            Path tmp = keyPath.resolveSibling(keyPath.getFileName() + ".tmp");
            Files.deleteIfExists(tmp);
            Files.writeString(tmp, b64, StandardCharsets.UTF_8, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
            String perms = "rw-------";
            try {
                Files.setPosixFilePermissions(tmp, PosixFilePermissions.fromString(perms));
                if (Files.exists(keyPath) && PanelSecrets.webGroup(keyPath)) {
                    Files.getFileAttributeView(tmp, java.nio.file.attribute.PosixFileAttributeView.class).setGroup(
                            tmp.getFileSystem().getUserPrincipalLookupService().lookupPrincipalByGroupName(PanelSecrets.WEB_GROUP));
                    perms = "rw-r-----";
                    Files.setPosixFilePermissions(tmp, PosixFilePermissions.fromString(perms));
                }
            } catch (UnsupportedOperationException ignored) {}
            Files.move(tmp, keyPath, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
            this.activeKey = new SecretKeySpec(newKeyBytes, "AES");
            this.keyStamp = stamp();
            LOGGER.info("[PasswordVault] New master key active and saved to " + KEY_FILE);
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
            cipher.init(Cipher.ENCRYPT_MODE, activeKey(), new GCMParameterSpec(GCM_TAG_BITS, iv));
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
        return decryptWithKey(encoded, activeKey().getEncoded());
    }

    /** Decifra con una chiave esplicita (usato durante la rotazione: decripta con la vecchia chiave). */
    public String decryptWithKey(String encoded, byte[] keyBytes) {
        if (encoded == null || encoded.isEmpty()) return null;
        try {
            byte[] data = Base64.getDecoder().decode(encoded);
            if (data.length <= GCM_IV_LEN) throw new IllegalArgumentException("blob too short");
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
    private static final String SYMBOLS = org.mail_panel.webserver.SecurityUtils.PASSWORD_SYMBOLS;
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
        if (length < org.mail_panel.webserver.SecurityUtils.MAILBOX_PASSWORD_MIN)
            length = org.mail_panel.webserver.SecurityUtils.MAILBOX_PASSWORD_MIN;
        if (length > org.mail_panel.webserver.SecurityUtils.PASSWORD_MAX) length = org.mail_panel.webserver.SecurityUtils.PASSWORD_MAX;

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

    // ============ KEY LOADING / GENERATION ============

    private static PasswordVault loadOrCreate() {
        try {
            Path keyPath = Paths.get(KEY_FILE);
            if (Files.exists(keyPath)) {
                // Il file può essere base64 (preferred) o raw bytes
                byte[] keyBytes = readKeyFile(keyPath);
                LOGGER.info("[PasswordVault] Master key loaded from " + KEY_FILE);
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
            LOGGER.warning("[PasswordVault] NEW master key generated in " + KEY_FILE +
                " — keep a safe backup of this file! Without it, the encrypted passwords are lost.");
            return new PasswordVault(new SecretKeySpec(newKey, "AES"));

        } catch (Exception e) {
            throw new RuntimeException("PasswordVault init failed: " + e.getMessage(), e);
        }
    }
}
