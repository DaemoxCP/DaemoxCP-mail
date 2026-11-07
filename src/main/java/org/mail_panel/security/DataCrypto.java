package org.mail_panel.security;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Locale;

/**
 * Cifratura dei dati personali che il pannello deve poter rileggere (l'email di accesso di ogni
 * amministratore, l'indirizzo IP e il browser di una sessione) e indice cieco per cercarli.
 *
 *  - AES-256-GCM, un nonce casuale di 12 byte per ogni cifratura, mai fisso; il testo cifrato si
 *    salva come "v1:" + base64(nonce || cifrato || tag). Mai AES_ENCRYPT() di MySQL;
 *  - l'indice cieco e' HMAC-SHA256 con una chiave diversa da quella di cifratura: permette di
 *    cercare un'email senza poterla leggere;
 *  - le chiavi stanno solo nel file dei segreti (PanelSecrets), mai nel database.
 */
public final class DataCrypto {

    private DataCrypto() {}

    private static final String PREFIX = "v1:";
    private static final int NONCE_BYTES = 12;
    private static final int TAG_BITS = 128;
    private static final SecureRandom RANDOM = new SecureRandom();

    public static String encrypt(String plain) {
        if (plain == null) return null;
        try {
            byte[] nonce = new byte[NONCE_BYTES];
            RANDOM.nextBytes(nonce);
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(PanelSecrets.key(PanelSecrets.DATA_KEY), "AES"),
                    new GCMParameterSpec(TAG_BITS, nonce));
            byte[] ct = c.doFinal(plain.getBytes(StandardCharsets.UTF_8));
            return PREFIX + Base64.getEncoder().encodeToString(ByteBuffer.allocate(nonce.length + ct.length).put(nonce).put(ct).array());
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Encryption failed", e);
        }
    }

    /** Il testo in chiaro; un valore manomesso o cifrato con un'altra chiave fa eccezione. */
    public static String decrypt(String stored) {
        if (stored == null) return null;
        if (!stored.startsWith(PREFIX)) throw new IllegalArgumentException("Not an encrypted value");
        try {
            byte[] all = Base64.getDecoder().decode(stored.substring(PREFIX.length()));
            if (all.length < NONCE_BYTES + TAG_BITS / 8) throw new IllegalArgumentException("Encrypted value too short");
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(PanelSecrets.key(PanelSecrets.DATA_KEY), "AES"),
                    new GCMParameterSpec(TAG_BITS, all, 0, NONCE_BYTES));
            return new String(c.doFinal(all, NONCE_BYTES, all.length - NONCE_BYTES), StandardCharsets.UTF_8);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Decryption failed (wrong key or tampered value)", e);
        }
    }

    /** Il testo in chiaro, o "" se il valore manca o non si decifra (chiave cambiata, valore rovinato). */
    public static String decryptOrEmpty(String stored) {
        if (stored == null || stored.isEmpty()) return "";
        try {
            return decrypt(stored);
        } catch (RuntimeException e) {
            return "";
        }
    }

    /** L'indice cieco di un'email: minuscole e senza spazi ai lati, poi HMAC-SHA256 in esadecimale. */
    public static String emailIndex(String email) {
        return hmacHex(PanelSecrets.key(PanelSecrets.INDEX_KEY), "email:" + email.trim().toLowerCase(Locale.ROOT));
    }

    /** L'impronta di un codice monouso: nel database c'e' solo questa, mai il codice. */
    public static String codeHash(String purpose, long adminId, String code) {
        return hmacHex(PanelSecrets.key(PanelSecrets.CODE_KEY), purpose + ":" + adminId + ":" + code);
    }

    /** SHA-256 in esadecimale (l'impronta dello User-Agent di una sessione). */
    public static String sha256Hex(String value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    /** Confronto a tempo costante di due impronte o token ASCII. */
    public static boolean sameHash(String a, String b) {
        if (a == null || b == null) return false;
        return MessageDigest.isEqual(a.getBytes(StandardCharsets.US_ASCII), b.getBytes(StandardCharsets.US_ASCII));
    }

    private static String hmacHex(byte[] key, String data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return HexFormat.of().formatHex(mac.doFinal(data.getBytes(StandardCharsets.UTF_8)));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HMAC failed", e);
        }
    }
}
