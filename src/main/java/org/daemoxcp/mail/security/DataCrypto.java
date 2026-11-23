package org.daemoxcp.mail.security;

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
 * Encryption of the personal data that the panel must be able to read back (the login email of every
 * administrator, the IP address and the browser of a session) and a blind index to look them up.
 *
 *  - AES-256-GCM, a random 12-byte nonce for every encryption, never fixed; the ciphertext is
 *    saved as "v1:" + base64(nonce || ciphertext || tag). Never MySQL's AES_ENCRYPT();
 *  - the blind index is HMAC-SHA256 with a key different from the encryption one: it allows
 *    looking up an email without being able to read it;
 *  - the keys are only in the secrets file (PanelSecrets), never in the database.
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

    /** The plaintext; a tampered value or one encrypted with another key throws an exception. */
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

    /** The plaintext, or "" if the value is missing or cannot be decrypted (key changed, value corrupted). */
    public static String decryptOrEmpty(String stored) {
        if (stored == null || stored.isEmpty()) return "";
        try {
            return decrypt(stored);
        } catch (RuntimeException e) {
            return "";
        }
    }

    /** The blind index of an email: lowercase and without spaces at the ends, then HMAC-SHA256 in hexadecimal. */
    public static String emailIndex(String email) {
        return hmacHex(PanelSecrets.key(PanelSecrets.INDEX_KEY), "email:" + email.trim().toLowerCase(Locale.ROOT));
    }

    /** The fingerprint of a one-time code: the database holds only this, never the code. */
    public static String codeHash(String purpose, long adminId, String code) {
        return hmacHex(PanelSecrets.key(PanelSecrets.CODE_KEY), purpose + ":" + adminId + ":" + code);
    }

    /** SHA-256 in hexadecimal (the fingerprint of a session's User-Agent). */
    public static String sha256Hex(String value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    /** Constant-time comparison of two ASCII fingerprints or tokens. */
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
