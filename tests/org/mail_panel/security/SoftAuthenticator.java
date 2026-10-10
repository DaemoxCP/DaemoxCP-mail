package org.mail_panel.security;

import com.upokecenter.cbor.CBORObject;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;

/**
 * A software WebAuthn authenticator for tests: a real P-256 key, real ES256 signatures, "none"
 * attestation, the same JSON the browser sends. Each knob breaks one thing the server must check.
 */
public final class SoftAuthenticator {

    private static final SecureRandom RANDOM = new SecureRandom();

    final KeyPair keys;
    public final byte[] credentialId = new byte[16];
    public long counter = 0;
    public String userHandle;

    // Knobs: what the next ceremony gets wrong on purpose.
    public String originOverride;
    public String rpIdOverride;
    public boolean userVerified = true;
    public boolean breakSignature;
    public Long counterOverride;

    public SoftAuthenticator() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(new ECGenParameterSpec("secp256r1"));
        keys = g.generateKeyPair();
        RANDOM.nextBytes(credentialId);
    }

    public static String b64u(byte[] b) { return Base64.getUrlEncoder().withoutPadding().encodeToString(b); }

    public String credentialIdB64u() { return b64u(credentialId); }

    private static byte[] sha256(byte[] b) throws Exception { return MessageDigest.getInstance("SHA-256").digest(b); }

    private static byte[] fixed32(BigInteger v) {
        byte[] raw = v.toByteArray();
        byte[] out = new byte[32];
        int n = Math.min(raw.length, 32);
        System.arraycopy(raw, raw.length - n, out, 32 - n, n);
        return out;
    }

    byte[] coseKey() {
        ECPublicKey pub = (ECPublicKey) keys.getPublic();
        CBORObject m = CBORObject.NewMap();
        m.Add(1, 2);      // kty: EC2
        m.Add(3, -7);     // alg: ES256
        m.Add(-1, 1);     // crv: P-256
        m.Add(-2, CBORObject.FromByteArray(fixed32(pub.getW().getAffineX())));
        m.Add(-3, CBORObject.FromByteArray(fixed32(pub.getW().getAffineY())));
        return m.EncodeToBytes();
    }

    private String clientData(String type, String challenge, String origin) {
        return new JSONObject().put("type", type).put("challenge", challenge).put("origin", origin).put("crossOrigin", false).toString();
    }

    private byte[] authData(String rpId, int flags, long count, byte[] attested) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(sha256(rpId.getBytes(StandardCharsets.UTF_8)));
        out.write(flags);
        out.write(ByteBuffer.allocate(4).putInt((int) count).array());
        if (attested != null) out.write(attested);
        return out.toByteArray();
    }

    /** The attestation object a registration produces ("none" attestation). */
    public byte[] attestationObject(String rpId) throws Exception {
        ByteArrayOutputStream acd = new ByteArrayOutputStream();
        acd.write(new byte[16]);                                       // AAGUID
        acd.write(ByteBuffer.allocate(2).putShort((short) credentialId.length).array());
        acd.write(credentialId);
        acd.write(coseKey());
        int flags = 0x01 | (userVerified ? 0x04 : 0) | 0x40;         // UP, UV, AT
        CBORObject ao = CBORObject.NewMap();
        ao.Add("fmt", "none");
        ao.Add("attStmt", CBORObject.NewMap());
        ao.Add("authData", CBORObject.FromByteArray(authData(rpId, flags, counter, acd.toByteArray())));
        return ao.EncodeToBytes();
    }

    /** The answer to navigator.credentials.create(), from the server's options JSON. */
    public String register(String optionsJson, String origin) throws Exception {
        JSONObject pk = new JSONObject(optionsJson).getJSONObject("publicKey");
        String rpId = rpIdOverride != null ? rpIdOverride : pk.getJSONObject("rp").getString("id");
        userHandle = pk.getJSONObject("user").getString("id");
        String cd = clientData("webauthn.create", pk.getString("challenge"), originOverride != null ? originOverride : origin);
        return new JSONObject().put("type", "public-key").put("id", credentialIdB64u()).put("rawId", credentialIdB64u())
                .put("clientExtensionResults", new JSONObject())
                .put("response", new JSONObject()
                        .put("clientDataJSON", b64u(cd.getBytes(StandardCharsets.UTF_8)))
                        .put("attestationObject", b64u(attestationObject(rpId))))
                .toString();
    }

    /** The answer to navigator.credentials.get(), from the server's options JSON. */
    public String assertion(String optionsJson, String origin) throws Exception {
        JSONObject pk = new JSONObject(optionsJson).getJSONObject("publicKey");
        String rpId = rpIdOverride != null ? rpIdOverride : pk.getString("rpId");
        String cd = clientData("webauthn.get", pk.getString("challenge"), originOverride != null ? originOverride : origin);
        long count = counterOverride != null ? counterOverride : ++counter;
        byte[] ad = authData(rpId, 0x01 | (userVerified ? 0x04 : 0), count, null);
        byte[] cdBytes = cd.getBytes(StandardCharsets.UTF_8);
        Signature s = Signature.getInstance("SHA256withECDSA");
        s.initSign(keys.getPrivate());
        s.update(ad);
        s.update(sha256(cdBytes));
        byte[] sig = s.sign();
        if (breakSignature) sig[sig.length - 1] ^= 0x01;
        JSONObject resp = new JSONObject()
                .put("authenticatorData", b64u(ad))
                .put("clientDataJSON", b64u(cdBytes))
                .put("signature", b64u(sig));
        if (userHandle != null) resp.put("userHandle", userHandle);
        return new JSONObject().put("type", "public-key").put("id", credentialIdB64u()).put("rawId", credentialIdB64u())
                .put("clientExtensionResults", new JSONObject()).put("response", resp).toString();
    }
}
