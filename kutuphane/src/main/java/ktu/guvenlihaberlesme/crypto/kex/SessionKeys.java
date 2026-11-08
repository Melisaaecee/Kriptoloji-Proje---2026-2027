package ktu.guvenlihaberlesme.crypto.kex;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Arrays;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/** Ortak sırdan AES-128 anahtarı türetir. */
final class SessionKeys {

    static final int AES_KEY_BYTES = 16;

    private SessionKeys() {
    }

    /** SHA-256 özetinin ilk 16 baytı AES anahtarı olur. */
    static SecretKey fromSharedSecret(byte[] sharedSecret) throws GeneralSecurityException {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(sharedSecret);
        return new SecretKeySpec(Arrays.copyOf(digest, AES_KEY_BYTES), "AES");
    }
}
