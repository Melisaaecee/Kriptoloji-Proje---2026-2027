package ktu.guvenlihaberlesme.crypto.aes;

import java.security.GeneralSecurityException;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/** Karşılaştırma için kütüphaneli AES-128: JDK, tek blok, padding ve IV yok. */
public final class JdkAes128 implements Aes128BlockCipher {

    @Override
    public byte[] encryptBlock(byte[] key, byte[] block) {
        return run(Cipher.ENCRYPT_MODE, key, block);
    }

    @Override
    public byte[] decryptBlock(byte[] key, byte[] block) {
        return run(Cipher.DECRYPT_MODE, key, block);
    }

    private static byte[] run(int mode, byte[] key, byte[] block) {
        if (key.length != KEY_BYTES || block.length != BLOCK_BYTES) {
            throw new IllegalArgumentException("Anahtar ve blok 16 bayt olmalı");
        }
        try {
            Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
            cipher.init(mode, new SecretKeySpec(key, "AES"));
            return cipher.doFinal(block);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }
}
