package ktu.guvenlihaberlesme.crypto.aes;

/**
 * Kütüphanesiz AES-128: S-box, ShiftRows, MixColumns, AddRoundKey ve anahtar genişletme burada yazılacak.
 * Bitince ManualAes128Test üzerindeki @Disabled kaldırılır.
 */
public final class ManualAes128 implements Aes128BlockCipher {

    @Override
    public byte[] encryptBlock(byte[] key, byte[] block) {
        throw new UnsupportedOperationException("Henüz yazılmadı");
    }

    @Override
    public byte[] decryptBlock(byte[] key, byte[] block) {
        throw new UnsupportedOperationException("Henüz yazılmadı");
    }
}
