package ktu.guvenlihaberlesme.crypto.aes;

/** Tek 16 baytlık blok üzerinde AES-128. Manuel ve kütüphaneli sürüm aynı girdiyle karşılaştırılır. */
public interface Aes128BlockCipher {

    int BLOCK_BYTES = 16;
    int KEY_BYTES = 16;

    byte[] encryptBlock(byte[] key, byte[] block);

    byte[] decryptBlock(byte[] key, byte[] block);
}
