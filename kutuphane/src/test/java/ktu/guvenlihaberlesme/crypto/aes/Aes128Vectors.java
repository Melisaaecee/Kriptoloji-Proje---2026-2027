package ktu.guvenlihaberlesme.crypto.aes;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import java.util.HexFormat;

/** FIPS 197, Ek C.1 test vektörü. */
final class Aes128Vectors {

    static final String KEY = "000102030405060708090a0b0c0d0e0f";
    static final String PLAINTEXT = "00112233445566778899aabbccddeeff";
    static final String CIPHERTEXT = "69c4e0d86a7b0430d8cdb78070b4c55a";

    private Aes128Vectors() {
    }

    static void assertMatchesFips197(Aes128BlockCipher aes) {
        HexFormat hex = HexFormat.of();
        byte[] key = hex.parseHex(KEY);
        assertArrayEquals(hex.parseHex(CIPHERTEXT), aes.encryptBlock(key, hex.parseHex(PLAINTEXT)));
        assertArrayEquals(hex.parseHex(PLAINTEXT), aes.decryptBlock(key, hex.parseHex(CIPHERTEXT)));
    }
}
