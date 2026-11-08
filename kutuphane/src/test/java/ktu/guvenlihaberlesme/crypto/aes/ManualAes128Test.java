package ktu.guvenlihaberlesme.crypto.aes;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import java.security.SecureRandom;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

@Disabled("ManualAes128 yazılınca kaldırılacak")
class ManualAes128Test {

    @Test
    void matchesFips197Vector() {
        Aes128Vectors.assertMatchesFips197(new ManualAes128());
    }

    @Test
    void matchesJdkForRandomInputs() {
        SecureRandom random = new SecureRandom();
        Aes128BlockCipher manual = new ManualAes128();
        Aes128BlockCipher jdk = new JdkAes128();
        for (int i = 0; i < 1000; i++) {
            byte[] key = new byte[Aes128BlockCipher.KEY_BYTES];
            byte[] block = new byte[Aes128BlockCipher.BLOCK_BYTES];
            random.nextBytes(key);
            random.nextBytes(block);
            assertArrayEquals(jdk.encryptBlock(key, block), manual.encryptBlock(key, block));
            assertArrayEquals(jdk.decryptBlock(key, block), manual.decryptBlock(key, block));
        }
    }
}
