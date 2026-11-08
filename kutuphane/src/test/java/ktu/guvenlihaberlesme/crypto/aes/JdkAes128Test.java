package ktu.guvenlihaberlesme.crypto.aes;

import org.junit.jupiter.api.Test;

class JdkAes128Test {

    @Test
    void matchesFips197Vector() {
        Aes128Vectors.assertMatchesFips197(new JdkAes128());
    }
}
