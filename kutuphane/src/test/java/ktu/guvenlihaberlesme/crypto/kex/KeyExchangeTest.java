package ktu.guvenlihaberlesme.crypto.kex;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

class KeyExchangeTest {

    @ParameterizedTest
    @EnumSource(KexMethod.class)
    void bothSidesReachSameAes128Key(KexMethod method) throws Exception {
        KeyExchange kex = method.create();
        KeyExchange.ServerSide server = kex.startServer();
        KeyExchange.ClientResult client = kex.respond(server.publicMessage());
        SecretKey serverKey = server.complete(client.replyMessage());

        assertEquals("AES", serverKey.getAlgorithm());
        assertEquals(16, serverKey.getEncoded().length);
        assertArrayEquals(client.aesKey().getEncoded(), serverKey.getEncoded());

        // Üretilen anahtar JCA AES ile kullanılabilmeli.
        byte[] plain = "merhaba".getBytes(StandardCharsets.UTF_8);
        byte[] iv = new byte[12];
        Cipher enc = Cipher.getInstance("AES/GCM/NoPadding");
        enc.init(Cipher.ENCRYPT_MODE, client.aesKey(), new GCMParameterSpec(128, iv));
        byte[] sealed = enc.doFinal(plain);
        Cipher dec = Cipher.getInstance("AES/GCM/NoPadding");
        dec.init(Cipher.DECRYPT_MODE, serverKey, new GCMParameterSpec(128, iv));
        assertArrayEquals(plain, dec.doFinal(sealed));
    }

    @ParameterizedTest
    @EnumSource(KexMethod.class)
    void eachSessionGetsDifferentKey(KexMethod method) throws Exception {
        KeyExchange kex = method.create();
        byte[] first = kex.respond(kex.startServer().publicMessage()).aesKey().getEncoded();
        byte[] second = kex.respond(kex.startServer().publicMessage()).aesKey().getEncoded();
        assertFalse(Arrays.equals(first, second));
    }

    @ParameterizedTest
    @EnumSource(KexMethod.class)
    void malformedMessagesAreRejected(KexMethod method) throws Exception {
        KeyExchange kex = method.create();
        KeyExchange.ServerSide server = kex.startServer();
        byte[] garbage = new byte[7];
        assertThrows(GeneralSecurityException.class, () -> kex.respond(garbage));
        assertThrows(GeneralSecurityException.class, () -> server.complete(garbage));
    }

    @Test
    void mlKemMessagesMatchFips203Sizes() throws Exception {
        KeyExchange kex = KexMethod.ML_KEM_768.create();
        KeyExchange.ServerSide server = kex.startServer();
        KeyExchange.ClientResult client = kex.respond(server.publicMessage());
        assertEquals(1184, server.publicMessage().length);
        assertEquals(1088, client.replyMessage().length);
    }

    @Test
    void tamperedMlKemCiphertextGivesDifferentKey() throws Exception {
        KeyExchange kex = KexMethod.ML_KEM_768.create();
        KeyExchange.ServerSide server = kex.startServer();
        KeyExchange.ClientResult client = kex.respond(server.publicMessage());
        byte[] tampered = client.replyMessage().clone();
        tampered[0] ^= 1;
        assertFalse(Arrays.equals(client.aesKey().getEncoded(), server.complete(tampered).getEncoded()));
    }
}
