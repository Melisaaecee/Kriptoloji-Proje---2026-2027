package ktu.guvenlihaberlesme.crypto.kex;

import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;

/** İstemci rastgele AES anahtarı üretir, sunucunun RSA-2048 açık anahtarıyla (OAEP) şifreleyip gönderir. */
final class RsaKeyExchange implements KeyExchange {

    private static final String TRANSFORMATION = "RSA/ECB/OAEPPadding";
    private static final OAEPParameterSpec OAEP = new OAEPParameterSpec(
            "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);

    @Override
    public String name() {
        return "RSA-2048";
    }

    @Override
    public ServerSide startServer() throws GeneralSecurityException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();
        return new ServerSide() {
            @Override
            public byte[] publicMessage() {
                return pair.getPublic().getEncoded();
            }

            @Override
            public SecretKey complete(byte[] clientMessage) throws GeneralSecurityException {
                Cipher cipher = Cipher.getInstance(TRANSFORMATION);
                cipher.init(Cipher.DECRYPT_MODE, pair.getPrivate(), OAEP);
                byte[] keyBytes = cipher.doFinal(clientMessage);
                if (keyBytes.length != SessionKeys.AES_KEY_BYTES) {
                    throw new InvalidKeyException("Beklenmeyen AES anahtar boyu: " + keyBytes.length);
                }
                return new SecretKeySpec(keyBytes, "AES");
            }
        };
    }

    @Override
    public ClientResult respond(byte[] serverMessage) throws GeneralSecurityException {
        PublicKey serverKey = KeyFactory.getInstance("RSA")
                .generatePublic(new X509EncodedKeySpec(serverMessage));
        KeyGenerator aes = KeyGenerator.getInstance("AES");
        aes.init(SessionKeys.AES_KEY_BYTES * 8);
        SecretKey aesKey = aes.generateKey();

        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, serverKey, OAEP);
        return new ClientResult(cipher.doFinal(aesKey.getEncoded()), aesKey);
    }
}
