package ktu.guvenlihaberlesme.crypto.kex;

import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.SecureRandom;
import javax.crypto.SecretKey;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.generators.MLKEMKeyPairGenerator;
import org.bouncycastle.crypto.kems.MLKEMExtractor;
import org.bouncycastle.crypto.kems.MLKEMGenerator;
import org.bouncycastle.crypto.params.MLKEMKeyGenerationParameters;
import org.bouncycastle.crypto.params.MLKEMParameters;
import org.bouncycastle.crypto.params.MLKEMPrivateKeyParameters;
import org.bouncycastle.crypto.params.MLKEMPublicKeyParameters;

/** Sunucu açık anahtar gönderir, istemci kapsüller, sunucu açar (Bouncy Castle, FIPS 203). */
final class MlKemKeyExchange implements KeyExchange {

    /** FIPS 203'e göre ML-KEM-768 açık anahtar ve şifreli metin boyları. */
    static final int PUBLIC_KEY_BYTES = 1184;
    static final int CIPHERTEXT_BYTES = 1088;

    private final SecureRandom random = new SecureRandom();

    @Override
    public String name() {
        return "ML-KEM-768";
    }

    @Override
    public ServerSide startServer() {
        MLKEMKeyPairGenerator generator = new MLKEMKeyPairGenerator();
        generator.init(new MLKEMKeyGenerationParameters(random, MLKEMParameters.ml_kem_768));
        AsymmetricCipherKeyPair pair = generator.generateKeyPair();
        MLKEMPublicKeyParameters publicKey = (MLKEMPublicKeyParameters) pair.getPublic();
        MLKEMPrivateKeyParameters privateKey = (MLKEMPrivateKeyParameters) pair.getPrivate();
        return new ServerSide() {
            @Override
            public byte[] publicMessage() {
                return publicKey.getEncoded();
            }

            @Override
            public SecretKey complete(byte[] clientMessage) throws GeneralSecurityException {
                requireLength(clientMessage, CIPHERTEXT_BYTES, "şifreli metin");
                byte[] secret = new MLKEMExtractor(privateKey).extractSecret(clientMessage);
                return SessionKeys.fromSharedSecret(secret);
            }
        };
    }

    @Override
    public ClientResult respond(byte[] serverMessage) throws GeneralSecurityException {
        requireLength(serverMessage, PUBLIC_KEY_BYTES, "açık anahtar");
        MLKEMPublicKeyParameters serverKey =
                new MLKEMPublicKeyParameters(MLKEMParameters.ml_kem_768, serverMessage);
        SecretWithEncapsulation encapsulated = new MLKEMGenerator(random).generateEncapsulated(serverKey);
        return new ClientResult(
                encapsulated.getEncapsulation(), SessionKeys.fromSharedSecret(encapsulated.getSecret()));
    }

    private static void requireLength(byte[] message, int expected, String label) throws InvalidKeyException {
        if (message.length != expected) {
            throw new InvalidKeyException("ML-KEM-768 " + label + " boyu " + expected
                    + " olmalı, gelen: " + message.length);
        }
    }
}
