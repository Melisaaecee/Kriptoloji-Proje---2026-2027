package ktu.guvenlihaberlesme.crypto.kex;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;

/**
 * DH ve ECDH ortak akışı: taraflar açık değerlerini değiştirir, ortak sırrı kendileri hesaplar.
 * İstemci, grubu sunucunun açık anahtarındaki parametrelerden alır.
 */
abstract class AgreementKeyExchange implements KeyExchange {

    private final String keyAlgorithm;
    private final String agreementAlgorithm;

    AgreementKeyExchange(String keyAlgorithm, String agreementAlgorithm) {
        this.keyAlgorithm = keyAlgorithm;
        this.agreementAlgorithm = agreementAlgorithm;
    }

    abstract void initializeServer(KeyPairGenerator generator) throws GeneralSecurityException;

    abstract AlgorithmParameterSpec parametersOf(PublicKey key);

    @Override
    public ServerSide startServer() throws GeneralSecurityException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(keyAlgorithm);
        initializeServer(generator);
        KeyPair pair = generator.generateKeyPair();
        return new ServerSide() {
            @Override
            public byte[] publicMessage() {
                return pair.getPublic().getEncoded();
            }

            @Override
            public SecretKey complete(byte[] clientMessage) throws GeneralSecurityException {
                return derive(pair.getPrivate(), decode(clientMessage));
            }
        };
    }

    @Override
    public ClientResult respond(byte[] serverMessage) throws GeneralSecurityException {
        PublicKey serverKey = decode(serverMessage);
        KeyPairGenerator generator = KeyPairGenerator.getInstance(keyAlgorithm);
        generator.initialize(parametersOf(serverKey));
        KeyPair pair = generator.generateKeyPair();
        return new ClientResult(pair.getPublic().getEncoded(), derive(pair.getPrivate(), serverKey));
    }

    private PublicKey decode(byte[] encoded) throws GeneralSecurityException {
        return KeyFactory.getInstance(keyAlgorithm).generatePublic(new X509EncodedKeySpec(encoded));
    }

    private SecretKey derive(PrivateKey own, PublicKey other) throws GeneralSecurityException {
        KeyAgreement agreement = KeyAgreement.getInstance(agreementAlgorithm);
        agreement.init(own);
        agreement.doPhase(other, true);
        return SessionKeys.fromSharedSecret(agreement.generateSecret());
    }
}
