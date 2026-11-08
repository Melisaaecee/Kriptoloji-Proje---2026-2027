package ktu.guvenlihaberlesme.crypto.kex;

import java.security.GeneralSecurityException;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;

/** ECDH, NIST P-256 (secp256r1) eğrisi üzerinde. */
final class EcdhKeyExchange extends AgreementKeyExchange {

    EcdhKeyExchange() {
        super("EC", "ECDH");
    }

    @Override
    public String name() {
        return "ECDH-P256";
    }

    @Override
    void initializeServer(KeyPairGenerator generator) throws GeneralSecurityException {
        generator.initialize(new ECGenParameterSpec("secp256r1"));
    }

    @Override
    AlgorithmParameterSpec parametersOf(PublicKey key) {
        return ((ECPublicKey) key).getParams();
    }
}
