package ktu.guvenlihaberlesme.crypto.kex;

import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.interfaces.DHPublicKey;

/** Diffie-Hellman 2048 bit. */
final class DhKeyExchange extends AgreementKeyExchange {

    DhKeyExchange() {
        super("DH", "DH");
    }

    @Override
    public String name() {
        return "DH-2048";
    }

    @Override
    void initializeServer(KeyPairGenerator generator) {
        generator.initialize(2048);
    }

    @Override
    AlgorithmParameterSpec parametersOf(PublicKey key) {
        return ((DHPublicKey) key).getParams();
    }
}
