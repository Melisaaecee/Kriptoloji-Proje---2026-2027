package ktu.guvenlihaberlesme.crypto.kex;

import java.util.function.Supplier;

/** Program açılışında seçilen anahtar dağıtım yöntemleri. */
public enum KexMethod {
    RSA_2048(RsaKeyExchange::new),
    DH_2048(DhKeyExchange::new),
    ECDH_P256(EcdhKeyExchange::new),
    ML_KEM_768(MlKemKeyExchange::new);

    private final Supplier<KeyExchange> factory;

    KexMethod(Supplier<KeyExchange> factory) {
        this.factory = factory;
    }

    public KeyExchange create() {
        return factory.get();
    }
}
