package ktu.guvenlihaberlesme.crypto.kex;

import java.security.GeneralSecurityException;
import javax.crypto.SecretKey;

/**
 * AES-128 oturum anahtarını iki taraf arasında paylaşan yöntem.
 *
 * <p>Dört yöntem de aynı iki mesajlık akışa oturur:
 * <ol>
 *   <li>Sunucu {@link #startServer()} ile anahtar üretir, {@link ServerSide#publicMessage()} gönderir.</li>
 *   <li>İstemci {@link #respond(byte[])} ile yanıt ve AES anahtarını üretir, yanıtı gönderir.</li>
 *   <li>Sunucu {@link ServerSide#complete(byte[])} ile aynı AES anahtarına ulaşır.</li>
 * </ol>
 *
 * <p>Sunucu her istemci için ayrı bir {@link ServerSide} başlatır. Ağdan gelen mesaj bozuksa
 * {@link GeneralSecurityException} fırlatılır.
 */
public interface KeyExchange {

    String name();

    ServerSide startServer() throws GeneralSecurityException;

    ClientResult respond(byte[] serverMessage) throws GeneralSecurityException;

    interface ServerSide {
        byte[] publicMessage();

        SecretKey complete(byte[] clientMessage) throws GeneralSecurityException;
    }

    record ClientResult(byte[] replyMessage, SecretKey aesKey) {
    }
}
