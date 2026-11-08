package ktu.guvenlihaberlesme.crypto.kex;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import javax.crypto.SecretKey;

/**
 * Rapordaki tablo için her yöntemi tek süreçte ölçer: 10 ölçümün ortalaması.
 *
 * <p>keygen_ms sunucu anahtar üretimi, exchange_ms istemci yanıtı ile sunucu tamamlamanın toplamıdır;
 * ağ gecikmesi dahil değildir. wire_bytes iki mesajın yük boyudur; TCP ve çerçeve başlıkları dahil değildir.
 *
 * <p>Kullanım: {@code KexBenchmark [csv-dosyası]}
 */
public final class KexBenchmark {

    private static final int ROUNDS = 10;
    /** JIT ısınması sonuçları bozmasın diye sayılmayan turlar. */
    private static final int WARMUP_ROUNDS = 5;

    private KexBenchmark() {
    }

    private record Result(String name, double keygenMs, double exchangeMs, int wireBytes) {
    }

    private record Sample(long keygenNanos, long exchangeNanos, int wireBytes) {
    }

    public static void main(String[] args) throws GeneralSecurityException, IOException {
        List<String> csv = new ArrayList<>();
        csv.add("method,keygen_ms,exchange_ms,wire_bytes");
        System.out.printf("%-12s %12s %12s %11s%n", "method", "keygen_ms", "exchange_ms", "wire_bytes");
        for (KexMethod method : KexMethod.values()) {
            Result r = measure(method.create());
            System.out.printf(Locale.ROOT, "%-12s %12.3f %12.3f %11d%n",
                    r.name(), r.keygenMs(), r.exchangeMs(), r.wireBytes());
            csv.add(String.format(Locale.ROOT, "%s,%.3f,%.3f,%d",
                    r.name(), r.keygenMs(), r.exchangeMs(), r.wireBytes()));
        }
        if (args.length > 0) {
            Path out = Path.of(args[0]);
            if (out.getParent() != null) {
                Files.createDirectories(out.getParent());
            }
            Files.write(out, csv, StandardCharsets.UTF_8);
        }
    }

    private static Result measure(KeyExchange kex) throws GeneralSecurityException {
        for (int i = 0; i < WARMUP_ROUNDS; i++) {
            sample(kex);
        }
        long keygenTotal = 0;
        long exchangeTotal = 0;
        int wireBytes = 0;
        for (int i = 0; i < ROUNDS; i++) {
            Sample s = sample(kex);
            keygenTotal += s.keygenNanos();
            exchangeTotal += s.exchangeNanos();
            wireBytes += s.wireBytes();
        }
        return new Result(kex.name(), keygenTotal / 1e6 / ROUNDS, exchangeTotal / 1e6 / ROUNDS, wireBytes / ROUNDS);
    }

    private static Sample sample(KeyExchange kex) throws GeneralSecurityException {
        long start = System.nanoTime();
        KeyExchange.ServerSide server = kex.startServer();
        long generated = System.nanoTime();

        byte[] serverMessage = server.publicMessage();
        KeyExchange.ClientResult client = kex.respond(serverMessage);
        SecretKey serverKey = server.complete(client.replyMessage());
        long finished = System.nanoTime();

        if (!MessageDigest.isEqual(serverKey.getEncoded(), client.aesKey().getEncoded())) {
            throw new IllegalStateException(kex.name() + ": taraflar farklı anahtara ulaştı");
        }
        return new Sample(generated - start, finished - generated,
                serverMessage.length + client.replyMessage().length);
    }
}
