# kutuphane

Sorumlu: _(isim)_ — branch: `kutuphane`

- Anahtar dağıtım yöntemleri: RSA-2048, Diffie-Hellman 2048, ECDH (JDK), ML-KEM-768 (Bouncy Castle)
- Her yöntem için ölçüm: anahtar üretme süresi, anahtar değişim süresi, ağa giden byte (10 ölçüm ortalaması)
- Kütüphanesiz AES-128 (round yapısı, S-box, permütasyonlar) ve aynı girdi için kütüphane çıktısıyla karşılaştırma

## Kurulum ve çalıştırma

Gereken tek şey JDK 17. Maven kurmak gerekmez, depo kökündeki `mvnw` onu kendisi indirir. Komutlar depo kökünde çalıştırılır (PowerShell'de `./mvnw` yerine `.\mvnw.cmd`).

```bash
./mvnw verify
```

```bash
./mvnw -q -pl kutuphane compile exec:java
```

İlki derler ve testleri çalıştırır, ikincisi ölçüm tablosunu yazar. Sonucu dosyaya almak için ikinci komuta `-Dexec.args=olcum/kex.csv` eklenir; dosya depo kökündeki `olcum/` klasörüne yazılır.

## Sürümler

| Bileşen | Sürüm |
|---|---|
| JDK | 17 |
| Bouncy Castle (`bcprov-jdk18on`) | 1.86 |
| JUnit | 6.1.3 (yalnızca test) |

## Sunucu ve istemciden kullanım

Yöntem `KexMethod` ile seçilir, akış dört yöntemde de aynıdır:

```java
KeyExchange kex = KexMethod.ML_KEM_768.create();

// Sunucu: her istemci için ayrı başlatılır
KeyExchange.ServerSide server = kex.startServer();
byte[] toClient = server.publicMessage();            // istemciye gönder

// İstemci
KeyExchange.ClientResult result = kex.respond(toClient);
byte[] toServer = result.replyMessage();             // sunucuya gönder
SecretKey clientKey = result.aesKey();

// Sunucu
SecretKey serverKey = server.complete(toServer);     // clientKey ile aynı anahtar
```

## Durum ve sınırlar

- `ManualAes128` henüz yazılmadı. Bitince `ManualAes128Test` üzerindeki `@Disabled` kaldırılır; test FIPS 197 vektörüyle ve rastgele girdilerle JDK çıktısına karşı doğrular.
- `KexBenchmark` tek süreçte ölçer: `exchange_ms` ağ gecikmesini, `wire_bytes` TCP ve çerçeve başlıklarını içermez.
- DH'de `keygen_ms` yalnızca anahtar çiftini kapsar; JDK 2048 bit için hazır grup kullanır, parametre üretmez.
- Anahtar değişimlerinde kimlik doğrulama yoktur. Ağdaki aktif bir saldırgan ortadaki adam saldırısı yapabilir; ödev kapsamı bunu istemez ama raporda belirtilmelidir.
