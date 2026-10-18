# Güvenli Haberleşme Projesi (erken aşama)

Karadeniz Teknik Üniversitesi  
Of Teknoloji Fakültesi, Yazılım Mühendisliği Bölümü  
Bilgi Güvenliği ve Kriptoloji — Dr. Hakan AYDIN

Sunucu ve iki istemciden oluşan bir haberleşme uygulaması. İstemciler birbirine doğrudan bağlanmaz. Metin ve PDF önce sunucuya gider; sunucu diğer istemciye iletir. Çalışma en az iki bilgisayarda yürütülür: birinde sunucu, diğerinde istemciler.

Uygulama şuanki planda Java ile, Maven projesi olarak kurulur. JDK 17 kullanılır. RSA, Diffie-Hellman ve ECDH için JDK’nin kripto arayüzü, ML-KEM-768 için Bouncy Castle (`bcprov-jdk18on` 1.86) kullanılır. AES-128 blok şifresi kütüphanesiz yazılır.

## Kapsam

- Bir sunucu ve iki istemci.
- Klavyeden metin ve klasörden PDF gönderimi.
- Güvensiz modda içerik şifrelenmeden iletilir. Wireshark kaydında içerik açık görülür.
- Güvenli modda önce istemci ile sunucu arasında bir AES-128 anahtarı kurulur. Metin ve dosya parçaları bu anahtarla şifrelenir. Sunucu gelen veriyi çözer, ekrana yazar, dosyaysa kaydeder ve diğer istemcinin anahtarıyla yeniden şifreleyerek iletir.
- RSA-2048, Diffie-Hellman (2048 bit), ECDH ve ML-KEM-768, veriyi şifrelemek için değil AES anahtarını iki taraf arasında paylaşmak için kullanılır. Yöntem, program açılışında seçilir.
- Her yöntem için anahtar üretme süresi, anahtar değişim süresi ve anahtar değişimi sırasında ağa giden boyut ölçülür. Tabloda on ölçümün ortalaması yer alır.
- AES-128; tur yapısı, S-box ve permütasyonlarla kütüphanesiz kodlanır. Aynı girdi, kütüphane çıktısıyla karşılaştırılır.
- Wireshark kayıtları sunucu tarafında ve istemci tarafında alınır. Her mod için en az bir `.pcapng` dosyası bulunur.

## Proje düzeni

```text
proje/
├── pom.xml
├── README.md
├── src/main/java/ktu/guvenlihaberlesme/
│   ├── protocol/
│   ├── server/
│   ├── client/
│   └── crypto/
│       ├── aes/
│       └── kex/
├── src/test/java/ktu/guvenlihaberlesme/crypto/aes/
├── olcum/
├── captures/
└── rapor/
```

| Bölüm | İçerik |
|---|---|
| `protocol` | Mesaj türü ve çerçeve |
| `server` | İki istemci, çözme, ekrana yazma, dosya kaydı, yeniden şifreleyip iletme |
| `client` | Metin, PDF seçimi, güvensiz ve güvenli gönderim |
| `crypto/aes` | Kütüphanesiz AES-128 ve kütüphane karşılaştırması |
| `crypto/kex` | RSA-2048, Diffie-Hellman, ECDH, ML-KEM-768 |
| `olcum` | Ölçüm kayıtları |
| `captures` | Wireshark kayıtları |
| `rapor` | Teknik rapor |

## Çalıştırma

Sunucu bir bilgisayarda, istemciler diğer bilgisayarda açılır. İstemci, bağlanacağı adres ve anahtar yöntemini başlangıçta alır. Güvenli modda anahtar kurulumu tamamlandıktan sonra metin ve PDF gönderilir.
