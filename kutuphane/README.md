# kutuphane

Sorumlu: _(isim)_ — branch: `kutuphane`

- Anahtar dağıtım yöntemleri: RSA-2048, Diffie-Hellman 2048, ECDH (JDK), ML-KEM-768 (Bouncy Castle)
- Her yöntem için ölçüm: anahtar üretme süresi, anahtar değişim süresi, ağa giden byte (10 ölçüm ortalaması)
- Kütüphanesiz AES-128 (round yapısı, S-box, permütasyonlar) ve aynı girdi için kütüphane çıktısıyla karşılaştırma
