# 🚀 SecApp Changelog

## v1.2.0 - Rate Limiting & Cache System (22 Temmuz 2025)

### 🆕 Yeni Özellikler

- **🔄 Akıllı Cache Sistemi**: Analiz sonuçlarını cache'leyerek API quota tasarrufu
- **⚡ Rate Limiting & Retry**: Exponential backoff ile 429 hatalarını önleme
- **🧠 Konservatif AI Modu**: Düşük riskli hedefler için kural tabanlı analiz
- **📊 Cache Yönetimi**: Web arayüzü ve CLI ile cache istatistikleri ve temizleme
- **🔧 Gelişmiş Hata Yönetimi**: AI quota aşımı durumunda graceful fallback

### 🛠️ Teknik İyileştirmeler

- **Exponential Backoff**: API çağrıları arasında artan bekleme süreleri
- **Request Timeout**: Yapılandırılabilir zaman aşımı ayarları
- **Threat Level Assessment**: Risk seviyesine göre AI kullanım kararı
- **Cache TTL**: Yapılandırılabilir cache yaşam süresi (varsayılan: 1 saat)

### 📝 Yeni CLI Komutları

```bash
./secapp --cache-stats        # Cache istatistikleri
./secapp --cache-clear        # Cache temizleme
./secapp target --no-ai       # Sadece API tabanlı analiz
```

### 🌐 Web Arayüzü İyileştirmeleri

- Cache istatistikleri butonu (Ayarlar > Cache İstatistikleri)
- Cache temizleme butonu (Ayarlar > Cache Temizle)
- Gelişmiş buton stilleri (info, warning)
- Real-time cache durumu gösterimi

### ⚙️ Konfigürasyon Eklentileri

`.env` dosyasına yeni parametreler:

```env
# Rate Limiting
AI_MAX_RETRIES=3
AI_BASE_DELAY=1.0
AI_MAX_DELAY=30.0
AI_REQUEST_TIMEOUT=30.0
AI_CONSERVATIVE_MODE=true
AI_CACHE_TTL=3600
```

### 🐛 Çözülen Sorunlar

- ✅ OpenAI API 429 hatasının uygulamayı durdurması
- ✅ Aynı hedeflerin tekrar tekrar AI analizi yapması
- ✅ Rate limit aşımında veri kaybı
- ✅ Kullanıcı dostu hata mesajlarının eksikliği

### 🔄 Geriye Uyumluluk

- Mevcut `.env` ayarları korunur
- Eski API endpoint'leri çalışmaya devam eder
- Cache sistemi opsiyoneldir ve otomatik çalışır

### 📈 Performans İyileştirmeleri

- %70'e varan API çağrısı azalması (cache sayesinde)
- Daha hızlı yanıt süreleri (cache'den sunulan sonuçlar)
- Düşük riskli hedefler için anında sonuç

---

## v1.1.0 - Initial Release (Önceki versiyon)

### 🚀 Ana Özellikler

- AI destekli güvenlik analizi (OpenAI GPT-4o)
- Çoklu güvenlik kaynağı entegrasyonu
- Web ve CLI arayüzleri
- PDF/Excel/JSON rapor exportu
- Batch analiz desteği
- İnteraktif grafikler ve göstergeler

---

## 🔮 Gelecek Planlar (v1.3.0)

- 🔍 Daha fazla güvenlik kaynağı entegrasyonu
- 🤖 Özelleştirilebilir AI promptları
- 📧 E-posta bildirimleri
- 🌍 Çoklu dil desteği
- 📱 Mobil responsive iyileştirmeleri
