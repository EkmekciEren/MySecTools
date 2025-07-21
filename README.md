# MySecTools 🔒

Gelişmiş Siber Güvenlik Analiz Platformu - AI destekli, çoklu kaynak, gerçek zamanlı güvenlik analizi

## 🚀 Özellikler

- **AI Destekli Analiz**: OpenAI GPT-4o ile kapsamlı risk değerlendirmesi
- **Çoklu Güvenlik Kaynağı**: URLScan.io, VirusTotal, AbuseIPDB entegrasyonu
- **Görsel Raporlama**: Chart.js ile interaktif grafikler ve göstergeler
- **Kapsamlı Export**: PDF, Excel, JSON formatında detaylı raporlar
- **Modern UI**: Minimal ve responsive tasarım
- **Gerçek Zamanlı**: Anlık güvenlik durumu analizi

## 📊 Desteklenen Analiz Türleri

- **URL Analizi**: Web sitelerinin güvenlik durumu
- **Domain Analizi**: Domain reputasyonu ve risk seviyesi  
- **IP Analizi**: IP adreslerinin kötüye kullanım geçmişi
- **Kapsamlı Raporlama**: Turkish karakterli PDF raporları

## 🛠 Teknolojiler

- **Backend**: Python Flask
- **Frontend**: HTML5, CSS3, JavaScript
- **Görselleştirme**: Chart.js
- **PDF Generation**: ReportLab (Turkish font desteği)
- **AI Integration**: OpenAI GPT-4o
- **APIs**: URLScan.io, VirusTotal, AbuseIPDB

## 🎯 Özellikler

- **Çoklu API Entegrasyonu**: URLScan.io, VirusTotal, AbuseIPDB
- **Yapay Zeka Analizi**: OpenAI GPT ile akıllı risk değerlendirmesi  
- **Web Arayüzü**: Kullanıcı dostu web tabanlı arayüz
- **JSON Export**: Analiz sonuçlarını JSON formatında indirme
- **Paralel İşleme**: Tüm API'ler eş zamanlı olarak sorgulanır
- **Hata Yönetimi**: Güçlü hata yakalama ve kullanıcı bilgilendirmesi

## 🏗️ Mimari

```
SecApp/
├── app.py                 # Ana Flask uygulaması
├── requirements.txt       # Python bağımlılıkları
├── .env                  # API anahtarları ve konfigürasyon
├── services/             # İş mantığı katmanı
│   ├── security_analyzer.py     # Ana orkestratör
│   ├── ai_analyzer.py           # AI analiz servisi
│   └── api_clients/             # Dış API istemcileri
│       ├── urlscan_client.py
│       ├── virustotal_client.py
│       └── abuseipdb_client.py
├── utils/                # Yardımcı fonksiyonlar
│   ├── validators.py     # Girdi doğrulama
│   └── response_formatter.py   # Yanıt formatlama
└── templates/           # Web arayüzü
    └── index.html
```

## 🚀 Kurulum

### 1. Projeyi İndirin
```bash
git clone <repo-url>
cd SecApp
```

### 2. Sanal Ortam Oluşturun
```bash
python3 -m venv venv
source venv/bin/activate  # Linux/Mac
# veya
venv\\Scripts\\activate   # Windows
```

### 3. Bağımlılıkları Yükleyin
```bash
pip install -r requirements.txt
```

### 4. API Anahtarlarını Ayarlayın
`.env` dosyasındaki API anahtarlarını gerçek değerlerle değiştirin:

```env
# Gerekli API Anahtarları
URLSCAN_API_KEY=your_actual_urlscan_api_key
VIRUSTOTAL_API_KEY=your_actual_virustotal_api_key  
ABUSEIPDB_API_KEY=your_actual_abuseipdb_api_key
OPENAI_API_KEY=your_actual_openai_api_key

# Uygulama Ayarları
DEBUG=False
PORT=5002
```

### 5. Uygulamayı Başlatın
```bash
python app.py
```

Uygulama `http://localhost:5002` adresinde çalışacaktır.

## 🔑 API Anahtarları Nasıl Alınır?

### URLScan.io
1. [URLScan.io](https://urlscan.io/) hesabı oluşturun
2. API bölümünden anahtarınızı alın
3. Ücretsiz plan: 1000 tarama/ay

### VirusTotal  
1. [VirusTotal](https://www.virustotal.com/) hesabı oluşturun
2. Profil > API Key bölümünden anahtarınızı alın
3. Ücretsiz plan: 500 istek/gün

### AbuseIPDB
1. [AbuseIPDB](https://www.abuseipdb.com/) hesabı oluşturun  
2. API Key bölümünden anahtarınızı alın
3. Ücretsiz plan: 1000 istek/gün

### OpenAI
1. [OpenAI Platform](https://platform.openai.com/) hesabı oluşturun
2. API Keys bölümünden yeni anahtar oluşturun
3. Ücretli servis (kullanım bazlı)

## 📡 API Kullanımı

### Analiz Endpoint
```
GET /analyze?target=<hedef>
```

**Örnek İstekler:**
```bash
# URL analizi
curl "http://localhost:5002/analyze?target=https://example.com"

# Domain analizi  
curl "http://localhost:5002/analyze?target=example.com"

# IP analizi
curl "http://localhost:5002/analyze?target=8.8.8.8"
```

**Örnek Yanıt:**
```json
{
  "target": "example.com",
  "timestamp": "2024-01-15T10:30:00Z",
  "analysis_summary": {
    "risk_level": "LOW",
    "threats_detected": false,
    "data_sources_used": ["URLScan.io", "VirusTotal", "AbuseIPDB"],
    "confidence_score": 100.0
  },
  "urlscan_data": {...},
  "virustotal_data": {...}, 
  "abuseipdb_data": {...},
  "ai_analysis": "Bu hedef güvenli görünüyor...",
  "metadata": {...}
}
```

### Health Check
```
GET /health
```

## 🧪 Test

Uygulamayı test etmek için bilinen şüpheli URL'leri kullanabilirsiniz:

```bash
# Güvenli test
curl "http://localhost:5002/analyze?target=google.com"

# Şüpheli test (dikkatli kullanın)
curl "http://localhost:5002/analyze?target=malware-traffic-analysis.net"
```

## ⚙️ Konfigürasyon

### Çevre Değişkenleri
- `DEBUG`: Geliştirme modu (True/False)
- `PORT`: Uygulama portu (varsayılan: 5002)
- `AI_MODEL`: Kullanılacak AI modeli (varsayılan: gpt-4o)
- `AI_MAX_TOKENS`: Maksimum AI yanıt uzunluğu (varsayılan: 1000)
- `AI_TEMPERATURE`: AI yaratıcılık seviyesi (varsayılan: 0.3)

### Logging
Uygulama logları konsola yazılır. Üretim ortamında log dosyasına yönlendirilebilir:
```bash
python app.py > app.log 2>&1
```

## 🔒 Güvenlik

- API anahtarları `.env` dosyasında saklanır ve repository'ye commit edilmemelidir
- `.gitignore` dosyası hassas dosyaları otomatik olarak hariç tutar
- Girdi validasyonu zararlı içerik için kontrol yapar
- Rate limiting API sağlayıcıları tarafından uygulanır

## 🚨 Sınırlamalar

- **API Limits**: Ücretsiz planlar günlük/aylık limitlere sahiptir
- **AI Costs**: OpenAI kullanım bazlı ücretlendirir
- **Private IPs**: Özel IP adresleri analiz edilemez
- **Localhost**: Yerel adresler desteklenmez

## 🤝 Katkıda Bulunma

1. Fork yapın
2. Feature branch oluşturun (`git checkout -b feature/amazing-feature`)
3. Değişikliklerinizi commit edin (`git commit -m 'Add amazing feature'`)
4. Branch'inizi push edin (`git push origin feature/amazing-feature`)
5. Pull Request oluşturun

## 📄 Lisans

Bu proje MIT lisansı altında dağıtılmaktadır.

## 🆘 Sorun Giderme

### Yaygın Hatalar

**"API key not configured"**
- `.env` dosyasındaki API anahtarlarını kontrol edin
- Anahtarların doğru formatta olduğundan emin olun

**"Module not found" hatası**
- Sanal ortamın aktif olduğundan emin olun
- `pip install -r requirements.txt` komutunu çalıştırın

**"Connection timeout" hatası**
- İnternet bağlantınızı kontrol edin
- API servislerinin erişilebilir olduğundan emin olun

**AI analiz yapılmıyor**
- OpenAI API anahtarının geçerli olduğundan emin olun
- Kredi bakiyenizi kontrol edin

### Debug Modu
Geliştirme sırasında debug modunu açın:
```bash
export DEBUG=True
python app.py
```

## 📞 İletişim

Sorularınız için issue açabilir veya e-posta gönderebilirsiniz.
