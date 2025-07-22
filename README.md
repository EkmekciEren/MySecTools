# MySecTools 🔒

Gelişmiş Siber Güvenlik Analiz Platformu - AI destekli, çoklu kaynak, gerçek zamanlı güvenlik analizi

## 🚀 Özellikler

- **AI Destekli Analiz**: OpenAI GPT-4o ile kapsamlı risk değerlendirmesi
- **Çoklu Güvenlik Kaynağı**: URLScan.io, VirusTotal, AbuseIPDB entegrasyonu
- **Görsel Raporlama**: Chart.js ile interaktif grafikler ve göstergeler
- **Kapsamlı Export**: PDF, Excel, JSON formatında detaylı raporlar
- **Modern UI**: Minimal ve responsive tasarım
- **Gerçek Zamanlı**: Anlık güvenlik durumu analizi
- **💻 CLI Desteği**: Komut satırı arayüzü ile Linux/macOS otomasyonu
- **🤖 Akıllı Hata Yönetimi**: AI quota aşımı durumunda otomatik kural tabanlı analiz
- **🎯 Flexible Analysis**: `--no-ai` parametresi ile sadece API tabanlı analiz

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
├── cli.py                 # 💻 Komut satırı arayüzü (CLI)
├── secapp                 # 🚀 CLI launcher script
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
git clone https://github.com/EkmekciEren/MySecTools.git
cd MySecTools
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
PORT=5000
```

### 5. Uygulamayı Başlatın

#### Web Arayüzü
```bash
python app.py
```
Uygulama `http://localhost:5001` adresinde çalışacaktır.

#### CLI Kullanımı
```bash
# CLI'yi çalıştırılabilir yapın (sadece ilk seferde)
chmod +x secapp

# Hemen analiz başlatın
./secapp google.com -v
```

## 💻 CLI Kullanımı

SecApp, web arayüzüne ek olarak güçlü bir komut satırı arayüzü (CLI) sunar. Bu özellik özellikle Linux kullanıcıları, sistem yöneticileri ve otomasyonlar için idealdir.

### CLI Kurulumu
CLI, ana kurulum ile birlikte otomatik olarak hazır hale gelir. Kurulum sonrası hemen kullanabilirsiniz.

### Temel Kullanım

#### Tek Hedef Analizi
```bash
# Domain analizi
./secapp google.com

# URL analizi  
./secapp https://example.com

# IP analizi
./secapp 8.8.8.8

# Detaylı analiz (verbose)
./secapp google.com -v
```

#### Batch (Toplu) Analiz
```bash
# Hedef listesi dosyası oluşturun (targets.txt)
echo -e "google.com\nmicrosoft.com\ngithub.com" > targets.txt

# Toplu analiz çalıştırın
./secapp -b targets.txt

# Detaylı toplu analiz
./secapp -b targets.txt -v

# Sonuçları dosyaya kaydedin
./secapp -b targets.txt -o json -d reports/
```

#### Rapor Export
```bash
# JSON raporu
./secapp google.com -o json -f google_report.json

# Text raporu
./secapp google.com -o txt -f google_report.txt

# Batch analiz raporları
./secapp -b targets.txt -o json -d ./reports/
```

#### AI Devre Dışı Mod
```bash
# Sadece API tabanlı analiz (AI olmadan)
./secapp google.com --no-ai -v

# Hızlı toplu analiz (AI olmadan)
./secapp -b targets.txt --no-ai -o json -d reports/
```

#### Hata Durumları ve Fallback
```bash
# AI quota aşımı durumunda otomatik kural tabanlı analiz
./secapp microsoft.com -v
# ⚠️ AI analiz yapılamadı: OpenAI API kotası aşıldı. Kural tabanlı analiz uygulanıyor...

# API anahtarı eksik durumunda uyarı
./secapp google.com --no-ai -v  
# ⚠️ AI analiz yapılamadı: API anahtarı yapılandırılmamış. Kural tabanlı analiz uygulanıyor...
```

#### İnteraktif Mod
```bash
# İnteraktif terminal başlatın
./secapp --interactive

# Terminal içinde komutlar:
SecApp> google.com           # Analiz yap
SecApp> help                 # Yardım göster
SecApp> quit                 # Çıkış yap
```

### CLI Özellikleri

- **🎨 Renkli Çıktı**: Terminal desteği ile renkli ve okunabilir sonuçlar
- **📊 Progress Tracking**: Batch analizlerde ilerleme göstergesi
- **🔄 Paralel İşleme**: Çoklu hedef analizlerde hız optimizasyonu
- **📁 Otomatik Raporlama**: JSON/TXT formatında otomatik rapor üretimi
- **⚡ Hızlı Analiz**: Web arayüzü olmadan doğrudan analiz
- **🔧 Automation Ready**: Script ve CI/CD entegrasyonu için ideal
- **🤖 Akıllı Fallback**: AI hatalarında otomatik kural tabanlı analiz
- **⚙️ Flexible Mode**: `--no-ai` parametresi ile AI'sız hızlı analiz

### CLI Komut Referansı

```bash
usage: secapp [-h] [-v] [-b FILE] [-o {json,txt}] [-f FILE] [-d DIR] [--interactive] [--no-ai] [--version] [target]

Argümanlar:
  target                    Analiz edilecek hedef (URL, domain, IP)
  -v, --verbose            Detaylı analiz sonuçları göster
  -b, --batch FILE         Hedef listesi dosyası (satır başına bir hedef)
  -o, --output-format      Çıktı formatı (json/txt)
  -f, --output-file FILE   Tek analiz için çıktı dosyası
  -d, --output-dir DIR     Batch analiz için çıktı klasörü
  --interactive            İnteraktif mod
  --no-ai                  AI analizini devre dışı bırak (sadece API analizi)
  --version                Versiyon bilgisi
  --help                   Yardım mesajı
```

### Linux/Unix Integration

CLI'yi sistem genelinde kullanmak için:

```bash
# Sistem PATH'ine ekleyin
sudo ln -s /path/to/SecApp/secapp /usr/local/bin/secapp

# Artık her yerden çalıştırabilirsiniz
secapp google.com
```

#### Örnek Kullanım Senaryoları

##### Günlük Güvenlik Kontrolü
```bash
#!/bin/bash
# daily_security_check.sh

echo "$(date): Günlük güvenlik kontrolü başlıyor..."
./secapp -b company_domains.txt -v -o json -d daily_reports/
echo "Kontrol tamamlandı. Raporlar daily_reports/ klasöründe."
```

##### CI/CD Pipeline Entegrasyonu
```bash
# .github/workflows/security_check.yml
- name: Security Analysis
  run: |
    ./secapp -b deploy_targets.txt --no-ai -o json -f security_report.json
    if grep -q "CRITICAL\|HIGH" security_report.json; then
      echo "Security issues found!"
      exit 1
    fi
```

##### Hızlı API-Only Batch Analiz
```bash
# AI olmadan hızlı toplu analiz (quota tasarrufu)
./secapp -b large_target_list.txt --no-ai -o json -d batch_results/

# Sonuçları analiz et
grep -r "CRITICAL\|HIGH" batch_results/ | wc -l
```

##### Log Analysis with Grep
```bash
# Kritik riskleri filtrele
./secapp -b targets.txt -v | grep -E "(CRITICAL|HIGH|ERROR)"

# Başarılı analizleri say
./secapp -b targets.txt | grep -c "✅"

# AI hatalarını takip et
./secapp -b targets.txt -v 2>&1 | grep "⚠️ AI analiz"
```

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
curl "http://localhost:5001/analyze?target=https://example.com"

# Domain analizi  
curl "http://localhost:5001/analyze?target=example.com"

# IP analizi
curl "http://localhost:5001/analyze?target=8.8.8.8"
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
curl "http://localhost:5001/analyze?target=google.com"

# CLI ile test
./secapp google.com -v

# AI olmadan hızlı test
./secapp google.com --no-ai
```

## ⚙️ Konfigürasyon

### Çevre Değişkenleri
- `DEBUG`: Geliştirme modu (True/False)
- `PORT`: Uygulama portu (varsayılan: 5001)
- `AI_MODEL`: Kullanılacak AI modeli (varsayılan: gpt-4o)
- `AI_MAX_TOKENS`: Maksimum AI yanıt uzunluğu (varsayılan: 2000)
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
- `--no-ai` parametresi ile API-only analiz deneyebilirsiniz

**CLI çalışmıyor**
- `chmod +x secapp` komutu ile çalıştırma izni verin
- Python sanal ortamının aktif olduğundan emin olun
- `./secapp --help` ile parametreleri kontrol edin

**"⚠️ AI analiz yapılamadı" mesajı**
- Bu normal bir durumdur, kural tabanlı analiz devam eder
- OpenAI quota'nızı kontrol edin
- `--no-ai` parametresi ile sadece API analizi yapabilirsiniz

### Debug Modu
Geliştirme sırasında debug modunu açın:
```bash
export DEBUG=True
python app.py
```

## 📞 İletişim

**Geliştirici:** Eren Ekmekci

- 📧 **E-posta:** [erenekmekci500@gmail.com](mailto:erenekmekci500@gmail.com)
- 🌐 **Portfolio:** [erenekmekci.com.tr](https://erenekmekci.com.tr)
- 💼 **LinkedIn:** [eren-ekmekci](https://www.linkedin.com/in/eren-ekmekci-9706391a5/)
- 🐙 **GitHub:** [EkmekciEren](https://github.com/EkmekciEren)
- 📋 **Issues:** [MySecTools Issues](https://github.com/EkmekciEren/MySecTools/issues)

Sorularınız için issue açabilir veya doğrudan e-posta gönderebilirsiniz. Feature request'ler ve bug report'lar memnuniyetle karşılanır!

---

⭐ **Bu projeyi beğendiyseniz yıldız vermeyi unutmayın!** ⭐
