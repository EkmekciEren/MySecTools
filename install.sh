#!/bin/bash

# Siber Güvenlik Analiz Uygulaması - Kurulum Scripti

echo "🔒 Siber Güvenlik Analiz Uygulaması Kurulumu Başlatılıyor..."

# Renk kodları
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Python sürümünü kontrol et
echo -e "\n${BLUE}Python sürümü kontrol ediliyor...${NC}"
python3 --version
if [ $? -ne 0 ]; then
    echo -e "${RED}❌ Python 3 bulunamadı. Lütfen Python 3.7+ yükleyin.${NC}"
    exit 1
fi

# Sanal ortam oluştur
echo -e "\n${BLUE}Sanal ortam oluşturuluyor...${NC}"
python3 -m venv venv
if [ $? -ne 0 ]; then
    echo -e "${RED}❌ Sanal ortam oluşturulamadı.${NC}"
    exit 1
fi

# Sanal ortamı aktifleştir
echo -e "${BLUE}Sanal ortam aktifleştiriliyor...${NC}"
source venv/bin/activate

# Pip'i güncelle
echo -e "\n${BLUE}Pip güncelleniyor...${NC}"
pip install --upgrade pip

# Bağımlılıkları yükle
echo -e "\n${BLUE}Bağımlılıklar yükleniyor...${NC}"
pip install -r requirements.txt
if [ $? -ne 0 ]; then
    echo -e "${RED}❌ Bağımlılıklar yüklenemedi.${NC}"
    exit 1
fi

# .env dosyasını kontrol et
echo -e "\n${BLUE}.env dosyası kontrol ediliyor...${NC}"
if [ ! -f ".env" ]; then
    echo -e "${RED}❌ .env dosyası bulunamadı.${NC}"
    exit 1
fi

# API anahtarlarını kontrol et
echo -e "\n${YELLOW}⚠️  API Anahtarları Kontrol Ediliyor...${NC}"
API_KEYS_CONFIGURED=true

if grep -q "your_urlscan_api_key_here" .env; then
    echo -e "${YELLOW}⚠️  URLScan API anahtarı yapılandırılmamış${NC}"
    API_KEYS_CONFIGURED=false
fi

if grep -q "your_virustotal_api_key_here" .env; then
    echo -e "${YELLOW}⚠️  VirusTotal API anahtarı yapılandırılmamış${NC}"
    API_KEYS_CONFIGURED=false
fi

if grep -q "your_abuseipdb_api_key_here" .env; then
    echo -e "${YELLOW}⚠️  AbuseIPDB API anahtarı yapılandırılmamış${NC}"
    API_KEYS_CONFIGURED=false
fi

if grep -q "your_openai_api_key_here" .env; then
    echo -e "${YELLOW}⚠️  OpenAI API anahtarı yapılandırılmamış${NC}"
    API_KEYS_CONFIGURED=false
fi

if [ "$API_KEYS_CONFIGURED" = false ]; then
    echo -e "\n${YELLOW}📝 Lütfen .env dosyasındaki API anahtarlarını gerçek değerlerle değiştirin:${NC}"
    echo -e "${YELLOW}   - URLScan.io: https://urlscan.io/user/signup${NC}"
    echo -e "${YELLOW}   - VirusTotal: https://www.virustotal.com/gui/join-us${NC}"
    echo -e "${YELLOW}   - AbuseIPDB: https://www.abuseipdb.com/register${NC}"
    echo -e "${YELLOW}   - OpenAI: https://platform.openai.com/signup${NC}"
    echo -e "\n${YELLOW}API anahtarları yapılandırıldıktan sonra uygulamayı başlatabilirsiniz.${NC}"
else
    echo -e "${GREEN}✅ Tüm API anahtarları yapılandırılmış görünüyor${NC}"
fi

# Dizin yapısını kontrol et
echo -e "\n${BLUE}Proje yapısı kontrol ediliyor...${NC}"
REQUIRED_DIRS=("services" "services/api_clients" "utils" "templates")
for dir in "${REQUIRED_DIRS[@]}"; do
    if [ ! -d "$dir" ]; then
        echo -e "${RED}❌ Gerekli dizin bulunamadı: $dir${NC}"
        exit 1
    fi
done

echo -e "\n${GREEN}✅ Kurulum başarıyla tamamlandı!${NC}"

# CLI çalıştırılabilir yap
echo -e "\n${BLUE}CLI hazırlanıyor...${NC}"
chmod +x cli.py
chmod +x secapp

echo -e "\n${BLUE}🚀 Uygulamayı başlatmak için:${NC}"
echo -e "\n${GREEN}📱 Web Arayüzü:${NC}"
echo -e "${GREEN}   source venv/bin/activate${NC}"
echo -e "${GREEN}   python app.py${NC}"
echo -e "${GREEN}   Tarayıcıda: http://localhost:5000${NC}"

echo -e "\n${GREEN}💻 CLI Kullanımı:${NC}"
echo -e "${GREEN}   ./secapp google.com              # Tek analiz${NC}"
echo -e "${GREEN}   ./secapp google.com -v           # Detaylı analiz${NC}"
echo -e "${GREEN}   ./secapp -b targets.txt          # Toplu analiz${NC}"
echo -e "${GREEN}   ./secapp --interactive           # İnteraktif mod${NC}"
echo -e "${GREEN}   ./secapp --help                  # Yardım${NC}"

# Sistem bilgilerini göster
echo -e "\n${BLUE}📊 Sistem Bilgileri:${NC}"
echo -e "   Python Sürümü: $(python3 --version)"
echo -e "   Pip Sürümü: $(pip --version | cut -d' ' -f2)"
echo -e "   İşletim Sistemi: $(uname -s)"
echo -e "   Kurulum Dizini: $(pwd)"

echo -e "\n${GREEN}🎉 Kurulum tamamlandı! İyi kullanımlar!${NC}"
