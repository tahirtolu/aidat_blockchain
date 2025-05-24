# Aidat ve Bağış Takip Sistemi

Bu proje, apartman veya site gibi topluluklarda aidat ve bağış işlemlerinin blockchain teknolojisi kullanılarak güvenli ve şeffaf bir şekilde takip edilmesini sağlar.

## Özellikler

- Kullanıcı kaydı ve girişi
- Aidat ve bağış ödemeleri
- Blockchain tabanlı işlem kaydı
- Akıllı sözleşme desteği
- İşlem geçmişi görüntüleme

## Kurulum

1. Backend kurulumu:
```bash
cd backend
pip install -r requirements.txt
```

2. Frontend kurulumu:
```bash
cd frontend
pip install -r requirements.txt
```

## Çalıştırma

1. Backend'i başlatın:
```bash
cd backend
uvicorn main:app --reload
```

2. Frontend'i başlatın:
```bash
cd frontend
streamlit run app.py
```

## Kullanım

1. Tarayıcınızda `http://localhost:8501` adresine gidin
2. Yeni kullanıcı kaydı oluşturun veya mevcut hesabınızla giriş yapın
3. Aidat işlemlerini gerçekleştirin
4. İşlem geçmişinizi görüntüleyin

## Teknolojiler

- Backend: FastAPI
- Frontend: Streamlit
- Veritabanı: SQLite
- Blockchain: Custom implementation 