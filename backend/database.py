from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import os
import logging

# Logging ayarları
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Veritabanı dosya yolu
DB_FILE = "aidat.db"
SQLALCHEMY_DATABASE_URL = f"sqlite:///./{DB_FILE}"

def init_db():
    """Veritabanını başlatır ve gerekirse oluşturur"""
    try:
        # Veritabanı dosyası var mı kontrol et
        db_exists = os.path.exists(DB_FILE)
        
        # Engine oluştur
        engine = create_engine(
            SQLALCHEMY_DATABASE_URL,
            connect_args={"check_same_thread": False}
        )
        
        # Session oluştur
        SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
        
        # Base sınıfını oluştur
        Base = declarative_base()
        
        # Veritabanı yoksa oluştur
        if not db_exists:
            logger.info("Veritabanı bulunamadı. Yeni veritabanı oluşturuluyor...")
            Base.metadata.create_all(bind=engine)
            logger.info("Veritabanı başarıyla oluşturuldu.")
        else:
            logger.info("Mevcut veritabanı kullanılıyor.")
        
        return engine, SessionLocal, Base
    
    except Exception as e:
        logger.error(f"Veritabanı başlatma hatası: {str(e)}")
        raise

# Veritabanını başlat
engine, SessionLocal, Base = init_db() 