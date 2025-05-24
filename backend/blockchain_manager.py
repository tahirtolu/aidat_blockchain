from sqlalchemy.orm import Session
import models
import json
from datetime import datetime
import logging

# Logging ayarları
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class BlockchainManager:
    def __init__(self, db: Session):
        self.db = db
    
    def get_latest_block(self):
        """En son bloğu getirir"""
        return self.db.query(models.Block).order_by(models.Block.id.desc()).first()
    
    def create_block(self, data):
        """Yeni blok oluşturur"""
        latest_block = self.get_latest_block()
        previous_hash = latest_block.hash if latest_block else "0" * 64
        
        new_block = models.Block(
            timestamp=datetime.utcnow(),
            previous_hash=previous_hash,
            data=json.dumps(data)
        )
        new_block.hash = new_block.calculate_hash()
        
        self.db.add(new_block)
        self.db.commit()
        self.db.refresh(new_block)
        
        logger.info(f"Yeni blok oluşturuldu: ID={new_block.id}")
        return new_block
    
    def create_transaction(self, user_id, transaction_type, amount, description, due_id=None):
        """Yeni işlem oluşturur"""
        # İşlem verilerini hazırla
        transaction_data = {
            "user_id": user_id,
            "type": transaction_type,
            "amount": amount,
            "description": description,
            "due_id": due_id,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        # Yeni blok oluştur
        block = self.create_block(transaction_data)
        
        # Kalan miktarı hesapla (eğer due_id varsa)
        remaining_amount = None
        if due_id is not None:
            due = self.db.query(models.Due).filter(models.Due.id == due_id).first()
            if due:
                total_paid = sum(
                    t.amount for t in self.db.query(models.Transaction)
                    .filter(models.Transaction.due_id == due_id).all()
                )
                remaining_amount = max(due.amount - total_paid, 0)
        
        # İşlemi oluştur
        transaction = models.Transaction(
            user_id=user_id,
            due_id=due_id,
            amount=amount,
            remaining_amount=remaining_amount,
            transaction_type=transaction_type
        )
        self.db.add(transaction)
        self.db.commit()
        self.db.refresh(transaction)
        transaction.transaction_hash = transaction.calculate_hash()
        self.db.commit()
        
        logger.info(f"Yeni işlem oluşturuldu: ID={transaction.id}")
        return transaction
    
    def create_due(self, owner_id, amount, description, due_date):
        """Yeni aidat oluşturur"""
        # Aidat oluştur
        due = models.Due(
            owner_id=owner_id,
            amount=amount,
            description=description,
            due_date=due_date
        )
        self.db.add(due)
        self.db.commit()
        self.db.refresh(due)
        
        # İşlem oluştur
        self.create_transaction(
            user_id=owner_id,
            transaction_type="DUE_CREATION",
            amount=amount,
            description=f"Aidat oluşturuldu: {description}",
            due_id=due.id
        )
        
        logger.info(f"Yeni aidat oluşturuldu: ID={due.id}")
        return due
    
    def make_payment(self, user_id, due_id, amount, description):
        """Aidat ödemesi yapar"""
        # Aidatı bul
        due = self.db.query(models.Due).filter(models.Due.id == due_id).first()
        if not due:
            raise ValueError("Aidat bulunamadı")
        
        # Ödeme işlemini oluştur
        transaction = self.create_transaction(
            user_id=user_id,
            transaction_type="PAYMENT",
            amount=amount,
            description=description,
            due_id=due_id
        )
        
        # Kullanıcının yaptığı toplam ödemeyi hesapla
        total_paid = sum(
            t.amount for t in self.db.query(models.Transaction)
            .filter(models.Transaction.due_id == due_id).all()
        )
        due.is_paid = total_paid >= due.amount
        self.db.commit()
        
        logger.info(f"Ödeme yapıldı: Due ID={due_id}, Transaction ID={transaction.id}")
        return transaction
    
    def verify_transaction(self, transaction_id, is_verified):
        """İşlemi doğrular"""
        transaction = self.db.query(models.Transaction).filter(
            models.Transaction.id == transaction_id
        ).first()
        
        if not transaction:
            raise ValueError("İşlem bulunamadı")
        
        transaction.is_verified = is_verified
        self.db.commit()
        
        # Doğrulama işlemini kaydet
        self.create_transaction(
            user_id=transaction.user_id,
            transaction_type="VERIFICATION",
            amount=0,
            description=f"İşlem doğrulandı: {transaction_id}",
            due_id=transaction.due_id
        )
        
        logger.info(f"İşlem doğrulandı: ID={transaction_id}, Verified={is_verified}")
        return transaction
    
    def get_transaction_history(self, user_id=None, due_id=None):
        """İşlem geçmişini getirir"""
        query = self.db.query(models.Transaction)
        
        if user_id:
            query = query.filter(models.Transaction.user_id == user_id)
        if due_id:
            query = query.filter(models.Transaction.due_id == due_id)
        
        return query.order_by(models.Transaction.timestamp.desc()).all()
    
    def get_blockchain(self):
        """Tüm blockchain'i getirir"""
        return self.db.query(models.Block).order_by(models.Block.id).all()
    
    def verify_blockchain(self):
        """Blockchain'in bütünlüğünü doğrular"""
        blocks = self.get_blockchain()
        for i in range(1, len(blocks)):
            current_block = blocks[i]
            previous_block = blocks[i-1]
            
            # Hash'leri kontrol et
            if current_block.previous_hash != previous_block.hash:
                return False
            if current_block.hash != current_block.calculate_hash():
                return False
        
        return True 