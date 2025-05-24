from sqlalchemy import Column, Integer, String, Float, Boolean, ForeignKey, DateTime, Text
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from database import Base
from datetime import datetime
import hashlib
import json

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    is_admin = Column(Boolean, default=False)
    wallet_address = Column(String, unique=True, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # İlişkiler
    dues = relationship("Due", back_populates="owner")
    transactions = relationship("Transaction", back_populates="user", foreign_keys="Transaction.user_id")

class Block(Base):
    __tablename__ = "blocks"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    previous_hash = Column(String)
    hash = Column(String, unique=True, index=True)
    data = Column(Text)  # JSON formatında işlem verileri
    
    def calculate_hash(self):
        """Block hash'ini hesaplar"""
        block_string = json.dumps({
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "previous_hash": self.previous_hash,
            "data": self.data
        }, sort_keys=True)
        return hashlib.sha256(block_string.encode()).hexdigest()

class SmartContract(Base):
    __tablename__ = "smart_contracts"

    id = Column(Integer, primary_key=True, index=True)
    contract_id = Column(String, unique=True, index=True)  # Benzersiz sözleşme ID'si
    title = Column(String, index=True)
    description = Column(String)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    def calculate_hash(self):
        """Smart contract hash'ini hesaplar"""
        contract_string = json.dumps({
            "id": self.id,
            "contract_id": self.contract_id,
            "title": self.title,
            "description": self.description,
            "created_at": self.created_at.isoformat()
        }, sort_keys=True)
        return hashlib.sha256(contract_string.encode()).hexdigest()

class Transaction(Base):
    __tablename__ = "transactions"

    id = Column(Integer, primary_key=True, index=True)
    amount = Column(Float)
    user_id = Column(Integer, ForeignKey("users.id"))
    due_id = Column(Integer, ForeignKey("dues.id"), nullable=True)  # Aidat ilişkisi için
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    remaining_amount = Column(Float, nullable=True)
    transaction_type = Column(String, nullable=True)
    
    # İlişkiler
    user = relationship("User", back_populates="transactions", foreign_keys=[user_id])
    due = relationship("Due", back_populates="transactions", foreign_keys=[due_id])
    
    def calculate_hash(self):
        created_at_str = self.created_at.isoformat() if self.created_at else ""
        transaction_string = json.dumps({
            "id": self.id,
            "amount": self.amount,
            "user_id": self.user_id,
            "due_id": self.due_id,
            "remaining_amount": self.remaining_amount,
            "transaction_type": self.transaction_type,
            "created_at": created_at_str
        }, sort_keys=True)
        return hashlib.sha256(transaction_string.encode()).hexdigest()

class Due(Base):
    __tablename__ = "dues"

    id = Column(Integer, primary_key=True, index=True)
    owner_id = Column(Integer, ForeignKey("users.id"))
    amount = Column(Float)
    description = Column(String)
    due_date = Column(DateTime)
    is_paid = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    smart_contract_id = Column(Integer, ForeignKey("smart_contracts.id"), nullable=True)
    
    # İlişkiler
    owner = relationship("User", back_populates="dues")
    transactions = relationship("Transaction", back_populates="due", foreign_keys="Transaction.due_id")
    smart_contract = relationship("SmartContract")
    
    def calculate_hash(self):
        """Due hash'ini hesaplar"""
        due_string = json.dumps({
            "id": self.id,
            "owner_id": self.owner_id,
            "amount": self.amount,
            "description": self.description,
            "due_date": self.due_date.isoformat(),
            "created_at": self.created_at.isoformat(),
            "smart_contract_id": self.smart_contract_id
        }, sort_keys=True)
        return hashlib.sha256(due_string.encode()).hexdigest() 