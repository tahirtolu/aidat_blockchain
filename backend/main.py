from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from typing import List
import models
import schemas
from database import SessionLocal, engine, Base
from auth import (
    authenticate_user, create_access_token, get_current_user,
    get_current_admin, get_password_hash, ACCESS_TOKEN_EXPIRE_MINUTES
)
from blockchain_manager import BlockchainManager
from datetime import timedelta, datetime
import logging
import uuid
import time
import json
from models import Block as DBBlock
from pydantic import BaseModel

# Logging ayarları
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Veritabanı tablolarını oluştur
Base.metadata.create_all(bind=engine)

# Genesis bloğu veritabanına kaydet
with SessionLocal() as db:
    blockchain_manager = BlockchainManager(db)
    if db.query(DBBlock).count() == 0:
        # Genesis blok yoksa oluştur
        blockchain_manager.create_block([])

app = FastAPI(title="Aidat Blockchain API")

# CORS ayarları
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Database bağlantısı için dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Blockchain manager için dependency
def get_blockchain_manager(db: Session = Depends(get_db)):
    return BlockchainManager(db)

@app.post("/token")
async def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    logger.info(f"Giriş denemesi: {form_data.username}")
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        logger.warning(f"Giriş başarısız: {form_data.username}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Kullanıcı adı veya şifre hatalı",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    logger.info(f"Giriş başarılı: {form_data.username}")
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/")
def read_root():
    return {"message": "Aidat Blockchain API'ye Hoş Geldiniz"}

# Kullanıcı işlemleri
@app.post("/users/", response_model=schemas.User)
def create_user(user: schemas.UserCreate, db: Session = Depends(get_db)):
    logger.info(f"Yeni kullanıcı kaydı: {user.username}")
    
    # Kullanıcı adı veya email kontrolü
    db_user = db.query(models.User).filter(
        (models.User.username == user.username) | 
        (models.User.email == user.email)
    ).first()
    if db_user:
        logger.warning(f"Kullanıcı adı veya email zaten kullanımda: {user.username}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Kullanıcı adı veya email zaten kullanımda"
        )
    
    # İlk kullanıcıyı admin yap
    is_first_user = db.query(models.User).count() == 0
    
    # Şifreyi hashle
    hashed_password = get_password_hash(user.password)
    db_user = models.User(
        email=user.email,
        username=user.username,
        hashed_password=hashed_password,
        is_admin=is_first_user  # İlk kullanıcı ise admin yap
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    
    if is_first_user:
        logger.info(f"İlk kullanıcı admin olarak oluşturuldu: {user.username}")
    else:
        logger.info(f"Kullanıcı başarıyla oluşturuldu: {user.username}")
    
    return db_user

@app.get("/users/me", response_model=schemas.User)
async def read_users_me(current_user: models.User = Depends(get_current_user)):
    return current_user

@app.get("/users/", response_model=List[schemas.User])
async def read_users(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_admin)
):
    users = db.query(models.User).offset(skip).limit(limit).all()
    return users

# Admin işlemleri
@app.post("/admin/users/{user_id}/make-admin")
async def make_user_admin(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_admin)
):
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Kullanıcı bulunamadı")
    user.is_admin = True
    db.commit()
    return {"message": "Kullanıcı admin yapıldı"}

@app.get("/admin/stats")
async def get_admin_stats(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_admin)
):
    total_users = db.query(models.User).count()
    total_dues = db.query(models.Due).count()
    total_transactions = db.query(models.Transaction).count()
    total_paid_dues = db.query(models.Due).filter(models.Due.is_paid == True).count()
    
    return {
        "total_users": total_users,
        "total_dues": total_dues,
        "total_transactions": total_transactions,
        "total_paid_dues": total_paid_dues,
        "payment_rate": (total_paid_dues / total_dues * 100) if total_dues > 0 else 0
    }

# Blockchain işlemleri
@app.get("/blockchain/status", response_model=schemas.BlockchainStatus)
async def get_blockchain_status(
    blockchain_manager: BlockchainManager = Depends(get_blockchain_manager),
    current_user: models.User = Depends(get_current_user)
):
    blocks = blockchain_manager.get_blockchain()
    latest_block = blocks[-1] if blocks else None
    
    return {
        "total_blocks": len(blocks),
        "total_transactions": len(blockchain_manager.get_transaction_history()),
        "is_valid": blockchain_manager.verify_blockchain(),
        "last_block_hash": latest_block.hash if latest_block else "",
        "last_block_timestamp": latest_block.timestamp if latest_block else datetime.utcnow()
    }

@app.get("/transactions/history", response_model=schemas.TransactionHistory)
async def get_transaction_history(
    blockchain_manager: BlockchainManager = Depends(get_blockchain_manager),
    current_user: models.User = Depends(get_current_user)
):
    transactions = blockchain_manager.get_transaction_history(user_id=current_user.id)
    total_amount = sum(t.amount for t in transactions)
    
    return {
        "transactions": transactions,
        "total_count": len(transactions),
        "total_amount": total_amount
    }

@app.post("/transactions/{transaction_id}/verify")
async def verify_transaction(
    transaction_id: int,
    is_verified: bool,
    blockchain_manager: BlockchainManager = Depends(get_blockchain_manager),
    current_user: models.User = Depends(get_current_admin)
):
    try:
        transaction = blockchain_manager.verify_transaction(transaction_id, is_verified)
        return {"message": "İşlem doğrulandı", "transaction_id": transaction.id}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

# Aidat işlemleri
@app.post("/dues/", response_model=schemas.Due)
async def create_due(
    due: schemas.DueCreate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_admin)
):
    contract = db.query(models.SmartContract).filter(models.SmartContract.contract_id == due.contract_id).first()
    if not contract:
        raise HTTPException(
            status_code=404,
            detail=f"Smart contract bulunamadı: {due.contract_id}"
        )
    db_due = models.Due(
        owner_id=due.owner_id,
        amount=due.amount,
        description=due.description,
        due_date=due.due_date,
        smart_contract_id=contract.id
    )
    db.add(db_due)
    db.commit()
    db.refresh(db_due)
    # Aidat oluşturma işlemini blockchain'e kaydet
    blockchain_manager = BlockchainManager(db)
    blockchain_manager.create_transaction(
        user_id=current_user.id,
        transaction_type="DUE_CREATION",
        amount=due.amount,
        description=f"Aidat oluşturuldu: {due.description}",
        due_id=db_due.id
    )
    return db_due

@app.get("/dues/", response_model=List[schemas.Due])
async def read_dues(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    # Herkes tüm aidatları görebilsin
    dues = db.query(models.Due).offset(skip).limit(limit).all()
    return dues

class PaymentRequest(BaseModel):
    amount: float
    description: str

@app.post("/dues/{due_id}/pay")
async def pay_due(
    due_id: int,
    payment: PaymentRequest,
    blockchain_manager: BlockchainManager = Depends(get_blockchain_manager),
    current_user: models.User = Depends(get_current_user)
):
    try:
        transaction = blockchain_manager.make_payment(
            user_id=current_user.id,
            due_id=due_id,
            amount=payment.amount,
            description=payment.description
        )
        return {"message": "Ödeme başarılı", "transaction_id": transaction.id}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

# Smart Contract işlemleri
@app.post("/smart-contracts/", response_model=schemas.SmartContract)
def create_smart_contract(
    contract: schemas.SmartContractCreate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_admin)
):
    contract_id = f"SC-{uuid.uuid4().hex[:8].upper()}"
    blockchain_manager = BlockchainManager(db)
    blockchain_manager.create_transaction(
        user_id=current_user.id,
        transaction_type="CONTRACT_CREATION",
        amount=0,
        description=f"Akıllı kontrat oluşturuldu: {contract.title}",
        due_id=None
    )
    db_contract = models.SmartContract(
        contract_id=contract_id,
        title=contract.title,
        description=contract.description
    )
    db.add(db_contract)
    db.commit()
    db.refresh(db_contract)
    return db_contract

@app.get("/smart-contracts/", response_model=List[schemas.SmartContract])
def read_smart_contracts(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    contracts = db.query(models.SmartContract).offset(skip).limit(limit).all()
    return contracts

@app.get("/smart-contracts/{contract_id}", response_model=schemas.SmartContract)
def read_smart_contract(contract_id: str, db: Session = Depends(get_db)):
    contract = db.query(models.SmartContract).filter(models.SmartContract.contract_id == contract_id).first()
    if contract is None:
        raise HTTPException(status_code=404, detail="Smart contract not found")
    return contract

@app.delete("/smart-contracts/{contract_id}")
def delete_smart_contract(contract_id: str, db: Session = Depends(get_db)):
    contract = db.query(models.SmartContract).filter(models.SmartContract.contract_id == contract_id).first()
    if contract is None:
        raise HTTPException(status_code=404, detail="Smart contract not found")
    blockchain_manager = BlockchainManager(db)
    blockchain_manager.create_transaction(
        user_id=None,
        transaction_type="CONTRACT_DELETION",
        amount=0,
        description=f"Akıllı kontrat silindi: {contract_id}",
        due_id=None
    )
    db.delete(contract)
    db.commit()
    return {"message": "Smart contract deleted successfully"}

@app.post("/transactions/", response_model=schemas.Transaction)
def create_transaction(
    transaction: schemas.TransactionCreate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    # Create transaction in database
    db_transaction = models.Transaction(
        amount=transaction.amount,
        user_id=current_user.id,
        due_id=transaction.due_id,
        remaining_amount=transaction.remaining_amount
    )
    db.add(db_transaction)
    db.commit()
    db.refresh(db_transaction)
    return db_transaction

@app.get("/transactions/", response_model=List[schemas.Transaction])
def read_transactions(
    user_id: int = None,
    due_id: int = None,
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db)
):
    query = db.query(models.Transaction)
    if user_id is not None:
        query = query.filter(models.Transaction.user_id == user_id)
    if due_id is not None:
        query = query.filter(models.Transaction.due_id == due_id)
    transactions = query.offset(skip).limit(limit).all()
    return transactions

@app.get("/blockchain/status")
def get_blockchain_status():
    return {
        "blocks": len(blockchain.chain),
        "pending_transactions": len(blockchain.pending_transactions),
        "is_valid": blockchain.is_chain_valid()
    }

@app.get("/blockchain/blocks/{index}", response_model=schemas.Block)
def get_block(index: int, db: Session = Depends(get_db)):
    blockchain_manager = BlockchainManager(db)
    blocks = blockchain_manager.get_blockchain()
    if index < 0 or index >= len(blocks):
        raise HTTPException(status_code=404, detail="Block not found")
    block = blocks[index]
    return {
        "index": index,
        "timestamp": block.timestamp,
        "data": block.data,
        "previous_hash": block.previous_hash,
        "hash": block.hash
    }

@app.get("/blockchain/transactions/{user_id}", response_model=List[schemas.Transaction])
def get_transaction_history(user_id: int, db: Session = Depends(get_db)):
    blockchain_manager = BlockchainManager(db)
    transactions = blockchain_manager.get_transaction_history(user_id=user_id)
    return transactions 