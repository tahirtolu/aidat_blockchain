from pydantic import BaseModel, EmailStr
from typing import Optional, List
from datetime import datetime

class UserBase(BaseModel):
    email: str
    username: str

class UserCreate(UserBase):
    password: str

class User(BaseModel):
    id: int
    email: str
    username: str
    is_admin: bool
    wallet_address: Optional[str] = None
    created_at: datetime

    class Config:
        from_attributes = True

class BlockBase(BaseModel):
    timestamp: datetime
    previous_hash: str
    hash: str
    data: str

class Block(BlockBase):
    id: int

    class Config:
        from_attributes = True

class TransactionBase(BaseModel):
    amount: float
    user_id: int
    due_id: Optional[int] = None
    remaining_amount: Optional[float] = None
    transaction_type: Optional[str] = None

class TransactionCreate(TransactionBase):
    pass

class Transaction(TransactionBase):
    id: int
    created_at: datetime

    class Config:
        from_attributes = True

class DueBase(BaseModel):
    amount: float
    description: str
    due_date: datetime

class DueCreate(DueBase):
    owner_id: int
    contract_id: str

class Due(DueBase):
    id: int
    owner_id: int
    is_paid: bool
    created_at: datetime
    smart_contract_id: int

    class Config:
        from_attributes = True

class BlockchainStatus(BaseModel):
    blocks: int
    pending_transactions: int
    is_valid: bool

class TransactionHistory(BaseModel):
    transactions: List[Transaction]
    total_count: int
    total_amount: float

class SmartContractBase(BaseModel):
    title: str
    description: str

class SmartContractCreate(SmartContractBase):
    pass

class SmartContract(SmartContractBase):
    id: int
    contract_id: str
    created_at: datetime

    class Config:
        from_attributes = True

class SmartContractResponse(SmartContract):
    creator: User
    transactions: List[Transaction]

class DueBase(BaseModel):
    amount: float
    description: str
    due_date: datetime

class DueCreate(DueBase):
    owner_id: int
    contract_id: str

class Due(DueBase):
    id: int
    owner_id: int
    is_paid: bool
    created_at: datetime
    smart_contract_id: int

    class Config:
        from_attributes = True 