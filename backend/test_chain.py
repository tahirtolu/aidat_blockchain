from database import SessionLocal
from blockchain_manager import BlockchainManager

db = SessionLocal()
manager = BlockchainManager(db)
print("Zincir geçerli mi?", manager.verify_blockchain())
db.close()