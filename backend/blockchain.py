import hashlib
import json
import time
from typing import List, Dict, Any
from datetime import datetime
from database import SessionLocal
from models import Block as DBBlock

class Block:
    def __init__(self, index: int, transactions: List[Dict], timestamp: float, previous_hash: str):
        self.index = index
        self.timestamp = timestamp
        self.transactions = transactions
        self.previous_hash = previous_hash
        self.nonce = 0
        self.hash = self.calculate_hash()

    def calculate_hash(self) -> str:
        block_string = json.dumps({
            "index": self.index,
            "timestamp": self.timestamp,
            "transactions": self.transactions,
            "previous_hash": self.previous_hash,
            "nonce": self.nonce
        }, sort_keys=True)
        return hashlib.sha256(block_string.encode()).hexdigest()

    def mine_block(self, difficulty: int) -> None:
        target = "0" * difficulty
        while self.hash[:difficulty] != target:
            self.nonce += 1
            self.hash = self.calculate_hash()

class Blockchain:
    def __init__(self, difficulty: int = 4):
        self.chain: List[Block] = [self.create_genesis_block()]
        self.difficulty = difficulty
        self.pending_transactions: List[Dict] = []
        self.mining_reward = 10

    def create_genesis_block(self) -> Block:
        return Block(0, [], time.time(), "0" * 64)

    def get_latest_block(self) -> Block:
        return self.chain[-1]

    def mine_pending_transactions(self, miner_address: str) -> None:
        # Create mining reward transaction
        reward_tx = {
            "from": "network",
            "to": miner_address,
            "amount": self.mining_reward,
            "timestamp": time.time()
        }
        self.pending_transactions.append(reward_tx)

        # Create new block with pending transactions
        block = Block(
            len(self.chain),
            self.pending_transactions,
            time.time(),
            self.get_latest_block().hash
        )

        # Mine the block
        block.mine_block(self.difficulty)

        # Add the block to the chain
        self.chain.append(block)

        # --- YENİ: Bloku veritabanına kaydet ---
        db = SessionLocal()
        db_block = DBBlock(
            timestamp=datetime.fromtimestamp(block.timestamp),
            previous_hash=block.previous_hash,
            hash=block.hash,
            data=json.dumps(block.transactions),
        )
        db.add(db_block)
        db.commit()
        db.close()

        # Reset pending transactions
        self.pending_transactions = []

    def add_transaction(self, transaction: Dict) -> None:
        self.pending_transactions.append(transaction)

    def get_balance(self, address: str) -> float:
        balance = 0.0

        for block in self.chain:
            for transaction in block.transactions:
                if transaction["from"] == address:
                    balance -= transaction["amount"]
                if transaction["to"] == address:
                    balance += transaction["amount"]

        return balance

    def is_chain_valid(self) -> bool:
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i-1]

            # Verify current block's hash
            if current_block.hash != current_block.calculate_hash():
                return False

            # Verify chain linkage
            if current_block.previous_hash != previous_block.hash:
                return False

        return True

    def get_block_by_index(self, index: int) -> Block:
        if 0 <= index < len(self.chain):
            return self.chain[index]
        return None

    def get_transaction_history(self, address: str) -> List[Dict]:
        history = []
        for block in self.chain:
            for transaction in block.transactions:
                if transaction["from"] == address or transaction["to"] == address:
                    history.append({
                        **transaction,
                        "block_index": block.index,
                        "timestamp": block.timestamp
                    })
        return history

# Singleton instance
blockchain = Blockchain() 