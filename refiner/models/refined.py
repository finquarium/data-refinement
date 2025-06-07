from datetime import datetime
from sqlalchemy import Column, String, Integer, Float, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

class User(Base):
    __tablename__ = 'users'
    id_hash = Column(String, primary_key=True, index=True)
    file_id = Column(Integer, index=True, nullable=True) # From environment variable

    financial_stats = relationship("UserFinancialStats", back_populates="user", uselist=False, cascade="all, delete-orphan")
    transactions = relationship("Transaction", back_populates="user", cascade="all, delete-orphan")
    assets = relationship("UserAsset", back_populates="user", cascade="all, delete-orphan")

class UserFinancialStats(Base):
    __tablename__ = 'user_financial_stats'
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id_hash = Column(String, ForeignKey('users.id_hash'), nullable=False, index=True, unique=True)

    total_volume = Column(Float, nullable=False)
    transaction_count = Column(Integer, nullable=False)
    unique_assets_count = Column(Integer, nullable=False)
    activity_period_days = Column(Integer, nullable=False)
    first_transaction_at = Column(DateTime, nullable=True)
    last_transaction_at = Column(DateTime, nullable=True)
    refined_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="financial_stats")

class Transaction(Base):
    __tablename__ = 'transactions'
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id_hash = Column(String, ForeignKey('users.id_hash'), nullable=False, index=True)

    transaction_type = Column(String, nullable=False, index=True) # e.g., trade, send, buy, fiat_withdrawal
    asset_symbol = Column(String, nullable=False, index=True)
    quantity = Column(Float, nullable=False)
    native_amount = Column(Float, nullable=False) # Consistent native currency (e.g., USD value at time of transaction)
    transaction_at = Column(DateTime, nullable=False, index=True)

    user = relationship("User", back_populates="transactions")

class UserAsset(Base):
    __tablename__ = 'user_assets'
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id_hash = Column(String, ForeignKey('users.id_hash'), nullable=False, index=True)
    asset_symbol = Column(String, nullable=False, index=True)

    user = relationship("User", back_populates="assets")