from datetime import datetime
from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import relationship
from .database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String(64), unique=True, index=True, nullable=False)
    hashed_password = Column(String(128), nullable=False)
    full_name = Column(String(128))
    role = Column(String(16), default="EMPLOYEE")  # EMPLOYEE | ADMIN

    passes = relationship("Pass", back_populates="owner")


class Pass(Base):
    __tablename__ = "passes"

    id = Column(Integer, primary_key=True)
    pass_uid = Column(String(64), unique=True, index=True, nullable=False)  # RFID UID
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    is_active = Column(Boolean, default=True)
    expires_at = Column(DateTime, nullable=False)
    issued_by = Column(Integer, ForeignKey("users.id"))

    owner = relationship("User", foreign_keys=[owner_id], back_populates="passes")


class AccessLog(Base):
    __tablename__ = "access_logs"

    id = Column(Integer, primary_key=True)
    pass_uid = Column(String(64), nullable=False)
    checkpoint = Column(String(64), nullable=False)
    allowed = Column(Boolean, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)
