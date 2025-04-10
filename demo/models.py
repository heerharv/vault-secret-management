"""
Database models for the Vault demo application
"""

import enum
import logging
from datetime import datetime
from typing import List, Optional, Dict, Any

from sqlalchemy import ForeignKey, String, Integer, Text, DateTime, Boolean
from sqlalchemy.orm import Mapped, mapped_column, relationship

from main import db

logger = logging.getLogger(__name__)

class SecretType(enum.Enum):
    """Enum for different types of secrets"""
    DATABASE = "database"
    API = "api"
    AWS = "aws"
    SSH = "ssh"

class SecretAction(enum.Enum):
    """Enum for different secret actions"""
    CREATE = "create"
    READ = "read"
    UPDATE = "update" 
    DELETE = "delete"

class Secret(db.Model):
    """Model for storing secret metadata"""
    __tablename__ = 'secrets'
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    path: Mapped[str] = mapped_column(String(255), nullable=False)
    type: Mapped[SecretType] = mapped_column(db.Enum(SecretType), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    access_logs: Mapped[List["AccessLog"]] = relationship(
        "AccessLog", 
        back_populates="secret", 
        cascade="all, delete-orphan",
        lazy="select"
    )
    
    def __repr__(self) -> str:
        return f"<Secret {self.name} ({self.type.value})>"
        
    @property
    def to_dict(self) -> Dict[str, Any]:
        """Convert Secret to dictionary for API responses"""
        return {
            "id": self.id,
            "name": self.name,
            "path": self.path,
            "type": self.type.value,
            "description": self.description,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat()
        }

class AccessLog(db.Model):
    """Model for logging secret access"""
    __tablename__ = 'access_logs'
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    secret_id: Mapped[int] = mapped_column(Integer, ForeignKey('secrets.id'), nullable=False)
    action: Mapped[SecretAction] = mapped_column(db.Enum(SecretAction), nullable=False)
    client_ip: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    user_agent: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    success: Mapped[bool] = mapped_column(Boolean, default=True)
    
    # Relationships
    secret: Mapped["Secret"] = relationship("Secret", back_populates="access_logs")
    
    def __repr__(self) -> str:
        return f"<AccessLog {self.action.value} on Secret #{self.secret_id} at {self.timestamp}>"
        
    @property
    def to_dict(self) -> Dict[str, Any]:
        """Convert AccessLog to dictionary for API responses"""
        return {
            "id": self.id,
            "secret_id": self.secret_id,
            "action": self.action.value,
            "client_ip": self.client_ip,
            "user_agent": self.user_agent,
            "timestamp": self.timestamp.isoformat(),
            "success": self.success
        }

class VaultRole(db.Model):
    """Model for storing Vault roles"""
    __tablename__ = 'vault_roles'
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(100), nullable=False, unique=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    policies: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # Comma-separated list of policies
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    
    def __repr__(self) -> str:
        return f"<VaultRole {self.name}>"
        
    @property
    def to_dict(self) -> Dict[str, Any]:
        """Convert VaultRole to dictionary for API responses"""
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "policies": self.policies.split(",") if self.policies else [],
            "created_at": self.created_at.isoformat()
        }
        
    @property
    def policy_list(self) -> List[str]:
        """Return list of policies from comma-separated string"""
        if not self.policies:
            return []
        return [p.strip() for p in self.policies.split(",")]