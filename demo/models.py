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
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    path = db.Column(db.String(255), nullable=False)
    type = db.Column(db.Enum(SecretType), nullable=False)
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    access_logs = db.relationship('AccessLog', backref='secret', lazy=True, cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<Secret {self.name} ({self.type.value})>"

class AccessLog(db.Model):
    """Model for logging secret access"""
    __tablename__ = 'access_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    secret_id = db.Column(db.Integer, db.ForeignKey('secrets.id'), nullable=False)
    action = db.Column(db.Enum(SecretAction), nullable=False)
    client_ip = db.Column(db.String(50))
    user_agent = db.Column(db.String(255))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    success = db.Column(db.Boolean, default=True)
    
    def __repr__(self):
        return f"<AccessLog {self.action.value} on Secret #{self.secret_id} at {self.timestamp}>"

class VaultRole(db.Model):
    """Model for storing Vault roles"""
    __tablename__ = 'vault_roles'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    description = db.Column(db.Text)
    policies = db.Column(db.Text)  # Comma-separated list of policies
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f"<VaultRole {self.name}>"