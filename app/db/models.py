from sqlalchemy import Column, String, Boolean, ForeignKey, DateTime, Enum
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from app.db.database import Base
import uuid

class UserAuth(Base):
    __tablename__ = "users_auth"
    user_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email = Column(String, unique=True, nullable=True)
    phone = Column(String, unique=True, nullable=True)
    password_hash = Column(String, nullable=True)
    service_type = Column(String)

class AuthProvider(Base):
    __tablename__ = "auth_providers"
    user_id = Column(UUID(as_uuid=True), ForeignKey("users_auth.user_id"))
    provider = Column(Enum("vk", "telegram", "yandex", name="provider_enum"))
    provider_id = Column(String, unique=True)

class EmailCode(Base):
    __tablename__ = "email_codes"
    user_id = Column(UUID(as_uuid=True), ForeignKey("users_auth.user_id"))
    code = Column(String)
    expires_at = Column(DateTime)

class PhoneCode(Base):
    __tablename__ = "phone_codes"
    user_id = Column(UUID(as_uuid=True), ForeignKey("users_auth.user_id"))
    code = Column(String)
    expires_at = Column(DateTime)

class Role(Base):
    __tablename__ = "roles"
    role_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    role_name = Column(String, unique=True)
    description = Column(String)

class UserRole(Base):
    __tablename__ = "user_roles"
    user_id = Column(UUID(as_uuid=True), ForeignKey("users_auth.user_id"), primary_key=True)
    role_id = Column(UUID(as_uuid=True), ForeignKey("roles.role_id"), primary_key=True)

class RefreshToken(Base):
    __tablename__ = "refresh_tokens"
    user_id = Column(UUID(as_uuid=True), ForeignKey("users_auth.user_id"))
    refresh_token = Column(String, unique=True)
    expires_at = Column(DateTime)
    is_revoked = Column(Boolean, default=False)
