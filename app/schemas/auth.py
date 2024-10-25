from pydantic import BaseModel
from typing import Optional
from uuid import UUID

class RegisterRequest(BaseModel):
    email: Optional[str] = None
    phone: Optional[str] = None

class RegisterConfirm(BaseModel):
    email: Optional[str] = None
    phone: Optional[str] = None
    code: str

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str

class EmailLoginRequest(BaseModel):
    email: str

class EmailCodeVerifyRequest(BaseModel):
    email: str
    code: str

class LoginRequest(BaseModel):
    email: str
    password: str
