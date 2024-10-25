from pydantic import BaseModel
from typing import List, Optional
from uuid import UUID

class RoleCreate(BaseModel):
    role_name: str
    description: Optional[str] = None

class UserRoleAssign(BaseModel):
    user_id: UUID
    role_name: str

class UserResponse(BaseModel):
    user_id: UUID
    email: Optional[str]
    phone: Optional[str]
    service_type: str
    roles: List[str]
