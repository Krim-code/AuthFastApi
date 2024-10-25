from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.db.models import UserAuth, Role, UserRole
from app.db.database import get_db
from app.schemas.user import UserResponse, RoleCreate, UserRoleAssign
import uuid

router = APIRouter()

# 1. Создание новой роли
@router.post("/roles/create", status_code=status.HTTP_201_CREATED)
async def create_role(role_data: RoleCreate, db: Session = Depends(get_db)):
    existing_role = db.query(Role).filter_by(role_name=role_data.role_name).first()
    if existing_role:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Role already exists")
    
    new_role = Role(role_id=uuid.uuid4(), role_name=role_data.role_name, description=role_data.description)
    db.add(new_role)
    db.commit()
    return {"message": f"Role '{role_data.role_name}' created successfully"}

# 2. Назначение роли пользователю
@router.post("/roles/assign", status_code=status.HTTP_200_OK)
async def assign_role(user_role_data: UserRoleAssign, db: Session = Depends(get_db)):
    user = db.query(UserAuth).filter_by(user_id=user_role_data.user_id).first()
    role = db.query(Role).filter_by(role_name=user_role_data.role_name).first()
    
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    if not role:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Role not found")
    
    user_role = db.query(UserRole).filter_by(user_id=user.user_id, role_id=role.role_id).first()
    if user_role:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User already has this role")
    
    new_user_role = UserRole(user_id=user.user_id, role_id=role.role_id)
    db.add(new_user_role)
    db.commit()
    return {"message": f"Role '{user_role_data.role_name}' assigned to user '{user.user_id}'"}

# 3. Получение информации о пользователе и его ролях
@router.get("/user/{user_id}", response_model=UserResponse)
async def get_user_info(user_id: str, db: Session = Depends(get_db)):
    user = db.query(UserAuth).filter_by(user_id=user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    
    roles = db.query(Role).join(UserRole).filter(UserRole.user_id == user.user_id).all()
    role_names = [role.role_name for role in roles]
    
    return UserResponse(
        user_id=user.user_id,
        email=user.email,
        phone=user.phone,
        service_type=user.service_type,
        roles=role_names
    )
