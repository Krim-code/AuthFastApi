import bcrypt
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session
from app.db.models import UserAuth, RefreshToken
from app.core.security import create_access_token, create_refresh_token, decode_token
from app.core.utils import (
    send_email_code,
    generate_phone_code,
    verify_email_code,
    verify_phone_code,
    get_or_create_user_from_provider,
    verify_telegram_auth
)
from app.db.database import get_db
from app.schemas.auth import (
    RegisterRequest,
    RegisterConfirm,
    TokenResponse,
    EmailLoginRequest,
    EmailCodeVerifyRequest,
    LoginRequest
)
from app.core.config import settings
import requests
from datetime import datetime, timedelta

router = APIRouter()

# 1. Регистрация нового пользователя с отправкой кода
@router.post("/register/request")
async def register_request(request: RegisterRequest, db: Session = Depends(get_db)):
    if request.email:
        existing_user = db.query(UserAuth).filter_by(email=request.email).first()
        if existing_user:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered")
        new_user = UserAuth(email=request.email, service_type="email")
        db.add(new_user)
        db.commit()
        send_email_code(new_user.user_id, new_user.email, db)
        return {"message": "Verification code sent to email"}
    elif request.phone:
        existing_user = db.query(UserAuth).filter_by(phone=request.phone).first()
        if existing_user:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Phone number already registered")
        new_user = UserAuth(phone=request.phone, service_type="phone")
        db.add(new_user)
        db.commit()
        code = generate_phone_code(new_user.user_id, db)
        return {"message": f"Verification code sent to phone {request.phone}"}
    else:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email or phone is required")

# 2. Подтверждение кода для завершения регистрации
@router.post("/register/confirm", response_model=TokenResponse)
async def register_confirm(request: RegisterConfirm, db: Session = Depends(get_db)):
    if request.email:
        user = db.query(UserAuth).filter_by(email=request.email).first()
        if not user or not verify_email_code(user.user_id, request.code, db):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid email verification code")
    elif request.phone:
        user = db.query(UserAuth).filter_by(phone=request.phone).first()
        if not user or not verify_phone_code(user.user_id, request.code, db):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid phone verification code")
    else:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email or phone is required")
    
    access_token = create_access_token({"user_id": str(user.user_id)})
    refresh_token = create_refresh_token({"user_id": str(user.user_id)}, db)
    return {"access_token": access_token, "refresh_token": refresh_token}

# 3. Логин по email с отправкой кода
@router.post("/email/login/request")
async def email_login_request(request: EmailLoginRequest, db: Session = Depends(get_db)):
    user = db.query(UserAuth).filter_by(email=request.email).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Email not registered")
    
    send_email_code(user.user_id, user.email, db)
    return {"message": "Verification code sent to email"}

# 4. Подтверждение кода для логина по email
@router.post("/email/login/verify", response_model=TokenResponse)
async def email_login_verify(request: EmailCodeVerifyRequest, db: Session = Depends(get_db)):
    user = db.query(UserAuth).filter_by(email=request.email).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Email not registered")
    
    if not verify_email_code(user.user_id, request.code, db):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid verification code")
    
    access_token = create_access_token({"user_id": str(user.user_id)})
    refresh_token = create_refresh_token({"user_id": str(user.user_id)}, db)
    return {"access_token": access_token, "refresh_token": refresh_token}

# 5. VK аутентификация
@router.get("/auth/vk")
async def vk_login():
    vk_auth_url = (
        f"https://oauth.vk.com/authorize?"
        f"client_id={settings.VK_CLIENT_ID}&"
        f"redirect_uri={settings.VK_REDIRECT_URI}&"
        f"response_type=code&scope=email"
    )
    return RedirectResponse(vk_auth_url)

@router.get("/auth/vk/callback")
async def vk_callback(code: str, db: Session = Depends(get_db)):
    token_url = (
        f"https://oauth.vk.com/access_token?"
        f"client_id={settings.VK_CLIENT_ID}&"
        f"client_secret={settings.VK_CLIENT_SECRET}&"
        f"redirect_uri={settings.VK_REDIRECT_URI}&"
        f"code={code}"
    )
    token_response = requests.get(token_url).json()
    access_token = token_response.get("access_token")
    vk_user_id = token_response.get("user_id")

    if not access_token or not vk_user_id:
        raise HTTPException(status_code=400, detail="Invalid VK login")

    user = get_or_create_user_from_provider(db, "vk", vk_user_id)
    access_token, refresh_token = create_tokens_for_user(user.user_id, db)
    return {"access_token": access_token, "refresh_token": refresh_token}

# 6. Telegram аутентификация
@router.post("/auth/telegram")
async def telegram_login(data: dict, db: Session = Depends(get_db)):
    if not verify_telegram_auth(data):
        raise HTTPException(status_code=400, detail="Invalid Telegram login")

    telegram_id = data.get("id")
    if not telegram_id:
        raise HTTPException(status_code=400, detail="Telegram ID missing")

    user = get_or_create_user_from_provider(db, "telegram", telegram_id)
    access_token, refresh_token = create_tokens_for_user(user.user_id, db)
    return {"access_token": access_token, "refresh_token": refresh_token}

# 7. Yandex аутентификация
@router.get("/auth/yandex")
async def yandex_login():
    yandex_auth_url = (
        f"https://oauth.yandex.com/authorize?"
        f"response_type=code&client_id={settings.YANDEX_CLIENT_ID}&"
        f"redirect_uri={settings.YANDEX_REDIRECT_URI}"
    )
    return RedirectResponse(yandex_auth_url)

@router.get("/auth/yandex/callback")
async def yandex_callback(code: str, db: Session = Depends(get_db)):
    token_url = "https://oauth.yandex.com/token"
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "client_id": settings.YANDEX_CLIENT_ID,
        "client_secret": settings.YANDEX_CLIENT_SECRET,
    }
    token_response = requests.post(token_url, data=data).json()
    access_token = token_response.get("access_token")

    if not access_token:
        raise HTTPException(status_code=400, detail="Invalid Yandex login")

    user_info = requests.get(
        "https://login.yandex.ru/info", headers={"Authorization": f"Bearer {access_token}"}
    ).json()
    yandex_id = user_info.get("id")

    user = get_or_create_user_from_provider(db, "yandex", yandex_id)
    access_token, refresh_token = create_tokens_for_user(user.user_id, db)
    return {"access_token": access_token, "refresh_token": refresh_token}

# 8. CMS Логин по email и паролю
@router.post("/cms/login", response_model=TokenResponse)
async def cms_login(request: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(UserAuth).filter_by(email=request.email).first()
    if not user or not bcrypt.checkpw(request.password.encode(), user.password_hash.encode()):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid CMS credentials")
    
    access_token, refresh_token = create_tokens_for_user(user.user_id, db)
    return {"access_token": access_token, "refresh_token": refresh_token}

# 9. Отзыв refresh токена
@router.post("/token/revoke")
async def revoke_refresh_token(refresh_token: str, db: Session = Depends(get_db)):
    token = db.query(RefreshToken).filter_by(refresh_token=refresh_token).first()
    if not token or token.is_revoked:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Token already revoked or invalid")
    
    token.is_revoked = True
    db.commit()
    return {"message": "Token revoked successfully"}

# 10. Обновление токенов
@router.post("/token/refresh", response_model=TokenResponse)
async def refresh_token(refresh_token: str, db: Session = Depends(get_db)):
    token = db.query(RefreshToken).filter_by(refresh_token=refresh_token).first()
    if not token or token.is_revoked or token.expires_at < datetime.utcnow():
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired refresh token")

    access_token, new_refresh_token = create_tokens_for_user(token.user_id, db)
    
    token.refresh_token = new_refresh_token
    token.expires_at = datetime.utcnow() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    db.commit()

    return {"access_token": access_token, "refresh_token": new_refresh_token}

# Вспомогательная функция для создания токенов
def create_tokens_for_user(user_id: str, db: Session):
    access_token = create_access_token({"user_id": user_id})
    refresh_token = create_refresh_token({"user_id": user_id}, db)
    return access_token, refresh_token
