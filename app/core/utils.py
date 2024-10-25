import random
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from app.db.models import EmailCode, PhoneCode, UserAuth, AuthProvider, RefreshToken
import uuid
import hashlib
import hmac
from app.core.config import settings

def send_email_code(user_id: str, email: str, db: Session):
    code = f"{random.randint(100000, 999999)}"
    expires_at = datetime.utcnow() + timedelta(minutes=15)
    email_code = EmailCode(user_id=user_id, code=code, expires_at=expires_at)
    db.add(email_code)
    db.commit()

def verify_email_code(user_id: str, code: str, db: Session) -> bool:
    email_code = db.query(EmailCode).filter_by(user_id=user_id, code=code).first()
    if email_code and email_code.expires_at > datetime.utcnow():
        db.delete(email_code)
        db.commit()
        return True
    return False

def generate_phone_code(user_id: str, db: Session):
    code = f"{random.randint(100000, 999999)}"
    expires_at = datetime.utcnow() + timedelta(minutes=5)
    phone_code = PhoneCode(user_id=user_id, code=code, expires_at=expires_at)
    db.add(phone_code)
    db.commit()
    return code

def verify_phone_code(user_id: str, code: str, db: Session) -> bool:
    phone_code = db.query(PhoneCode).filter_by(user_id=user_id, code=code).first()
    if phone_code and phone_code.expires_at > datetime.utcnow():
        db.delete(phone_code)
        db.commit()
        return True
    return False

def get_or_create_user_from_provider(db: Session, provider: str, provider_id: str):
    user = db.query(UserAuth).join(AuthProvider).filter(
        AuthProvider.provider == provider,
        AuthProvider.provider_id == provider_id
    ).first()

    if not user:
        user = UserAuth(user_id=uuid.uuid4(), service_type=provider)
        db.add(user)
        db.commit()
        db.refresh(user)

        auth_provider = AuthProvider(user_id=user.user_id, provider=provider, provider_id=provider_id)
        db.add(auth_provider)
        db.commit()

    return user

def verify_telegram_auth(data: dict) -> bool:
    auth_data = data.copy()
    hash_from_telegram = auth_data.pop("hash", None)

    if not hash_from_telegram:
        return False

    data_check_string = "\n".join(
        [f"{key}={value}" for key, value in sorted(auth_data.items())]
    )

    secret_key = hashlib.sha256(settings.TELEGRAM_BOT_TOKEN.encode()).digest()
    generated_hash = hmac.new(secret_key, data_check_string.encode(), hashlib.sha256).hexdigest()

    return hmac.compare_digest(generated_hash, hash_from_telegram)
