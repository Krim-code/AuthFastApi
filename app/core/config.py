import os
from dotenv import load_dotenv

load_dotenv()

class Settings:
    DATABASE_URL = os.getenv("DATABASE_URL", "postgresql+asyncpg://user:password@localhost/authdb")
    JWT_SECRET = os.getenv("JWT_SECRET", "your_secret_key")
    JWT_ALGORITHM = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES = 15
    REFRESH_TOKEN_EXPIRE_DAYS = 7

    VK_CLIENT_ID = os.getenv("VK_CLIENT_ID")
    VK_CLIENT_SECRET = os.getenv("VK_CLIENT_SECRET")
    VK_REDIRECT_URI = os.getenv("VK_REDIRECT_URI", "https://yourdomain.com/auth/vk/callback")

    TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
    
    YANDEX_CLIENT_ID = os.getenv("YANDEX_CLIENT_ID")
    YANDEX_CLIENT_SECRET = os.getenv("YANDEX_CLIENT_SECRET")
    YANDEX_REDIRECT_URI = os.getenv("YANDEX_REDIRECT_URI", "https://yourdomain.com/auth/yandex/callback")

settings = Settings()
