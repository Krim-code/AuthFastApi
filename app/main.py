from fastapi import FastAPI
from app.api import auth, users

app = FastAPI()

app.include_router(auth.router, prefix="/auth")
app.include_router(users.router, prefix="/users")