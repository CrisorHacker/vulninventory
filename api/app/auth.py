import os
from datetime import datetime, timedelta

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from .db import get_db
from . import models

pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login", auto_error=False)


def _jwt_secret() -> str:
    secret = os.environ.get("JWT_SECRET")
    insecure_defaults = {"change-me", "changeme", "secret", "test", ""}
    if not secret or secret in insecure_defaults:
        if os.environ.get("DEV_MODE", "false").lower() == "true":
            import logging

            logging.getLogger("security").critical(
                "JWT_SECRET no configurado. Usando default inseguro solo para DEV."
            )
            return "dev-insecure-change-me-in-production"
        raise RuntimeError(
            "JWT_SECRET no está configurado o es inseguro. "
            "Configura JWT_SECRET con al menos 32 caracteres."
        )
    if len(secret) < 32:
        raise RuntimeError(
            f"JWT_SECRET demasiado corto ({len(secret)} chars). Mínimo 32 caracteres."
        )
    return secret


def _password_policy(password: str) -> None:
    if len(password) < 10:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="La contraseña es muy corta")
    if password.lower() == password or password.upper() == password:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="La contraseña debe mezclar mayúsculas y minúsculas")
    if not any(char.isdigit() for char in password):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="La contraseña debe incluir un número")


def hash_password(password: str) -> str:
    _password_policy(password)
    return pwd_context.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    return pwd_context.verify(password, password_hash)


def create_access_token(subject: str, expires_minutes: int | None = None) -> str:
    ttl = expires_minutes or int(os.environ.get("JWT_EXPIRES_MIN", "60"))
    expire = datetime.utcnow() + timedelta(minutes=ttl)
    payload = {"sub": subject, "exp": expire, "type": "access"}
    return jwt.encode(payload, _jwt_secret(), algorithm="HS256")


def create_refresh_token(subject: str, expires_days: int | None = None) -> str:
    ttl = expires_days or int(os.environ.get("JWT_REFRESH_DAYS", "7"))
    expire = datetime.utcnow() + timedelta(days=ttl)
    payload = {"sub": subject, "exp": expire, "type": "refresh"}
    return jwt.encode(payload, _jwt_secret(), algorithm="HS256")


def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, _jwt_secret(), algorithms=["HS256"])
    except JWTError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token inválido") from exc


def password_expired(user: models.User) -> bool:
    max_age_days = int(os.environ.get("PASSWORD_MAX_AGE_DAYS", "90"))
    if max_age_days <= 0:
        return False
    last_change = user.password_updated_at or user.created_at
    return datetime.utcnow() - last_change > timedelta(days=max_age_days)


def get_current_user(token: str | None = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> models.User:
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Falta el token")
    payload = decode_token(token)
    if payload.get("type") not in (None, "access"):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token inválido")

    subject = payload.get("sub")
    if not subject:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token inválido")

    user = db.query(models.User).filter(models.User.email == subject).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Usuario no encontrado")
    return user


def get_user_from_refresh(token: str, db: Session) -> models.User:
    payload = decode_token(token)
    if payload.get("type") != "refresh":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token inválido")
    subject = payload.get("sub")
    if not subject:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token inválido")
    user = db.query(models.User).filter(models.User.email == subject).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Usuario no encontrado")
    return user
