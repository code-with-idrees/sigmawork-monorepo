"""
SigmaWork — Security utilities.

Handles password hashing (bcrypt) and JWT token creation / verification.
Passwords are NEVER stored in plain text (SRS §4.2).
"""

import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

from jose import JWTError, jwt
from passlib.context import CryptContext

from app.config import settings

# ── Password hashing ─────────────────────────────────────

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(plain: str) -> str:
    """Hash a plain-text password with bcrypt."""
    return pwd_context.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    """Verify a plain-text password against its bcrypt hash."""
    return pwd_context.verify(plain, hashed)


# ── JWT tokens ────────────────────────────────────────────

def create_access_token(
    data: dict,
    expires_delta: Optional[timedelta] = None,
) -> str:
    """
    Create a short-lived JWT access token.
    Default lifetime: ACCESS_TOKEN_EXPIRE_MINUTES from settings.
    """
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta
        or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode.update({"exp": expire, "type": "access"})
    return jwt.encode(
        to_encode,
        settings.JWT_SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM,
    )


def create_refresh_token(
    data: dict,
    expires_delta: Optional[timedelta] = None,
) -> str:
    """
    Create a long-lived JWT refresh token.
    Default lifetime: REFRESH_TOKEN_EXPIRE_DAYS from settings.
    """
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta
        or timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    )
    to_encode.update({"exp": expire, "type": "refresh"})
    return jwt.encode(
        to_encode,
        settings.JWT_SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM,
    )


def decode_token(token: str) -> Optional[dict]:
    """
    Decode and verify a JWT token.
    Returns the payload dict on success, or None if the token
    is expired / invalid.
    """
    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],
        )
        return payload
    except JWTError:
        return None


# ── Password reset tokens ────────────────────────────────

def generate_reset_token() -> str:
    """Generate a cryptographically-secure URL-safe reset token."""
    return secrets.token_urlsafe(32)
