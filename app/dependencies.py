"""
SigmaWork — FastAPI dependencies.

Provides injectable dependencies for database sessions
and authenticated user extraction from JWT tokens.
"""

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.database import SessionLocal
from app.services.auth_service import get_user_by_id
from app.utils.security import decode_token

# Bearer token scheme for Swagger UI
security_scheme = HTTPBearer(auto_error=False)


def get_db():
    """Yield a database session, closing it after the request."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security_scheme),
    db: Session = Depends(get_db),
):
    """
    Extract and validate the current user from the Authorization header.

    Raises 401 if:
      - No token is provided
      - Token is expired or invalid
      - User ID in token doesn't match a real user
      - User account is deleted, suspended, or banned
    """
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    payload = decode_token(credentials.credentials)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user_id: str = payload.get("sub")
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload.",
        )

    user = get_user_by_id(db, user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found.",
        )

    if user.is_deleted():
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail="This account has been deleted.",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Your account has been suspended.",
        )

    if user.is_banned:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Your account has been permanently banned.",
        )

    return user
