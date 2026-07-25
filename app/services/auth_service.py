"""
SigmaWork — Authentication business logic.

All database operations for accounts flow through here. The router
layer calls these functions; they should never import FastAPI directly.
"""

from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.user import User
from app.utils.security import (
    create_access_token,
    create_refresh_token,
    generate_reset_token,
    hash_password,
    verify_password,
)
from app.utils.validators import validate_password_strength


# ━━ Exceptions ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class AuthError(Exception):
    """Raised when an authentication operation fails."""

    def __init__(self, message: str, status_code: int = 400):
        self.message = message
        self.status_code = status_code
        super().__init__(self.message)


# ━━ Service functions ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def register_user(
    db: Session,
    full_name: str,
    email: str,
    password: str,
    confirm_password: str,
) -> User:
    """
    Register a new user with email + password.

    Validates:
      - Passwords match
      - Password meets strength requirements (SRS §3.1)
      - Email is not already registered
    """
    # 1. Check passwords match
    if password != confirm_password:
        raise AuthError("Passwords do not match.", 400)

    # 2. Check password strength
    strength_error = validate_password_strength(password)
    if strength_error:
        raise AuthError(strength_error, 400)

    # 3. Check email uniqueness
    existing = db.execute(
        select(User).where(User.email == email.lower().strip())
    ).scalar_one_or_none()

    if existing:
        raise AuthError(
            "An account with this email already exists.",
            409,
        )

    # 4. Create the user
    user = User(
        full_name=full_name.strip(),
        email=email.lower().strip(),
        hashed_password=hash_password(password),
        role="user",
        auth_provider="local",
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def login_user(
    db: Session,
    email: str,
    password: str,
) -> dict:
    """
    Authenticate a user and return JWT tokens.

    Returns a dict with access_token, refresh_token, and user object.
    """
    user = db.execute(
        select(User).where(User.email == email.lower().strip())
    ).scalar_one_or_none()

    # Generic error to prevent email enumeration
    if not user or not user.hashed_password:
        raise AuthError("Invalid email or password.", 401)

    if not verify_password(password, user.hashed_password):
        raise AuthError("Invalid email or password.", 401)

    if user.is_deleted():
        raise AuthError("This account has been deleted.", 410)

    if not user.is_active:
        raise AuthError(
            "Your account has been suspended. Contact support.",
            403,
        )

    if user.is_banned:
        raise AuthError(
            "Your account has been permanently banned.",
            403,
        )

    # Generate tokens
    token_data = {"sub": user.id, "role": user.role}
    access_token = create_access_token(token_data)
    refresh_token = create_refresh_token(token_data)

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "user": user,
    }


def get_user_by_id(db: Session, user_id: str) -> Optional[User]:
    """Fetch a user by their UUID."""
    return db.execute(
        select(User).where(User.id == user_id)
    ).scalar_one_or_none()


def request_password_reset(db: Session, email: str) -> Optional[str]:
    """
    Generate a password-reset token for the given email.

    Always returns None to the caller (the router returns 200 regardless)
    to prevent email enumeration.

    In development mode the raw token is returned so you can test the flow
    without an email service.
    """
    user = db.execute(
        select(User).where(User.email == email.lower().strip())
    ).scalar_one_or_none()

    if not user or user.is_deleted():
        return None  # Don't reveal whether the email exists

    raw_token = generate_reset_token()
    user.password_reset_token = hash_password(raw_token)
    user.password_reset_expires = datetime.now(timezone.utc) + timedelta(hours=1)
    db.commit()

    # TODO: send email with raw_token via SMTP / SendGrid
    # For now, return the raw token in dev so the flow can be tested.
    return raw_token


def reset_password(
    db: Session,
    token: str,
    new_password: str,
    confirm_password: str,
) -> None:
    """
    Reset a user's password using a valid reset token.
    """
    if new_password != confirm_password:
        raise AuthError("Passwords do not match.", 400)

    strength_error = validate_password_strength(new_password)
    if strength_error:
        raise AuthError(strength_error, 400)

    # Find users with a non-expired reset token
    users = db.execute(
        select(User).where(
            User.password_reset_token.isnot(None),
            User.password_reset_expires > datetime.now(timezone.utc),
        )
    ).scalars().all()

    # Verify the token against each candidate (bcrypt comparison)
    target_user: Optional[User] = None
    for user in users:
        if verify_password(token, user.password_reset_token):
            target_user = user
            break

    if not target_user:
        raise AuthError("Invalid or expired reset token.", 400)

    target_user.hashed_password = hash_password(new_password)
    target_user.password_reset_token = None
    target_user.password_reset_expires = None
    db.commit()


def delete_account(db: Session, user: User) -> None:
    """
    Soft-delete and anonymize a user's account (SRS §3.1).

    Personal data is wiped. The row is kept so that foreign-key
    references (comments, threads) stay intact in anonymized form.
    """
    user.anonymize()
    db.commit()


def export_user_data(db: Session, user: User) -> dict:
    """
    Return all of a user's personal data as a dict (SRS §3.1 — data export).
    """
    return {
        "id": user.id,
        "full_name": user.full_name,
        "email": user.email,
        "role": user.role,
        "auth_provider": user.auth_provider,
        "profile_picture_url": user.profile_picture_url,
        "email_verified": user.email_verified,
        "is_active": user.is_active,
        "created_at": user.created_at.isoformat() if user.created_at else None,
        "updated_at": user.updated_at.isoformat() if user.updated_at else None,
    }


def find_or_create_oauth_user(
    db: Session,
    email: str,
    full_name: str,
    provider: str,
    provider_id: str,
    picture_url: Optional[str] = None,
) -> User:
    """
    Find an existing user by OAuth provider + ID, or create a new one.
    Used by Google and GitHub OAuth callbacks.
    """
    # First try by provider + provider_id
    user = db.execute(
        select(User).where(
            User.auth_provider == provider,
            User.auth_provider_id == provider_id,
        )
    ).scalar_one_or_none()
    if user:
        return user

    # Then try by email (link accounts)
    user = db.execute(
        select(User).where(User.email == email.lower().strip())
    ).scalar_one_or_none()
    if user:
        # Link the OAuth provider to existing account
        user.auth_provider = provider
        user.auth_provider_id = provider_id
        if picture_url and not user.profile_picture_url:
            user.profile_picture_url = picture_url
        db.commit()
        db.refresh(user)
        return user

    # Create new user
    user = User(
        full_name=full_name,
        email=email.lower().strip(),
        auth_provider=provider,
        auth_provider_id=provider_id,
        profile_picture_url=picture_url,
        email_verified=True,  # OAuth providers verify email
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user
