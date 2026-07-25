"""
SigmaWork — User database model.

Covers SRS §3.1 (Accounts and Authentication):
  - Multiple account types (user, recruiter, admin)
  - Local auth (email + hashed password) and OAuth (Google, GitHub)
  - Soft delete with data anonymisation
  - Password reset tokens
  - Account suspension and banning

Adapted for Microsoft SQL Server.
"""

import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    String,
    func,
)
from app.database import Base


class User(Base):
    """Represents a registered user on the SigmaWork platform."""

    __tablename__ = "users"

    # ── Primary key ───────────────────────────────────────
    id = Column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )

    # ── Identity ──────────────────────────────────────────
    full_name = Column(String(150), nullable=False)
    email = Column(String(255), unique=True, nullable=False, index=True)
    hashed_password = Column(String(255), nullable=True)  # NULL for OAuth-only users

    # ── Role & auth provider ──────────────────────────────
    # Using String instead of Enum for SQL Server compatibility
    role = Column(
        String(20),
        nullable=False,
        default="user",
        server_default="user",
    )
    auth_provider = Column(
        String(20),
        nullable=False,
        default="local",
        server_default="local",
    )
    auth_provider_id = Column(String(255), nullable=True)

    # ── Profile ───────────────────────────────────────────
    profile_picture_url = Column(String(512), nullable=True)

    # ── Account state ─────────────────────────────────────
    is_active = Column(Boolean, default=True, server_default="1")
    is_banned = Column(Boolean, default=False, server_default="0")
    email_verified = Column(Boolean, default=False, server_default="0")

    # ── Password reset ────────────────────────────────────
    password_reset_token = Column(String(255), nullable=True)
    password_reset_expires = Column(DateTime, nullable=True)

    # ── Timestamps ────────────────────────────────────────
    created_at = Column(DateTime, nullable=False, server_default=func.getdate())
    updated_at = Column(
        DateTime,
        nullable=False,
        server_default=func.getdate(),
        onupdate=func.getdate(),
    )
    deleted_at = Column(DateTime, nullable=True)  # Soft delete

    def __repr__(self) -> str:
        return f"<User id={self.id} email={self.email} role={self.role}>"

    def is_deleted(self) -> bool:
        """Check if the account has been soft-deleted."""
        return self.deleted_at is not None

    def anonymize(self) -> None:
        """
        Anonymize user data for GDPR-style deletion.
        Preserves the row so that foreign-key references
        (comments, threads, etc.) remain intact.
        """
        self.full_name = "Deleted User"
        self.email = f"deleted-{self.id}@anonymized.sigmawork"
        self.hashed_password = None
        self.profile_picture_url = None
        self.auth_provider_id = None
        self.password_reset_token = None
        self.password_reset_expires = None
        self.is_active = False
        self.deleted_at = datetime.utcnow()
