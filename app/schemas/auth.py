"""
SigmaWork — Pydantic schemas for authentication endpoints.

These schemas validate request bodies and shape response payloads.
"""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, EmailStr, Field


# ━━ Request Schemas ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class RegisterRequest(BaseModel):
    """POST /api/auth/register"""
    full_name: str = Field(
        ...,
        min_length=2,
        max_length=150,
        examples=["Daniel Gallego"],
    )
    email: EmailStr = Field(
        ...,
        examples=["hello@reallygreatsite.com"],
    )
    password: str = Field(
        ...,
        min_length=8,
        max_length=128,
        examples=["Str0ng!Pass"],
    )
    confirm_password: str = Field(
        ...,
        min_length=8,
        max_length=128,
        examples=["Str0ng!Pass"],
    )


class LoginRequest(BaseModel):
    """POST /api/auth/login"""
    email: EmailStr = Field(
        ...,
        examples=["hello@reallygreatsite.com"],
    )
    password: str = Field(
        ...,
        examples=["Str0ng!Pass"],
    )


class ForgotPasswordRequest(BaseModel):
    """POST /api/auth/forgot-password"""
    email: EmailStr = Field(
        ...,
        examples=["hello@reallygreatsite.com"],
    )


class ResetPasswordRequest(BaseModel):
    """POST /api/auth/reset-password"""
    token: str = Field(..., min_length=1)
    new_password: str = Field(..., min_length=8, max_length=128)
    confirm_password: str = Field(..., min_length=8, max_length=128)


# ━━ Response Schemas ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class UserResponse(BaseModel):
    """Public-facing user representation."""
    id: str
    full_name: str
    email: str
    role: str
    auth_provider: str
    profile_picture_url: Optional[str] = None
    email_verified: bool
    created_at: datetime

    model_config = {"from_attributes": True}


class TokenResponse(BaseModel):
    """Returned after successful login."""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    user: UserResponse


class MessageResponse(BaseModel):
    """Generic success message."""
    message: str
    detail: Optional[str] = None


class UserExportResponse(BaseModel):
    """Data export payload (SRS §3.1 — data export before deletion)."""
    id: str
    full_name: str
    email: str
    role: str
    auth_provider: str
    profile_picture_url: Optional[str] = None
    email_verified: bool
    is_active: bool
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}
