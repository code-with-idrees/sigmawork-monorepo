"""
SigmaWork — Authentication API endpoints.

All routes are mounted under /api/auth/ by main.py.
Covers SRS §3.1 (Accounts and Authentication).
"""

from urllib.parse import urlencode

import httpx
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from app.config import settings
from app.dependencies import get_current_user, get_db
from app.models.user import User
from app.schemas.auth import (
    ForgotPasswordRequest,
    LoginRequest,
    MessageResponse,
    RegisterRequest,
    ResetPasswordRequest,
    TokenResponse,
    UserExportResponse,
    UserResponse,
)
from app.services.auth_service import (
    AuthError,
    delete_account,
    export_user_data,
    find_or_create_oauth_user,
    login_user,
    register_user,
    request_password_reset,
    reset_password,
)
from app.utils.security import create_access_token, create_refresh_token

router = APIRouter(prefix="/api/auth", tags=["Authentication"])


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Registration & Login
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


@router.post(
    "/register",
    response_model=MessageResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new account",
)
def register(body: RegisterRequest, db: Session = Depends(get_db)):
    """
    Register a new user with email and password.

    Password must be ≥ 8 chars with uppercase, lowercase, digit, and special character.
    """
    try:
        user = register_user(
            db,
            full_name=body.full_name,
            email=body.email,
            password=body.password,
            confirm_password=body.confirm_password,
        )
        return MessageResponse(
            message="Account created successfully.",
            detail=f"User ID: {user.id}",
        )
    except AuthError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)


@router.post(
    "/login",
    response_model=TokenResponse,
    summary="Log in with email and password",
)
def login(body: LoginRequest, db: Session = Depends(get_db)):
    """
    Authenticate with email and password.
    Returns JWT access and refresh tokens.
    """
    try:
        result = login_user(db, email=body.email, password=body.password)
        return TokenResponse(
            access_token=result["access_token"],
            refresh_token=result["refresh_token"],
            user=UserResponse.model_validate(result["user"]),
        )
    except AuthError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)


@router.post(
    "/logout",
    response_model=MessageResponse,
    summary="Log out (client-side token discard)",
)
def logout(_: User = Depends(get_current_user)):
    """
    Log out the current user.

    Since JWTs are stateless, the client should discard the tokens.
    This endpoint exists so the frontend has a semantic action to call.
    """
    return MessageResponse(message="Logged out successfully.")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Password Reset
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


@router.post(
    "/forgot-password",
    response_model=MessageResponse,
    summary="Request a password reset",
)
def forgot_password(
    body: ForgotPasswordRequest,
    db: Session = Depends(get_db),
):
    """
    Request a password-reset token.

    Always returns 200 to prevent email enumeration.
    In development mode, the raw token is included in the response for testing.
    """
    raw_token = request_password_reset(db, email=body.email)

    response = MessageResponse(
        message="If an account with that email exists, a reset link has been sent."
    )

    # In development, include the token so the flow can be tested
    # without setting up an email service.
    if settings.APP_ENV == "development" and raw_token:
        response.detail = f"DEV_ONLY_RESET_TOKEN: {raw_token}"

    return response


@router.post(
    "/reset-password",
    response_model=MessageResponse,
    summary="Reset password using a token",
)
def do_reset_password(
    body: ResetPasswordRequest,
    db: Session = Depends(get_db),
):
    """Reset password using a valid reset token."""
    try:
        reset_password(
            db,
            token=body.token,
            new_password=body.new_password,
            confirm_password=body.confirm_password,
        )
        return MessageResponse(message="Password has been reset successfully.")
    except AuthError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Current User
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


@router.get(
    "/me",
    response_model=UserResponse,
    summary="Get current user profile",
)
def me(user: User = Depends(get_current_user)):
    """Return the authenticated user's profile data."""
    return UserResponse.model_validate(user)


@router.delete(
    "/me",
    response_model=MessageResponse,
    summary="Delete your account",
)
def delete_me(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Soft-delete and anonymize the current user's account (SRS §3.1).
    Personal data is wiped; the row is retained for referential integrity.
    """
    delete_account(db, user)
    return MessageResponse(message="Your account has been deleted and data anonymized.")


@router.get(
    "/me/export",
    response_model=UserExportResponse,
    summary="Export your data",
)
def export_me(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Export all of the current user's personal data as JSON (SRS §3.1).
    Can be called at any time, including before account deletion.
    """
    data = export_user_data(db, user)
    return data


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  OAuth — Google
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


@router.get(
    "/oauth/google",
    summary="Redirect to Google OAuth",
)
def google_oauth_redirect():
    """Redirect the user to Google's OAuth 2.0 consent screen."""
    if not settings.GOOGLE_CLIENT_ID:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail="Google OAuth is not configured. Set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET in .env",
        )

    params = urlencode({
        "client_id": settings.GOOGLE_CLIENT_ID,
        "redirect_uri": settings.GOOGLE_REDIRECT_URI,
        "response_type": "code",
        "scope": "openid email profile",
        "access_type": "offline",
        "prompt": "consent",
    })
    return RedirectResponse(
        url=f"https://accounts.google.com/o/oauth2/v2/auth?{params}"
    )


@router.get(
    "/oauth/google/callback",
    summary="Google OAuth callback",
)
async def google_oauth_callback(code: str, db: Session = Depends(get_db)):
    """
    Handle the Google OAuth callback.
    Exchanges the authorization code for tokens, fetches user info,
    and creates or links the account.
    """
    # Exchange code for tokens
    async with httpx.AsyncClient() as client:
        token_resp = await client.post(
            "https://oauth2.googleapis.com/token",
            data={
                "code": code,
                "client_id": settings.GOOGLE_CLIENT_ID,
                "client_secret": settings.GOOGLE_CLIENT_SECRET,
                "redirect_uri": settings.GOOGLE_REDIRECT_URI,
                "grant_type": "authorization_code",
            },
        )

    if token_resp.status_code != 200:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to exchange Google authorization code.",
        )

    token_data = token_resp.json()
    access_token = token_data.get("access_token")

    # Fetch user info
    async with httpx.AsyncClient() as client:
        user_resp = await client.get(
            "https://www.googleapis.com/oauth2/v2/userinfo",
            headers={"Authorization": f"Bearer {access_token}"},
        )

    if user_resp.status_code != 200:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to fetch Google user info.",
        )

    google_user = user_resp.json()

    user = find_or_create_oauth_user(
        db,
        email=google_user["email"],
        full_name=google_user.get("name", "Google User"),
        provider="google",
        provider_id=google_user["id"],
        picture_url=google_user.get("picture"),
    )

    # Generate JWT tokens and redirect to frontend
    token_payload = {"sub": user.id, "role": user.role}
    jwt_access = create_access_token(token_payload)
    jwt_refresh = create_refresh_token(token_payload)

    # Redirect to frontend with tokens as query params
    redirect_url = (
        f"{settings.FRONTEND_URL}/index.html"
        f"?access_token={jwt_access}"
        f"&refresh_token={jwt_refresh}"
    )
    return RedirectResponse(url=redirect_url)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  OAuth — GitHub
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


@router.get(
    "/oauth/github",
    summary="Redirect to GitHub OAuth",
)
def github_oauth_redirect():
    """Redirect the user to GitHub's OAuth authorization page."""
    if not settings.GITHUB_CLIENT_ID:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail="GitHub OAuth is not configured. Set GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET in .env",
        )

    params = urlencode({
        "client_id": settings.GITHUB_CLIENT_ID,
        "redirect_uri": settings.GITHUB_REDIRECT_URI,
        "scope": "user:email read:user",
    })
    return RedirectResponse(
        url=f"https://github.com/login/oauth/authorize?{params}"
    )


@router.get(
    "/oauth/github/callback",
    summary="GitHub OAuth callback",
)
async def github_oauth_callback(code: str, db: Session = Depends(get_db)):
    """
    Handle the GitHub OAuth callback.
    Exchanges the authorization code for an access token, fetches user info,
    and creates or links the account.
    """
    # Exchange code for access token
    async with httpx.AsyncClient() as client:
        token_resp = await client.post(
            "https://github.com/login/oauth/access_token",
            json={
                "client_id": settings.GITHUB_CLIENT_ID,
                "client_secret": settings.GITHUB_CLIENT_SECRET,
                "code": code,
                "redirect_uri": settings.GITHUB_REDIRECT_URI,
            },
            headers={"Accept": "application/json"},
        )

    if token_resp.status_code != 200:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to exchange GitHub authorization code.",
        )

    token_data = token_resp.json()
    access_token = token_data.get("access_token")

    if not access_token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="GitHub did not return an access token.",
        )

    # Fetch user info
    async with httpx.AsyncClient() as client:
        user_resp = await client.get(
            "https://api.github.com/user",
            headers={
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/vnd.github+json",
            },
        )

        # Get primary email (may be private)
        email_resp = await client.get(
            "https://api.github.com/user/emails",
            headers={
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/vnd.github+json",
            },
        )

    if user_resp.status_code != 200:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to fetch GitHub user info.",
        )

    github_user = user_resp.json()

    # Find primary verified email
    email = github_user.get("email")
    if not email and email_resp.status_code == 200:
        emails = email_resp.json()
        for e in emails:
            if e.get("primary") and e.get("verified"):
                email = e["email"]
                break

    if not email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Could not retrieve a verified email from GitHub.",
        )

    user = find_or_create_oauth_user(
        db,
        email=email,
        full_name=github_user.get("name") or github_user.get("login", "GitHub User"),
        provider="github",
        provider_id=str(github_user["id"]),
        picture_url=github_user.get("avatar_url"),
    )

    # Generate JWT tokens and redirect to frontend
    token_payload = {"sub": user.id, "role": user.role}
    jwt_access = create_access_token(token_payload)
    jwt_refresh = create_refresh_token(token_payload)

    redirect_url = (
        f"{settings.FRONTEND_URL}/index.html"
        f"?access_token={jwt_access}"
        f"&refresh_token={jwt_refresh}"
    )
    return RedirectResponse(url=redirect_url)
