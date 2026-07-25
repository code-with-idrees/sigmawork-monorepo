"""
SigmaWork — App configuration.
Loads all settings from .env using pydantic-settings.
"""

from pathlib import Path
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # ── Database ──────────────────────────────────────────
    # SQL Server connection via pyodbc (Windows Auth)
    DB_SERVER: str = "localhost\\SQLEXPRESS"
    DB_NAME: str = "sigmawork"
    DB_DRIVER: str = "ODBC Driver 18 for SQL Server"
    DB_TRUSTED_CONNECTION: str = "yes"
    DB_TRUST_CERT: str = "yes"

    # ── JWT ───────────────────────────────────────────────
    JWT_SECRET_KEY: str = "change-this-to-a-long-random-string"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # ── OAuth — Google ────────────────────────────────────
    GOOGLE_CLIENT_ID: str = ""
    GOOGLE_CLIENT_SECRET: str = ""
    GOOGLE_REDIRECT_URI: str = "http://localhost:8000/api/auth/oauth/google/callback"

    # ── OAuth — GitHub ────────────────────────────────────
    GITHUB_CLIENT_ID: str = ""
    GITHUB_CLIENT_SECRET: str = ""
    GITHUB_REDIRECT_URI: str = "http://localhost:8000/api/auth/oauth/github/callback"

    # ── App ───────────────────────────────────────────────
    FRONTEND_URL: str = "http://localhost:8000"
    APP_ENV: str = "development"

    @property
    def DATABASE_URL(self) -> str:
        """Build the SQLAlchemy connection string for SQL Server."""
        from urllib.parse import quote_plus
        conn_str = (
            f"DRIVER={{{self.DB_DRIVER}}};"
            f"SERVER={self.DB_SERVER};"
            f"DATABASE={self.DB_NAME};"
            f"Trusted_Connection={self.DB_TRUSTED_CONNECTION};"
            f"TrustServerCertificate={self.DB_TRUST_CERT};"
        )
        return f"mssql+pyodbc:///?odbc_connect={quote_plus(conn_str)}"

    model_config = {
        "env_file": str(Path(__file__).resolve().parent.parent / ".env"),
        "env_file_encoding": "utf-8",
        "extra": "ignore",
    }


settings = Settings()
