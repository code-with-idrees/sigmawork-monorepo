# sigmawork-monorepo
AI-assisted professional networking and career growth platform built as a modular microservices architecture

# SigmaWork — Authentication Backend

AI-assisted professional networking platform. This module covers **Accounts and Authentication** (SRS §3.1).

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Framework | FastAPI (async) |
| Database | MySQL 8+ |
| ORM | SQLAlchemy 2.0 (async) |
| Auth | JWT (access + refresh tokens) |
| Passwords | bcrypt via passlib |
| OAuth | Google, GitHub (prepared) |

## Quick Start

### 1. Prerequisites

- **Python 3.10+** installed
- **MySQL 8+** installed and running
- Create the database:
  ```sql
  CREATE DATABASE sigmawork CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
  ```

### 2. Setup

```bash
# Clone and enter the project
cd Sigma-Intern

# Create virtual environment
python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # macOS/Linux

# Install dependencies
pip install -r requirements.txt

# Create .env from template
copy .env.example .env       # Windows
# cp .env.example .env       # macOS/Linux

# Edit .env with your MySQL credentials
```

### 3. Configure `.env`

Open `.env` and set your MySQL credentials:

```env
DATABASE_URL=mysql+aiomysql://root:YOUR_PASSWORD@localhost:3306/sigmawork
JWT_SECRET_KEY=generate-a-random-64-char-string-here
```

### 4. Run

```bash
uvicorn app.main:app --reload
```

The server starts at **http://localhost:8000**:
- 🌐 **Frontend**: http://localhost:8000/
- 📚 **API Docs**: http://localhost:8000/docs
- 📝 **ReDoc**: http://localhost:8000/redoc

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/auth/register` | Create account |
| `POST` | `/api/auth/login` | Login → JWT tokens |
| `POST` | `/api/auth/logout` | Logout (discard tokens) |
| `POST` | `/api/auth/forgot-password` | Request password reset |
| `POST` | `/api/auth/reset-password` | Reset password with token |
| `GET`  | `/api/auth/me` | Get current user |
| `DELETE` | `/api/auth/me` | Delete account |
| `GET`  | `/api/auth/me/export` | Export your data |
| `GET`  | `/api/auth/oauth/google` | Google OAuth redirect |
| `GET`  | `/api/auth/oauth/google/callback` | Google callback |
| `GET`  | `/api/auth/oauth/github` | GitHub OAuth redirect |
| `GET`  | `/api/auth/oauth/github/callback` | GitHub callback |

## Setting Up OAuth (Optional)

### Google

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a project → Enable Google+ API
3. Create OAuth 2.0 credentials (Web application)
4. Set redirect URI: `http://localhost:8000/api/auth/oauth/google/callback`
5. Copy Client ID and Secret to `.env`

### GitHub

1. Go to [GitHub Developer Settings](https://github.com/settings/developers)
2. Create a new OAuth App
3. Set callback URL: `http://localhost:8000/api/auth/oauth/github/callback`
4. Copy Client ID and Secret to `.env`

## Project Structure

```
Sigma-Intern/
├── app/
│   ├── main.py              # FastAPI entrypoint
│   ├── config.py            # Settings from .env
│   ├── database.py          # Async SQLAlchemy engine
│   ├── dependencies.py      # get_db, get_current_user
│   ├── models/
│   │   └── user.py          # User model (roles, OAuth, soft delete)
│   ├── schemas/
│   │   └── auth.py          # Request/response validation
│   ├── routers/
│   │   └── auth.py          # API endpoints
│   ├── services/
│   │   └── auth_service.py  # Business logic
│   └── utils/
│       ├── security.py      # Hashing + JWT
│       └── validators.py    # Password strength
├── frontend/
│   ├── index.html           # Login page
│   ├── signup.html          # Registration page
│   ├── forgot-password.html # Password reset page
│   ├── css/style.css        # Styling
│   └── js/auth.js           # Frontend logic
├── requirements.txt
├── .env.example
└── README.md
```
