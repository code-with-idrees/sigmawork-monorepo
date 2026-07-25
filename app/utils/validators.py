"""
SigmaWork — Input validators.

Password strength rules per SRS §3.1:
  "Passwords must meet a minimum strength requirement, at minimum a set
   length combined with a mix of character types, and the system must
   reject registration if this is not met."
"""

import re
from typing import Optional


def validate_password_strength(password: str) -> Optional[str]:
    """
    Validate password meets strength requirements.

    Rules:
      - At least 8 characters long
      - Contains at least one uppercase letter
      - Contains at least one lowercase letter
      - Contains at least one digit
      - Contains at least one special character (!@#$%^&*…)

    Returns:
        None if the password is strong enough,
        or a human-readable error string explaining what's missing.
    """
    if len(password) < 8:
        return "Password must be at least 8 characters long."

    if not re.search(r"[A-Z]", password):
        return "Password must contain at least one uppercase letter."

    if not re.search(r"[a-z]", password):
        return "Password must contain at least one lowercase letter."

    if not re.search(r"\d", password):
        return "Password must contain at least one digit."

    if not re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?`~]", password):
        return "Password must contain at least one special character."

    return None  # Password is valid
