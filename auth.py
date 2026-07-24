"""
auth.py — JWT authentication utilities.

Phase 2 hardening:
  ✅ Token creation with expiry
  ✅ Token validation as a FastAPI dependency
  ✅ 401 Unauthorized returned for missing / invalid / expired tokens
"""

from datetime import datetime, timedelta, timezone

import jwt
from jwt.exceptions import InvalidTokenError
# pyrefly: ignore [missing-import]
from fastapi import Depends, HTTPException, status
# pyrefly: ignore [missing-import]
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from config import JWT_SECRET_KEY, JWT_ALGORITHM, JWT_EXPIRE_MINUTES
from logger import log

# ── Bearer token extractor ─────────────────────────────────────────────────────
_bearer = HTTPBearer()


def create_access_token(subject: str) -> str:
    """
    Create a signed JWT that expires after JWT_EXPIRE_MINUTES.

    :param subject: Typically the username being authenticated.
    :returns: Encoded JWT string.
    """
    expire = datetime.now(timezone.utc) + timedelta(minutes=JWT_EXPIRE_MINUTES)
    payload = {"sub": subject, "exp": expire}
    token = jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    log.info("Access token created", extra={"subject": subject,
                                             "expires_at": expire.isoformat()})
    return token


def verify_token(
    credentials: HTTPAuthorizationCredentials = Depends(_bearer),
) -> str:
    """
    FastAPI dependency — validates the Bearer JWT on every protected request.

    :returns: The subject (username) from the token if valid.
    :raises HTTPException 401: If the token is missing, invalid, or expired.
    """
    token = credentials.credentials
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired token.",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        subject: str = payload.get("sub", "")
        if not subject:
            log.warning("JWT missing 'sub' claim")
            raise credentials_exception
        log.info("Token verified", extra={"subject": subject})
        return subject
    except InvalidTokenError as exc:
        log.warning("JWT validation failed", extra={"reason": str(exc)})
        raise credentials_exception
