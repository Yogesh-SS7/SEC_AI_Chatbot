"""
config.py — Centralized application configuration.

All settings are loaded from environment variables (populated by .env via
python-dotenv).  No raw strings or magic values should appear in main.py.
"""

import os
import logging
from pathlib import Path
from dotenv import load_dotenv

# ── Load .env before anything else ────────────────────────────────────────────
load_dotenv()

# ── Paths ─────────────────────────────────────────────────────────────────────
BASE_DIR: Path = Path(__file__).resolve().parent

# Upload directory — resolved to an absolute path to prevent traversal
_raw_upload_dir = os.getenv("UPLOAD_DIR", "uploads")
UPLOAD_DIR: Path = (BASE_DIR / _raw_upload_dir).resolve()

# ── Ollama / AI ────────────────────────────────────────────────────────────────
OLLAMA_URL: str = os.getenv("OLLAMA_URL", "http://localhost:11434/api/chat")
MODEL_NAME: str = os.getenv("MODEL_NAME", "llama3.2")
ACTIVE_PROMPT_FILE: str = os.getenv("ACTIVE_PROMPT_FILE", "secure_system_prompt.txt")

# ── Server ─────────────────────────────────────────────────────────────────────
HOST: str = os.getenv("HOST", "0.0.0.0")
PORT: int = int(os.getenv("PORT", "8000"))

# ── JWT Authentication ─────────────────────────────────────────────────────────
JWT_SECRET_KEY: str = os.getenv("JWT_SECRET_KEY", "")
JWT_ALGORITHM: str = os.getenv("JWT_ALGORITHM", "HS256")
JWT_EXPIRE_MINUTES: int = int(os.getenv("JWT_EXPIRE_MINUTES", "60"))

# ── App Credentials ────────────────────────────────────────────────────────────
APP_USERNAME: str = os.getenv("APP_USERNAME", "")
APP_PASSWORD: str = os.getenv("APP_PASSWORD", "")

# ── Logging ────────────────────────────────────────────────────────────────────
LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO").upper()
