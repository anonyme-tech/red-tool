"""
Authentication helpers for the defensive listener lab.
"""
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional
import uuid

import jwt
from fastapi import HTTPException, status


class JWTManager:
    """Minimal JWT helper for local UI and API access."""

    SECRET_KEY = "your-secret-key-change-this-in-production"
    ALGORITHM = "HS256"
    TOKEN_EXPIRE_MINUTES = 1440

    @staticmethod
    def utcnow() -> datetime:
        return datetime.now(timezone.utc)

    @staticmethod
    def create_token(operator_id: str, username: str) -> str:
        """Create a JWT token."""
        payload = {
            "operator_id": operator_id,
            "username": username,
            "exp": JWTManager.utcnow() + timedelta(minutes=JWTManager.TOKEN_EXPIRE_MINUTES),
            "iat": JWTManager.utcnow(),
        }
        return jwt.encode(payload, JWTManager.SECRET_KEY, algorithm=JWTManager.ALGORITHM)

    @staticmethod
    def verify_token(token: str) -> Optional[Dict]:
        """Validate and decode a JWT token."""
        try:
            return jwt.decode(token, JWTManager.SECRET_KEY, algorithms=[JWTManager.ALGORITHM])
        except jwt.ExpiredSignatureError as exc:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired") from exc
        except jwt.InvalidTokenError as exc:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token") from exc


class APIKeyManager:
    """Simple in-memory API key registry for simulated agents."""

    def __init__(self):
        self.api_keys: Dict[str, Dict] = {
            "agent_default_key": {
                "listener_id": "listener_1",
                "active": True,
                "created": JWTManager.utcnow(),
            }
        }

    def generate_agent_key(self, listener_id: str) -> str:
        """Generate an agent API key."""
        key = f"agent_{uuid.uuid4().hex[:16]}"
        self.api_keys[key] = {
            "listener_id": listener_id,
            "active": True,
            "created": JWTManager.utcnow(),
        }
        return key

    def validate_agent_key(self, api_key: str) -> Optional[str]:
        """Validate an API key and return the listener id."""
        key_data = self.api_keys.get(api_key)
        if key_data and key_data.get("active"):
            return key_data.get("listener_id")
        return None

    def revoke_key(self, api_key: str):
        """Revoke an API key."""
        if api_key in self.api_keys:
            self.api_keys[api_key]["active"] = False


jwt_manager = JWTManager()
api_key_manager = APIKeyManager()
