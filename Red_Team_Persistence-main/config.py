"""
Project configuration for the defensive listener lab.
"""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
SERVER_DIR = BASE_DIR / "server"
AGENT_DIR = BASE_DIR / "agent"
WEB_DIR = BASE_DIR / "web"

SERVER_HOST = os.getenv("LAB_SERVER_HOST", "127.0.0.1")
SERVER_PORT = int(os.getenv("LAB_SERVER_PORT", "8000"))
DEBUG = os.getenv("LAB_DEBUG", "False") == "True"

USE_SSL = os.getenv("LAB_USE_SSL", "False") == "True"
CERT_FILE = os.getenv("LAB_CERT_FILE", "")
KEY_FILE = os.getenv("LAB_KEY_FILE", "")

JWT_SECRET = os.getenv("LAB_JWT_SECRET", "change-this-secret-in-local-labs")
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = 24

AGENT_BEACON_INTERVAL = int(os.getenv("AGENT_BEACON_INTERVAL", "5"))
AGENT_JITTER = float(os.getenv("AGENT_JITTER", "0.2"))
MAX_AGENT_TIMEOUT = int(os.getenv("MAX_AGENT_TIMEOUT", "60"))

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
LOG_FILE = os.getenv("LOG_FILE", str(BASE_DIR / "logs" / "listener_lab.log"))

Path(BASE_DIR / "logs").mkdir(exist_ok=True)
