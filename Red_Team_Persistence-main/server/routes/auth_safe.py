"""
Authentication and registration routes for the defensive listener lab.
"""
import os
import sys
from typing import Optional

from fastapi import APIRouter, Header, HTTPException, status

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from middleware.auth import api_key_manager, jwt_manager
from models import RegisterAgentRequest, RegisterAgentResponse
from modules.listener_runtime import listener_manager


router = APIRouter(prefix="/api/auth", tags=["authentication"])


def _build_agent_id(request: RegisterAgentRequest) -> str:
    hostname = (request.hostname or "sim-host").strip().replace(" ", "_")
    username = (request.username or "user").strip().replace(" ", "_")
    return f"sim_{hostname}_{username}_{request.process_id}"


@router.post("/register", response_model=RegisterAgentResponse)
async def register_agent(request: RegisterAgentRequest):
    listener = listener_manager.get_listener(request.listener_id)
    if not listener:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Listener not found")
    if listener.get("status") != "online":
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Listener is offline")

    payload = {
        "agent_id": _build_agent_id(request),
        "listener_id": request.listener_id,
        "hostname": request.hostname,
        "username": request.username,
        "process_id": request.process_id,
        "system_info": request.system_info.model_dump(),
        "agent_version": request.agent_version,
        "privileges": request.privileges,
        "operating_system": request.operating_system,
        "event_type": "registration",
        "signal": "registration",
    }
    ack = listener_manager.register_simulated_agent(request.listener_id, payload)
    jitter = float((listener.get("config", {}).get("beacon_config", {}) or {}).get("jitter", 0.0))
    return RegisterAgentResponse(
        agent_id=ack["agent_id"],
        status="registered",
        sleep_interval=int(listener.get("beacon_interval", 5)),
        jitter=jitter,
    )


@router.post("/login")
async def login(username: str, password: str):
    if username == "admin" and password == "password":
        token = jwt_manager.create_token("op_1", username)
        return {
            "access_token": token,
            "token_type": "bearer",
            "operator_id": "op_1",
            "mode": "defensive-simulation",
        }
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")


@router.get("/verify")
async def verify_token(authorization: Optional[str] = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid authorization header",
        )

    token = authorization.replace("Bearer ", "")
    payload = jwt_manager.verify_token(token)
    return {
        "valid": True,
        "operator_id": payload.get("operator_id"),
        "username": payload.get("username"),
    }


@router.post("/agent/verify")
async def verify_agent_key(api_key: str):
    listener_id = api_key_manager.validate_agent_key(api_key)
    if listener_id:
        return {"valid": True, "listener_id": listener_id, "mode": "defensive-simulation"}
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key")
