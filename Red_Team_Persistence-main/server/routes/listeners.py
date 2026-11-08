"""
Routes de gestion des listeners C2
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from fastapi import APIRouter, HTTPException, status, Body, Query
from typing import List, Dict, Any, Optional
from datetime import datetime
import json
import uuid

from modules import C2Database
from modules.listener_manager import ListenerManager, ListenerStatus
from models.listener import CreateListenerRequest, UpdateListenerRequest
from models.listener_profiles import PROFILES_MAP, ProfileType

router = APIRouter(prefix="/api/listeners", tags=["listeners"])
db = C2Database()
manager = ListenerManager()
_hydrated = False


def _hydrate_manager_from_db() -> None:
    """Charge les listeners persistés (SQLite) dans le ListenerManager (mémoire)."""
    global _hydrated
    if _hydrated:
        return
    try:
        for l in db.get_all_listeners():
            cfg = {
                "listener_id": l.get("listener_id"),
                "name": l.get("name"),
                "protocol": l.get("protocol"),
                "host": l.get("host"),
                "port": l.get("port"),
                "profile": l.get("profile") or "custom",
                "enabled": bool(l.get("enabled")),
                "use_ssl": bool(l.get("use_ssl")),
                "cert_file": l.get("cert_file"),
                "key_file": l.get("key_file"),
                "user_agent": l.get("user_agent"),
                "callback_path": l.get("callback_path"),
                "beacon_interval": l.get("beacon_interval"),
                "domain_front": l.get("domain_front"),
                "http_headers": l.get("http_headers") or {},
                "metadata": l.get("metadata") or {},
            }
            # Full v2 config blob is stored in listeners.config
            if l.get("config"):
                cfg.update(l.get("config") if isinstance(l.get("config"), dict) else {})

            created = manager.create_listener(cfg, skip_validation=True)
            # mirror persisted status/stats/errors if present
            if l.get("status"):
                created["status"] = l.get("status")
            if l.get("stats"):
                created["stats"] = l.get("stats")
            if l.get("errors"):
                created["errors"] = l.get("errors")
    finally:
        _hydrated = True


@router.get("/", response_model=List[dict])
async def list_listeners():
    """Liste tous les listeners configurés"""
    _hydrate_manager_from_db()
    return db.get_all_listeners()


@router.get("/{listener_id}", response_model=dict)
async def get_listener(listener_id: str):
    """Récupère un listener"""
    _hydrate_manager_from_db()
    l = db.get_listener(listener_id)
    if not l:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Listener not found")
    return l


@router.post("/", response_model=dict)
async def create_listener(request: CreateListenerRequest):
    """Crée un nouveau listener (v2 compatible)"""
    _hydrate_manager_from_db()

    listener_id = f"listener_{uuid.uuid4().hex[:8]}"
    protocol = request.protocol.value if hasattr(request.protocol, "value") else str(request.protocol)
    profile = request.profile.value if hasattr(request.profile, "value") else str(request.profile)

    # Base config understood by ListenerManager
    listener_config: Dict[str, Any] = {
        "listener_id": listener_id,
        "name": request.name,
        "protocol": protocol,
        "host": request.host,
        "port": request.port,
        "profile": profile,
        "enabled": request.enabled,
        "use_ssl": request.use_ssl,
        "cert_file": request.cert_file,
        "key_file": request.key_file,
        "user_agent": request.user_agent or "Mozilla/5.0",
        "callback_path": request.callback_path or "/api/beacon",
        "beacon_interval": request.beacon_interval or 5,
        "domain_front": request.domain_front,
        "http_headers": request.http_headers or {},
        "metadata": request.metadata or {},
    }
    # v2 nested config blob
    if request.config:
        listener_config["config"] = request.config

    try:
        created_listener = manager.create_listener(listener_config)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    # Persist essential fields + v2 blobs
    listener_data = {
        "listener_id": created_listener["listener_id"],
        "name": created_listener["name"],
        "protocol": created_listener["protocol"],
        "host": created_listener["host"],
        "port": created_listener["port"],
        "profile": created_listener.get("profile", profile),
        "enabled": bool(created_listener.get("enabled", True)),
        "use_ssl": bool(listener_config.get("use_ssl", True)),
        "cert_file": listener_config.get("cert_file"),
        "key_file": listener_config.get("key_file"),
        "user_agent": listener_config.get("user_agent"),
        "callback_path": listener_config.get("callback_path"),
        "beacon_interval": listener_config.get("beacon_interval", 5),
        "domain_front": listener_config.get("domain_front"),
        "http_headers": listener_config.get("http_headers", {}),
        "metadata": listener_config.get("metadata", {}),
        "agents_connected": 0,
        "status": created_listener.get("status", ListenerStatus.ONLINE.value),
        "last_modified": datetime.utcnow().isoformat(),
        "config": created_listener.get("config", {}),
        "stats": created_listener.get("stats", {}),
        "errors": created_listener.get("errors", []),
    }

    ok = db.add_listener(listener_data)
    if not ok:
        manager.delete_listener(created_listener["listener_id"])
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to create listener")

    return db.get_listener(listener_id) or listener_data


@router.put("/{listener_id}", response_model=dict)
async def update_listener(listener_id: str, request: UpdateListenerRequest):
    """Met à jour un listener existant (v2)"""
    _hydrate_manager_from_db()
    existing = db.get_listener(listener_id)
    if not existing:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Listener not found")

    updates: Dict[str, Any] = {}
    for field in [
        "name", "enabled", "beacon_interval", "domain_front", "user_agent", "callback_path",
        "cert_file", "key_file"
    ]:
        v = getattr(request, field, None)
        if v is not None:
            updates[field] = v

    if request.protocol is not None:
        updates["protocol"] = request.protocol.value if hasattr(request.protocol, "value") else str(request.protocol)
    if request.host is not None:
        updates["host"] = request.host
    if request.port is not None:
        updates["port"] = request.port
    if request.use_ssl is not None:
        updates["use_ssl"] = request.use_ssl
    if request.profile is not None:
        updates["profile"] = request.profile.value if hasattr(request.profile, "value") else str(request.profile)
    if request.http_headers is not None:
        updates["http_headers"] = request.http_headers
    if request.metadata is not None:
        updates["metadata"] = request.metadata
    if request.config is not None:
        updates["config"] = request.config

    # Validate and apply in manager (memory)
    try:
        if listener_id not in manager.listeners:
            # If manager wasn't hydrated with this id, load it now without validation
            manager.create_listener(existing, skip_validation=True)
        manager.update_listener(listener_id, {"config": updates.get("config")} if "config" in updates else updates)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    updates["last_modified"] = datetime.utcnow().isoformat()

    ok = db.update_listener(listener_id, updates)
    if not ok:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to update listener")
    return db.get_listener(listener_id) or {"listener_id": listener_id, **updates}


@router.delete("/{listener_id}", response_model=dict)
async def delete_listener(listener_id: str):
    """Supprime un listener"""
    _hydrate_manager_from_db()
    existing = db.get_listener(listener_id)
    if not existing:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Listener not found")

    ok = db.delete_listener(listener_id)
    if not ok:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to delete listener")
    try:
        if manager.get_listener(listener_id):
            manager.delete_listener(listener_id)
    except Exception:
        pass
    return {"status": "deleted", "listener_id": listener_id}


# ----------------------------
# v2 operations (start/stop)
# ----------------------------
@router.post("/{listener_id}/start", response_model=dict)
async def start_listener(listener_id: str):
    _hydrate_manager_from_db()
    l = db.get_listener(listener_id)
    if not l:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Listener not found")
    try:
        if not manager.get_listener(listener_id):
            manager.create_listener(l, skip_validation=True)
        manager.start_listener(listener_id)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    db.update_listener(listener_id, {"status": ListenerStatus.ONLINE.value, "enabled": True, "last_modified": datetime.utcnow().isoformat()})
    return db.get_listener(listener_id) or {"listener_id": listener_id, "status": "online"}


@router.post("/{listener_id}/stop", response_model=dict)
async def stop_listener(listener_id: str):
    _hydrate_manager_from_db()
    l = db.get_listener(listener_id)
    if not l:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Listener not found")
    try:
        if not manager.get_listener(listener_id):
            manager.create_listener(l, skip_validation=True)
        manager.stop_listener(listener_id)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    db.update_listener(listener_id, {"status": ListenerStatus.OFFLINE.value, "enabled": False, "last_modified": datetime.utcnow().isoformat()})
    return db.get_listener(listener_id) or {"listener_id": listener_id, "status": "offline"}


@router.post("/{listener_id}/restart", response_model=dict)
async def restart_listener(listener_id: str):
    await stop_listener(listener_id)
    return await start_listener(listener_id)


# ----------------------------
# v2 stats / errors / summary
# ----------------------------
@router.get("/{listener_id}/stats", response_model=dict)
async def get_listener_stats(listener_id: str):
    _hydrate_manager_from_db()
    l = db.get_listener(listener_id)
    if not l:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Listener not found")
    stats = manager.get_listener_stats(listener_id) if manager.get_listener(listener_id) else l.get("stats") or {}
    endpoint = f"{l.get('protocol')}://{l.get('host')}:{l.get('port')}"
    return {"listener_id": listener_id, "name": l.get("name"), "endpoint": endpoint, "stats": stats}


@router.post("/{listener_id}/stats/update", response_model=dict)
async def update_listener_stats(listener_id: str, stats_update: Dict[str, Any] = Body(...)):
    _hydrate_manager_from_db()
    l = db.get_listener(listener_id)
    if not l:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Listener not found")
    if not manager.get_listener(listener_id):
        manager.create_listener(l, skip_validation=True)
    ok = manager.update_listener_stats(listener_id, stats_update)
    if not ok:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Failed to update stats")
    stats = manager.get_listener_stats(listener_id) or {}
    db.update_listener(listener_id, {"stats": stats, "last_modified": datetime.utcnow().isoformat()})
    return {"listener_id": listener_id, "stats": stats}


@router.get("/{listener_id}/errors", response_model=dict)
async def get_listener_errors(listener_id: str, limit: int = Query(20, ge=1, le=200)):
    _hydrate_manager_from_db()
    l = db.get_listener(listener_id)
    if not l:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Listener not found")
    if not manager.get_listener(listener_id):
        manager.create_listener(l, skip_validation=True)
    errs = manager.get_listener_errors(listener_id) or []
    return {"listener_id": listener_id, "errors": errs[-limit:]}


@router.post("/{listener_id}/errors/add", response_model=dict)
async def add_listener_error(listener_id: str, payload: Dict[str, Any] = Body(...)):
    _hydrate_manager_from_db()
    l = db.get_listener(listener_id)
    if not l:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Listener not found")
    message = (payload.get("message") or "").strip()
    if not message:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Missing 'message'")
    if not manager.get_listener(listener_id):
        manager.create_listener(l, skip_validation=True)
    manager.add_listener_error(listener_id, message)
    errors = manager.get_listener_errors(listener_id) or []
    stats = manager.get_listener_stats(listener_id) or {}
    db.update_listener(listener_id, {"errors": errors, "stats": stats, "last_modified": datetime.utcnow().isoformat()})
    return {"status": "ok", "listener_id": listener_id}


@router.get("/status/summary", response_model=dict)
async def listeners_summary():
    _hydrate_manager_from_db()
    return manager.get_summary()


@router.get("/history", response_model=List[dict])
async def listeners_history(limit: int = Query(50, ge=1, le=500)):
    _hydrate_manager_from_db()
    return manager.get_history(limit=limit)


# ----------------------------
# v2 randomization helpers
# ----------------------------
@router.get("/{listener_id}/user-agent", response_model=dict)
async def get_random_user_agent(listener_id: str):
    _hydrate_manager_from_db()
    l = db.get_listener(listener_id)
    if not l:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Listener not found")
    if not manager.get_listener(listener_id):
        manager.create_listener(l, skip_validation=True)
    return {"listener_id": listener_id, "user_agent": manager.get_random_user_agent(listener_id)}


@router.get("/{listener_id}/uri", response_model=dict)
async def get_random_uri(listener_id: str):
    _hydrate_manager_from_db()
    l = db.get_listener(listener_id)
    if not l:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Listener not found")
    if not manager.get_listener(listener_id):
        manager.create_listener(l, skip_validation=True)
    return {"listener_id": listener_id, "uri": manager.get_random_uri(listener_id)}


@router.get("/{listener_id}/headers", response_model=dict)
async def get_headers(listener_id: str):
    _hydrate_manager_from_db()
    l = db.get_listener(listener_id)
    if not l:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Listener not found")
    if not manager.get_listener(listener_id):
        manager.create_listener(l, skip_validation=True)
    return {"listener_id": listener_id, "headers": manager.get_random_http_header(listener_id)}


# ----------------------------
# v2 profiles + import/export
# ----------------------------
@router.get("/profiles/list", response_model=List[dict])
async def list_profiles():
    out = []
    for ptype, prof in PROFILES_MAP.items():
        out.append({
            "type": ptype.value,
            "profile_id": prof.profile_id,
            "profile_name": prof.profile_name,
            "description": prof.description,
        })
    return out


@router.get("/profiles/{profile_type}", response_model=dict)
async def get_profile(profile_type: str):
    try:
        p = ProfileType(profile_type)
    except Exception:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Unknown profile type")
    prof = PROFILES_MAP.get(p)
    if not prof:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Profile not found")
    return json.loads(prof.model_dump_json())


@router.post("/profiles/apply/{profile_type}/{listener_id}", response_model=dict)
async def apply_profile(profile_type: str, listener_id: str):
    _hydrate_manager_from_db()
    l = db.get_listener(listener_id)
    if not l:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Listener not found")
    try:
        p = ProfileType(profile_type)
    except Exception:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Unknown profile type")
    prof = PROFILES_MAP.get(p)
    if not prof:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Profile not found")

    prof_dict = json.loads(prof.model_dump_json())
    # store under config.* to match listener_manager expectations (http_config/user_agents/uris/headers/etc.)
    cfg_blob = l.get("config") or {}
    cfg_blob.update({
        "http_config": prof_dict.get("http_config", {}),
        "response_config": prof_dict.get("response_config", {}),
        "beacon_config": prof_dict.get("beacon_config", {}),
        "encryption_config": prof_dict.get("encryption_config", {}),
        "ssl_config": prof_dict.get("ssl_config", {}),
        "proxy_config": prof_dict.get("proxy_config", {}),
        "domain_fronting_config": prof_dict.get("domain_fronting_config", {}),
        "profile_type": prof_dict.get("profile_type"),
        "profile_id": prof_dict.get("profile_id"),
        "profile_name": prof_dict.get("profile_name"),
    })
    db.update_listener(listener_id, {"profile": profile_type, "config": cfg_blob, "last_modified": datetime.utcnow().isoformat()})
    if not manager.get_listener(listener_id):
        manager.create_listener({**l, "config": cfg_blob, "profile": profile_type}, skip_validation=True)
    else:
        manager.update_listener(listener_id, {"config": cfg_blob, "profile": profile_type})
    return db.get_listener(listener_id) or {"listener_id": listener_id, "profile": profile_type}


@router.get("/{listener_id}/export", response_model=dict)
async def export_listener(listener_id: str):
    _hydrate_manager_from_db()
    l = db.get_listener(listener_id)
    if not l:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Listener not found")
    if not manager.get_listener(listener_id):
        manager.create_listener(l, skip_validation=True)
    raw = manager.export_listener_profile(listener_id)
    return {"listener_id": listener_id, "profile_json": raw}


@router.post("/import", response_model=dict)
async def import_listener(payload: Dict[str, Any] = Body(...)):
    _hydrate_manager_from_db()
    profile_json = payload.get("profile_json")
    if not isinstance(profile_json, str) or not profile_json.strip():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Missing 'profile_json'")
    try:
        imported = manager.import_listener_profile(profile_json)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    # persist imported (ensure id unique)
    listener_id = imported.get("listener_id") or f"listener_{uuid.uuid4().hex[:8]}"
    if db.get_listener(listener_id):
        listener_id = f"listener_{uuid.uuid4().hex[:8]}"
        imported["listener_id"] = listener_id
        manager.listeners[listener_id] = imported

    listener_data = {
        "listener_id": listener_id,
        "name": imported.get("name", f"Listener_{listener_id}"),
        "protocol": imported.get("protocol", "https"),
        "host": imported.get("host", "0.0.0.0"),
        "port": imported.get("port", 443),
        "profile": imported.get("profile", "custom"),
        "enabled": bool(imported.get("enabled", True)),
        "use_ssl": bool(imported.get("config", {}).get("use_ssl", True)) if isinstance(imported.get("config"), dict) else True,
        "cert_file": None,
        "key_file": None,
        "user_agent": (imported.get("config", {}) or {}).get("user_agent", "Mozilla/5.0") if isinstance(imported.get("config"), dict) else "Mozilla/5.0",
        "callback_path": (imported.get("config", {}) or {}).get("callback_path", "/api/beacon") if isinstance(imported.get("config"), dict) else "/api/beacon",
        "beacon_interval": (imported.get("config", {}) or {}).get("beacon_interval", 5) if isinstance(imported.get("config"), dict) else 5,
        "domain_front": None,
        "http_headers": {},
        "metadata": {},
        "agents_connected": 0,
        "status": imported.get("status", ListenerStatus.ONLINE.value),
        "last_modified": datetime.utcnow().isoformat(),
        "config": imported.get("config", {}),
        "stats": imported.get("stats", {}),
        "errors": imported.get("errors", []),
    }

    ok = db.add_listener(listener_data)
    if not ok:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to persist imported listener")
    return db.get_listener(listener_id) or listener_data

