"""
Safe listener routes for the localhost-only defensive lab.
"""
import hashlib
import json
import os
import sys
import uuid
from typing import Any, Dict, List

from fastapi import APIRouter, Body, HTTPException, Query, status

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from models.listener import CreateListenerRequest, UpdateListenerRequest
from models.listener_profiles import PROFILES_MAP, ProfileType
from modules.database_runtime import audit_db
from modules.listener_lab import ListenerStatus
from modules.listener_runtime import listener_manager


router = APIRouter(prefix="/api/listeners", tags=["listeners"])
manager = listener_manager


def _listener_or_404(listener_id: str) -> Dict[str, Any]:
    listener = manager.get_listener(listener_id)
    if not listener:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Listener not found")
    return listener


def _parse_report_json(report_json: str) -> Dict[str, Any]:
    try:
        parsed = json.loads(report_json)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid report_json") from exc

    if not isinstance(parsed, dict):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="report_json must decode to an object")
    return parsed


def _report_summary(report: Dict[str, Any]) -> tuple[int, str]:
    findings = report.get("findings")
    finding_count = report.get("findingCount")

    if not isinstance(finding_count, int):
        finding_count = len(findings) if isinstance(findings, list) else 0

    risk_level = str(report.get("riskLevel") or "UNKNOWN").upper()
    return finding_count, risk_level


def _report_list_item(report: Dict[str, Any]) -> Dict[str, Any]:
    summary = dict(report)
    summary.pop("report_json", None)
    return summary


def _build_listener_payload(request: CreateListenerRequest) -> Dict[str, Any]:
    profile = request.profile.value if hasattr(request.profile, "value") else str(request.profile)
    protocol = request.protocol.value if hasattr(request.protocol, "value") else str(request.protocol)
    return {
        "name": request.name,
        "protocol": protocol,
        "host": request.host,
        "port": request.port,
        "profile": profile,
        "enabled": request.enabled,
        "use_ssl": request.use_ssl,
        "cert_file": request.cert_file,
        "key_file": request.key_file,
        "user_agent": request.user_agent,
        "callback_path": request.callback_path,
        "beacon_interval": request.beacon_interval,
        "domain_front": request.domain_front,
        "http_headers": request.http_headers or {},
        "metadata": request.metadata or {},
        "config": request.config or {},
    }


@router.get("/status/summary", response_model=dict)
async def listeners_summary():
    return manager.get_summary()


@router.get("/history", response_model=List[dict])
async def listeners_history(
    limit: int = Query(50, ge=1, le=500),
    listener_id: str | None = Query(default=None),
):
    return manager.get_history(limit=limit, listener_id=listener_id)


@router.get("/profiles/list", response_model=List[dict])
async def list_profiles():
    out = []
    for ptype, prof in PROFILES_MAP.items():
        out.append(
            {
                "type": ptype.value,
                "profile_id": prof.profile_id,
                "profile_name": prof.profile_name,
                "description": prof.description,
            }
        )
    return out


@router.get("/profiles/{profile_type}", response_model=dict)
async def get_profile(profile_type: str):
    try:
        profile = PROFILES_MAP[ProfileType(profile_type)]
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Unknown profile type") from exc
    return json.loads(profile.model_dump_json())


@router.post("/import", response_model=dict)
async def import_listener(payload: Dict[str, Any] = Body(...)):
    profile_json = payload.get("profile_json")
    if not isinstance(profile_json, str) or not profile_json.strip():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Missing 'profile_json'")

    try:
        return manager.import_listener_profile(profile_json)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@router.get("/", response_model=List[dict])
async def list_listeners():
    return manager.list_listeners()


@router.post("/", response_model=dict)
async def create_listener(request: CreateListenerRequest):
    try:
        return manager.create_listener(_build_listener_payload(request))
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@router.get("/{listener_id}", response_model=dict)
async def get_listener(listener_id: str):
    return _listener_or_404(listener_id)


@router.put("/{listener_id}", response_model=dict)
async def update_listener(listener_id: str, request: UpdateListenerRequest):
    _listener_or_404(listener_id)

    updates: Dict[str, Any] = {}
    for field in [
        "name",
        "enabled",
        "beacon_interval",
        "domain_front",
        "user_agent",
        "callback_path",
        "cert_file",
        "key_file",
        "host",
        "port",
        "use_ssl",
        "http_headers",
        "metadata",
        "config",
    ]:
        value = getattr(request, field, None)
        if value is not None:
            updates[field] = value

    if request.protocol is not None:
        updates["protocol"] = request.protocol.value if hasattr(request.protocol, "value") else str(request.protocol)
    if request.profile is not None:
        updates["profile"] = request.profile.value if hasattr(request.profile, "value") else str(request.profile)

    try:
        return manager.update_listener(listener_id, updates)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@router.delete("/{listener_id}", response_model=dict)
async def delete_listener(listener_id: str):
    _listener_or_404(listener_id)
    manager.delete_listener(listener_id)
    return {"status": "deleted", "listener_id": listener_id}


@router.post("/{listener_id}/start", response_model=dict)
async def start_listener(listener_id: str):
    _listener_or_404(listener_id)
    try:
        return manager.start_listener(listener_id)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@router.post("/{listener_id}/stop", response_model=dict)
async def stop_listener(listener_id: str):
    _listener_or_404(listener_id)
    try:
        return manager.stop_listener(listener_id)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@router.post("/{listener_id}/restart", response_model=dict)
async def restart_listener(listener_id: str):
    _listener_or_404(listener_id)
    manager.stop_listener(listener_id)
    return manager.start_listener(listener_id)


@router.get("/{listener_id}/stats", response_model=dict)
async def get_listener_stats(listener_id: str):
    listener = _listener_or_404(listener_id)
    endpoint = f"{listener.get('protocol')}://{listener.get('host')}:{listener.get('port')}"
    return {
        "listener_id": listener_id,
        "name": listener.get("name"),
        "endpoint": endpoint,
        "mode": listener.get("mode"),
        "stats": manager.get_listener_stats(listener_id) or {},
    }


@router.post("/{listener_id}/stats/update", response_model=dict)
async def update_listener_stats(listener_id: str, stats_update: Dict[str, Any] = Body(...)):
    _listener_or_404(listener_id)
    ok = manager.update_listener_stats(listener_id, stats_update)
    if not ok:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Failed to update stats")
    return {"listener_id": listener_id, "stats": manager.get_listener_stats(listener_id) or {}}


@router.get("/{listener_id}/errors", response_model=dict)
async def get_listener_errors(listener_id: str, limit: int = Query(20, ge=1, le=200)):
    _listener_or_404(listener_id)
    errors = manager.get_listener_errors(listener_id)
    return {"listener_id": listener_id, "errors": errors[-limit:]}


@router.post("/{listener_id}/errors/add", response_model=dict)
async def add_listener_error(listener_id: str, payload: Dict[str, Any] = Body(...)):
    _listener_or_404(listener_id)
    message = str(payload.get("message") or "").strip()
    if not message:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Missing 'message'")
    manager.add_listener_error(listener_id, message)
    return {"status": "ok", "listener_id": listener_id}


@router.get("/{listener_id}/agents", response_model=dict)
async def list_listener_agents(listener_id: str):
    _listener_or_404(listener_id)
    agents = manager.list_simulated_agents(listener_id=listener_id)
    return {"listener_id": listener_id, "agents": agents, "total": len(agents)}


@router.get("/{listener_id}/activity", response_model=dict)
async def listener_activity(listener_id: str, limit: int = Query(25, ge=1, le=200)):
    _listener_or_404(listener_id)
    history = manager.get_history(limit=limit, listener_id=listener_id)
    return {"listener_id": listener_id, "events": history, "total": len(history)}


@router.post("/{listener_id}/heartbeat", response_model=dict)
async def record_listener_heartbeat(listener_id: str, payload: Dict[str, Any] = Body(...)):
    listener = _listener_or_404(listener_id)
    if listener.get("status") != ListenerStatus.ONLINE.value:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Listener is offline")
    try:
        return manager.record_heartbeat(listener_id, payload)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@router.post("/{listener_id}/audit-reports", response_model=dict)
async def ingest_audit_report(listener_id: str, payload: Dict[str, Any] = Body(...)):
    listener = _listener_or_404(listener_id)
    if listener.get("status") != ListenerStatus.ONLINE.value:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Listener is offline")

    report_json = payload.get("report_json")
    if not isinstance(report_json, str) or not report_json.strip():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Missing 'report_json'")

    metadata = payload.get("metadata") or {}
    if not isinstance(metadata, dict):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="'metadata' must be an object")

    report = _parse_report_json(report_json)
    finding_count, risk_level = _report_summary(report)
    system = report.get("system") if isinstance(report.get("system"), dict) else {}

    machine_name = str(payload.get("machine_name") or system.get("machineName") or payload.get("hostname") or "audit-host")
    username = str(payload.get("username") or system.get("userName") or "unknown")
    domain = str(payload.get("domain") or system.get("domain") or "WORKGROUP")
    operating_system = str(payload.get("operating_system") or system.get("osVersion") or "Windows")
    agent_id = str(payload.get("agent_id") or f"audit_{machine_name}_{username}").strip().replace(" ", "_")
    architecture = str(payload.get("architecture") or "x64")
    privileges = str(
        payload.get("privileges")
        or ("administrator" if bool(system.get("isAdministrator")) else "user")
    )

    try:
        process_id = int(payload.get("process_id") or 0)
        sleep_interval = int(payload.get("sleep_interval") or listener.get("beacon_interval") or 60)
        jitter = float(payload.get("jitter") or 0.0)
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid numeric audit payload field") from exc

    report_id = str(payload.get("report_id") or f"report_{uuid.uuid4().hex}")
    filename = str(payload.get("filename") or f"{report_id}.json")
    sha256 = hashlib.sha256(report_json.encode("utf-8")).hexdigest()

    stored = audit_db.add_audit_report(
        {
            "report_id": report_id,
            "listener_id": listener_id,
            "agent_id": agent_id,
            "machine_name": machine_name,
            "username": username,
            "filename": filename,
            "report_json": report_json,
            "finding_count": finding_count,
            "risk_level": risk_level,
            "sha256": sha256,
            "source": str(payload.get("source") or "myagent"),
            "metadata": {
                **metadata,
                "event_type": "audit_report",
            },
        }
    )
    if not stored:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to persist audit report")

    heartbeat_payload = {
        "agent_id": agent_id,
        "hostname": machine_name,
        "username": username,
        "process_id": process_id,
        "system_info": {
            "os": operating_system,
            "hostname": machine_name,
            "username": username,
            "domain": domain,
            "pid": process_id,
            "architecture": architecture,
            "privileges": privileges,
        },
        "agent_version": str(payload.get("agent_version") or "myagent-audit-1.0"),
        "privileges": privileges,
        "operating_system": operating_system,
        "event_type": "audit_report",
        "signal": "audit_report",
        "sleep_interval": sleep_interval,
        "jitter": jitter,
        "ip_address": str(payload.get("ip_address") or "127.0.0.1"),
        "user_agent": str(payload.get("user_agent") or listener.get("user_agent") or "MyAgent/1.0"),
        "uri": str(payload.get("uri") or listener.get("callback_path") or "/lab/audit"),
        "metadata": {
            **metadata,
            "report_id": report_id,
            "filename": filename,
            "finding_count": finding_count,
            "risk_level": risk_level,
            "sha256": sha256,
        },
        "report_json": report_json,
    }

    try:
        manager.record_heartbeat(listener_id, heartbeat_payload)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    return {
        "status": "stored",
        "listener_id": listener_id,
        "agent_id": agent_id,
        "report_id": report_id,
        "filename": filename,
        "finding_count": finding_count,
        "risk_level": risk_level,
        "sha256": sha256,
    }


@router.get("/{listener_id}/audit-reports", response_model=dict)
async def list_audit_reports(
    listener_id: str,
    limit: int = Query(25, ge=1, le=200),
    agent_id: str | None = Query(default=None),
):
    _listener_or_404(listener_id)
    reports = audit_db.get_audit_reports(listener_id=listener_id, agent_id=agent_id, limit=limit)
    return {
        "listener_id": listener_id,
        "reports": [_report_list_item(report) for report in reports],
        "total": len(reports),
    }


@router.get("/{listener_id}/audit-reports/{report_id}", response_model=dict)
async def get_audit_report(listener_id: str, report_id: str):
    _listener_or_404(listener_id)
    report = audit_db.get_audit_report(report_id)
    if not report or report.get("listener_id") != listener_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Audit report not found")
    return report


@router.get("/{listener_id}/user-agent", response_model=dict)
async def get_random_user_agent(listener_id: str):
    _listener_or_404(listener_id)
    return {"listener_id": listener_id, "user_agent": manager.get_random_user_agent(listener_id)}


@router.get("/{listener_id}/uri", response_model=dict)
async def get_random_uri(listener_id: str):
    _listener_or_404(listener_id)
    return {"listener_id": listener_id, "uri": manager.get_random_uri(listener_id)}


@router.get("/{listener_id}/headers", response_model=dict)
async def get_headers(listener_id: str):
    _listener_or_404(listener_id)
    return {"listener_id": listener_id, "headers": manager.get_random_http_header(listener_id)}


@router.post("/profiles/apply/{profile_type}/{listener_id}", response_model=dict)
async def apply_profile(profile_type: str, listener_id: str):
    _listener_or_404(listener_id)

    try:
        profile = PROFILES_MAP[ProfileType(profile_type)]
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Unknown profile type") from exc

    profile_data = json.loads(profile.model_dump_json())
    config_blob = {
        "http_config": profile_data.get("http_config", {}),
        "response_config": profile_data.get("response_config", {}),
        "beacon_config": profile_data.get("beacon_config", {}),
        "encryption_config": profile_data.get("encryption_config", {}),
        "ssl_config": profile_data.get("ssl_config", {}),
        "proxy_config": profile_data.get("proxy_config", {}),
        "domain_fronting_config": profile_data.get("domain_fronting_config", {}),
        "profile_type": profile_data.get("profile_type"),
        "profile_id": profile_data.get("profile_id"),
        "profile_name": profile_data.get("profile_name"),
    }

    return manager.update_listener(
        listener_id,
        {
            "profile": profile_type,
            "config": config_blob,
        },
    )


@router.get("/{listener_id}/export", response_model=dict)
async def export_listener(listener_id: str):
    _listener_or_404(listener_id)
    return {"listener_id": listener_id, "profile_json": manager.export_listener_profile(listener_id)}
