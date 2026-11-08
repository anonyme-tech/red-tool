import asyncio
import json
import os
import sys
import tempfile
import uuid
from pathlib import Path

import pytest
from fastapi import HTTPException
from starlette.routing import Match


REPO_ROOT = Path(__file__).resolve().parents[1]
SERVER_ROOT = REPO_ROOT / "server"
AGENT_ROOT = REPO_ROOT / "agent"
os.chdir(REPO_ROOT)
sys.path.insert(0, str(SERVER_ROOT))
sys.path.insert(0, str(AGENT_ROOT))

from main import app  # noqa: E402
from beacon import Beacon  # noqa: E402
from models import RegisterAgentRequest, SystemInfo  # noqa: E402
from modules.database import C2Database  # noqa: E402
from modules.listener_lab import ListenerManager  # noqa: E402
from modules.listener_runtime import listener_manager  # noqa: E402
from routes import auth_safe  # noqa: E402
from routes import agents_safe  # noqa: E402
from routes import listeners_safe  # noqa: E402


@pytest.fixture(autouse=True)
def clear_runtime_state():
    listener_manager.clear()
    yield
    listener_manager.clear()


def test_listener_manager_rejects_non_local_hosts():
    manager = ListenerManager()
    with pytest.raises(ValueError):
        manager.create_listener(
            {
                "name": "remote",
                "protocol": "https",
                "host": "10.10.10.10",
                "port": 9443,
            }
        )


def test_heartbeat_updates_stats_and_agents():
    listener = listener_manager.create_listener(
        {
            "name": "lab-listener",
            "protocol": "https",
            "host": "127.0.0.1",
            "port": 9443,
            "enabled": True,
        }
    )

    ack = listener_manager.record_heartbeat(
        listener["listener_id"],
        {
            "agent_id": "sim-agent-01",
            "hostname": "sim-agent-01",
            "username": "lab-user",
            "process_id": 111,
            "system_info": {
                "os": "Simulated",
                "hostname": "sim-agent-01",
                "username": "lab-user",
                "domain": "lab.local",
                "pid": 111,
                "architecture": "x64",
                "privileges": "simulated",
            },
            "event_type": "heartbeat",
            "signal": "heartbeat",
            "sleep_interval": 5,
            "jitter": 0.1,
            "user_agent": "LabSimulator/1.0",
            "uri": "/lab/heartbeat",
        },
    )

    stats = listener_manager.get_listener_stats(listener["listener_id"])
    agents = listener_manager.list_simulated_agents(listener_id=listener["listener_id"])

    assert ack["status"] == "acknowledged"
    assert stats["heartbeats_received"] == 1
    assert stats["agents_connected"] == 1
    assert len(agents) == 1
    assert any(observation["type"] == "new_agent" for observation in ack["observations"])


def test_static_listener_routes_win_over_dynamic_listener_id():
    expectations = {
        "/api/listeners/history": "/api/listeners/history",
        "/api/listeners/profiles/list": "/api/listeners/profiles/list",
        "/api/listeners/status/summary": "/api/listeners/status/summary",
    }

    for path, expected in expectations.items():
        scope = {
            "type": "http",
            "method": "GET",
            "path": path,
            "root_path": "",
            "scheme": "http",
            "query_string": b"",
            "headers": [],
        }
        winner = None
        for route in app.router.routes:
            route_path = getattr(route, "path", None)
            if not route_path or not route_path.startswith("/api/listeners"):
                continue
            match, _ = route.matches(scope)
            if match == Match.FULL:
                winner = route_path
                break
        assert winner == expected


def test_tasking_is_disabled_in_simulation_mode():
    listener = listener_manager.create_listener(
        {
            "name": "lab-listener",
            "protocol": "https",
            "host": "127.0.0.1",
            "port": 9555,
            "enabled": True,
        }
    )
    listener_manager.record_heartbeat(
        listener["listener_id"],
        {
            "agent_id": "sim-agent-02",
            "hostname": "sim-agent-02",
            "username": "lab-user",
            "process_id": 222,
            "system_info": {
                "os": "Simulated",
                "hostname": "sim-agent-02",
                "username": "lab-user",
                "domain": "lab.local",
                "pid": 222,
                "architecture": "x64",
                "privileges": "simulated",
            },
        },
    )

    async def invoke():
        await agents_safe.create_task_for_agent("sim-agent-02", "execute_command")

    with pytest.raises(HTTPException) as exc:
        asyncio.run(invoke())

    assert exc.value.status_code == 410


def test_register_agent_uses_safe_generated_id():
    listener_manager.create_listener(
        {
            "listener_id": "listener_reg",
            "name": "lab-listener",
            "protocol": "https",
            "host": "127.0.0.1",
            "port": 9666,
            "enabled": True,
        }
    )

    async def invoke():
        request = RegisterAgentRequest(
            listener_id="listener_reg",
            hostname="HOST-01",
            username="analyst",
            process_id=333,
            system_info=SystemInfo(
                os="Simulated",
                hostname="HOST-01",
                username="analyst",
                domain="lab.local",
                pid=333,
                architecture="x64",
                privileges="simulated",
            ),
            agent_version="lab-sim-1.0",
        )
        return await auth_safe.register_agent(request)

    result = asyncio.run(invoke())
    agent = listener_manager.get_simulated_agent("sim_HOST-01_analyst_333")

    assert result.agent_id == "sim_HOST-01_analyst_333"
    assert agent is not None
    assert agent["listener_id"] == "listener_reg"


def test_beacon_rejects_non_loopback_server():
    with pytest.raises(ValueError):
        Beacon("http://10.10.10.10:8000", "listener_1")


def test_audit_report_ingestion_persists_json_and_updates_listener(monkeypatch):
    listener_manager.create_listener(
        {
            "listener_id": "listener_audit",
            "name": "audit-listener",
            "protocol": "https",
            "host": "127.0.0.1",
            "port": 9777,
            "enabled": True,
        }
    )

    temp_db_dir = Path(tempfile.gettempdir()) / "red_team_persistence_tests"
    temp_db_dir.mkdir(parents=True, exist_ok=True)
    memory_db = C2Database(str(temp_db_dir / f"audit_reports_{uuid.uuid4().hex}.db"))
    monkeypatch.setattr(listeners_safe, "audit_db", memory_db)

    payload = {
        "agent_id": "audit_HOST-02_analyst",
        "machine_name": "HOST-02",
        "username": "analyst",
        "domain": "lab.local",
        "operating_system": "Windows 11",
        "process_id": 444,
        "report_json": json.dumps(
            {
                "timestamp": "2026-04-03T12:00:00+00:00",
                "system": {
                    "machineName": "HOST-02",
                    "userName": "analyst",
                    "domain": "lab.local",
                    "osVersion": "Windows 11",
                    "isAdministrator": False,
                },
                "riskLevel": "MEDIUM",
                "findingCount": 1,
                "findings": [
                    {
                        "type": "Writable Service Binary",
                        "target": "SvcA",
                        "severity": "HIGH",
                        "category": "Service",
                        "description": "Writable binary",
                        "evidencePath": "C:\\Temp\\svc.exe",
                    }
                ],
                "warnings": [],
            }
        ),
        "metadata": {
            "source": "pytest",
        },
    }

    result = asyncio.run(listeners_safe.ingest_audit_report("listener_audit", payload))
    listing = asyncio.run(listeners_safe.list_audit_reports("listener_audit", limit=10, agent_id=None))
    stored = memory_db.get_audit_report(result["report_id"])
    agent = listener_manager.get_simulated_agent("audit_HOST-02_analyst")
    stats = listener_manager.get_listener_stats("listener_audit")

    assert result["status"] == "stored"
    assert stored is not None
    assert stored["listener_id"] == "listener_audit"
    assert stored["report_json"] == payload["report_json"]
    assert stored["finding_count"] == 1
    assert stored["risk_level"] == "MEDIUM"
    assert listing["total"] == 1
    assert "report_json" not in listing["reports"][0]
    assert agent is not None
    assert agent["last_event_type"] == "audit_report"
    assert stats["heartbeats_received"] == 1
