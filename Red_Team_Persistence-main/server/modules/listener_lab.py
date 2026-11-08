"""
Listener manager for defensive lab simulations.
"""
import ipaddress
import json
import logging
import random
import secrets
import socket
from copy import deepcopy
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _utc_now_iso() -> str:
    return _utc_now().isoformat()


LOCAL_HOST_ALIASES = {
    "localhost": "127.0.0.1",
    "::1": "127.0.0.1",
}


class ListenerStatus(str, Enum):
    """Operational status for a simulated listener."""

    OFFLINE = "offline"
    ONLINE = "online"
    ERROR = "error"
    PAUSED = "paused"


class ListenerStats:
    """Mutable stats container used by the listener manager."""

    def __init__(self, *, started: bool = False):
        now = _utc_now()
        self.agents_connected = 0
        self.total_agents_seen = 0
        self.tasks_sent = 0
        self.tasks_completed = 0
        self.bytes_received = 0
        self.bytes_sent = 0
        self.start_time = now if started else None
        self.uptime_seconds = 0
        self.last_activity = None
        self.errors_count = 0
        self.heartbeats_received = 0
        self.events_recorded = 0
        self.alerts_generated = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "agents_connected": self.agents_connected,
            "total_agents_seen": self.total_agents_seen,
            "tasks_sent": self.tasks_sent,
            "tasks_completed": self.tasks_completed,
            "bytes_received": self.bytes_received,
            "bytes_sent": self.bytes_sent,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "uptime_seconds": self.uptime_seconds,
            "last_activity": self.last_activity.isoformat() if self.last_activity else None,
            "errors_count": self.errors_count,
            "heartbeats_received": self.heartbeats_received,
            "events_recorded": self.events_recorded,
            "alerts_generated": self.alerts_generated,
        }


class ListenerManager:
    """In-memory listener manager for defensive lab use."""

    def __init__(self):
        self.listeners: Dict[str, Dict[str, Any]] = {}
        self.agent_sessions: Dict[str, Dict[str, Dict[str, Any]]] = {}
        self.history: List[Dict[str, Any]] = []
        self.profiles: Dict[str, Dict[str, Any]] = {}
        self.logger = logging.getLogger("ListenerManager")

    def clear(self) -> None:
        """Reset in-memory state. Used by tests."""
        self.listeners.clear()
        self.agent_sessions.clear()
        self.history.clear()

    def normalize_local_host(self, host: str) -> str:
        """Normalize listener host and accept LAN/IP targets."""
        candidate = (host or "127.0.0.1").strip().lower()
        candidate = LOCAL_HOST_ALIASES.get(candidate, candidate)
        if not candidate:
            return "127.0.0.1"

        # Allow direct IPv4/IPv6 values as-is.
        try:
            ipaddress.ip_address(candidate)
            return candidate
        except ValueError:
            pass

        # Allow DNS hostnames (e.g. lab gateway/FQDN).
        try:
            socket.getaddrinfo(candidate, None)
            return candidate
        except socket.gaierror as exc:
            raise ValueError("Listener host must be a valid IP or resolvable hostname") from exc

    def validate_port_available(self, host: str, port: int, *, listener_id: Optional[str] = None) -> bool:
        """Check whether listener host/port pair is available."""
        normalized_host = self.normalize_local_host(host)

        for existing_id, listener in self.listeners.items():
            if listener_id and existing_id == listener_id:
                continue
            if listener.get("host") == normalized_host and listener.get("port") == port:
                return False

        # Active port probing is only meaningful for loopback checks.
        if normalized_host not in {"127.0.0.1", "::1"}:
            return True

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                result = sock.connect_ex((normalized_host, port))
            finally:
                sock.close()
            return result != 0
        except OSError as exc:
            self.logger.error("Error checking local port %s: %s", port, exc)
            return False

    def generate_encryption_key(self) -> Dict[str, str]:
        """Generate simulation-only encryption material."""
        return {"key": secrets.token_hex(32), "iv": secrets.token_hex(16)}

    def create_listener(self, listener_config: Dict[str, Any], *, skip_validation: bool = False) -> Dict[str, Any]:
        """Create a new in-memory lab listener."""
        listener_id = listener_config.get("listener_id") or f"listener_{secrets.token_hex(6)}"
        host = self.normalize_local_host(listener_config.get("host", "127.0.0.1"))
        port = int(listener_config.get("port") or 0)

        if port <= 0 or port > 65535:
            raise ValueError("Listener port must be between 1 and 65535")

        if listener_id in self.listeners:
            raise ValueError(f"Listener already exists: {listener_id}")

        if not skip_validation and not self.validate_port_available(host, port):
            raise ValueError(f"Port {port} already in use")

        config_blob = self._normalize_config(listener_config)
        enabled = bool(listener_config.get("enabled", True))
        status = listener_config.get("status") or (
            ListenerStatus.ONLINE.value if enabled else ListenerStatus.OFFLINE.value
        )
        enabled = status == ListenerStatus.ONLINE.value
        now = _utc_now_iso()

        listener = {
            "listener_id": listener_id,
            "name": listener_config.get("name", f"Listener_{listener_id}"),
            "protocol": (listener_config.get("protocol") or "https").lower(),
            "host": host,
            "port": port,
            "profile": listener_config.get("profile", "default"),
            "enabled": enabled,
            "status": status,
            "mode": "lab-local",
            "created_at": listener_config.get("created_at") or now,
            "last_modified": listener_config.get("last_modified") or now,
            "user_agent": listener_config.get("user_agent") or self._pick_first(
                config_blob.get("http_config", {}).get("user_agents"),
                "LabSimulator/1.0",
            ),
            "callback_path": listener_config.get("callback_path")
            or self._pick_first(config_blob.get("http_config", {}).get("uris"), "/lab/heartbeat"),
            "beacon_interval": int(
                listener_config.get("beacon_interval")
                or config_blob.get("beacon_config", {}).get("beacon_interval", 5)
            ),
            "domain_front": listener_config.get("domain_front")
            or (config_blob.get("domain_fronting_config", {}) or {}).get("front_domain"),
            "use_ssl": bool(listener_config.get("use_ssl", False)),
            "cert_file": listener_config.get("cert_file"),
            "key_file": listener_config.get("key_file"),
            "http_headers": deepcopy(listener_config.get("http_headers") or {}),
            "metadata": deepcopy(listener_config.get("metadata") or {}),
            "config": config_blob,
            "stats": self._coerce_stats(listener_config.get("stats"), started=enabled),
            "errors": self._coerce_errors(listener_config.get("errors")),
            "agents_connected": 0,
        }

        self.listeners[listener_id] = listener
        self.agent_sessions[listener_id] = {}
        self._refresh_listener_stats(listener_id)
        self._add_to_history("listener_created", listener_id, self._public_listener(listener))
        return self.get_listener(listener_id) or {}

    def update_listener(self, listener_id: str, updates: Dict[str, Any]) -> Dict[str, Any]:
        """Update a simulated listener."""
        listener = self.listeners.get(listener_id)
        if not listener:
            raise ValueError(f"Listener not found: {listener_id}")

        changed = deepcopy(updates)

        if "host" in changed and changed["host"] is not None:
            changed["host"] = self.normalize_local_host(str(changed["host"]))
        if "port" in changed and changed["port"] is not None:
            port = int(changed["port"])
            if port <= 0 or port > 65535:
                raise ValueError("Listener port must be between 1 and 65535")
            if not self.validate_port_available(changed.get("host", listener["host"]), port, listener_id=listener_id):
                raise ValueError(f"Port {port} already in use")
            changed["port"] = port

        for key in [
            "name",
            "protocol",
            "host",
            "port",
            "profile",
            "use_ssl",
            "cert_file",
            "key_file",
            "user_agent",
            "callback_path",
            "beacon_interval",
            "domain_front",
            "http_headers",
            "metadata",
            "mode",
        ]:
            if key in changed and changed[key] is not None:
                listener[key] = deepcopy(changed[key])

        if "enabled" in changed and changed["enabled"] is not None:
            listener["enabled"] = bool(changed["enabled"])
            listener["status"] = (
                ListenerStatus.ONLINE.value if listener["enabled"] else ListenerStatus.OFFLINE.value
            )

        if "status" in changed and changed["status"] is not None:
            listener["status"] = str(changed["status"])
            listener["enabled"] = listener["status"] == ListenerStatus.ONLINE.value

        if "config" in changed and changed["config"] is not None:
            listener["config"] = self._deep_merge(listener.get("config", {}), deepcopy(changed["config"]))

        listener["config"] = self._normalize_config(listener)
        listener["beacon_interval"] = int(
            listener["config"].get("beacon_config", {}).get("beacon_interval", listener.get("beacon_interval", 5))
        )
        listener["callback_path"] = self._pick_first(
            listener["config"].get("http_config", {}).get("uris"),
            listener.get("callback_path") or "/lab/heartbeat",
        )
        listener["user_agent"] = self._pick_first(
            listener["config"].get("http_config", {}).get("user_agents"),
            listener.get("user_agent") or "LabSimulator/1.0",
        )
        listener["domain_front"] = (
            listener["config"].get("domain_fronting_config", {}).get("front_domain")
            or listener.get("domain_front")
        )
        listener["last_modified"] = _utc_now_iso()
        self._refresh_listener_stats(listener_id)
        self._add_to_history("listener_updated", listener_id, changed)
        return self.get_listener(listener_id) or {}

    def delete_listener(self, listener_id: str) -> bool:
        """Delete a simulated listener."""
        if listener_id not in self.listeners:
            raise ValueError(f"Listener not found: {listener_id}")

        listener = self._public_listener(self.listeners[listener_id])
        self.listeners.pop(listener_id, None)
        self.agent_sessions.pop(listener_id, None)
        self._add_to_history("listener_deleted", listener_id, listener)
        return True

    def start_listener(self, listener_id: str) -> Dict[str, Any]:
        """Mark a listener online."""
        listener = self.listeners.get(listener_id)
        if not listener:
            raise ValueError(f"Listener not found: {listener_id}")

        listener["status"] = ListenerStatus.ONLINE.value
        listener["enabled"] = True
        if not listener["stats"].get("start_time"):
            listener["stats"]["start_time"] = _utc_now_iso()
        listener["last_modified"] = _utc_now_iso()
        self._refresh_listener_stats(listener_id)
        self._add_to_history("listener_started", listener_id, {})
        return self.get_listener(listener_id) or {}

    def stop_listener(self, listener_id: str) -> Dict[str, Any]:
        """Mark a listener offline."""
        listener = self.listeners.get(listener_id)
        if not listener:
            raise ValueError(f"Listener not found: {listener_id}")

        listener["status"] = ListenerStatus.OFFLINE.value
        listener["enabled"] = False
        listener["last_modified"] = _utc_now_iso()
        for agent in self.agent_sessions.get(listener_id, {}).values():
            agent["status"] = "sleeping"
        self._refresh_listener_stats(listener_id)
        self._add_to_history("listener_stopped", listener_id, {})
        return self.get_listener(listener_id) or {}

    def get_listener(self, listener_id: str) -> Optional[Dict[str, Any]]:
        """Return a public listener snapshot."""
        listener = self.listeners.get(listener_id)
        if not listener:
            return None
        self._refresh_listener_stats(listener_id)
        return self._public_listener(listener)

    def list_listeners(self) -> List[Dict[str, Any]]:
        """List all listeners."""
        listeners: List[Dict[str, Any]] = []
        for listener_id in sorted(self.listeners.keys()):
            public_listener = self.get_listener(listener_id)
            if public_listener:
                listeners.append(public_listener)
        return listeners

    def get_listener_by_name(self, name: str) -> Optional[Dict[str, Any]]:
        """Find a listener by name."""
        for listener_id, listener in self.listeners.items():
            if listener.get("name") == name:
                return self.get_listener(listener_id)
        return None

    def update_listener_stats(self, listener_id: str, stats_update: Dict[str, Any]) -> bool:
        """Increment or set safe counters for a listener."""
        listener = self.listeners.get(listener_id)
        if not listener:
            return False

        stats = listener["stats"]
        for key, value in stats_update.items():
            if key not in stats:
                continue
            if isinstance(stats.get(key), int) and isinstance(value, int):
                stats[key] += value
            else:
                stats[key] = value

        stats["last_activity"] = _utc_now_iso()
        listener["last_modified"] = _utc_now_iso()
        self._refresh_listener_stats(listener_id)
        return True

    def get_listener_stats(self, listener_id: str) -> Optional[Dict[str, Any]]:
        """Return listener stats."""
        if listener_id not in self.listeners:
            return None
        self._refresh_listener_stats(listener_id)
        return deepcopy(self.listeners[listener_id]["stats"])

    def get_listener_errors(self, listener_id: str) -> List[Dict[str, Any]]:
        """Return listener errors."""
        if listener_id not in self.listeners:
            return []
        return deepcopy(self.listeners[listener_id]["errors"])

    def add_listener_error(self, listener_id: str, error_msg: str) -> bool:
        """Append a listener error."""
        listener = self.listeners.get(listener_id)
        if not listener:
            return False

        listener["errors"].append(
            {"timestamp": _utc_now_iso(), "message": error_msg.strip() or "unknown error"}
        )
        if len(listener["errors"]) > 100:
            listener["errors"] = listener["errors"][-100:]

        listener["stats"]["errors_count"] += 1
        listener["last_modified"] = _utc_now_iso()
        self._add_to_history("listener_error", listener_id, {"message": error_msg})
        return True

    def record_heartbeat(self, listener_id: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Record a safe simulated heartbeat for a listener."""
        listener = self.listeners.get(listener_id)
        if not listener:
            raise ValueError(f"Listener not found: {listener_id}")
        if listener.get("status") != ListenerStatus.ONLINE.value:
            raise ValueError("Listener is offline")

        now = _utc_now_iso()
        data = deepcopy(payload or {})
        sessions = self.agent_sessions.setdefault(listener_id, {})
        
        # ============================================================
        # FORCER l'utilisation des vraies valeurs depuis le payload
        # ============================================================
        real_hostname = (
            data.get("hostname") or 
            data.get("system_info", {}).get("hostname") or 
            data.get("system_info", {}).get("computer_name") or 
            socket.gethostname()
        )
        real_username = (
            data.get("username") or 
            data.get("system_info", {}).get("username") or 
            data.get("system_info", {}).get("user") or 
            "user"
        )
        real_ip = (
            data.get("ip_address") or 
            data.get("system_info", {}).get("ip_address") or 
            data.get("system_info", {}).get("ip") or 
            data.get("local_ip") or 
            "127.0.0.1"
        )
        real_os = (
            data.get("operating_system") or 
            data.get("system_info", {}).get("os") or 
            "Windows"
        )
        
        # Debug log
        print(f"[DEBUG] Heartbeat - Hostname: {real_hostname}, Username: {real_username}, IP: {real_ip}, OS: {real_os}")
        
        agent_id = (
            str(
                data.get("agent_id")
                or data.get("simulation_id")
                or data.get("hostname")
                or f"sim_{secrets.token_hex(4)}"
            )
            .strip()
            .replace(" ", "_")
        )
        
        event_type = str(data.get("event_type") or "heartbeat").strip() or "heartbeat"
        requested_interval = int(
            data.get("sleep_interval")
            or data.get("interval_seconds")
            or listener.get("beacon_interval")
            or 5
        )
        requested_jitter = float(
            data.get("jitter")
            or (listener.get("config", {}).get("beacon_config", {}) or {}).get("jitter", 0.0)
        )

        system_info = deepcopy(data.get("system_info") or {})
        metadata = deepcopy(data.get("metadata") or {})
        user_agent = data.get("user_agent") or self.get_random_user_agent(listener_id)
        uri = data.get("uri") or self.get_random_uri(listener_id)
        signal = str(data.get("signal") or event_type)

        agent = sessions.get(agent_id)
        if not agent:
            # Création d'un nouvel agent avec les vraies informations
            agent = {
                "agent_id": agent_id,
                "listener_id": listener_id,
                "hostname": real_hostname,
                "username": real_username,
                "process_id": int(data.get("process_id") or system_info.get("pid") or 0),
                "ip_address": real_ip,
                "first_seen": now,
                "status": "alive",
                "system_info": system_info or {},
                "agent_version": data.get("agent_version") or "lab-sim-1.0",
                "privileges": data.get("privileges") or system_info.get("privileges") or "user",
                "sleep_interval": requested_interval,
                "jitter": requested_jitter,
                "operating_system": real_os,
                "hostname_domain": system_info.get("domain") or "WORKGROUP",
                "heartbeat_count": 0,
                "last_event_type": event_type,
                "last_signal": signal,
                "last_user_agent": user_agent,
                "last_uri": uri,
                "metadata": {},
            }
        else:
            # Mise à jour avec les vraies valeurs
            agent["hostname"] = real_hostname
            agent["username"] = real_username
            agent["ip_address"] = real_ip
            agent["operating_system"] = real_os
            agent["system_info"] = system_info or agent.get("system_info") or {}
            agent["last_seen"] = now
            agent["status"] = str(data.get("status") or "alive")
            agent["sleep_interval"] = requested_interval
            agent["jitter"] = requested_jitter
            agent["heartbeat_count"] = int(agent.get("heartbeat_count", 0)) + 1
            agent["last_event_type"] = event_type
            agent["last_signal"] = signal
            agent["last_user_agent"] = user_agent
            agent["last_uri"] = uri
            agent["metadata"] = self._deep_merge(agent.get("metadata", {}), metadata)

        sessions[agent_id] = agent

        observations = self._build_observations(listener, agent, requested_interval, user_agent, uri)

        listener["stats"]["heartbeats_received"] += 1
        listener["stats"]["events_recorded"] += 1
        listener["stats"]["bytes_received"] += len(json.dumps(data, default=str).encode("utf-8"))
        listener["stats"]["last_activity"] = now
        if observations:
            listener["stats"]["alerts_generated"] += len(observations)
        listener["last_modified"] = now
        self._refresh_listener_stats(listener_id)

        self._add_to_history(
            "heartbeat_received",
            listener_id,
            {
                "agent_id": agent_id,
                "event_type": event_type,
                "signal": signal,
                "user_agent": user_agent,
                "uri": uri,
                "observations": observations,
            },
        )

        return {
            "status": "acknowledged",
            "listener_id": listener_id,
            "agent_id": agent_id,
            "event_type": event_type,
            "recommended_sleep_interval": listener.get("beacon_interval", 5),
            "recommended_jitter": (listener.get("config", {}).get("beacon_config", {}) or {}).get("jitter", 0.0),
            "observations": observations,
        }

    def register_simulated_agent(self, listener_id: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Compatibility helper used by the safe auth route."""
        registration_payload = deepcopy(payload or {})
        registration_payload.setdefault("event_type", "registration")
        registration_payload.setdefault("signal", "registration")
        return self.record_heartbeat(listener_id, registration_payload)

    def list_simulated_agents(
        self,
        listener_id: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List all simulated agents."""
        agents: List[Dict[str, Any]] = []
        listener_ids = [listener_id] if listener_id else list(self.agent_sessions.keys())

        for current_listener_id in listener_ids:
            for agent in self.agent_sessions.get(current_listener_id, {}).values():
                if status and agent.get("status") != status:
                    continue
                agents.append(deepcopy(agent))

        agents.sort(key=lambda item: item.get("last_seen") or item.get("first_seen") or "", reverse=True)
        return agents

    def get_simulated_agent(self, agent_id: str) -> Optional[Dict[str, Any]]:
        """Get a simulated agent by id."""
        for listener_agents in self.agent_sessions.values():
            if agent_id in listener_agents:
                return deepcopy(listener_agents[agent_id])
        return None

    def remove_simulated_agent(self, agent_id: str) -> bool:
        """Remove a simulated agent session."""
        for listener_id, listener_agents in self.agent_sessions.items():
            if agent_id not in listener_agents:
                continue
            listener_agents.pop(agent_id, None)
            self._refresh_listener_stats(listener_id)
            self._add_to_history("agent_removed", listener_id, {"agent_id": agent_id})
            self.logger.info("Removed simulated agent %s from listener %s", agent_id, listener_id)
            return True
        return False

    def update_simulated_agent_status(self, agent_id: str, new_status: str) -> Optional[Dict[str, Any]]:
        """Update a simulated agent status."""
        for listener_id, listener_agents in self.agent_sessions.items():
            if agent_id not in listener_agents:
                continue
            listener_agents[agent_id]["status"] = new_status
            listener_agents[agent_id]["last_seen"] = _utc_now_iso()
            self._refresh_listener_stats(listener_id)
            self._add_to_history(
                "agent_status_updated",
                listener_id,
                {"agent_id": agent_id, "status": new_status},
            )
            return deepcopy(listener_agents[agent_id])
        return None

    def get_random_http_header(self, listener_id: str) -> Dict[str, str]:
        """Return HTTP headers from the listener profile."""
        listener = self.listeners.get(listener_id)
        if not listener:
            return {}
        return deepcopy((listener.get("config", {}).get("http_config", {}) or {}).get("headers", {}))

    def get_random_user_agent(self, listener_id: str) -> str:
        """Return a profile user-agent."""
        listener = self.listeners.get(listener_id)
        if not listener:
            return "LabSimulator/1.0"
        user_agents = (listener.get("config", {}).get("http_config", {}) or {}).get("user_agents", [])
        return random.choice(user_agents) if user_agents else "LabSimulator/1.0"

    def get_random_uri(self, listener_id: str) -> str:
        """Return a profile URI."""
        listener = self.listeners.get(listener_id)
        if not listener:
            return "/lab/heartbeat"
        uris = (listener.get("config", {}).get("http_config", {}) or {}).get("uris", [])
        return random.choice(uris) if uris else "/lab/heartbeat"

    def export_listener_profile(self, listener_id: str) -> str:
        """Export a listener as JSON."""
        listener = self.listeners.get(listener_id)
        if not listener:
            return ""
        exported = self._public_listener(listener)
        exported["recent_history"] = self.get_history(limit=25, listener_id=listener_id)
        exported["simulated_agents"] = self.list_simulated_agents(listener_id=listener_id)
        return json.dumps(exported, indent=2, default=str)

    def import_listener_profile(self, profile_json: str) -> Dict[str, Any]:
        """Import a listener from a JSON payload."""
        try:
            config = json.loads(profile_json)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON profile: {exc}") from exc

        if isinstance(config, dict) and "listener" in config and isinstance(config["listener"], dict):
            config = config["listener"]

        config.pop("recent_history", None)
        config.pop("simulated_agents", None)
        return self.create_listener(config)

    def get_history(self, limit: int = 50, *, listener_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Return recent history, optionally filtered by listener id."""
        entries = self.history
        if listener_id:
            entries = [entry for entry in entries if entry.get("listener_id") == listener_id]
        return deepcopy(entries[-limit:])

    def get_summary(self) -> Dict[str, Any]:
        """Return a global listener summary."""
        total_agents = 0
        total_heartbeats = 0
        listeners_online = 0
        listeners_offline = 0

        for listener_id, listener in self.listeners.items():
            self._refresh_listener_stats(listener_id)
            stats = listener.get("stats", {})
            total_agents += stats.get("agents_connected", 0)
            total_heartbeats += stats.get("heartbeats_received", 0)
            if listener.get("status") == ListenerStatus.ONLINE.value:
                listeners_online += 1
            else:
                listeners_offline += 1

        return {
            "mode": "lab-local",
            "total_listeners": len(self.listeners),
            "listeners_online": listeners_online,
            "listeners_offline": listeners_offline,
            "total_agents": total_agents,
            "total_tasks": 0,
            "total_heartbeats": total_heartbeats,
            "uptime": "simulation-only",
        }

    def _normalize_config(self, source: Dict[str, Any]) -> Dict[str, Any]:
        config_blob = deepcopy(source.get("config") or {})
        http_config = deepcopy(config_blob.get("http_config") or {})
        beacon_config = deepcopy(config_blob.get("beacon_config") or {})
        response_config = deepcopy(config_blob.get("response_config") or {})
        encryption_config = deepcopy(config_blob.get("encryption_config") or {})
        ssl_config = deepcopy(config_blob.get("ssl_config") or {})
        proxy_config = deepcopy(config_blob.get("proxy_config") or {})
        domain_fronting_config = deepcopy(config_blob.get("domain_fronting_config") or {})

        http_config.setdefault("method", "POST")
        http_config.setdefault("uris", [])
        if source.get("callback_path") and source.get("callback_path") not in http_config["uris"]:
            http_config["uris"].insert(0, source["callback_path"])
        if not http_config["uris"]:
            http_config["uris"] = ["/lab/heartbeat"]

        http_config.setdefault("user_agents", [])
        if source.get("user_agent") and source["user_agent"] not in http_config["user_agents"]:
            http_config["user_agents"].insert(0, source["user_agent"])
        if not http_config["user_agents"]:
            http_config["user_agents"] = ["LabSimulator/1.0"]

        merged_headers = deepcopy(source.get("http_headers") or {})
        merged_headers.update(deepcopy(http_config.get("headers") or {}))
        http_config["headers"] = merged_headers
        http_config.setdefault("callback_port", int(source.get("port") or 0))
        http_config.setdefault("host_rotation", False)

        beacon_config["beacon_interval"] = int(
            source.get("beacon_interval") or beacon_config.get("beacon_interval") or 5
        )
        beacon_config["jitter"] = float(beacon_config.get("jitter", 0.0))
        beacon_config.setdefault("max_retries", 0)
        beacon_config.setdefault("retry_delay", 0)
        beacon_config.setdefault("timeout", 5)
        beacon_config.setdefault("use_sleep_obfuscation", False)
        beacon_config.setdefault("sleep_obfuscation_type", "none")

        response_config.setdefault("page_payload", "<html><body>lab-ok</body></html>")
        response_config.setdefault("page_404", "<html><body>lab-404</body></html>")
        response_config.setdefault("page_error", "<html><body>lab-error</body></html>")
        response_config.setdefault("response_headers", {"Content-Type": "application/json"})

        if encryption_config.get("generate_key") and not encryption_config.get("key"):
            generated = self.generate_encryption_key()
            encryption_config["key"] = generated["key"]
            encryption_config["iv"] = generated["iv"]
        encryption_config.setdefault("encryption_type", "simulation")
        encryption_config.setdefault("hmac_enabled", False)
        encryption_config.setdefault("generate_key", False)

        ssl_config["use_ssl"] = bool(source.get("use_ssl", ssl_config.get("use_ssl", False)))
        if source.get("cert_file"):
            ssl_config["cert_file"] = source.get("cert_file")
        if source.get("key_file"):
            ssl_config["key_file"] = source.get("key_file")
        ssl_config.setdefault("tls_version", "simulation")
        ssl_config.setdefault("verify_peer", False)
        ssl_config.setdefault("self_signed", False)

        proxy_config.setdefault("enabled", False)
        proxy_config.setdefault("proxy_type", "none")
        proxy_config.setdefault("host", "")
        proxy_config.setdefault("port", 0)
        proxy_config.setdefault("verify_ssl", False)

        domain_fronting_config["enabled"] = bool(
            source.get("domain_front") or domain_fronting_config.get("enabled", False)
        )
        if source.get("domain_front"):
            domain_fronting_config["front_domain"] = source["domain_front"]
        domain_fronting_config.setdefault("real_domain", source.get("host", "127.0.0.1"))
        domain_fronting_config.setdefault("domain_header", "Host")

        normalized = {
            "http_config": http_config,
            "beacon_config": beacon_config,
            "response_config": response_config,
            "encryption_config": encryption_config,
            "ssl_config": ssl_config,
            "proxy_config": proxy_config,
            "domain_fronting_config": domain_fronting_config,
            "profile_type": source.get("profile", "default"),
        }
        for extra_key in ["profile_id", "profile_name", "profile_type"]:
            if extra_key in config_blob:
                normalized[extra_key] = config_blob[extra_key]
        return normalized

    def _coerce_stats(self, stats: Any, *, started: bool) -> Dict[str, Any]:
        base = ListenerStats(started=started).to_dict()
        if not isinstance(stats, dict):
            return base

        for key, value in stats.items():
            if key not in base:
                continue
            base[key] = value

        if started and not base.get("start_time"):
            base["start_time"] = _utc_now_iso()
        return base

    def _coerce_errors(self, errors: Any) -> List[Dict[str, Any]]:
        if not isinstance(errors, list):
            return []
        cleaned = []
        for item in errors:
            if not isinstance(item, dict):
                continue
            cleaned.append(
                {
                    "timestamp": item.get("timestamp") or _utc_now_iso(),
                    "message": str(item.get("message") or "unknown error"),
                }
            )
        return cleaned[-100:]

    def _deep_merge(self, base: Dict[str, Any], updates: Dict[str, Any]) -> Dict[str, Any]:
        merged = deepcopy(base)
        for key, value in updates.items():
            if isinstance(value, dict) and isinstance(merged.get(key), dict):
                merged[key] = self._deep_merge(merged[key], value)
            else:
                merged[key] = deepcopy(value)
        return merged

    def _build_observations(
        self,
        listener: Dict[str, Any],
        agent: Dict[str, Any],
        requested_interval: int,
        user_agent: str,
        uri: str,
    ) -> List[Dict[str, str]]:
        observations: List[Dict[str, str]] = []
        http_config = listener.get("config", {}).get("http_config", {}) or {}
        allowed_user_agents = http_config.get("user_agents", [])
        allowed_uris = http_config.get("uris", [])

        if allowed_user_agents and user_agent not in allowed_user_agents:
            observations.append(
                {
                    "type": "user_agent_outlier",
                    "severity": "medium",
                    "message": "Heartbeat used a user-agent outside the configured listener profile.",
                }
            )

        if allowed_uris and uri not in allowed_uris:
            observations.append(
                {
                    "type": "uri_outlier",
                    "severity": "medium",
                    "message": "Heartbeat used a URI outside the configured listener profile.",
                }
            )

        if requested_interval < 1 or requested_interval > 3600:
            observations.append(
                {
                    "type": "interval_outlier",
                    "severity": "low",
                    "message": "Heartbeat interval was outside the recommended lab range.",
                }
            )

        if agent.get("heartbeat_count") == 1:
            observations.append(
                {
                    "type": "new_agent",
                    "severity": "info",
                    "message": "New simulated agent observed on this listener.",
                }
            )

        return observations

    def _refresh_listener_stats(self, listener_id: str) -> None:
        listener = self.listeners.get(listener_id)
        if not listener:
            return

        stats = listener.setdefault("stats", ListenerStats().to_dict())
        agents = self.agent_sessions.get(listener_id, {})
        stats["agents_connected"] = sum(1 for agent in agents.values() if agent.get("status") == "alive")
        stats["total_agents_seen"] = len(agents)

        start_time = stats.get("start_time")
        if listener.get("status") == ListenerStatus.ONLINE.value and start_time:
            parsed = self._parse_datetime(start_time)
            if parsed:
                stats["uptime_seconds"] = max(int((_utc_now() - parsed).total_seconds()), 0)
        else:
            stats["uptime_seconds"] = 0

        listener["agents_connected"] = stats["agents_connected"]

    def _public_listener(self, listener: Dict[str, Any]) -> Dict[str, Any]:
        public = deepcopy(listener)
        public["stats"] = deepcopy(listener.get("stats", {}))
        public["errors"] = deepcopy(listener.get("errors", []))
        public["config"] = deepcopy(listener.get("config", {}))
        public["metadata"] = deepcopy(listener.get("metadata", {}))
        public["http_headers"] = deepcopy(listener.get("http_headers", {}))
        public["agents_connected"] = public.get("stats", {}).get("agents_connected", 0)
        return public

    def _add_to_history(self, action: str, listener_id: str, details: Any) -> None:
        self.history.append(
            {
                "timestamp": _utc_now_iso(),
                "action": action,
                "listener_id": listener_id,
                "details": deepcopy(details),
            }
        )
        if len(self.history) > 1000:
            self.history = self.history[-1000:]

    def _parse_datetime(self, value: Any) -> Optional[datetime]:
        if not value:
            return None
        if isinstance(value, datetime):
            return value
        if not isinstance(value, str):
            return None
        try:
            return datetime.fromisoformat(value)
        except ValueError:
            return None

    def _pick_first(self, values: Any, fallback: str) -> str:
        if isinstance(values, list) and values:
            return str(values[0])
        return fallback


# Instance globale
listener_manager = ListenerManager()
