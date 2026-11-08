"""
Listener Manager - Gestion avancée des listeners C2
Inspiré par Havoc Framework et Adaptix
"""
import json
import random
import secrets
from typing import List, Dict, Optional, Any
from datetime import datetime
from enum import Enum
import socket
import ssl
import logging

logger = logging.getLogger(__name__)


class ListenerStatus(str, Enum):
    """État d'un listener"""
    OFFLINE = "offline"
    ONLINE = "online"
    ERROR = "error"
    PAUSED = "paused"


class ListenerStats:
    """Statistiques d'un listener"""
    
    def __init__(self):
        self.agents_connected = 0
        self.total_agents_seen = 0
        self.tasks_sent = 0
        self.tasks_completed = 0
        self.bytes_received = 0
        self.bytes_sent = 0
        self.start_time = datetime.utcnow()
        self.uptime_seconds = 0
        self.last_activity = None
        self.errors_count = 0

    def to_dict(self) -> Dict[str, Any]:
        """Convertit les stats en dictionnaire"""
        return {
            "agents_connected": self.agents_connected,
            "total_agents_seen": self.total_agents_seen,
            "tasks_sent": self.tasks_sent,
            "tasks_completed": self.tasks_completed,
            "bytes_received": self.bytes_received,
            "bytes_sent": self.bytes_sent,
            "start_time": self.start_time.isoformat(),
            "uptime_seconds": self.uptime_seconds,
            "last_activity": self.last_activity.isoformat() if self.last_activity else None,
            "errors_count": self.errors_count
        }


class ListenerManager:
    """Gestionnaire principal des listeners"""
    
    def __init__(self):
        self.listeners: Dict[str, Dict[str, Any]] = {}
        self.profiles: Dict[str, Dict[str, Any]] = {}
        self.history: List[Dict[str, Any]] = []
        self.logger = logging.getLogger("ListenerManager")

    def validate_port_available(self, host: str, port: int) -> bool:
        """Vérifie si le port est disponible"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            result = sock.connect_ex((host, port))
            sock.close()
            return result != 0
        except Exception as e:
            self.logger.error(f"Error checking port {port}: {e}")
            return False

    def validate_ssl_cert(self, cert_file: str, key_file: str) -> bool:
        """Valide les fichiers SSL/TLS"""
        try:
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            context.load_cert_chain(cert_file, key_file)
            return True
        except Exception as e:
            self.logger.error(f"SSL/TLS validation error: {e}")
            return False

    def generate_encryption_key(self) -> Dict[str, str]:
        """Génère une clé d'encryptage AES-256-GCM"""
        key = secrets.token_hex(32)  # 256 bits
        iv = secrets.token_hex(16)   # 128 bits
        return {"key": key, "iv": iv}

    def create_listener(self, listener_config: Dict[str, Any], *, skip_validation: bool = False) -> Dict[str, Any]:
        """Crée un nouveau listener avec validation complète"""
        
        listener_id = listener_config.get("listener_id")
        if not listener_id:
            listener_id = f"listener_{secrets.token_hex(6)}"

        # Validation port
        host = listener_config.get("host", "0.0.0.0")
        port = listener_config.get("port")
        
        if not skip_validation:
            if port and not self.validate_port_available(host if host != "0.0.0.0" else "127.0.0.1", port):
                raise ValueError(f"Port {port} already in use")

        # SSL/TLS validation
        if not skip_validation:
            if listener_config.get("use_ssl"):
                cert_file = listener_config.get("cert_file")
                key_file = listener_config.get("key_file")
                
                if cert_file and key_file:
                    if not self.validate_ssl_cert(cert_file, key_file):
                        raise ValueError("Invalid SSL/TLS certificates")

        # Generate encryption keys if needed
        if listener_config.get("encryption_config", {}).get("generate_key"):
            encryption_keys = self.generate_encryption_key()
            if "encryption_config" not in listener_config:
                listener_config["encryption_config"] = {}
            listener_config["encryption_config"]["key"] = encryption_keys["key"]
            listener_config["encryption_config"]["iv"] = encryption_keys["iv"]

        # Create listener entry
        listener = {
            "listener_id": listener_id,
            "name": listener_config.get("name", f"Listener_{listener_id}"),
            "protocol": listener_config.get("protocol", "https"),
            "host": host,
            "port": port,
            "profile": listener_config.get("profile", "custom"),
            "enabled": listener_config.get("enabled", True),
            "status": ListenerStatus.ONLINE.value,
            "created_at": datetime.utcnow().isoformat(),
            "last_modified": datetime.utcnow().isoformat(),
            "config": listener_config,
            "stats": ListenerStats().to_dict(),
            "errors": []
        }

        self.listeners[listener_id] = listener
        self._add_to_history("listener_created", listener_id, listener)
        
        return listener

    def update_listener(self, listener_id: str, updates: Dict[str, Any]) -> Dict[str, Any]:
        """Met à jour un listener existant"""
        
        if listener_id not in self.listeners:
            raise ValueError(f"Listener not found: {listener_id}")

        listener = self.listeners[listener_id]
        
        # Port change validation
        if "port" in updates or "host" in updates:
            host = updates.get("host", listener["host"])
            port = updates.get("port", listener["port"])
            if not self.validate_port_available(host if host != "0.0.0.0" else "127.0.0.1", port):
                raise ValueError(f"Port {port} already in use")

        # Update config
        if "config" in updates:
            listener["config"].update(updates["config"])
        else:
            for key in ["enabled", "status", "profile"]:
                if key in updates:
                    listener[key] = updates[key]

        listener["last_modified"] = datetime.utcnow().isoformat()
        self._add_to_history("listener_updated", listener_id, updates)
        
        return listener

    def delete_listener(self, listener_id: str) -> bool:
        """Supprime un listener"""
        
        if listener_id not in self.listeners:
            raise ValueError(f"Listener not found: {listener_id}")

        listener = self.listeners.pop(listener_id)
        self._add_to_history("listener_deleted", listener_id, listener)
        
        return True

    def start_listener(self, listener_id: str) -> Dict[str, Any]:
        """Démarre un listener"""
        
        if listener_id not in self.listeners:
            raise ValueError(f"Listener not found: {listener_id}")

        listener = self.listeners[listener_id]
        listener["status"] = ListenerStatus.ONLINE.value
        listener["stats"]["start_time"] = datetime.utcnow().isoformat()
        self._add_to_history("listener_started", listener_id, {})
        
        return listener

    def stop_listener(self, listener_id: str) -> Dict[str, Any]:
        """Arrête un listener"""
        
        if listener_id not in self.listeners:
            raise ValueError(f"Listener not found: {listener_id}")

        listener = self.listeners[listener_id]
        listener["status"] = ListenerStatus.OFFLINE.value
        self._add_to_history("listener_stopped", listener_id, {})
        
        return listener

    def get_listener(self, listener_id: str) -> Optional[Dict[str, Any]]:
        """Récupère les infos d'un listener"""
        return self.listeners.get(listener_id)

    def list_listeners(self) -> List[Dict[str, Any]]:
        """Liste tous les listeners"""
        return list(self.listeners.values())

    def get_listener_by_name(self, name: str) -> Optional[Dict[str, Any]]:
        """Récupère un listener par son nom"""
        for listener in self.listeners.values():
            if listener["name"] == name:
                return listener
        return None

    def update_listener_stats(self, listener_id: str, stats_update: Dict[str, Any]) -> bool:
        """Met à jour les statistiques d'un listener"""
        
        if listener_id not in self.listeners:
            return False

        listener = self.listeners[listener_id]
        stats = listener["stats"]
        
        for key, value in stats_update.items():
            if key in stats:
                if isinstance(stats[key], int):
                    stats[key] += value
                else:
                    stats[key] = value

        stats["last_activity"] = datetime.utcnow().isoformat()
        listener["stats"] = stats
        
        return True

    def get_listener_stats(self, listener_id: str) -> Optional[Dict[str, Any]]:
        """Récupère les statistiques d'un listener"""
        
        if listener_id not in self.listeners:
            return None

        return self.listeners[listener_id]["stats"]

    def get_listener_errors(self, listener_id: str) -> List[Dict[str, Any]]:
        """Récupère les erreurs d'un listener"""
        
        if listener_id not in self.listeners:
            return []

        return self.listeners[listener_id]["errors"]

    def add_listener_error(self, listener_id: str, error_msg: str) -> bool:
        """Ajoute une erreur à un listener"""
        
        if listener_id not in self.listeners:
            return False

        self.listeners[listener_id]["errors"].append({
            "timestamp": datetime.utcnow().isoformat(),
            "message": error_msg
        })
        
        # Keep only last 100 errors
        if len(self.listeners[listener_id]["errors"]) > 100:
            self.listeners[listener_id]["errors"] = self.listeners[listener_id]["errors"][-100:]

        self.listeners[listener_id]["stats"]["errors_count"] += 1
        
        return True

    def get_random_http_header(self, listener_id: str) -> Dict[str, str]:
        """Récupère des headers HTTP aléatoires pour un listener"""
        
        listener = self.get_listener(listener_id)
        if not listener:
            return {}

        config = listener.get("config", {})
        http_config = config.get("http_config", {})
        headers = http_config.get("headers", {})
        
        return headers

    def get_random_user_agent(self, listener_id: str) -> str:
        """Récupère un User-Agent aléatoire"""
        
        listener = self.get_listener(listener_id)
        if not listener:
            return "Mozilla/5.0"

        config = listener.get("config", {})
        http_config = config.get("http_config", {})
        user_agents = http_config.get("user_agents", ["Mozilla/5.0"])
        
        return random.choice(user_agents) if user_agents else "Mozilla/5.0"

    def get_random_uri(self, listener_id: str) -> str:
        """Récupère une URI aléatoire"""
        
        listener = self.get_listener(listener_id)
        if not listener:
            return "/api/beacon"

        config = listener.get("config", {})
        http_config = config.get("http_config", {})
        uris = http_config.get("uris", ["/api/beacon"])
        
        return random.choice(uris) if uris else "/api/beacon"

    def export_listener_profile(self, listener_id: str) -> str:
        """Exporte la configuration d'un listener en JSON"""
        
        listener = self.get_listener(listener_id)
        if not listener:
            return ""

        return json.dumps(listener, indent=2, default=str)

    def import_listener_profile(self, profile_json: str) -> Dict[str, Any]:
        """Importe la configuration d'un listener depuis JSON"""
        
        try:
            config = json.loads(profile_json)
            return self.create_listener(config)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON profile: {e}")

    def _add_to_history(self, action: str, listener_id: str, details: Any) -> None:
        """Ajoute une entrée à l'historique"""
        
        self.history.append({
            "timestamp": datetime.utcnow().isoformat(),
            "action": action,
            "listener_id": listener_id,
            "details": details
        })
        
        # Keep only last 1000 entries
        if len(self.history) > 1000:
            self.history = self.history[-1000:]

    def get_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Récupère l'historique des listeners"""
        return self.history[-limit:]

    def get_summary(self) -> Dict[str, Any]:
        """Récupère un résumé de tous les listeners"""
        
        total_agents = 0
        total_tasks = 0
        listeners_online = 0
        listeners_offline = 0

        for listener in self.listeners.values():
            stats = listener.get("stats", {})
            total_agents += stats.get("agents_connected", 0)
            total_tasks += stats.get("tasks_sent", 0)
            
            if listener["status"] == ListenerStatus.ONLINE.value:
                listeners_online += 1
            else:
                listeners_offline += 1

        return {
            "total_listeners": len(self.listeners),
            "listeners_online": listeners_online,
            "listeners_offline": listeners_offline,
            "total_agents": total_agents,
            "total_tasks": total_tasks,
            "uptime": "N/A"
        }
