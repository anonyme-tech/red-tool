#!/usr/bin/env python3
"""
Safe CLI for the defensive listener lab.
"""

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests


API_BASE_URL = "http://localhost:8000/api/listeners"
TIMEOUT = 10


def _print_rows(rows: List[Dict[str, Any]], columns: List[str]) -> None:
    if not rows:
        print("(empty)")
        return

    widths = {column: len(column) for column in columns}
    for row in rows:
        for column in columns:
            widths[column] = max(widths[column], len(str(row.get(column, ""))))

    header = " | ".join(column.ljust(widths[column]) for column in columns)
    rule = "-+-".join("-" * widths[column] for column in columns)
    print(header)
    print(rule)
    for row in rows:
        print(" | ".join(str(row.get(column, "")).ljust(widths[column]) for column in columns))


class ListenerCLI:
    def __init__(self):
        self.api_base = API_BASE_URL
        self.timeout = TIMEOUT

    def make_request(self, method: str, endpoint: str, data: Optional[Dict[str, Any]] = None) -> Dict[str, Any] | List[Any]:
        url = f"{self.api_base}{endpoint}"
        if method == "GET":
            response = requests.get(url, timeout=self.timeout)
        elif method == "POST":
            response = requests.post(url, json=data, timeout=self.timeout)
        elif method == "PUT":
            response = requests.put(url, json=data, timeout=self.timeout)
        elif method == "DELETE":
            response = requests.delete(url, timeout=self.timeout)
        else:
            raise ValueError(f"Unsupported method: {method}")

        if response.status_code >= 400:
            try:
                detail = response.json().get("detail")
            except Exception:
                detail = response.text
            raise RuntimeError(f"HTTP {response.status_code}: {detail}")

        return response.json() if response.text else {"status": "ok"}

    def list_listeners(self):
        listeners = self.make_request("GET", "/")
        rows = [
            {
                "id": listener.get("listener_id", ""),
                "name": listener.get("name", ""),
                "host": listener.get("host", ""),
                "port": listener.get("port", ""),
                "profile": listener.get("profile", ""),
                "status": listener.get("status", ""),
                "agents": listener.get("stats", {}).get("agents_connected", 0),
            }
            for listener in listeners
        ]
        _print_rows(rows, ["id", "name", "host", "port", "profile", "status", "agents"])

    def show_listener(self, listener_id: str):
        print(json.dumps(self.make_request("GET", f"/{listener_id}"), indent=2, default=str))

    def create_listener(self, config_file: str):
        payload = json.loads(Path(config_file).read_text(encoding="utf-8"))
        result = self.make_request("POST", "/", payload)
        print(json.dumps(result, indent=2, default=str))

    def start_listener(self, listener_id: str):
        print(json.dumps(self.make_request("POST", f"/{listener_id}/start", {}), indent=2, default=str))

    def stop_listener(self, listener_id: str):
        print(json.dumps(self.make_request("POST", f"/{listener_id}/stop", {}), indent=2, default=str))

    def delete_listener(self, listener_id: str):
        print(json.dumps(self.make_request("DELETE", f"/{listener_id}"), indent=2, default=str))

    def show_stats(self, listener_id: str):
        print(json.dumps(self.make_request("GET", f"/{listener_id}/stats"), indent=2, default=str))

    def show_errors(self, listener_id: str, limit: int = 10):
        result = self.make_request("GET", f"/{listener_id}/errors?limit={limit}")
        print(json.dumps(result, indent=2, default=str))

    def list_profiles(self):
        profiles = self.make_request("GET", "/profiles/list")
        _print_rows(list(profiles), ["type", "profile_id", "profile_name", "description"])

    def apply_profile(self, profile_type: str, listener_id: str):
        print(json.dumps(self.make_request("POST", f"/profiles/apply/{profile_type}/{listener_id}", {}), indent=2, default=str))

    def show_summary(self):
        print(json.dumps(self.make_request("GET", "/status/summary"), indent=2, default=str))

    def show_history(self, limit: int = 20, listener_id: Optional[str] = None):
        endpoint = f"/history?limit={limit}"
        if listener_id:
            endpoint += f"&listener_id={listener_id}"
        result = self.make_request("GET", endpoint)
        rows = [
            {
                "timestamp": item.get("timestamp", ""),
                "action": item.get("action", ""),
                "listener_id": item.get("listener_id", ""),
            }
            for item in result
        ]
        _print_rows(rows, ["timestamp", "action", "listener_id"])

    def export_listener(self, listener_id: str, output_file: str):
        result = self.make_request("GET", f"/{listener_id}/export")
        Path(output_file).write_text(result.get("profile_json", ""), encoding="utf-8")
        print(f"Exported to {output_file}")

    def list_agents(self, listener_id: str):
        result = self.make_request("GET", f"/{listener_id}/agents")
        agents = result.get("agents", [])
        rows = [
            {
                "agent_id": agent.get("agent_id", ""),
                "hostname": agent.get("hostname", ""),
                "status": agent.get("status", ""),
                "last_seen": agent.get("last_seen", ""),
                "count": agent.get("heartbeat_count", 0),
            }
            for agent in agents
        ]
        _print_rows(rows, ["agent_id", "hostname", "status", "last_seen", "count"])

    def send_heartbeat(self, listener_id: str, agent_id: str, signal: str):
        payload = {
            "agent_id": agent_id,
            "hostname": agent_id,
            "username": "lab-user",
            "process_id": 0,
            "system_info": {
                "os": "Simulated",
                "hostname": agent_id,
                "username": "lab-user",
                "domain": "lab.local",
                "pid": 0,
                "architecture": "x64",
                "privileges": "simulated",
            },
            "event_type": "heartbeat",
            "signal": signal,
            "sleep_interval": 5,
            "jitter": 0.1,
            "ip_address": "127.0.0.1",
            "user_agent": "LabSimulator/1.0",
            "uri": "/lab/heartbeat",
            "metadata": {"manual_cli": True},
        }
        print(json.dumps(self.make_request("POST", f"/{listener_id}/heartbeat", payload), indent=2, default=str))


def main():
    parser = argparse.ArgumentParser(description="Defensive listener lab CLI")
    subparsers = parser.add_subparsers(dest="command", help="Commands")

    subparsers.add_parser("list", help="List listeners")

    show_parser = subparsers.add_parser("show", help="Show listener details")
    show_parser.add_argument("listener_id")

    create_parser = subparsers.add_parser("create", help="Create listener from JSON config")
    create_parser.add_argument("config_file")

    start_parser = subparsers.add_parser("start", help="Start a listener")
    start_parser.add_argument("listener_id")

    stop_parser = subparsers.add_parser("stop", help="Stop a listener")
    stop_parser.add_argument("listener_id")

    delete_parser = subparsers.add_parser("delete", help="Delete a listener")
    delete_parser.add_argument("listener_id")

    stats_parser = subparsers.add_parser("stats", help="Show listener stats")
    stats_parser.add_argument("listener_id")

    errors_parser = subparsers.add_parser("errors", help="Show listener errors")
    errors_parser.add_argument("listener_id")
    errors_parser.add_argument("--limit", type=int, default=10)

    subparsers.add_parser("profiles", help="List profiles")

    apply_parser = subparsers.add_parser("apply-profile", help="Apply profile to a listener")
    apply_parser.add_argument("profile_type")
    apply_parser.add_argument("listener_id")

    subparsers.add_parser("summary", help="Show summary")

    history_parser = subparsers.add_parser("history", help="Show recent listener history")
    history_parser.add_argument("--limit", type=int, default=20)
    history_parser.add_argument("--listener-id")

    export_parser = subparsers.add_parser("export", help="Export listener config")
    export_parser.add_argument("listener_id")
    export_parser.add_argument("--output", "-o", default="listener_export.json")

    agents_parser = subparsers.add_parser("agents", help="List simulated agents for a listener")
    agents_parser.add_argument("listener_id")

    heartbeat_parser = subparsers.add_parser("heartbeat", help="Send a manual heartbeat")
    heartbeat_parser.add_argument("listener_id")
    heartbeat_parser.add_argument("agent_id")
    heartbeat_parser.add_argument("--signal", default="manual")

    args = parser.parse_args()
    cli = ListenerCLI()

    if args.command == "list":
        cli.list_listeners()
    elif args.command == "show":
        cli.show_listener(args.listener_id)
    elif args.command == "create":
        cli.create_listener(args.config_file)
    elif args.command == "start":
        cli.start_listener(args.listener_id)
    elif args.command == "stop":
        cli.stop_listener(args.listener_id)
    elif args.command == "delete":
        cli.delete_listener(args.listener_id)
    elif args.command == "stats":
        cli.show_stats(args.listener_id)
    elif args.command == "errors":
        cli.show_errors(args.listener_id, args.limit)
    elif args.command == "profiles":
        cli.list_profiles()
    elif args.command == "apply-profile":
        cli.apply_profile(args.profile_type, args.listener_id)
    elif args.command == "summary":
        cli.show_summary()
    elif args.command == "history":
        cli.show_history(limit=args.limit, listener_id=args.listener_id)
    elif args.command == "export":
        cli.export_listener(args.listener_id, args.output)
    elif args.command == "agents":
        cli.list_agents(args.listener_id)
    elif args.command == "heartbeat":
        cli.send_heartbeat(args.listener_id, args.agent_id, args.signal)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
