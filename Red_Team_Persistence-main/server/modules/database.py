"""
Module de base de données SQLite pour le Teamserver C2
"""
import os
import sqlite3
import json
import tempfile
from datetime import datetime
from typing import Optional, List, Dict, Any
from pathlib import Path


class C2Database:
    """Gestionnaire de base de données C2 (SQLite)"""
    
    def __init__(self, db_path: Optional[str] = None):
        self.db_path = self._resolve_db_path(db_path)
        self.connection = None
        self.init_database()

    def _resolve_db_path(self, db_path: Optional[str]) -> str:
        project_root = Path(__file__).resolve().parents[2]
        default_db_path = Path(tempfile.gettempdir()) / "Red_Team_Persistence" / "c2_framework.db"
        raw_path = db_path or os.getenv("C2_DB_PATH") or str(default_db_path)

        if raw_path == ":memory:":
            return raw_path

        resolved = Path(raw_path).expanduser()
        if not resolved.is_absolute():
            resolved = project_root / resolved
        resolved.parent.mkdir(parents=True, exist_ok=True)
        return str(resolved.resolve())
    
    def connect(self):
        """Connecte à la base de données"""
        self.connection = sqlite3.connect(self.db_path)
        self.connection.row_factory = sqlite3.Row  # Allow dict-like access
        self.connection.execute("PRAGMA foreign_keys = ON")
        return self.connection
    
    def disconnect(self):
        """Déconnecte de la base de données"""
        if self.connection:
            self.connection.close()
            self.connection = None
    
    def init_database(self):
        """Initialise le schéma de base de données"""
        conn = self.connect()
        cursor = conn.cursor()
        
        # Table Listeners
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS listeners (
                listener_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                protocol TEXT NOT NULL,
                host TEXT NOT NULL,
                port INTEGER NOT NULL,
                profile TEXT,
                enabled BOOLEAN DEFAULT 1,
                use_ssl BOOLEAN DEFAULT 1,
                cert_file TEXT,
                key_file TEXT,
                user_agent TEXT,
                callback_path TEXT,
                beacon_interval INTEGER,
                domain_front TEXT,
                http_headers TEXT,
                metadata TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                agents_connected INTEGER DEFAULT 0,
                status TEXT DEFAULT 'offline',
                last_modified TIMESTAMP,
                config TEXT,
                stats TEXT,
                errors TEXT
            )
        ''')
        
        # Table Agents
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS agents (
                agent_id TEXT PRIMARY KEY,
                listener_id TEXT NOT NULL,
                hostname TEXT NOT NULL,
                username TEXT NOT NULL,
                process_id INTEGER NOT NULL,
                ip_address TEXT NOT NULL,
                status TEXT DEFAULT 'alive',
                system_info TEXT NOT NULL,
                agent_version TEXT,
                privileges TEXT,
                sleep_interval INTEGER,
                jitter REAL,
                operating_system TEXT,
                hostname_domain TEXT,
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (listener_id) REFERENCES listeners(listener_id)
            )
        ''')
        
        # Table Tasks
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS tasks (
                task_id TEXT PRIMARY KEY,
                agent_id TEXT NOT NULL,
                request_id INTEGER NOT NULL,
                command_type TEXT NOT NULL,
                command_args TEXT,
                status TEXT DEFAULT 'staged',
                priority INTEGER DEFAULT 0,
                operator_id TEXT NOT NULL,
                mitre_technique TEXT,
                result TEXT,
                error TEXT,
                metadata TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                sent_at TIMESTAMP,
                completed_at TIMESTAMP,
                FOREIGN KEY (agent_id) REFERENCES agents(agent_id)
            )
        ''')
        
        # Table Execution Logs
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS execution_logs (
                log_id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id TEXT NOT NULL,
                task_id TEXT,
                command_type TEXT,
                status TEXT,
                result TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (agent_id) REFERENCES agents(agent_id),
                FOREIGN KEY (task_id) REFERENCES tasks(task_id)
            )
        ''')

        # Table Audit Reports
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS audit_reports (
                report_id TEXT PRIMARY KEY,
                listener_id TEXT NOT NULL,
                agent_id TEXT,
                machine_name TEXT,
                username TEXT,
                filename TEXT NOT NULL,
                report_json TEXT NOT NULL,
                finding_count INTEGER DEFAULT 0,
                risk_level TEXT,
                sha256 TEXT,
                source TEXT DEFAULT 'myagent',
                metadata TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Table Operators
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS operators (
                operator_id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT DEFAULT 'operator',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP,
                active BOOLEAN DEFAULT 1
            )
        ''')
        
        # Table Sessions
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY,
                operator_id TEXT NOT NULL,
                token TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP,
                active BOOLEAN DEFAULT 1,
                FOREIGN KEY (operator_id) REFERENCES operators(operator_id)
            )
        ''')
        
        # Create indices pour performance
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_agents_status ON agents(status)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_tasks_agent ON tasks(agent_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_logs_agent ON execution_logs(agent_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_audit_reports_listener ON audit_reports(listener_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_audit_reports_agent ON audit_reports(agent_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_audit_reports_created_at ON audit_reports(created_at)')
        
        conn.commit()
        self.disconnect()

        # Lightweight migration for existing DBs (older schema)
        self._migrate_listeners_table()

    def _migrate_listeners_table(self):
        """Ajoute les colonnes listeners v2 si absentes (SQLite ALTER TABLE)"""
        conn = self.connect()
        cursor = conn.cursor()
        try:
            cursor.execute("PRAGMA table_info(listeners)")
            cols = {row["name"] if isinstance(row, sqlite3.Row) else row[1] for row in cursor.fetchall()}
            wanted = {
                "status": "TEXT DEFAULT 'offline'",
                "last_modified": "TIMESTAMP",
                "config": "TEXT",
                "stats": "TEXT",
                "errors": "TEXT",
            }
            for col, ddl in wanted.items():
                if col in cols:
                    continue
                cursor.execute(f"ALTER TABLE listeners ADD COLUMN {col} {ddl}")
            conn.commit()
        finally:
            self.disconnect()
    
    def add_agent(self, agent_dict: Dict[str, Any]) -> bool:
        """Ajoute un nouvel agent"""
        conn = self.connect()
        cursor = conn.cursor()
        
        system_info_json = json.dumps(agent_dict.get('system_info', {}))
        metadata_json = json.dumps(agent_dict.get('metadata', {}))
        
        try:
            cursor.execute('''
                INSERT INTO agents 
                (agent_id, listener_id, hostname, username, process_id, ip_address,
                 system_info, agent_version, privileges, sleep_interval, jitter,
                 operating_system, hostname_domain)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                agent_dict['agent_id'],
                agent_dict['listener_id'],
                agent_dict['hostname'],
                agent_dict['username'],
                agent_dict['process_id'],
                agent_dict.get('ip_address', '0.0.0.0'),
                system_info_json,
                agent_dict.get('agent_version', '1.0.0'),
                agent_dict.get('privileges', 'user'),
                agent_dict.get('sleep_interval', 5),
                agent_dict.get('jitter', 0.2),
                agent_dict.get('operating_system', 'Windows'),
                agent_dict.get('hostname_domain', '')
            ))
            conn.commit()
            return True
        except Exception as e:
            print(f"Error adding agent: {e}")
            return False
        finally:
            self.disconnect()
    
    def get_agent(self, agent_id: str) -> Optional[Dict]:
        """Récupère un agent par ID"""
        conn = self.connect()
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM agents WHERE agent_id = ?', (agent_id,))
        row = cursor.fetchone()
        self.disconnect()
        
        if row:
            return dict(row)
        return None
    
    def get_all_agents(self) -> List[Dict]:
        """Récupère tous les agents"""
        conn = self.connect()
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM agents ORDER BY last_seen DESC')
        rows = cursor.fetchall()
        self.disconnect()
        
        return [dict(row) for row in rows]
    
    def update_agent_last_seen(self, agent_id: str):
        """Met à jour le timestamp last_seen"""
        conn = self.connect()
        cursor = conn.cursor()
        
        cursor.execute(
            'UPDATE agents SET last_seen = CURRENT_TIMESTAMP WHERE agent_id = ?',
            (agent_id,)
        )
        conn.commit()
        self.disconnect()

    def add_listener(self, listener_dict: Dict[str, Any]) -> bool:
        """Ajoute un nouveau listener"""
        conn = self.connect()
        cursor = conn.cursor()

        http_headers_json = json.dumps(listener_dict.get('http_headers', {}))
        metadata_json = json.dumps(listener_dict.get('metadata', {}))
        config_json = json.dumps(listener_dict.get('config', {}))
        stats_json = json.dumps(listener_dict.get('stats', {}))
        errors_json = json.dumps(listener_dict.get('errors', []))

        try:
            cursor.execute('''
                INSERT INTO listeners
                (listener_id, name, protocol, host, port, profile, enabled, use_ssl,
                 cert_file, key_file, user_agent, callback_path, beacon_interval,
                 domain_front, http_headers, metadata, agents_connected, status, last_modified, config, stats, errors)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                listener_dict['listener_id'],
                listener_dict['name'],
                listener_dict.get('protocol', 'https'),
                listener_dict.get('host', '0.0.0.0'),
                listener_dict['port'],
                listener_dict.get('profile', 'default'),
                1 if listener_dict.get('enabled', True) else 0,
                1 if listener_dict.get('use_ssl', True) else 0,
                listener_dict.get('cert_file'),
                listener_dict.get('key_file'),
                listener_dict.get('user_agent', 'Mozilla/5.0'),
                listener_dict.get('callback_path', '/api/beacon'),
                listener_dict.get('beacon_interval', 5),
                listener_dict.get('domain_front'),
                http_headers_json,
                metadata_json,
                listener_dict.get('agents_connected', 0),
                listener_dict.get('status', 'offline'),
                listener_dict.get('last_modified'),
                config_json,
                stats_json,
                errors_json,
            ))
            conn.commit()
            return True
        except Exception as e:
            print(f"Error adding listener: {e}")
            return False
        finally:
            self.disconnect()

    def get_all_listeners(self) -> List[Dict]:
        """Récupère tous les listeners"""
        conn = self.connect()
        cursor = conn.cursor()

        cursor.execute('SELECT * FROM listeners ORDER BY created_at DESC')
        rows = cursor.fetchall()
        self.disconnect()

        listeners = []
        for row in rows:
            listener = dict(row)
            if isinstance(listener.get('http_headers'), str):
                try:
                    listener['http_headers'] = json.loads(listener['http_headers'])
                except Exception:
                    listener['http_headers'] = {}
            if isinstance(listener.get('metadata'), str):
                try:
                    listener['metadata'] = json.loads(listener['metadata'])
                except Exception:
                    listener['metadata'] = {}
            if isinstance(listener.get('config'), str):
                try:
                    listener['config'] = json.loads(listener['config'])
                except Exception:
                    listener['config'] = {}
            if isinstance(listener.get('stats'), str):
                try:
                    listener['stats'] = json.loads(listener['stats'])
                except Exception:
                    listener['stats'] = {}
            if isinstance(listener.get('errors'), str):
                try:
                    listener['errors'] = json.loads(listener['errors'])
                except Exception:
                    listener['errors'] = []
            listeners.append(listener)

        return listeners

    def get_listener(self, listener_id: str) -> Optional[Dict]:
        """Récupère un listener par ID"""
        conn = self.connect()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM listeners WHERE listener_id = ?', (listener_id,))
        row = cursor.fetchone()
        self.disconnect()
        if not row:
            return None
        listener = dict(row)
        if isinstance(listener.get('http_headers'), str):
            try:
                listener['http_headers'] = json.loads(listener['http_headers'])
            except Exception:
                listener['http_headers'] = {}
        if isinstance(listener.get('metadata'), str):
            try:
                listener['metadata'] = json.loads(listener['metadata'])
            except Exception:
                listener['metadata'] = {}
        if isinstance(listener.get('config'), str):
            try:
                listener['config'] = json.loads(listener['config'])
            except Exception:
                listener['config'] = {}
        if isinstance(listener.get('stats'), str):
            try:
                listener['stats'] = json.loads(listener['stats'])
            except Exception:
                listener['stats'] = {}
        if isinstance(listener.get('errors'), str):
            try:
                listener['errors'] = json.loads(listener['errors'])
            except Exception:
                listener['errors'] = []
        return listener

    def update_listener(self, listener_id: str, updates: Dict[str, Any]) -> bool:
        """Met à jour un listener (champs supportés: name, protocol, host, port, use_ssl, enabled)"""
        allowed = {
            "name", "protocol", "host", "port", "use_ssl", "enabled", "profile",
            "cert_file", "key_file", "user_agent", "callback_path", "beacon_interval",
            "domain_front", "http_headers", "metadata", "agents_connected",
            "status", "last_modified", "config", "stats", "errors"
        }
        sets = []
        values = []
        for k, v in updates.items():
            if k not in allowed:
                continue
            if k in {"use_ssl", "enabled"}:
                v = 1 if bool(v) else 0
            if k in {"http_headers", "metadata", "config", "stats", "errors"} and not isinstance(v, str):
                v = json.dumps(v)
            sets.append(f"{k} = ?")
            values.append(v)
        if not sets:
            return False

        conn = self.connect()
        cursor = conn.cursor()
        try:
            cursor.execute(f"UPDATE listeners SET {', '.join(sets)} WHERE listener_id = ?", (*values, listener_id))
            conn.commit()
            return cursor.rowcount > 0
        except Exception as e:
            print(f"Error updating listener: {e}")
            return False
        finally:
            self.disconnect()

    def delete_listener(self, listener_id: str) -> bool:
        """Supprime un listener"""
        conn = self.connect()
        cursor = conn.cursor()
        try:
            cursor.execute("DELETE FROM listeners WHERE listener_id = ?", (listener_id,))
            conn.commit()
            return cursor.rowcount > 0
        except Exception as e:
            print(f"Error deleting listener: {e}")
            return False
        finally:
            self.disconnect()
    
    def add_task(self, task_dict: Dict[str, Any]) -> bool:
        """Ajoute une nouvelle tâche"""
        conn = self.connect()
        cursor = conn.cursor()
        
        command_args_json = json.dumps(task_dict.get('command_args', {}))
        metadata_json = json.dumps(task_dict.get('metadata', {}))
        
        try:
            cursor.execute('''
                INSERT INTO tasks
                (task_id, agent_id, request_id, command_type, command_args, status,
                 priority, operator_id, mitre_technique, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                task_dict['task_id'],
                task_dict['agent_id'],
                task_dict['request_id'],
                task_dict['command_type'],
                command_args_json,
                task_dict.get('status', 'staged'),
                task_dict.get('priority', 0),
                task_dict['operator_id'],
                task_dict.get('mitre_technique'),
                metadata_json
            ))
            conn.commit()
            return True
        except Exception as e:
            print(f"Error adding task: {e}")
            return False
        finally:
            self.disconnect()
    
    def get_pending_tasks(self, agent_id: str) -> List[Dict]:
        """Récupère les tâches en attente pour un agent"""
        conn = self.connect()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT * FROM tasks 
            WHERE agent_id = ? AND status IN ('staged', 'sent')
            ORDER BY priority DESC, created_at ASC
        ''', (agent_id,))
        
        rows = cursor.fetchall()
        self.disconnect()
        
        return [dict(row) for row in rows]
    
    def update_task_status(self, task_id: str, status: str, result: str = None, error: str = None):
        """Met à jour le statut d'une tâche"""
        conn = self.connect()
        cursor = conn.cursor()
        
        if status == 'completed' or status == 'failed':
            cursor.execute('''
                UPDATE tasks 
                SET status = ?, result = ?, error = ?, completed_at = CURRENT_TIMESTAMP
                WHERE task_id = ?
            ''', (status, result, error, task_id))
        else:
            cursor.execute('''
                UPDATE tasks SET status = ?
                WHERE task_id = ?
            ''', (status, task_id))
        
        conn.commit()
        self.disconnect()
    
    def log_execution(self, agent_id: str, task_id: str, command_type: str, 
                     status: str, result: str = None):
        """Enregistre une exécution de tâche"""
        conn = self.connect()
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO execution_logs
            (agent_id, task_id, command_type, status, result)
            VALUES (?, ?, ?, ?, ?)
        ''', (agent_id, task_id, command_type, status, result))
        
        conn.commit()
        self.disconnect()

    def add_audit_report(self, report_dict: Dict[str, Any]) -> bool:
        """Ajoute un rapport d'audit JSON."""
        conn = self.connect()
        cursor = conn.cursor()

        metadata_json = json.dumps(report_dict.get("metadata", {}))

        try:
            cursor.execute(
                '''
                INSERT INTO audit_reports
                (report_id, listener_id, agent_id, machine_name, username, filename,
                 report_json, finding_count, risk_level, sha256, source, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''',
                (
                    report_dict["report_id"],
                    report_dict["listener_id"],
                    report_dict.get("agent_id"),
                    report_dict.get("machine_name"),
                    report_dict.get("username"),
                    report_dict["filename"],
                    report_dict["report_json"],
                    int(report_dict.get("finding_count", 0)),
                    report_dict.get("risk_level"),
                    report_dict.get("sha256"),
                    report_dict.get("source", "myagent"),
                    metadata_json,
                ),
            )
            conn.commit()
            return True
        except Exception as e:
            print(f"Error adding audit report: {e}")
            return False
        finally:
            self.disconnect()

    def get_audit_report(self, report_id: str) -> Optional[Dict[str, Any]]:
        """RÃ©cupÃ¨re un rapport d'audit par ID."""
        conn = self.connect()
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM audit_reports WHERE report_id = ?", (report_id,))
        row = cursor.fetchone()
        self.disconnect()

        if not row:
            return None
        return self._decode_audit_report(dict(row))

    def get_audit_reports(
        self,
        listener_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """RÃ©cupÃ¨re les rapports d'audit les plus rÃ©cents."""
        conn = self.connect()
        cursor = conn.cursor()

        clauses = []
        values: List[Any] = []

        if listener_id:
            clauses.append("listener_id = ?")
            values.append(listener_id)
        if agent_id:
            clauses.append("agent_id = ?")
            values.append(agent_id)

        query = "SELECT * FROM audit_reports"
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY created_at DESC LIMIT ?"
        values.append(limit)

        cursor.execute(query, tuple(values))
        rows = cursor.fetchall()
        self.disconnect()
        return [self._decode_audit_report(dict(row)) for row in rows]

    def count_audit_reports(self) -> int:
        """Compte le nombre total de rapports d'audit."""
        conn = self.connect()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) AS total FROM audit_reports")
        row = cursor.fetchone()
        self.disconnect()
        return int((dict(row) if row else {}).get("total", 0))

    def _decode_audit_report(self, report: Dict[str, Any]) -> Dict[str, Any]:
        """DÃ©code les champs JSON d'un rapport d'audit."""
        if isinstance(report.get("metadata"), str):
            try:
                report["metadata"] = json.loads(report["metadata"])
            except Exception:
                report["metadata"] = {}
        return report
