import json
import sqlite3
import os
import time
from datetime import datetime
from utils.output import section, info, success, warning, error, result, table


class ProjectDB:
    description = "Project database: SQLite-backed target/project management with scan comparison"

    DB_DIR = os.path.expanduser("~/.reconnor")
    DB_PATH = os.path.join(DB_DIR, "projects.db")

    @staticmethod
    def run(cmd="", project="", target="", tool="", tool_name="", file="", name="", list_runs=False, compare="", timeout=5, **kwargs):
        section("Project Database")

        os.makedirs(ProjectDB.DB_DIR, exist_ok=True)
        conn = sqlite3.connect(ProjectDB.DB_PATH)
        conn.row_factory = sqlite3.Row
        ProjectDB._init_db(conn)

        result_data = {"database": ProjectDB.DB_PATH, "command": cmd, "project": project, "result": None}

        if cmd == "init" or (not cmd and (name or project)):
            project_name = name or project
            ProjectDB._ensure_project(conn, project_name, target or "")
            result_data["result"] = f"Project '{project_name}' initialized"
            success(f"Project '{project_name}' ready")

        elif cmd == "list":
            projects = [dict(p) for p in ProjectDB._list_projects(conn)]
            result_data["result"] = projects
            if projects:
                table(["ID", "Name", "Target", "Runs", "Created"], [[p["id"], p["name"], p.get("target", ""), p["run_count"], p["created_at"]] for p in projects])
            else:
                info("No projects yet")

        elif cmd == "save" and file:
            run_id = ProjectDB._save_scan(conn, name or project, tool or tool_name, file, target)
            result_data["result"] = {"run_id": run_id}
            success(f"Scan saved as run #{run_id}")

        elif cmd == "runs" or list_runs:
            if name or project:
                project_name = name or project
                runs = [dict(r) for r in ProjectDB._list_runs(conn, project_name)]
                result_data["result"] = runs
                if runs:
                    table(["ID", "Tool", "Target", "Date", "File"], [[r["id"], r["tool"], r.get("target", ""), r["created_at"], r.get("file_path", "")[:40]] for r in runs])
                else:
                    info(f"No runs for project '{project}'")
            else:
                info("Specify --project to list runs")

        elif cmd == "show":
            run = ProjectDB._get_run(conn, name or "")
            if run:
                run = dict(run)
                result_data["result"] = run
                result("Run ID", str(run["id"]))
                result("Tool", run["tool"])
                result("Target", run.get("target", ""))
                result("Date", run["created_at"])
                if run.get("file_path") and os.path.exists(run["file_path"]):
                    try:
                        with open(run["file_path"]) as f:
                            data = json.load(f)
                        info(f"Data: {json.dumps(data, indent=2, default=str)[:1000]}")
                    except:
                        warning(f"Cannot read {run['file_path']}")
            else:
                warning(f"Run {name} not found")

        elif cmd == "compare" and compare:
            parts = compare.split(",")
            runs_data = []
            for run_id in parts:
                run = ProjectDB._get_run(conn, run_id.strip())
                if run:
                    run = dict(run)
                if run and run.get("file_path") and os.path.exists(run["file_path"]):
                    try:
                        with open(run["file_path"]) as f:
                            data = json.load(f)
                            runs_data.append({"id": run_id, "tool": run["tool"], "target": run.get("target", ""), "data": data})
                    except:
                        pass
            if len(runs_data) >= 2:
                ProjectDB._compare_runs(runs_data, result_data)
            else:
                info("Need at least 2 valid runs to compare")

        elif cmd == "delete":
            count = 0
            for run_id in compare.split(",") if compare else []:
                c = conn.execute("DELETE FROM runs WHERE id = ?", (run_id.strip(),)).rowcount
                count += c
            conn.commit()
            result_data["result"] = f"Deleted {count} run(s)"
            success(f"Deleted {count} run(s)")

        else:
            table(["Command", "Description"], [
                ["init", "Initialize/find a project (--name + --target)"],
                ["list", "List all projects"],
                ["save", "Save a scan result (--file + --tool + --project)"],
                ["runs", "List runs for a project (--project)"],
                ["show", "Show a specific run (--name <run_id>)"],
                ["compare", "Compare two runs (--compare id1,id2)"],
                ["delete", "Delete runs (--compare id1,id2,...)"],
            ])

        conn.close()
        info(f"Database: {ProjectDB.DB_PATH}")
        return result_data

    @staticmethod
    def _init_db(conn):
        conn.execute("""
            CREATE TABLE IF NOT EXISTS projects (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                target TEXT DEFAULT '',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project_id INTEGER,
                tool TEXT NOT NULL,
                target TEXT DEFAULT '',
                file_path TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (project_id) REFERENCES projects(id)
            )
        """)
        conn.commit()

    @staticmethod
    def _ensure_project(conn, name, target=""):
        existing = conn.execute("SELECT id FROM projects WHERE name = ?", (name,)).fetchone()
        if existing:
            if target:
                conn.execute("UPDATE projects SET target = ? WHERE id = ?", (target, existing["id"]))
                conn.commit()
            return existing["id"]
        conn.execute("INSERT INTO projects (name, target) VALUES (?, ?)", (name, target))
        conn.commit()
        return conn.execute("SELECT id FROM projects WHERE name = ?", (name,)).fetchone()["id"]

    @staticmethod
    def _save_scan(conn, project, tool, file_path, target=""):
        if not project:
            r = conn.execute("SELECT id, name FROM projects ORDER BY id DESC LIMIT 1").fetchone()
            project = r["name"] if r else "default"
        proj_id = ProjectDB._ensure_project(conn, project, target)
        conn.execute("INSERT INTO runs (project_id, tool, target, file_path) VALUES (?, ?, ?, ?)",
                     (proj_id, tool, target, file_path))
        conn.commit()
        return conn.execute("SELECT last_insert_rowid()").fetchone()[0]

    @staticmethod
    def _list_projects(conn):
        return conn.execute("""
            SELECT p.id, p.name, p.target, p.created_at,
                   (SELECT COUNT(*) FROM runs WHERE project_id = p.id) as run_count
            FROM projects p ORDER BY p.created_at DESC
        """).fetchall()

    @staticmethod
    def _list_runs(conn, project):
        return conn.execute("""
            SELECT r.id, r.tool, r.target, r.file_path, r.created_at
            FROM runs r JOIN projects p ON r.project_id = p.id
            WHERE p.name = ? ORDER BY r.created_at DESC
        """, (project,)).fetchall()

    @staticmethod
    def _get_run(conn, run_id):
        try:
            return conn.execute("SELECT * FROM runs WHERE id = ?", (int(run_id),)).fetchone()
        except:
            return None

    @staticmethod
    def _compare_runs(runs_data, result_data):
        section("Comparing Runs")
        result_data["comparison"] = []

        for i in range(1, len(runs_data)):
            old = runs_data[0]["data"]
            new = runs_data[i]["data"]
            result_data["comparison"].append({"old_id": runs_data[0]["id"], "new_id": runs_data[i]["id"]})

            if isinstance(old, dict) and isinstance(new, dict):
                # Compare keys
                old_keys = set(old.keys())
                new_keys = set(new.keys())

                added = new_keys - old_keys
                removed = old_keys - new_keys
                common = old_keys & new_keys

                if added:
                    warning(f"New fields in #{runs_data[i]['id']}: {', '.join(added)}")
                if removed:
                    info(f"Removed fields from #{runs_data[i]['id']}: {', '.join(removed)}")

                # Compare list-based findings
                for key in common:
                    if isinstance(old[key], list) and isinstance(new[key], list):
                        if len(new[key]) != len(old[key]):
                            info(f"  {key}: {len(old[key])} -> {len(new[key])} items")
                    elif isinstance(old[key], (int, float)) and isinstance(new[key], (int, float)):
                        if old[key] != new[key]:
                            info(f"  {key}: {old[key]} -> {new[key]}")

            success(f"Comparison complete: #{runs_data[0]['id']} vs #{runs_data[i]['id']}")
