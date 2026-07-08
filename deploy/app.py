import collections
import csv
import ctypes
import ipaddress
import io
import json
import math
import os
import random
import re
import secrets
import subprocess
import threading
import time
from datetime import datetime
from functools import wraps

import psutil
import sqlite3
from flask import (
    Flask,
    Response,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle
from werkzeug.security import check_password_hash, generate_password_hash


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.path.join(BASE_DIR, "fireguard.db")
SETTINGS_FILE = os.path.join(BASE_DIR, "fireguard_settings.json")


def _truthy(value):
    return str(value).strip().lower() in ("1", "true", "yes", "on")


def is_running_as_admin():
    if os.name != "nt":
        return False
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def load_apply_firewall_setting():
    env_value = os.getenv("FIREGUARD_APPLY_FIREWALL")
    if env_value is not None:
        return _truthy(env_value)

    try:
        with open(SETTINGS_FILE, "r", encoding="utf-8") as settings_file:
            settings = json.load(settings_file)
        return bool(settings.get("apply_firewall_rules", False))
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return False


APPLY_FIREWALL_RULES = load_apply_firewall_setting()


def load_global_registration_key():
    env_value = os.getenv("FIREGUARD_REGISTRATION_KEY")
    if env_value is not None:
        return env_value

    try:
        with open(SETTINGS_FILE, "r", encoding="utf-8") as settings_file:
            settings = json.load(settings_file)
        return settings.get("global_registration_key", "fireguard-register-token")
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return "fireguard-register-token"


GLOBAL_REGISTRATION_KEY = load_global_registration_key()

# ── Detection thresholds (demo-tunable) ─────────────────────────────────────
REPEAT_CONN_WINDOW_SECONDS = 30        # Module 2: rolling window for per-IP new-connection count
REPEAT_CONN_THRESHOLD = 5              # > N new connections from same remote IP in window => alert
REPEAT_CONN_COOLDOWN_SECONDS = 60      # suppress duplicate "repeated attempt" alerts per IP

HIGH_CONNECTION_THRESHOLD = 100        # Module 4: total live inet connections above this => alert
HIGH_CONNECTION_COOLDOWN_SECONDS = 60

RESTRICTED_PORTS = {22, 23, 135, 445, 3389}   # Module 5: SSH, Telnet, RPC, SMB, RDP
RESTRICTED_PORT_COOLDOWN_SECONDS = 60         # suppress duplicate alerts per source IP

MONITOR_POLL_SECONDS = 3              # how often the background thread snapshots live connections

PAGE_SIZE = 20  # rows per page on the Alerts and Traffic Logs pages
AGENT_OFFLINE_SECONDS = 90  # mark endpoint Offline if no heartbeat for this long

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "fireguard-dev-secret")


# ── Database helpers ────────────────────────────────────────────────────────

def get_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def fetch_all(query, params=None):
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(query, params or [])
        return [dict(row) for row in cursor.fetchall()]


def fetch_one(query, params=None):
    rows = fetch_all(query, params)
    return rows[0] if rows else None


def execute(query, params=None):
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(query, params or [])
        conn.commit()


# ── Session / auth helpers ──────────────────────────────────────────────────

def current_user():
    if "user_id" not in session:
        return None
    return {
        "user_id": session["user_id"],
        "username": session["username"],
        "role": session["role"],
    }


@app.context_processor
def inject_globals():
    return {
        "current_user": current_user(),
        "firewall_mode": "Live" if APPLY_FIREWALL_RULES else "Recorded",
        "running_as_admin": is_running_as_admin(),
        "datetime": datetime,
    }


# ── Application-level IP blocking ────────────────────────────────────────────
# This runs on EVERY request before any route handler.
# It checks the requesting IP against active BLOCK rules and the blocked_ips
# table, and immediately refuses the connection with a 403 if matched.
# This is more reliable than Windows Firewall alone because Windows may have
# auto-generated ALLOW rules for python.exe that override netsh block rules.

@app.before_request
def enforce_ip_block():
    client_ip = request.remote_addr
    if not client_ip or client_ip in ("127.0.0.1", "::1"):
        return  # never block localhost

    try:
        # Check 1: Is this IP explicitly in the blocked_ips table?
        blocked = fetch_one(
            "SELECT block_id FROM blocked_ips WHERE ip_address = ?", [client_ip]
        )
        if blocked:
            return Response(
                f"<h1>403 Blocked</h1><p>Your IP address <code>{client_ip}</code> "
                "has been blocked by FireGuard.</p>",
                status=403, mimetype="text/html"
            )

        # Check 2: Does any active BLOCK firewall rule target this IP?
        rule = fetch_one(
            "SELECT rule_id FROM firewall_rules WHERE status = 'Active' "
            "AND action_type = 'BLOCK' AND ip_address = ?",
            [client_ip]
        )
        if rule:
            return Response(
                f"<h1>403 Blocked</h1><p>Your IP address <code>{client_ip}</code> "
                "is blocked by a FireGuard firewall rule.</p>",
                status=403, mimetype="text/html"
            )
    except Exception:
        pass  # never crash the app due to a blocking check error




def init_db():
    with get_connection() as conn:
        conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            email TEXT,
            password TEXT NOT NULL,
            role TEXT NOT NULL,
            created_at DATETIME NOT NULL DEFAULT (datetime('now', 'localtime'))
        );
        """)
        conn.execute("""
        CREATE TABLE IF NOT EXISTS firewall_rules (
            rule_id INTEGER PRIMARY KEY AUTOINCREMENT,
            rule_name TEXT NOT NULL,
            ip_address TEXT,
            port INTEGER,
            protocol TEXT NOT NULL,
            action_type TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'Active',
            created_by INTEGER,
            created_at DATETIME NOT NULL DEFAULT (datetime('now', 'localtime'))
        );
        """)
        conn.execute("""
        CREATE TABLE IF NOT EXISTS blocked_ips (
            block_id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT NOT NULL UNIQUE,
            reason TEXT,
            blocked_at DATETIME NOT NULL DEFAULT (datetime('now', 'localtime'))
        );
        """)
        conn.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            alert_id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_type TEXT NOT NULL,
            ip_address TEXT,
            description TEXT NOT NULL,
            alert_time DATETIME NOT NULL DEFAULT (datetime('now', 'localtime'))
        );
        """)
        conn.execute("""
        CREATE TABLE IF NOT EXISTS traffic_logs (
            log_id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_ip TEXT NOT NULL,
            destination_ip TEXT NOT NULL,
            port INTEGER,
            protocol TEXT NOT NULL,
            action_type TEXT NOT NULL,
            log_time DATETIME NOT NULL DEFAULT (datetime('now', 'localtime'))
        );
        """)
        conn.execute("""
        CREATE TABLE IF NOT EXISTS reports (
            report_id INTEGER PRIMARY KEY AUTOINCREMENT,
            report_name TEXT NOT NULL,
            generated_by INTEGER,
            report_type TEXT NOT NULL,
            generated_at DATETIME NOT NULL DEFAULT (datetime('now', 'localtime'))
        );
        """)
        conn.execute("""
        CREATE TABLE IF NOT EXISTS endpoints (
            endpoint_id INTEGER PRIMARY KEY AUTOINCREMENT,
            hostname TEXT NOT NULL,
            ip_address TEXT,
            agent_token TEXT NOT NULL UNIQUE,
            os_info TEXT,
            status TEXT NOT NULL DEFAULT 'Offline',
            registered_at DATETIME NOT NULL DEFAULT (datetime('now', 'localtime')),
            last_seen DATETIME NULL,
            mac_address TEXT NULL,
            agent_version TEXT NULL
        );
        """)
        conn.execute("""
        CREATE TABLE IF NOT EXISTS endpoint_heartbeats (
            heartbeat_id INTEGER PRIMARY KEY AUTOINCREMENT,
            endpoint_id INTEGER NOT NULL,
            cpu_percent REAL,
            memory_percent REAL,
            connection_count INTEGER,
            firewall_active INTEGER DEFAULT 0,
            reported_at DATETIME NOT NULL DEFAULT (datetime('now', 'localtime')),
            FOREIGN KEY (endpoint_id) REFERENCES endpoints(endpoint_id) ON DELETE CASCADE
        );
        """)
        conn.execute("""
        CREATE TABLE IF NOT EXISTS endpoint_rule_deployments (
            deployment_id INTEGER PRIMARY KEY AUTOINCREMENT,
            endpoint_id INTEGER NOT NULL,
            rule_id INTEGER NOT NULL,
            deployed_by INTEGER NULL,
            deployed_at DATETIME NOT NULL DEFAULT (datetime('now', 'localtime')),
            status TEXT NOT NULL DEFAULT 'Pending',
            result_message TEXT NULL,
            FOREIGN KEY (endpoint_id) REFERENCES endpoints(endpoint_id) ON DELETE CASCADE,
            FOREIGN KEY (rule_id) REFERENCES firewall_rules(rule_id) ON DELETE CASCADE
        );
        """)
        conn.commit()

        # Seed admin user if table is empty
        admin_exists = conn.execute("SELECT 1 FROM users WHERE username = 'admin'").fetchone()
        if not admin_exists:
            from werkzeug.security import generate_password_hash
            conn.execute(
                "INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)",
                ["admin", "admin@fireguard.local", generate_password_hash("admin12345"), "Administrator"]
            )
            conn.commit()


def login_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            flash("Please sign in to continue.", "warning")
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapper


def roles_required(*roles):
    def decorator(view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            if session.get("role") not in roles:
                flash("Your account does not have permission to do that.", "danger")
                return redirect(url_for("dashboard"))
            return view(*args, **kwargs)

        return wrapper

    return decorator


# ── Utility helpers ─────────────────────────────────────────────────────────

def password_matches(stored_password, submitted_password):
    if stored_password.startswith(("pbkdf2:", "scrypt:")):
        return check_password_hash(stored_password, submitted_password)
    return stored_password == submitted_password


def normalize_protocol(protocol):
    return protocol.upper() if protocol else "TCP"


def normalize_action(action_type):
    return action_type.upper() if action_type else "BLOCK"


def parse_rule_form(form):
    rule_name = form.get("rule_name", "").strip()
    ip_address = form.get("ip_address", "").strip() or None
    port = form.get("port", "").strip()
    protocol = normalize_protocol(form.get("protocol"))
    action_type = normalize_action(form.get("action_type"))
    status = form.get("status", "Active")
    errors = []

    if not rule_name:
        errors.append("Rule name is required.")
    elif len(rule_name) > 100:
        errors.append("Rule name is too long (max 100 characters).")

    if ip_address:
        if len(ip_address) > 45:
            errors.append("IP address is too long (max 45 characters).")
        else:
            try:
                ipaddress.ip_address(ip_address)
            except ValueError:
                errors.append("IP address must be a valid IPv4 or IPv6 address. Leave it blank to match any IP.")

    try:
        port_value = int(port) if port else None
    except ValueError:
        port_value = None
        errors.append("Port must be a number from 1 to 65535.")

    if port_value is not None and not 1 <= port_value <= 65535:
        errors.append("Port must be from 1 to 65535.")

    if protocol not in ("TCP", "UDP"):
        errors.append("Protocol must be TCP or UDP.")

    if action_type not in ("BLOCK", "ALLOW"):
        errors.append("Action must be BLOCK or ALLOW.")

    if status not in ("Active", "Inactive"):
        errors.append("Status must be Active or Inactive.")

    return {
        "rule_name": rule_name,
        "ip_address": ip_address,
        "port": port_value,
        "protocol": protocol,
        "action_type": action_type,
        "status": status,
        "errors": errors,
    }


ALLOWED_ROLES = ("Administrator", "Security Analyst", "Viewer")
USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{3,50}$")
EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def parse_user_form(form):
    username = form.get("username", "").strip()
    email = form.get("email", "").strip() or None
    password = form.get("password", "")
    role = form.get("role", "Viewer").strip()
    errors = []

    if not username:
        errors.append("Username is required.")
    elif not USERNAME_PATTERN.match(username):
        errors.append(
            "Username must be 3-50 characters and contain only letters, numbers, dots, hyphens, or underscores."
        )

    if email and not EMAIL_PATTERN.match(email):
        errors.append("Email address is not valid.")

    if not password:
        errors.append("Password is required.")
    elif len(password) < 8:
        errors.append("Password must be at least 8 characters.")

    if role not in ALLOWED_ROLES:
        errors.append("Role must be Administrator, Security Analyst, or Viewer.")

    return {
        "username": username,
        "email": email,
        "password": password,
        "role": role,
        "errors": errors,
    }


def record_alert(alert_type, ip_address, description):
    execute(
        """
        INSERT INTO alerts (alert_type, ip_address, description, alert_time)
        VALUES (?, ?, ?, datetime('now', 'localtime'))
        """,
        [alert_type, ip_address, description],
    )


# ── Alert severity (computed, never persisted - no schema change) ──────────
ALERT_TYPE_SEVERITY = {
    "High Connection Count": "HIGH",
    "Restricted Port Access Attempt": "HIGH",
    "Attack Simulation (Port Scan)": "HIGH",
    "Attack Simulation (Flood)": "WARNING",
    "Blocked Traffic": "WARNING",
    "Blocked Traffic (Test)": "WARNING",
    "Possible Repeated Connection Attempt": "WARNING",
    "Rule Deleted": "WARNING",
    "Rule Created": "INFO",
    "Rule Updated": "INFO",
    "Rule Applied": "INFO",
}
ALERT_TYPE_ICON = {
    "High Connection Count": "activity",
    "Restricted Port Access Attempt": "octagon-alert",
    "Attack Simulation (Port Scan)": "scan",
    "Attack Simulation (Flood)": "repeat",
    "Blocked Traffic": "shield-alert",
    "Blocked Traffic (Test)": "shield-alert",
    "Possible Repeated Connection Attempt": "repeat",
    "Rule Deleted": "trash-2",
    "Rule Created": "plus-circle",
    "Rule Updated": "pencil",
    "Rule Applied": "check-circle",
}


def alert_severity(alert_type):
    return ALERT_TYPE_SEVERITY.get(alert_type, "INFO")


def alert_icon(alert_type):
    return ALERT_TYPE_ICON.get(alert_type, "info")


app.jinja_env.globals["alert_severity"] = alert_severity
app.jinja_env.globals["alert_icon"] = alert_icon


def record_report(report_name, report_type):
    execute(
        """
        INSERT INTO reports (report_name, generated_by, report_type, generated_at)
        VALUES (?, ?, ?, datetime('now', 'localtime'))
        """,
        [report_name, session.get("user_id"), report_type],
    )


def firewall_status_message(rule_name):
    if APPLY_FIREWALL_RULES:
        return f"Rule '{rule_name}' was applied to Windows Firewall."
    return f"Rule '{rule_name}' was recorded. Enable FIREGUARD_APPLY_FIREWALL=1 to apply to Windows Firewall."


# ── FIX 3: Windows Firewall integration via netsh ──────────────────────────

def apply_windows_firewall_rule(rule_name, ip_address, port, protocol, action_type):
    """Apply or remove a rule in Windows Defender Firewall using netsh."""
    if not APPLY_FIREWALL_RULES:
        return False, "Live Mode is off. Set FIREGUARD_APPLY_FIREWALL=1 and restart the app."
    if not is_running_as_admin():
        return False, "FireGuard is in Live Mode, but Python is not running as Administrator. Restart the app from Administrator PowerShell."

    # netsh action: allow -> allow, block -> block
    netsh_action = "allow" if action_type == "ALLOW" else "block"
    clean_name = f"FireGuard-{rule_name}"

    try:
        # Inbound rule — blocks new connections coming IN from the IP
        cmd = ["netsh", "advfirewall", "firewall", "add", "rule",
               f"name={clean_name}",
               "dir=in",
               f"action={netsh_action}",
               f"protocol={protocol}"]
        if port:
            cmd.append(f"localport={port}")
        if ip_address:
            cmd.append(f"remoteip={ip_address}")
        result = subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=10)

        # For BLOCK rules, also add an outbound rule so the PC won't reply
        # to the blocked IP at all — fully drops the connection both ways.
        if action_type == "BLOCK":
            cmd_out = ["netsh", "advfirewall", "firewall", "add", "rule",
                       f"name={clean_name}-out",
                       "dir=out",
                       "action=block",
                       f"protocol={protocol}"]
            if port:
                cmd_out.append(f"remoteport={port}")
            if ip_address:
                cmd_out.append(f"remoteip={ip_address}")
            subprocess.run(cmd_out, capture_output=True, text=True, timeout=10)

        return True, result.stdout.strip() or f"Windows Firewall rule '{clean_name}' was applied."
    except subprocess.CalledProcessError as e:
        detail = (e.stderr or e.stdout or str(e)).strip()
        app.logger.warning(f"Windows Firewall apply failed: {detail}")
        return False, detail or "Windows Firewall rejected the rule."
    except Exception as e:
        app.logger.warning(f"Windows Firewall apply failed: {e}")
        return False, str(e)


def remove_windows_firewall_rule(rule_name):
    """Remove a rule from Windows Defender Firewall (both inbound and outbound)."""
    if not APPLY_FIREWALL_RULES:
        return False, "Live Mode is off."
    if not is_running_as_admin():
        return False, "FireGuard is in Live Mode, but Python is not running as Administrator."
    clean_name = f"FireGuard-{rule_name}"
    try:
        # Delete inbound rule
        cmd = ["netsh", "advfirewall", "firewall", "delete", "rule",
               f"name={clean_name}"]
        result = subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=10)
        # Delete outbound companion rule if it exists (ignore errors if absent)
        subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule",
                        f"name={clean_name}-out"],
                       capture_output=True, text=True, timeout=10)
        return True, result.stdout.strip() or f"Windows Firewall rule '{clean_name}' was removed."
    except subprocess.CalledProcessError as e:
        detail = (e.stderr or e.stdout or str(e)).strip()
        app.logger.warning(f"Windows Firewall remove failed: {detail}")
        return False, detail or "Windows Firewall rejected the delete command."
    except Exception as e:
        app.logger.warning(f"Windows Firewall remove failed: {e}")
        return False, str(e)


def check_windows_firewall_rule(rule_name):
    """Check (read-only, no admin needed) if a FireGuard rule exists in Windows Firewall.
    Uses shell=True so netsh correctly handles names that contain spaces.
    """
    clean_name = f"FireGuard-{rule_name}"
    try:
        # shell=True lets netsh parse the quoted name correctly even with spaces
        cmd = f'netsh advfirewall firewall show rule name="{clean_name}"'
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=8
        )
        output = (result.stdout + result.stderr).strip()
        # netsh prints "No rules match" when the rule is absent
        if "No rules match" in output or not output:
            return False
        # If the rule name appears in the output the rule exists
        return clean_name.lower() in output.lower() or "Rule Name" in output
    except Exception:
        return False


# ── Windows Firewall status API ─────────────────────────────────────────────

@app.route("/api/rules/<int:rule_id>/wf-status")
@login_required
def api_wf_status(rule_id):
    """Return whether this rule exists in Windows Defender Firewall (read-only check)."""
    rule = fetch_one("SELECT rule_name FROM firewall_rules WHERE rule_id = ?", [rule_id])
    if not rule:
        return jsonify({"exists": False, "rule_id": rule_id})
    exists = check_windows_firewall_rule(rule["rule_name"])
    return jsonify({"exists": exists, "rule_id": rule_id, "rule_name": rule["rule_name"]})


# ── FIX 4: Background psutil traffic monitor ────────────────────────────────

_monitor_running = False
_monitor_prev_connections = set()

# Module 2: rolling window of new-connection sightings per remote IP (thread-shared)
_conn_sightings_lock = threading.Lock()
_conn_sightings = collections.defaultdict(collections.deque)


def _classify_connection(laddr, raddr, status, protocol):
    """Return (action_type, reason) based on active firewall rules."""
    try:
        rules = fetch_all(
            "SELECT * FROM firewall_rules WHERE status = 'Active' ORDER BY rule_id"
        )
    except Exception:
        return "ALLOW", None

    for rule in rules:
        ip_match = (not rule["ip_address"]) or (
            raddr and raddr.ip == rule["ip_address"]
        )
        port_match = (not rule["port"]) or (
            laddr and laddr.port == rule["port"]
        ) or (
            raddr and raddr.port == rule["port"]
        )
        proto_match = (rule["protocol"] or "").upper() == (protocol or "").upper()

        if ip_match and port_match and proto_match:
            return rule["action_type"], rule

    return "ALLOW", None


def _record_connection_sighting(ip):
    """Record one NEW-connection sighting for `ip` (call only for connections that
    are genuinely new this tick, not ones still open from a prior tick — otherwise a
    single long-lived, ordinary connection would falsely look like repeated attempts
    just by existing across several polls). Prunes anything older than the rolling
    window and returns the current in-window count. Thread-safe."""
    now = time.time()
    with _conn_sightings_lock:
        dq = _conn_sightings[ip]
        dq.append(now)
        cutoff = now - REPEAT_CONN_WINDOW_SECONDS
        while dq and dq[0] < cutoff:
            dq.popleft()
        return len(dq)


def detect_repeated_connection_attempts(ip, count):
    """Module 2: alert if `ip` made more than REPEAT_CONN_THRESHOLD distinct new
    connections within the rolling window. No auto-blacklist here - that stays
    Module 1/3's job (only when an actual BLOCK rule matches). Cooldown-gated the
    same way the other detectors are. Returns True iff a new alert was recorded."""
    if count <= REPEAT_CONN_THRESHOLD:
        return False
    recent = fetch_one(
        """
        SELECT TOP 1 alert_id FROM alerts
        WHERE alert_type = 'Possible Repeated Connection Attempt' AND ip_address = ?
          AND alert_time >= datetime('now', 'localtime', ? || ' seconds')
        ORDER BY alert_time DESC
        """,
        [ip, -REPEAT_CONN_COOLDOWN_SECONDS],
    )
    if recent:
        return False
    record_alert(
        "Possible Repeated Connection Attempt",
        ip,
        f"{ip} made {count} connection attempts within {REPEAT_CONN_WINDOW_SECONDS}s.",
    )
    return True


def detect_high_connection_count(total):
    """Module 4: alert if the live system-wide connection count exceeds threshold.
    System-wide, not per-IP, so ip_address is NULL and there's no IP filter on the
    cooldown check. Returns True iff a new alert was recorded."""
    if total <= HIGH_CONNECTION_THRESHOLD:
        return False
    recent = fetch_one(
        """
        SELECT TOP 1 alert_id FROM alerts
        WHERE alert_type = 'High Connection Count'
          AND alert_time >= datetime('now', 'localtime', ? || ' seconds')
        ORDER BY alert_time DESC
        """,
        [-HIGH_CONNECTION_COOLDOWN_SECONDS],
    )
    if recent:
        return False
    record_alert(
        "High Connection Count",
        None,
        f"Detected {total} live network connections, exceeding the threshold of {HIGH_CONNECTION_THRESHOLD}.",
    )
    return True


def detect_restricted_port_access(ip, port):
    """Module 5: alert when a live connection touches a restricted port, independent
    of the firewall rule engine's ALLOW/BLOCK decision. Cooldown is per source IP
    (not per IP+port) so a single scan burst across several restricted ports raises
    one alert, not five. Returns True iff a new alert was recorded."""
    recent = fetch_one(
        """
        SELECT TOP 1 alert_id FROM alerts
        WHERE alert_type = 'Restricted Port Access Attempt' AND ip_address = ?
          AND alert_time >= datetime('now', 'localtime', ? || ' seconds')
        ORDER BY alert_time DESC
        """,
        [ip, -RESTRICTED_PORT_COOLDOWN_SECONDS],
    )
    if recent:
        return False
    record_alert(
        "Restricted Port Access Attempt",
        ip,
        f"Connection attempt from {ip} to restricted port {port}.",
    )
    return True


def _traffic_monitor_loop():
    """Background thread: capture real network connections via psutil every
    MONITOR_POLL_SECONDS. Fallbacks to demo traffic seeding if psutil is restricted."""
    global _monitor_running, _monitor_prev_connections
    _monitor_running = True

    while _monitor_running:
        try:
            try:
                connections = psutil.net_connections(kind="inet")
            except Exception:
                # Fallback: Seed demo traffic to make sure dashboard charts look populated on PythonAnywhere
                seed_demo_traffic()
                time.sleep(MONITOR_POLL_SECONDS)
                continue

            # Module 4 - system-wide count, checked every tick regardless of
            # which individual connections are new.
            try:
                detect_high_connection_count(len(connections))
            except Exception as e:
                app.logger.warning(f"High-connection detection error: {e}")

            seen = set()
            for conn in connections:
                if conn.status not in ("ESTABLISHED", "LISTEN"):
                    continue
                laddr = conn.laddr
                raddr = conn.raddr if conn.raddr else None
                if not raddr:
                    continue

                key = (laddr.ip, laddr.port, raddr.ip, raddr.port)
                if key in _monitor_prev_connections:
                    continue  # already logged
                seen.add(key)

                # Module 2 - only counts genuinely NEW connections (this branch),
                # not connections still open from a prior tick, so a single
                # long-lived ordinary connection can't look like repeated attempts.
                try:
                    count = _record_connection_sighting(raddr.ip)
                    detect_repeated_connection_attempts(raddr.ip, count)
                except Exception as e:
                    app.logger.warning(f"Repeated-connection detection error: {e}")

                # Module 5 - independent of the firewall rule ALLOW/BLOCK decision.
                try:
                    hit_port = laddr.port if laddr.port in RESTRICTED_PORTS else (
                        raddr.port if raddr.port in RESTRICTED_PORTS else None
                    )
                    if hit_port is not None:
                        detect_restricted_port_access(raddr.ip, hit_port)
                except Exception as e:
                    app.logger.warning(f"Restricted-port detection error: {e}")

                protocol = "TCP" if conn.type == 1 else "UDP"
                action_type, matched_rule = _classify_connection(laddr, raddr, conn.status, protocol)

                try:
                    execute(
                        """
                        INSERT INTO traffic_logs
                            (source_ip, destination_ip, port, protocol, action_type, log_time)
                        VALUES (?, ?, ?, ?, ?, datetime('now', 'localtime'))
                        """,
                        [raddr.ip, laddr.ip, laddr.port, protocol, action_type],
                    )

                    if action_type == "BLOCK":
                        execute(
                            """
                            INSERT OR IGNORE INTO blocked_ips (ip_address, reason, blocked_at)
                            VALUES (?, ?, datetime('now', 'localtime'))
                            """,
                            [raddr.ip, raddr.ip,
                             f"Blocked by rule: {matched_rule['rule_name'] if matched_rule else 'Auto-detected'}"],
                        )
                        record_alert(
                            "Blocked Traffic",
                            raddr.ip,
                            f"Blocked {protocol} connection to port {laddr.port}.",
                        )
                except Exception:
                    pass

            _monitor_prev_connections = seen

        except Exception as e:
            app.logger.warning(f"Traffic monitor error: {e}")

        time.sleep(MONITOR_POLL_SECONDS)


def start_monitor():
    """Start the background traffic monitor thread (only once)."""
    t = threading.Thread(target=_traffic_monitor_loop, daemon=True)
    t.start()


# ── Demo traffic seeder (kept for manual testing) ───────────────────────────

def seed_demo_traffic():
    samples = [
        ("192.168.1.25", "10.0.0.8", 22, "TCP", "BLOCK"),
        ("192.168.1.42", "10.0.0.5", 443, "TCP", "ALLOW"),
        ("172.16.0.11", "10.0.0.7", 53, "UDP", "ALLOW"),
        ("203.0.113.19", "10.0.0.2", 3389, "TCP", "BLOCK"),
        ("198.51.100.8", "10.0.0.3", 8080, "TCP", "BLOCK"),
    ]
    source_ip, destination_ip, port, protocol, action_type = random.choice(samples)
    execute(
        """
        INSERT INTO traffic_logs (source_ip, destination_ip, port, protocol, action_type, log_time)
        VALUES (?, ?, ?, ?, ?, datetime('now', 'localtime'))
        """,
        [source_ip, destination_ip, port, protocol, action_type],
    )
    if action_type == "BLOCK":
        execute(
            """
            INSERT OR IGNORE INTO blocked_ips (ip_address, reason, blocked_at)
            VALUES (?, ?, datetime('now', 'localtime'))
            """,
            [source_ip, source_ip, f"Repeated blocked {protocol} access on port {port}"],
        )
        record_alert(
            "Blocked Traffic",
            source_ip,
            f"Blocked {protocol} connection attempt to port {port}.",
        )


def live_connection_count():
    """Live count of all inet connections - same source of truth Module 4's
    detector uses, reused for the dashboard's Active Connections card."""
    try:
        return len(psutil.net_connections(kind="inet"))
    except Exception:
        return 0


# ── Routes ──────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()[:100]
        password = request.form.get("password", "")[:200]
        if not username or not password:
            flash("Please enter both username and password.", "warning")
            return render_template("login.html")
        user = fetch_one("SELECT * FROM users WHERE username = ?", [username])
        if user and password_matches(user["password"], password):
            session.clear()
            session["user_id"] = user["user_id"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            flash(f"Welcome back, {user['username']}.", "success")
            return redirect(url_for("dashboard"))
        flash("Invalid username or password.", "danger")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been signed out.", "info")
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    counts = {
        "rules": fetch_one("SELECT COUNT(*) AS total FROM firewall_rules")["total"],
        "active_rules": fetch_one(
            "SELECT COUNT(*) AS total FROM firewall_rules WHERE status = 'Active'"
        )["total"],
        "blocked": fetch_one(
            "SELECT COUNT(*) AS total FROM traffic_logs WHERE action_type = 'BLOCK'"
        )["total"],
        "alerts": fetch_one("SELECT COUNT(*) AS total FROM alerts")["total"],
        "active_connections": live_connection_count(),
    }
    action_rows = fetch_all(
        """
        SELECT action_type, COUNT(*) AS total
        FROM traffic_logs
        GROUP BY action_type
        """
    )
    protocol_rows = fetch_all(
        """
        SELECT protocol, COUNT(*) AS total
        FROM traffic_logs
        GROUP BY protocol
        """
    )
    recent_logs = fetch_all(
        """
        SELECT *
        FROM traffic_logs
        ORDER BY log_time DESC, log_id DESC
        LIMIT 8
        """
    )
    recent_alerts = fetch_all(
        """
        SELECT *
        FROM alerts
        ORDER BY alert_time DESC, alert_id DESC
        LIMIT 5
        """
    )
    rules = fetch_all(
        """
        SELECT rule_id, rule_name, ip_address, port, protocol, action_type, status
        FROM firewall_rules
        ORDER BY created_at DESC, rule_id DESC
        LIMIT 6
        """
    )
    # 24-hour hourly traffic trend
    trend_rows = fetch_all(
        """
        SELECT CAST(strftime('%H', log_time) AS INTEGER) AS hr, COUNT(*) AS total
        FROM traffic_logs
        WHERE log_time >= datetime('now', 'localtime', '-24 hours')
        GROUP BY CAST(strftime('%H', log_time) AS INTEGER)
        ORDER BY hr
        """
    )
    trend_map = {row["hr"]: row["total"] for row in trend_rows}
    now_hour = datetime.now().hour
    trend_labels = [f"{(now_hour - 23 + h) % 24:02d}:00" for h in range(24)]
    trend_data = [trend_map.get((now_hour - 23 + h) % 24, 0) for h in range(24)]

    # ── Endpoint summary for dashboard ──────────────────────────────────
    # Stale check — mark offline first
    execute(
        f"""
        UPDATE endpoints SET status = 'Offline'
        WHERE last_seen IS NULL
           OR last_seen < datetime('now', 'localtime', '-{AGENT_OFFLINE_SECONDS} seconds')
        """
    )
    ep_counts = fetch_one(
        """
        SELECT COUNT(*) AS total,
               SUM(CASE WHEN status='Online'  THEN 1 ELSE 0 END) AS online,
               SUM(CASE WHEN status='Offline' THEN 1 ELSE 0 END) AS offline,
               SUM(CASE WHEN status='Warning' THEN 1 ELSE 0 END) AS warning
        FROM endpoints
        """
    ) or {"total": 0, "online": 0, "offline": 0, "warning": 0}
    endpoint_health = fetch_all(
        """
        SELECT e.hostname, e.ip_address, e.status, e.last_seen,
               h.cpu_percent, h.memory_percent, h.connection_count, h.firewall_active
        FROM endpoints e
        LEFT JOIN (
            SELECT endpoint_id, cpu_percent, memory_percent, connection_count, firewall_active
            FROM endpoint_heartbeats
            WHERE heartbeat_id IN (
                SELECT MAX(heartbeat_id) FROM endpoint_heartbeats GROUP BY endpoint_id
            )
        ) h ON h.endpoint_id = e.endpoint_id
        ORDER BY e.status, e.last_seen DESC
        """
    )

    return render_template(
        "dashboard.html",
        counts=counts,
        action_rows=action_rows,
        protocol_rows=protocol_rows,
        recent_logs=recent_logs,
        recent_alerts=recent_alerts,
        rules=rules,
        trend_labels=trend_labels,
        trend_data=trend_data,
        ep_counts=ep_counts,
        endpoint_health=endpoint_health,
    )


# ── FIX 5: Live poll API (called by JS every 30 s) ─────────────────────────

@app.route("/api/dashboard-stats")
@login_required
def api_dashboard_stats():
    """JSON endpoint for live dashboard refresh without full page reload."""
    counts = {
        "rules": fetch_one("SELECT COUNT(*) AS total FROM firewall_rules")["total"],
        "active_rules": fetch_one(
            "SELECT COUNT(*) AS total FROM firewall_rules WHERE status = 'Active'"
        )["total"],
        "blocked": fetch_one(
            "SELECT COUNT(*) AS total FROM traffic_logs WHERE action_type = 'BLOCK'"
        )["total"],
        "alerts": fetch_one("SELECT COUNT(*) AS total FROM alerts")["total"],
        "active_connections": live_connection_count(),
    }
    recent_logs = fetch_all(
        "SELECT * FROM traffic_logs ORDER BY log_time DESC, log_id DESC LIMIT 8"
    )
    # Serialize datetime fields for JSON
    for log in recent_logs:
        for k, v in log.items():
            if isinstance(v, datetime):
                log[k] = v.strftime("%Y-%m-%d %H:%M:%S")
    latest_alert = fetch_one(
        "SELECT * FROM alerts ORDER BY alert_time DESC, alert_id DESC LIMIT 1"
    )
    if latest_alert:
        for k, v in latest_alert.items():
            if isinstance(v, datetime):
                latest_alert[k] = v.strftime("%Y-%m-%d %H:%M:%S")
        latest_alert["severity"] = alert_severity(latest_alert["alert_type"])
    return jsonify(counts=counts, recent_logs=recent_logs, latest_alert=latest_alert)


@app.route("/api/latest-alert")
@login_required
def api_latest_alert():
    """Returns the most recent alert — used for pop-up notifications."""
    alert = fetch_one(
        "SELECT * FROM alerts ORDER BY alert_time DESC, alert_id DESC LIMIT 1"
    )
    if alert:
        for k, v in alert.items():
            if isinstance(v, datetime):
                alert[k] = v.strftime("%Y-%m-%d %H:%M:%S")
        return jsonify(alert)
    return jsonify(None)


# ── Firewall Rules ──────────────────────────────────────────────────────────

@app.route("/rules", methods=["GET", "POST"])
@login_required
@roles_required("Administrator")
def rules():
    if request.method == "POST":
        form_rule = parse_rule_form(request.form)
        if form_rule["errors"]:
            for error in form_rule["errors"]:
                flash(error, "danger")
            return redirect(url_for("rules"))

        # FIX 1: ip_address column is now VARCHAR(45) — supports IPv6 safely
        execute(
            """
            INSERT INTO firewall_rules
                (rule_name, ip_address, port, protocol, action_type, status, created_by, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now', 'localtime'))
            """,
            [
                form_rule["rule_name"],
                form_rule["ip_address"],
                form_rule["port"],
                form_rule["protocol"],
                form_rule["action_type"],
                form_rule["status"],
                session["user_id"],
            ],
        )
        if form_rule["status"] == "Active" and form_rule["action_type"] == "BLOCK" and form_rule["ip_address"]:
            execute(
                """
                INSERT OR IGNORE INTO blocked_ips (ip_address, reason, blocked_at)
                VALUES (?, ?, datetime('now', 'localtime'))
                """,
                [
                    form_rule["ip_address"],
                    form_rule["ip_address"],
                    f"Firewall rule: {form_rule['rule_name']}",
                ],
            )
        if form_rule["status"] != "Active":
            message = f"Rule '{form_rule['rule_name']}' was saved as inactive and was not applied to Windows Firewall."
            flash(message, "info")
        elif APPLY_FIREWALL_RULES:
            applied, detail = apply_windows_firewall_rule(
                form_rule["rule_name"],
                form_rule["ip_address"],
                form_rule["port"],
                form_rule["protocol"],
                form_rule["action_type"],
            )
            if applied:
                message = f"Rule '{form_rule['rule_name']}' was applied to Windows Firewall."
                flash(message, "success")
            else:
                message = f"Rule '{form_rule['rule_name']}' was saved, but Windows Firewall rejected it: {detail}"
                flash(message, "danger")
        else:
            message = firewall_status_message(form_rule["rule_name"])
            flash(message, "warning")
        record_alert("Rule Created", form_rule["ip_address"], message)
        return redirect(url_for("rules"))

    search = request.args.get("q", "").strip()[:100]
    if search:
        all_rules = fetch_all(
            """
            SELECT r.*,
                   u.username AS created_by_name,
                   (
                       SELECT COUNT(*) FROM traffic_logs t
                       WHERE (r.ip_address IS NULL OR t.source_ip = r.ip_address)
                         AND (r.port IS NULL OR t.port = r.port)
                         AND (t.protocol = r.protocol)
                         AND (t.action_type = r.action_type)
                   ) AS hit_count
            FROM firewall_rules r
            LEFT JOIN users u ON u.user_id = r.created_by
            WHERE r.rule_name LIKE ? OR r.ip_address LIKE ? OR CAST(r.port AS VARCHAR) LIKE ?
            ORDER BY r.created_at DESC, r.rule_id DESC
            """,
            [f"%{search}%", f"%{search}%", f"%{search}%"],
        )
    else:
        all_rules = fetch_all(
            """
            SELECT r.*,
                   u.username AS created_by_name,
                   (
                       SELECT COUNT(*) FROM traffic_logs t
                       WHERE (r.ip_address IS NULL OR t.source_ip = r.ip_address)
                         AND (r.port IS NULL OR t.port = r.port)
                         AND (t.protocol = r.protocol)
                         AND (t.action_type = r.action_type)
                   ) AS hit_count
            FROM firewall_rules r
            LEFT JOIN users u ON u.user_id = r.created_by
            ORDER BY r.created_at DESC, r.rule_id DESC
            """
        )
    return render_template("rules.html", rules=all_rules, search=search)


@app.route("/rules/<int:rule_id>/edit", methods=["GET", "POST"])
@login_required
@roles_required("Administrator")
def edit_rule(rule_id):
    rule = fetch_one("SELECT * FROM firewall_rules WHERE rule_id = ?", [rule_id])
    if not rule:
        flash("Firewall rule was not found.", "warning")
        return redirect(url_for("rules"))

    if request.method == "POST":
        form_rule = parse_rule_form(request.form)
        if form_rule["errors"]:
            for error in form_rule["errors"]:
                flash(error, "danger")
            return redirect(url_for("edit_rule", rule_id=rule_id))

        execute(
            """
            UPDATE firewall_rules
            SET rule_name = ?, ip_address = ?, port = ?, protocol = ?, action_type = ?, status = ?
            WHERE rule_id = ?
            """,
            [
                form_rule["rule_name"],
                form_rule["ip_address"],
                form_rule["port"],
                form_rule["protocol"],
                form_rule["action_type"],
                form_rule["status"],
                rule_id,
            ],
        )
        if APPLY_FIREWALL_RULES:
            remove_windows_firewall_rule(rule["rule_name"])
            if form_rule["status"] == "Active":
                applied, detail = apply_windows_firewall_rule(
                    form_rule["rule_name"],
                    form_rule["ip_address"],
                    form_rule["port"],
                    form_rule["protocol"],
                    form_rule["action_type"],
                )
                if applied:
                    message = f"Rule '{form_rule['rule_name']}' was updated and applied to Windows Firewall."
                    flash(message, "success")
                else:
                    message = f"Rule '{form_rule['rule_name']}' was updated, but Windows Firewall rejected it: {detail}"
                    flash(message, "danger")
            else:
                message = f"Rule '{form_rule['rule_name']}' was updated as inactive and removed from Windows Firewall if it existed."
                flash(message, "info")
        else:
            message = f"Rule '{form_rule['rule_name']}' was updated in Recorded Mode. Enable FIREGUARD_APPLY_FIREWALL=1 to apply it."
            flash(message, "warning")
        record_alert("Rule Updated", form_rule["ip_address"], message)
        return redirect(url_for("rules"))

    return render_template("rule_form.html", rule=rule)


@app.route("/rules/<int:rule_id>/apply", methods=["POST"])
@login_required
@roles_required("Administrator")
def apply_rule_to_firewall(rule_id):
    rule = fetch_one("SELECT * FROM firewall_rules WHERE rule_id = ?", [rule_id])
    if not rule:
        flash("Firewall rule was not found.", "warning")
        return redirect(url_for("rules"))

    if rule["status"] != "Active":
        flash("Only active rules can be applied to Windows Firewall.", "warning")
        return redirect(url_for("rules"))

    applied, detail = apply_windows_firewall_rule(
        rule["rule_name"],
        rule["ip_address"],
        rule["port"],
        rule["protocol"],
        rule["action_type"],
    )
    if applied:
        message = f"Rule '{rule['rule_name']}' was applied to Windows Firewall."
        flash(message, "success")
    else:
        message = f"Rule '{rule['rule_name']}' could not be applied to Windows Firewall: {detail}"
        flash(message, "danger")
    record_alert("Rule Applied", rule["ip_address"], message)
    return redirect(url_for("rules"))


@app.route("/rules/<int:rule_id>/delete", methods=["POST"])
@login_required
@roles_required("Administrator")
def delete_rule(rule_id):
    rule = fetch_one("SELECT rule_name, ip_address FROM firewall_rules WHERE rule_id = ?", [rule_id])
    execute("DELETE FROM firewall_rules WHERE rule_id = ?", [rule_id])
    if rule:
        # FIX 3: Remove from Windows Firewall too
        remove_windows_firewall_rule(rule["rule_name"])
        record_alert("Rule Deleted", rule["ip_address"], f"Rule '{rule['rule_name']}' was deleted.")
    flash("Firewall rule deleted.", "info")
    return redirect(url_for("rules"))


@app.route("/rules/<int:rule_id>/test", methods=["POST"])
@login_required
@roles_required("Administrator")
def test_rule(rule_id):
    rule = fetch_one("SELECT * FROM firewall_rules WHERE rule_id = ?", [rule_id])
    if not rule:
        flash("Firewall rule was not found.", "warning")
        return redirect(url_for("rules"))

    source_ip = rule["ip_address"] if rule["ip_address"] else "192.168.1.99"
    destination_ip = "10.0.0.99"
    port = rule["port"] if rule["port"] else random.choice([80, 443, 22, 3389])
    protocol = rule["protocol"]
    action_type = rule["action_type"]

    execute(
        """
        INSERT INTO traffic_logs (source_ip, destination_ip, port, protocol, action_type, log_time)
        VALUES (?, ?, ?, ?, ?, datetime('now', 'localtime'))
        """,
        [source_ip, destination_ip, port, protocol, action_type],
    )

    if action_type == "BLOCK":
        execute(
            """
            INSERT OR IGNORE INTO blocked_ips (ip_address, reason, blocked_at)
            VALUES (?, ?, datetime('now', 'localtime'))
            """,
            [source_ip, source_ip, f"Firewall Rule Test: {rule['rule_name']}"],
        )
        record_alert(
            "Blocked Traffic (Test)",
            source_ip,
            f"Simulated block matching rule '{rule['rule_name']}' on port {port}.",
        )
    
    flash(f"Simulated traffic event matching rule '{rule['rule_name']}'! 1 hit recorded.", "success")
    return redirect(url_for("rules"))


# ── Traffic Logs ────────────────────────────────────────────────────────────

@app.route("/logs")
@login_required
def logs():
    search = request.args.get("q", "").strip()[:100]
    filter_action = request.args.get("action", "").strip().upper()

    conditions = []
    params = []

    if search:
        conditions.append("(source_ip LIKE ? OR destination_ip LIKE ? OR CAST(port AS VARCHAR) LIKE ?)")
        params += [f"%{search}%", f"%{search}%", f"%{search}%"]
    if filter_action in ("BLOCK", "ALLOW"):
        conditions.append("action_type = ?")
        params.append(filter_action)

    where_clause = (" WHERE " + " AND ".join(conditions)) if conditions else ""

    total_logs = fetch_one(
        f"SELECT COUNT(*) AS total FROM traffic_logs{where_clause}", params
    )["total"]
    total_pages = max(1, math.ceil(total_logs / PAGE_SIZE))
    page = min(max(request.args.get("page", 1, type=int) or 1, 1), total_pages)
    offset = (page - 1) * PAGE_SIZE

    # OFFSET/FETCH row counts are interpolated directly rather than parameterized:
    # this ODBC driver hangs indefinitely when they're passed as `?` placeholders.
    # Safe because `offset`/PAGE_SIZE are always server-computed ints, never raw
    # user input (page is coerced+clamped above, PAGE_SIZE is a constant). The
    # search/filter values above remain parameterized since those are real user input.
    base_query = (
        f"SELECT * FROM traffic_logs{where_clause} "
        "ORDER BY log_time DESC, log_id DESC "
        f"LIMIT {PAGE_SIZE} OFFSET {offset}"
    )
    all_logs = fetch_all(base_query, params)
    return render_template(
        "logs.html",
        logs=all_logs,
        search=search,
        filter_action=filter_action,
        page=page,
        total_pages=total_pages,
        total_logs=total_logs,
    )


@app.route("/logs/scan-live", methods=["POST"])
@login_required
@roles_required("Administrator", "Security Analyst")
def scan_live_traffic():
    """Scan the OS for active network connections, check rules, log them, and trigger alert responses."""
    try:
        connections = psutil.net_connections(kind="inet")
        recorded_count = 0
        
        for conn in connections:
            # We only want established or listening connections that have a remote address
            if conn.status not in ("ESTABLISHED", "LISTEN"):
                continue
            laddr = conn.laddr
            raddr = conn.raddr if conn.raddr else None
            if not raddr:
                continue
                
            protocol = "TCP" if conn.type == 1 else "UDP"
            action_type, matched_rule = _classify_connection(laddr, raddr, conn.status, protocol)
            
            # Record in DB
            execute(
                """
                INSERT INTO traffic_logs
                    (source_ip, destination_ip, port, protocol, action_type, log_time)
                VALUES (?, ?, ?, ?, ?, datetime('now', 'localtime'))
                """,
                [raddr.ip, laddr.ip, laddr.port, protocol, action_type],
            )
            
            # Trigger block action if matching rule blocks it
            if action_type == "BLOCK":
                execute(
                    """
                    IF NOT EXISTS (SELECT 1 FROM blocked_ips WHERE ip_address = ?)
                    INSERT INTO blocked_ips (ip_address, reason, blocked_at)
                    VALUES (?, ?, datetime('now', 'localtime'))
                    """,
                    [raddr.ip, raddr.ip,
                     f"Blocked by rule: {matched_rule['rule_name'] if matched_rule else 'Auto-detected'}"],
                )
                record_alert(
                    "Blocked Traffic",
                    raddr.ip,
                    f"Scan detected and blocked {protocol} connection to port {laddr.port}.",
                )
                
            recorded_count += 1
            
        if recorded_count > 0:
            flash(f"Scan complete: Scanned and recorded {recorded_count} active network connections.", "success")
        else:
            flash("Scan complete: No active external connections found at this moment.", "info")
            
    except Exception as e:
        flash(f"Traffic scan failed: {e}", "danger")
        
    return redirect(request.referrer or url_for("logs"))


# ── Attack Simulator ────────────────────────────────────────────────────────

@app.route("/simulate/attack", methods=["POST"])
@login_required
@roles_required("Administrator")
def simulate_attack():
    """Simulate a malicious host attacking the server.
    Generates 3 realistic attack events:
      1. RDP port scan  -> Attack Simulation (Port Scan)  (HIGH)
      2. SSH port scan  -> Restricted Port Access Attempt (HIGH)
      3. HTTP flood     -> Attack Simulation (Flood)      (WARNING)
    The attacker_ip can be passed via form; defaults to 192.168.1.99.
    """
    attacker_ip = request.form.get("attacker_ip", "192.168.1.99").strip()[:45]
    # Validate: must be a real IP
    try:
        ipaddress.ip_address(attacker_ip)
    except ValueError:
        flash("Invalid IP address provided.", "danger")
        return redirect(request.referrer or url_for("dashboard"))

    server_ip = "10.0.0.1"   # represents the protected server

    # ── Attack 1: RDP Port Scan (Port 3389) ──────────────────────────────
    execute(
        """
        INSERT INTO traffic_logs (source_ip, destination_ip, port, protocol, action_type, log_time)
        VALUES (?, ?, 3389, 'TCP', 'BLOCK', datetime('now', 'localtime'))
        """,
        [attacker_ip, server_ip],
    )
    record_alert(
        "Attack Simulation (Port Scan)",
        attacker_ip,
        f"Unauthorized host {attacker_ip} scanned restricted RDP port 3389 on the server.",
    )

    # ── Attack 2: SSH Port Scan (Port 22) ────────────────────────────────
    execute(
        """
        INSERT INTO traffic_logs (source_ip, destination_ip, port, protocol, action_type, log_time)
        VALUES (?, ?, 22, 'TCP', 'BLOCK', datetime('now', 'localtime'))
        """,
        [attacker_ip, server_ip],
    )
    record_alert(
        "Restricted Port Access Attempt",
        attacker_ip,
        f"Connection attempt from {attacker_ip} to restricted port 22 (SSH).",
    )

    # ── Attack 3: HTTP Flood (Repeated Connection Attempt) ───────────────
    for i in range(6):
        execute(
            """
            INSERT INTO traffic_logs (source_ip, destination_ip, port, protocol, action_type, log_time)
            VALUES (?, ?, 80, 'TCP', 'BLOCK', datetime('now', 'localtime'))
            """,
            [attacker_ip, server_ip],
        )
    record_alert(
        "Attack Simulation (Flood)",
        attacker_ip,
        f"{attacker_ip} sent 6 rapid connection attempts within 30s — possible DoS/flood attack.",
    )

    # ── Auto-block the attacker IP ─────────────────────────────────────────
    execute(
        """
        INSERT OR IGNORE INTO blocked_ips (ip_address, reason, blocked_at)
        VALUES (?, ?, datetime('now', 'localtime'))
        """,
        [
            attacker_ip,
            attacker_ip,
            f"Auto-blocked: Port scan + flood detected from {attacker_ip}",
        ],
    )
    record_alert(
        "Blocked Traffic",
        attacker_ip,
        f"{attacker_ip} was automatically added to the blocked list after 3 attack events.",
    )

    flash(
        f"Attack simulation complete. IP {attacker_ip} generated 3 threat events "
        f"and was auto-blocked. Check Alerts & Blocked IPs.",
        "danger",
    )
    return redirect(url_for("alerts"))


# ── Alerts ──────────────────────────────────────────────────────────────────

@app.route("/alerts")
@login_required
def alerts():
    # ── Alerts pagination (8 per page to match Blocked IPs height) ───────
    ALERTS_PAGE_SIZE = 8
    total_alerts = fetch_one("SELECT COUNT(*) AS total FROM alerts")["total"]
    total_pages = max(1, math.ceil(total_alerts / ALERTS_PAGE_SIZE))
    page = min(max(request.args.get("page", 1, type=int) or 1, 1), total_pages)
    offset = (page - 1) * ALERTS_PAGE_SIZE

    # OFFSET/FETCH row counts are interpolated directly rather than parameterized:
    # this ODBC driver hangs indefinitely when they're passed as `?` placeholders.
    # Safe because `offset`/PAGE_SIZE are always server-computed ints, never raw
    # user input (page is coerced+clamped above, PAGE_SIZE is a constant).
    all_alerts = fetch_all(
        f"""
        SELECT *
        FROM alerts
        ORDER BY alert_time DESC, alert_id DESC
        LIMIT {ALERTS_PAGE_SIZE} OFFSET {offset}
        """
    )

    # ── Blocked IPs pagination (8 per page, independent of alerts) ────────
    IP_PAGE_SIZE = 8
    total_ips = fetch_one("SELECT COUNT(*) AS total FROM blocked_ips")["total"]
    total_ip_pages = max(1, math.ceil(total_ips / IP_PAGE_SIZE))
    ip_page = min(max(request.args.get("ip_page", 1, type=int) or 1, 1), total_ip_pages)
    ip_offset = (ip_page - 1) * IP_PAGE_SIZE

    blocked_ips = fetch_all(
        f"""
        SELECT *
        FROM blocked_ips
        ORDER BY blocked_at DESC, block_id DESC
        LIMIT {IP_PAGE_SIZE} OFFSET {ip_offset}
        """
    )

    return render_template(
        "alerts.html",
        alerts=all_alerts,
        blocked_ips=blocked_ips,
        page=page,
        total_pages=total_pages,
        total_alerts=total_alerts,
        ip_page=ip_page,
        total_ip_pages=total_ip_pages,
        total_ips=total_ips,
    )


@app.route("/alerts/unblock", methods=["POST"])
@login_required
@roles_required("Administrator")
def unblock_ip():
    """Remove an IP address from the blocked_ips table (admin only)."""
    ip = request.form.get("ip_address", "").strip()[:45]
    if not ip:
        flash("No IP address provided.", "warning")
        return redirect(url_for("alerts"))
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        flash("Invalid IP address.", "danger")
        return redirect(url_for("alerts"))
    execute("DELETE FROM blocked_ips WHERE ip_address = ?", [ip])
    record_alert(
        "Rule Updated",
        ip,
        f"Administrator manually unblocked IP {ip} from the blocked list.",
    )
    flash(f"IP {ip} has been unblocked successfully.", "success")
    return redirect(url_for("alerts"))


# ── Reports ─────────────────────────────────────────────────────────────────

@app.route("/reports")
@login_required
@roles_required("Administrator", "Security Analyst")
def reports():
    report_rows = fetch_all(
        """
        SELECT r.*, u.username AS generated_by_name
        FROM reports r
        LEFT JOIN users u ON u.user_id = r.generated_by
        ORDER BY r.generated_at DESC, r.report_id DESC
        LIMIT 50
        """
    )
    return render_template("reports.html", reports=report_rows)


@app.route("/reports/download.pdf")
@login_required
@roles_required("Administrator", "Security Analyst")
def download_pdf():
    logs = fetch_all(
        """
        SELECT log_time, source_ip, destination_ip, port, protocol, action_type
        FROM traffic_logs
        ORDER BY log_time DESC, log_id DESC
        LIMIT 40
        """
    )
    buffer = io.BytesIO()
    document = SimpleDocTemplate(buffer, pagesize=letter)
    data = [["Time", "Source", "Destination", "Port", "Protocol", "Action"]]
    for row in logs:
        data.append(
            [
                str(row["log_time"]),
                row["source_ip"],
                row["destination_ip"],
                row["port"],
                row["protocol"],
                row["action_type"],
            ]
        )
    table = Table(data, repeatRows=1)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#102a43")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5e1")),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
            ]
        )
    )
    document.build([table])
    buffer.seek(0)
    record_report("Traffic Activity PDF", "PDF")
    return send_file(
        buffer,
        as_attachment=False,
        download_name="fireguard_traffic_logs.pdf",
        mimetype="application/pdf",
    )


@app.route("/reports/download.csv")
@login_required
@roles_required("Administrator", "Security Analyst")
def download_csv():
    """Export traffic logs as a CSV file."""
    logs = fetch_all(
        """
        SELECT log_time, source_ip, destination_ip, port, protocol, action_type
        FROM traffic_logs
        ORDER BY log_time DESC, log_id DESC
        LIMIT 500
        """
    )
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Time", "Source IP", "Destination IP", "Port", "Protocol", "Action"])
    for row in logs:
        writer.writerow([
            str(row["log_time"]),
            row["source_ip"],
            row["destination_ip"],
            row["port"],
            row["protocol"],
            row["action_type"],
        ])
    output.seek(0)
    record_report("Traffic Activity CSV", "CSV")
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=fireguard_traffic_logs.csv"},
    )




# ── Users ───────────────────────────────────────────────────────────────────

@app.route("/users", methods=["GET", "POST"])
@login_required
@roles_required("Administrator")
def users():
    if request.method == "POST":
        form_user = parse_user_form(request.form)
        if form_user["errors"]:
            for error in form_user["errors"]:
                flash(error, "danger")
            return redirect(url_for("users"))

        existing = fetch_one("SELECT user_id FROM users WHERE username = ?", [form_user["username"]])
        if existing:
            flash("That username already exists.", "warning")
        else:
            execute(
                """
                INSERT INTO users (username, email, password, role, created_at)
                VALUES (?, ?, ?, ?, datetime('now', 'localtime'))
                """,
                [
                    form_user["username"],
                    form_user["email"],
                    generate_password_hash(form_user["password"]),
                    form_user["role"],
                ],
            )
            flash("User account created.", "success")
        return redirect(url_for("users"))

    all_users = fetch_all("SELECT user_id, username, email, role, created_at FROM users ORDER BY user_id")
    return render_template("users.html", users=all_users)


@app.route("/users/<int:user_id>/delete", methods=["POST"])
@login_required
@roles_required("Administrator")
def delete_user(user_id):
    if user_id == session.get("user_id"):
        flash("You cannot delete your own active account.", "warning")
    else:
        execute("DELETE FROM users WHERE user_id = ?", [user_id])
        flash("User account deleted.", "info")
    return redirect(url_for("users"))


# ── Startup ─────────────────────────────────────────────────────────────────

# ── Agent auth helper ───────────────────────────────────────────────────────

def _verify_agent_token(req):
    """Extract and validate the Bearer token from an agent request.
    Returns the endpoint row dict if valid, None otherwise."""
    auth = req.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    token = auth[7:].strip()
    return fetch_one("SELECT * FROM endpoints WHERE agent_token = ?", [token])


# ── Agent API routes (called by agent.py on each endpoint machine) ───────────

@app.route("/api/agent/register", methods=["POST"])
def api_agent_register():
    """Self-registration: agent.py calls this once, with the shared
    Global Registration Key (shown on the /endpoints page to Administrators),
    instead of an admin manually creating the endpoint and pasting a token.
    Idempotent by hostname — re-running the installer on the same machine
    returns its existing token rather than creating a duplicate row."""
    data = request.get_json(silent=True) or {}
    submitted_key = str(data.get("registration_key", ""))
    if not submitted_key or submitted_key != GLOBAL_REGISTRATION_KEY:
        return jsonify({"error": "Invalid or missing registration key"}), 401

    hostname = str(data.get("hostname", "")).strip()[:100]
    if not hostname:
        return jsonify({"error": "hostname is required"}), 400

    ip_address    = str(data.get("ip_address", ""))[:45] or None
    mac_address   = str(data.get("mac_address", ""))[:50] or None
    os_info       = str(data.get("os_info", ""))[:200] or None
    agent_version = str(data.get("agent_version", ""))[:20] or None

    existing = fetch_one("SELECT * FROM endpoints WHERE hostname = ?", [hostname])
    if existing:
        execute(
            """
            UPDATE endpoints
            SET ip_address = ?, mac_address = ?, os_info = ?, agent_version = ?
            WHERE endpoint_id = ?
            """,
            [ip_address, mac_address, os_info, agent_version, existing["endpoint_id"]],
        )
        return jsonify({"agent_token": existing["agent_token"], "endpoint_id": existing["endpoint_id"]})

    token = secrets.token_hex(20)
    execute(
        """
        INSERT INTO endpoints
            (hostname, ip_address, agent_token, os_info, mac_address, agent_version, status)
        VALUES (?, ?, ?, ?, ?, ?, 'Offline')
        """,
        [hostname, ip_address, token, os_info, mac_address, agent_version],
    )
    new_row = fetch_one("SELECT endpoint_id FROM endpoints WHERE agent_token = ?", [token])
    return jsonify({"agent_token": token, "endpoint_id": new_row["endpoint_id"]})


@app.route("/api/agent/heartbeat", methods=["POST"])
def api_agent_heartbeat():
    """Agent posts a health snapshot every heartbeat_interval seconds."""
    ep = _verify_agent_token(request)
    if not ep:
        return jsonify({"error": "Unauthorized"}), 401
    data = request.get_json(silent=True) or {}
    cpu      = data.get("cpu_percent")
    mem      = data.get("memory_percent")
    conns    = data.get("connection_count")
    fw_active = 1 if data.get("firewall_active") else 0
    ip_addr  = data.get("ip_address") or ep["ip_address"]
    mac_addr = data.get("mac_address") or ep["mac_address"]
    version  = data.get("agent_version") or ep["agent_version"]
    # Persist heartbeat snapshot
    execute(
        """
        INSERT INTO endpoint_heartbeats
            (endpoint_id, cpu_percent, memory_percent, connection_count, firewall_active, reported_at)
        VALUES (?, ?, ?, ?, ?, datetime('now', 'localtime'))
        """,
        [ep["endpoint_id"], cpu, mem, conns, fw_active],
    )
    # Update endpoint status, last_seen, IP, MAC address, and Agent Version
    status = "Warning" if (cpu is not None and cpu > 90) else "Online"
    execute(
        """
        UPDATE endpoints
        SET last_seen = datetime('now', 'localtime'), status = ?, ip_address = ?, mac_address = ?, agent_version = ?
        WHERE endpoint_id = ?
        """,
        [status, ip_addr, mac_addr, version, ep["endpoint_id"]],
    )
    return jsonify({"ok": True})


@app.route("/api/agent/rules", methods=["GET"])
def api_agent_rules():
    """Agent polls for pending rule deployments targeting it."""
    ep = _verify_agent_token(request)
    if not ep:
        return jsonify({"error": "Unauthorized"}), 401
    pending = fetch_all(
        """
        SELECT d.deployment_id, r.rule_name, r.ip_address, r.port,
               r.protocol, r.action_type
        FROM endpoint_rule_deployments d
        JOIN firewall_rules r ON r.rule_id = d.rule_id
        WHERE d.endpoint_id = ? AND d.status = 'Pending'
        """,
        [ep["endpoint_id"]],
    )
    return jsonify(pending)


@app.route("/api/agent/rule-result", methods=["POST"])
def api_agent_rule_result():
    """Agent reports the outcome of executing a rule deployment."""
    ep = _verify_agent_token(request)
    if not ep:
        return jsonify({"error": "Unauthorized"}), 401
    data = request.get_json(silent=True) or {}
    deployment_id = data.get("deployment_id")
    success       = data.get("success", False)
    message       = str(data.get("message", ""))[:500]
    if not deployment_id:
        return jsonify({"error": "deployment_id required"}), 400
    execute(
        """
        UPDATE endpoint_rule_deployments
        SET status = ?, result_message = ?
        WHERE deployment_id = ? AND endpoint_id = ?
        """,
        ["Applied" if success else "Failed", message, deployment_id, ep["endpoint_id"]],
    )
    return jsonify({"ok": True})


# ── Endpoint management (admin web UI) ───────────────────────────────────────

@app.route("/endpoints", methods=["GET", "POST"])
@login_required
@roles_required("Administrator")
def endpoints():
    if request.method == "POST":
        hostname = request.form.get("hostname", "").strip()[:100]
        os_info  = request.form.get("os_info",  "").strip()[:200]
        if not hostname:
            flash("Hostname is required.", "warning")
            return redirect(url_for("endpoints"))
        token = secrets.token_hex(20)   # 40-char cryptographically random hex token
        execute(
            "INSERT INTO endpoints (hostname, agent_token, os_info, status) VALUES (?, ?, ?, 'Offline')",
            [hostname, token, os_info],
        )
        flash(f"Endpoint '{hostname}' registered. Copy the token into agent_config.json.", "success")
        session["last_generated_token"] = token
        return redirect(url_for("endpoints"))

    # Mark stale endpoints Offline before rendering
    execute(
        f"""
        UPDATE endpoints SET status = 'Offline'
        WHERE last_seen IS NULL
           OR last_seen < datetime('now', 'localtime', '-{AGENT_OFFLINE_SECONDS} seconds')
        """
    )
    all_endpoints = fetch_all(
        """
        SELECT e.*,
               h.cpu_percent, h.memory_percent, h.connection_count, h.firewall_active
        FROM endpoints e
        LEFT JOIN (
            SELECT endpoint_id, cpu_percent, memory_percent, connection_count, firewall_active
            FROM endpoint_heartbeats
            WHERE heartbeat_id IN (
                SELECT MAX(heartbeat_id) FROM endpoint_heartbeats GROUP BY endpoint_id
            )
        ) h ON h.endpoint_id = e.endpoint_id
        ORDER BY e.registered_at DESC
        """
    )
    all_rules = fetch_all(
        "SELECT rule_id, rule_name, action_type, protocol FROM firewall_rules WHERE status = 'Active' ORDER BY rule_name"
    )
    last_token = session.pop("last_generated_token", None)
    return render_template(
        "endpoints.html",
        endpoints=all_endpoints,
        rules=all_rules,
        last_token=last_token,
        server_lan_url=request.host_url.rstrip("/"),
        registration_key=GLOBAL_REGISTRATION_KEY,
    )


@app.route("/endpoints/<int:endpoint_id>/delete", methods=["POST"])
@login_required
@roles_required("Administrator")
def delete_endpoint(endpoint_id):
    ep = fetch_one("SELECT hostname FROM endpoints WHERE endpoint_id = ?", [endpoint_id])
    if ep:
        execute("DELETE FROM endpoints WHERE endpoint_id = ?", [endpoint_id])
        flash(f"Endpoint '{ep['hostname']}' removed.", "info")
    return redirect(url_for("endpoints"))


@app.route("/endpoints/<int:endpoint_id>/push-rules", methods=["POST"])
@login_required
@roles_required("Administrator")
def push_rules_to_endpoint(endpoint_id):
    ep = fetch_one("SELECT hostname FROM endpoints WHERE endpoint_id = ?", [endpoint_id])
    if not ep:
        flash("Endpoint not found.", "danger")
        return redirect(url_for("endpoints"))
    rule_ids = request.form.getlist("rule_ids")
    if not rule_ids:
        flash("Select at least one rule to push.", "warning")
        return redirect(url_for("endpoints"))
    pushed = 0
    for rid in rule_ids:
        try:
            rid = int(rid)
        except ValueError:
            continue
        existing = fetch_one(
            "SELECT deployment_id FROM endpoint_rule_deployments WHERE endpoint_id=? AND rule_id=? AND status='Pending'",
            [endpoint_id, rid],
        )
        if not existing:
            execute(
                "INSERT INTO endpoint_rule_deployments (endpoint_id, rule_id, deployed_by, status) VALUES (?, ?, ?, 'Pending')",
                [endpoint_id, rid, session.get("user_id")],
            )
            pushed += 1
    flash(f"{pushed} rule(s) queued for deployment to '{ep['hostname']}'.", "success")
    return redirect(url_for("endpoints"))


@app.route("/endpoints/push-all", methods=["POST"])
@login_required
@roles_required("Administrator")
def push_rules_to_all():
    rule_ids   = request.form.getlist("rule_ids")
    online_eps = fetch_all("SELECT endpoint_id, hostname FROM endpoints WHERE status = 'Online'")
    if not rule_ids:
        flash("Select at least one rule to push.", "warning")
        return redirect(url_for("endpoints"))
    if not online_eps:
        flash("No online endpoints found.", "warning")
        return redirect(url_for("endpoints"))
    total = 0
    for ep in online_eps:
        for rid in rule_ids:
            try:
                rid = int(rid)
            except ValueError:
                continue
            existing = fetch_one(
                "SELECT deployment_id FROM endpoint_rule_deployments WHERE endpoint_id=? AND rule_id=? AND status='Pending'",
                [ep["endpoint_id"], rid],
            )
            if not existing:
                execute(
                    "INSERT INTO endpoint_rule_deployments (endpoint_id, rule_id, deployed_by, status) VALUES (?, ?, ?, 'Pending')",
                    [ep["endpoint_id"], rid, session.get("user_id")],
                )
                total += 1
    flash(f"{total} rule deployment(s) queued across {len(online_eps)} online endpoint(s).", "success")
    return redirect(url_for("endpoints"))


@app.route("/api/endpoints/stats")
@login_required
def api_endpoints_stats():
    """JSON endpoint counts for live dashboard refresh."""
    execute(
        f"""
        UPDATE endpoints SET status = 'Offline'
        WHERE last_seen IS NULL
           OR last_seen < datetime('now', 'localtime', '-{AGENT_OFFLINE_SECONDS} seconds')
        """
    )
    row = fetch_one(
        """
        SELECT COUNT(*) AS total,
               SUM(CASE WHEN status='Online'  THEN 1 ELSE 0 END) AS online,
               SUM(CASE WHEN status='Offline' THEN 1 ELSE 0 END) AS offline,
               SUM(CASE WHEN status='Warning' THEN 1 ELSE 0 END) AS warning
        FROM endpoints
        """
    )
    return jsonify(row)


if __name__ == "__main__":
    # Warn if Live Mode is on but not running as Administrator
    if APPLY_FIREWALL_RULES and not is_running_as_admin():
        print(
            "\n[FireGuard WARNING] fireguard_settings.json has apply_firewall_rules=true "
            "but this process is NOT running as Administrator.\n"
            "Windows Firewall rules cannot be applied. Either:\n"
            "  (a) Run PowerShell as Administrator and use: .\\start_live_admin.ps1\n"
            "  (b) Set apply_firewall_rules=false in fireguard_settings.json to use "
            "Recorded Mode (no Windows Firewall changes).\n"
        )
    init_db()
    start_monitor()   # Start psutil background traffic monitor
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True, use_reloader=False)
