import json, os, platform, socket, subprocess, sys, time, uuid
import psutil, requests

try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:
    pass

BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(BASE_DIR, "agent_config.json")
DEFAULT_CONFIG = {
    "server_url":          "http://127.0.0.1:5000",
    "registration_key":    "",
    "agent_token":         "",
    "heartbeat_interval":  30,
}
AGENT_VERSION = "2.0"


def get_mac_address():
    try:
        node = uuid.getnode()
        mac = ':'.join(['{:02x}'.format((node >> ele) & 0xff) for ele in range(0, 8*6, 8)][::-1])
        return mac
    except Exception:
        return "00:00:00:00:00:00"


def register_agent(cfg):
    """Self-registration: exchange the shared Global Registration Key (shown
    to Administrators on the /endpoints page) for a per-endpoint agent token,
    instead of an admin manually creating the endpoint and pasting a token."""
    reg_key = cfg.get("registration_key")
    if not reg_key:
        print("[Agent] ERROR: No agent_token and no registration_key set in agent_config.json.")
        print("[Agent] Either paste a token generated on the /endpoints page, or set")
        print("[Agent] registration_key to the Global Registration Key shown there.")
        sys.exit(1)

    url = cfg["server_url"].rstrip("/") + "/api/agent/register"
    payload = {
        "registration_key": reg_key,
        "hostname":         socket.gethostname(),
        "ip_address":       _local_ip(),
        "mac_address":      get_mac_address(),
        "os_info":          platform.system() + " " + platform.release(),
        "agent_version":    AGENT_VERSION,
    }
    print("[Agent] Self-registering with " + url + " ...")
    try:
        r = requests.post(url, json=payload, timeout=15, verify=False)
    except Exception as e:
        print("[Agent] ERROR: Could not reach server: " + str(e))
        sys.exit(1)

    if r.status_code != 200:
        print("[Agent] ERROR: Registration rejected. HTTP " + str(r.status_code) + " " + r.text[:200])
        sys.exit(1)

    token = r.json().get("agent_token")
    if not token:
        print("[Agent] ERROR: Server response missing agent_token.")
        sys.exit(1)

    cfg["agent_token"] = token
    with open(CONFIG_FILE, "w") as f:
        json.dump(cfg, f, indent=2)
    print("[Agent] Registered successfully. Token saved to agent_config.json.")
    return token


def _local_ip():
    try:
        return socket.gethostbyname(socket.gethostname())
    except Exception:
        return "unknown"


def load_config():
    if not os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "w") as f:
            json.dump(DEFAULT_CONFIG, f, indent=2)
        print("[Agent] Created default config at " + CONFIG_FILE)
        print("[Agent] Set server_url and either registration_key (self-register)")
        print("[Agent] or agent_token (pasted from the /endpoints page), then restart.")
        sys.exit(0)
    with open(CONFIG_FILE) as f:
        cfg = json.load(f)
    token = cfg.get("agent_token")
    if not token or token == "PASTE_YOUR_TOKEN_HERE":
        token = register_agent(cfg)
        cfg["agent_token"] = token
    return cfg


def _headers(token):
    return {"Authorization": "Bearer " + token, "Content-Type": "application/json"}


def _post(url, token, payload):
    try:
        return requests.post(url, json=payload, headers=_headers(token), timeout=10, verify=False)
    except Exception as e:
        print("[Agent] POST error: " + str(e))
        return None


def _get(url, token):
    try:
        return requests.get(url, headers=_headers(token), timeout=10, verify=False)
    except Exception as e:
        print("[Agent] GET error: " + str(e))
        return None


def _firewall_active():
    try:
        r = subprocess.run(
            ["netsh", "advfirewall", "show", "allprofiles", "state"],
            capture_output=True, text=True, timeout=8
        )
        return "ON" in r.stdout.upper()
    except Exception:
        return False


def collect_health():
    try:
        cpu = psutil.cpu_percent(interval=1)
    except Exception:
        cpu = 0.0
    try:
        mem = psutil.virtual_memory().percent
    except Exception:
        mem = 0.0
    try:
        conns = len(psutil.net_connections(kind="inet"))
    except Exception:
        conns = 0
    try:
        ip = socket.gethostbyname(socket.gethostname())
    except Exception:
        ip = "unknown"
    return {
        "cpu_percent":      cpu,
        "memory_percent":   mem,
        "connection_count": conns,
        "firewall_active":  _firewall_active(),
        "ip_address":       ip,
        "mac_address":      get_mac_address(),
        "agent_version":     AGENT_VERSION,
    }


def send_heartbeat(cfg, health):
    url = cfg["server_url"].rstrip("/") + "/api/agent/heartbeat"
    r   = _post(url, cfg["agent_token"], health)
    if r and r.status_code == 200:
        fw = "ON" if health["firewall_active"] else "OFF"
        print(
            "[Agent] Heartbeat OK | CPU %.1f%% | MEM %.1f%% | Conns %d | FW %s"
            % (health["cpu_percent"], health["memory_percent"], health["connection_count"], fw)
        )
    elif r:
        print("[Agent] Heartbeat rejected: HTTP " + str(r.status_code))


def fetch_pending_rules(cfg):
    url = cfg["server_url"].rstrip("/") + "/api/agent/rules"
    r   = _get(url, cfg["agent_token"])
    return r.json() if (r and r.status_code == 200) else []


def apply_rule(rule):
    name     = "FireGuard-" + rule["rule_name"]
    action   = "block" if rule["action_type"] == "BLOCK" else "allow"
    protocol = rule.get("protocol", "TCP")
    ip       = rule.get("ip_address")
    port     = rule.get("port")
    cmd = ["netsh", "advfirewall", "firewall", "add", "rule",
           "name=" + name, "dir=in", "action=" + action, "protocol=" + protocol]
    if port:
        cmd.append("localport=" + str(port))
    if ip:
        cmd.append("remoteip=" + ip)
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        ok  = res.returncode == 0
        msg = (res.stdout + res.stderr).strip()[:500] or "Applied."
        if ok and action == "block":
            cmd2 = ["netsh", "advfirewall", "firewall", "add", "rule",
                    "name=" + name + "-out", "dir=out", "action=block", "protocol=" + protocol]
            if port:
                cmd2.append("remoteport=" + str(port))
            if ip:
                cmd2.append("remoteip=" + ip)
            subprocess.run(cmd2, capture_output=True, text=True, timeout=15)
        return ok, msg
    except Exception as e:
        return False, str(e)


def report_rule_result(cfg, did, ok, msg):
    url = cfg["server_url"].rstrip("/") + "/api/agent/rule-result"
    _post(url, cfg["agent_token"], {"deployment_id": did, "success": ok, "message": msg})


def main():
    print("=" * 60)
    print(" FireGuard Agent")
    print(" Host: " + socket.gethostname())
    print(" OS  : " + platform.system() + " " + platform.version()[:40])
    print("=" * 60)
    cfg = load_config()
    print("[Agent] Server   : " + cfg["server_url"])
    print("[Agent] Interval : " + str(cfg["heartbeat_interval"]) + "s")
    print("[Agent] Press Ctrl+C to stop.")
    while True:
        health = collect_health()
        send_heartbeat(cfg, health)
        for rule in fetch_pending_rules(cfg):
            did = rule.get("deployment_id")
            print("[Agent] Applying rule: " + str(rule.get("rule_name")) + " #" + str(did))
            ok, msg = apply_rule(rule)
            print("[Agent]   [" + ("OK" if ok else "FAIL") + "] " + msg[:80])
            report_rule_result(cfg, did, ok, msg)
        time.sleep(cfg.get("heartbeat_interval", 30))


if __name__ == "__main__":
    main()
