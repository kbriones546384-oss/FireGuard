FireGuard Agent Installer
=========================

WHAT THIS IS
------------
This folder turns another Windows laptop into a FireGuard-managed endpoint,
so it shows up live on the FireGuard dashboard's Endpoints page during your
demo/defense.

You need the FireGuard SERVER running somewhere reachable, and a second
Windows laptop to act as the ENDPOINT (this installer goes there). The
server can be either:
  (a) Another laptop on the SAME Wi-Fi/network (runs app.py locally), or
  (b) A cloud-hosted deployment (e.g. Render) reachable over the internet
      from anywhere — no shared Wi-Fi needed.

HOW TO USE (on the laptop being managed, i.e. the endpoint)
--------------------------------------------------------------
1. Copy this whole "agent_installer" folder onto the endpoint laptop (USB
   drive, shared folder, AirDrop-equivalent, whatever's easiest).

2. On the server (either the other laptop, or your Render dashboard), log in
   as an Administrator and open the "Endpoints" page. You'll see a box
   titled "Endpoint Self-Registration" showing:
       Server URL               e.g. http://192.168.1.10:5000 (same-Wi-Fi)
                                 or   https://your-app.onrender.com (cloud)
       Global Registration Key  e.g. fireguard-register-token
   Keep that page open, or copy both values somewhere.

3. On the endpoint laptop, right-click "Install-FireGuardAgent.ps1" -> "Run with
   PowerShell". If Windows blocks it, right-click -> Properties -> check
   "Unblock" -> OK, then try again. (Or run it from a PowerShell window:
   powershell -ExecutionPolicy Bypass -File Install-FireGuardAgent.ps1)

   It will:
     - Check Python 3 is installed (installs psutil/requests if needed)
     - Ask you to paste the Server URL and Registration Key from step 2
     - Save that into agent_config.json
     - Test that Laptop B can actually reach Laptop A

4. Right-click "Start-FireGuardAgent.ps1" -> "Run with PowerShell".
   Windows will ask for Administrator approval (click Yes) - this is
   required so the agent can apply firewall rules with netsh. A window will
   open and start printing heartbeat lines, e.g.:
       [Agent] Heartbeat OK | CPU 12.3% | MEM 44.1% | Conns 38 | FW ON
   Leave this window open during the demo.

5. Back on the server's dashboard -> Endpoints page, the endpoint laptop
   should appear within a few seconds, listed by its own hostname, status
   "Online".

THAT'S IT - no manual token copy-pasting needed. The agent registers itself
the first time it runs, using the shared Registration Key, and remembers its
token afterwards (saved into agent_config.json).

TROUBLESHOOTING
---------------
Same-Wi-Fi server:
- "Could not reach server" during install: confirm both laptops are on the
  same network, and the server laptop's Windows Firewall allows inbound
  connections on port 5000 (or temporarily disable it for the demo).
- Endpoint never shows up online: check the Start-FireGuardAgent.ps1 window
  for error lines - "POST error" usually means the Server URL is wrong
  (typo, wrong IP, or the server laptop's IP changed after reconnecting to
  Wi-Fi).
- The server laptop's LAN IP changes if it reconnects to Wi-Fi: just re-check
  the Endpoints page for the current Server URL and re-run Install if it
  changed.

Render/cloud server:
- "Could not reach server" during install: confirm this machine has internet
  access, and that the Server URL uses https:// (not http://) - Render
  redirects http requests to https, and that redirect can break the agent's
  self-registration request.
- Endpoint never shows up online: the free Render tier can spin the service
  down after inactivity, causing the first request after a while to be slow
  or briefly fail - try again after a few seconds, or check the Render
  dashboard's logs for errors.

Either setup:
- To re-run setup from scratch: delete agent_config.json in this folder and
  run Install-FireGuardAgent.ps1 again.
