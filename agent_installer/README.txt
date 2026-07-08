FireGuard Agent Installer
=========================

WHAT THIS IS
------------
This folder turns another Windows laptop into a FireGuard-managed endpoint,
so it shows up live on the FireGuard dashboard's Endpoints page during your
demo/defense.

You need TWO laptops on the SAME Wi-Fi/network:
  - Laptop A = the FireGuard SERVER (runs app.py, has the web dashboard)
  - Laptop B = the ENDPOINT being managed (this installer goes here)

HOW TO USE (on Laptop B, the second laptop)
--------------------------------------------
1. Copy this whole "agent_installer" folder onto Laptop B (USB drive, shared
   folder, AirDrop-equivalent, whatever's easiest).

2. On Laptop A (the server), make sure FireGuard is running (python app.py),
   log into the dashboard as an Administrator, and open the "Endpoints" page.
   You'll see a box titled "Endpoint Self-Registration" showing:
       Server URL               e.g. http://192.168.1.10:5000
       Global Registration Key  e.g. fireguard-register-token
   Keep that page open, or copy both values somewhere.

3. On Laptop B, right-click "Install-FireGuardAgent.ps1" -> "Run with
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

5. Back on Laptop A's dashboard -> Endpoints page, Laptop B should appear
   within a few seconds, listed by its own hostname, status "Online".

THAT'S IT - no manual token copy-pasting needed. The agent registers itself
the first time it runs, using the shared Registration Key, and remembers its
token afterwards (saved into agent_config.json).

TROUBLESHOOTING
---------------
- "Could not reach server" during install: confirm both laptops are on the
  same network, and Laptop A's Windows Firewall allows inbound connections
  on port 5000 (or temporarily disable Laptop A's firewall for the demo).
- Endpoint never shows up online: check the Start-FireGuardAgent.ps1 window
  for error lines - "POST error" usually means the Server URL is wrong
  (typo, wrong IP, or Laptop A's IP changed after reconnecting to Wi-Fi).
- Laptop A's LAN IP changes if it reconnects to Wi-Fi: just re-check the
  Endpoints page for the current Server URL and re-run Install if it changed.
- To re-run setup from scratch: delete agent_config.json in this folder and
  run Install-FireGuardAgent.ps1 again.
