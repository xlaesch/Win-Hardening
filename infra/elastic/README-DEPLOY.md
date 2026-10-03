# Elastic detection stack - deploy on the Kali VM (WireGuard into the lab)

One-command, self-contained ES + Kibana with the Win-Hardening detection layer:
integration ingest pipelines (installed directly - no Fleet Server), Elastic's
prebuilt rules (curated CCDC set enabled), four custom CCDC rules, and an
optional webhook for alert push. Bundled offline: integration packages included.

## Deploy (Kali, ~6 GB RAM free)

```bash
sudo apt install -y docker.io docker-compose-v2 jq python3-yaml
sudo usermod -aG docker $USER && newgrp docker   # or run with sudo

cd infra/elastic
cp .env.example .env
# set ELASTIC_PASSWORD (openssl rand -base64 18)
# set STACK_IP to the Kali's WireGuard-side IP on the lab network

docker compose up -d          # ES on :9200, Kibana on :5601
./setup.sh                    # pipelines + 2165 prebuilt rules + curated + custom
```

Kibana: http://<kali-vpn-ip>:5601 - login `elastic` / your `.env` password.
Detect: hamburger menu -> Security -> Alerts (detections live here).
Discover: pick the `logs-*` data view - Security channel events arrive
ECS-mapped (`event.action`, `source.ip`, `user.name`, `winlog.logon.type`).

## WireGuard notes (agents must reach the stack)

Agents ship to `http://<kali-vpn-ip>:9200`. On the WireGuard config:
- The Kali's peer on the lab-side WireGuard server needs `AllowedIPs` including
  the lab subnet (e.g. `192.168.56.0/24`) so replies route back.
- The lab gateway needs a route for the WireGuard subnet via the WG server
  (the GOAD LXC already routes 192.168.56.0/24 toward the WG-side host).
- Test from a Windows box: `Test-NetConnection <kali-vpn-ip> -Port 9200`.

## Point the lab hosts at the stack

On each Windows host (toolkit present):

```powershell
# scripts\files\elastic-config.json:
{ "ElasticUrl": "http://<kali-vpn-ip>:9200", "Username": "elastic", "Password": "<env password>" }
.\Invoke-Harden.ps1 -Modules ElasticAgent     # installs/updates the agent
```

Datasets: Security -> `system.security` (full ECS pipeline), Sysmon/PowerShell/
Defender -> `windows.*`. The pipelines were installed by setup.sh on the stack.

## Trial license

setup.sh starts the 30-day trial when available (unlocks editing prebuilt rules
and attaching actions). After expiry: detections keep working; to re-arm, `docker
compose down -v` and redeploy (fresh cluster = fresh trial; agents re-ship and
data streams recreate automatically).

## Webhook alerts (optional)

Set `WEBHOOK_URL` in `.env` before running setup.sh: every curated rule gets a
post-per-alert action (message = rule name + context).

## What fires out of the box

Curated prebuilt: logon-failure bursts, failure-then-success, privileged-account
brute force, Kerberoasting (RC4 TGS), pre-auth-disabled changes, remote service
installs, scheduled-task creation, privileged-group additions, LSASS access, PS
hacktool script blocks, PS ticket dumps, Defender tampering.
Custom: Defender 1116/1117 detections, AS-REP roast requests (4768 preauth=0),
RDP brute force (type 10), network logon spray (type 3).

Note: running hardening module 04 on a host will legitimately trip the
Defender-tamper rule (it writes Defender policy keys) - expected noise.
