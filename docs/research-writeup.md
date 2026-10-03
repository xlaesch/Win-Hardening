# CCDC Windows Hardening — Research Writeup

*Research date: 2026-09-29. Sources verified at time of research; placement claims
backed by the official NCCDC winners list and CIAS press releases.*

This document records **how historically successful CCDC teams hardened Windows**,
filtered by how well teams placed, and maps each finding to the modules in this repo.
It drives every design decision here.

## 1. Top-placing programs, 2015-2026

Official winners list: <https://www.nationalccdc.org/winners.html>

| Team | National results (window) | Public playbook? |
|---|---|---|
| UCF (Hack@UCF) | 6 titles incl. 2015, 2016, 2021, 2022, 2024; 3 runner-up | **No** (kept private) |
| U. Virginia | 3 straight titles 2018-2020; runner-up 2025, 2026 | Partial - BLUESPAWN (open-source EDR) |
| Cal Poly **Pomona** (SWIFT) | Runner-up 2023 & 2024 | **Yes** - [cpp-cyber/blue](https://github.com/cpp-cyber/blue) |
| Stanford (Applied Cyber) | Champion 2023 | No |
| UC Irvine (Cyber@UCI) | Champion 2025 | No public repos |
| Dakota State (DefSec) | Champion 2026; runner-up 2022 | Org only: [DSU-DefSec](https://github.com/DSU-DefSec) |
| DePaul (Security Daemons) | Runner-up 2021; third 2016, 2023 | No |
| BYU | Runner-up 2016; third 2017 | **Yes** - [BYU-CCDC/public-ccdc-resources](https://github.com/BYU-CCDC/public-ccdc-resources) |
| RIT | Champion 2013; third 2014/2015/2019 | No |

Note: Cal Poly **Pomona**, not San Luis Obispo, is the CCDC powerhouse (common confusion).

Key structural fact: **the very top teams do not publish their tooling.** The best
public, placement-verified playbooks are BYU (2016 runner-up) and Cal Poly Pomona
(2023/24 runner-up), and both are gold mines. Regional-level live repos (UW-Stout,
UC Riverside, WGU) add first-minute automation patterns.

## 2. What the publishable top teams actually did

### BYU — 2016 national runner-up (most detailed public playbook)

Source: `windows/hardening/AD-Hardening.ps1` and `Local-Hardening.ps1` in their repo.

- **Backups first**: firewall rules, DNS zones, group memberships exported before changes.
- **Mass-disable every inherited AD user**, create 2-3 fresh competition accounts (one
  full admin in Domain/Enterprise/Schema Admins + **Protected Users** group).
- **Kerberoast/AS-REP fixes**: clear `DoesNotRequirePreauth`, force AES-only
  (`msDS-SupportedEncryptionTypes=24`) on service accounts, reset their passwords.
- **Firewall allowlist**: delete every rule, re-add only needed ports (AD: 53, 88, 135,
  139, 389, 445, 464, 636, 3268/3269; scored web/ssh/rdp as applicable).
- **Registry hardening**: NoLMHash, RestrictAnonymous/SAM, NTLM minimum security,
  **SMB signing required both directions**, LDAP signing + channel binding enforced,
  CachedLogonsCount=0, full UAC.
- **Named-CVE kills**: EternalBlue/MS17-010, SMBv1 off, DCSync audit ACLs, WDigest off.
- **~58 audit subcategories** + **Sysmon + Splunk Universal Forwarder on every box**.
- **Persistence wipe**: unregister ALL scheduled tasks, delete accessibility backdoor
  binaries (sethc.exe, Utilman.exe, osk.exe, Narrator.exe, Magnify.exe).
- IIS hardening: request filtering, no directory browsing, ISAPI/CGI restrictions.

### Cal Poly Pomona — runner-up 2023 & 2024

Sources: [cpp-cyber/blue](https://github.com/cpp-cyber/blue) +
[altoid0's writeups](https://altoid0.com/) (their Windows lead, 2023/2024):

- **Script chain pushed over WinRM** (their dispatcher: [Dovetail](https://github.com/Altoid0/Dovetail)):
  Inventory -> Fix (QOL) -> SMB -> PHP -> Log -> Users -> Hard. "Less is more" - small
  scripts, not monoliths.
- **Inventory.ps1 first**: users, startups, software, shares, IIS bindings. Their
  captain's scored-service-to-box mapping sheet was "quite literally gold."
- **Pass-the-hash suite**: NoLmHash, LmCompatibilityLevel=5, WDigest off,
  LocalAccountTokenFilterPolicy=0, RunAsPPL.
- **Defender**: cloud block level 6, tamper protection, **15 ASR rules** (verified count
  in their Hard.ps1), all exclusions removed.
- **DC fixes**: Zerologon (FullSecureChannelProtection), noPac (MachineAccountQuota=0),
  spooler disabled + PrintNightmare mitigations, LDAP signing client+server.
- **krbtgt rotation** to kill golden tickets — but warn: their 2023 automation **double-reset
  krbtgt and broke Kerberos domain-wide**, forcing manual hardening of 17 boxes. Lesson:
  rotate krbtgt ONCE, wait for replication, verify.
- 2024 pivot: at Nationals they went **manual for the first 15 minutes** ("the first 15
  minutes is the most important") — automation failed them when WinRM depended on
  firewall state. Result: zero red-team activity on Windows day 1.
- OpSec lessons: a plaintext Wazuh password in a web-accessible script gave red team
  log-flooding + sinkholes; reused passwords on the Linux side = instant SSH access.

### UVA — champions 2018-2020

Built **BLUESPAWN** (<https://github.com/ION28/BLUESPAWN>): open-source Windows
EDR/active-defense with Hunt/Monitor/Mitigate modes, MITRE-mapped detections tested
against Atomic Red Team, STIG-informed hardening audits. Takeaway: when commercial
EDR is banned, host-based detection + scripted hardening audits is the champion pattern.
(A BLUESPAWN client binary is vendored in `tools/`.)

### Regional live repos

- **UW-Stout** ([CCDC-scripts](https://github.com/UWStout-CCDC/CCDC-scripts), very active):
  first-minute `init.ps1` — rotate local passwords, clear registry persistence,
  **rotate the krbtgt/service password (invalidates stolen tickets)**, apply GPO pack,
  ClamAV + Wazuh agents, IIS hardening.
- **UC Riverside** ([ucrcyber/CCDC](https://github.com/ucrcyber/CCDC)): bulk password
  scripts, AD export/audit, group management review — "automate initial auditing so the
  valuable first minutes can be used working on more complicated hardening."
- **WGU** ([Blue-Team-Tools](https://github.com/WGU-CCDC/Blue-Team-Tools)): CC0 toolkit
  with CCDCprep first-steps guides.

### Canonical cross-team sources

- **[mubix/howtowinccdc](https://github.com/mubix/howtowinccdc)** — community deck
  maintained since 2010 by red teamers; archives **every team packet 2007-2026**.
  Priorities: clear head > firewalls > AV > FIM > logs > patches. "NO ONE IS GOING TO
  DROP 0DAY AT CCDC" — initial access is **default credentials**.
- **Red team TTPs** (what hardening must survive):
  - Cobalt Strike's NCCDC post: hashes dumped within 5 minutes; pre-implanted webshells;
    per-system + per-method scoring means every blocked technique stacks value.
  - Alex Levinson's toolbox posts: hash-cracking fleet ("the more hashes you give us,
    the more we'll crack"), credential flypaper, persistence layered because scheduled
    tasks "are easily detected" (they got caught there).
  - sshell.co NCCDC 2025: initial access via vulnerable web plugins; **10-20 reused
    credentials cracked on day 1 opened everything**; C2 tunneled over NTP from a DC
    unnoticed; "no team fully rotated default DB creds by end of day 1."
  - David Cowen (HECFB): "reinstalling is not remediation" — attacker re-compromise
    during rebuild = sustained SLA loss, the biggest point drain.

## 3. Ranked consensus control list -> module mapping

| # | Action (cross-source frequency) | Where in this repo |
|---|---|---|
| 1 | Scripted credential rotation day one | `16-Passwords.ps1` (rule-gated: confirm flag, 24-char cap, CSV) |
| 2 | SMB/NTLM hygiene: SMBv1 off, signing, NTLMv2-only, no LM hash, restrict anonymous | `02-SmbNtlm.ps1` |
| 3 | LSASS protection: WDigest off, RunAsPPL, LSASS auditing | `03-Lsass.ps1` |
| 4 | Firewall ON + allowlist egress (never block scoring engine) | `01-Firewall.ps1` (enable+logging; allowlist in backlog) |
| 5 | Patch wormable CVEs (Zerologon, noPac, PrintNightmare) | `10-Services.ps1`, `12-DomainController.ps1` (OS patching in backlog) |
| 6 | Advanced audit + Sysmon + central forwarding (incident reports recover points) | `05-Audit.ps1`, `07-Sysmon.ps1`, `14-PsLogging.ps1` (WEF in backlog) |
| 7 | Persistence hunting: scheduled tasks, startup keys, webshells, service installs | `Invoke-Inventory.ps1`, `Invoke-Hunt.ps1` |
| 8 | Defender on + tamper + ASR + exclusions removed | `04-Defender.ps1` |
| 9 | Disable LLMNR/NBT-NS (Responder) | `06-NameResolution.ps1` |
| 10 | Inventory everything before touching anything | `Invoke-Inventory.ps1` (CPP template) |
| 11 | UAC + RDP NLA + LDAP signing + GPO neutralization + share lockdown | `08`, `09`, `11`, `13`, `15` (CPP parity) |
| 12 | Know the rules: anti-gamification, change freeze, revert limits | `docs/runbook.md` |

## 4. Competition constraints that shape hardening (2025 NCCDC team packet)

From <https://github.com/mubix/howtowinccdc/blob/master/documents/Nationals/2025-NCCDC-TeamPacket.pdf>:

- Scoring: ~30% critical services, ~30% injects, ~30% Orange/White/Ops, minus deductions.
- **One mass password reset per system** without approval; admin passwords need not be
  reported; scored-service user passwords must be submitted as CSVs (10-15 min to take
  passwords max 24 characters.
- Day-1 change freeze: patching allowed, no OS migrations, no containerizing scored
  services. DMZ/NAT allowed if the service stays reachable at its original IP/FQDN.
- **Anti-gamification clause**: over-lockdown is penalized (blocking internal traffic,
  disabling DNS, shells to /bin/false...). Workstations must still reach AD/mail/file.
- CCSClient monitoring agent must keep reaching its server (TCP 80/443) — never firewall it.
- VM reverts: first 12 free, then -50 each. "Reinstalling is not remediation."
- Deductions are per-system AND per-method; incident reports (with source IP) recover points.
- Red team start: regionals typically ~1 hour grace; day 1 = credentials, day 2 = full malware.

## 5. Tooling research conclusions

- **No `win_lgpo` Ansible module exists** (verified against current collection indexes).
  Real building blocks: `community.windows.win_security_policy`, `ansible.windows`
  `win_user_right`/`win_audit_policy_system`/`win_firewall_rule`/`win_updates`,
  `microsoft.ad` for domain objects. (For the future Ansible wrapper phase.)
- **ansible-lockdown CIS roles** (Windows-2019-CIS etc.): good as a menu, dangerous as a
  whole-run (no check mode; Level 2 breaks services). Not used in v1.
- **Microsoft SCT + LGPO.exe**: fast bulk baselines with rollback (`LGPO.exe /b`), but
  coarse for competition (can't exempt scored services easily). Optional future module;
  LGPO.exe is vendored in `tools/Security Compliance Toolkit`.
- **Sysmon configs**: SwiftOnSecurity (5.7k stars, the classic) vendored as our default;
  olafhartong/sysmon-modular is the modular alternative for later tuning.
- **No "defended GOAD" exists publicly** — this project (hardening GOAD-Light and
  measuring before/after) is novel ground.

## 6. Lab facts (GOAD-Light)

- 3 VMs, all Windows Server 2019: DC01 `kingslanding.sevenkingdoms.local` (parent DC,
  ADCS with ESC1), DC02 `winterfell.north.sevenkingdoms.local` (child DC), SRV02
  `castelblack` (member server: IIS with ASP upload, MSSQL, SMB shares).
- Deliberate weaknesses our modules remediate: firewall disabled on all profiles
  (module 01), LLMNR/NBT-NS enabled (module 06), LmCompatibilityLevel=2 (module 02),
  Defender off on SRV02 (module 04), Kerberoastable SPNs/AS-REP users and weak domain
  DACLs (future AD module), password in a user description (surfaced by inventory).
- Post-provision credentials documented in `ad/GOAD-Light/data/inventory_disable_vagrant`
  (per-DC local/domain admin) — lab reference for the Proxmox deployment.
