# Runbook

Operational guide for the Win-Hardening toolkit: the lab test loop, module-by-module
notes, and competition-day order of operations.

## 1. The scripts

| Script | Purpose | Mutates state? |
|---|---|---|
| `Invoke-Inventory.ps1` | Read-only recon (CPP template: users, startups, software, shares, IIS, services, TCP, tasks, features) | No |
| `Invoke-Preflight.ps1` | Break-glass admin + full backups of everything modules touch | Yes (creates account + backups) |
| `Invoke-Harden.ps1` | Master runner: `-All` or `-Modules X,Y` | Via modules |
| `Invoke-Verify.ps1` | Service health checks + hardening state readback | No |
| `Invoke-Hunt.ps1` | Active-threat hunting: webshell process trees, events 7045/4742/5140, Defender detections | No |
| `Invoke-Restore.ps1` | Undo everything from a preflight backup | Yes |
| `lib/common.ps1` | Shared helpers (loaded by everything) | - |
| `modules/01-Firewall.ps1` | Firewall ON all profiles + drop logging (rules untouched) | Yes |
| `modules/02-SmbNtlm.ps1` | SMBv1 off, signing required (cmdlet + registry), NTLMv2-only, no LM hash, restrict anonymous | Yes |
| `modules/03-Lsass.ps1` | WDigest off, LSASS RunAsPPL + LSASS audit level (PPL effective after reboot) | Yes |
| `modules/04-Defender.ps1` | Real-time on, tamper protection (cmdlet + registry), 15 ASR rules, ASR + scan exclusions removed, full policy-key tree | Yes |
| `modules/05-Audit.ps1` | Core advanced audit policy + command-line logging; `-Full` = every category | Yes |
| `modules/06-NameResolution.ps1` | LLMNR + NBT-NS off (anti-Responder) | Yes |
| `modules/07-Sysmon.ps1` | Sysmon install/update + SwiftOnSecurity config, 512 MB log | Yes |
| `modules/08-Uac.ps1` | Full UAC + LocalAccountTokenFilterPolicy=0 (remote UAC / PTH) | Yes |
| `modules/09-RdpNla.ps1` | RDP NLA required (RDP stays on) | Yes |
| `modules/10-Services.ps1` | Spooler off, PrintNightmare mitigations, BITS lockdown | Yes |
| `modules/11-Ldap.ps1` | LDAP signing required (client + server on DCs) | Yes |
| `modules/12-DomainController.ps1` | Zerologon full protection + noPac (MAQ=0); DC-only | Yes |
| `modules/13-Gpo.ps1` | DC: all GPOs disabled / member: local GPO cache reset (+gpupdate) | Yes |
| `modules/14-PsLogging.ps1` | PowerShell script-block + module logging + transcription | Yes |
| `modules/15-SmbShares.ps1` | Non-exempt shares read-only + null-session pipe/share decoys | Yes |
| `modules/16-Passwords.ps1` | Bulk rotation + CSV (`-ConfirmRotation` required; DC via `-DomainUsers`, krbtgt excluded) | Yes |
| `modules/17-Php.ps1` | php.ini: dangerous functions disabled, uploads off (`-KeepUploads` to keep) | Yes |
| `modules/18-Iis.ps1` | IIS request logging on | Yes |
| `modules/19-AccessInsurance.ps1` | Narrator/Utilman/Sethc emergency console swap (`-AcceptRisk` required; never under `-All`) | Yes |
| `modules/20-FixExplorer.ps1` | Show hidden files, extensions, protected OS files | Yes |
| `modules/21-ElasticAgent.ps1` | Central logging: Elastic Agent standalone -> team Elasticsearch (skips until configured) | Yes |

All state changes land in `C:\HardeningBackups\<timestamp>\` with a
`backup-manifest.json`, per-change `change-log.json`, and transcripts under `logs\`.

### Cal Poly Pomona parity map

Every hardening in [cpp-cyber/blue](https://github.com/cpp-cyber/blue) `Windows/`
is covered (their transport/analysis scripts deferred to our Ansible phase):

| CPP script | What it does | Ours |
|---|---|---|
| Hard.ps1 | PTH suite, Defender+ASR+policy keys, UAC, RDP NLA, spooler/PrintNightmare/BITS, LDAP signing, Zerologon/noPac, Narrator trick | 02, 03, 04, 08, 09, 10, 11, 12, 19 |
| SMB.ps1 | SMB1/signing registry + share permissions read-only | 02, 15 |
| Log.ps1 | auditpol all, PS logging, IIS logging, Sysmon | 05 (-Full), 14, 18, 07 |
| Gpo.ps1 | disable all GPOs | 13 |
| Usr.ps1 / bruhpdate.ps1 | bulk password rotation + admin groups | 16 + preflight (RDP/WinRM groups) |
| Misc.ps1 | null-session pipes/shares decoys | 15 |
| Fix.ps1 | local GPO reset + Explorer visibility (+ QOL fonts/language, not hardening) | 13, 20 |
| php.ps1 | disable dangerous PHP functions + uploads | 17 |
| Webshell_Hunter.ps1 | web-worker child process hunt | Invoke-Hunt.ps1 |
| Comp.ps1 | events 7045/4742/5140 | Invoke-Hunt.ps1 |
| Inv.ps1 | inventory | Invoke-Inventory.ps1 |
| Passwords.ps1 | (joke file) | - |
| Run/Exec/Prop/testport | WinRM dispatch, bin propagation, port test | Ansible phase (transport, not hardening) |
| postprocessing.ps1 | team-side inventory parsing | backlog (analysis tooling) |

## 2. Lab test loop (GOAD-Light on Proxmox)

The lab lives on the team's Proxmox server (GOAD-Light: DC01 kingslanding,
DC02 winterfell, SRV02 castelblack - all Server 2019). For each test cycle:

1. **Snapshot** the VM (Proxmox) at the clean-provisioned "gold" state.
2. **Copy the toolkit** onto the target (`scripts\` and `tools\`, via SMB share,
   RDP clipboard, or any transfer that works - keep the `scripts\` folder structure).
3. **Inventory** (read-only, learn the box):
   ```powershell
   Set-ExecutionPolicy Bypass -Scope Process -Force
   .\Invoke-Inventory.ps1
   ```
4. **Preflight** (break-glass admin + backups): `.\Invoke-Preflight.ps1`
   - Record the printed break-glass password.
5. **Harden**: `.\Invoke-Harden.ps1 -All` (or per-module; `-WhatIf` to preview).
6. **Verify**: `.\Invoke-Verify.ps1` - all checks must PASS:
   - DC01/DC02: DNS resolves, NTDS running, SYSVOL/NETLOGON present, AD queries work.
   - SRV02: IIS serves localhost:80 (200), MSSQL running, port 1433 listens.
   - Everywhere: WinRM listener still answers (that is our management plane).
7. **Red-team spot checks** (optional, from another VM): `nltest /sc_verify:`,
   SMB share access, Responder run (should get nothing with LLMNR off).
8. **Restore** (`.\Invoke-Restore.ps1`) and/or revert the Proxmox snapshot, then
   iterate.

### Module-specific lab expectations (GOAD-Light)

- **01-Firewall**: GOAD disables all profiles; module re-enables. IIS/RDP/WinRM explicit
  allow rules already exist, so services keep answering - that is exactly what Verify checks.
- **02-SmbNtlm**: GOAD sets `LmCompatibilityLevel=2`; module raises to 5. Watch for
  NTLM auth issues from anything ancient (nothing in GOAD-Light qualifies).
- **04-Defender**: SRV02 ships with Defender off - this flips it on. DCs have updates
  disabled; Defender still runs with the built-in signature set. Signature updates
  (`Update-MpSignature`) are left to the team (internet-dependent).
- **06-NameResolution**: GOAD explicitly enables LLMNR (`EnableMulticast=1`) - the module
  is a direct remediation of a planted weakness. NBT-NS changes are per-adapter and
  apply after adapter refresh.
- **11-Ldap**: `LDAPClientIntegrity=2` applies to new sessions; on DCs
  `LDAPServerIntegrity` needs an NTDS restart. Watch domain-joined tools that use
  unsigned LDAP (none in GOAD-Light).
- **12-DomainController**: MAQ=0 stops machine-account creation (RBCD-style abuse).
  Zerologon protection can reject ancient Netlogon clients - none in GOAD.
- **13-Gpo**: on GOAD DCs this kills Default Domain Policy enforcement - expected;
  watch `gpresult` and adcs/GPO-linked vulns losing effect.
- **15-SmbShares**: GOAD SRV02 has writable shares; downgrading to Read is the point.
  NETLOGON/SYSVOL are exempt by default. Null-session decoys are inert names.
- **16-Passwords**: gate keeps it out of `-All`; run it deliberately
  (`-ConfirmRotation`, plus `-DomainUsers` on DCs). krbtgt is always excluded -
  rotate krbtgt manually, ONCE (CPP's double-reset broke their 2023 domain).
- **19-AccessInsurance**: never runs under `-All`; explicit `-AcceptRisk` only.
- **21-ElasticAgent**: needs the ES server reachable from the lab/competition network
  BEFORE the first run. One-time setup: `copy scripts\files\elastic-config.example.json
  scripts\files\elastic-config.json`, fill in URL + password (file is gitignored).
  Then `-All` deploys the agent everywhere automatically. The Sysmon channel stream
  appears only on boxes where module 07 ran first (ordering handles this).
  In Kibana create a `logs-*` data view once (Stack Management -> Data Views) to see
  events in Discover. Pin the agent zip version to your stack's version (matched
  versions are the safe play; currently vendored: 9.5.4).

### What "gold snapshot" to keep

One Proxmox snapshot per VM after GOAD provisioning completes and the toolkit has been
copied on. That is the fastest loop: snapshot-revert -> preflight -> harden -> verify.

## 3. Competition-day order of operations

Derived from the researched winners (CPP 2023/24, BYU 2016, howtowinccdc):

1. **Read the team packet + rules first** (change freeze, scoring-engine IPs, password
   reporting format, anti-gamification clause). 10 minutes. Non-negotiable.
2. **Inventory every Windows box** (`Invoke-Inventory.ps1`); build the
   service-to-box mapping sheet. CPP called this sheet "literally gold."
3. **Preflight every box** (break-glass admin + backups) before anything else.
4. **`Invoke-Harden.ps1 -All`**, then `Invoke-Verify.ps1`. Fix any FAIL before moving on.
   (Rotation 16 and AccessInsurance 19 are gated; they run only when invoked deliberately.
   ElasticAgent 21 skips itself if elastic-config.json isn't filled in yet.)
5. **Logging first-class**: after agents check in, build the two dashboards that pay
   for themselves - failed logons by source IP (4625) and process creations with
   weird parents (Sysmon 1). CPP answered injects from exactly these at NCCDC 2024.
6. **Deliberate actions**: `16-Passwords.ps1 -ConfirmRotation` (one mass reset; report
   scored-service passwords as CSVs), krbtgt rotation ONCE by hand, optional
   `19-AccessInsurance.ps1 -AcceptRisk` as a team decision.
7. **Hunt on a cadence**: `Invoke-Hunt.ps1 -Hours 1` after every red-team alert;
   incident reports from these events recover points.
8. **Never**: block the scoring engine/CCSClient, firewall internal server<->workstation
   traffic, disable DNS, or reinstall to remediate (SLA bleed).

## 4. Dev notes (Linux side)

- `scripts/parse-check.ps1` and `scripts/lint-check.ps1` are dev-only validators
  (run with pwsh from repo root; lint expects PSScriptAnalyzer in `/tmp/psa`).
- Accepted lint warnings (by design): `Write-Host` (operator console + transcripts),
  `ConvertTo-SecureString` with plaintext (just-generated random passwords),
  empty catch blocks (best-effort sections), helper verb warnings (suppressed with
  documented attributes).
- Scripts target **Windows PowerShell 5.1** (Server 2019 default). Verified with
  `PSUseCompatibleSyntax` for 5.1.

## 5. Backlog (post-v1, in research-priority order)

1. AD credential hygiene: Kerberoast/AS-REP fixes, Protected Users migration,
   DCSync audit ACLs, gMSA for service accounts.
2. Windows Event Forwarding to a collector (DC01 in the lab).
3. Firewall allowlist builder that reads the inventory output and preserves
   scored-service paths.
4. Team-side post-processing (CPP postprocessing.ps1 equivalent): parse inventory
   reports across hosts into one service-to-box sheet.
5. Ansible wrapper (transport only): distribute + execute these exact scripts
   (replaces CPP's Run/Prop dispatch).
6. LGPO/SCT bulk-baseline module (LGPO.exe already vendored in `tools/`).

## 6. Manual deployment walk-through (tested live, 2026-10-02)

Proven end-to-end on Proxmox GOAD-Light (DC01/DC02/SRV02, all Server 2019) with a
ScoringEngine oracle: **21 modules per host, all 10 scored checks UP throughout,
including through a reboot and a full restore round-trip.**

### The flow that worked

1. **Jump box**: everything runs from the lab gateway LXC (192.168.56.1) over WinRM
   (5985) with the local admin account. A ~50-line pywinrm shim (`wr.py --host <ip>
   --user <u> --pass <p> --ps '<command>'`) is session tooling on the LXC - set
   BOTH `protocol` and `transport` read timeouts to 900 or long installs die at 30 s.
2. **Ship the toolkit**: zip scripts/+tools/, serve with `python3 -m http.server`
   on the LXC, per VM: `Invoke-WebRequest http://192.168.56.1:8000/toolkit.zip` +
   `Expand-Archive C:\Hardening\toolkit`. Script-only updates: a small
   scripts-update.zip to the same share (fast iteration loop).
3. **Per host**: `Invoke-Verify.ps1` (baseline) -> `Invoke-Preflight.ps1` (record the
   break-glass password!) -> `Invoke-Harden.ps1 -All` (~2 min/host) -> `Invoke-Verify.ps1`.
4. **On DCs, re-run 13-Gpo as the break-glass DOMAIN admin** (GPO flags need Domain
   Admins; the stock vagrant admin is only BUILTIN\Administrators).
5. **Elastic**: compose up ES+Kibana first, then drop `elastic-config.json` into
   `scripts/files/` and module 21 goes live under -All.

### Lab-proven timings (per host)

Modules 01-21 via -All: ~100-130 s (17-Php dominates at 60-120 s; it sweeps the
disk for php.exe and no-ops without PHP). Preflight ~30 s. Verify ~40 s.

### Findings that changed the modules (all fixed and re-proven)

- **RDP went dark when the firewall turned on** (GOAD NICs sit on the Public
  profile; the Remote Desktop rule group was disabled). 01-Firewall now enables
  the RDP + WinRM rule groups on all profiles.
- **LDAP scored check broke** with server-side signing=required (its ldapsearch
  does unsigned binds). 11-Ldap defaults DCs to negotiate (1); -StrictServerSigning
  opts into required (2).
- **GPO COM writes fail over WinRM** (E_ACCESSDENIED) - 13-Gpo flips the AD `flags`
  attribute via Set-ADObject instead (and needs a Domain Admin).
- **secedit export + DPAPI + GPMGMT all misbehave in WinRM session-0 logons** -
  all are best-effort with explicit warnings; registry backups cover restore.
- **WinRM stderr wrapping kills native installers** (Sysmon died mid-install on
  DCs): installers run via `cmd /c ... > file 2>&1` and the file is logged.
- **Stringy "False" booleans over WinRM** make `-not $x.Enabled` skip hardening:
  compare with `-eq`/string compare; Enable-NetFirewallRule used unconditionally.
- **Reboot test**: everything survives. Two effects to expect and brief the team on:
  - After reboot, `LocalAccountTokenFilterPolicy=0` (module 08, the PTH mitigation)
    strips remote-admin from non-built-in local accounts. Manage via the built-in
    Administrator (rotated password is in the CSV) or domain accounts. That is the
    mitigation working.
  - Rotating an account a service runs under breaks that service at next start
    (cloudbase-init in the lab) - 16-Passwords excludes well-known service
    identities and warns for the rest; check the inventory's service StartName
    column before rotating.

### Hardened-state evidence

- PingCastle (sevenkingdoms.local, post-hardening): GlobalScore 53, 1 remaining
  risk rule. OS/protocol hardening is done; the remaining exposure is the AD-side
  backlog (DACL/ESC remediation - see backlog).
- Locksmith audit (DC01): 22 AD CS template findings remain (ESC11/13/15 family) -
  same backlog, next phase of module work.
- Elastic: ~230k events within the first hours across Security/Sysmon/PowerShell/
  System channels from all three hosts; `logs-*` data view in Kibana.

### Scoreboard notes (lab oracle)

- The engine picks a RANDOM team account per check; in a multi-domain lab no pool
  account is valid everywhere. RDP/WinRM checks got a listener-level fallback
  (auth-first, protocol probe on credential miss) so they measure availability.
  Rounds run every 180 s - wait a full round before judging a change.
- After 16-Passwords, submit changed credentials the way CCDC rules require
  (CSV to ops / update the scoreboard accounts): monitors and the scoring engine
  both need the new values.
