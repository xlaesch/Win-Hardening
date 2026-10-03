# Win-Hardening

> Windows hardening toolkit for CCDC (Collegiate Cyber Defense Competition) blue teams.
> Simple, standalone PowerShell 5.1 scripts - proven against a GOAD-Light lab - designed
> to be Ansible-wrappable later (parameterized, idempotent, clean exit codes).

Built from research into how top-placing CCDC teams (BYU 2016 runner-up, Cal Poly
Pomona 2023/24 runner-up, UVA's BLUESPAWN, and the community knowledge base at
[mubix/howtowinccdc](https://github.com/mubix/howtowinccdc)) actually hardened Windows.
See [docs/research-writeup.md](docs/research-writeup.md) for findings and sources.

## Design rules

1. **Inventory before you touch.** Modeled on Cal Poly Pomona's first-script
   Inventory.ps1 (national runner-up 2023/24): know users, shares, services, tasks,
   IIS bindings before changing anything.
2. **Never break scored services.** Over-hardening is penalized in CCDC; every module
   is chosen to be safe on a live business network.
3. **Every change is reversible.** `Invoke-Preflight.ps1` backs up state before anything
   runs; `Invoke-Restore.ps1` undoes every change from those backups.
4. **Lockout guard first.** A fresh admin account is created before any
   credential-adjacent work so the team never loses access to its own box.
5. **One file, one concern.** Plain PowerShell 5.1, no modules to install, runs
   standalone on any Windows Server 2016+ box.
6. **Idempotent.** Re-running a module is always safe; it verifies current state first
   and only changes what differs.

## Layout

```
scripts/
├── lib/common.ps1              # shared helpers: logging, backups, check-then-set
├── Invoke-Inventory.ps1        # run FIRST: read-only recon (CPP template)
├── Invoke-Preflight.ps1        # break-glass admin + full state backups
├── Invoke-Harden.ps1           # master runner: -All or -Modules Firewall,SmbNtlm,...
├── Invoke-Hunt.ps1             # webshell + event hunting (7045/4742/5140, Defender)
├── Invoke-Restore.ps1          # inverse of everything, from preflight backups
├── Invoke-Verify.ps1           # service sanity checks (DNS/AD/IIS/MSSQL/WinRM)
├── modules/
│   ├── 01-Firewall.ps1         # firewall ON all profiles (existing rules untouched)
│   ├── 02-SmbNtlm.ps1          # SMBv1 off, NTLMv2-only, no LM hash, SMB signing
│   ├── 03-Lsass.ps1            # WDigest off, LSASS RunAsPPL + audit
│   ├── 04-Defender.ps1         # Defender ON, tamper, 15 ASR rules, policy keys
│   ├── 05-Audit.ps1            # advanced audit policy (-Full = all categories)
│   ├── 06-NameResolution.ps1   # LLMNR / NBT-NS off (anti-Responder)
│   ├── 07-Sysmon.ps1           # Sysmon install + SwiftOnSecurity config
│   ├── 08-Uac.ps1              # full UAC + LocalAccountTokenFilterPolicy
│   ├── 09-RdpNla.ps1           # RDP NLA required
│   ├── 10-Services.ps1         # spooler/PrintNightmare/BITS
│   ├── 11-Ldap.ps1             # LDAP signing (client + server on DCs)
│   ├── 12-DomainController.ps1 # Zerologon + noPac (DC-only)
│   ├── 13-Gpo.ps1              # disable GPOs (DC) / reset local GPO cache
│   ├── 14-PsLogging.ps1        # script-block, module, transcription logging
│   ├── 15-SmbShares.ps1        # shares read-only + null-session decoys
│   ├── 16-Passwords.ps1        # bulk rotation (-ConfirmRotation gated)
│   ├── 17-Php.ps1              # disable dangerous PHP functions
│   ├── 18-Iis.ps1              # IIS request logging on
│   ├── 19-AccessInsurance.ps1  # emergency access console (-AcceptRisk gated)
│   ├── 20-FixExplorer.ps1      # show hidden files/extensions/OS files
│   └── 21-ElasticAgent.ps1     # central logging -> Elasticsearch (offline zip)
├── parse-check.ps1             # dev-only: syntax validation
└── lint-check.ps1              # dev-only: PSScriptAnalyzer (PS 5.1 compat)
tools/                          # PingCastle, Locksmith, BLUESPAWN, SCT/LGPO, sysinternals,
                                #   elastic/ (Elastic Agent 9.5.4 zip + sha512)
docs/                           # research writeup, runbook (incl. CPP parity map)
```

### Central logging (module 21)

One-time: `copy scripts\files\elastic-config.example.json scripts\files\elastic-config.json`
and fill in your Elasticsearch URL + password (the real file is gitignored). After that,
`Invoke-Harden.ps1 -All` deploys the vendored Elastic Agent (offline, sha512-verified)
on every box, shipping Security/Sysmon/PowerShell logs + system metrics to Kibana.

Full Cal Poly Pomona parity map (every hardening in their `Windows/` folder → our
module) lives in [docs/runbook.md](docs/runbook.md).

## Quick start (per host, as Administrator)

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force

.\Invoke-Inventory.ps1                  # 1. know the box (read-only)
.\Invoke-Preflight.ps1                  # 2. break-glass admin + backups (run once per box)
.\Invoke-Harden.ps1 -All                # 3. harden (or -Modules Firewall,Defender; -WhatIf previews)
.\Invoke-Verify.ps1                     # 4. prove services survived

.\Invoke-Restore.ps1                    # if anything went wrong
```

Everything lands under `C:\HardeningBackups\<timestamp>\` (backups, change log,
transcripts). See [docs/runbook.md](docs/runbook.md) for the lab test loop,
module-by-module notes, and competition-day order of operations.

## Lab

Tested against [GOAD-Light](https://orange-cyberdefense.github.io/GOAD/labs/GOAD-Light/)
running on the team's Proxmox server (3x Windows Server 2019: two DCs in a parent/child
domain + one IIS/MSSQL member server). The lab's planted weaknesses (firewall off,
LLMNR on, NTLM downgrade, Defender off) map directly to modules 01/02/04/06.
