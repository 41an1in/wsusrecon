# wsusrecon

wsusrecon is a read-only recon tool that answers one question from a low-privilege foothold: **is a rogue-WSUS attack feasible here?** Given a domain controller and any domain credential, it enumerates the WSUS configuration pushed via Group Policy and the population of clients steered to that WSUS server. If clients are pointed at an **HTTP** WSUS endpoint, an attacker who can MITM client↔server traffic can serve a forged signed update (pywsus/WSUSpect style) and get **SYSTEM-level code execution** on those clients.

wsusrecon only reads: it fetches files from SYSVOL over SMB and issues LDAP searches. It never exploits, writes to, or otherwise modifies any target.

## How it works

WSUS settings are computer-side GPO registry policy, stored on the DC in `SYSVOL\<domain>\Policies\{GPO-GUID}\Machine\Registry.pol` and applied to `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate` on clients. wsusrecon:

1. **SMB (impacket)** — logs in to the DC and downloads every `Machine\Registry.pol` from `SYSVOL\<domain>\Policies\{GUID}\` (GPOs without one are skipped silently).
2. **Registry.pol parser (pure Python, MS-GPSB)** — decodes the binary policy format (`PReg` header + UTF-16LE-delimited entries) with no dependencies.
3. **Verdict** — extracts the `WindowsUpdate` policy values (`WUServer`, `WUStatusServer`, `UpdateServiceUrlAlternate`, and `AU\UseWUServer`, `AUOptions`, `NoAutoUpdate`, `ScheduledInstallDay/Time`) and assesses each GPO.
4. **LDAP (ldap3)** — resolves each WSUS GPO's display name, finds which OUs / the domain root link it (`gPLink`, with disabled/enforced flags), and paged-searches computer objects under those containers — the potential WSUS client population.

## Installation

```bash
pip install -r requirements.txt
# or, isolated:
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
```

**Kali Linux:** both dependencies are packaged — no pip needed:

```bash
sudo apt install python3-impacket python3-ldap3
```

**pipx note:** pipx installs applications into isolated environments, so `pipx install impacket` does not make the library importable by a standalone script. Use a venv (or the Kali apt packages) instead; e.g. `pipx install --python python3 pipx`-style tricks won't help here — a venv is the right tool.

Requires Python 3.10+.

## Usage

```
wsusrecon.py -d corp.local --dc-ip 10.0.0.10 -u lowpriv [-p pass | -H LM:NT] [-k]
             [--no-clients] [--clients-out FILE] [-o report.json] [--max-clients N]
```

Password authentication:

```bash
./wsusrecon.py -d corp.local --dc-ip 10.0.0.10 -u lowpriv -p 'Passw0rd'
```

Pass-the-hash (`LM:NT` or `:NT`):

```bash
./wsusrecon.py -d corp.local --dc-ip 10.0.0.10 -u lowpriv -H ':31d6cfe0d16ae931b73c59d7e0c089c0'
```

Kerberos (uses the ccache in `KRB5CCNAME` for SMB; LDAP is attempted via ldap3 SASL/GSSAPI and skipped with a warning if the bind fails — re-run with `-p`/`-H` for full LDAP coverage):

```bash
./wsusrecon.py -d corp.local --dc-ip 10.0.0.10 -u lowpriv -k
```

Skip client enumeration (still resolves GPO display names and links), save the client list and a JSON report:

```bash
./wsusrecon.py -d corp.local --dc-ip 10.0.0.10 -u lowpriv -p 'Passw0rd' --clients-out wsus_clients.txt -o report.json
./wsusrecon.py -d corp.local --dc-ip 10.0.0.10 -u lowpriv -p 'Passw0rd' --no-clients
```

Options: `-d/--domain`, `--dc-ip`, `-u/--username` (required); `-p/--password`, `-H/--hashes`, `-k/--kerberos` (exactly one form of auth material required); `--no-clients`, `--clients-out FILE`, `-o/--output FILE` (JSON report), `--max-clients N` (default 5000).

## Output

One section per GPO that carries WSUS settings:

```
=== WSUS Settings {6AC1786C-016F-11D2-945F-00C04FB984F9} ===
  WUServer (REG_SZ) = http://wsus.corp.local:8530
  WUStatusServer (REG_SZ) = http://wsus.corp.local:8530
  AU\UseWUServer (REG_DWORD) = 1
  AU\AUOptions (REG_DWORD) = 3
  verdict: VULNERABLE — WSUS over HTTP — if you can MITM client<->server traffic, rogue-update attack (pywsus) gives SYSTEM on clients
  WUServer host wsus.corp.local: 10.0.0.5; port 8530 (default WSUS port)
  links:
    OU=Workstations,DC=corp,DC=local (enforced)
    DC=corp,DC=local (link disabled — GPO not applied here; domain root — applies domain-wide)
  clients: 42 (potential population — security filtering / WMI filters not evaluated)
    ws01.corp.local — Windows 10 Enterprise
    ...

summary: 12 GPO(s) scanned, 1 with WSUS settings, 42 unique clients
```

- **verdict** (red when VULNERABLE on a tty):
  - `VULNERABLE` — `UseWUServer=1` and `WUServer` is `http://…`: the rogue-WSUS precondition holds; exploitation still needs a MITM position on client↔WSUS traffic.
  - `OK` — WSUS over HTTPS: MITM is not practical without a trusted certificate.
  - `ANOMALY` — `UseWUServer=1` but no `WUServer` URL in this GPO (the URL may come from another GPO; precedence is not computed).
  - `INFO` — WSUS-related values present but clients are not steered by this GPO alone.
- **WUServer host** — best-effort DNS resolution from the machine running wsusrecon (helps MITM positioning). URLs without an explicit port mean the WSUS defaults: **8530 (HTTP) / 8531 (HTTPS)**.
- **links** — every OU / domain root whose `gPLink` references the GPO, with the link flags: `link disabled` (GPO not applied there) and `enforced`. A link at the domain root applies domain-wide.
- **clients** — computer objects under the linked containers, deduplicated across GPOs/containers; first 20 shown. This is the *potential* population: GPO security filtering and WMI filters are not evaluated.
- **errors** — non-fatal problems (fetch/parse/LDAP failures) collected during the run; they never abort it.

`--clients-out` writes unique client names one per line (`dNSHostName`, falling back to `sAMAccountName`). `-o` writes the full JSON report: `{dc, domain, scanned_gpos, gpos: [{guid, name, settings, verdict, verdict_detail, links: [{dn, disabled, enforced}], clients: [{name, sam, os}]}], errors: []}`.

## Limitations

- **Feasibility, not proof.** `VULNERABLE` means the precondition (HTTP WSUS + clients directed to it) exists; you still need a MITM position, and hardened clients may add friction. wsusrecon never exploits anything.
- **Machine policy only.** Only `Machine\Registry.pol` is parsed (WSUS settings are computer-side). Group Policy Preferences registry items (`Registry.xml`) are not parsed.
- **No GPO precedence.** GPO merging, LSDOU order, block inheritance, and conflicts between multiple GPOs are not resolved — settings are reported per GPO as found.
- **No security/WMI filtering.** The client list is every computer under the linked containers — the potential population, not the exact resultant set.
- **LDAP fidelity.** Password binds are full-fidelity; pass-the-hash is best-effort (full `LM:NT` then NT-only are tried); `-k` needs a working ldap3 GSSAPI setup and often fails against a bare IP — re-run with `-p`/`-H` for LDAP.
- **DNS is resolved from your machine**, not from the target's perspective; split-horizon DNS may give different answers.
- Kerberos for SMB works best when the DC hostname resolves; with `-k` and only an IP, impacket may fail to build the service ticket.
