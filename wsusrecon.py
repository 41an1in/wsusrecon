#!/usr/bin/env python3
import argparse
import io
import json
import re
import socket
import struct
import sys

WU_KEY = r"Software\Policies\Microsoft\Windows\WindowsUpdate"
AU_KEY = WU_KEY + r"\AU"
BASE_VALUE_NAMES = {"wuserver", "wustatusserver", "updateserviceurlalternate"}
AU_VALUE_NAMES = {"usewuserver", "auoptions", "noautoupdate", "scheduledinstallday", "scheduledinstalltime"}
REG_TYPE_NAMES = {
    1: "REG_SZ",
    2: "REG_EXPAND_SZ",
    3: "REG_BINARY",
    4: "REG_DWORD",
    5: "REG_DWORD_BIG_ENDIAN",
    6: "REG_LINK",
    7: "REG_MULTI_SZ",
    11: "REG_QWORD",
}
GUID_RE = re.compile(r"^\{[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\}$")
GPLINK_RE = re.compile(r"LDAP://CN=(\{[^}]+\}),[^;\]]*;(\d+)", re.IGNORECASE)
URL_RE = re.compile(r"^(https?)://([^/:]+)(?::(\d+))?", re.IGNORECASE)
CLIENT_SHOW = 20
RED, GREEN, YELLOW, GREY, RESET = "\033[31m", "\033[32m", "\033[33m", "\033[90m", "\033[0m"


class PolParseError(ValueError):
    pass


def _utf16z(buf, pos):
    start = pos
    while pos + 2 <= len(buf):
        if buf[pos:pos + 2] == b"\x00\x00":
            return buf[start:pos].decode("utf-16-le", errors="replace"), pos + 2
        pos += 2
    raise PolParseError(f"unterminated string at offset {start}")


def _expect(buf, pos, delim):
    if buf[pos:pos + 2] != delim:
        raise PolParseError(f"malformed entry at offset {pos}")
    return pos + 2


def _take(buf, pos, n):
    if pos + n > len(buf):
        raise PolParseError(f"truncated entry at offset {pos}")
    return buf[pos:pos + n], pos + n


def decode_reg_value(vtype, raw):
    if vtype in (1, 2):
        return raw.decode("utf-16-le", errors="replace").rstrip("\x00")
    if vtype == 4 and len(raw) == 4:
        return struct.unpack("<I", raw)[0]
    if vtype == 7:
        return [s for s in raw.decode("utf-16-le", errors="replace").split("\x00") if s]
    if vtype == 11 and len(raw) == 8:
        return struct.unpack("<Q", raw)[0]
    return raw.hex()


def parse_registry_pol(data):
    if len(data) < 8 or data[:4] != b"PReg":
        raise PolParseError("bad signature: not a Registry.pol file")
    version = struct.unpack_from("<I", data, 4)[0]
    if version != 1:
        raise PolParseError(f"unsupported Registry.pol version {version}")
    entries = []
    pos = 8
    while pos + 2 <= len(data):
        if data[pos:pos + 2] != b"[\x00":
            break  # tolerate trailing garbage
        pos += 2
        key, pos = _utf16z(data, pos)
        pos = _expect(data, pos, b";\x00")
        value, pos = _utf16z(data, pos)
        pos = _expect(data, pos, b";\x00")
        raw, pos = _take(data, pos, 4)
        vtype = struct.unpack("<I", raw)[0]
        pos = _expect(data, pos, b";\x00")
        raw, pos = _take(data, pos, 4)
        size = struct.unpack("<I", raw)[0]
        pos = _expect(data, pos, b";\x00")
        raw, pos = _take(data, pos, size)
        pos = _expect(data, pos, b"]\x00")
        entries.append({"key": key, "value": value, "type": vtype, "data": decode_reg_value(vtype, raw)})
    return entries


def is_wsus_entry(entry):
    key = entry["key"].lower().rstrip("\\")
    return key == WU_KEY.lower() or key.startswith(WU_KEY.lower() + "\\")


def value_label(entry):
    key = entry["key"].lower().rstrip("\\")
    if key == WU_KEY.lower():
        return entry["value"]
    if key == AU_KEY.lower():
        return "AU\\" + entry["value"]
    return entry["key"] + "\\" + entry["value"]


def collect_settings(entries):
    settings = {}
    for entry in entries:
        key = entry["key"].lower().rstrip("\\")
        name = entry["value"].lower()
        if key == WU_KEY.lower() and name in BASE_VALUE_NAMES:
            settings[name] = entry["data"]
        elif key == AU_KEY.lower() and name in AU_VALUE_NAMES:
            settings[name] = entry["data"]
    return settings


def assess(settings):
    use = settings.get("usewuserver")
    enabled = use == 1 or (isinstance(use, str) and use.strip() == "1")
    url = settings.get("wuserver")
    if enabled:
        if isinstance(url, str) and url.lower().startswith("http://"):
            return "VULNERABLE", ("WSUS over HTTP — if you can MITM client<->server traffic, "
                                  "rogue-update attack (pywsus) gives SYSTEM on clients")
        if isinstance(url, str) and url.lower().startswith("https://"):
            return "OK", "WSUS over HTTPS — MITM not practical without trusted cert"
        return "ANOMALY", "UseWUServer=1 but no WUServer URL in this GPO — the URL may be pushed by another GPO"
    if isinstance(url, str) and url:
        return "INFO", "WUServer is set but UseWUServer is not 1 — clients are not steered to WSUS by this GPO alone"
    return "INFO", "WSUS-related settings present, but no UseWUServer=1 / WUServer pair"


def resolve_url(url):
    m = URL_RE.match(url.strip())
    if not m:
        return None
    ips = []
    try:
        ips = sorted({info[4][0] for info in socket.getaddrinfo(m.group(2), None)})
    except socket.gaierror:
        pass
    return {"host": m.group(2), "port": int(m.group(3)) if m.group(3) else None, "ips": ips}


def split_hashes(hashes):
    parts = hashes.split(":", 1)
    if len(parts) == 2:
        return parts[0], parts[1]
    return "", hashes


def die(message):
    print(f"error: {message}", file=sys.stderr)
    sys.exit(1)


def smb_connect(args):
    try:
        from impacket.smbconnection import SMBConnection
    except ImportError:
        die("impacket is not installed; install it with: pip install impacket"
            "  (Kali: sudo apt install python3-impacket)")
    lmhash, nthash = split_hashes(args.hashes) if args.hashes else ("", "")
    try:
        conn = SMBConnection(args.dc_ip, args.dc_ip)
        if args.kerberos:
            conn.kerberosLogin(args.username, args.password or "", args.domain,
                               lmhash, nthash, kdcHost=args.dc_ip)
        else:
            conn.login(args.username, args.password or "", args.domain, lmhash, nthash)
    except Exception as e:
        die(f"SMB login on {args.dc_ip} failed: {e}")
    return conn


def sysvol_domain_dir(conn, domain):
    try:
        conn.listPath("SYSVOL", f"/{domain}/*")
        return domain
    except Exception:
        pass
    for entry in conn.listPath("SYSVOL", "/*"):
        name = entry.get_longname()
        if entry.is_directory() and name.lower() == domain.lower():
            return name
    raise RuntimeError(f"no directory matching '{domain}' found under SYSVOL")


def fetch_machine_pol(conn, sysvol_dir, guid, errors):
    buf = io.BytesIO()
    try:
        conn.getFile("SYSVOL", f"/{sysvol_dir}/Policies/{guid}/Machine/Registry.pol", buf.write)
    except Exception as e:
        text = str(e)
        if any(s in text for s in ("STATUS_OBJECT_NAME_NOT_FOUND", "STATUS_OBJECT_PATH_NOT_FOUND",
                                   "STATUS_NO_SUCH_FILE")):
            return None  # most GPOs have no Machine\Registry.pol
        errors.append(f"{guid}: failed to fetch Machine\\Registry.pol: {e}")
        return None
    return buf.getvalue()


def ldap_connect(args, errors):
    try:
        import ldap3
    except ImportError:
        errors.append("ldap3 is not installed; skipping LDAP enumeration. Install with: pip install ldap3"
                      "  (Kali: sudo apt install python3-ldap3)")
        return None
    server = ldap3.Server(args.dc_ip, port=389)
    if args.kerberos:
        try:
            return ldap3.Connection(server, authentication=ldap3.SASL,
                                    sasl_mechanism=ldap3.GSSAPI, auto_bind=True)
        except Exception as e:
            errors.append(f"LDAP kerberos (GSSAPI) bind failed: {e}. ldap3 kerberos needs working gssapi "
                          "plus a ccache; re-run with -p or -H for LDAP. Skipping LDAP enumeration.")
            return None
    candidates = []
    if args.password is not None:
        candidates.append(args.password)
    if args.hashes:
        candidates.append(args.hashes)
        candidates.append(args.hashes.split(":")[-1])
    for candidate in candidates:
        try:
            return ldap3.Connection(server, user=f"{args.domain}\\{args.username}", password=candidate,
                                    authentication=ldap3.NTLM, auto_bind=True)
        except Exception:
            continue
    errors.append("LDAP bind failed with password/hash — skipping LDAP enumeration "
                  "(GPO names, links, clients)")
    return None


def _first(value):
    if value is None:
        return ""
    if isinstance(value, list):
        return str(value[0]) if value else ""
    return str(value)


def ldap_gpo_names(ldap, base_dn, errors):
    names = {}
    try:
        ldap.search(f"CN=Policies,CN=System,{base_dn}", "(objectClass=groupPolicyContainer)",
                    attributes=["name", "displayName"])
        for entry in ldap.entries:
            attrs = entry.entry_attributes_as_dict
            name = _first(attrs.get("name"))
            if name:
                names[name.lower()] = _first(attrs.get("displayName"))
    except Exception as e:
        errors.append(f"LDAP GPO name lookup failed: {e}")
    return names


def ldap_gplinks(ldap, base_dn, errors):
    links = []
    try:
        ldap.search(base_dn, "(&(|(objectClass=organizationalUnit)(objectClass=domainDNS))(gPLink=*))",
                    search_scope="SUBTREE", attributes=["gPLink"])
        for entry in ldap.entries:
            gplink = "".join(str(v) for v in entry.entry_attributes_as_dict.get("gPLink", []))
            links.append({"dn": entry.entry_dn, "gplink": gplink})
    except Exception as e:
        errors.append(f"LDAP gPLink search failed: {e}")
    return links


def link_flags(gplink, guid):
    for m in GPLINK_RE.finditer(gplink):
        if m.group(1).lower() == guid.lower():
            return int(m.group(2))
    return None


def enum_clients(ldap, dn, limit, errors):
    clients = []
    try:
        results = ldap.extend.standard.paged_search(
            search_base=dn,
            search_filter="(objectClass=computer)",
            search_scope="SUBTREE",
            attributes=["dNSHostName", "sAMAccountName", "operatingSystem"],
            paged_size=500,
            generator=True,
        )
        for item in results:
            if item.get("type") != "searchResEntry":
                continue
            attrs = item["attributes"]
            sam = _first(attrs.get("sAMAccountName"))
            dns = _first(attrs.get("dNSHostName"))
            if not sam and not dns:
                continue
            clients.append({"name": dns or sam, "sam": sam,
                            "os": _first(attrs.get("operatingSystem"))})
            if len(clients) >= limit:
                break
    except Exception as e:
        errors.append(f"client search under {dn} failed: {e}")
    return clients


def print_gpo(g, base_dn):
    label = f"{g['name']} " if g["name"] else ""
    print(f"\n=== {label}{g['guid']} ===")
    for entry in g["entries"]:
        tname = REG_TYPE_NAMES.get(entry["type"], f"REG_TYPE_{entry['type']}")
        data = entry["data"]
        if isinstance(data, list):
            data = ", ".join(data)
        print(f"  {value_label(entry)} ({tname}) = {data}")
    color = {"VULNERABLE": RED, "OK": GREEN, "ANOMALY": YELLOW}.get(g["verdict"], GREY)
    if sys.stdout.isatty():
        print(f"  verdict: {color}{g['verdict']}{RESET} — {g['detail']}")
    else:
        print(f"  verdict: {g['verdict']} — {g['detail']}")
    url = g["settings"].get("wuserver")
    if isinstance(url, str) and url:
        info = resolve_url(url)
        if info:
            port = info["port"]
            if port is None:
                port_note = "no explicit port — WSUS defaults: 8530 (HTTP) / 8531 (HTTPS)"
            elif port in (8530, 8531):
                port_note = f"port {port} (default WSUS port)"
            else:
                port_note = f"port {port} (non-standard)"
            ips = ", ".join(info["ips"]) if info["ips"] else "resolution failed (from this host)"
            print(f"  WUServer host {info['host']}: {ips}; {port_note}")
    if not g["links"]:
        print("  links: none found (or LDAP unavailable)")
    else:
        print("  links:")
        for link in g["links"]:
            states = []
            if link["disabled"]:
                states.append("link disabled — GPO not applied here")
            if link["enforced"]:
                states.append("enforced")
            if link["dn"].lower() == base_dn.lower():
                states.append("domain root — applies domain-wide")
            suffix = f" ({'; '.join(states)})" if states else ""
            print(f"    {link['dn']}{suffix}")
    if g["clients"]:
        print(f"  clients: {len(g['clients'])} (potential population — "
              "security filtering / WMI filters not evaluated)")
        for client in g["clients"][:CLIENT_SHOW]:
            os_note = f" — {client['os']}" if client["os"] else ""
            print(f"    {client['name']}{os_note}")
        if len(g["clients"]) > CLIENT_SHOW:
            print(f"    ... and {len(g['clients']) - CLIENT_SHOW} more")


def build_parser():
    parser = argparse.ArgumentParser(
        prog="wsusrecon",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Read-only WSUS recon: pull Machine\\Registry.pol files from SYSVOL, extract "
                    "WindowsUpdate GPO settings, and enumerate the WSUS client population via LDAP — "
                    "to assess whether a rogue-WSUS attack (pywsus/WSUSpect) is feasible.",
        epilog="examples:\n"
               "  wsusrecon.py -d corp.local --dc-ip 10.0.0.10 -u lowpriv -p 'Passw0rd'\n"
               "  wsusrecon.py -d corp.local --dc-ip 10.0.0.10 -u lowpriv -H ':31d6cfe0d16ae931b73c59d7e0c089c0'\n"
               "  wsusrecon.py -d corp.local --dc-ip 10.0.0.10 -u lowpriv -k --no-clients -o report.json\n",
    )
    parser.add_argument("-d", "--domain", required=True, help="AD domain, e.g. corp.local")
    parser.add_argument("--dc-ip", dest="dc_ip", required=True, help="domain controller IP")
    parser.add_argument("-u", "--username", required=True, help="low-privilege domain username")
    parser.add_argument("-p", "--password", default=None, help="password for the user")
    parser.add_argument("-H", "--hashes", default="", help="NTLM hashes, LM:NT or :NT")
    parser.add_argument("-k", "--kerberos", action="store_true",
                        help="use Kerberos (ccache via KRB5CCNAME for SMB; ldap3 GSSAPI attempted for LDAP)")
    parser.add_argument("--no-clients", dest="no_clients", action="store_true",
                        help="skip computer-object enumeration (GPO names and links are still resolved)")
    parser.add_argument("--clients-out", dest="clients_out", default=None, metavar="FILE",
                        help="write unique client names (dNSHostName, fallback sAMAccountName) to FILE")
    parser.add_argument("-o", "--output", default=None, metavar="FILE", help="write full JSON report to FILE")
    parser.add_argument("--max-clients", dest="max_clients", type=int, default=5000,
                        help="cap on enumerated clients (default: 5000)")
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.password is None and not args.hashes and not args.kerberos:
        parser.error("one of -p/--password, -H/--hashes, or -k/--kerberos is required")
    if args.max_clients < 1:
        parser.error("--max-clients must be >= 1")
    errors = []
    conn = smb_connect(args)
    try:
        try:
            sysvol_dir = sysvol_domain_dir(conn, args.domain)
            pol_entries = conn.listPath("SYSVOL", f"/{sysvol_dir}/Policies/*")
        except Exception as e:
            die(f"failed to enumerate SYSVOL Policies on {args.dc_ip}: {e}")
        guids = sorted(e.get_longname() for e in pol_entries
                       if e.is_directory() and GUID_RE.match(e.get_longname() or ""))
        print(f"[+] {args.dc_ip}: SYSVOL\\{sysvol_dir}\\Policies contains {len(guids)} GPO(s)")
        gpos = []
        for guid in guids:
            data = fetch_machine_pol(conn, sysvol_dir, guid, errors)
            if data is None:
                continue
            try:
                parsed = parse_registry_pol(data)
            except PolParseError as e:
                errors.append(f"{guid}: failed to parse Registry.pol: {e}")
                continue
            wsus_entries = [e for e in parsed if is_wsus_entry(e)]
            if not wsus_entries:
                continue
            settings = collect_settings(wsus_entries)
            verdict, detail = assess(settings)
            gpos.append({"guid": guid, "name": "", "entries": wsus_entries, "settings": settings,
                         "verdict": verdict, "detail": detail, "links": [], "clients": []})
    finally:
        try:
            conn.logoff()
        except Exception:
            pass

    base_dn = ",".join(f"DC={part}" for part in args.domain.split(".") if part)
    ldap = ldap_connect(args, errors)
    truncated = False
    if ldap is None:
        if gpos:
            print("[!] LDAP unavailable — GPO display names, links, and client enumeration skipped")
    else:
        print(f"[+] LDAP bound on {args.dc_ip}: resolving GPO names, links"
              + ("" if args.no_clients else ", and clients"))
        names = ldap_gpo_names(ldap, base_dn, errors)
        links = ldap_gplinks(ldap, base_dn, errors)
        seen = {}
        for g in gpos:
            g["name"] = names.get(g["guid"].lower(), "")
            for link in links:
                flags = link_flags(link["gplink"], g["guid"])
                if flags is not None:
                    g["links"].append({"dn": link["dn"], "disabled": bool(flags & 1),
                                       "enforced": bool(flags & 2)})
        if not args.no_clients:
            total = 0
            for g in gpos:
                for link in g["links"]:
                    if total >= args.max_clients:
                        truncated = True
                        break
                    for client in enum_clients(ldap, link["dn"], args.max_clients - total, errors):
                        key = (client["sam"] or client["name"]).lower()
                        if key in seen:
                            continue
                        seen[key] = client
                        g["clients"].append(client)
                        total += 1
                if truncated:
                    break
        try:
            ldap.unbind()
        except Exception:
            pass

    unique_clients = {}
    for g in gpos:
        print_gpo(g, base_dn)
        for client in g["clients"]:
            unique_clients[(client["sam"] or client["name"]).lower()] = client

    if not gpos:
        print("\nno WSUS GPO settings found in SYSVOL")
    if args.no_clients:
        client_note = ", clients not enumerated (--no-clients)"
    elif ldap is None:
        client_note = ", clients not enumerated (LDAP unavailable)"
    else:
        client_note = f", {len(unique_clients)} unique clients"
        if truncated:
            client_note += f" (truncated at --max-clients {args.max_clients})"
    print(f"\nsummary: {len(guids)} GPO(s) scanned, {len(gpos)} with WSUS settings{client_note}")

    if args.clients_out:
        out_names = sorted(c["name"] for c in unique_clients.values())
        try:
            with open(args.clients_out, "w") as fh:
                fh.write("".join(n + "\n" for n in out_names))
            print(f"[+] wrote {len(out_names)} client name(s) to {args.clients_out}")
        except OSError as e:
            errors.append(f"failed to write {args.clients_out}: {e}")

    if args.output:
        report = {
            "dc": args.dc_ip,
            "domain": args.domain,
            "scanned_gpos": len(guids),
            "gpos": [
                {
                    "guid": g["guid"],
                    "name": g["name"],
                    "settings": {value_label(e): e["data"] for e in g["entries"]},
                    "verdict": g["verdict"],
                    "verdict_detail": g["detail"],
                    "links": g["links"],
                    "clients": g["clients"],
                }
                for g in gpos
            ],
            "errors": errors,
        }
        try:
            with open(args.output, "w") as fh:
                json.dump(report, fh, indent=2)
            print(f"[+] wrote JSON report to {args.output}")
        except OSError as e:
            errors.append(f"failed to write {args.output}: {e}")

    if errors:
        print(f"\nerrors ({len(errors)}):")
        for error in errors:
            print(f"  - {error}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
