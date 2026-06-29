#!/usr/bin/env python3

import argparse
import datetime as dt
import ipaddress
import json
import os
import random
import shutil
import subprocess
import sys
import time
import uuid
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple


USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
]


def now_utc_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def log(level: str, msg: str) -> None:
    ts = dt.datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] [{level}] {msg}")


def _go_bin_dirs() -> List[str]:
    dirs: List[str] = []
    gobin = os.environ.get("GOBIN")
    if gobin:
        dirs.append(gobin)
    gopath = os.environ.get("GOPATH")
    if gopath:
        dirs.append(os.path.join(gopath, "bin"))
    dirs.append(os.path.expanduser("~/go/bin"))
    return dirs


def resolve_executable(name: str) -> Optional[str]:
    """Resolve a CLI tool path. On Ubuntu, Go installs often land in ~/go/bin, which cron/systemd may omit from PATH."""
    found = shutil.which(name)
    if found:
        return found
    extra = os.environ.get("RECON_TOOL_PATH", "")
    search_dirs: List[str] = []
    for part in extra.split(os.pathsep):
        p = part.strip()
        if p:
            search_dirs.append(p)
    search_dirs.extend(_go_bin_dirs())
    search_dirs.append("/usr/local/bin")
    for d in search_dirs:
        candidate = os.path.join(d, name)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


def tool_exists(name: str) -> bool:
    return resolve_executable(name) is not None


def safe_mkdir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def write_text_lines(path: str, lines: Iterable[str]) -> None:
    safe_mkdir(os.path.dirname(path))
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        for line in lines:
            line = line.strip()
            if line:
                f.write(line + "\n")


def write_json(path: str, obj: Any) -> None:
    safe_mkdir(os.path.dirname(path))
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)


def read_text_lines(path: str) -> List[str]:
    if not os.path.exists(path) or os.path.getsize(path) == 0:
        return []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return [line.strip() for line in f if line.strip()]


def dedupe_sorted(items: Iterable[str]) -> List[str]:
    return sorted({i.strip() for i in items if i and i.strip()})


class CommandRunner:
    def __init__(self, timeout_s: int = 900, quiet_stderr: bool = True):
        self.timeout_s = timeout_s
        self.quiet_stderr = quiet_stderr

    def run(
        self,
        cmd: Sequence[str],
        *,
        stdout_path: Optional[str] = None,
        stdin_text: Optional[str] = None,
        env_extra: Optional[Dict[str, str]] = None,
        retries: int = 1,
        retry_backoff_s: float = 1.5,
        delay_s: float = 0.0,
        allow_fail: bool = False,
    ) -> bool:
        if delay_s > 0:
            time.sleep(delay_s)

        env = os.environ.copy()
        if env_extra:
            env.update(env_extra)

        for attempt in range(retries):
            try:
                log("INFO", f"Running: {' '.join(cmd)}")
                stdout_handle = None
                stderr_handle = subprocess.DEVNULL if self.quiet_stderr else None
                if stdout_path:
                    safe_mkdir(os.path.dirname(stdout_path))
                    stdout_handle = open(stdout_path, "w", encoding="utf-8", newline="\n")
                p = subprocess.run(
                    list(cmd),
                    input=stdin_text,
                    text=True,
                    env=env,
                    stdout=stdout_handle if stdout_handle else subprocess.DEVNULL,
                    stderr=stderr_handle,
                    timeout=self.timeout_s,
                    check=True,
                )
                if stdout_handle:
                    stdout_handle.close()
                return True
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError) as e:
                if "FileNotFoundError" in type(e).__name__:
                    log("ERROR", f"Tool not found: {cmd[0]}")
                    return False
                log("WARNING", f"Command failed (attempt {attempt + 1}/{retries}): {e}")
                if attempt < retries - 1:
                    time.sleep(retry_backoff_s ** attempt)

        if allow_fail:
            return False
        return False


@dataclass
class ScanMeta:
    scan_id: str
    target: str
    started_at_utc: str
    finished_at_utc: Optional[str] = None
    output_dir: str = ""
    script: str = "SuperReconn.py"
    script_version: str = "1.0.0"
    args: Dict[str, Any] = field(default_factory=dict)
    tools: Dict[str, bool] = field(default_factory=dict)


@dataclass
class DNSRecord:
    name: str
    rtype: str
    value: str
    ttl: Optional[int] = None


@dataclass
class HttpService:
    url: str
    host: str
    port: Optional[int] = None
    scheme: Optional[str] = None
    status_code: Optional[int] = None
    title: Optional[str] = None
    technologies: List[str] = field(default_factory=list)
    server: Optional[str] = None
    ip: Optional[str] = None
    cname: Optional[str] = None
    raw: Dict[str, Any] = field(default_factory=dict)


@dataclass
class NetworkService:
    ip: str
    port: int
    protocol: str
    state: str
    service_name: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    extrainfo: Optional[str] = None
    cpe: List[str] = field(default_factory=list)


@dataclass
class Finding:
    category: str  # nuclei/gf/waf/takeover/other
    source: str  # tool name or template id
    severity: Optional[str] = None
    target: Optional[str] = None  # url or hostname or ip:port
    title: Optional[str] = None
    raw: Dict[str, Any] = field(default_factory=dict)


def normalize_domain(s: str) -> str:
    s = (s or "").strip()
    if not s:
        return s
    s = s.rstrip(".")
    return s.lower()


def normalize_ip(s: str) -> Optional[str]:
    s = (s or "").strip()
    if not s:
        return None
    try:
        return str(ipaddress.ip_address(s))
    except ValueError:
        return None


def parse_massdns_stdout(lines: Iterable[str]) -> Tuple[Set[str], Set[str], List[DNSRecord]]:
    domains: Set[str] = set()
    ips: Set[str] = set()
    records: List[DNSRecord] = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        # Example: sub.example.com. A 1.2.3.4
        parts = line.split()
        if len(parts) < 3:
            continue
        name = normalize_domain(parts[0])
        rtype = parts[1].upper()
        value = parts[2].strip()
        if not name:
            continue
        domains.add(name)
        if rtype == "A":
            ip = normalize_ip(value)
            if ip:
                ips.add(ip)
                records.append(DNSRecord(name=name, rtype="A", value=ip))
        elif rtype in {"AAAA", "CNAME", "TXT", "NS", "MX"}:
            records.append(DNSRecord(name=name, rtype=rtype, value=value.rstrip(".")))
    return domains, ips, records


def run_massdns_resolve(runner: CommandRunner, resolvers_file: str, subdomains: List[str]) -> Tuple[List[str], List[str], List[DNSRecord]]:
    if not subdomains:
        return [], [], []
    md = resolve_executable("massdns")
    if not md:
        log("ERROR", "massdns not found in PATH or RECON_TOOL_PATH / ~/go/bin / /usr/local/bin")
        return [], [], []
    cmd = [md, "-r", resolvers_file, "-t", "A", "-o", "S"]
    stdin_text = "\n".join(subdomains) + "\n"
    try:
        p = subprocess.run(
            cmd,
            input=stdin_text,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=runner.timeout_s,
            check=True,
        )
        lines = p.stdout.splitlines()
    except Exception as e:
        log("ERROR", f"massdns failed: {e}")
        return [], [], []

    domains, ips, records = parse_massdns_stdout(lines)
    return dedupe_sorted(domains), dedupe_sorted(ips), records


def run_subdomain_enumeration(
    runner: CommandRunner,
    target: str,
    wordlist: str,
    resolvers_file: str,
    out_dir: str,
    *,
    enable_passive: bool = True,
    enable_active: bool = True,
) -> List[str]:
    found: List[str] = []
    passive_files: List[str] = []

    if enable_passive:
        sf = resolve_executable("subfinder")
        if sf:
            out = os.path.join(out_dir, "passive", "subfinder.txt")
            runner.run([sf, "-d", target, "-silent"], stdout_path=out, retries=2, allow_fail=True)
            passive_files.append(out)
        am = resolve_executable("amass")
        if am:
            out = os.path.join(out_dir, "passive", "amass.txt")
            runner.run([am, "enum", "-passive", "-d", target, "-silent"], stdout_path=out, retries=1, allow_fail=True)
            passive_files.append(out)
        af = resolve_executable("assetfinder")
        if af:
            out = os.path.join(out_dir, "passive", "assetfinder.txt")
            runner.run([af, "--subs-only", target], stdout_path=out, retries=1, allow_fail=True)
            passive_files.append(out)
        else:
            log("WARNING", "assetfinder not found (install or add to PATH / ~/go/bin / RECON_TOOL_PATH); skipping")

    if enable_active:
        sd = resolve_executable("shuffledns")
        if sd:
            out = os.path.join(out_dir, "active", "shuffledns_bruteforce.txt")
            safe_mkdir(os.path.dirname(out))
            runner.run(
                [
                    sd,
                    "-d",
                    target,
                    "-w",
                    wordlist,
                    "-r",
                    resolvers_file,
                    "-mode",
                    "bruteforce",
                    "-t",
                    "500",
                    "-o",
                    out,
                ],
                retries=1,
                allow_fail=True,
            )
            passive_files.append(out)
        else:
            log("WARNING", "shuffledns not found (install or add to PATH / ~/go/bin / RECON_TOOL_PATH); skipping")

    for f in passive_files:
        found.extend(read_text_lines(f))

    found = [normalize_domain(s) for s in found]
    return dedupe_sorted([s for s in found if s and (s == target or s.endswith("." + target))])


def parse_httpx_jsonl(path: str) -> List[HttpService]:
    results: List[HttpService] = []
    if not os.path.exists(path) or os.path.getsize(path) == 0:
        return results
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            url = obj.get("url") or obj.get("final_url") or obj.get("input")
            if not url:
                continue
            host = obj.get("host") or ""
            port = obj.get("port")
            try:
                port_int = int(port) if port is not None else None
            except (TypeError, ValueError):
                port_int = None
            tech = obj.get("tech") or obj.get("technologies") or []
            if isinstance(tech, str):
                tech_list = [t.strip() for t in tech.split(",") if t.strip()]
            elif isinstance(tech, list):
                tech_list = [str(t).strip() for t in tech if str(t).strip()]
            else:
                tech_list = []
            svc = HttpService(
                url=url,
                host=normalize_domain(host) if host else normalize_domain(url.split("://", 1)[-1].split("/", 1)[0]),
                port=port_int,
                scheme=obj.get("scheme"),
                status_code=obj.get("status_code"),
                title=obj.get("title"),
                technologies=dedupe_sorted(tech_list),
                server=obj.get("webserver") or obj.get("server"),
                ip=normalize_ip(obj.get("ip")) if obj.get("ip") else None,
                cname=obj.get("cname"),
                raw=obj,
            )
            results.append(svc)
    return results


def run_http_discovery(
    runner: CommandRunner,
    domains: List[str],
    out_dir: str,
    *,
    rate_limit: int = 100,
    proxy: Optional[str] = None,
) -> Tuple[str, List[HttpService]]:
    out_jsonl = os.path.join(out_dir, "discovery", "httpx.jsonl")
    out_txt = os.path.join(out_dir, "discovery", "active_urls.txt")
    domains_file = os.path.join(out_dir, "discovery", "httpx_input_domains.txt")

    if not domains:
        write_text_lines(out_txt, [])
        write_text_lines(out_jsonl, [])
        return out_txt, []

    httpx_bin = resolve_executable("httpx")
    if not httpx_bin:
        log("WARNING", "httpx not found; skipping HTTP discovery")
        write_text_lines(out_txt, [])
        write_text_lines(out_jsonl, [])
        return out_txt, []

    write_text_lines(domains_file, domains)
    ua = random.choice(USER_AGENTS)
    cmd = [
        httpx_bin,
        "-l",
        domains_file,
        "-silent",
        "-json",
        "-status-code",
        "-title",
        "-tech-detect",
        "-rl",
        str(rate_limit),
        "-H",
        f"User-Agent: {ua}",
    ]
    if proxy:
        cmd.extend(["-proxy", proxy])

    runner.run(cmd, stdout_path=out_jsonl, retries=2, allow_fail=True)
    services = parse_httpx_jsonl(out_jsonl)
    write_text_lines(out_txt, dedupe_sorted([s.url for s in services]))
    return out_txt, services


def parse_naabu_jsonl(path: str) -> List[Tuple[str, int, str]]:
    out: List[Tuple[str, int, str]] = []
    if not os.path.exists(path) or os.path.getsize(path) == 0:
        return out
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            ip = normalize_ip(obj.get("ip") or obj.get("host"))
            port = obj.get("port")
            proto = (obj.get("protocol") or "tcp").lower()
            if not ip:
                continue
            try:
                port_i = int(port)
            except (TypeError, ValueError):
                continue
            out.append((ip, port_i, proto))
    return out


def parse_naabu_text(path: str) -> List[Tuple[str, int, str]]:
    out: List[Tuple[str, int, str]] = []
    for line in read_text_lines(path):
        if ":" not in line:
            continue
        ip_s, port_s = line.split(":", 1)
        ip = normalize_ip(ip_s)
        if not ip:
            continue
        try:
            port = int(port_s.strip())
        except ValueError:
            continue
        out.append((ip, port, "tcp"))
    return out


def run_port_scan(
    runner: CommandRunner,
    ips: List[str],
    out_dir: str,
    *,
    rate_limit: int = 100,
    proxy: Optional[str] = None,
) -> Tuple[str, List[Tuple[str, int, str]]]:
    out_txt = os.path.join(out_dir, "discovery", "open_ports.txt")
    out_jsonl = os.path.join(out_dir, "discovery", "naabu.jsonl")
    ips_file = os.path.join(out_dir, "discovery", "naabu_input_ips.txt")
    if not ips:
        write_text_lines(out_txt, [])
        write_text_lines(out_jsonl, [])
        return out_txt, []

    naabu_bin = resolve_executable("naabu")
    if not naabu_bin:
        log("WARNING", "naabu not found; skipping port scan")
        write_text_lines(out_txt, [])
        write_text_lines(out_jsonl, [])
        return out_txt, []

    write_text_lines(ips_file, ips)
    cmd = [naabu_bin, "-silent", "-json", "-rate", str(rate_limit), "-list", ips_file]
    if proxy:
        cmd.extend(["-proxy", proxy])
    runner.run(cmd, stdout_path=out_jsonl, retries=1, allow_fail=True)
    results = parse_naabu_jsonl(out_jsonl)
    if not results:
        runner.run([naabu_bin, "-silent", "-list", ips_file], stdout_path=out_txt, retries=1, allow_fail=True)
        results = parse_naabu_text(out_txt)
    write_text_lines(out_txt, dedupe_sorted([f"{ip}:{port}" for ip, port, _ in results]))
    return out_txt, results


def parse_nmap_xml(path: str) -> List[NetworkService]:
    services: List[NetworkService] = []
    if not os.path.exists(path) or os.path.getsize(path) == 0:
        return services
    try:
        tree = ET.parse(path)
        root = tree.getroot()
    except ET.ParseError:
        return services

    for host in root.findall("host"):
        addr = host.find("address")
        if addr is None:
            continue
        ip = normalize_ip(addr.attrib.get("addr"))
        if not ip:
            continue
        ports = host.find("ports")
        if ports is None:
            continue
        for port_el in ports.findall("port"):
            proto = (port_el.attrib.get("protocol") or "tcp").lower()
            portid = port_el.attrib.get("portid")
            try:
                port = int(portid)
            except (TypeError, ValueError):
                continue
            state_el = port_el.find("state")
            state = state_el.attrib.get("state") if state_el is not None else "unknown"
            svc_el = port_el.find("service")
            service_name = svc_el.attrib.get("name") if svc_el is not None else None
            product = svc_el.attrib.get("product") if svc_el is not None else None
            version = svc_el.attrib.get("version") if svc_el is not None else None
            extrainfo = svc_el.attrib.get("extrainfo") if svc_el is not None else None
            cpes: List[str] = []
            if svc_el is not None:
                for cpe_el in svc_el.findall("cpe"):
                    if cpe_el.text:
                        cpes.append(cpe_el.text.strip())
            services.append(
                NetworkService(
                    ip=ip,
                    port=port,
                    protocol=proto,
                    state=state,
                    service_name=service_name,
                    product=product,
                    version=version,
                    extrainfo=extrainfo,
                    cpe=dedupe_sorted(cpes),
                )
            )
    return services


def run_nmap_service_detection(
    runner: CommandRunner,
    ips: List[str],
    discovered_ports: List[Tuple[str, int, str]],
    out_dir: str,
) -> Tuple[Tuple[str, str], List[NetworkService]]:
    out_txt = os.path.join(out_dir, "scans", "nmap_versions.txt")
    out_xml = os.path.join(out_dir, "scans", "nmap_versions.xml")

    nmap_bin = resolve_executable("nmap")
    if not ips or not discovered_ports or not nmap_bin:
        write_text_lines(out_txt, [])
        write_text_lines(out_xml, [])
        return (out_txt, out_xml), []

    unique_ports = sorted({p for _, p, proto in discovered_ports if proto == "tcp"})
    if not unique_ports:
        write_text_lines(out_txt, [])
        write_text_lines(out_xml, [])
        return (out_txt, out_xml), []

    ports_arg = ",".join(str(p) for p in unique_ports)
    ips_file = os.path.join(out_dir, "discovery", "nmap_input_ips.txt")
    write_text_lines(ips_file, ips)
    runner.run(
        [
            nmap_bin,
            "-sV",
            "-sC",
            "-p",
            ports_arg,
            "-iL",
            ips_file,
            "-oN",
            out_txt,
            "-oX",
            out_xml,
            "--version-intensity",
            "5",
        ],
        retries=1,
        allow_fail=True,
    )
    services = parse_nmap_xml(out_xml)
    return (out_txt, out_xml), services


def run_wayback(runner: CommandRunner, target: str, out_dir: str) -> str:
    out = os.path.join(out_dir, "discovery", "waybackurls.txt")
    wb = resolve_executable("waybackurls")
    if not wb:
        write_text_lines(out, [])
        return out
    runner.run([wb, target], stdout_path=out, retries=2, allow_fail=True)
    return out


def run_katana(runner: CommandRunner, active_urls_path: str, out_dir: str, *, waf_delay_s: float = 0.0) -> str:
    out = os.path.join(out_dir, "discovery", "katana.txt")
    kat = resolve_executable("katana")
    if not kat:
        write_text_lines(out, [])
        return out
    urls = read_text_lines(active_urls_path)
    if not urls:
        write_text_lines(out, [])
        return out
    runner.run(
        [kat, "-silent", "-jc", "-d", "5", "-H", f"User-Agent: {random.choice(USER_AGENTS)}"],
        stdout_path=out,
        stdin_text="\n".join(urls) + "\n",
        delay_s=waf_delay_s,
        retries=1,
        allow_fail=True,
    )
    return out


def merge_endpoints(out_dir: str, katana_path: str, wayback_path: str) -> str:
    out = os.path.join(out_dir, "discovery", "discovered_endpoints.txt")
    endpoints = set(read_text_lines(katana_path)) | set(read_text_lines(wayback_path))
    write_text_lines(out, dedupe_sorted(endpoints))
    return out


def run_gf_filters(runner: CommandRunner, endpoints_path: str, out_dir: str, patterns: Sequence[str], *, waf_delay_s: float = 0.0) -> Dict[str, str]:
    out_map: Dict[str, str] = {}
    gf = resolve_executable("gf")
    if not gf:
        for p in patterns:
            out_map[p] = os.path.join(out_dir, "vulns", f"gf_{p}.txt")
            write_text_lines(out_map[p], [])
        return out_map
    endpoints = read_text_lines(endpoints_path)
    for pattern in patterns:
        out = os.path.join(out_dir, "vulns", f"gf_{pattern}.txt")
        runner.run([gf, pattern], stdout_path=out, stdin_text="\n".join(endpoints) + "\n", delay_s=waf_delay_s, allow_fail=True)
        out_map[pattern] = out
    return out_map


def parse_nuclei_jsonl(path: str) -> List[Finding]:
    findings: List[Finding] = []
    if not os.path.exists(path) or os.path.getsize(path) == 0:
        return findings
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            info = obj.get("info") or {}
            findings.append(
                Finding(
                    category="nuclei",
                    source=str(obj.get("template-id") or obj.get("templateID") or "nuclei"),
                    severity=(info.get("severity") if isinstance(info, dict) else None),
                    target=obj.get("matched-at") or obj.get("host") or obj.get("url"),
                    title=(info.get("name") if isinstance(info, dict) else None),
                    raw=obj,
                )
            )
    return findings


def run_nuclei(
    runner: CommandRunner,
    active_urls_path: str,
    out_dir: str,
    *,
    rate_limit: int = 100,
    proxy: Optional[str] = None,
    waf_delay_s: float = 0.0,
) -> Tuple[Dict[str, str], List[Finding]]:
    categories = {
        "cves": "cves/",
        "exposure": "exposure/",
        "misconfig": "security-misconfiguration/",
        "panels": "exposed-panel/",
        "tokens": "exposed-tokens/",
        "vulns": "vulnerabilities/",
        "dns": "dns/",
        "javascript": "javascript/",
        "network": "network/",
    }
    out_paths: Dict[str, str] = {}
    all_findings: List[Finding] = []

    nuclei_bin = resolve_executable("nuclei")
    if not nuclei_bin:
        for k in categories:
            out_paths[k] = os.path.join(out_dir, "scans", f"nuclei_{k}.jsonl")
            write_text_lines(out_paths[k], [])
        return out_paths, []

    urls = read_text_lines(active_urls_path)
    if not urls:
        for k in categories:
            out_paths[k] = os.path.join(out_dir, "scans", f"nuclei_{k}.jsonl")
            write_text_lines(out_paths[k], [])
        return out_paths, []

    base = [nuclei_bin, "-jsonl", "-silent", "-c", "20", "-rate-limit", str(rate_limit), "-timeout", "30", "-l", "-"]
    if proxy:
        base.extend(["-proxy", proxy])

    for key, tmpl in categories.items():
        out = os.path.join(out_dir, "scans", f"nuclei_{key}.jsonl")
        out_paths[key] = out
        runner.run(base + ["-t", tmpl], stdout_path=out, stdin_text="\n".join(urls) + "\n", delay_s=waf_delay_s, retries=1, allow_fail=True)
        all_findings.extend(parse_nuclei_jsonl(out))

    return out_paths, all_findings


def run_takeover_check(runner: CommandRunner, subdomains: List[str], out_dir: str, *, waf_delay_s: float = 0.0) -> Tuple[str, List[Finding]]:
    out = os.path.join(out_dir, "vulns", "subdomain_takeover.jsonl")
    nuclei_bin = resolve_executable("nuclei")
    if not nuclei_bin or not subdomains:
        write_text_lines(out, [])
        return out, []
    runner.run(
        [nuclei_bin, "-silent", "-jsonl", "-l", "-", "-t", "vulnerabilities/network/subdomain-takeover/"],
        stdout_path=out,
        stdin_text="\n".join(subdomains) + "\n",
        delay_s=waf_delay_s,
        allow_fail=True,
    )
    findings = parse_nuclei_jsonl(out)
    for f in findings:
        f.category = "takeover"
    return out, findings


def detect_waf_httpx(runner: CommandRunner, active_urls_path: str, out_dir: str, *, proxy: Optional[str] = None) -> Tuple[str, List[Finding]]:
    out_jsonl = os.path.join(out_dir, "waf", "httpx_waf.jsonl")
    httpx_bin = resolve_executable("httpx")
    if not httpx_bin:
        write_text_lines(out_jsonl, [])
        return out_jsonl, []
    urls = read_text_lines(active_urls_path)
    if not urls:
        write_text_lines(out_jsonl, [])
        return out_jsonl, []

    cmd = [httpx_bin, "-silent", "-json", "-tls-probe", "-cname-probe", "-H", f"User-Agent: {random.choice(USER_AGENTS)}"]
    if proxy:
        cmd.extend(["-proxy", proxy])
    runner.run(cmd, stdout_path=out_jsonl, stdin_text="\n".join(urls) + "\n", allow_fail=True)

    findings: List[Finding] = []
    for svc in parse_httpx_jsonl(out_jsonl):
        if svc.cname:
            findings.append(Finding(category="waf", source="httpx", target=svc.url, title="cname_probe", raw={"cname": svc.cname}))
    return out_jsonl, findings


def build_structured_output(
    meta: ScanMeta,
    *,
    subdomains: List[str],
    resolved_domains: List[str],
    resolved_ips: List[str],
    dns_records: List[DNSRecord],
    http_services: List[HttpService],
    naabu_ports: List[Tuple[str, int, str]],
    network_services: List[NetworkService],
    findings: List[Finding],
    artifacts: Dict[str, str],
) -> Dict[str, Any]:
    return {
        "meta": asdict(meta),
        "subdomains": subdomains,
        "resolved_domains": resolved_domains,
        "resolved_ips": resolved_ips,
        "dns_records": [asdict(r) for r in dns_records],
        "http_services": [asdict(s) for s in http_services],
        "open_ports": [{"ip": ip, "port": port, "protocol": proto} for ip, port, proto in naabu_ports],
        "network_services": [asdict(s) for s in network_services],
        "findings": [asdict(f) for f in findings],
        "artifacts": artifacts,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="SuperReconn - active/passive recon + inventory + security + MSSQL-ready JSON artifacts")
    parser.add_argument("target", help="Target domain (e.g. example.com)")
    parser.add_argument("-o", "--output", help="Output directory (default: <target>-<date>)")
    parser.add_argument("--wordlist", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "wordlists", "subdomains.txt"))
    parser.add_argument("--resolvers", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "resolvers.txt"))
    parser.add_argument("--rate-limit", type=int, default=int(os.getenv("RECON_RATE_LIMIT", "100")))
    parser.add_argument("--waf-delay", type=float, default=float(os.getenv("RECON_WAF_DELAY", "1")))
    parser.add_argument("--proxy", default=os.getenv("RECON_PROXY", ""))

    parser.add_argument("--no-passive", action="store_true", help="Disable passive subdomain enumeration")
    parser.add_argument("--no-active", action="store_true", help="Disable active brute-force subdomain enumeration")
    parser.add_argument("--no-waf", action="store_true", help="Disable WAF probing")
    parser.add_argument("--no-crawl", action="store_true", help="Disable crawling (katana/wayback)")
    parser.add_argument("--no-gf", action="store_true", help="Disable gf filtering")
    parser.add_argument("--no-nuclei", action="store_true", help="Disable nuclei scans")
    parser.add_argument("--no-takeover", action="store_true", help="Disable subdomain takeover checks")
    args = parser.parse_args()

    target = normalize_domain(args.target)
    if not target or "." not in target:
        log("ERROR", "Target must be a domain like example.com")
        return 2

    script_dir = os.path.dirname(os.path.abspath(__file__))
    output_dir = args.output or os.path.join(script_dir, f"{target}-{dt.date.today().isoformat()}")
    safe_mkdir(output_dir)

    # base dirs
    for d in ["subdomains", "passive", "active", "discovery", "scans", "vulns", "waf", "structured"]:
        safe_mkdir(os.path.join(output_dir, d))

    if not os.path.exists(args.resolvers) or os.path.getsize(args.resolvers) == 0:
        log("ERROR", f"Resolvers file missing/empty: {args.resolvers}")
        return 2
    if not os.path.exists(args.wordlist) or os.path.getsize(args.wordlist) == 0:
        log("ERROR", f"Wordlist missing/empty: {args.wordlist}")
        return 2

    proxy = args.proxy.strip() or None

    meta = ScanMeta(
        scan_id=str(uuid.uuid4()),
        target=target,
        started_at_utc=now_utc_iso(),
        output_dir=output_dir,
        args={
            "rate_limit": args.rate_limit,
            "waf_delay": args.waf_delay,
            "proxy": proxy,
            "no_passive": args.no_passive,
            "no_active": args.no_active,
            "no_waf": args.no_waf,
            "no_crawl": args.no_crawl,
            "no_gf": args.no_gf,
            "no_nuclei": args.no_nuclei,
            "no_takeover": args.no_takeover,
        },
    )

    required_tools = ["massdns", "httpx", "naabu", "nmap"]
    optional_tools = ["subfinder", "amass", "assetfinder", "shuffledns", "katana", "waybackurls", "gf", "nuclei"]
    meta.tools = {t: tool_exists(t) for t in required_tools + optional_tools}

    runner = CommandRunner(timeout_s=1200, quiet_stderr=True)

    artifacts: Dict[str, str] = {}
    findings: List[Finding] = []

    log("INFO", f"Target: {target}")
    log("INFO", f"Output: {output_dir}")
    if proxy:
        log("INFO", f"Proxy: {proxy}")

    # Phase 1+2: subdomain enumeration
    subdomains = run_subdomain_enumeration(
        runner,
        target,
        args.wordlist,
        args.resolvers,
        output_dir,
        enable_passive=not args.no_passive,
        enable_active=not args.no_active,
    )
    subdomains_path = os.path.join(output_dir, "subdomains", "all_subdomains.txt")
    write_text_lines(subdomains_path, subdomains)
    artifacts["subdomains_all"] = subdomains_path
    write_json(os.path.join(output_dir, "structured", "subdomains.json"), {"subdomains": subdomains})

    # Phase 3: DNS resolution (pure Python parsing)
    resolved_domains, resolved_ips, dns_records = run_massdns_resolve(runner, args.resolvers, subdomains or [target])
    resolved_domains_path = os.path.join(output_dir, "discovery", "resolved_domains.txt")
    resolved_ips_path = os.path.join(output_dir, "discovery", "resolved_ips.txt")
    write_text_lines(resolved_domains_path, resolved_domains)
    write_text_lines(resolved_ips_path, resolved_ips)
    artifacts["resolved_domains"] = resolved_domains_path
    artifacts["resolved_ips"] = resolved_ips_path
    write_json(
        os.path.join(output_dir, "structured", "dns_records.json"),
        {"records": [asdict(r) for r in dns_records]},
    )

    # Phase 4: HTTP discovery
    active_urls_path, http_services = run_http_discovery(runner, resolved_domains, output_dir, rate_limit=args.rate_limit, proxy=proxy)
    artifacts["active_urls"] = active_urls_path
    write_json(os.path.join(output_dir, "structured", "http_services.json"), {"services": [asdict(s) for s in http_services]})

    # Phase 5: port scanning
    open_ports_path, naabu_ports = run_port_scan(runner, resolved_ips, output_dir, rate_limit=args.rate_limit, proxy=proxy)
    artifacts["open_ports"] = open_ports_path
    write_json(
        os.path.join(output_dir, "structured", "open_ports.json"),
        {"open_ports": [{"ip": ip, "port": port, "protocol": proto} for ip, port, proto in naabu_ports]},
    )

    # Phase 6: service/version detection via nmap xml
    (nmap_txt, nmap_xml), network_services = run_nmap_service_detection(runner, resolved_ips, naabu_ports, output_dir)
    artifacts["nmap_versions_txt"] = nmap_txt
    artifacts["nmap_versions_xml"] = nmap_xml
    write_json(os.path.join(output_dir, "structured", "network_services.json"), {"services": [asdict(s) for s in network_services]})

    # Phase 7: WAF probing
    if not args.no_waf:
        waf_jsonl, waf_findings = detect_waf_httpx(runner, active_urls_path, output_dir, proxy=proxy)
        artifacts["waf_httpx_jsonl"] = waf_jsonl
        findings.extend(waf_findings)

    # Phase 8: crawling
    if not args.no_crawl:
        katana_path = run_katana(runner, active_urls_path, output_dir, waf_delay_s=args.waf_delay)
        wayback_path = run_wayback(runner, target, output_dir)
        artifacts["katana"] = katana_path
        artifacts["wayback"] = wayback_path
        endpoints_path = merge_endpoints(output_dir, katana_path, wayback_path)
        artifacts["endpoints"] = endpoints_path
        write_json(os.path.join(output_dir, "structured", "endpoints.json"), {"endpoints": read_text_lines(endpoints_path)})
    else:
        endpoints_path = os.path.join(output_dir, "discovery", "discovered_endpoints.txt")
        write_text_lines(endpoints_path, [])
        artifacts["endpoints"] = endpoints_path

    # Phase 9: gf filters
    if not args.no_gf:
        gf_out = run_gf_filters(runner, endpoints_path, output_dir, ["xss", "rce", "ssti", "sqli", "ssrf", "lfi", "redirect", "crlf"], waf_delay_s=args.waf_delay)
        artifacts.update({f"gf_{k}": v for k, v in gf_out.items()})
        for pat, pth in gf_out.items():
            for url in read_text_lines(pth):
                findings.append(Finding(category="gf", source=pat, severity="info", target=url, title=f"gf_{pat}", raw={}))

    # Phase 10: nuclei
    if not args.no_nuclei:
        nuclei_paths, nuclei_findings = run_nuclei(
            runner,
            active_urls_path,
            output_dir,
            rate_limit=args.rate_limit,
            proxy=proxy,
            waf_delay_s=args.waf_delay,
        )
        artifacts.update({f"nuclei_{k}": v for k, v in nuclei_paths.items()})
        findings.extend(nuclei_findings)

    # Phase 11: takeover
    if not args.no_takeover:
        takeover_path, takeover_findings = run_takeover_check(runner, subdomains, output_dir, waf_delay_s=args.waf_delay)
        artifacts["takeover"] = takeover_path
        findings.extend(takeover_findings)

    meta.finished_at_utc = now_utc_iso()

    structured = build_structured_output(
        meta,
        subdomains=subdomains,
        resolved_domains=resolved_domains,
        resolved_ips=resolved_ips,
        dns_records=dns_records,
        http_services=http_services,
        naabu_ports=naabu_ports,
        network_services=network_services,
        findings=findings,
        artifacts=artifacts,
    )
    consolidated_path = os.path.join(output_dir, "structured", "superreconn.json")
    write_json(consolidated_path, structured)
    artifacts["structured_consolidated"] = consolidated_path

    summary_path = os.path.join(output_dir, "discovery", "summary.txt")
    summary_lines = [
        f"SuperReconn Summary for {target}",
        f"Scan ID: {meta.scan_id}",
        f"Started: {meta.started_at_utc}",
        f"Finished: {meta.finished_at_utc}",
        f"Output: {output_dir}",
        "",
        f"Subdomains: {len(subdomains)}",
        f"Resolved domains: {len(resolved_domains)}",
        f"Resolved IPs: {len(resolved_ips)}",
        f"HTTP services: {len(http_services)}",
        f"Open ports: {len(naabu_ports)}",
        f"Network services (nmap xml parsed): {len(network_services)}",
        f"Findings: {len(findings)}",
    ]
    write_text_lines(summary_path, summary_lines)
    artifacts["summary"] = summary_path

    log("SUCCESS", f"Done. Consolidated JSON: {consolidated_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

