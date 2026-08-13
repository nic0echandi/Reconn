#!/usr/bin/env python3

"""
SuperReconn - Reconnaissance pipeline para mapeo de superficie expuesta.

Combina enumeración pasiva/activa de subdominios, descubrimiento de servicios HTTP,
escaneo de puertos, detección de servicios/versiones y análisis de vulnerabilidades
con salida JSON estructurada y persistencia opcional en SQL Server.

Herramientas soportadas:
    Requeridas: massdns, httpx, naabu, nmap
    Opcionales: subfinder, amass, assetfinder, shuffledns, katana, waybackurls, gf, nuclei

Uso:
    python3 SuperReconn.py example.com
    python3 SuperReconn.py example.com -o ./resultados --rate-limit 200 --waf-delay 2
    python3 SuperReconn.py example.com --no-nuclei --no-crawl  # Modo rápido

Variables de entorno:
    RECON_TOOL_PATH: Rutas adicionales donde buscar herramientas (separadas por :)
    RECON_RATE_LIMIT: Límite de tasa (default: 100)
    RECON_WAF_DELAY: Delay entre peticiones para eludir WAF (default: 1)
    RECON_PROXY: Proxy HTTP/HTTPS (ej: http://127.0.0.1:8080)

Nota: La persistencia en SQL Server es OPCIONAL. Usa persist_mssql.py después de ejecutar.
"""

import argparse
import datetime as dt
import ipaddress
import json
import logging
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

_logger: Optional[logging.Logger] = None


def setup_logging(output_dir: str) -> logging.Logger:
    """
    Configura logging a archivo y consola.
    
    Args:
        output_dir: Directorio donde guardar el archivo execution.log
        
    Returns:
        Logger configurado
    """
    global _logger
    
    log_file = os.path.join(output_dir, "execution.log")
    
    # Crear logger
    logger = logging.getLogger("SuperReconn")
    logger.setLevel(logging.DEBUG)
    
    # Handler para archivo (DEBUG)
    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_formatter = logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    file_handler.setFormatter(file_formatter)
    
    # Handler para consola (INFO)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_formatter = logging.Formatter(
        fmt="[%(asctime)s] [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S"
    )
    console_handler.setFormatter(console_formatter)
    
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    _logger = logger
    return logger


def now_utc_iso() -> str:
    """Retorna timestamp UTC en formato ISO 8601."""
    return dt.datetime.now(dt.timezone.utc).isoformat()


def log(level: str, msg: str) -> None:
    """
    Log mensaje a consola y archivo.
    
    Args:
        level: Nivel de log (INFO, WARNING, ERROR, DEBUG)
        msg: Mensaje a loguear
    """
    if _logger is None:
        # Fallback si logging no está configurado
        ts = dt.datetime.now().strftime("%H:%M:%S")
        print(f"[{ts}] [{level}] {msg}")
        return
    
    log_level = getattr(logging, level.upper(), logging.INFO)
    _logger.log(log_level, msg)


def _go_bin_dirs() -> List[str]:
    """
    Retorna lista de directorios donde buscar binarios Go.
    
    En Ubuntu, las herramientas instaladas con Go frecuentemente se encuentran
    en ~/go/bin, que puede no estar en PATH cuando se ejecuta desde cron/systemd.
    
    Returns:
        Lista de directorios candidatos
    """
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
    """
    Resuelve la ruta de una herramienta CLI.
    
    Busca en: PATH -> RECON_TOOL_PATH -> Go dirs -> /usr/local/bin
    
    Args:
        name: Nombre del ejecutable
        
    Returns:
        Ruta absoluta del ejecutable o None si no se encuentra
    """
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
    """Verifica si una herramienta está disponible."""
    return resolve_executable(name) is not None


def validate_environment() -> None:
    """
    Valida que el entorno esté configurado correctamente.
    
    Verifica:
    - Herramientas requeridas disponibles
    - Archivos de configuración necesarios
    
    Raises:
        SystemExit: Si hay errores críticos
    """
    required_tools = ["massdns", "httpx", "naabu", "nmap"]
    missing = [t for t in required_tools if not tool_exists(t)]
    
    if missing:
        log("ERROR", f"Herramientas requeridas no encontradas: {', '.join(missing)}")
        log("ERROR", "Asegúrate de que estén en PATH o en RECON_TOOL_PATH")
        sys.exit(1)
    
    log("INFO", f"Herramientas validadas: {', '.join(required_tools)}")



def safe_mkdir(path: str) -> None:
    """Crea directorio recursivamente si no existe."""
    os.makedirs(path, exist_ok=True)


def write_text_lines(path: str, lines: Iterable[str]) -> None:
    """
    Escribe líneas de texto a archivo.
    
    Stripea espacios en blanco y salta líneas vacías.
    """
    safe_mkdir(os.path.dirname(path))
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        for line in lines:
            line = line.strip()
            if line:
                f.write(line + "\n")


def write_json(path: str, obj: Any) -> None:
    """Escribe objeto Python a JSON con indentación."""
    safe_mkdir(os.path.dirname(path))
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)


def read_text_lines(path: str) -> List[str]:
    """Lee líneas de texto desde archivo, stripea espacios en blanco."""
    if not os.path.exists(path) or os.path.getsize(path) == 0:
        return []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return [line.strip() for line in f if line.strip()]


def dedupe_sorted(items: Iterable[str]) -> List[str]:
    """Deduplica y ordena lista de strings."""
    return sorted({i.strip() for i in items if i and i.strip()})


class CommandRunner:
    """
    Ejecutor de comandos externo con reintentos, timeout y manejo de errores.
    
    Attributes:
        timeout_s: Timeout en segundos para cada comando
        quiet_stderr: Si es True, suprime stderr
    """
    
    def __init__(self, timeout_s: int = 900, quiet_stderr: bool = True):
        """
        Inicializa CommandRunner.
        
        Args:
            timeout_s: Timeout por defecto (default: 900s = 15min)
            quiet_stderr: Si True, redirige stderr a /dev/null (default: True)
        """
        self.timeout_s = timeout_s
        self.quiet_stderr = quiet_stderr
        self.last_error: Optional[str] = None

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
        """
        Ejecuta comando con reintentos y timeout.
        
        Args:
            cmd: Comando a ejecutar (lista de strings)
            stdout_path: Archivo donde guardar stdout (opcional)
            stdin_text: Texto a pasar a stdin (opcional)
            env_extra: Variables de entorno adicionales
            retries: Número de reintentos (default: 1)
            retry_backoff_s: Factor de backoff exponencial entre reintentos
            delay_s: Delay antes de ejecutar
            allow_fail: Si True, no falla si el comando retorna error
            
        Returns:
            True si el comando fue exitoso, False en caso contrario
        """
        if delay_s > 0:
            time.sleep(delay_s)

        self.last_error = None
        env = os.environ.copy()
        if env_extra:
            env.update(env_extra)

        for attempt in range(retries):
            try:
                log("DEBUG", f"Running: {' '.join(cmd)}")
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
                self.last_error = str(e)
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
    """Metadata sobre la ejecución del scan."""
    scan_id: str
    target: str
    started_at_utc: str
    finished_at_utc: Optional[str] = None
    output_dir: str = ""
    script: str = "SuperReconn.py"
    script_version: str = "1.1.0"
    args: Dict[str, Any] = field(default_factory=dict)
    tools: Dict[str, bool] = field(default_factory=dict)
    health: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DNSRecord:
    """Registro DNS resuelto."""
    name: str
    rtype: str
    value: str
    ttl: Optional[int] = None


@dataclass
class HttpService:
    """Servicio HTTP descubierto."""
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
    """Servicio de red descubierto por nmap."""
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
    """Hallazgo de seguridad (vulnerabilidad, misconfiguration, etc)."""
    category: str  # nuclei/gf/waf/takeover/other
    source: str  # tool name or template id
    severity: Optional[str] = None
    target: Optional[str] = None  # url or hostname or ip:port
    title: Optional[str] = None
    raw: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PhaseResult:
    """Resultado de una fase del pipeline."""
    name: str
    status: str  # ok | warning | failed | skipped
    detail: str = ""
    count: Optional[int] = None


# Rutas de templates nuclei v3 (relativas al directorio nuclei-templates)
NUCLEI_CATEGORIES: Dict[str, str] = {
    "cves": "http/cves/",
    "exposure": "http/exposures/",
    "misconfig": "http/misconfiguration/",
    "panels": "http/exposed-panels/",
    "tokens": "http/token-spray/",
    "vulns": "http/vulnerabilities/",
    "dns": "dns/",
    "javascript": "javascript/",
    "network": "network/",
}

NUCLEI_TAKEOVER_TEMPLATES = "http/takeovers/"


def record_phase(phases: List[PhaseResult], name: str, status: str, detail: str = "", count: Optional[int] = None) -> None:
    """Registra el resultado de una fase y lo escribe al log."""
    phases.append(PhaseResult(name=name, status=status, detail=detail, count=count))
    level = {"ok": "INFO", "skipped": "INFO", "warning": "WARNING", "failed": "ERROR"}.get(status, "INFO")
    suffix = f" ({count})" if count is not None else ""
    log(level, f"Phase [{name}] {status}{suffix}: {detail}" if detail else f"Phase [{name}] {status}{suffix}")


def overall_health_status(phases: List[PhaseResult]) -> str:
    """Calcula estado general: healthy | degraded | failed."""
    if any(p.status == "failed" for p in phases):
        return "failed" if sum(1 for p in phases if p.status == "ok") == 0 else "degraded"
    if any(p.status == "warning" for p in phases):
        return "degraded"
    return "healthy"


def write_health_report(output_dir: str, phases: List[PhaseResult]) -> str:
    """Escribe reporte de salud post-scan y retorna la ruta del archivo."""
    path = os.path.join(output_dir, "discovery", "health_report.txt")
    overall = overall_health_status(phases)
    lines = [
        "SuperReconn Health Report",
        f"Overall status: {overall}",
        "",
        f"{'Phase':<28} {'Status':<10} {'Count':<8} Detail",
        "-" * 80,
    ]
    for p in phases:
        count_s = str(p.count) if p.count is not None else "-"
        lines.append(f"{p.name:<28} {p.status:<10} {count_s:<8} {p.detail}")
    lines.extend(["", f"Phases: {len(phases)} total, {sum(1 for p in phases if p.status == 'ok')} ok, "
                       f"{sum(1 for p in phases if p.status == 'failed')} failed, "
                       f"{sum(1 for p in phases if p.status == 'warning')} warnings, "
                       f"{sum(1 for p in phases if p.status == 'skipped')} skipped"])
    write_text_lines(path, lines)
    return path


def nuclei_templates_available(nuclei_bin: str, template_path: str) -> bool:
    """Verifica que existan templates nuclei para una ruta dada."""
    try:
        p = subprocess.run(
            [nuclei_bin, "-tl", "-t", template_path],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        return p.returncode == 0 and bool(p.stdout.strip())
    except (subprocess.TimeoutExpired, OSError):
        return False


def ensure_nuclei_templates(runner: CommandRunner, *, update: bool = False) -> Tuple[bool, str]:
    """
    Valida templates nuclei; opcionalmente ejecuta nuclei -update-templates.

    Returns:
        (ok, mensaje)
    """
    nuclei_bin = resolve_executable("nuclei")
    if not nuclei_bin:
        return False, "nuclei not installed"

    probe = NUCLEI_CATEGORIES["cves"]
    if nuclei_templates_available(nuclei_bin, probe):
        return True, f"templates available ({probe})"

    if update:
        log("INFO", "Updating nuclei templates (nuclei -update-templates)...")
        if runner.run([nuclei_bin, "-update-templates"], allow_fail=True, quiet_stderr=False):
            if nuclei_templates_available(nuclei_bin, probe):
                return True, "templates updated successfully"
            return False, "update completed but templates still missing; check nuclei install"

    return False, (
        "nuclei templates missing or outdated; run: nuclei -update-templates "
        "or re-run with --update-nuclei-templates"
    )


def normalize_domain(s: str) -> str:
    """Normaliza dominio: strip, lowercase, sin punto final."""
    s = (s or "").strip()
    if not s:
        return s
    s = s.rstrip(".")
    return s.lower()


def normalize_ip(s: str) -> Optional[str]:
    """Valida y normaliza dirección IP."""
    s = (s or "").strip()
    if not s:
        return None
    try:
        return str(ipaddress.ip_address(s))
    except ValueError:
        return None


def parse_massdns_stdout(lines: Iterable[str]) -> Tuple[Set[str], Set[str], List[DNSRecord]]:
    """
    Parsea salida de massdns (formato: nombre tipo valor).
    
    Returns:
        (dominios, IPs, registros DNS)
    """
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
) -> Tuple[Dict[str, str], List[Finding], List[str]]:
    out_paths: Dict[str, str] = {}
    all_findings: List[Finding] = []
    failed_categories: List[str] = []

    nuclei_bin = resolve_executable("nuclei")
    if not nuclei_bin:
        for k in NUCLEI_CATEGORIES:
            out_paths[k] = os.path.join(out_dir, "scans", f"nuclei_{k}.jsonl")
            write_text_lines(out_paths[k], [])
        return out_paths, [], ["nuclei not installed"]

    urls = read_text_lines(active_urls_path)
    if not urls:
        for k in NUCLEI_CATEGORIES:
            out_paths[k] = os.path.join(out_dir, "scans", f"nuclei_{k}.jsonl")
            write_text_lines(out_paths[k], [])
        return out_paths, [], []

    targets_file = os.path.join(out_dir, "scans", "nuclei_targets.txt")
    write_text_lines(targets_file, urls)

    base = [
        nuclei_bin,
        "-jsonl",
        "-silent",
        "-c",
        "20",
        "-rate-limit",
        str(rate_limit),
        "-timeout",
        "30",
        "-l",
        targets_file,
    ]
    if proxy:
        base.extend(["-proxy", proxy])

    for key, tmpl in NUCLEI_CATEGORIES.items():
        out = os.path.join(out_dir, "scans", f"nuclei_{key}.jsonl")
        out_paths[key] = out
        if not nuclei_templates_available(nuclei_bin, tmpl):
            log("WARNING", f"Nuclei templates not found for {key} ({tmpl}); skipping category")
            write_text_lines(out, [])
            failed_categories.append(key)
            continue
        ok = runner.run(base + ["-t", tmpl], stdout_path=out, delay_s=waf_delay_s, retries=1, allow_fail=True)
        if not ok:
            failed_categories.append(key)
            log("WARNING", f"Nuclei scan failed for category {key}: {runner.last_error or 'unknown error'}")
        all_findings.extend(parse_nuclei_jsonl(out))

    return out_paths, all_findings, failed_categories


def run_takeover_check(runner: CommandRunner, subdomains: List[str], out_dir: str, *, waf_delay_s: float = 0.0) -> Tuple[str, List[Finding], bool]:
    out = os.path.join(out_dir, "vulns", "subdomain_takeover.jsonl")
    nuclei_bin = resolve_executable("nuclei")
    if not nuclei_bin or not subdomains:
        write_text_lines(out, [])
        return out, [], False

    if not nuclei_templates_available(nuclei_bin, NUCLEI_TAKEOVER_TEMPLATES):
        log("WARNING", f"Takeover templates not found ({NUCLEI_TAKEOVER_TEMPLATES})")
        write_text_lines(out, [])
        return out, [], False

    targets_file = os.path.join(out_dir, "vulns", "takeover_targets.txt")
    write_text_lines(targets_file, subdomains)
    ok = runner.run(
        [nuclei_bin, "-silent", "-jsonl", "-l", targets_file, "-t", NUCLEI_TAKEOVER_TEMPLATES],
        stdout_path=out,
        delay_s=waf_delay_s,
        allow_fail=True,
    )
    findings = parse_nuclei_jsonl(out)
    for f in findings:
        f.category = "takeover"
    return out, findings, ok


def detect_waf_httpx(runner: CommandRunner, active_urls_path: str, out_dir: str, *, proxy: Optional[str] = None) -> Tuple[str, List[Finding], bool]:
    out_jsonl = os.path.join(out_dir, "waf", "httpx_waf.jsonl")
    httpx_bin = resolve_executable("httpx")
    if not httpx_bin:
        write_text_lines(out_jsonl, [])
        return out_jsonl, [], False
    urls = read_text_lines(active_urls_path)
    if not urls:
        write_text_lines(out_jsonl, [])
        return out_jsonl, [], False

    cmd = [
        httpx_bin,
        "-l",
        active_urls_path,
        "-silent",
        "-json",
        "-cdn",
        "-cname",
        "-H",
        f"User-Agent: {random.choice(USER_AGENTS)}",
    ]
    if proxy:
        cmd.extend(["-proxy", proxy])
    ok = runner.run(cmd, stdout_path=out_jsonl, allow_fail=True)

    findings: List[Finding] = []
    for svc in parse_httpx_jsonl(out_jsonl):
        raw = svc.raw or {}
        cdn_name = raw.get("cdn_name")
        cdn_type = raw.get("cdn_type")
        if cdn_name:
            severity = "info"
            if cdn_type == "waf":
                severity = "low"
            findings.append(
                Finding(
                    category="waf",
                    source="httpx",
                    severity=severity,
                    target=svc.url,
                    title=f"WAF/CDN detected: {cdn_name}",
                    raw={"cdn_name": cdn_name, "cdn_type": cdn_type, "cname": svc.cname},
                )
            )
        elif svc.cname:
            findings.append(
                Finding(
                    category="waf",
                    source="httpx",
                    severity="info",
                    target=svc.url,
                    title="CNAME detected",
                    raw={"cname": svc.cname},
                )
            )
    return out_jsonl, findings, ok


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
    """
    Función principal de SuperReconn.
    
    Returns:
        Código de salida (0 = éxito, != 0 = error)
    """
    parser = argparse.ArgumentParser(
        description="SuperReconn - active/passive recon + inventory + security + MSSQL-ready JSON artifacts",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos de uso:
  python3 SuperReconn.py example.com
  python3 SuperReconn.py example.com -o ./resultados/example.com
  python3 SuperReconn.py example.com --rate-limit 200 --waf-delay 2
  python3 SuperReconn.py example.com --no-nuclei --no-crawl (modo rápido)

Variables de entorno:
  RECON_TOOL_PATH      Rutas adicionales para buscar herramientas (separadas por :)
  RECON_RATE_LIMIT     Límite de tasa por defecto (default: 100)
  RECON_WAF_DELAY      Delay entre peticiones (default: 1s)
  RECON_PROXY          Proxy HTTP/HTTPS (ej: http://127.0.0.1:8080)

Para persistencia en SQL Server:
  Ejecuta después: python3 persist_mssql.py ./resultados/example.com-2026-07-02/structured/superreconn.json
        """
    )
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
    parser.add_argument(
        "--update-nuclei-templates",
        action="store_true",
        help="Run nuclei -update-templates before vulnerability scanning if templates are missing",
    )
    args = parser.parse_args()

    target = normalize_domain(args.target)
    if not target or "." not in target:
        print("ERROR: Target must be a domain like example.com")
        return 2

    script_dir = os.path.dirname(os.path.abspath(__file__))
    output_dir = args.output or os.path.join(script_dir, f"{target}-{dt.date.today().isoformat()}")
    safe_mkdir(output_dir)
    
    # Configurar logging ANTES de hacer logs
    setup_logging(output_dir)

    # base dirs
    for d in ["subdomains", "passive", "active", "discovery", "scans", "vulns", "waf", "structured"]:
        safe_mkdir(os.path.join(output_dir, d))

    log("INFO", "="*70)
    log("INFO", "SuperReconn - Active/Passive Reconnaissance Pipeline")
    log("INFO", "="*70)

    if not os.path.exists(args.resolvers) or os.path.getsize(args.resolvers) == 0:
        log("ERROR", f"Resolvers file missing/empty: {args.resolvers}")
        return 2
    if not os.path.exists(args.wordlist) or os.path.getsize(args.wordlist) == 0:
        log("ERROR", f"Wordlist missing/empty: {args.wordlist}")
        return 2

    # Validar herramientas requeridas
    validate_environment()

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
            "update_nuclei_templates": args.update_nuclei_templates,
        },
    )

    required_tools = ["massdns", "httpx", "naabu", "nmap"]
    optional_tools = ["subfinder", "amass", "assetfinder", "shuffledns", "katana", "waybackurls", "gf", "nuclei"]
    meta.tools = {t: tool_exists(t) for t in required_tools + optional_tools}
    
    log("INFO", f"Target: {target}")
    log("INFO", f"Scan ID: {meta.scan_id}")
    log("INFO", f"Output: {output_dir}")
    if proxy:
        log("INFO", f"Proxy: {proxy}")

    runner = CommandRunner(timeout_s=1200, quiet_stderr=True)

    artifacts: Dict[str, str] = {}
    findings: List[Finding] = []
    phases: List[PhaseResult] = []

    resolver_count = len([ln for ln in read_text_lines(args.resolvers) if not ln.startswith("#")])
    if resolver_count < 20:
        record_phase(phases, "resolvers", "warning", f"only {resolver_count} resolvers configured; consider updating resolvers.txt", resolver_count)

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
    sub_status = "ok" if subdomains else "warning"
    record_phase(phases, "subdomain_enumeration", sub_status, f"{len(subdomains)} subdomains", len(subdomains))
    subdomains_path = os.path.join(output_dir, "subdomains", "all_subdomains.txt")
    write_text_lines(subdomains_path, subdomains)
    artifacts["subdomains_all"] = subdomains_path
    write_json(os.path.join(output_dir, "structured", "subdomains.json"), {"subdomains": subdomains})

    # Phase 3: DNS resolution (pure Python parsing)
    resolved_domains, resolved_ips, dns_records = run_massdns_resolve(runner, args.resolvers, subdomains or [target])
    dns_status = "ok" if resolved_domains else "warning"
    record_phase(phases, "dns_resolution", dns_status, f"{len(resolved_domains)} domains, {len(resolved_ips)} IPs", len(resolved_domains))
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
    record_phase(phases, "http_discovery", "ok" if http_services else "warning", f"{len(http_services)} services", len(http_services))
    artifacts["active_urls"] = active_urls_path
    write_json(os.path.join(output_dir, "structured", "http_services.json"), {"services": [asdict(s) for s in http_services]})

    # Phase 5: port scanning
    open_ports_path, naabu_ports = run_port_scan(runner, resolved_ips, output_dir, rate_limit=args.rate_limit, proxy=proxy)
    record_phase(phases, "port_scan", "ok" if naabu_ports else "warning", f"{len(naabu_ports)} open ports", len(naabu_ports))
    artifacts["open_ports"] = open_ports_path
    write_json(
        os.path.join(output_dir, "structured", "open_ports.json"),
        {"open_ports": [{"ip": ip, "port": port, "protocol": proto} for ip, port, proto in naabu_ports]},
    )

    # Phase 6: service/version detection via nmap xml
    (nmap_txt, nmap_xml), network_services = run_nmap_service_detection(runner, resolved_ips, naabu_ports, output_dir)
    record_phase(phases, "nmap_services", "ok" if network_services else "warning", f"{len(network_services)} services", len(network_services))
    artifacts["nmap_versions_txt"] = nmap_txt
    artifacts["nmap_versions_xml"] = nmap_xml
    write_json(os.path.join(output_dir, "structured", "network_services.json"), {"services": [asdict(s) for s in network_services]})

    # Phase 7: WAF probing
    if not args.no_waf:
        waf_jsonl, waf_findings, waf_ok = detect_waf_httpx(runner, active_urls_path, output_dir, proxy=proxy)
        artifacts["waf_httpx_jsonl"] = waf_jsonl
        findings.extend(waf_findings)
        waf_status = "ok" if waf_ok else "failed"
        if waf_ok and not waf_findings:
            waf_status = "ok"
        record_phase(
            phases,
            "waf_detection",
            waf_status,
            f"{len(waf_findings)} WAF/CDN indicators" if waf_ok else (runner.last_error or "httpx WAF probe failed"),
            len(waf_findings),
        )
    else:
        record_phase(phases, "waf_detection", "skipped", "disabled via --no-waf")

    # Phase 8: crawling
    if not args.no_crawl:
        katana_path = run_katana(runner, active_urls_path, output_dir, waf_delay_s=args.waf_delay)
        wayback_path = run_wayback(runner, target, output_dir)
        artifacts["katana"] = katana_path
        artifacts["wayback"] = wayback_path
        endpoints_path = merge_endpoints(output_dir, katana_path, wayback_path)
        artifacts["endpoints"] = endpoints_path
        write_json(os.path.join(output_dir, "structured", "endpoints.json"), {"endpoints": read_text_lines(endpoints_path)})
        endpoint_count = len(read_text_lines(endpoints_path))
        record_phase(phases, "crawling", "ok" if endpoint_count else "warning", f"{endpoint_count} endpoints", endpoint_count)
    else:
        endpoints_path = os.path.join(output_dir, "discovery", "discovered_endpoints.txt")
        write_text_lines(endpoints_path, [])
        artifacts["endpoints"] = endpoints_path
        record_phase(phases, "crawling", "skipped", "disabled via --no-crawl")

    # Phase 9: gf filters
    if not args.no_gf:
        gf_out = run_gf_filters(runner, endpoints_path, output_dir, ["xss", "rce", "ssti", "sqli", "ssrf", "lfi", "redirect", "crlf"], waf_delay_s=args.waf_delay)
        artifacts.update({f"gf_{k}": v for k, v in gf_out.items()})
        gf_count = 0
        for pat, pth in gf_out.items():
            for url in read_text_lines(pth):
                gf_count += 1
                findings.append(Finding(category="gf", source=pat, severity="info", target=url, title=f"gf_{pat}", raw={}))
        record_phase(phases, "gf_patterns", "ok", f"{gf_count} pattern matches", gf_count)
    else:
        record_phase(phases, "gf_patterns", "skipped", "disabled via --no-gf")

    # Phase 10: nuclei
    if not args.no_nuclei:
        templates_ok, templates_msg = ensure_nuclei_templates(runner, update=args.update_nuclei_templates)
        record_phase(phases, "nuclei_templates", "ok" if templates_ok else "failed", templates_msg)
        if templates_ok:
            nuclei_paths, nuclei_findings, nuclei_failed = run_nuclei(
                runner,
                active_urls_path,
                output_dir,
                rate_limit=args.rate_limit,
                proxy=proxy,
                waf_delay_s=args.waf_delay,
            )
            artifacts.update({f"nuclei_{k}": v for k, v in nuclei_paths.items()})
            findings.extend(nuclei_findings)
            nuclei_status = "ok" if not nuclei_failed else ("warning" if nuclei_findings else "failed")
            detail = f"{len(nuclei_findings)} findings"
            if nuclei_failed:
                detail += f"; failed categories: {', '.join(nuclei_failed)}"
            record_phase(phases, "nuclei_scan", nuclei_status, detail, len(nuclei_findings))
        else:
            record_phase(phases, "nuclei_scan", "skipped", templates_msg)
    else:
        record_phase(phases, "nuclei_scan", "skipped", "disabled via --no-nuclei")

    # Phase 11: takeover
    if not args.no_takeover:
        takeover_path, takeover_findings, takeover_ok = run_takeover_check(runner, subdomains, output_dir, waf_delay_s=args.waf_delay)
        artifacts["takeover"] = takeover_path
        findings.extend(takeover_findings)
        record_phase(
            phases,
            "subdomain_takeover",
            "ok" if takeover_ok else "failed",
            f"{len(takeover_findings)} takeover candidates" if takeover_ok else (runner.last_error or "takeover check failed"),
            len(takeover_findings),
        )
    else:
        record_phase(phases, "subdomain_takeover", "skipped", "disabled via --no-takeover")

    meta.finished_at_utc = now_utc_iso()
    health_path = write_health_report(output_dir, phases)
    artifacts["health_report"] = health_path
    meta.health = {
        "overall": overall_health_status(phases),
        "phases": [asdict(p) for p in phases],
    }

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
        f"Health: {meta.health.get('overall', 'unknown')}",
    ]
    write_text_lines(summary_path, summary_lines)
    artifacts["summary"] = summary_path

    overall = meta.health.get("overall", "healthy")
    log("SUCCESS", f"Done. Consolidated JSON: {consolidated_path}")
    log("SUCCESS", f"Health report: {health_path} ({overall})")
    log("SUCCESS", f"Execution log: {os.path.join(output_dir, 'execution.log')}")
    log("SUCCESS", f"Summary: {summary_path}")
    if overall != "healthy":
        log("WARNING", f"Scan completed with status '{overall}'; review {health_path}")
    log("INFO", "")
    log("INFO", "Próximos pasos:")
    log("INFO", f"  1. Revisar resultados en: {output_dir}")
    log("INFO", f"  2. (Opcional) Persistir en SQL Server:")
    log("INFO", f"     python3 persist_mssql.py {consolidated_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

