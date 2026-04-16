#!/usr/bin/env python3

import argparse
import json
import os
import socket
from typing import Any, Dict, Iterable, List, NoReturn, Optional, Sequence, Tuple


try:
    import pyodbc  # type: ignore
except Exception:  # pragma: no cover
    pyodbc = None  # type: ignore


def die(msg: str, code: int = 2) -> NoReturn:
    print(f"[ERROR] {msg}")
    raise SystemExit(code)


def log(msg: str) -> None:
    print(f"[INFO] {msg}")


def read_json(path: str) -> Dict[str, Any]:
    if not os.path.exists(path):
        die(f"JSON not found: {path}")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def chunked(seq: Sequence[Any], size: int) -> Iterable[Sequence[Any]]:
    for i in range(0, len(seq), size):
        yield seq[i : i + size]


def build_conn_str(
    *,
    driver: str,
    server: str,
    database: str,
    encrypt: str,
    trust_server_certificate: str,
    timeout_s: int,
    auth_mode: str,
    username: Optional[str],
    password: Optional[str],
) -> str:
    parts = [
        f"DRIVER={{{driver}}}",
        f"SERVER={server}",
        f"DATABASE={database}",
        f"Encrypt={encrypt}",
        f"TrustServerCertificate={trust_server_certificate}",
        f"Connection Timeout={timeout_s}",
    ]
    auth_mode = auth_mode.lower().strip()
    if auth_mode in {"windows", "trusted"}:
        parts.append("Trusted_Connection=yes")
    elif auth_mode in {"sql", "sqlauth"}:
        if not username or not password:
            die("SQL auth requires username/password (MSSQL_USERNAME/MSSQL_PASSWORD or flags).")
        parts.append(f"UID={username}")
        parts.append(f"PWD={password}")
    else:
        die("Unknown auth mode. Use: windows | sql")
    return ";".join(parts) + ";"


def ensure_scan_run(cur, scan_run_id: str, target_domain: str, meta: Dict[str, Any]) -> int:
    cur.execute(
        """
        MERGE recon.targets AS t
        USING (SELECT ? AS Domain) AS s
        ON (t.Domain = s.Domain)
        WHEN NOT MATCHED THEN INSERT (Domain) VALUES (s.Domain)
        ;
        """,
        target_domain,
    )
    cur.execute("SELECT TargetId FROM recon.targets WHERE Domain = ?", target_domain)
    row = cur.fetchone()
    if not row:
        die("Failed to resolve TargetId after upsert.")
    target_id = int(row[0])

    started = meta.get("started_at_utc")
    finished = meta.get("finished_at_utc")
    output_dir = meta.get("output_dir")
    script_name = meta.get("script") or "SuperReconn.py"
    script_version = meta.get("script_version")
    args_json = json.dumps(meta.get("args") or {}, ensure_ascii=False)
    hostname = socket.gethostname()

    cur.execute(
        """
        IF NOT EXISTS (SELECT 1 FROM recon.scan_runs WHERE ScanRunId = ?)
        BEGIN
            INSERT INTO recon.scan_runs
                (ScanRunId, TargetId, StartedAtUtc, FinishedAtUtc, OutputDir, ScriptName, ScriptVersion, ArgsJson, Hostname)
            VALUES
                (?, ?, TRY_CONVERT(datetime2(0), ?), TRY_CONVERT(datetime2(0), ?), ?, ?, ?, ?, ?);
        END
        """,
        scan_run_id,
        scan_run_id,
        target_id,
        started,
        finished,
        output_dir,
        script_name,
        script_version,
        args_json,
        hostname,
    )
    return target_id


def upsert_hosts(cur, ips: List[str]) -> None:
    if not ips:
        return
    for batch in chunked(ips, 500):
        params = [(ip,) for ip in batch]
        cur.fast_executemany = True
        cur.executemany(
            """
            MERGE recon.hosts AS h
            USING (SELECT ? AS IpAddress) AS s
            ON (h.IpAddress = s.IpAddress)
            WHEN NOT MATCHED THEN INSERT (IpAddress) VALUES (s.IpAddress)
            ;
            """,
            params,
        )


def upsert_hostnames(cur, target_id: int, hostnames: List[str]) -> None:
    if not hostnames:
        return
    params = [(target_id, hn) for hn in hostnames]
    for batch in chunked(params, 500):
        cur.fast_executemany = True
        cur.executemany(
            """
            MERGE recon.hostnames AS hn
            USING (SELECT ? AS TargetId, ? AS Hostname) AS s
            ON (hn.TargetId = s.TargetId AND hn.Hostname = s.Hostname)
            WHEN NOT MATCHED THEN INSERT (TargetId, Hostname) VALUES (s.TargetId, s.Hostname)
            ;
            """,
            list(batch),
        )


def load_host_id_map(cur, ips: List[str]) -> Dict[str, int]:
    if not ips:
        return {}
    host_map: Dict[str, int] = {}
    for batch in chunked(ips, 1000):
        q_marks = ",".join("?" for _ in batch)
        cur.execute(f"SELECT HostId, IpAddress FROM recon.hosts WHERE IpAddress IN ({q_marks})", list(batch))
        for host_id, ip in cur.fetchall():
            host_map[str(ip)] = int(host_id)
    return host_map


def load_hostname_id_map(cur, target_id: int, hostnames: List[str]) -> Dict[str, int]:
    if not hostnames:
        return {}
    hn_map: Dict[str, int] = {}
    for batch in chunked(hostnames, 1000):
        q_marks = ",".join("?" for _ in batch)
        cur.execute(
            f"SELECT HostnameId, Hostname FROM recon.hostnames WHERE TargetId = ? AND Hostname IN ({q_marks})",
            [target_id, *batch],
        )
        for hn_id, hn in cur.fetchall():
            hn_map[str(hn)] = int(hn_id)
    return hn_map


def insert_dns_records(cur, scan_run_id: str, hn_id_map: Dict[str, int], dns_records: List[Dict[str, Any]]) -> None:
    rows: List[Tuple[Any, ...]] = []
    for r in dns_records:
        name = r.get("name")
        rtype = r.get("rtype")
        value = r.get("value")
        ttl = r.get("ttl")
        if not name or not rtype or value is None:
            continue
        hn_id = hn_id_map.get(name)
        if not hn_id:
            continue
        rows.append((scan_run_id, hn_id, str(rtype), str(value), int(ttl) if ttl is not None else None))
    if not rows:
        return
    cur.fast_executemany = True
    cur.executemany(
        """
        INSERT INTO recon.dns_records (ScanRunId, HostnameId, RecordType, Value, Ttl)
        SELECT ?, ?, ?, ?, ?
        WHERE NOT EXISTS (
            SELECT 1 FROM recon.dns_records
            WHERE ScanRunId = ? AND HostnameId = ? AND RecordType = ? AND Value = ?
        );
        """,
        [(sr, hn, rt, v, ttl, sr, hn, rt, v) for (sr, hn, rt, v, ttl) in rows],
    )


def insert_services(cur, scan_run_id: str, host_id_map: Dict[str, int], services: List[Dict[str, Any]]) -> None:
    rows: List[Tuple[Any, ...]] = []
    for s in services:
        ip = s.get("ip")
        host_id = host_id_map.get(ip)
        if not host_id:
            continue
        port = s.get("port")
        proto = s.get("protocol") or "tcp"
        state = s.get("state") or "unknown"
        try:
            port_i = int(port)
        except (TypeError, ValueError):
            continue
        cpe_json = json.dumps(s.get("cpe") or [], ensure_ascii=False)
        rows.append(
            (
                scan_run_id,
                host_id,
                port_i,
                str(proto),
                str(state),
                s.get("service_name"),
                s.get("product"),
                s.get("version"),
                s.get("extrainfo"),
                cpe_json,
            )
        )
    if not rows:
        return
    cur.fast_executemany = True
    cur.executemany(
        """
        INSERT INTO recon.services
            (ScanRunId, HostId, Port, Protocol, State, ServiceName, Product, Version, ExtraInfo, CpeJson)
        SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
        WHERE NOT EXISTS (
            SELECT 1 FROM recon.services
            WHERE ScanRunId = ? AND HostId = ? AND Port = ? AND Protocol = ?
        );
        """,
        [
            (
                sr,
                hid,
                port,
                proto,
                state,
                svc,
                prod,
                ver,
                extra,
                cpe,
                sr,
                hid,
                port,
                proto,
            )
            for (sr, hid, port, proto, state, svc, prod, ver, extra, cpe) in rows
        ],
    )


def insert_http_endpoints(cur, scan_run_id: str, hn_id_map: Dict[str, int], http_services: List[Dict[str, Any]]) -> None:
    rows: List[Tuple[Any, ...]] = []
    tech_links: List[Tuple[str, str]] = []
    for s in http_services:
        url = s.get("url")
        host = s.get("host")
        if not url:
            continue
        hn_id = hn_id_map.get(host) if host else None
        raw_json = json.dumps(s.get("raw") or {}, ensure_ascii=False)
        rows.append(
            (
                scan_run_id,
                hn_id,
                url,
                s.get("scheme"),
                s.get("port"),
                s.get("status_code"),
                s.get("title"),
                s.get("server"),
                s.get("ip"),
                s.get("cname"),
                raw_json,
            )
        )
        for tech in (s.get("technologies") or []):
            if tech and isinstance(tech, str):
                tech_links.append((url, tech))

    if not rows:
        return

    cur.fast_executemany = True
    cur.executemany(
        """
        INSERT INTO recon.http_endpoints
            (ScanRunId, HostnameId, Url, Scheme, Port, StatusCode, Title, Server, IpAddress, Cname, RawJson)
        SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
        WHERE NOT EXISTS (
            SELECT 1 FROM recon.http_endpoints WHERE ScanRunId = ? AND Url = ?
        );
        """,
        [
            (*r, scan_run_id, r[2])
            for r in rows
        ],
    )

    if not tech_links:
        return

    # Upsert technologies
    techs = sorted({t for _, t in tech_links})
    if techs:
        for batch in chunked(techs, 500):
            cur.fast_executemany = True
            cur.executemany(
                """
                MERGE recon.technologies AS t
                USING (SELECT ? AS Name) AS s
                ON (t.Name = s.Name)
                WHEN NOT MATCHED THEN INSERT (Name) VALUES (s.Name)
                ;
                """,
                [(t,) for t in batch],
            )

    # Map URL -> HttpEndpointId
    urls = sorted({u for u, _ in tech_links})
    endpoint_id_by_url: Dict[str, int] = {}
    for batch in chunked(urls, 800):
        q_marks = ",".join("?" for _ in batch)
        cur.execute(
            f"SELECT HttpEndpointId, Url FROM recon.http_endpoints WHERE ScanRunId = ? AND Url IN ({q_marks})",
            [scan_run_id, *batch],
        )
        for eid, url in cur.fetchall():
            endpoint_id_by_url[str(url)] = int(eid)

    # Map tech -> TechnologyId
    tech_id_by_name: Dict[str, int] = {}
    for batch in chunked(techs, 800):
        q_marks = ",".join("?" for _ in batch)
        cur.execute(f"SELECT TechnologyId, Name FROM recon.technologies WHERE Name IN ({q_marks})", list(batch))
        for tid, name in cur.fetchall():
            tech_id_by_name[str(name)] = int(tid)

    join_rows: List[Tuple[int, int]] = []
    for url, tech in tech_links:
        eid = endpoint_id_by_url.get(url)
        tid = tech_id_by_name.get(tech)
        if eid and tid:
            join_rows.append((eid, tid))
    if not join_rows:
        return
    join_rows = list({(eid, tid) for eid, tid in join_rows})
    cur.fast_executemany = True
    cur.executemany(
        """
        INSERT INTO recon.http_endpoint_technologies (HttpEndpointId, TechnologyId)
        SELECT ?, ?
        WHERE NOT EXISTS (
            SELECT 1 FROM recon.http_endpoint_technologies WHERE HttpEndpointId = ? AND TechnologyId = ?
        );
        """,
        [(eid, tid, eid, tid) for eid, tid in join_rows],
    )


def insert_findings(cur, scan_run_id: str, findings: List[Dict[str, Any]]) -> None:
    rows: List[Tuple[Any, ...]] = []
    for f in findings:
        if not f.get("category") or not f.get("source"):
            continue
        rows.append(
            (
                scan_run_id,
                str(f.get("category")),
                str(f.get("source")),
                f.get("severity"),
                f.get("target"),
                f.get("title"),
                json.dumps(f.get("raw") or {}, ensure_ascii=False),
            )
        )
    if not rows:
        return
    cur.fast_executemany = True
    cur.executemany(
        """
        INSERT INTO recon.findings (ScanRunId, Category, Source, Severity, Target, Title, RawJson)
        VALUES (?, ?, ?, ?, ?, ?, ?);
        """,
        rows,
    )


def insert_artifacts(cur, scan_run_id: str, artifacts: Dict[str, str]) -> None:
    rows = [(scan_run_id, k, v) for k, v in artifacts.items() if k and v]
    if not rows:
        return
    cur.fast_executemany = True
    cur.executemany(
        """
        INSERT INTO recon.artifacts (ScanRunId, ArtifactKey, ArtifactPath)
        SELECT ?, ?, ?
        WHERE NOT EXISTS (
            SELECT 1 FROM recon.artifacts WHERE ScanRunId = ? AND ArtifactKey = ?
        );
        """,
        [(sr, k, p, sr, k) for (sr, k, p) in rows],
    )


def main() -> int:
    if pyodbc is None:
        die("pyodbc is not installed. Install it first (pip install pyodbc).")

    ap = argparse.ArgumentParser(description="Persist SuperReconn structured JSON into SQL Server")
    ap.add_argument("json_path", help="Path to structured/superreconn.json")
    ap.add_argument("--server", default=os.getenv("MSSQL_SERVER", "localhost"))
    ap.add_argument("--database", default=os.getenv("MSSQL_DATABASE", "SuperReconn"))
    ap.add_argument("--driver", default=os.getenv("MSSQL_DRIVER", "ODBC Driver 18 for SQL Server"))
    ap.add_argument("--schema", default=os.getenv("MSSQL_SCHEMA", "recon"))

    default_auth = os.getenv("MSSQL_AUTH", "windows" if os.name == "nt" else "sql").lower()
    ap.add_argument("--auth", choices=["windows", "sql"], default=default_auth)
    ap.add_argument("--username", default=os.getenv("MSSQL_USERNAME", ""))
    ap.add_argument("--password", default=os.getenv("MSSQL_PASSWORD", ""))
    ap.add_argument("--encrypt", default=os.getenv("MSSQL_ENCRYPT", "yes"))
    ap.add_argument("--trust-server-certificate", default=os.getenv("MSSQL_TRUST_SERVER_CERTIFICATE", "yes"))
    ap.add_argument("--timeout", type=int, default=int(os.getenv("MSSQL_TIMEOUT", "15")))
    args = ap.parse_args()
    if args.auth == "windows" and os.name != "nt":
        log("Using --auth windows on Linux requires Kerberos/ODBC integrated auth configured in the host.")

    data = read_json(args.json_path)
    meta = data.get("meta") or {}
    scan_run_id = meta.get("scan_id")
    target_domain = meta.get("target")
    if not scan_run_id or not target_domain:
        die("Invalid structured JSON: meta.scan_id/meta.target are required.")

    if args.schema != "recon":
        log("Note: scripts create schema 'recon'. If you changed MSSQL_SCHEMA, ensure the DB objects exist there.")

    conn_str = build_conn_str(
        driver=args.driver,
        server=args.server,
        database=args.database,
        encrypt=args.encrypt,
        trust_server_certificate=args.trust_server_certificate,
        timeout_s=args.timeout,
        auth_mode=args.auth,
        username=args.username or None,
        password=args.password or None,
    )

    log(f"Connecting to SQL Server: server={args.server} database={args.database} auth={args.auth}")
    conn = pyodbc.connect(conn_str, autocommit=False)
    try:
        cur = conn.cursor()

        target_id = ensure_scan_run(cur, scan_run_id, target_domain, meta)

        resolved_ips = [ip for ip in (data.get("resolved_ips") or []) if isinstance(ip, str) and ip.strip()]
        hostnames = []
        for hn in (data.get("subdomains") or []):
            if isinstance(hn, str) and hn.strip():
                hostnames.append(hn.strip().lower())
        for hn in (data.get("resolved_domains") or []):
            if isinstance(hn, str) and hn.strip():
                hostnames.append(hn.strip().lower())
        hostnames = sorted(set(hostnames))

        upsert_hosts(cur, resolved_ips)
        upsert_hostnames(cur, target_id, hostnames)

        host_id_map = load_host_id_map(cur, resolved_ips)
        hn_id_map = load_hostname_id_map(cur, target_id, hostnames)

        insert_dns_records(cur, scan_run_id, hn_id_map, data.get("dns_records") or [])
        insert_services(cur, scan_run_id, host_id_map, data.get("network_services") or [])
        insert_http_endpoints(cur, scan_run_id, hn_id_map, data.get("http_services") or [])
        insert_findings(cur, scan_run_id, data.get("findings") or [])
        insert_artifacts(cur, scan_run_id, data.get("artifacts") or {})

        conn.commit()
        log("Import committed successfully.")
        return 0
    except Exception as e:
        conn.rollback()
        die(f"Import failed, transaction rolled back: {e}", code=1)
    finally:
        conn.close()


if __name__ == "__main__":
    raise SystemExit(main())

