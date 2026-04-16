USE [SuperReconn];
GO

/* Views */

CREATE OR ALTER VIEW recon.v_inventory_hosts_services
AS
SELECT
    t.Domain,
    sr.ScanRunId,
    sr.StartedAtUtc,
    h.IpAddress,
    s.Port,
    s.Protocol,
    s.State,
    s.ServiceName,
    s.Product,
    s.Version,
    s.ExtraInfo
FROM recon.scan_runs sr
JOIN recon.targets t ON t.TargetId = sr.TargetId
JOIN recon.services s ON s.ScanRunId = sr.ScanRunId
JOIN recon.hosts h ON h.HostId = s.HostId;
GO

CREATE OR ALTER VIEW recon.v_inventory_http
AS
SELECT
    t.Domain,
    sr.ScanRunId,
    sr.StartedAtUtc,
    hn.Hostname,
    he.Url,
    he.StatusCode,
    he.Title,
    he.Server,
    he.IpAddress,
    he.Cname
FROM recon.scan_runs sr
JOIN recon.targets t ON t.TargetId = sr.TargetId
JOIN recon.http_endpoints he ON he.ScanRunId = sr.ScanRunId
LEFT JOIN recon.hostnames hn ON hn.HostnameId = he.HostnameId;
GO

CREATE OR ALTER VIEW recon.v_findings
AS
SELECT
    t.Domain,
    sr.ScanRunId,
    sr.StartedAtUtc,
    f.Category,
    f.Source,
    f.Severity,
    f.Target,
    f.Title
FROM recon.scan_runs sr
JOIN recon.targets t ON t.TargetId = sr.TargetId
JOIN recon.findings f ON f.ScanRunId = sr.ScanRunId;
GO

/* Procedures */

CREATE OR ALTER PROCEDURE recon.sp_get_latest_scan_run
    @Domain nvarchar(253)
AS
BEGIN
    SET NOCOUNT ON;

    SELECT TOP (1)
        sr.ScanRunId,
        sr.StartedAtUtc,
        sr.FinishedAtUtc,
        sr.OutputDir,
        sr.ScriptName,
        sr.ScriptVersion
    FROM recon.scan_runs sr
    JOIN recon.targets t ON t.TargetId = sr.TargetId
    WHERE t.Domain = @Domain
    ORDER BY sr.StartedAtUtc DESC;
END
GO

CREATE OR ALTER PROCEDURE recon.sp_get_open_ports_by_domain
    @Domain nvarchar(253),
    @SinceUtc datetime2(0) = NULL
AS
BEGIN
    SET NOCOUNT ON;

    SELECT
        sr.ScanRunId,
        sr.StartedAtUtc,
        h.IpAddress,
        s.Port,
        s.Protocol,
        s.State,
        s.ServiceName,
        s.Product,
        s.Version
    FROM recon.scan_runs sr
    JOIN recon.targets t ON t.TargetId = sr.TargetId
    JOIN recon.services s ON s.ScanRunId = sr.ScanRunId
    JOIN recon.hosts h ON h.HostId = s.HostId
    WHERE t.Domain = @Domain
      AND (@SinceUtc IS NULL OR sr.StartedAtUtc >= @SinceUtc)
    ORDER BY sr.StartedAtUtc DESC, h.IpAddress, s.Port;
END
GO

