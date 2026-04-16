USE [SuperReconn];
GO

/* Core entities */

IF OBJECT_ID(N'recon.targets', N'U') IS NULL
BEGIN
    CREATE TABLE recon.targets (
        TargetId int IDENTITY(1,1) NOT NULL CONSTRAINT PK_targets PRIMARY KEY,
        Domain nvarchar(253) NOT NULL,
        CreatedAt datetime2(0) NOT NULL CONSTRAINT DF_targets_CreatedAt DEFAULT (sysutcdatetime()),
        CONSTRAINT UQ_targets_Domain UNIQUE (Domain)
    );
END
GO

IF OBJECT_ID(N'recon.scan_runs', N'U') IS NULL
BEGIN
    CREATE TABLE recon.scan_runs (
        ScanRunId uniqueidentifier NOT NULL CONSTRAINT PK_scan_runs PRIMARY KEY,
        TargetId int NOT NULL,
        StartedAtUtc datetime2(0) NOT NULL,
        FinishedAtUtc datetime2(0) NULL,
        OutputDir nvarchar(1024) NULL,
        ScriptName nvarchar(128) NULL,
        ScriptVersion nvarchar(64) NULL,
        ArgsJson nvarchar(max) NULL,
        Hostname nvarchar(255) NULL CONSTRAINT DF_scan_runs_Hostname DEFAULT (HOST_NAME()),
        InsertedAtUtc datetime2(0) NOT NULL CONSTRAINT DF_scan_runs_InsertedAtUtc DEFAULT (sysutcdatetime()),
        CONSTRAINT FK_scan_runs_targets FOREIGN KEY (TargetId) REFERENCES recon.targets(TargetId)
    );
    CREATE INDEX IX_scan_runs_TargetId_StartedAtUtc ON recon.scan_runs(TargetId, StartedAtUtc DESC);
END
GO

IF OBJECT_ID(N'recon.hosts', N'U') IS NULL
BEGIN
    CREATE TABLE recon.hosts (
        HostId int IDENTITY(1,1) NOT NULL CONSTRAINT PK_hosts PRIMARY KEY,
        IpAddress varchar(45) NOT NULL,
        FirstSeenAtUtc datetime2(0) NOT NULL CONSTRAINT DF_hosts_FirstSeenAtUtc DEFAULT (sysutcdatetime()),
        CONSTRAINT UQ_hosts_IpAddress UNIQUE (IpAddress)
    );
END
GO

IF OBJECT_ID(N'recon.hostnames', N'U') IS NULL
BEGIN
    CREATE TABLE recon.hostnames (
        HostnameId int IDENTITY(1,1) NOT NULL CONSTRAINT PK_hostnames PRIMARY KEY,
        TargetId int NOT NULL,
        Hostname nvarchar(253) NOT NULL,
        FirstSeenAtUtc datetime2(0) NOT NULL CONSTRAINT DF_hostnames_FirstSeenAtUtc DEFAULT (sysutcdatetime()),
        CONSTRAINT FK_hostnames_targets FOREIGN KEY (TargetId) REFERENCES recon.targets(TargetId),
        CONSTRAINT UQ_hostnames_TargetId_Hostname UNIQUE (TargetId, Hostname)
    );
    CREATE INDEX IX_hostnames_Hostname ON recon.hostnames(Hostname);
END
GO

/* DNS */

IF OBJECT_ID(N'recon.dns_records', N'U') IS NULL
BEGIN
    CREATE TABLE recon.dns_records (
        DnsRecordId bigint IDENTITY(1,1) NOT NULL CONSTRAINT PK_dns_records PRIMARY KEY,
        ScanRunId uniqueidentifier NOT NULL,
        HostnameId int NOT NULL,
        RecordType varchar(16) NOT NULL,
        Value nvarchar(1024) NOT NULL,
        Ttl int NULL,
        InsertedAtUtc datetime2(0) NOT NULL CONSTRAINT DF_dns_records_InsertedAtUtc DEFAULT (sysutcdatetime()),
        CONSTRAINT FK_dns_records_scan_runs FOREIGN KEY (ScanRunId) REFERENCES recon.scan_runs(ScanRunId),
        CONSTRAINT FK_dns_records_hostnames FOREIGN KEY (HostnameId) REFERENCES recon.hostnames(HostnameId),
        CONSTRAINT UQ_dns_records_ScanRun_Host_RType_Value UNIQUE (ScanRunId, HostnameId, RecordType, Value)
    );
    CREATE INDEX IX_dns_records_HostnameId ON recon.dns_records(HostnameId);
    CREATE INDEX IX_dns_records_RecordType ON recon.dns_records(RecordType);
END
GO

/* Network services */

IF OBJECT_ID(N'recon.services', N'U') IS NULL
BEGIN
    CREATE TABLE recon.services (
        ServiceId bigint IDENTITY(1,1) NOT NULL CONSTRAINT PK_services PRIMARY KEY,
        ScanRunId uniqueidentifier NOT NULL,
        HostId int NOT NULL,
        Port int NOT NULL,
        Protocol varchar(8) NOT NULL,
        State varchar(16) NOT NULL,
        ServiceName nvarchar(64) NULL,
        Product nvarchar(128) NULL,
        Version nvarchar(128) NULL,
        ExtraInfo nvarchar(256) NULL,
        CpeJson nvarchar(max) NULL,
        InsertedAtUtc datetime2(0) NOT NULL CONSTRAINT DF_services_InsertedAtUtc DEFAULT (sysutcdatetime()),
        CONSTRAINT FK_services_scan_runs FOREIGN KEY (ScanRunId) REFERENCES recon.scan_runs(ScanRunId),
        CONSTRAINT FK_services_hosts FOREIGN KEY (HostId) REFERENCES recon.hosts(HostId),
        CONSTRAINT UQ_services_ScanRun_Host_Port_Proto UNIQUE (ScanRunId, HostId, Port, Protocol)
    );
    CREATE INDEX IX_services_HostId_Port ON recon.services(HostId, Port);
    CREATE INDEX IX_services_ServiceName ON recon.services(ServiceName);
END
GO

/* HTTP endpoints */

IF OBJECT_ID(N'recon.http_endpoints', N'U') IS NULL
BEGIN
    CREATE TABLE recon.http_endpoints (
        HttpEndpointId bigint IDENTITY(1,1) NOT NULL CONSTRAINT PK_http_endpoints PRIMARY KEY,
        ScanRunId uniqueidentifier NOT NULL,
        HostnameId int NULL,
        Url nvarchar(2048) NOT NULL,
        Scheme varchar(16) NULL,
        Port int NULL,
        StatusCode int NULL,
        Title nvarchar(512) NULL,
        Server nvarchar(128) NULL,
        IpAddress varchar(45) NULL,
        Cname nvarchar(1024) NULL,
        RawJson nvarchar(max) NULL,
        InsertedAtUtc datetime2(0) NOT NULL CONSTRAINT DF_http_endpoints_InsertedAtUtc DEFAULT (sysutcdatetime()),
        CONSTRAINT FK_http_endpoints_scan_runs FOREIGN KEY (ScanRunId) REFERENCES recon.scan_runs(ScanRunId),
        CONSTRAINT FK_http_endpoints_hostnames FOREIGN KEY (HostnameId) REFERENCES recon.hostnames(HostnameId),
        CONSTRAINT UQ_http_endpoints_ScanRun_Url UNIQUE (ScanRunId, Url)
    );
    CREATE INDEX IX_http_endpoints_HostnameId ON recon.http_endpoints(HostnameId);
    CREATE INDEX IX_http_endpoints_StatusCode ON recon.http_endpoints(StatusCode);
END
GO

IF OBJECT_ID(N'recon.technologies', N'U') IS NULL
BEGIN
    CREATE TABLE recon.technologies (
        TechnologyId int IDENTITY(1,1) NOT NULL CONSTRAINT PK_technologies PRIMARY KEY,
        Name nvarchar(128) NOT NULL,
        CreatedAtUtc datetime2(0) NOT NULL CONSTRAINT DF_technologies_CreatedAtUtc DEFAULT (sysutcdatetime()),
        CONSTRAINT UQ_technologies_Name UNIQUE (Name)
    );
END
GO

IF OBJECT_ID(N'recon.http_endpoint_technologies', N'U') IS NULL
BEGIN
    CREATE TABLE recon.http_endpoint_technologies (
        HttpEndpointId bigint NOT NULL,
        TechnologyId int NOT NULL,
        CONSTRAINT PK_http_endpoint_technologies PRIMARY KEY (HttpEndpointId, TechnologyId),
        CONSTRAINT FK_http_endpoint_technologies_http_endpoints FOREIGN KEY (HttpEndpointId) REFERENCES recon.http_endpoints(HttpEndpointId),
        CONSTRAINT FK_http_endpoint_technologies_technologies FOREIGN KEY (TechnologyId) REFERENCES recon.technologies(TechnologyId)
    );
END
GO

/* Findings */

IF OBJECT_ID(N'recon.findings', N'U') IS NULL
BEGIN
    CREATE TABLE recon.findings (
        FindingId bigint IDENTITY(1,1) NOT NULL CONSTRAINT PK_findings PRIMARY KEY,
        ScanRunId uniqueidentifier NOT NULL,
        Category varchar(32) NOT NULL,
        Source nvarchar(256) NOT NULL,
        Severity varchar(32) NULL,
        Target nvarchar(2048) NULL,
        Title nvarchar(512) NULL,
        RawJson nvarchar(max) NULL,
        InsertedAtUtc datetime2(0) NOT NULL CONSTRAINT DF_findings_InsertedAtUtc DEFAULT (sysutcdatetime()),
        CONSTRAINT FK_findings_scan_runs FOREIGN KEY (ScanRunId) REFERENCES recon.scan_runs(ScanRunId)
    );
    CREATE INDEX IX_findings_Category ON recon.findings(Category);
    CREATE INDEX IX_findings_Severity ON recon.findings(Severity);
END
GO

/* Artifacts */

IF OBJECT_ID(N'recon.artifacts', N'U') IS NULL
BEGIN
    CREATE TABLE recon.artifacts (
        ArtifactId bigint IDENTITY(1,1) NOT NULL CONSTRAINT PK_artifacts PRIMARY KEY,
        ScanRunId uniqueidentifier NOT NULL,
        ArtifactKey nvarchar(128) NOT NULL,
        ArtifactPath nvarchar(2048) NOT NULL,
        InsertedAtUtc datetime2(0) NOT NULL CONSTRAINT DF_artifacts_InsertedAtUtc DEFAULT (sysutcdatetime()),
        CONSTRAINT FK_artifacts_scan_runs FOREIGN KEY (ScanRunId) REFERENCES recon.scan_runs(ScanRunId),
        CONSTRAINT UQ_artifacts_ScanRun_Key UNIQUE (ScanRunId, ArtifactKey)
    );
END
GO

