/*
  SuperReconn - SQL Server initialization

  Usage (SSMS / sqlcmd):
    1) Run this file to create the database (optional) and schema.
    2) Run 002_tables_constraints.sql
    3) Run 003_views_procs.sql
*/

DECLARE @DbName sysname = N'SuperReconn';

IF DB_ID(@DbName) IS NULL
BEGIN
    DECLARE @sql nvarchar(max) = N'CREATE DATABASE ' + QUOTENAME(@DbName) + N';';
    EXEC (@sql);
END
GO

USE [SuperReconn];
GO

IF NOT EXISTS (SELECT 1 FROM sys.schemas WHERE name = N'recon')
BEGIN
    EXEC (N'CREATE SCHEMA recon AUTHORIZATION dbo;');
END
GO

