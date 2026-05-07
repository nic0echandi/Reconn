# SuperReconn

Pipeline de reconocimiento activo/pasivo para mapear superficie expuesta de un dominio, con salida estructurada en JSON y persistencia en Microsoft SQL Server.

## Caracteristicas

- Enumeracion pasiva de subdominios (`subfinder`, `amass`, `assetfinder`)
- Enumeracion activa por fuerza bruta (`shuffledns`)
- Resolucion DNS y normalizacion de activos
- Descubrimiento de servicios HTTP (`httpx`)
- Escaneo de puertos (`naabu`)
- Deteccion de servicios/versiones (`nmap -sV -sC`)
- Modulos opcionales de seguridad: WAF, crawling, `gf`, `nuclei`, takeover
- Salida consolidada en `structured/superreconn.json`
- Persistencia transaccional a SQL Server (`persist_mssql.py`)

## Estructura principal

- `SuperReconn.py`: script principal de reconocimiento
- `persist_mssql.py`: carga resultados JSON en SQL Server
- `sql/001_init_database.sql`: crea base y schema
- `sql/002_tables_constraints.sql`: tablas, PK/FK, indices
- `sql/003_views_procs.sql`: vistas y procedimientos
- `wordlists/subdomains.txt`: wordlist de subdominios
- `resolvers.txt`: resolvers DNS

## Requisitos (Ubuntu / bash)

## 1) Python

```bash
python3 --version
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install pyodbc
```

## 2) Driver ODBC para SQL Server

Ejemplo para Ubuntu 22.04/24.04 (ajusta segun version):

```bash
sudo apt-get update
sudo apt-get install -y curl gnupg2 apt-transport-https ca-certificates unixodbc unixodbc-dev

curl https://packages.microsoft.com/keys/microsoft.asc | sudo gpg --dearmor -o /usr/share/keyrings/microsoft-prod.gpg
echo "deb [arch=amd64 signed-by=/usr/share/keyrings/microsoft-prod.gpg] https://packages.microsoft.com/ubuntu/22.04/prod jammy main" | sudo tee /etc/apt/sources.list.d/mssql-release.list

sudo apt-get update
sudo ACCEPT_EULA=Y apt-get install -y msodbcsql18
```

Verifica que exista el driver:

```bash
odbcinst -q -d | grep "ODBC Driver 18 for SQL Server"
```

## 3) Herramientas de reconocimiento

Debes tener disponibles en PATH (segun el alcance que quieras usar):

- Requeridas para inventario base: `massdns`, `httpx`, `naabu`, `nmap`
- Recomendadas/opcionales: `subfinder`, `amass`, `assetfinder`, `shuffledns`, `katana`, `waybackurls`, `gf`, `nuclei`

Si alguna opcional no esta instalada, el script continua y omite esa fase.

## Inicializacion de base de datos SQL Server

Ejecuta en orden:

1. `sql/001_init_database.sql`
2. `sql/002_tables_constraints.sql`
3. `sql/003_views_procs.sql`

Puedes correrlos desde SSMS, Azure Data Studio o `sqlcmd`.

## Uso de SuperReconn

Ejecucion basica:

```bash
python3 SuperReconn.py ejemplo.com
```

Con salida custom:

```bash
python3 SuperReconn.py ejemplo.com -o ./resultados/ejemplo.com-$(date +%F)
```

Opciones comunes:

```bash
python3 SuperReconn.py ejemplo.com \
  --rate-limit 100 \
  --waf-delay 1 \
  --proxy http://127.0.0.1:8080
```

Desactivar modulos:

```bash
python3 SuperReconn.py ejemplo.com \
  --no-waf --no-crawl --no-gf --no-nuclei --no-takeover
```

Archivo consolidado esperado:

`<output>/structured/superreconn.json`

## Persistencia en SQL Server

### A) SQL Authentication (recomendado en Linux)

```bash
export MSSQL_SERVER="10.0.0.10,1433"
export MSSQL_DATABASE="SuperReconn"
export MSSQL_DRIVER="ODBC Driver 18 for SQL Server"
export MSSQL_AUTH="sql"
export MSSQL_USERNAME="usuario"
export MSSQL_PASSWORD="password"
export MSSQL_ENCRYPT="yes"
export MSSQL_TRUST_SERVER_CERTIFICATE="yes"

python3 persist_mssql.py "./ejemplo.com-2026-04-16/structured/superreconn.json"
```

### B) Windows/Integrated auth en Linux

Disponible con:

```bash
python3 persist_mssql.py "./ruta/structured/superreconn.json" --auth windows
```

Nota: en Linux requiere entorno Kerberos/ODBC integrado correctamente configurado.

## Variables de entorno soportadas

### SuperReconn

- `RECON_TOOL_PATH` (optional; paths to search for CLI tools like `massdns` and `shuffledns`)
- `RECON_RATE_LIMIT` (default `100`)
- `RECON_WAF_DELAY` (default `1`)
- `RECON_PROXY` (default vacio)

### Persistencia MSSQL

- `MSSQL_SERVER` (default `localhost`)
- `MSSQL_DATABASE` (default `SuperReconn`)
- `MSSQL_DRIVER` (default `ODBC Driver 18 for SQL Server`)
- `MSSQL_AUTH` (`sql` en Linux por defecto, `windows` en Windows)
- `MSSQL_USERNAME`
- `MSSQL_PASSWORD`
- `MSSQL_ENCRYPT` (default `yes`)
- `MSSQL_TRUST_SERVER_CERTIFICATE` (default `yes`)
- `MSSQL_TIMEOUT` (default `15`)

## Troubleshooting rapido

- Error `pyodbc not installed`: instala `pip install pyodbc`
- Error de driver ODBC: valida con `odbcinst -q -d`
- No se generan activos: revisa `wordlists/subdomains.txt`, `resolvers.txt` y herramientas en PATH
- Fallas de SQL auth: prueba conectividad a `server,1433` y credenciales

## Uso responsable

Ejecuta este framework solo sobre dominios/sistemas con autorizacion explicita.
