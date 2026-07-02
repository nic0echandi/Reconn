# SuperReconn 🔍

Pipeline profesional de reconocimiento activo/pasivo para mapeo de superficie expuesta de dominios, con salida JSON estructurada e integración con Microsoft SQL Server.

**Versión:** 1.0.0 | **Licencia:** MIT | **Python:** 3.8+

---

## 📋 Tabla de Contenidos

1. [Características](#-características)
2. [Arquitectura](#-arquitectura-de-fases)
3. [Requisitos](#-requisitos)
4. [Instalación](#-instalación)
5. [Configuración](#-configuración)
6. [Uso](#-uso)
7. [Salida](#-salida)
8. [Persistencia SQL Server](#-persistencia-en-sql-server)
9. [Troubleshooting](#-troubleshooting)
10. [Desarrollo](#-desarrollo)
11. [FAQ](#-faq)

---

## ✨ Características

- **Enumeración de subdominios:**
  - Pasiva: `subfinder`, `amass`, `assetfinder`
  - Activa: `shuffledns` con wordlist bruteforce
  
- **Descubrimiento de servicios:**
  - Resolución DNS masiva (`massdns`)
  - Identificación HTTP (`httpx`) con detección de tecnologías
  - Escaneo de puertos (`naabu`)
  - Detección de versiones y servicios (`nmap -sV -sC`)

- **Análisis de seguridad (modular):**
  - Detección de WAF
  - Crawling de endpoints (`katana`, `waybackurls`)
  - Análisis de vulnerabilidades (`nuclei` con 9 categorías)
  - Búsqueda de patrones (`gf`: XSS, RCE, SQLi, SSRF, etc)
  - Verificación de subdomain takeover

- **Salida estructurada:**
  - JSON consolidado con toda la información
  - Archivos intermedios organizados por tipo
  - Log de ejecución completo
  - Resumen ejecutivo

- **Persistencia opcional:**
  - Almacenamiento en Microsoft SQL Server
  - Vistas y procedimientos para análisis

---

## 🏗️ Arquitectura de Fases

```
FASE 1+2: Enumeración de Subdominios
    ├─ Pasiva (subfinder, amass, assetfinder)
    └─ Activa (shuffledns bruteforce)
           ↓
FASE 3: Resolución DNS
    └─ massdns → Dominios resueltos + IPs
           ↓
FASE 4: Descubrimiento HTTP
    └─ httpx → URLs activas + tecnologías
           ↓
FASE 5: Escaneo de Puertos
    └─ naabu → Puertos abiertos
           ↓
FASE 6: Detección de Servicios
    └─ nmap -sV → Versiones + servicios
           ↓
FASE 7: Detección de WAF (opcional)
    └─ httpx probe → WAF detected
           ↓
FASE 8: Crawling de Endpoints (opcional)
    ├─ katana (crawl activo)
    ├─ waybackurls (histórico)
    └─ merge → endpoints consolidados
           ↓
FASE 9: Búsqueda de Patrones (opcional)
    └─ gf filters → URLs potencialmente vulnerables
           ↓
FASE 10: Análisis de Vulnerabilidades (opcional)
    └─ nuclei → CVEs, misconfigs, expociones
           ↓
FASE 11: Verificación de Takeover (opcional)
    └─ nuclei templates → Subdomain takeover
           ↓
OUTPUT: JSON consolidado + Persistencia SQL (opcional)
```

| Fase | Herramienta | Tipo | Duración | Crítica |
|------|-------------|------|----------|---------|
| 1+2  | subfinder, amass, shuffledns | Enumeración | 30-120s | ✅ |
| 3    | massdns | Resolución | 30-60s | ✅ |
| 4    | httpx | Discovery | 1-3m | ✅ |
| 5    | naabu | Port Scan | 2-5m | ✅ |
| 6    | nmap | Versioning | 3-10m | ✅ |
| 7    | httpx | WAF Detection | 1-2m | ❌ |
| 8    | katana, wayback | Crawling | 2-10m | ❌ |
| 9    | gf | Pattern Matching | 1m | ❌ |
| 10   | nuclei | Vuln Scanning | 5-20m | ❌ |
| 11   | nuclei | Takeover Check | 2-5m | ❌ |

---

## 📦 Requisitos

### Sistema Operativo

- **Soportado:** Ubuntu 20.04+, Debian 11+, CentOS 8+, macOS 11+
- **No soportado:** Windows (usar WSL2)

### Python

- Python 3.8 o superior
- pip (administrador de paquetes)
- venv (entorno virtual)

### Herramientas (se instalan por separado)

**Requeridas (críticas):**
- `massdns` - Resolución DNS paralela
- `httpx` - HTTP banner grabbing  
- `naabu` - Escaneo de puertos
- `nmap` - Identificación de servicios

**Opcionales (se omiten si no están disponibles):**
- `subfinder` - Enumeración pasiva de subdominios
- `amass` - OSINT avanzado
- `assetfinder` - Búsqueda de activos
- `shuffledns` - Brute-force DNS
- `katana` - Web crawler activo
- `waybackurls` - URLs históricas
- `gf` - Patrón matching de URLs
- `nuclei` - Template-based vulnerability scanner

### Persistencia SQL Server (opcional)

- `pyodbc` (instalado via pip)
- Driver ODBC 18 para SQL Server (Sistema)
- SQL Server 2019+ o Azure SQL Database

---

## 🚀 Instalación

### 1️⃣ Configuración Inicial

```bash
# Clonar repositorio
git clone https://github.com/tuusuario/SuperReconn.git
cd SuperReconn

# Crear entorno virtual
python3 -m venv venv
source venv/bin/activate  # En Windows: venv\Scripts\activate

# Instalar dependencias Python
pip install --upgrade pip
pip install -r requirements.txt
```

### 2️⃣ Instalar Herramientas (Ubuntu 22.04+)

```bash
# Actualizar paquetes
sudo apt update && sudo apt upgrade -y

# Instalar dependencias
sudo apt install -y \
    git \
    golang-go \
    build-essential \
    pkg-config \
    libpcap-dev \
    nmap

# Configurar Go paths
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin
echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc

# Instalar herramientas Go (se instalan en ~/go/bin)
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/owasp-amass/amass/v4/...@latest
go install -v github.com/tomnomnom/assetfinder@latest
go install -v github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/tomnomnom/waybackurls@latest
go install -v github.com/tomnomnom/gf@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

### 3️⃣ Validar Instalación

```bash
# Verificar herramientas críticas
massdns --version
httpx --version
naabu --help | head -5
nmap --version

# Verificar Python
python3 SuperReconn.py --help
```

### 4️⃣ Configuración (Opcional)

```bash
# Copiar template de configuración
cp .env.example .env

# Editar con tus valores
nano .env

# Cargar variables de entorno
source .env
```

---

## ⚙️ Configuración

### Variables de Entorno

```bash
# Paths
RECON_TOOL_PATH=/custom/bin     # Rutas adicionales para buscar herramientas
RECON_WORDLIST=./wordlists/...  # Wordlist de subdominios
RECON_RESOLVERS=./resolvers.txt # Resolvers DNS

# Performance
RECON_RATE_LIMIT=100            # Límite de tasa (requests/sec)
RECON_WAF_DELAY=1               # Delay entre peticiones (segundos)
RECON_PROXY=http://proxy:8080   # Proxy opcional

# SQL Server (ver sección Persistencia)
MSSQL_SERVER=localhost
MSSQL_DATABASE=SuperReconn
MSSQL_AUTH=sql
MSSQL_USERNAME=sa
MSSQL_PASSWORD=****
```

Ver [.env.example](.env.example) para documentación completa.

---

## 📖 Uso

### Ejecución Básica

```bash
# Scan completo (todas las fases)
python3 SuperReconn.py example.com

# Con salida custom
python3 SuperReconn.py example.com -o ./resultados/example.com-scan1

# Modo rápido (sin crawling ni nuclei)
python3 SuperReconn.py example.com --no-crawl --no-nuclei

# Con proxy
python3 SuperReconn.py example.com --proxy http://127.0.0.1:8080

# Con rate limiting alto (conexión rápida)
python3 SuperReconn.py example.com --rate-limit 500 --waf-delay 0.5
```

### Opciones Avanzadas

```bash
# Deshabilitar fases específicas
python3 SuperReconn.py example.com \
  --no-passive    # Sin enumeración pasiva
  --no-active     # Sin brute-force
  --no-waf        # Sin detección de WAF
  --no-crawl      # Sin katana/wayback
  --no-gf         # Sin patrón matching
  --no-nuclei     # Sin vulnerability scanning
  --no-takeover   # Sin check de takeover

# Combinación: inventario rápido sin análisis de seguridad
python3 SuperReconn.py example.com \
  --no-waf --no-crawl --no-gf --no-nuclei --no-takeover

# Ver ayuda completa
python3 SuperReconn.py --help
```

### Recursos Recomendados

```bash
# Conexión lenta (Rate limited agresivamente)
python3 SuperReconn.py example.com \
  --rate-limit 50 \
  --waf-delay 2

# Máquina baja en recursos
python3 SuperReconn.py example.com \
  --no-nuclei --no-crawl

# Objetivos con WAF fuerte
python3 SuperReconn.py example.com \
  --waf-delay 3 \
  --proxy http://rotating-proxy:8080 \
  --rate-limit 30
```

---

## 📤 Salida

### Estructura de Directorios

```
example.com-2026-07-02/
├── execution.log                    # Log completo de ejecución
├── discovery/
│   ├── summary.txt                 # Resumen ejecutivo
│   ├── resolved_domains.txt        # Dominios resueltos
│   ├── resolved_ips.txt            # IPs resueltas
│   ├── active_urls.txt             # URLs HTTP activas
│   ├── open_ports.txt              # Puertos abiertos
│   ├── waybackurls.txt             # URLs del histórico
│   ├── katana.txt                  # Endpoints descubiertos
│   ├── discovered_endpoints.txt    # Endpoints consolidados
│   ├── httpx.jsonl                 # Salida HTTP detallada
│   └── naabu.jsonl                 # Salida de puertos
├── subdomains/
│   └── all_subdomains.txt          # Todos los subdominios
├── passive/
│   ├── subfinder.txt
│   ├── amass.txt
│   └── assetfinder.txt
├── active/
│   └── shuffledns_bruteforce.txt
├── scans/
│   ├── nmap_versions.txt           # Salida nmap texto
│   ├── nmap_versions.xml           # Salida nmap XML
│   ├── nuclei_cves.jsonl
│   ├── nuclei_exposure.jsonl
│   ├── nuclei_misconfig.jsonl
│   ├── nuclei_panels.jsonl
│   ├── nuclei_tokens.jsonl
│   ├── nuclei_vulns.jsonl
│   ├── nuclei_dns.jsonl
│   ├── nuclei_javascript.jsonl
│   └── nuclei_network.jsonl
├── vulns/
│   ├── gf_xss.txt
│   ├── gf_rce.txt
│   ├── gf_sqli.txt
│   ├── gf_ssrf.txt
│   ├── gf_lfi.txt
│   ├── gf_ssti.txt
│   ├── gf_redirect.txt
│   ├── gf_crlf.txt
│   └── subdomain_takeover.jsonl
├── waf/
│   └── httpx_waf.jsonl             # Detección de WAF
└── structured/
    ├── superreconn.json            # 🎯 JSON consolidado (PRINCIPAL)
    ├── subdomains.json
    ├── dns_records.json
    ├── http_services.json
    ├── open_ports.json
    ├── network_services.json
    └── endpoints.json
```

### Archivo Principal: `superreconn.json`

```json
{
  "meta": {
    "scan_id": "uuid-aqui",
    "target": "example.com",
    "started_at_utc": "2026-07-02T10:30:00+00:00",
    "finished_at_utc": "2026-07-02T11:15:00+00:00",
    "output_dir": "./example.com-2026-07-02",
    "script": "SuperReconn.py",
    "script_version": "1.0.0",
    "args": { ... },
    "tools": {
      "massdns": true,
      "httpx": true,
      "nuclei": false
    }
  },
  "subdomains": ["www.example.com", "api.example.com", ...],
  "resolved_domains": ["www.example.com", ...],
  "resolved_ips": ["1.2.3.4", "5.6.7.8"],
  "dns_records": [...],
  "http_services": [...],
  "open_ports": [...],
  "network_services": [...],
  "findings": [
    {
      "category": "nuclei",
      "source": "cves/2024-xxxx",
      "severity": "high",
      "target": "https://api.example.com",
      "title": "RCE in framework X",
      ...
    }
  ],
  "artifacts": { ... }
}
```

---

## 💾 Persistencia en SQL Server

La persistencia en SQL Server es **COMPLETAMENTE OPCIONAL**. SuperReconn produce JSON válido sin necesidad de SQL Server.

### A) Instalación del Driver ODBC

```bash
# Ubuntu 22.04+
sudo apt-get update
sudo apt-get install -y curl gnupg2 apt-transport-https ca-certificates unixodbc unixodbc-dev

curl https://packages.microsoft.com/keys/microsoft.asc | sudo gpg --dearmor -o /usr/share/keyrings/microsoft-prod.gpg

echo "deb [arch=amd64 signed-by=/usr/share/keyrings/microsoft-prod.gpg] https://packages.microsoft.com/ubuntu/22.04/prod jammy main" | sudo tee /etc/apt/sources.list.d/mssql-release.list

sudo apt-get update
sudo ACCEPT_EULA=Y apt-get install -y msodbcsql18

# Validar
odbcinst -q -d | grep "ODBC Driver 18 for SQL Server"
```

### B) Configurar Base de Datos

```bash
# 1. Crear base de datos en SQL Server (una sola vez)
sqlcmd -S servidor.com -U sa -P password < sql/001_init_database.sql
sqlcmd -S servidor.com -U sa -P password < sql/002_tables_constraints.sql
sqlcmd -S servidor.com -U sa -P password < sql/003_views_procs.sql

# O usar Azure Data Studio / SSMS manualmente
```

### C) Persistir Resultados

```bash
# Después de ejecutar SuperReconn
python3 persist_mssql.py ./example.com-2026-07-02/structured/superreconn.json

# Con credenciales en variables de entorno
export MSSQL_SERVER="sql.server.com"
export MSSQL_DATABASE="SuperReconn"
export MSSQL_AUTH="sql"
export MSSQL_USERNAME="usuario"
export MSSQL_PASSWORD="password"
python3 persist_mssql.py ./example.com-2026-07-02/structured/superreconn.json

# Con flags
python3 persist_mssql.py ./resultados/superreconn.json \
  --server sql.server.com \
  --username sa \
  --password password \
  --database SuperReconn
```

### D) Usar Datos en SQL Server

```sql
-- Ver todos los scans
SELECT ScanRunId, TargetDomain, StartedAtUtc, FinishedAtUtc 
FROM recon.scan_runs 
ORDER BY StartedAtUtc DESC;

-- Dominios de un scan específico
SELECT Domain 
FROM recon.subdomains 
WHERE ScanRunId = 'uuid-aqui';

-- HTTP services vulnerables
SELECT url, status_code, technologies 
FROM recon.http_services_view 
WHERE ScanRunId = 'uuid-aqui' 
AND status_code >= 400;

-- Hallazgos de seguridad
SELECT severity, title, target, category 
FROM recon.findings 
WHERE ScanRunId = 'uuid-aqui' 
AND severity IN ('high', 'critical');
```

---

## 🆘 Troubleshooting

### Herramientas No Encontradas

```
ERROR: massdns not found in PATH or RECON_TOOL_PATH / ~/go/bin / /usr/local/bin
```

**Solución:**
```bash
# Verificar ubicación
which massdns
# o
find ~ -name massdns 2>/dev/null

# Agregar a PATH
export RECON_TOOL_PATH="/path/to/massdns:$RECON_TOOL_PATH"

# O configurar en .env
echo "RECON_TOOL_PATH=$HOME/go/bin" >> .env
```

### Error de Resolvers

```
ERROR: Resolvers file missing/empty: ./resolvers.txt
```

**Solución:**
```bash
# Descargar resolvers públicos
curl https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/http/resolvers.txt -o resolvers.txt

# O usar el wordlist incluido
wget https://raw.githubusercontent.com/tomnomnom/massdns/master/lists/resolvers.txt
```

### Timeout en Comandos

```
WARNING: Command failed (attempt 1/1): timeout
```

**Solución:**
```bash
# Usar flag para aumentar timeout
python3 SuperReconn.py example.com --rate-limit 50  # Más lento

# O reducir objetivos
python3 SuperReconn.py example.com --no-nuclei --no-crawl
```

### Error de Conexión SQL Server

```
ERROR: pyodbc not installed
```

**Solución:**
```bash
pip install pyodbc
```

```
ERROR: Driver ODBC not found
```

**Solución:**
```bash
odbcinst -q -d
# Si no aparece "ODBC Driver 18 for SQL Server", instalar:
sudo ACCEPT_EULA=Y apt-get install -y msodbcsql18
```

### Archivo no tiene permisos de ejecución

```
FileNotFoundError: [Errno 2] No such file or directory: './SuperReconn.py'
```

**Solución:**
```bash
chmod +x SuperReconn.py
python3 SuperReconn.py example.com  # Usar python3 explícitamente
```

---

## 👨‍💻 Desarrollo

### Estructura del Proyecto

```
SuperReconn/
├── SuperReconn.py          # Script principal
├── persist_mssql.py        # Persistencia SQL Server (opcional)
├── requirements.txt        # Dependencias Python
├── .env.example            # Configuración template
├── README.md               # Este archivo
├── CONTRIBUTING.md         # Guía de contribución
├── CHANGELOG.md            # Historial de cambios
├── Makefile                # Automatización
├── sql/                    # Scripts SQL Server
├── wordlists/              # Datos
└── docs/                   # Documentación adicional
```

### Ejecutar Tests

```bash
# Instalar pytest
pip install pytest

# Correr tests
pytest tests/ -v

# Con coverage
pytest tests/ --cov=SuperReconn --cov-report=html
```

### Linting y Formateo

```bash
# Instalar herramientas
pip install black flake8 mypy pylint

# Formatear código
black SuperReconn.py persist_mssql.py

# Validar
flake8 SuperReconn.py
mypy SuperReconn.py
```

Ver [CONTRIBUTING.md](CONTRIBUTING.md) para más detalles.

---

## ❓ FAQ

**P: ¿Necesito SQL Server para usar SuperReconn?**  
R: No. SuperReconn genera JSON válido sin SQL Server. La persistencia es completamente opcional.

**P: ¿Cuánto tiempo toma un escaneo completo?**  
R: Depende del dominio y cantidad de subdominios:
- Pequeño: 10-30 min
- Mediano: 30-120 min
- Grande (500+ subdominos): 2-8 horas

**P: ¿Puedo escanear direcciones IP en lugar de dominios?**  
R: Actualmente, SuperReconn está diseñado para dominios. Para IPs, usa `nmap` directamente.

**P: ¿Necesito credenciales de APIs para servicios como subfinder?**  
R: No son requeridas. Con APIs configuradas, obtienes mejores resultados.

**P: ¿Puedo usar SuperReconn en Windows?**  
R: Oficialmente no. Usa WSL2 (Windows Subsystem for Linux) con Ubuntu.

**P: ¿Se pueden ejecutar múltiples scans en paralelo?**  
R: Sí, cada scan es independiente. Usa directorios de salida diferentes (`-o` flag).

**P: ¿Cómo integro SuperReconn en mis workflows?**  
R: SuperReconn genera JSON que se puede procesar fácilmente:
```python
import json
with open('superreconn.json') as f:
    data = json.load(f)
    for finding in data['findings']:
        print(f"{finding['severity']}: {finding['title']}")
```

---

## 📝 Licencia

Este proyecto está bajo licencia MIT. Ver [LICENSE](LICENSE) para detalles.

## 🤝 Contribuciones

¿Encontraste un bug? ¿Tienes una idea? Ver [CONTRIBUTING.md](CONTRIBUTING.md) para guía de contribución.

## 📞 Soporte

- 📖 [Documentación completa](https://github.com/tuusuario/SuperReconn/wiki)
- 🐛 [Reportar bugs](https://github.com/tuusuario/SuperReconn/issues)
- 💬 [Discussions](https://github.com/tuusuario/SuperReconn/discussions)

---

**Última actualización:** 2026-07-02  
**Versión:** 1.0.0

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
