# Changelog

Todos los cambios notables en SuperReconn serán documentados en este archivo.

El formato es basado en [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) y este proyecto adhiere a [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] - 2026-07-02

### ✨ Features

#### Core
- **Pipeline completo de reconocimiento activo/pasivo**
  - Enumeración pasiva: `subfinder`, `amass`, `assetfinder`
  - Enumeración activa: `shuffledns` brute-force
  - Resolución DNS masiva: `massdns`
  - Descubrimiento HTTP: `httpx` con detección de tecnologías
  - Escaneo de puertos: `naabu`
  - Detección de servicios: `nmap -sV -sC`

#### Análisis de Seguridad
- Detección de WAF (`httpx` probes)
- Crawling de endpoints (`katana`, `waybackurls`)
- Análisis de vulnerabilidades (`nuclei` con 9 categorías):
  - CVEs
  - Exposición de datos
  - Misconfiguración
  - Paneles expuestos
  - Tokens expuestos
  - Vulnerabilidades generales
  - DNS
  - JavaScript
  - Network
- Búsqueda de patrones (`gf`): XSS, RCE, SQLi, SSRF, LFI, SSTI, Redirect, CRLF
- Verificación de subdomain takeover

#### Salida y Persistencia
- **Salida JSON estructurada** con toda la información de reconocimiento
- Archivos organizados por tipo (subdomains, discovery, scans, vulns, waf)
- Log de ejecución completo en `execution.log`
- Resumen ejecutivo en `summary.txt`
- **Persistencia opcional en SQL Server** mediante `persist_mssql.py`
- Vistas y procedimientos SQL para análisis

#### Funcionalidades
- Modularidad: fases opcionales para adaptar a diferentes escenarios
- Rate limiting configurable
- Delay configurable para eludir WAF
- Proxy support
- Reintentos automáticos con backoff exponencial
- Resolución robusta de ejecutables en múltiples directorios
- Logging a consola y archivo

### 🔧 Infraestructura

- **Setup automatizado** mediante `setup.sh`
- **Makefile** para tareas comunes (lint, test, clean)
- **Dockerización preparada** (estructura lista para Dockerfile)
- **CI/CD ready** (GitHub Actions structure)
- **Python 3.8+** soportado
- **Multiplataforma** (Linux, macOS, WSL2)

### 📖 Documentación

- **README.md completo** con:
  - Tabla de contenidos
  - Arquitectura de fases
  - Requisitos por sistema
  - Guía de instalación paso a paso
  - Configuración detallada
  - Ejemplos de uso
  - Troubleshooting expandido
  - FAQ
- **CONTRIBUTING.md** para desarrollo
- **.env.example** totalmente documentado
- **Docstrings** completos en código Python
- **Type hints** en todas las funciones

### ⚙️ Configuración

- Variables de entorno:
  - `RECON_TOOL_PATH`: paths custom para herramientas
  - `RECON_RATE_LIMIT`: control de tasa
  - `RECON_WAF_DELAY`: delay para eludir WAF
  - `RECON_PROXY`: soporte para proxy
  - `MSSQL_*`: configuración de SQL Server
- Flags de CLI para cada opción
- Archivo `.env.example` de referencia

### 🐛 Fixes (Iniciales)

- N/A (primera release)

### 📊 Cambios Internos

- Código base limpio y modular
- Manejo robusto de errores
- Dataclasses para estructuras de datos
- Type hints en todo el código
- Logging a archivo y consola

---

## [Unreleased]

## [1.1.0] - 2026-08-13

### Added
- Health report post-scan (`discovery/health_report.txt` + `meta.health` en JSON)
- Flag `--update-nuclei-templates` para actualizar templates antes del escaneo
- Validación de templates nuclei por categoría antes de ejecutar

### Fixed
- Rutas de templates nuclei v3 (`http/cves/` en lugar de `cves/`)
- Nuclei/takeover usan archivo `-l` en lugar de `-l -` con stdin
- Detección WAF: flags httpx corregidos (`-cdn -cname` en lugar de `-cname-probe`)
- WAF findings incluyen `cdn_name` / `cdn_type` cuando httpx los detecta

### Changed
- `setup.sh`: instala massdns, descarga resolvers si hay pocos, actualiza templates nuclei
- `.gitignore`: excluye outputs de scan y entornos Python
- README: eliminada sección duplicada

### Planeado para el Futuro

#### Features Propuestas
- [ ] Interfaz web (Flask/FastAPI)
- [ ] API REST
- [ ] Soporte para múltiples bases de datos (MySQL, PostgreSQL)
- [ ] Exportación a formatos adicionales (Excel, PDF)
- [ ] Integración con herramientas SIEM
- [ ] Webhooks para notificaciones
- [ ] Histórico de scans y comparación
- [ ] Reportes automatizados
- [ ] Plugin system
- [ ] Escalado con Kubernetes

#### Mejoras Planeadas
- [ ] Performance: paralelización adicional
- [ ] UX: barra de progreso en tiempo real
- [ ] Seguridad: encriptación de credenciales
- [ ] Documentación: video tutorials
- [ ] Testing: cobertura del 80%+
- [ ] CI/CD: GitHub Actions, GitLab CI
- [ ] Containers: Dockerfile oficial, Docker Compose

#### Herramientas Potenciales
- [ ] `nuclei` versioning para reproducibilidad
- [ ] `dnsx` para más opciones de DNS
- [ ] `httpprobe` como alternativa a `httpx`
- [ ] `shodan` integration
- [ ] `censys` integration

---

## Notas de Versión

### v1.0.0 - Release Inicial

SuperReconn v1.0.0 representa el release inicial del proyecto con:

- ✅ Pipeline completo de reconocimiento
- ✅ 11 fases de análisis
- ✅ Salida JSON estructurada
- ✅ Persistencia SQL Server
- ✅ Documentación completa
- ✅ Setup automatizado
- ✅ Multiplataforma (Linux/macOS/WSL2)

**Estado:** Producción (estable)

**Requisitos Mínimos:**
- Python 3.8+
- Ubuntu 20.04+ / Debian 11+ / macOS 11+
- 4GB RAM mínimo
- 10GB espacio en disco

**Testeado en:**
- Ubuntu 22.04 LTS
- Ubuntu 20.04 LTS
- Debian 11
- macOS 12+ (con Homebrew)
- WSL2 Ubuntu

---

## Formato de Changelog

Este changelog sigue estos convenciones:

- **Added** para nuevas features
- **Changed** para cambios en funcionalidad existente
- **Deprecated** para features que serán removidas pronto
- **Removed** para features removidas
- **Fixed** para bug fixes
- **Security** para fixes de seguridad

---

## Cómo Reportar Cambios

Para contribuir cambios a este changelog:

1. Abre un PR con el cambio
2. Usa la sección `[Unreleased]` mientras está en desarrollo
3. Cuando se publica una versión, mueve cambios a una sección fechada
4. Sigue el formato de versión `[X.Y.Z] - YYYY-MM-DD`

---

## Links

- [Releases](https://github.com/tuusuario/SuperReconn/releases)
- [Issues](https://github.com/tuusuario/SuperReconn/issues)
- [Pull Requests](https://github.com/tuusuario/SuperReconn/pulls)

---

**Última actualización:** 2026-07-02  
**Mantenido por:** SuperReconn Team
