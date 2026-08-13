#!/bin/bash

################################################################################
# SuperReconn Setup Script
#
# Instalación completamente automatizada de SuperReconn en Ubuntu/Debian
#
# Uso:
#   chmod +x setup.sh
#   ./setup.sh          # Instalación completa
#   ./setup.sh --help   # Ver opciones
#
# Este script:
#   1. Valida el sistema operativo
#   2. Instala dependencias del SO
#   3. Instala/configura Go y herramientas
#   4. Crea entorno virtual Python
#   5. Instala paquetes Python
#   6. Valida toda la instalación
#   7. Crea archivo .env desde .env.example
#
################################################################################

set -e  # Exit on error

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Variables
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${SCRIPT_DIR}/venv"
GOPATH="${HOME}/go"
GO_VERSION="1.21.0"

# Funciones de utilidad
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

log_error() {
    echo -e "${RED}[✗]${NC} $1"
}

print_header() {
    echo ""
    echo "================================================================================"
    echo "  $1"
    echo "================================================================================"
    echo ""
}

print_help() {
    cat << EOF
SuperReconn Setup Script

Uso: $0 [OPCIONES]

Opciones:
    --help              Muestra esta ayuda
    --no-go            Salta instalación de Go y herramientas
    --no-python        Salta configuración Python
    --only-check       Solo verifica instalación, no instala nada
    --dev              Instala también dependencias de desarrollo (pytest, black, etc)

Ejemplos:
    $0                  # Instalación completa
    $0 --only-check     # Verificar que esté todo instalado
    $0 --no-go          # Solo Python, asume que Go está instalado
    $0 --dev            # Instalación completa + herramientas de desarrollo

EOF
    exit 0
}

# Parsear argumentos
SKIP_GO=false
SKIP_PYTHON=false
ONLY_CHECK=false
INSTALL_DEV=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --help) print_help ;;
        --no-go) SKIP_GO=true; shift ;;
        --no-python) SKIP_PYTHON=true; shift ;;
        --only-check) ONLY_CHECK=true; shift ;;
        --dev) INSTALL_DEV=true; shift ;;
        *) log_error "Opción desconocida: $1"; exit 1 ;;
    esac
done

# ============================================================================
# Validación del Sistema
# ============================================================================

print_header "VALIDACIÓN DEL SISTEMA"

# Verificar SO
if [[ "$OSTYPE" != "linux-gnu"* ]]; then
    log_error "Sistema operativo no soportado: $OSTYPE"
    log_info "Soportado: Ubuntu 20.04+, Debian 11+, CentOS 8+"
    exit 1
fi

# Detectar distribución
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
    VER=$VERSION_ID
else
    log_error "No se pudo detectar el SO"
    exit 1
fi

log_success "SO detectado: $OS $VER"

# Verificar privilegios
if [[ $EUID -eq 0 ]]; then
    log_warning "Se está ejecutando como root. No es recomendable."
fi

# ============================================================================
# Validación de Dependencias Básicas
# ============================================================================

print_header "VALIDACIÓN DE DEPENDENCIAS"

check_command() {
    if command -v "$1" &> /dev/null; then
        log_success "$1 está instalado"
        return 0
    else
        log_warning "$1 NO está instalado"
        return 1
    fi
}

check_command "python3"
check_command "curl"
check_command "wget"
check_command "git"

# ============================================================================
# Instalación Solo en Modo No-Check
# ============================================================================

if [ "$ONLY_CHECK" = true ]; then
    print_header "VERIFICACIÓN DE INSTALACIÓN"
    log_info "Modo verificación activado"
    
    MISSING=()
    
    # Verificar herramientas críticas
    for tool in massdns httpx naabu nmap; do
        if ! command -v "$tool" &> /dev/null; then
            MISSING+=("$tool")
        else
            log_success "$tool disponible"
        fi
    done
    
    if [ ${#MISSING[@]} -ne 0 ]; then
        log_error "Herramientas faltantes: ${MISSING[*]}"
        exit 1
    else
        log_success "Todas las herramientas críticas están disponibles"
    fi
    
    exit 0
fi

# ============================================================================
# Actualización del Sistema
# ============================================================================

print_header "ACTUALIZACIÓN DEL SISTEMA"

log_info "Actualizando repositorios (requiere sudo)..."
sudo apt-get update -qq > /dev/null
log_success "Repositorios actualizados"

# ============================================================================
# Instalación de Dependencias del SO
# ============================================================================

print_header "INSTALACIÓN DE DEPENDENCIAS DEL SISTEMA"

PACKAGES=(
    "git"
    "curl"
    "wget"
    "build-essential"
    "pkg-config"
    "libpcap-dev"
    "unixodbc"
    "unixodbc-dev"
    "nmap"
)

log_info "Instalando paquetes: ${PACKAGES[*]}"
sudo apt-get install -y "${PACKAGES[@]}" > /dev/null
    log_success "Dependencias del sistema instaladas"

# ============================================================================
# Instalación de massdns (requerido, no disponible via go install)
# ============================================================================

if [ "$SKIP_GO" = false ]; then
    print_header "INSTALACIÓN DE MASSDNS"

    if command -v massdns &> /dev/null; then
        log_success "massdns ya está instalado: $(massdns 2>&1 | head -1 || echo 'ok')"
    else
        log_info "Compilando massdns desde fuente..."
        MASSDNS_DIR="/tmp/massdns-build-$$"
        rm -rf "$MASSDNS_DIR"
        git clone --depth 1 https://github.com/blechschmidt/massdns.git "$MASSDNS_DIR"
        make -C "$MASSDNS_DIR" > /dev/null
        sudo cp "$MASSDNS_DIR/bin/massdns" /usr/local/bin/massdns
        sudo chmod +x /usr/local/bin/massdns
        rm -rf "$MASSDNS_DIR"
        log_success "massdns instalado en /usr/local/bin/massdns"
    fi
fi

# ============================================================================
# Resolvers DNS
# ============================================================================

print_header "CONFIGURACIÓN DE RESOLVERS DNS"

RESOLVERS_FILE="$SCRIPT_DIR/resolvers.txt"
RESOLVER_COUNT=0
if [ -f "$RESOLVERS_FILE" ]; then
    RESOLVER_COUNT=$(grep -v '^#' "$RESOLVERS_FILE" | grep -c . || true)
fi

if [ ! -s "$RESOLVERS_FILE" ] || [ "$RESOLVER_COUNT" -lt 20 ]; then
    log_info "Descargando resolvers DNS públicos (${RESOLVER_COUNT} actuales)..."
    if curl -fsSL "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt" -o "$RESOLVERS_FILE"; then
        RESOLVER_COUNT=$(grep -v '^#' "$RESOLVERS_FILE" | grep -c . || true)
        log_success "Resolvers descargados: ${RESOLVER_COUNT} entradas"
    else
        log_warning "No se pudieron descargar resolvers; conservando $RESOLVERS_FILE"
    fi
else
    log_success "Resolvers OK: ${RESOLVER_COUNT} entradas en resolvers.txt"
fi

# ============================================================================
# Instalación de Go (si no está saltado)
# ============================================================================

if [ "$SKIP_GO" = false ]; then
    print_header "INSTALACIÓN DE GO Y HERRAMIENTAS"
    
    if command -v go &> /dev/null; then
        GO_VERSION_INSTALLED=$(go version | awk '{print $3}')
        log_success "Go ya está instalado: $GO_VERSION_INSTALLED"
    else
        log_info "Descargando Go $GO_VERSION..."
        
        # Detectar arquitectura
        ARCH=$(uname -m)
        if [ "$ARCH" = "x86_64" ]; then
            GO_ARCH="amd64"
        elif [ "$ARCH" = "aarch64" ]; then
            GO_ARCH="arm64"
        else
            log_error "Arquitectura no soportada: $ARCH"
            exit 1
        fi
        
        GO_TARBALL="/tmp/go${GO_VERSION}.linux-${GO_ARCH}.tar.gz"
        
        if [ ! -f "$GO_TARBALL" ]; then
            curl -sL "https://go.dev/dl/go${GO_VERSION}.linux-${GO_ARCH}.tar.gz" -o "$GO_TARBALL"
        fi
        
        log_info "Instalando Go..."
        sudo rm -rf /usr/local/go
        sudo tar -C /usr/local -xzf "$GO_TARBALL"
        rm -f "$GO_TARBALL"
        
        log_success "Go instalado"
    fi
    
    # Configurar variables de Go
    export GOPATH="$GOPATH"
    export PATH="$PATH:$GOPATH/bin:/usr/local/go/bin"
    
    # Agregar a .bashrc si no está
    if ! grep -q "export GOPATH" "$HOME/.bashrc"; then
        cat >> "$HOME/.bashrc" << 'EOL'

# Go configuration
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin:/usr/local/go/bin
EOL
        log_success "Variables de Go agregadas a ~/.bashrc"
    fi
    
    mkdir -p "$GOPATH/bin"
    
    # Instalar herramientas Go
    log_info "Instalando herramientas de reconocimiento..."
    
    TOOLS=(
        "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
        "github.com/owasp-amass/amass/v4/...@latest"
        "github.com/tomnomnom/assetfinder@latest"
        "github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest"
        "github.com/projectdiscovery/httpx/cmd/httpx@latest"
        "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
        "github.com/projectdiscovery/katana/cmd/katana@latest"
        "github.com/tomnomnom/waybackurls@latest"
        "github.com/tomnomnom/gf@latest"
        "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    )
    
    for tool in "${TOOLS[@]}"; do
        TOOL_NAME=$(echo $tool | cut -d/ -f4)
        log_info "  Instalando $TOOL_NAME..."
        go install -v "$tool" 2>&1 | grep -v "^go get" | head -1 || true
    done
    
    log_success "Herramientas de reconocimiento instaladas"

    # Actualizar templates nuclei (requerido para fases de vulnerabilidades)
    if command -v nuclei &> /dev/null; then
        log_info "Actualizando templates nuclei..."
        if nuclei -update-templates > /dev/null 2>&1; then
            log_success "Templates nuclei actualizados"
        else
            log_warning "No se pudieron actualizar templates nuclei; ejecuta manualmente: nuclei -update-templates"
        fi
    fi
fi

# ============================================================================
# Configuración de Python
# ============================================================================

if [ "$SKIP_PYTHON" = false ]; then
    print_header "CONFIGURACIÓN DE PYTHON"
    
    # Verificar Python 3
    if ! command -v python3 &> /dev/null; then
        log_error "Python 3 no está instalado"
        exit 1
    fi
    
    PYTHON_VERSION=$(python3 --version | awk '{print $2}')
    log_success "Python $PYTHON_VERSION detectado"
    
    # Crear venv
    if [ ! -d "$VENV_DIR" ]; then
        log_info "Creando entorno virtual..."
        python3 -m venv "$VENV_DIR"
        log_success "Entorno virtual creado"
    else
        log_info "Entorno virtual ya existe"
    fi
    
    # Activar venv
    source "$VENV_DIR/bin/activate"
    
    # Actualizar pip
    log_info "Actualizando pip..."
    pip install --upgrade pip setuptools wheel > /dev/null
    log_success "pip actualizado"
    
    # Instalar dependencias
    log_info "Instalando dependencias Python..."
    pip install -r "$SCRIPT_DIR/requirements.txt" > /dev/null
    log_success "Dependencias Python instaladas"
    
    # Dependencias de desarrollo (opcional)
    if [ "$INSTALL_DEV" = true ]; then
        log_info "Instalando herramientas de desarrollo..."
        pip install pytest pytest-cov black flake8 mypy pylint > /dev/null
        log_success "Herramientas de desarrollo instaladas"
    fi
fi

# ============================================================================
# Instalación de Driver ODBC (opcional, para SQL Server)
# ============================================================================

print_header "INSTALACIÓN DE DRIVER ODBC (OPCIONAL)"

if command -v odbcinst &> /dev/null; then
    if odbcinst -q -d | grep -q "ODBC Driver 18 for SQL Server"; then
        log_success "Driver ODBC 18 ya está instalado"
    else
        log_warning "Driver ODBC 18 NO está instalado"
        log_info "Para instalarlo manualmente, ejecuta:"
        cat << 'EOF'
    sudo apt-get install -y curl gnupg2 apt-transport-https ca-certificates
    curl https://packages.microsoft.com/keys/microsoft.asc | sudo gpg --dearmor -o /usr/share/keyrings/microsoft-prod.gpg
    echo "deb [arch=amd64 signed-by=/usr/share/keyrings/microsoft-prod.gpg] https://packages.microsoft.com/ubuntu/22.04/prod jammy main" | sudo tee /etc/apt/sources.list.d/mssql-release.list
    sudo apt-get update
    sudo ACCEPT_EULA=Y apt-get install -y msodbcsql18
EOF
    fi
else
    log_warning "odbcinst no está disponible (SQL Server optional)"
fi

# ============================================================================
# Crear archivo .env
# ============================================================================

print_header "CONFIGURACIÓN"

if [ ! -f "$SCRIPT_DIR/.env" ]; then
    log_info "Creando archivo .env desde .env.example..."
    cp "$SCRIPT_DIR/.env.example" "$SCRIPT_DIR/.env"
    log_success "Archivo .env creado"
    log_warning "IMPORTANTE: Edita $SCRIPT_DIR/.env con tus valores (especialmente MSSQL_*)"
else
    log_info ".env ya existe, no se sobrescribió"
fi

# ============================================================================
# Validación Final
# ============================================================================

print_header "VALIDACIÓN FINAL"

if [ "$SKIP_PYTHON" = false ]; then
    source "$VENV_DIR/bin/activate"
fi

source "$HOME/.bashrc" 2>/dev/null || true
export GOPATH="$GOPATH"
export PATH="$PATH:$GOPATH/bin:/usr/local/go/bin"

MISSING_TOOLS=()
for tool in massdns httpx naabu nmap; do
    if command -v "$tool" &> /dev/null; then
        log_success "$tool disponible"
    else
        log_warning "$tool NO disponible"
        MISSING_TOOLS+=("$tool")
    fi
done

if [ ${#MISSING_TOOLS[@]} -gt 0 ]; then
    log_error "Algunas herramientas faltantes: ${MISSING_TOOLS[*]}"
    log_info "Asegúrate de que $GOPATH/bin esté en el PATH:"
    log_info "  echo 'export PATH=\$PATH:$GOPATH/bin' >> ~/.bashrc"
    log_info "  source ~/.bashrc"
else
    log_success "Todas las herramientas críticas disponibles"
fi

# ============================================================================
# Resumen Final
# ============================================================================

print_header "INSTALACIÓN COMPLETADA ✓"

cat << EOF

SuperReconn está listo para usar.

Próximos pasos:

1. Cargar variables de entorno (si usas bash):
   echo 'export GOPATH=\$HOME/go' >> ~/.bashrc
   echo 'export PATH=\$PATH:\$GOPATH/bin:/usr/local/go/bin' >> ~/.bashrc
   source ~/.bashrc

2. Editar configuración (opcional):
   nano $SCRIPT_DIR/.env

3. Ejecutar SuperReconn:
   source $VENV_DIR/bin/activate
   python3 $SCRIPT_DIR/SuperReconn.py example.com

4. Validar instalación:
   python3 $SCRIPT_DIR/SuperReconn.py --help

Para más información, consulta README.md

EOF

exit 0
