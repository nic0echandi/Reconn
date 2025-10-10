import os
import sys
import mysql.connector # Conector estable de Oracle
import datetime

# python3 storedb.py /resultados_recon/ejemplo.com.ar

# --- Configuración de la Base de Datos ---
DB_CONFIG = {
    'host': 'localhost', # Dirección IP del contenedor Docker/MariaDB
    'port': 3306,
    'user': 'user',
    'password': 'password',
    'database': 'discovery' # nombre de la base de datos
}
TARGET_DB_NAME = DB_CONFIG['database']

# --- Funciones de Conexión y Setup de BD ---

def connect_db():
    """
    Establece y retorna la conexión a la base de datos usando mysql.connector.
    Fuerza el plugin de autenticación para resolver el Error 2003 (código 65).
    """
    try:
        conn = mysql.connector.connect(
            host=DB_CONFIG['host'],
            port=DB_CONFIG['port'],
            user=DB_CONFIG['user'],
            password=DB_CONFIG['password'],
            database=DB_CONFIG['database'],
            
            # --- SOLUCIÓN CRÍTICA: Fuerza el plugin de autenticación ---
            auth_plugin='mysql_native_password' 
        )
        print(f"\n[+] Conexión exitosa a MariaDB ({DB_CONFIG['host']}:{DB_CONFIG['port']})")
        return conn
    except mysql.connector.Error as e:
        # Error handling específico
        print(f"\n[!!!] ERROR CRÍTICO DE CONEXIÓN A MARIA DB [!!!]")
        print(f"Host: {DB_CONFIG['host']}:{DB_CONFIG['port']} | User: {DB_CONFIG['user']}")
        print(f"Código de error de MySQL/MariaDB: {e.errno}")
        print(f"Detalle: {e.msg}")
        print("\nVerifique las credenciales si este error persiste, la red funciona.")
        sys.exit(1)
    except Exception as e:
        print(f"[!!!] ERROR DESCONOCIDO DE CONEXIÓN: {e}")
        sys.exit(1)

def setup_database(conn):
    """Crea las tablas si no existen."""
    cursor = conn.cursor()
    print(f"[+] Asegurando que las tablas existan en la DB: {TARGET_DB_NAME}")
    
    # Tabla para Listas Simples (Subdominios, URLs, GF)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS simple_recon_data (
            id INT AUTO_INCREMENT PRIMARY KEY,
            target_dir VARCHAR(255) NOT NULL,
            scan_type VARCHAR(50) NOT NULL,
            value TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        );
    """)

    # Tabla para Puertos Abiertos (Naabu)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS naabu_ports (
            id INT AUTO_INCREMENT PRIMARY KEY,
            target_dir VARCHAR(255) NOT NULL,
            ip_address VARCHAR(45) NOT NULL,
            port INT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        );
    """)

    # Tabla para Escaneo de Versiones (Nmap)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS nmap_versions (
            id INT AUTO_INCREMENT PRIMARY KEY,
            target_dir VARCHAR(255) NOT NULL,
            ip_address VARCHAR(45) NOT NULL,
            port_proto VARCHAR(10) NOT NULL,
            state VARCHAR(15),
            service VARCHAR(50),
            version VARCHAR(255),
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        );
    """)

    # Tabla para Hallazgos de Vulnerabilidades (Nuclei)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS nuclei_scans (
            id INT AUTO_INCREMENT PRIMARY KEY,
            target_dir VARCHAR(255) NOT NULL,
            scan_category VARCHAR(50) NOT NULL,
            template_id VARCHAR(100),
            severity VARCHAR(20),
            url_host TEXT,
            full_output TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        );
    """)
    conn.commit()
    print("[+] Estructura de la base de datos verificada/creada.")

# --- Funciones de Inserción ---

def insert_simple_data(conn, base_dir, scan_type, data):
    """Inserta datos de listas simples (subdominios, urls, gf)."""
    cursor = conn.cursor()
    sql = "INSERT INTO simple_recon_data (target_dir, scan_type, value) VALUES (%s, %s, %s)"
    records = [(os.path.basename(base_dir), scan_type, row[0]) for row in data]
    
    if records:
        cursor.executemany(sql, records)
        conn.commit()
        print(f"    -> {len(records)} registros de '{scan_type}' insertados.")
    else:
        print(f"    -> 0 registros de '{scan_type}' para insertar.")

def insert_naabu_data(conn, base_dir, data):
    """Inserta puertos IP:PUERTO."""
    cursor = conn.cursor()
    sql = "INSERT INTO naabu_ports (target_dir, ip_address, port) VALUES (%s, %s, %s)"
    records = [(os.path.basename(base_dir), row[0], int(row[1])) for row in data if row[1].isdigit()]
    
    if records:
        cursor.executemany(sql, records)
        conn.commit()
        print(f"    -> {len(records)} puertos de Naabu insertados.")
    else:
        print("    -> 0 puertos de Naabu para insertar.")

def insert_nmap_data(conn, base_dir, data):
    """Inserta resultados de Nmap -sV."""
    cursor = conn.cursor()
    sql = """
    INSERT INTO nmap_versions (target_dir, ip_address, port_proto, state, service, version) 
    VALUES (%s, %s, %s, %s, %s, %s)
    """
    records = [(os.path.basename(base_dir), *row) for row in data]
    
    if records:
        cursor.executemany(sql, records)
        conn.commit()
        print(f"    -> {len(records)} versiones de Nmap insertadas.")
    else:
        print("    -> 0 versiones de Nmap para insertar.")

def insert_nuclei_data(conn, base_dir, scan_category, data):
    """Inserta hallazgos de Nuclei."""
    cursor = conn.cursor()
    sql = """
    INSERT INTO nuclei_scans (target_dir, scan_category, template_id, severity, url_host, full_output) 
    VALUES (%s, %s, %s, %s, %s, %s)
    """
    records = [(os.path.basename(base_dir), scan_category, row[0], row[1], row[2], row[3]) for row in data]
    
    if records:
        cursor.executemany(sql, records)
        conn.commit()
        print(f"    -> {len(records)} hallazgos de Nuclei ({scan_category}) insertados.")
    else:
        print(f"    -> 0 hallazgos de Nuclei ({scan_category}) para insertar.")

# --- Funciones de Parsing (Se mantienen igual) ---

def read_simple_list(filepath, header):
    """Lee archivos de lista simple (Subdominios, URLs, GF) y retorna una lista de listas."""
    data = []
    try:
        with open(filepath, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    data.append([line])
        return [header], data
    except FileNotFoundError:
        return [header], [["[ARCHIVO NO ENCONTRADO]"]]
    except Exception as e:
        return [header], [[f"[ERROR DE LECTURA: {e}]"]]

def parse_naabu_ports(filepath):
    """Lee IP:PUERTO y separa los campos."""
    header = ["IP", "Puerto"]
    data = []
    try:
        with open(filepath, 'r') as f:
            for line in f:
                line = line.strip()
                if ':' in line:
                    ip, port = line.split(':', 1)
                    if port.strip().isdigit(): 
                        data.append([ip.strip(), port.strip()])
        return header, data
    except FileNotFoundError:
        return header, [["[ARCHIVO NO ENCONTRADO]", ""]]
    except Exception:
        return header, [["[ERROR AL PARSEAR]", ""]]

def parse_nuclei_scan(filepath):
    """
    Lee la salida de Nuclei (formato texto simple, una línea por hallazgo).
    Asume el formato: [Template-ID] [Severity] URL
    """
    header = ["Plantilla (ID)", "Severidad", "URL/Host", "Hallazgo Completo"]
    data = []
    try:
        with open(filepath, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                parts = line.split(' ', 3)
                
                if len(parts) >= 3:
                    template = parts[0].strip('[]') if parts[0].startswith('[') else parts[0]
                    severity = parts[1].strip('[]') if parts[1].startswith('[') else parts[1]
                    url_host = parts[2]
                    
                    data.append([template, severity, url_host, line])
                else:
                    data.append(["N/A", "N/A", "N/A", line])

        return header, data
    except FileNotFoundError:
        return header, [["[ARCHIVO NO ENCONTRADO]", "", "", ""]]
    except Exception as e:
        return header, [[f"[ERROR AL PARSEAR: {e}]", "", "", ""]]

def parse_nmap_versions(filepath):
    """
    Analiza la salida de Nmap (-oN) para extraer IP, Puerto, Estado, Servicio y Versión.
    """
    header = ["IP", "Puerto", "Estado", "Servicio", "Versión"]
    data = []
    current_ip = "N/A"
    
    try:
        with open(filepath, 'r') as f:
            for line in f:
                line = line.strip()
                
                if line.startswith("Nmap scan report for"):
                    if '(' in line and ')' in line:
                        current_ip = line.split('(')[-1].strip(')')
                    else:
                        current_ip = line.split()[-1]

                if line and line[0].isdigit() and ('/tcp' in line or '/udp' in line) and ('open' in line or 'closed' in line):
                    
                    parts = line.split()
                    
                    if len(parts) >= 3:
                        port_proto = parts[0] 
                        state = parts[1]      
                        service = parts[2]    
                        version = " ".join(parts[3:]) if len(parts) > 3 else "N/A"
                        
                        data.append([current_ip, port_proto, state, service, version])

        if not data:
             return header, [["", "", "", "No se pudo extraer la data estructurada de Nmap.", ""]]

        return header, data
    except FileNotFoundError:
        return header, [["[ARCHIVO NO ENCONTRADO]", "", "", "", ""]]
    except Exception as e:
        return header, [[f"[ERROR DE PARSING: {e}]", "", "", "", ""]]


# --- Función Principal del Reporte ---

def generate_report(base_dir):
    """Conecta a la DB, ejecuta todos los parsers e inserta los resultados."""
    
    # Conexión a DB y setup de tablas
    conn = connect_db()
    setup_database(conn)
    
    base_dir = os.path.expanduser(base_dir)
    print(f"\n[+] Iniciando carga de datos desde: {base_dir}\n")

    # Definición de archivos, paths y parsers
    file_map = {
        "Subdominios Totales": ("subdomains/all_subdomains.txt", read_simple_list, "subdomain"),
        "Dominios Resueltos": ("discovery/resolved_domains.txt", read_simple_list, "resolved_domain"),
        "URLs Activas (httpx)": ("discovery/active_urls.txt", read_simple_list, "active_url"),
        
        "Puertos Abiertos (Naabu)": ("discovery/open_ports.txt", parse_naabu_ports, "naabu"),
        "Versiones de Servicios (Nmap -sV)": ("scans/nmap_versions.txt", parse_nmap_versions, "nmap"),
        
        "Endpoints con Patrón XSS (gf)": ("discovery/xss_endpoints.txt", read_simple_list, "xss_endpoint"),
        "Endpoints con Patrón RCE (gf)": ("discovery/rce_endpoints.txt", read_simple_list, "rce_endpoint"),
        
        "Vulnerabilidades CVE (Nuclei)": ("scans/cves_scan.txt", parse_nuclei_scan, "cves"),
        "Exposición/Archivos Sensibles (Nuclei)": ("scans/files_scan.txt", parse_nuclei_scan, "exposure"),
    }

    for title, (rel_path, parser, data_type) in file_map.items():
        filepath = os.path.join(base_dir, rel_path)
        print(f"--- Procesando: {title} ---")
        
        # 1. Ejecutar parser
        h, data = parser(filepath, "Dummy") if parser == read_simple_list else parser(filepath)

        # 2. Insertar los datos en la base de datos
        if not data or data[0][0] in ["[ARCHIVO NO ENCONTRADO]", "", "No se pudo extraer la data estructurada de Nmap."]:
            print("    -> ADVERTENCIA: Archivo no encontrado o sin datos para insertar.")
            continue

        try:
            if parser == read_simple_list:
                insert_simple_data(conn, base_dir, data_type, data)
            elif parser == parse_naabu_ports:
                insert_naabu_data(conn, base_dir, data)
            elif parser == parse_nmap_versions:
                insert_nmap_data(conn, base_dir, data)
            elif parser == parse_nuclei_scan:
                insert_nuclei_data(conn, base_dir, data_type, data)
        except mysql.connector.Error as e:
            print(f"    [!!!] ERROR SQL al insertar {title}: {e.msg}")
            conn.rollback()
        
        print("----------------------------------------")

    conn.close()
    print(f"\n[+] Carga de datos completada y conexión a MariaDB cerrada. 🎉")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Uso: python3 db_report_loader.py <ruta_del_directorio_de_resultados>")
        print("Ejemplo: python3 db_report_loader.py ~/ejemplo.com-2025-10-09")
        sys.exit(1)
        
    BASE_DIRECTORY = sys.argv[1]
    
    if not os.path.isdir(os.path.expanduser(BASE_DIRECTORY)):
        print(f"ERROR: El directorio '{os.path.expanduser(BASE_DIRECTORY)}' no existe o no es válido.")
        sys.exit(1)
        
    generate_report(BASE_DIRECTORY)