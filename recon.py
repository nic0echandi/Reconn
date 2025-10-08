import os
import subprocess
import datetime
import sys

# --- Configuración ---
if len(sys.argv) < 2:
    print("Uso: python3 recon.py <objetivo.com>")
    sys.exit(1)

TARGET = sys.argv[1]

# Obtener la ruta del directorio donde se ejecuta el script
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# Las demás rutas se definen de forma relativa a SCRIPT_DIR
WORDLIST = os.path.join(SCRIPT_DIR, "wordlists/subdomains.txt")
RESOLVERS_FILE = os.path.join(SCRIPT_DIR, "resolvers.txt")

# diferencio los distintos escaneos agregando la fecha al nombre del directorio.
# para sobreescribir resultados, edito la linea siguiente y saco la fecha
#OUTPUT_DIR = os.path.join(SCRIPT_DIR, f"{TARGET}-{datetime.date.today()}")
OUTPUT_DIR = os.path.join(SCRIPT_DIR, f"{TARGET}")

# Archivos clave
all_subdomains = os.path.join(OUTPUT_DIR, "subdomains", "all_subdomains.txt")
resolved_all = os.path.join(OUTPUT_DIR, "discovery", "resolved_all.txt")
resolved_domains = os.path.join(OUTPUT_DIR, "discovery", "resolved_domains.txt")
resolved_ips = os.path.join(OUTPUT_DIR, "discovery", "resolved_ips.txt")

# --- Funciones ---
def run_command(command, output_file=None):
    """Ejecuta un comando de shell y captura su salida, con manejo de errores."""
    print(f"[+] Ejecutando: {' '.join(command)}")
    try:
        if output_file:
            # Redirigir stdout al archivo, stderr a /dev/null
            with open(output_file, 'w') as f, open(os.devnull, 'w') as devnull:
                subprocess.run(command, check=True, stdout=f, stderr=devnull, text=True)
        else:
            # Redirigir todo a /dev/null
            with open(os.devnull, 'w') as devnull:
                subprocess.run(command, check=True, stdout=devnull, stderr=devnull, text=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        print(f"[-] El comando falló: {e}")
        return False

def run_piped_commands(command1, command2, output_file=None):
    """
    Ejecuta dos comandos encadenados con una tubería.
    Captura y muestra el stderr del segundo comando si falla.
    """
    print(f"[+] Ejecutando: {' '.join(command1)} | {' '.join(command2)}")
    try:
        # 1. Iniciar el primer proceso (ej. cat)
        proc1 = subprocess.Popen(command1, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        
        # 2. Ejecutar el segundo proceso (ej. massdns o httpx)
        if output_file:
            # Usar stdout=f y stderr=subprocess.PIPE (para captura de errores)
            with open(output_file, 'w') as f:
                result = subprocess.run(command2, stdin=proc1.stdout, stdout=f, stderr=subprocess.PIPE, check=True, text=True)
        else:
            # Redirigir stdout a /dev/null y capturar stderr
            with open(os.devnull, 'w') as devnull:
                result = subprocess.run(command2, stdin=proc1.stdout, stdout=devnull, stderr=subprocess.PIPE, check=True, text=True)
            
        proc1.stdout.close() 
        return True
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        error_message = f"[-] El comando encadenado falló: {e}"
        
        if isinstance(e, subprocess.CalledProcessError) and e.stderr:
            error_message += f"\n[!] Mensaje de error de la herramienta: {e.stderr.strip()}"
        elif isinstance(e, FileNotFoundError):
             error_message += f"\n[!] POSIBLE CAUSA: La herramienta '{command2[0]}' no se encuentra (no está instalada o no está en el PATH)."
        
        print(error_message)
        return False

def setup_directories():
    """Crea los directorios necesarios para los resultados."""
    try:
        os.makedirs(os.path.join(OUTPUT_DIR, "subdomains"), exist_ok=True)
        os.makedirs(os.path.join(OUTPUT_DIR, "discovery"), exist_ok=True)
        os.makedirs(os.path.join(OUTPUT_DIR, "scans"), exist_ok=True)
    except OSError as e:
        print(f"[-] Error al crear directorios: {e}")
        sys.exit(1)

# --- Script principal ---
if __name__ == "__main__":
    setup_directories()

    # --- Verificación de archivos locales ---
    if not os.path.exists(RESOLVERS_FILE) or os.path.getsize(RESOLVERS_FILE) == 0:
        print(f"[-] ERROR: El archivo de resolvedores NO existe o está vacío: {RESOLVERS_FILE}")
        sys.exit(1)
    
    if not os.path.exists(WORDLIST) or os.path.getsize(WORDLIST) == 0:
        print(f"[-] ERROR: El archivo de wordlist NO existe o está vacío: {WORDLIST}")
        sys.exit(1)


    # 1. Enumeración de subdominios pasiva (subfinder)
    passive_output = os.path.join(OUTPUT_DIR, "subdomains", "passive.txt")
    if not run_command(["subfinder", "-d", TARGET, "-o", passive_output]):
        print("[-] subfinder falló. Saliendo.")
        sys.exit(1)

    # 2. Brute-force activo con shuffledns
    bruteforce_output = os.path.join(OUTPUT_DIR, "subdomains", "bruteforce.txt")
    run_command(["shuffledns", "-d", TARGET, "-w", WORDLIST, "-r", RESOLVERS_FILE, "-mode", "bruteforce", "-t", "500", "-o", bruteforce_output])

    # 3. Combinar y ordenar subdominios (100% Python)
    files_to_combine = [f for f in [passive_output, bruteforce_output] if os.path.exists(f)]
    
    if files_to_combine:
        
        print(f"[+] Combinando y deduplicando subdominios (Lógica 100% nativa de Python)")
        unique_subdomains = set()
        
        try:
            # Primer paso: Combinar y deduplicar en memoria
            for fname in files_to_combine:
                with open(fname, 'r') as infile:
                    for line in infile:
                        if line.strip(): 
                            unique_subdomains.add(line.strip())
            
            # Segundo paso: Ordenar y escribir los subdominios únicos
            with open(all_subdomains, 'w') as outfile:
                for subdomain in sorted(list(unique_subdomains)):
                    outfile.write(subdomain + '\n')

            print(f"[+] Archivos combinados y deduplicados escritos en: {all_subdomains}")

        except Exception as e:
            print(f"[-] Error al combinar/deduplicar archivos de forma nativa: {e}")
            sys.exit(1)
    else:
        print("[-] Error: No se encontraron subdominios para combinar. Saliendo.")
        sys.exit(1)

    # 4. Resolver subdominios con massdns
    massdns_command = ["massdns", "-r", RESOLVERS_FILE, "-t", "A", "-o", "S"]

    if not run_piped_commands(["cat", all_subdomains], massdns_command, output_file=resolved_all):
        print("[-] massdns falló. Saliendo.")
        sys.exit(1)

    
    # 4.1 LIMPIEZA DE LA SALIDA DEL RESOLVEDOR (Método robusto con shell=True)
    print("[+] Limpiando salida del resolvedor para httpx y naabu (Método robusto)...")
    
    # a) Extraer DOMINIOS limpios (para httpx y katana)
    domain_extraction_command = f"cat {resolved_all} | awk '{{print $1}}' | sed 's/\\.$//' > {resolved_domains}"
    print(f"[+] Ejecutando limpieza de dominios: {domain_extraction_command}")
    
    try:
        subprocess.run(domain_extraction_command, shell=True, check=True, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError as e:
        print(f"[-] Error al limpiar dominios: {e}. Saliendo.")
        sys.exit(1)
        
    # b) Extraer IPs limpias (solo A records, para naabu)
    ip_extraction_command = f"grep ' A ' {resolved_all} | awk '{{print $NF}}' > {resolved_ips}"
    print(f"[+] Ejecutando limpieza de IPs: {ip_extraction_command}")
    
    try:
        subprocess.run(ip_extraction_command, shell=True, check=True, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError:
        pass 

    # Garantizar que los archivos de input existan
    if not os.path.exists(resolved_ips) or os.path.getsize(resolved_ips) == 0:
        open(resolved_ips, 'w').close()
        print(f"[-] ADVERTENCIA: No se encontraron registros 'A'. '{os.path.basename(resolved_ips)}' está vacío.")
    
    if not os.path.exists(resolved_domains) or os.path.getsize(resolved_domains) == 0:
        open(resolved_domains, 'w').close()
        print(f"[-] ADVERTENCIA: No se encontraron dominios limpios. '{os.path.basename(resolved_domains)}' está vacío.")


    # 5. Probar servicios HTTP/HTTPS (httpx) - USANDO DOMINIOS LIMPIOS
    active_urls = os.path.join(OUTPUT_DIR, "discovery", "active_urls.txt")
    
    if os.path.exists(resolved_domains) and os.path.getsize(resolved_domains) > 0:
        run_piped_commands(["cat", resolved_domains], ["httpx", "-silent", "-o", active_urls])
    else:
        print("[-] ADVERTENCIA: No hay dominios limpios para escanear con httpx. Creando archivo vacío.")
        open(active_urls, 'w').close()


    # 6. Escaneo de puertos (naabu) - USANDO IPs LIMPIAS
    open_ports = os.path.join(OUTPUT_DIR, "discovery", "open_ports.txt")
    if os.path.getsize(resolved_ips) > 0:
        if not run_command(["naabu", "-list", resolved_ips, "-o", open_ports]):
            print("[-] naabu falló. Continuando con el siguiente paso.")
    else:
        print("[-] ADVERTENCIA: Saltando naabu, no hay direcciones IP limpias para escanear.")
        open(open_ports, 'w').close()
    
    
    # 7. Crawling de URLs (katana y waybackurls)
    discovered_endpoints = os.path.join(OUTPUT_DIR, "discovery", "discovered_endpoints.txt")
    
    if os.path.getsize(active_urls) > 0:
        run_piped_commands(["katana", "-list", active_urls, "-jc", "-silent"], ["anew", discovered_endpoints])
    else:
        print("[-] ADVERTENCIA: Saltando katana (crawling), no hay URLs activas.")

    # Siempre ejecutar waybackurls
    run_piped_commands(["waybackurls", TARGET], ["anew", discovered_endpoints])
    
    
    # 8. Filtrar parámetros interesantes (gf)
    xss_endpoints = os.path.join(OUTPUT_DIR, "discovery", "xss_endpoints.txt")
    rce_endpoints = os.path.join(OUTPUT_DIR, "discovery", "rce_endpoints.txt")
    ssti_endpoints = os.path.join(OUTPUT_DIR, "discovery", "ssti_endpoints.txt")
    
    if os.path.exists(discovered_endpoints) and os.path.getsize(discovered_endpoints) > 0:
        run_piped_commands(["cat", discovered_endpoints], ["gf", "xss"], xss_endpoints)
        run_piped_commands(["cat", discovered_endpoints], ["gf", "rce"], rce_endpoints)
        run_piped_commands(["cat", discovered_endpoints], ["gf", "ssti"], ssti_endpoints)
    else:
        print("[-] ADVERTENCIA: Saltando gf, no se descubrieron endpoints.")

    # 9. Escaneo de vulnerabilidades con Nuclei
    cves_scan = os.path.join(OUTPUT_DIR, "scans", "cves_scan.txt")
    files_scan = os.path.join(OUTPUT_DIR, "scans", "files_scan.txt")
    
    if os.path.exists(active_urls) and os.path.getsize(active_urls) > 0:
        
        # Escaneo de CVEs (Se mantiene)
        run_command(["nuclei", "-l", active_urls, "-t", "cves/", "-c", "20", "-o", cves_scan])
        
        # CORRECCIÓN DE ERROR: Cambiamos "-t files/" por "-t exposure/"
        # La carpeta 'exposure' contiene plantillas para fugas de información, archivos sensibles, etc.
        run_command(["nuclei", "-l", active_urls, "-file", "-c", "20", "-o", files_scan])
        
    else:
        print("[-] ADVERTENCIA: Saltando Nuclei, no hay URLs activas para escanear.")
    
    print(f"\n[+] Reconocimiento completado. Los resultados están en {OUTPUT_DIR}.")