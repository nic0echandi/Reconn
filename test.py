import socket
import sys

TARGET_HOST = '192.168.100.222'
TARGET_PORT = 3306

try:
    # 1. Creamos el objeto socket (IPv4, TCP)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # Establecemos un timeout bajo
    s.settimeout(5)
    
    print(f"Intentando conectar a {TARGET_HOST}:{TARGET_PORT}...")
    
    # 2. Intentamos la conexión
    s.connect((TARGET_HOST, TARGET_PORT))
    
    print(f"\n[+] ¡ÉXITO! La conexión TCP Pura a {TARGET_HOST}:{TARGET_PORT} funcionó.")
    print("El problema es la implementación del conector MySQL, no el sistema de sockets.")
    
    s.close()

except socket.timeout:
    print(f"\n[!!!] FALLO: Tiempo de espera agotado al conectar a {TARGET_HOST}:{TARGET_PORT}.")
    print("Aunque la ruta existe, su sistema está bloqueando la respuesta TCP.")
except socket.error as e:
    # Si devuelve el Error 65 aquí, confirma que el sistema está mintiendo al proceso de Python.
    print(f"\n[!!!] FALLO: Error de socket: {e}")
    print("Este error confirma que la conexión TCP es bloqueada a nivel de proceso.")
    
except Exception as e:
    print(f"Error inesperado: {e}")