"""
server.py - Nodo de Cómputo Seguro (Capa Servidora)
=====================================================
Gestiona procesos del SO local (listar, monitorear, detener, iniciar).
Se registra en el middleware al arrancar. Toda la comunicación usa TLS
y requiere autenticación por contraseña antes de ejecutar cualquier comando.

Arquitectura: Capa 2 (de 3)
Puerto: 6000
Depende de: middleware.py (corriendo en puerto 5000)
Seguridad: TLS/SSL + autenticación básica por token
"""

import socket
import threading
import json
import ssl       # [TLS] Cifrado de comunicaciones
import psutil
import subprocess

# =============================================================================
# CONFIGURACIÓN GLOBAL
# =============================================================================
HOST = '192.168.1.69'
PORT = 6000

MIDDLEWARE_HOST = '127.0.0.1'
MIDDLEWARE_PORT = 5000

# --- [SEGURIDAD] Contraseña compartida (debe coincidir con middleware y cliente) ---
SHARED_PASSWORD = "SO_PROYECTO_2024"

# --- [TLS] Archivos de certificado (el mismo par que usa el middleware) ---
CERT_FILE = "server.crt"
KEY_FILE  = "server.key"

# ---------------------------------------------------------------------------
# PROTOCOLO DE FRAMING: delimitador '\n' (JSON Lines / NDJSON)
# ---------------------------------------------------------------------------
# Simétrico con client.py y middleware.py.
# Emisor:   json.dumps(datos).encode() + b'\n'  →  sendall()
# Receptor: acumular en while True hasta b'\n'  →  json.loads()
# Beneficio clave: resuelve el truncado a ~16 KB en listas grandes de procesos.
# ---------------------------------------------------------------------------
BUFFER_SIZE   = 65536          # 64 KB por fragmento de lectura
MSG_DELIMITER = b'\n'         # Carácter separador de mensajes


def _enviar_mensaje(conn, datos_dict):
    """
    Serializa 'datos_dict' a JSON y lo envía con el delimitador '\n'.
    Toda respuesta del servidor (incluyendo la lista de procesos grande)
    viaja con este framing para que el cliente pueda recibirla completa.

    Args:
        conn:       Socket TLS destino.
        datos_dict: Diccionario Python a enviar como JSON.
    """
    mensaje = json.dumps(datos_dict).encode('utf-8') + MSG_DELIMITER
    conn.sendall(mensaje)


def _recibir_completo(conn):
    """
    [ROBUSTEZ] Bucle while True con buffer de 64 KB que acumula fragmentos
    hasta encontrar el delimitador '\n', garantizando que el comando del
    cliente se recibe íntegro antes de procesarlo.

    Args:
        conn: Socket TLS del cual leer.

    Returns:
        str: Mensaje JSON completo decodificado (sin el delimitador).

    Raises:
        ConnectionResetError: Si la conexión se cierra antes del delimitador.
    """
    buffer = b''
    while True:
        fragmento = conn.recv(BUFFER_SIZE)      # Lee hasta 64 KB por ciclo
        if not fragmento:                        # Conexión cerrada inesperadamente
            raise ConnectionResetError("Socket cerrado antes del delimitador.")
        buffer += fragmento
        if MSG_DELIMITER in buffer:             # Delimitador encontrado → mensaje completo
            mensaje, _ = buffer.split(MSG_DELIMITER, 1)
            return mensaje.decode('utf-8')


# =============================================================================
# CONTEXTO SSL - LADO SERVIDOR
# =============================================================================

def crear_contexto_ssl_servidor():
    """
    [TLS] Crea el contexto SSL para que este server actúe como servidor TLS.
    Presenta su certificado al cliente para establecer la sesión cifrada.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
    return ctx


def crear_contexto_ssl_cliente():
    """
    [TLS] Crea el contexto SSL para cuando ESTE servidor actúa como CLIENTE
    al conectarse al middleware. check_hostname=False y CERT_NONE permiten
    usar certificados autofirmados (apropiado para un proyecto universitario).
    En producción, se verificaría el CA del middleware.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False                          # Cert autofirmado
    ctx.verify_mode   = ssl.CERT_NONE                  # Sin verificación de CA
    return ctx


# =============================================================================
# REGISTRO EN EL MIDDLEWARE (CON TLS + AUTENTICACIÓN)
# =============================================================================

def registrar_en_middleware():
    """
    Al arrancar, anuncia este servidor al Service Registry.
    [TLS] La conexión al middleware también es cifrada y autenticada.
    """
    try:
        ssl_ctx = crear_contexto_ssl_cliente()
        raw_s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # [TLS] Envuelve el socket raw con TLS antes de conectar
        with ssl_ctx.wrap_socket(raw_s, server_hostname=MIDDLEWARE_HOST) as s:
            s.connect((MIDDLEWARE_HOST, MIDDLEWARE_PORT))

            # --- [SEGURIDAD] Paso 1: Autenticarse en el middleware ---
            auth_payload = {"accion": "auth", "password": SHARED_PASSWORD}
            _enviar_mensaje(s, auth_payload)
            auth_resp = json.loads(_recibir_completo(s))

            if auth_resp.get("status") != "ok":
                print(f"[SERVIDOR] ✘ Autenticación en middleware fallida: {auth_resp.get('mensaje')}")
                return

            # --- Paso 2: Enviar solicitud de registro ---
            payload = {"accion": "register", "ip": HOST, "puerto": PORT}
            _enviar_mensaje(s, payload)
            respuesta = json.loads(_recibir_completo(s))

            if respuesta.get("status") == "ok":
                print("[SERVIDOR] ✔ Registrado en middleware con TLS exitosamente.")
            else:
                print(f"[SERVIDOR] ✘ Fallo al registrar: {respuesta.get('mensaje')}")

    except ConnectionRefusedError:
        print(f"[SERVIDOR] ✘ No se pudo conectar al middleware en {MIDDLEWARE_HOST}:{MIDDLEWARE_PORT}.")
        print("[SERVIDOR]   Verifique que middleware.py esté corriendo.")
    except ssl.SSLError as e:
        print(f"[SERVIDOR] ✘ Error TLS al conectar con middleware: {e}")
    except Exception as e:
        print(f"[SERVIDOR] ✘ Error durante el registro: {e}")


# =============================================================================
# AUTENTICACIÓN DE CLIENTES
# =============================================================================

def autenticar_cliente(conn):
    """
    [SEGURIDAD] Verifica la contraseña que envía el cliente como primer mensaje.
    Rechaza la conexión si la contraseña es incorrecta.
    """
    try:
        # [FRAMING] Leer mensaje de auth con el protocolo de delimitador
        datos_raw = _recibir_completo(conn)
        datos     = json.loads(datos_raw)

        if datos.get("accion") == "auth" and datos.get("password") == SHARED_PASSWORD:
            _enviar_mensaje(conn, {"status": "ok", "mensaje": "Autenticado."})
            return True
        else:
            _enviar_mensaje(conn, {"status": "error", "mensaje": "Contraseña incorrecta."})
            return False
    except Exception:
        return False


# =============================================================================
# LÓGICA DE GESTIÓN DE PROCESOS
# =============================================================================

def handle_command(datos):
    """
    Núcleo del servidor: recibe un dict con 'accion' y la ejecuta.
    Usa psutil para introspección del SO y subprocess para lanzar apps.

    Args:
        datos (dict): JSON parseado con la acción y parámetros opcionales.
    Returns:
        dict: Respuesta estructurada con 'status' y resultado.
    """
    accion = datos.get('accion')

    # --- ACCIÓN 1: Listar todos los procesos activos ---
    if accion == 'list':
        try:
            procesos = []
            for proc in psutil.process_iter(['pid', 'name', 'status']):
                try:
                    info = proc.info
                    procesos.append({
                        "pid":    info['pid'],
                        "nombre": info['name'],
                        "estado": info['status']
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            return {"status": "ok", "procesos": procesos}
        except Exception as e:
            return {"status": "error", "mensaje": f"Error al listar: {e}"}

    # --- ACCIÓN 2: Monitorear uso de CPU y RAM ---
    elif accion == 'monitor':
        try:
            cpu    = psutil.cpu_percent(interval=1)
            mem    = psutil.virtual_memory()
            return {
                "status":          "ok",
                "cpu_percent":     cpu,
                "memoria_percent": mem.percent,
                "memoria_total_gb": round(mem.total / (1024**3), 2),
                "memoria_usada_gb": round(mem.used  / (1024**3), 2),
            }
        except Exception as e:
            return {"status": "error", "mensaje": f"Error al monitorear: {e}"}

    # --- ACCIÓN 3: Detener un proceso por PID ---
    elif accion == 'stop':
        pid = datos.get('pid')
        if pid is None:
            return {"status": "error", "mensaje": "Se requiere el campo 'pid'."}
        try:
            proceso     = psutil.Process(int(pid))
            nombre_proc = proceso.name()
            proceso.terminate()
            return {"status": "ok", "mensaje": f"Proceso '{nombre_proc}' (PID {pid}) terminado."}
        except psutil.NoSuchProcess:
            return {"status": "error", "mensaje": f"No existe proceso con PID {pid}."}
        except psutil.AccessDenied:
            return {"status": "error", "mensaje": f"Acceso denegado para terminar PID {pid}."}
        except Exception as e:
            return {"status": "error", "mensaje": f"Error al detener: {e}"}

    # --- ACCIÓN 4: Iniciar una aplicación ---
    elif accion == 'start':
        app = datos.get('app')
        if not app:
            return {"status": "error", "mensaje": "Se requiere el campo 'app'."}
        try:
            proc = subprocess.Popen(app, shell=True)
            return {"status": "ok", "mensaje": f"Aplicación '{app}' iniciada con PID {proc.pid}."}
        except FileNotFoundError:
            return {"status": "error", "mensaje": f"Aplicación '{app}' no encontrada."}
        except Exception as e:
            return {"status": "error", "mensaje": f"Error al iniciar: {e}"}

    else:
        return {"status": "error", "mensaje": f"Acción desconocida: '{accion}'"}


# =============================================================================
# MANEJO DE CLIENTES (Hilos)
# =============================================================================

def manejar_cliente(conn, addr):
    """
    Ejecutado en hilo separado por cada cliente. Autenticación → Comando → Respuesta.
    
    [TLS] conn ya es un socket TLS envuelto; toda lectura/escritura es cifrada.
    """
    print(f"[SERVIDOR] Nueva conexión TLS desde {addr}")
    try:
        # --- [SEGURIDAD] Autenticación obligatoria ---
        if not autenticar_cliente(conn):
            print(f"[SERVIDOR] ✘ Autenticación fallida desde {addr}.")
            return

        print(f"[SERVIDOR] ✔ Cliente {addr} autenticado.")

        # [ROBUSTEZ] Acumular fragmentos hasta encontrar el delimitador '\n'
        datos_raw = _recibir_completo(conn)
        if not datos_raw:
            return

        datos   = json.loads(datos_raw)
        accion  = datos.get('accion', 'DESCONOCIDA')
        print(f"[SERVIDOR] Comando recibido de {addr}: '{accion}'")

        respuesta = handle_command(datos)

        # [FRAMING] Enviar la respuesta (puede ser una lista enorme) con '\n'
        _enviar_mensaje(conn, respuesta)

    except json.JSONDecodeError:
        _enviar_mensaje(conn, {"status": "error", "mensaje": "JSON malformado."})
    except ssl.SSLError as e:
        print(f"[SERVIDOR] ✘ Error TLS con {addr}: {e}")
    except Exception as e:
        print(f"[SERVIDOR] ✘ Error inesperado con {addr}: {e}")
    finally:
        conn.close()


# =============================================================================
# SERVIDOR PRINCIPAL
# =============================================================================

def iniciar_servidor():
    """
    Ciclo de vida:
    1. Se registra en el middleware via TLS.
    2. Crea su socket TLS para escuchar comandos de clientes.
    3. Cada conexión entrante se delega a un hilo independiente.
    """
    registrar_en_middleware()

    ssl_ctx    = crear_contexto_ssl_servidor()
    raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    raw_socket.bind((HOST, PORT))
    raw_socket.listen(10)

    # [TLS] Envolver el socket del servidor con SSL
    tls_socket = ssl_ctx.wrap_socket(raw_socket, server_side=True)

    print("=" * 55)
    print("  SERVIDOR SEGURO (Nodo de Cómputo + TLS) iniciado")
    print(f"  Escuchando en {HOST}:{PORT} [TLS HABILITADO]")
    print("=" * 55)

    try:
        while True:
            conn, addr = tls_socket.accept()
            hilo = threading.Thread(
                target=manejar_cliente,
                args=(conn, addr),
                daemon=True
            )
            hilo.start()
    except KeyboardInterrupt:
        print("\n[SERVIDOR] Apagando el servicio...")
    finally:
        tls_socket.close()


if __name__ == '__main__':
    iniciar_servidor()
