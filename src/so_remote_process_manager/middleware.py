"""
middleware.py - Service Registry Seguro (Capa Intermedia)
==========================================================
Actúa como directorio centralizado con cifrado TLS y autenticación
por contraseña. Los servidores y clientes deben presentar la contraseña
correcta antes de poder interactuar con el registro.

Arquitectura: Capa 1 (de 3)
Puerto: 5000
Seguridad: TLS/SSL + autenticación básica por token
"""

import socket
import threading
import json
import ssl  # [TLS] Módulo estándar de Python para cifrado SSL/TLS

# =============================================================================
# CONFIGURACIÓN GLOBAL
# =============================================================================
HOST = '0.0.0.0'   # Escucha en todas las interfaces (requerido para RHEL cloud)
PORT = 5000

# --- [SEGURIDAD] Contraseña compartida (en producción usar hash+salt) ---
# Esta clave debe ser idéntica en server.py y client.py
SHARED_PASSWORD = "SO_PROYECTO_2024"

# --- [TLS] Rutas a los archivos de certificado y clave privada ---
# Generar con: openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes
CERT_FILE = "server.crt"
KEY_FILE  = "server.key"

# Lista compartida entre hilos que almacena los servidores activos.
servidores_activos = []

# Lock para evitar condiciones de carrera al modificar la lista compartida
lock = threading.Lock()

# ---------------------------------------------------------------------------
# PROTOCOLO DE FRAMING: delimitador '\n' (JSON Lines / NDJSON)
# ---------------------------------------------------------------------------
# Simétrico con client.py. El emisor agrega '\n' al final del JSON;
# el receptor acumula bytes en un while True hasta encontrar '\n'.
# ---------------------------------------------------------------------------
BUFFER_SIZE   = 65536          # 64 KB por fragmento de lectura
MSG_DELIMITER = b'\n'         # Caracter separador de mensajes


def _enviar_mensaje(conn, datos_dict):
    """
    Serializa 'datos_dict' a JSON y lo envía con el delimitador '\n',
    permitiendo que el receptor detecte inequívocamente el fin del mensaje.

    Args:
        conn:       Socket TLS de la conexión establecida.
        datos_dict: Diccionario Python a enviar como JSON.
    """
    mensaje = json.dumps(datos_dict).encode('utf-8') + MSG_DELIMITER
    conn.sendall(mensaje)


def _recibir_completo(conn):
    """
    [ROBUSTEZ] Bucle while True con buffer de 64 KB que acumula fragmentos
    hasta encontrar el delimitador '\n', garantizando que el JSON completo
    esté en memoria antes de llamar a json.loads().

    Resuelve el truncado de JSON a ~16 KB que provoca 'Unterminated string'
    cuando hay muchos procesos en el sistema operativo remoto.

    Args:
        conn: Socket TLS envuelto de la conexión entrante.

    Returns:
        str: Mensaje JSON completo decodificado (sin el delimitador '\n').

    Raises:
        ConnectionResetError: Si el socket se cierra antes del delimitador.
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
# CREACIÓN DEL CONTEXTO SSL (Lado Servidor)
# =============================================================================

def crear_contexto_ssl():
    """
    Crea y configura el contexto SSL para el lado servidor.
    
    [TLS] ssl.PROTOCOL_TLS_SERVER indica que este extremo actúa como servidor.
    [TLS] El servidor presenta su certificado (server.crt) y su clave (server.key)
          al cliente para que este pueda verificar la identidad del servidor.
    [TLS] check_hostname y verify_mode=CERT_NONE permiten conexiones sin
          verificar el certificado del cliente (autenticación unilateral).
    
    Returns:
        ssl.SSLContext: Contexto configurado para el servidor.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
    return ctx


# =============================================================================
# LÓGICA DE AUTENTICACIÓN
# =============================================================================

def autenticar_cliente(conn):
    """
    Primer paso de cada conexión: recibe y valida la contraseña del cliente.
    
    [SEGURIDAD] El cliente DEBE enviar {"accion": "auth", "password": "..."} 
    como primer mensaje. Si la contraseña no coincide, se rechaza la conexión.
    
    Args:
        conn: Socket TLS envuelto de la conexión entrante.
    
    Returns:
        bool: True si la autenticación fue exitosa, False en caso contrario.
    """
    try:
        # [FRAMING] Leer el mensaje de autenticación con el protocolo de delimitador
        datos_raw = _recibir_completo(conn)
        datos = json.loads(datos_raw)

        if datos.get("accion") == "auth" and datos.get("password") == SHARED_PASSWORD:
            _enviar_mensaje(conn, {"status": "ok", "mensaje": "Autenticado."})
            return True
        else:
            _enviar_mensaje(conn, {"status": "error", "mensaje": "Contraseña incorrecta."})
            return False
    except Exception:
        return False


# =============================================================================
# LÓGICA DE MANEJO DE CONEXIONES
# =============================================================================

def manejar_cliente(conn, addr):
    """
    Función ejecutada en un hilo separado por cada cliente que se conecta.
    Primero autentica, luego procesa 'register' o 'get_servers'.
    
    Args:
        conn: Socket TLS envuelto de la conexión establecida.
        addr: Tupla (ip, puerto) del cliente conectado.
    """
    print(f"[MIDDLEWARE] Nueva conexión TLS desde {addr}")
    try:
        # --- [SEGURIDAD] PASO 1: Autenticación obligatoria ---
        if not autenticar_cliente(conn):
            print(f"[MIDDLEWARE] ✘ Autenticación fallida desde {addr}. Conexión rechazada.")
            return

        print(f"[MIDDLEWARE] ✔ Cliente {addr} autenticado.")

        # --- PASO 2: Procesar el comando real ---
        # [ROBUSTEZ] Bucle while: acumula fragmentos hasta encontrar '\n'
        datos_raw = _recibir_completo(conn)
        if not datos_raw:
            return

        datos  = json.loads(datos_raw)
        accion = datos.get('accion')

        if accion == 'register':
            ip_servidor     = datos.get('ip')
            puerto_servidor = datos.get('puerto')
            nuevo_servidor  = {"ip": ip_servidor, "puerto": puerto_servidor}

            with lock:
                if nuevo_servidor not in servidores_activos:
                    servidores_activos.append(nuevo_servidor)
                    print(f"[MIDDLEWARE] ✔ Servidor registrado: {ip_servidor}:{puerto_servidor}")
                else:
                    print(f"[MIDDLEWARE] Servidor {ip_servidor}:{puerto_servidor} ya registrado.")

            respuesta = {"status": "ok", "mensaje": "Servidor registrado exitosamente."}

        elif accion == 'get_servers':
            print(f"[MIDDLEWARE] Cliente {addr} solicitó la lista de servidores.")
            with lock:
                respuesta = {"status": "ok", "servidores": list(servidores_activos)}

        else:
            respuesta = {"status": "error", "mensaje": f"Acción desconocida: '{accion}'"}

        # [FRAMING] Responder con delimitador '\n'
        _enviar_mensaje(conn, respuesta)

    except json.JSONDecodeError:
        print(f"[MIDDLEWARE] ✘ JSON inválido recibido de {addr}")
        _enviar_mensaje(conn, {"status": "error", "mensaje": "JSON inválido."})
    except ssl.SSLError as e:
        print(f"[MIDDLEWARE] ✘ Error TLS con {addr}: {e}")
    except Exception as e:
        print(f"[MIDDLEWARE] ✘ Error inesperado con {addr}: {e}")
    finally:
        conn.close()


# =============================================================================
# SERVIDOR PRINCIPAL
# =============================================================================

def iniciar_middleware():
    """
    Inicializa el socket TLS y acepta conexiones cifradas de forma indefinida.
    
    [TLS] El socket raw es envuelto con ssl_ctx.wrap_socket() para que toda
    la comunicación posterior esté cifrada con TLS.
    """
    ssl_ctx = crear_contexto_ssl()

    # Crear el socket TCP estándar
    raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    raw_socket.bind((HOST, PORT))
    raw_socket.listen(10)

    # [TLS] Envolver el socket con SSL: a partir de aquí todo es cifrado
    tls_socket = ssl_ctx.wrap_socket(raw_socket, server_side=True)

    print("=" * 55)
    print("  MIDDLEWARE SEGURO (Service Registry + TLS) iniciado")
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
        print("\n[MIDDLEWARE] Apagando el servicio...")
    finally:
        tls_socket.close()


if __name__ == '__main__':
    iniciar_middleware()
