"""
client.py - Interfaz Gráfica Segura (Capa Cliente)
====================================================
GUI construida con CustomTkinter para gestionar procesos remotos.
Se conecta al middleware (TLS) para descubrir servidores y luego
envía comandos cifrados al servidor seleccionado.

Arquitectura: Capa 3 (de 3)
Dependencias: pip install customtkinter psutil

Para instalar: pip install customtkinter
"""

import socket
import json
import ssl
import threading
import tkinter as tk
from tkinter import ttk, messagebox
from datetime import datetime

try:
    import customtkinter as ctk
    ctk.set_appearance_mode("Dark")
    ctk.set_default_color_theme("blue")
    USE_CTK = True
except ImportError:
    # Fallback a Tkinter estándar si CustomTkinter no está instalado
    USE_CTK = False
    import tkinter as ctk


# =============================================================================
# PALETA DE COLORES (Dashboard Oscuro Profesional)
# =============================================================================

COLORS = {
    "bg_dark":      "#0f1117",   # Fondo principal
    "bg_panel":     "#1a1d27",   # Paneles secundarios
    "bg_card":      "#20243a",   # Tarjetas / frames
    "accent":       "#4f8ef7",   # Azul acento principal
    "accent_hover": "#3a72d4",   # Hover sobre acento
    "success":      "#2ecc71",   # Verde OK
    "error":        "#e74c3c",   # Rojo ERROR
    "warning":      "#f39c12",   # Amarillo WARN
    "info":         "#3498db",   # Azul INFO
    "text_primary": "#e8eaf6",   # Texto principal
    "text_muted":   "#8892b0",   # Texto secundario / apagado
    "border":       "#2d3250",   # Borde de tarjetas
    "tree_bg":      "#1e2235",   # Fondo del Treeview
    "tree_row_alt": "#252a40",   # Filas alternadas del Treeview
    "tree_sel":     "#2a4080",   # Fila seleccionada
    "tree_head":    "#252a40",   # Cabecera del Treeview
    "console_bg":   "#000000",   # Terminal de logs
    "console_fg":   "#00ff00",   # Texto tipo consola
}

FONT_UI    = ("Segoe UI", 10)
FONT_LABEL = ("Segoe UI", 10)
FONT_TITLE = ("Segoe UI", 11, "bold")
FONT_BIG   = ("Segoe UI", 26, "bold")
FONT_CON   = ("Consolas", 11)


# =============================================================================
# CONFIGURACIÓN TLS (CLIENTE)
# =============================================================================

def crear_contexto_ssl():
    """
    [TLS] Crea el contexto SSL para el cliente.
    check_hostname=False y CERT_NONE permiten certificados autofirmados.
    En producción, se cargaría el certificado del servidor para verificarlo.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False      # Certificado autofirmado
    ctx.verify_mode   = ssl.CERT_NONE
    return ctx


# =============================================================================
# CAPA DE COMUNICACIÓN (SOCKETS TLS + JSON)
# =============================================================================

# ---------------------------------------------------------------------------
# PROTOCOLO DE FRAMING: delimitador '\n' (JSON Lines / NDJSON)
# ---------------------------------------------------------------------------
# Cada mensaje JSON se termina con '\n' antes de enviarse.
# El receptor acumula bytes en un bucle while True hasta encontrar '\n'.
# Ventajas frente a parseo especulativo:
#   • Es determinístico: nunca da falsos positivos ni falsos negativos.
#   • Funciona con sockets TLS de larga vida (no se cierran entre mensajes).
#   • El JSON se parsea UNA SOLA VEZ, tras recibir el mensaje completo.
# ---------------------------------------------------------------------------
BUFFER_SIZE   = 65536          # 64 KB por fragmento de lectura
MSG_DELIMITER = b'\n'         # Caracter separador de mensajes


def _enviar_mensaje(sock, datos_dict):
    """
    Serializa 'datos_dict' a JSON y lo envía al socket con el delimitador
    '\n' al final, garantizando que el receptor pueda detectar el fin del
    mensaje de forma inequívoca.

    Args:
        sock:       Socket TLS destino.
        datos_dict: Diccionario Python a enviar como JSON.
    """
    mensaje = json.dumps(datos_dict).encode('utf-8') + MSG_DELIMITER
    sock.sendall(mensaje)


def _recibir_completo(sock):
    """
    [ROBUSTEZ] Bucle while True que acumula fragmentos de 64 KB hasta
    encontrar el delimitador '\n', garantizando que el JSON completo
    esté en memoria antes de llamar a json.loads().

    Esto resuelve el error 'Unterminated string' causado por el truncado
    del JSON a ~16 KB cuando un único recv() no puede abarcar el payload.

    Protocolo:
        Emisor  →  json.dumps(datos) + '\n'
        Receptor →  acumular hasta '\n', luego json.loads()

    Args:
        sock: Socket TLS del cual leer.

    Returns:
        str: Mensaje JSON completo decodificado (sin el delimitador).

    Raises:
        ConnectionResetError: Si el socket se cierra antes de recibir '\n'.
    """
    buffer = b''
    while True:
        fragmento = sock.recv(BUFFER_SIZE)      # Lee hasta 64 KB por ciclo
        if not fragmento:                        # Conexión cerrada inesperadamente
            raise ConnectionResetError("Socket cerrado antes de recibir el delimitador.")
        buffer += fragmento
        if MSG_DELIMITER in buffer:             # Delimitador encontrado → mensaje completo
            # Separar el primer mensaje del resto (precaución con pipelines futuros)
            mensaje, _ = buffer.split(MSG_DELIMITER, 1)
            return mensaje.decode('utf-8')


def _conectar_tls(host, puerto, password, accion_payload):
    """
    Función interna reutilizable:
    1. Abre socket TCP → lo envuelve con TLS.
    2. Envía el mensaje de autenticación (con delimitador '\n').
    3. Envía el payload de la acción (con delimitador '\n').
    4. Acumula la respuesta con _recibir_completo() y retorna el JSON.

    [TLS]  ssl_ctx.wrap_socket() cifra todo el tráfico con TLS.
    [FRAMING] _enviar_mensaje / _recibir_completo usan '\n' como
              delimitador para garantizar que el JSON NUNCA se trunque,
              sin importar el tamaño de la lista de procesos.

    Args:
        host (str):            IP del servidor/middleware.
        puerto (int):          Puerto destino.
        password (str):        Contraseña compartida.
        accion_payload (dict): El comando a enviar.

    Returns:
        dict: Respuesta JSON del servidor, o dict con 'status': 'error'.
    """
    ssl_ctx = crear_contexto_ssl()
    try:
        raw_s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_s.settimeout(20)  # Margen amplio para listas grandes de procesos

        # [TLS] Establecer el túnel cifrado
        with ssl_ctx.wrap_socket(raw_s, server_hostname=host) as s:
            s.connect((host, int(puerto)))

            # --- [SEGURIDAD] Paso 1: Autenticación ---
            _enviar_mensaje(s, {"accion": "auth", "password": password})
            resp_auth = json.loads(_recibir_completo(s))

            if resp_auth.get("status") != "ok":
                return {"status": "error", "mensaje": f"Auth fallida: {resp_auth.get('mensaje', '')}"}

            # --- Paso 2: Enviar el comando real ---
            _enviar_mensaje(s, accion_payload)

            # [ROBUSTEZ] Acumular todos los fragmentos hasta encontrar '\n'
            datos_raw = _recibir_completo(s)
            return json.loads(datos_raw)

    except ssl.SSLError as e:
        return {"status": "error", "mensaje": f"Error TLS: {e}"}
    except socket.timeout:
        return {"status": "error", "mensaje": "Tiempo de espera agotado."}
    except ConnectionRefusedError:
        return {"status": "error", "mensaje": f"Conexión rechazada en {host}:{puerto}"}
    except ConnectionResetError as e:
        return {"status": "error", "mensaje": f"Conexión interrumpida: {e}"}
    except Exception as e:
        return {"status": "error", "mensaje": f"Error de comunicación: {e}"}


def obtener_servidores(mw_host, mw_port, password):
    """Consulta el middleware por la lista de nodos disponibles."""
    return _conectar_tls(mw_host, mw_port, password, {"accion": "get_servers"})


def enviar_comando(host, puerto, password, accion, extra=None):
    """Envía un comando al servidor de cómputo seleccionado."""
    payload = {"accion": accion}
    if extra:
        payload.update(extra)
    return _conectar_tls(host, puerto, password, payload)


# =============================================================================
# HELPER: Estilo oscuro para ttk.Treeview
# =============================================================================

def _aplicar_estilo_treeview():
    """
    Aplica un tema oscuro al ttk.Treeview para que combine con CustomTkinter.
    Se crea un ttk.Style propio para no afectar otros widgets ttk.
    """
    style = ttk.Style()
    style.theme_use("default")

    # Fondo general y texto
    style.configure("Dark.Treeview",
        background=COLORS["tree_bg"],
        foreground=COLORS["text_primary"],
        fieldbackground=COLORS["tree_bg"],
        rowheight=28,
        font=FONT_UI,
        borderwidth=0,
        relief="flat",
    )
    # Cabeceras
    style.configure("Dark.Treeview.Heading",
        background=COLORS["tree_head"],
        foreground=COLORS["accent"],
        font=FONT_TITLE,
        relief="flat",
        borderwidth=0,
        padding=6,
    )
    # Hover sobre encabezado
    style.map("Dark.Treeview.Heading",
        background=[("active", COLORS["bg_card"])],
        foreground=[("active", COLORS["text_primary"])],
    )
    # Fila seleccionada
    style.map("Dark.Treeview",
        background=[("selected", COLORS["tree_sel"])],
        foreground=[("selected", "#ffffff")],
    )

    # Scrollbar integrada
    style.configure("Dark.Vertical.TScrollbar",
        background=COLORS["bg_card"],
        troughcolor=COLORS["tree_bg"],
        arrowcolor=COLORS["accent"],
        borderwidth=0,
    )

    # Combobox oscuro
    style.configure("Dark.TCombobox",
        fieldbackground=COLORS["bg_card"],
        background=COLORS["bg_card"],
        foreground=COLORS["text_primary"],
        arrowcolor=COLORS["accent"],
        borderwidth=1,
        relief="flat",
    )
    style.map("Dark.TCombobox",
        fieldbackground=[("readonly", COLORS["bg_card"])],
        selectbackground=[("readonly", COLORS["bg_card"])],
        selectforeground=[("readonly", COLORS["text_primary"])],
    )


# =============================================================================
# APLICACIÓN GUI
# =============================================================================

class AppGestion(ctk.CTk if USE_CTK else tk.Tk):
    """
    Ventana principal de la aplicación de gestión remota de procesos.
    Compuesta por:
      - Panel de conexión (IP, Puerto, Contraseña)
      - Tabla de procesos
      - Panel de métricas (CPU / RAM)
      - Barra de acciones (Listar, Monitorear, Detener, Iniciar)
      - Registro de actividades (Log)
    """

    COLOR_OK    = COLORS["success"]
    COLOR_ERROR = COLORS["error"]
    COLOR_INFO  = COLORS["info"]
    COLOR_WARN  = COLORS["warning"]

    def __init__(self):
        super().__init__()
        self.title("🖥️  Gestión Remota de Procesos — SO Proyecto Final")
        self.geometry("1280x820")
        self.minsize(1100, 700)
        self.resizable(True, True)

        # Aplicar color de fondo base a la ventana raíz
        if USE_CTK:
            self.configure(fg_color=COLORS["bg_dark"])
        else:
            self.configure(bg=COLORS["bg_dark"])

        # Estado interno
        self._servidor_actual = None   # {"ip": ..., "puerto": ...}

        # Aplicar estilos oscuros a ttk
        _aplicar_estilo_treeview()

        self._construir_ui()

    # -------------------------------------------------------------------------
    # CONSTRUCCIÓN DE LA INTERFAZ
    # -------------------------------------------------------------------------

    def _construir_ui(self):
        """Ensambla todos los paneles de la ventana."""
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=0)  # Header
        self.grid_rowconfigure(1, weight=0)  # Conexion
        self.grid_rowconfigure(2, weight=1)  # Panel principal
        self.grid_rowconfigure(3, weight=0)  # Log

        self._panel_header()
        self._panel_conexion()
        self._panel_principal()
        self._panel_log()

    def _panel_header(self):
        """Banda superior con título y subtítulo de la aplicación."""
        frame = ctk.CTkFrame(self, corner_radius=0, fg_color=COLORS["bg_panel"],
                             border_width=0) if USE_CTK else tk.Frame(self, bg=COLORS["bg_panel"])
        frame.grid(row=0, column=0, sticky="ew")
        frame.grid_columnconfigure(0, weight=1)

        # Línea decorativa izquierda
        accent_bar = ctk.CTkFrame(frame, width=5, corner_radius=0,
                                   fg_color=COLORS["accent"]) if USE_CTK else tk.Frame(frame, width=5, bg=COLORS["accent"])
        accent_bar.pack(side="left", fill="y")

        inner = ctk.CTkFrame(frame, fg_color="transparent") if USE_CTK else tk.Frame(frame, bg=COLORS["bg_panel"])
        inner.pack(side="left", padx=20, pady=14)

        title_lbl = ctk.CTkLabel(inner,
                                  text="🖥️  Remote Process Manager",
                                  font=("Segoe UI", 20, "bold"),
                                  text_color=COLORS["text_primary"]) if USE_CTK else tk.Label(
            inner, text="🖥️  Remote Process Manager",
            font=("Segoe UI", 20, "bold"), bg=COLORS["bg_panel"], fg=COLORS["text_primary"])
        title_lbl.pack(anchor="w")

        sub_lbl = ctk.CTkLabel(inner,
                                text="Sistema Operativos — TLS Encrypted Connection  🔒",
                                font=("Segoe UI", 10),
                                text_color=COLORS["text_muted"]) if USE_CTK else tk.Label(
            inner, text="Sistema Operativos — TLS Encrypted Connection  🔒",
            font=("Segoe UI", 10), bg=COLORS["bg_panel"], fg=COLORS["text_muted"])
        sub_lbl.pack(anchor="w")

        # Indicador de estado (lado derecho)
        self.lbl_status = ctk.CTkLabel(frame,
                                        text="● Desconectado",
                                        font=("Segoe UI", 10, "bold"),
                                        text_color=COLORS["error"]) if USE_CTK else tk.Label(
            frame, text="● Desconectado", font=("Segoe UI", 10, "bold"),
            bg=COLORS["bg_panel"], fg=COLORS["error"])
        self.lbl_status.pack(side="right", padx=20)

    def _panel_conexion(self):
        """Fila de conexión al middleware con campos e IP, Puerto y Contraseña."""
        outer = ctk.CTkFrame(self, corner_radius=12, fg_color=COLORS["bg_panel"],
                              border_width=1, border_color=COLORS["border"]) if USE_CTK else tk.Frame(
            self, bg=COLORS["bg_panel"])
        outer.grid(row=1, column=0, sticky="ew", padx=18, pady=(14, 6))
        outer.grid_columnconfigure(8, weight=1)

        ent_cls = ctk.CTkEntry if USE_CTK else tk.Entry

        # Sección title
        sec_lbl = ctk.CTkLabel(outer, text="  CONEXIÓN AL MIDDLEWARE",
                                font=("Segoe UI", 9, "bold"),
                                text_color=COLORS["accent"]) if USE_CTK else tk.Label(
            outer, text="  CONEXIÓN AL MIDDLEWARE",
            font=("Segoe UI", 9, "bold"), bg=COLORS["bg_panel"], fg=COLORS["accent"])
        sec_lbl.grid(row=0, column=0, columnspan=9, sticky="w", padx=12, pady=(10, 4))

        def _lbl(text, col):
            l = ctk.CTkLabel(outer, text=text, font=FONT_LABEL,
                              text_color=COLORS["text_muted"]) if USE_CTK else tk.Label(
                outer, text=text, font=FONT_LABEL, bg=COLORS["bg_panel"], fg=COLORS["text_muted"])
            l.grid(row=1, column=col, padx=(14, 4), pady=(2, 12), sticky="e")

        _lbl("Middleware IP:", 0)
        self.inp_mw_ip = ent_cls(outer, width=140, font=FONT_UI,
                                   placeholder_text="127.0.0.1") if USE_CTK else tk.Entry(
            outer, width=14, font=FONT_UI, bg=COLORS["bg_card"], fg=COLORS["text_primary"],
            insertbackground=COLORS["accent"], relief="flat")
        self.inp_mw_ip.insert(0, "127.0.0.1")
        self.inp_mw_ip.grid(row=1, column=1, padx=4, pady=(2, 12))

        _lbl("Puerto:", 2)
        self.inp_mw_port = ent_cls(outer, width=80, font=FONT_UI,
                                    placeholder_text="5000") if USE_CTK else tk.Entry(
            outer, width=7, font=FONT_UI, bg=COLORS["bg_card"], fg=COLORS["text_primary"],
            insertbackground=COLORS["accent"], relief="flat")
        self.inp_mw_port.insert(0, "5000")
        self.inp_mw_port.grid(row=1, column=3, padx=4, pady=(2, 12))

        _lbl("Contraseña:", 4)
        self.inp_password = ent_cls(outer, width=200, show="●", font=FONT_UI,
                                     placeholder_text="••••••••") if USE_CTK else tk.Entry(
            outer, width=18, show="●", font=FONT_UI, bg=COLORS["bg_card"],
            fg=COLORS["text_primary"], insertbackground=COLORS["accent"], relief="flat")
        self.inp_password.grid(row=1, column=5, padx=4, pady=(2, 12))

        # Spacer
        outer.grid_columnconfigure(6, weight=1)

        btn = ctk.CTkButton(outer, text="🔍  Descubrir Servidores",
                             command=self._accion_descubrir,
                             width=200, height=36,
                             corner_radius=8,
                             font=("Segoe UI", 11, "bold"),
                             fg_color=COLORS["accent"],
                             hover_color=COLORS["accent_hover"],
                             text_color="#ffffff") if USE_CTK else tk.Button(
            outer, text="🔍 Descubrir Servidores",
            command=self._accion_descubrir, font=FONT_UI,
            bg=COLORS["accent"], fg="white", relief="flat", cursor="hand2")
        btn.grid(row=1, column=7, padx=(8, 14), pady=(2, 12))

    def _panel_principal(self):
        """Zona central: barra de acciones + tabla de procesos + métricas."""
        frame = ctk.CTkFrame(self, corner_radius=0, fg_color="transparent") if USE_CTK else tk.Frame(self, bg=COLORS["bg_dark"])
        frame.grid(row=2, column=0, sticky="nsew", padx=18, pady=4)
        frame.grid_columnconfigure(0, weight=3)
        frame.grid_columnconfigure(1, weight=1)
        frame.grid_rowconfigure(1, weight=1)

        # --- Barra de acciones ---
        self._barra_acciones(frame)

        # --- Tabla de procesos ---
        self._tabla_procesos(frame)

        # --- Panel métricas ---
        self._panel_metricas(frame)

    def _barra_acciones(self, parent):
        """Botones de control y selector de nodo activo."""
        bar = ctk.CTkFrame(parent, corner_radius=10, fg_color=COLORS["bg_panel"],
                            border_width=1,
                            border_color=COLORS["border"]) if USE_CTK else tk.Frame(parent, bg=COLORS["bg_panel"])
        bar.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 8))

        btn_cls = ctk.CTkButton if USE_CTK else tk.Button

        ACCIONES = [
            ("📋  Listar Procesos",  self._accion_listar,    COLORS["accent"],   "#3a72d4"),
            ("📊  Monitorear",       self._accion_monitorear, "#6c5ce7",          "#5849c0"),
            ("🛑  Detener PID",      self._accion_detener,   COLORS["error"],    "#c0392b"),
            ("🚀  Iniciar App",      self._accion_iniciar,   COLORS["success"],  "#27ae60"),
        ]
        for texto, cmd, color, hover in ACCIONES:
            b = ctk.CTkButton(bar, text=texto, command=cmd,
                               width=165, height=38,
                               corner_radius=8,
                               font=("Segoe UI", 10, "bold"),
                               fg_color=color,
                               hover_color=hover,
                               text_color="#ffffff") if USE_CTK else tk.Button(
                bar, text=texto, command=cmd, font=FONT_UI,
                bg=color, fg="white", relief="flat", cursor="hand2")
            b.pack(side="left", padx=8, pady=10)

        # Selector de servidor descubierto
        sep = ctk.CTkLabel(bar, text="│", text_color=COLORS["border"],
                            font=("Segoe UI", 20)) if USE_CTK else tk.Label(
            bar, text="│", bg=COLORS["bg_panel"], fg=COLORS["border"])
        sep.pack(side="left", padx=(12, 0))

        nodo_lbl = ctk.CTkLabel(bar, text="  Nodo activo:", font=FONT_LABEL,
                                  text_color=COLORS["text_muted"]) if USE_CTK else tk.Label(
            bar, text="  Nodo activo:", font=FONT_LABEL,
            bg=COLORS["bg_panel"], fg=COLORS["text_muted"])
        nodo_lbl.pack(side="left", padx=(8, 4))

        self.cb_servidores = ttk.Combobox(bar, width=26, state="readonly",
                                           font=FONT_UI, style="Dark.TCombobox")
        self.cb_servidores.pack(side="left", padx=4, ipady=4)
        self.cb_servidores.bind("<<ComboboxSelected>>", self._on_servidor_seleccionado)

    def _tabla_procesos(self, parent):
        """Tabla con scroll oscuro para mostrar procesos (PID, Nombre, Estado)."""
        card = ctk.CTkFrame(parent, corner_radius=12,
                             fg_color=COLORS["bg_panel"],
                             border_width=1,
                             border_color=COLORS["border"]) if USE_CTK else tk.Frame(
            parent, bg=COLORS["bg_panel"])
        card.grid(row=1, column=0, sticky="nsew", padx=(0, 8))
        card.grid_rowconfigure(1, weight=1)
        card.grid_columnconfigure(0, weight=1)

        # Encabezado de tarjeta
        hdr = ctk.CTkLabel(card, text="  ⚙️  Procesos Remotos",
                             font=("Segoe UI", 10, "bold"),
                             text_color=COLORS["accent"]) if USE_CTK else tk.Label(
            card, text="  ⚙️  Procesos Remotos",
            font=("Segoe UI", 10, "bold"), bg=COLORS["bg_panel"], fg=COLORS["accent"])
        hdr.grid(row=0, column=0, sticky="w", padx=14, pady=(10, 4))

        tree_frame = tk.Frame(card, bg=COLORS["tree_bg"])
        tree_frame.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))
        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)

        cols = ("PID", "Nombre", "Estado")
        self.tabla = ttk.Treeview(tree_frame, columns=cols, show="headings",
                                   style="Dark.Treeview")
        for col in cols:
            self.tabla.heading(col, text=col)
        self.tabla.column("PID",    width=80,  anchor="center")
        self.tabla.column("Nombre", width=320, anchor="w")
        self.tabla.column("Estado", width=120, anchor="center")

        # Filas con color alternado (tags)
        self.tabla.tag_configure("odd",  background=COLORS["tree_bg"])
        self.tabla.tag_configure("even", background=COLORS["tree_row_alt"])

        self.tabla.grid(row=0, column=0, sticky="nsew")

        scroll = ttk.Scrollbar(tree_frame, orient="vertical",
                                command=self.tabla.yview,
                                style="Dark.Vertical.TScrollbar")
        self.tabla.configure(yscrollcommand=scroll.set)
        scroll.grid(row=0, column=1, sticky="ns")

    def _panel_metricas(self, parent):
        """Panel lateral con métricas de CPU y RAM con estilo de dashboard."""
        card = ctk.CTkFrame(parent, corner_radius=12,
                             fg_color=COLORS["bg_panel"],
                             border_width=1,
                             border_color=COLORS["border"]) if USE_CTK else tk.LabelFrame(
            parent, text="Métricas", bg=COLORS["bg_panel"], fg=COLORS["text_primary"])
        card.grid(row=1, column=1, sticky="nsew")

        # Título del panel
        hdr = ctk.CTkLabel(card, text="📈  Recursos del Servidor",
                             font=("Segoe UI", 10, "bold"),
                             text_color=COLORS["accent"]) if USE_CTK else tk.Label(
            card, text="📈  Recursos del Servidor",
            font=("Segoe UI", 10, "bold"), bg=COLORS["bg_panel"], fg=COLORS["accent"])
        hdr.pack(pady=(14, 6), padx=14, anchor="w")

        divider = ctk.CTkFrame(card, height=1, fg_color=COLORS["border"]) if USE_CTK else tk.Frame(card, height=1, bg=COLORS["border"])
        divider.pack(fill="x", padx=14, pady=(0, 16))

        lbl_cls  = ctk.CTkLabel   if USE_CTK else tk.Label
        prog_cls = ctk.CTkProgressBar if USE_CTK else ttk.Progressbar

        # --- CPU ---
        self._metrica_bloque(card, "CPU", "cpu")

        # --- RAM ---
        self._metrica_bloque(card, "RAM", "ram")

        # Detalle RAM
        self.lbl_ram_detalle = ctk.CTkLabel(card, text="",
                                              font=("Segoe UI", 9),
                                              text_color=COLORS["text_muted"]) if USE_CTK else tk.Label(
            card, text="", font=("Segoe UI", 9), bg=COLORS["bg_panel"], fg=COLORS["text_muted"])
        self.lbl_ram_detalle.pack(pady=(0, 16))

    def _metrica_bloque(self, parent, label_text, key):
        """Crea un bloque reutilizable de métrica (número grande + barra de progreso)."""
        wrapper = ctk.CTkFrame(parent, fg_color=COLORS["bg_card"],
                                corner_radius=10) if USE_CTK else tk.Frame(parent, bg=COLORS["bg_card"])
        wrapper.pack(fill="x", padx=14, pady=(0, 14), ipady=8)

        row_top = ctk.CTkFrame(wrapper, fg_color="transparent") if USE_CTK else tk.Frame(wrapper, bg=COLORS["bg_card"])
        row_top.pack(fill="x", padx=12, pady=(10, 2))

        lbl = ctk.CTkLabel(row_top, text=label_text,
                            font=("Segoe UI", 10, "bold"),
                            text_color=COLORS["text_muted"]) if USE_CTK else tk.Label(
            row_top, text=label_text, font=("Segoe UI", 10, "bold"),
            bg=COLORS["bg_card"], fg=COLORS["text_muted"])
        lbl.pack(side="left")

        big_val = ctk.CTkLabel(row_top, text="— %",
                                font=FONT_BIG,
                                text_color=COLORS["text_primary"]) if USE_CTK else tk.Label(
            row_top, text="— %", font=FONT_BIG,
            bg=COLORS["bg_card"], fg=COLORS["text_primary"])
        big_val.pack(side="right")

        if USE_CTK:
            bar = ctk.CTkProgressBar(wrapper, width=180, height=10,
                                      corner_radius=5,
                                      fg_color=COLORS["bg_panel"],
                                      progress_color=COLORS["accent"])
            bar.pack(padx=12, pady=(4, 12))
            bar.set(0)
        else:
            bar = ttk.Progressbar(wrapper, length=180, maximum=100)
            bar.pack(padx=12, pady=(4, 12))

        # Almacenar referencias
        if key == "cpu":
            self.lbl_cpu = big_val
            self.bar_cpu = bar
        else:
            self.lbl_ram = big_val
            self.bar_ram = bar

    def _panel_log(self):
        """Área inferior: terminal de logs con estilo consola."""
        outer = ctk.CTkFrame(self, corner_radius=12,
                              fg_color=COLORS["bg_panel"],
                              border_width=1,
                              border_color=COLORS["border"]) if USE_CTK else tk.LabelFrame(
            self, text="📜 Registro de Actividades",
            bg=COLORS["bg_panel"], fg=COLORS["accent"])
        outer.grid(row=3, column=0, sticky="ew", padx=18, pady=(6, 16))
        outer.grid_columnconfigure(0, weight=1)

        hdr_row = ctk.CTkFrame(outer, fg_color="transparent") if USE_CTK else tk.Frame(outer, bg=COLORS["bg_panel"])
        hdr_row.grid(row=0, column=0, sticky="ew", padx=12, pady=(8, 2))

        hdr_lbl = ctk.CTkLabel(hdr_row, text="📜  Registro de Actividades",
                                 font=("Segoe UI", 10, "bold"),
                                 text_color=COLORS["accent"]) if USE_CTK else tk.Label(
            hdr_row, text="📜  Registro de Actividades",
            font=("Segoe UI", 10, "bold"), bg=COLORS["bg_panel"], fg=COLORS["accent"])
        hdr_lbl.pack(side="left")

        hint = ctk.CTkLabel(hdr_row, text="— consola TLS cifrada",
                              font=("Segoe UI", 9),
                              text_color=COLORS["text_muted"]) if USE_CTK else tk.Label(
            hdr_row, text="— consola TLS cifrada", font=("Segoe UI", 9),
            bg=COLORS["bg_panel"], fg=COLORS["text_muted"])
        hint.pack(side="left", padx=6)

        # Cuadro de texto estilo consola
        if USE_CTK:
            self.log_text = ctk.CTkTextbox(
                outer, height=120,
                font=FONT_CON,
                fg_color=COLORS["console_bg"],
                text_color=COLORS["console_fg"],
                corner_radius=8,
                border_width=1,
                border_color="#1a1a1a",
                scrollbar_button_color=COLORS["bg_card"],
                scrollbar_button_hover_color=COLORS["accent"],
            )
        else:
            self.log_text = tk.Text(
                outer, height=7,
                bg=COLORS["console_bg"],
                fg=COLORS["console_fg"],
                font=FONT_CON,
                insertbackground=COLORS["console_fg"],
                selectbackground=COLORS["accent"],
                relief="flat",
                padx=8, pady=6,
            )
        self.log_text.grid(row=1, column=0, sticky="ew", padx=12, pady=(2, 12))

        self._log("Sistema iniciado. Configure la conexión y pulse 'Descubrir Servidores'.", "INFO")

    # -------------------------------------------------------------------------
    # UTILIDADES DE LOG
    # -------------------------------------------------------------------------

    def _log(self, mensaje, nivel="INFO"):
        """
        Agrega una línea al registro de actividades con timestamp y color indicativo.

        Args:
            mensaje (str): Texto a registrar.
            nivel   (str): INFO | OK | ERROR | WARN
        """
        iconos = {"INFO": "[INFO] ", "OK": "[ OK ]  ", "ERROR": "[ERR]  ", "WARN": "[WARN] "}
        ts     = datetime.now().strftime("%H:%M:%S")
        linea  = f"[{ts}] {iconos.get(nivel,'•')} {mensaje}\n"
        if USE_CTK:
            self.log_text.configure(state="normal")
            self.log_text.insert("end", linea)
            self.log_text.see("end")
            self.log_text.configure(state="disabled")
        else:
            self.log_text.insert("end", linea)
            self.log_text.see("end")

    # -------------------------------------------------------------------------
    # ACCIONES (ejecutadas en hilos para no bloquear la GUI)
    # -------------------------------------------------------------------------

    def _get_conn_params(self):
        """Retorna (ip, puerto, password) desde los campos de entrada."""
        return (
            self.inp_mw_ip.get().strip(),
            self.inp_mw_port.get().strip(),
            self.inp_password.get().strip(),
        )

    def _accion_descubrir(self):
        """Consulta el middleware por servidores disponibles (en hilo)."""
        ip, port, pw = self._get_conn_params()
        if not pw:
            messagebox.showwarning("Atención", "Ingresa la contraseña.")
            return
        self._log(f"Consultando middleware en {ip}:{port} …", "INFO")
        threading.Thread(target=self._worker_descubrir, args=(ip, port, pw), daemon=True).start()

    def _worker_descubrir(self, ip, port, pw):
        resp = obtener_servidores(ip, port, pw)
        if resp.get("status") == "ok":
            srvs = resp.get("servidores", [])
            opciones = [f"{s['ip']}:{s['puerto']}" for s in srvs]
            self.after(0, lambda: self._actualizar_combobox(opciones, srvs))
            n = len(srvs)
            self._log(f"{n} servidor(es) encontrado(s) via TLS.", "OK")
            self.after(0, lambda: self.lbl_status.configure(
                text=f"● Conectado  ({n} nodo(s))",
                text_color=COLORS["success"]))
        else:
            self._log(f"Error al descubrir: {resp.get('mensaje')}", "ERROR")
            self.after(0, lambda: self.lbl_status.configure(
                text="● Error de conexión",
                text_color=COLORS["error"]))

    def _actualizar_combobox(self, opciones, srvs):
        self.cb_servidores['values'] = opciones
        self._srvs_data = srvs
        if opciones:
            self.cb_servidores.current(0)
            self._servidor_actual = srvs[0]

    def _on_servidor_seleccionado(self, _event):
        idx = self.cb_servidores.current()
        if hasattr(self, '_srvs_data') and 0 <= idx < len(self._srvs_data):
            self._servidor_actual = self._srvs_data[idx]
            self._log(f"Nodo activo: {self._servidor_actual['ip']}:{self._servidor_actual['puerto']}", "INFO")

    def _check_servidor(self):
        """Verifica que haya un servidor seleccionado y contraseña ingresada."""
        if not self._servidor_actual:
            messagebox.showwarning("Atención", "Primero descubre y selecciona un servidor.")
            return False
        if not self.inp_password.get().strip():
            messagebox.showwarning("Atención", "Ingresa la contraseña.")
            return False
        return True

    # --- Listar ---
    def _accion_listar(self):
        if not self._check_servidor():
            return
        self._log("Solicitando lista de procesos …", "INFO")
        ip  = self._servidor_actual['ip']
        pt  = self._servidor_actual['puerto']
        pw  = self.inp_password.get().strip()
        threading.Thread(target=self._worker_listar, args=(ip, pt, pw), daemon=True).start()

    def _worker_listar(self, ip, pt, pw):
        resp = enviar_comando(ip, pt, pw, 'list')
        if resp.get("status") == "ok":
            procs = resp.get("procesos", [])
            self.after(0, lambda: self._llenar_tabla(procs))
            self._log(f"{len(procs)} procesos obtenidos del nodo {ip}:{pt}.", "OK")
        else:
            self._log(f"Error al listar: {resp.get('mensaje')}", "ERROR")

    def _llenar_tabla(self, procesos):
        self.tabla.delete(*self.tabla.get_children())
        for i, p in enumerate(procesos):
            tag = "even" if i % 2 == 0 else "odd"
            self.tabla.insert("", "end",
                               values=(p['pid'], p['nombre'], p.get('estado', '—')),
                               tags=(tag,))

    # --- Monitorear ---
    def _accion_monitorear(self):
        if not self._check_servidor():
            return
        self._log("Midiendo CPU y RAM (espere ~1 s) …", "INFO")
        ip = self._servidor_actual['ip']
        pt = self._servidor_actual['puerto']
        pw = self.inp_password.get().strip()
        threading.Thread(target=self._worker_monitorear, args=(ip, pt, pw), daemon=True).start()

    def _worker_monitorear(self, ip, pt, pw):
        resp = enviar_comando(ip, pt, pw, 'monitor')
        if resp.get("status") == "ok":
            cpu  = resp.get("cpu_percent", 0)
            mem  = resp.get("memoria_percent", 0)
            tot  = resp.get("memoria_total_gb", 0)
            used = resp.get("memoria_usada_gb", 0)
            self.after(0, lambda: self._actualizar_metricas(cpu, mem, tot, used))
            self._log(f"CPU={cpu:.1f}%  RAM={mem:.1f}%  ({used:.1f}/{tot:.1f} GB)", "OK")
        else:
            self._log(f"Error al monitorear: {resp.get('mensaje')}", "ERROR")

    def _actualizar_metricas(self, cpu, mem, tot, used):
        self.lbl_cpu.configure(text=f"{cpu:.1f} %")
        self.lbl_ram.configure(text=f"{mem:.1f} %")
        self.lbl_ram_detalle.configure(text=f"{used:.1f} / {tot:.1f} GB")
        if USE_CTK:
            self.bar_cpu.set(cpu / 100)
            self.bar_ram.set(mem / 100)
        else:
            self.bar_cpu['value'] = cpu
            self.bar_ram['value'] = mem

    # --- Detener ---
    def _accion_detener(self):
        if not self._check_servidor():
            return
        # Intentar obtener PID de la fila seleccionada en la tabla
        sel = self.tabla.selection()
        pid_sugerido = ""
        if sel:
            pid_sugerido = self.tabla.item(sel[0])['values'][0]

        dialogo = _DialogoEntrada(self, titulo="Detener Proceso",
                                   etiqueta="PID a detener:", valor_inicial=str(pid_sugerido))
        pid_str = dialogo.resultado
        if pid_str is None:
            return
        try:
            pid = int(pid_str)
        except ValueError:
            messagebox.showerror("Error", "PID debe ser un número entero.")
            return

        self._log(f"Enviando señal TERMINATE al PID {pid} …", "WARN")
        ip = self._servidor_actual['ip']
        pt = self._servidor_actual['puerto']
        pw = self.inp_password.get().strip()
        threading.Thread(target=self._worker_detener, args=(ip, pt, pw, pid), daemon=True).start()

    def _worker_detener(self, ip, pt, pw, pid):
        resp = enviar_comando(ip, pt, pw, 'stop', {"pid": pid})
        nivel = "OK" if resp.get("status") == "ok" else "ERROR"
        self._log(resp.get("mensaje", str(resp)), nivel)

    # --- Iniciar ---
    def _accion_iniciar(self):
        if not self._check_servidor():
            return
        dialogo = _DialogoEntrada(self, titulo="Iniciar Aplicación",
                                   etiqueta="Nombre o ruta de la app:", valor_inicial="")
        app = dialogo.resultado
        if not app:
            return

        self._log(f"Iniciando '{app}' en el nodo remoto …", "INFO")
        ip = self._servidor_actual['ip']
        pt = self._servidor_actual['puerto']
        pw = self.inp_password.get().strip()
        threading.Thread(target=self._worker_iniciar, args=(ip, pt, pw, app), daemon=True).start()

    def _worker_iniciar(self, ip, pt, pw, app):
        resp = enviar_comando(ip, pt, pw, 'start', {"app": app})
        nivel = "OK" if resp.get("status") == "ok" else "ERROR"
        self._log(resp.get("mensaje", str(resp)), nivel)


# =============================================================================
# DIÁLOGO AUXILIAR PARA ENTRADAS DE TEXTO (Estilo oscuro)
# =============================================================================

class _DialogoEntrada(tk.Toplevel):
    """Diálogo modal simple para pedir un valor al usuario — tema oscuro."""

    def __init__(self, parent, titulo, etiqueta, valor_inicial=""):
        super().__init__(parent)
        self.title(titulo)
        self.resizable(False, False)
        self.wait_visibility()  # Espera a que la ventana exista físicamente
        self.grab_set()         # Ahora sí la hace modal sin errores
        self.resultado = None
        self.configure(bg=COLORS["bg_panel"])

        # Contenedor con margen
        wrapper = tk.Frame(self, bg=COLORS["bg_panel"])
        wrapper.pack(padx=28, pady=24, fill="both", expand=True)

        tk.Label(wrapper, text=titulo, font=("Segoe UI", 13, "bold"),
                 bg=COLORS["bg_panel"], fg=COLORS["text_primary"]).pack(anchor="w")
        tk.Frame(wrapper, height=1, bg=COLORS["border"]).pack(fill="x", pady=(6, 16))

        tk.Label(wrapper, text=etiqueta, font=("Segoe UI", 10),
                 bg=COLORS["bg_panel"], fg=COLORS["text_muted"]).pack(anchor="w")

        self.entrada = tk.Entry(wrapper, width=32, font=("Segoe UI", 11),
                                bg=COLORS["bg_card"], fg=COLORS["text_primary"],
                                insertbackground=COLORS["accent"],
                                relief="flat", bd=6)
        self.entrada.insert(0, valor_inicial)
        self.entrada.pack(fill="x", pady=(4, 16))
        self.entrada.focus()

        btns = tk.Frame(wrapper, bg=COLORS["bg_panel"])
        btns.pack(fill="x")

        tk.Button(btns, text="  Aceptar  ", font=("Segoe UI", 10, "bold"),
                  bg=COLORS["accent"], fg="white", activebackground=COLORS["accent_hover"],
                  activeforeground="white", relief="flat", cursor="hand2",
                  command=self._aceptar).pack(side="left", padx=(0, 8))

        tk.Button(btns, text="  Cancelar  ", font=("Segoe UI", 10),
                  bg=COLORS["bg_card"], fg=COLORS["text_muted"],
                  activebackground=COLORS["border"], activeforeground=COLORS["text_primary"],
                  relief="flat", cursor="hand2",
                  command=self.destroy).pack(side="left")

        self.bind("<Return>", lambda _: self._aceptar())
        self.bind("<Escape>", lambda _: self.destroy())
        self.wait_window()

    def _aceptar(self):
        self.resultado = self.entrada.get().strip()
        self.destroy()


# =============================================================================
# PUNTO DE ENTRADA
# =============================================================================

if __name__ == '__main__':
    app = AppGestion()
    app.mainloop()
