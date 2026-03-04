# 🖥️ Remote Process Manager v2.0

> **Proyecto Final — Sistemas Operativos**
> Sistema distribuido de 3 capas para gestión remota de procesos en tiempo real.

![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Security](https://img.shields.io/badge/Security-TLS%2FSSL-success?style=for-the-badge&logo=letsencrypt&logoColor=white)
![GUI](https://img.shields.io/badge/GUI-CustomTkinter-blueviolet?style=for-the-badge&logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Windows%20%2B%20Ubuntu-0078D6?style=for-the-badge&logo=linux&logoColor=white)
![Protocol](https://img.shields.io/badge/Protocol-TCP%2FIP%20%2B%20JSON-orange?style=for-the-badge)
![Cloud](https://img.shields.io/badge/Cloud--Ready-AWS%20EC2%20%2F%20Docker-FF9900?style=for-the-badge&logo=amazonaws&logoColor=white)

---

## 📋 Tabla de Contenidos

- [Descripción](#-descripción)
- [Arquitectura](#-arquitectura)
- [Características Clave v2.0](#-características-clave-v20)
- [Entorno Multiplataforma](#-entorno-multiplataforma-red-real)
- [Dependencias](#-dependencias)
- [Configuración TLS — Certificados](#-configuración-tls--certificados-paso-previo-obligatorio)
- [Instrucciones de Ejecución](#-instrucciones-de-ejecución)
- [Flujo de Mensajes JSON](#-flujo-de-mensajes-json)
- [Manejo de Cargas Masivas](#-manejo-de-cargas-masivas-buffer-64-kb)
- [Roadmap Cloud](#-roadmap-cloud-ready)

---

## 📖 Descripción

Sistema distribuido de gestión remota de procesos compuesto por **3 capas** que se comunican mediante **Sockets TCP/IP cifrados con TLS** e intercambian **mensajes JSON** con un protocolo de framing por delimitador (`\n`).

La versión 2.0 evoluciona de un prototipo de consola local a un sistema de **red real multiplataforma**, con un **Dashboard GUI asíncrono** en el cliente y **cifrado TLS extremo a extremo** en toda la infraestructura.

---

## 🏗️ Arquitectura

```
                    ┌ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┐
                              UBUNTU 24.04 VM (Adaptador Puente)
                    │                                                           │
    ┌─────────────────────┐  [TLS🔒] Auth+Register  ┌─────────────────────┐
    │      CAPA 1         │◄────────────────────────│      CAPA 2         │   │
    │    middleware.py    │                          │     server.py       │
    │                     │────────────────────────►│                     │   │
    │  Service Registry   │    {status: "ok"}        │  Nodo de Cómputo    │
    │   Puerto: 5000      │                          │   Puerto: 6000      │   │
    │  TLS 🔒 | Auth 🔑  │                          │  TLS 🔒 | psutil   │
    └─────────────────────┘                          └──────────┬──────────┘   │
             ▲                                                  │
    │        │ [TLS🔒] get_servers                              │ [TLS🔒]     │
             │                                                  │  Comandos
    │        │                                                  │  + Procesos │
             │         ┌───────────────────────────────────────►│
    │        │         │                                        │             │
             │   ┌─────┴────────────────┐                       │
    │        └───│      CAPA 3          │◄──────────────────────┘             │
                 │     client.py        │      JSON  { procesos: [...] }
    │            │                      │                                     │
                 │  Dashboard GUI       │
    │            │  (CustomTkinter)     │                                     │
                 │  Windows Host 🪟     │
    │            │  TLS 🔒 | Async     │                                     │
                 └──────────────────────┘
    └ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─┘
```

> **Flujo de descubrimiento:**
>
> 1. `server.py` se **registra** en el middleware via TLS al iniciar.
> 2. `client.py` consulta al middleware (**get_servers**) para descubrir nodos disponibles.
> 3. `client.py` se comunica **directamente** con el `server.py` seleccionado para enviar comandos.

---

## ✨ Características Clave v2.0

| Característica          | v1.0 (Inicial)              | v2.0 (Actual)                                   |
| ----------------------- | --------------------------- | ----------------------------------------------- |
| **Interfaz de usuario** | CLI (consola)               | Dashboard GUI asíncrono (CustomTkinter)         |
| **Seguridad**           | Sin cifrado                 | TLS/SSL extremo a extremo 🔒                    |
| **Autenticación**       | Sin auth                    | Token/contraseña compartida (`SHARED_PASSWORD`) |
| **Entorno**             | `localhost` únicamente      | Red real (Bridged Network) — Windows + Ubuntu   |
| **Carga de procesos**   | Buffer por defecto (~16 KB) | Buffer 64 KB + framing `\n` (300+ procesos)     |
| **Descubrimiento**      | IP hardcodeada              | Service Registry dinámico (Middleware)          |
| **Escalabilidad**       | 1 nodo fijo                 | Múltiples nodos registrados simultáneamente     |

---

## 🌐 Entorno Multiplataforma (Red Real)

El sistema fue desarrollado y probado en un entorno de **red real** con dos máquinas físicamente separadas comunicadas por red LAN:

| Componente                         | Plataforma                                  | IP de ejemplo  |
| ---------------------------------- | ------------------------------------------- | -------------- |
| `client.py` — Dashboard GUI        | Windows 11 (Host)                           | `192.168.1.X`  |
| `middleware.py` — Service Registry | Ubuntu 24.04 VM (Adaptador Puente)          | `192.168.1.Y`  |
| `server.py` — Nodo de Cómputo      | Ubuntu 24.04 VM (mismo host que middleware) | `192.168.1.69` |

> ⚠️ **Adaptador Puente** obligatorio en la VM para que reciba su propia IP del router y sea accesible desde el host Windows. El adaptador NAT no permite la comunicación bidireccional requerida.

---

## 📦 Dependencias

```bash
# Instalar todas las dependencias necesarias
pip install customtkinter psutil
```

| Librería          | Uso                                            | Capa               |
| ----------------- | ---------------------------------------------- | ------------------ |
| `socket`          | Comunicación TCP/IP                            | Todas              |
| `ssl`             | Cifrado TLS/SSL                                | Todas              |
| `threading`       | Manejo concurrente de conexiones               | middleware, server |
| `json`            | Serialización de mensajes                      | Todas              |
| `psutil`          | Información de procesos del SO (300+ procesos) | server             |
| `subprocess`      | Lanzar aplicaciones remotamente                | server             |
| `customtkinter`   | Dashboard GUI moderno                          | client             |
| `tkinter` / `ttk` | Widgets de tabla y fallback                    | client             |

---

## 🔐 Configuración TLS — Certificados (Paso Previo Obligatorio)

Toda la comunicación está cifrada con **TLS 1.2/1.3**. Debes generar o ubicar los certificados antes de ejecutar cualquier componente.

### Opción A: Generar un certificado autofirmado (Recomendado para desarrollo)

Ejecuta el siguiente comando **dentro del directorio del proyecto** (donde están los `.py`):

```bash
openssl req -x509 -newkey rsa:4096 \
  -keyout server.key \
  -out server.crt \
  -days 365 \
  -nodes \
  -subj "/CN=SO-Proyecto/O=Universidad/C=MX"
```

> ✅ Esto genera `server.crt` y `server.key` — los dos archivos que los tres componentes necesitan.

### Opción B: Usar los certificados ya incluidos en este repositorio

El repositorio ya incluye un par de certificados autofirmados válidos:

```
server.crt   ← Certificado público (X.509, RSA 4096)
server.key   ← Clave privada (NO compartir en producción)
```

⚠️ Para **producción real** en la nube, reemplaza estos archivos por certificados firmados por una CA confiable (Let's Encrypt, AWS ACM, etc.).

### Dónde deben estar los archivos

Coloca `server.crt` y `server.key` en el **mismo directorio** desde donde ejecutas cada script:

```
so_remote_process_manager/
├── middleware.py
├── server.py
├── client.py
├── server.crt   ← AQUÍ
└── server.key   ← AQUÍ
```

---

## 🚀 Instrucciones de Ejecución

> **IMPORTANTE:** Abre terminales separadas y respeta el orden. El middleware SIEMPRE debe iniciar primero.

### Terminal 1 — Middleware (Ubuntu VM) 🌐

```bash
cd /ruta/al/proyecto
python3 middleware.py
```

Salida esperada:

```
=======================================================
  MIDDLEWARE SEGURO (Service Registry + TLS) iniciado
  Escuchando en 0.0.0.0:5000 [TLS HABILITADO]
=======================================================
```

### Terminal 2 — Servidor / Nodo de Cómputo (Ubuntu VM) ⚙️

> Antes de ejecutar, edita `server.py` y ajusta:
>
> - `HOST` → IP de la VM Ubuntu (ej: `192.168.1.69`)
> - `MIDDLEWARE_HOST` → IP del middleware (puede ser `127.0.0.1` si corren en la misma VM)

```bash
cd /ruta/al/proyecto
python3 server.py
```

Salida esperada:

```
[SERVIDOR] ✔ Registrado en middleware con TLS exitosamente.
=======================================================
  SERVIDOR SEGURO (Nodo de Cómputo + TLS) iniciado
  Escuchando en 192.168.1.69:6000 [TLS HABILITADO]
=======================================================
```

### Terminal 3 — Cliente Dashboard GUI (Windows Host) 🪟

> Antes de ejecutar, edita `client.py` y ajusta el campo `inp_mw_ip` por defecto, o simplemente ingrésala en la GUI al iniciar.

```bash
cd C:\ruta\al\proyecto
python client.py
```

En la GUI:

1. Ingresa la **IP del Middleware** (ej: `192.168.1.Y`) y Puerto `5000`.
2. Ingresa la **contraseña compartida**: `SO_PROYECTO_2024`.
3. Pulsa **🔍 Descubrir Servidores**.
4. Selecciona el nodo en el **Combobox** y usa los botones de acción.

---

## 📨 Flujo de Mensajes JSON

### Fase 1: Autenticación (obligatoria en toda conexión)

| Paso          | Emisor                    | Receptor                      | Payload                                              |
| ------------- | ------------------------- | ----------------------------- | ---------------------------------------------------- |
| Auth request  | `client.py` / `server.py` | `middleware.py` / `server.py` | `{"accion": "auth", "password": "SO_PROYECTO_2024"}` |
| Auth response | middleware / server       | cliente                       | `{"status": "ok", "mensaje": "Autenticado."}`        |

### Fase 2: Service Discovery (Client ↔ Middleware)

| Acción        | Emisor          | Receptor        | Payload                                                           |
| ------------- | --------------- | --------------- | ----------------------------------------------------------------- |
| `register`    | `server.py`     | `middleware.py` | `{"accion": "register", "ip": "192.168.1.69", "puerto": 6000}`    |
| `get_servers` | `client.py`     | `middleware.py` | `{"accion": "get_servers"}`                                       |
| Respuesta     | `middleware.py` | `client.py`     | `{"status": "ok", "servidores": [{"ip": "...", "puerto": 6000}]}` |

### Fase 3: Comandos de Gestión (Client ↔ Server)

| Acción    | Emisor      | Receptor    | Payload de ejemplo                      |
| --------- | ----------- | ----------- | --------------------------------------- |
| `list`    | `client.py` | `server.py` | `{"accion": "list"}`                    |
| `monitor` | `client.py` | `server.py` | `{"accion": "monitor"}`                 |
| `stop`    | `client.py` | `server.py` | `{"accion": "stop", "pid": 1234}`       |
| `start`   | `client.py` | `server.py` | `{"accion": "start", "app": "firefox"}` |

### Respuestas del Servidor

| Comando   | Respuesta exitosa                                                                                                  |
| --------- | ------------------------------------------------------------------------------------------------------------------ |
| `list`    | `{"status": "ok", "procesos": [{"pid": 1, "nombre": "systemd", "estado": "sleeping"}, ...]}`                       |
| `monitor` | `{"status": "ok", "cpu_percent": 12.5, "memoria_percent": 67.3, "memoria_total_gb": 8.0, "memoria_usada_gb": 5.4}` |
| `stop`    | `{"status": "ok", "mensaje": "Proceso 'firefox' (PID 1234) terminado."}`                                           |
| `start`   | `{"status": "ok", "mensaje": "Aplicación 'gedit' iniciada con PID 5678."}`                                         |

---

## 🛡️ Seguridad — Capas Implementadas

```
  Cliente                    Middleware / Servidor
     │                              │
     │──── 1. TLS Handshake ───────►│  (cifrado del canal con server.crt)
     │                              │
     │──── 2. {"accion":"auth"} ───►│  (autenticación por token)
     │◄─── {"status":"ok"} ────────│
     │                              │
     │──── 3. Comando JSON ────────►│  (mensaje con delimitador \n)
     │◄─── Respuesta JSON ─────────│  (framing garantiza integridad)
     │                              │
```

- **TLS 1.2/1.3**: El socket TCP es envuelto con `ssl.SSLContext` antes de cualquier transmisión.
- **Autenticación por token**: Cada conexión debe presentar `SHARED_PASSWORD` como primer mensaje.
- **Certificados autofirmados**: Válidos para entorno universitario/desarrollo. Para producción, usar CA confiable.
- **Sin exposición de credenciales**: La contraseña viaja cifrada dentro del túnel TLS.

---

## 📦 Manejo de Cargas Masivas (Buffer 64 KB)

Un sistema Linux real puede tener **300+ procesos activos**. El JSON resultante puede superar los 16 KB, lo que causaba el error `Unterminated string` con un solo `recv()`.

**Solución implementada — Protocolo de Framing con delimitador `\n`:**

```
Emisor:   json.dumps(datos).encode('utf-8') + b'\n'  →  sendall()
Receptor: Acumular en while True hasta encontrar b'\n'  →  json.loads()
```

```python
BUFFER_SIZE   = 65536    # 64 KB por fragmento de lectura
MSG_DELIMITER = b'\n'    # Separador de fin de mensaje

def _recibir_completo(conn):
    buffer = b''
    while True:
        fragmento = conn.recv(BUFFER_SIZE)   # Lee hasta 64 KB
        if not fragmento:
            raise ConnectionResetError("Socket cerrado antes del delimitador.")
        buffer += fragmento
        if MSG_DELIMITER in buffer:          # Mensaje completo recibido
            mensaje, _ = buffer.split(MSG_DELIMITER, 1)
            return mensaje.decode('utf-8')
```

Este protocolo está implementado simétricamente en los tres componentes: `middleware.py`, `server.py` y `client.py`.

---

## ☁️ Roadmap Cloud-Ready

La arquitectura del **Service Registry (Middleware)** está diseñada para escalar horizontalmente a la nube sin cambios en `server.py` o `client.py`:

### Migración a AWS EC2

```
                    ┌─────────────────────────────┐
                    │      AWS EC2 Instance        │
                    │  ┌───────────────────────┐   │
Internet ─── HTTPS ──►│  middleware.py         │   │
                    │  │  Puerto 5000 (TLS)    │   │
                    │  │  Security Group: 5000 │   │
                    │  └───────────────────────┘   │
                    │  Elastic IP: x.x.x.x         │
                    └─────────────────────────────┘
                              ▲         │
                    register  │         │  get_servers
                              │         ▼
                    ┌─────────┐      ┌──────────┐
                    │server.py│      │client.py │
                    │(Ubuntu) │      │(Windows) │
                    └─────────┘      └──────────┘
```

### Migración a Docker

```yaml
# docker-compose.yml (concepto)
services:
  middleware:
    build: .
    command: python3 middleware.py
    ports:
      - "5000:5000"
    volumes:
      - ./server.crt:/app/server.crt
      - ./server.key:/app/server.key

  server:
    build: .
    command: python3 server.py
    environment:
      - MIDDLEWARE_HOST=middleware
    depends_on:
      - middleware
```

### Pasos para escalar

1. **Reemplazar** `server.crt` / `server.key` por certificados firmados por una CA (Let's Encrypt).
2. **Configurar** la variable `SHARED_PASSWORD` como variable de entorno (`os.environ.get`).
3. **Desplegar** el middleware en EC2 o como contenedor en ECS/Fargate.
4. **Configurar** Security Groups para permitir el puerto `5000` solo desde las IPs de los servidores.
5. **Escalar** horizontalmente añadiendo más instancias de `server.py` que se registren en el mismo middleware.

---

## 📁 Estructura del Proyecto

```
so_remote_process_manager/
│
├── middleware.py     # Capa 1: Service Registry (puerto 5000, TLS, Threading)
├── server.py         # Capa 2: Nodo de Cómputo (puerto 6000, TLS, psutil)
├── client.py         # Capa 3: Dashboard GUI (CustomTkinter, async, TLS)
│
├── server.crt        # Certificado TLS público (X.509, RSA 4096)
├── server.key        # Clave privada TLS (mantener segura)
│
└── README.md         # Este archivo
```

---

## 👨‍💻 Autor

**Eduardo Quiroz, Kenneth Zuany y Oscar Reyes**
Proyecto Final — Curso de Sistemas Operativos
Universidad | Semestre 2026

---

<div align="center">

**⚡ Built with Python · Secured with TLS · Powered by psutil**

![Status](https://img.shields.io/badge/Status-Funcional%20en%20Red%20Real-brightgreen?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-blue?style=flat-square)

</div>
