# 🐺 WazuhBOTS — Boss of the SOC con Wazuh

## Proyecto: Plataforma CTF Open Source basada en Wazuh SIEM

**Autor:** MrHacker (Kevin Muñoz) — Wazuh Technology Ambassador  
**Versión:** 1.0  
**Fecha:** Febrero 2026  
**Licencia:** Open Source (MIT)

---

## 1. Visión General del Proyecto

### 1.1 ¿Qué es WazuhBOTS?

WazuhBOTS es una plataforma de competencia estilo "Boss of the SOC" (BOTS) construida 100% con herramientas open source, centrada en Wazuh como SIEM principal. Los participantes investigan incidentes de seguridad reales pre-generados, respondiendo preguntas escalonadas por dificultad cuyas respuestas se validan como "flags" en una plataforma CTF.

### 1.2 Objetivos Multi-Propósito

El diseño modular permite que WazuhBOTS funcione para:

- **Entrenamiento interno SOC:** Onboarding de analistas N1/N2, evaluación de competencias, simulacros de incidentes.
- **Eventos comunitarios / Meetups Wazuh:** Competencias en vivo con scoreboard, ideal para Wazuh Community Meetups.
- **Contenido educativo:** Material publicable como laboratorio autoguiado, tutoriales, o cursos.
- **CTF público:** Competencia abierta con registro, equipos, y clasificación global.

### 1.3 Modelo de Dificultad Progresiva

| Nivel | Nombre | Perfil | Puntos por pregunta | Descripción |
|-------|--------|--------|---------------------|-------------|
| 1 | **Cachorro (Pup)** | Analista N1 / Estudiante | 100 pts | Navegación básica de dashboards, búsquedas simples, identificación de alertas |
| 2 | **Cazador (Hunter)** | Analista N2 | 200 pts | Correlación de eventos, análisis de reglas, investigación de incidentes |
| 3 | **Alfa (Alpha)** | Threat Hunter / IR | 300 pts | Threat hunting avanzado, análisis forense, creación de reglas custom |
| 4 | **Fenrir (Boss)** | Experto / Red Team | 500 pts | Escenarios complejos multi-vector, evasión de detección, respuesta completa |

---

## 2. Arquitectura Técnica

### 2.1 Stack Tecnológico Completo (100% Open Source)

| Componente | Herramienta | Función |
|------------|-------------|---------|
| SIEM Core | Wazuh Manager 4.x | Recolección, decodificación y correlación de logs |
| Indexer | Wazuh Indexer (OpenSearch) | Almacenamiento e indexación de alertas |
| Dashboard | Wazuh Dashboard | Interfaz de análisis para participantes |
| Plataforma CTF | CTFd | Scoreboard, flags, hints, equipos, registro |
| Generación de Ataques | Atomic Red Team + CALDERA | Simulación de TTPs del MITRE ATT&CK |
| Máquinas Víctima | Docker containers | Servidores vulnerables con agentes Wazuh |
| Orquestación | Docker Compose | Despliegue completo en un solo comando |
| Proxy Reverso | Nginx | Acceso unificado a Dashboard y CTFd |
| Automatización | Python scripts | Ingestión de datasets, generación de flags, setup |

### 2.2 Diagrama de Arquitectura

```
┌─────────────────────────────────────────────────────────────────┐
│                    WazuhBOTS Infrastructure                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐       │
│  │  Participante │    │  Participante │    │  Participante │       │
│  │   Browser     │    │   Browser     │    │   Browser     │       │
│  └──────┬───────┘    └──────┬───────┘    └──────┬───────┘       │
│         │                   │                   │                │
│         └───────────────────┼───────────────────┘                │
│                             │                                    │
│                    ┌────────▼────────┐                           │
│                    │   Nginx Proxy    │                           │
│                    │   :80 / :443     │                           │
│                    └───┬────────┬────┘                           │
│                        │        │                                │
│              ┌─────────▼──┐  ┌──▼──────────┐                    │
│              │   Wazuh     │  │    CTFd      │                    │
│              │  Dashboard  │  │  Scoreboard  │                    │
│              │   :5601     │  │    :8000     │                    │
│              └─────┬───────┘  └──────┬──────┘                    │
│                    │                 │                            │
│              ┌─────▼───────┐  ┌─────▼───────┐                   │
│              │   Wazuh      │  │   MariaDB    │                   │
│              │   Indexer    │  │   (CTFd DB)  │                   │
│              │  (OpenSearch)│  │    :3306     │                   │
│              │   :9200     │  └──────────────┘                   │
│              └─────┬───────┘                                     │
│                    │                                             │
│              ┌─────▼───────┐                                     │
│              │   Wazuh      │                                     │
│              │   Manager    │                                     │
│              │   :1514/1515 │                                     │
│              └─────┬───────┘                                     │
│                    │                                             │
│    ┌───────────────┼───────────────┐                             │
│    │               │               │                             │
│  ┌─▼──────┐  ┌────▼─────┐  ┌─────▼────┐                        │
│  │ WEB-SRV │  │ DC-SRV   │  │ LNX-SRV  │                        │
│  │ (Vuln   │  │ (Active  │  │ (Linux   │                        │
│  │  WebApp)│  │  Dir Sim)│  │  Server) │                        │
│  │ Agent 1 │  │ Agent 2  │  │ Agent 3  │                        │
│  └─────────┘  └──────────┘  └──────────┘                        │
│                                                                  │
│  ┌──────────────────────────────────────┐                       │
│  │    Attack Simulation Layer            │                       │
│  │  ┌────────────┐  ┌────────────────┐  │                       │
│  │  │ Atomic Red  │  │    CALDERA     │  │                       │
│  │  │   Team      │  │   (C2 Server)  │  │                       │
│  │  └────────────┘  └────────────────┘  │                       │
│  └──────────────────────────────────────┘                       │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### 2.3 Requisitos de Hardware

| Escenario | CPU | RAM | Disco | Notas |
|-----------|-----|-----|-------|-------|
| Desarrollo / Personal | 4 cores | 16 GB | 100 GB SSD | Laptop/PC local |
| Meetup (10-20 personas) | 8 cores | 32 GB | 200 GB SSD | VPS o servidor dedicado |
| CTF Público (50+ personas) | 16 cores | 64 GB | 500 GB SSD | Cloud (AWS/Azure/GCP) |
| Entrenamiento corporativo | 8 cores | 32 GB | 200 GB SSD | Servidor on-premise |

---

## 3. Escenarios de Ataque

### 3.1 Escenario 1: "Operation Dark Harvest" (Web Application Compromise)

**Narrativa:** Un atacante externo compromete una aplicación web vulnerable, escala privilegios y exfiltra datos de la base de datos.

**Kill Chain:**
1. Reconocimiento con Nmap/Nikto (logs en Wazuh)
2. Explotación de SQLi en aplicación DVWA
3. Web shell upload (detección por FIM de Wazuh)
4. Escalación de privilegios local (sudo exploit)
5. Dump de base de datos y exfiltración
6. Persistencia vía cron job malicioso

**Máquina víctima:** `web-srv` — Container con Apache + DVWA + MySQL + Wazuh Agent

**Reglas Wazuh activadas:**
- Rule 31101-31110: Web attack detection
- Rule 550-553: File integrity monitoring
- Rule 5715-5716: SSH/sudo anomalies
- Rule 87900+: Custom correlation rules

**Preguntas por nivel:**

**Nivel 1 — Cachorro (100 pts c/u):**
- ¿Cuántas alertas de nivel "High" se generaron el día del ataque en web-srv?
- ¿Qué dirección IP origen generó la mayor cantidad de alertas web?
- ¿Qué regla de Wazuh (rule.id) detectó el primer intento de SQL Injection?

**Nivel 2 — Cazador (200 pts c/u):**
- ¿Qué User-Agent utilizó el atacante durante la fase de reconocimiento?
- ¿Cuál es el nombre del archivo subido como web shell? (incluir extensión)
- ¿Qué comando ejecutó el atacante para verificar sus privilegios después de la escalación?

**Nivel 3 — Alfa (300 pts c/u):**
- ¿Cuál es el MITRE ATT&CK Technique ID asociado a la técnica de persistencia utilizada?
- Escribe una regla de Wazuh (XML) que detecte la cadena de ataque: SQLi → file upload → command execution en menos de 5 minutos. (Flag: hash MD5 de la regla)
- ¿Qué tabla de la base de datos fue exfiltrada? Proporciona el comando exacto usado.

**Nivel 4 — Fenrir (500 pts c/u):**
- El atacante intentó evadir la detección de FIM. ¿Qué técnica usó y en qué archivo de configuración de Wazuh debería monitorearse?
- Construye una timeline completa del incidente con timestamps UTC. (Flag: hash SHA256 del timestamp del primer y último evento)


### 3.2 Escenario 2: "Iron Gate" (Active Directory Compromise)

**Narrativa:** Un ataque de phishing lleva a credential harvesting, movimiento lateral en Active Directory simulado, y despliegue de ransomware.

**Kill Chain:**
1. Spearphishing (log de email simulado)
2. Ejecución de macro maliciosa (Sysmon + Wazuh)
3. Credential dumping (Mimikatz patterns)
4. Kerberoasting / Pass-the-Hash
5. Movimiento lateral (WMI/PSExec)
6. Ransomware deployment (encryption behavior)

**Máquina víctima:** `dc-srv` — Container simulando AD logs + Sysmon + Wazuh Agent

**Preguntas por nivel:**

**Nivel 1 — Cachorro:**
- ¿Qué usuario recibió el email de phishing?
- ¿Cuál es la dirección IP del host que ejecutó el payload inicial?
- ¿Qué regla de Wazuh alertó sobre el proceso sospechoso?

**Nivel 2 — Cazador:**
- ¿Qué herramienta se usó para el credential dumping? (nombre del ejecutable)
- ¿Cuántos hosts fueron contactados durante el movimiento lateral?
- ¿Qué Service Principal Name (SPN) fue objetivo del Kerberoasting?

**Nivel 3 — Alfa:**
- Identifica el Event ID de Windows que correlaciona con la actividad de Pass-the-Hash
- ¿Qué regla de Wazuh con nivel >= 12 se activó durante el despliegue del ransomware?
- Proporciona el hash SHA256 del ejecutable malicioso detectado por Wazuh

**Nivel 4 — Fenrir:**
- El atacante usó una técnica de evasión para bypass AMSI. ¿Qué string fue ofuscado en el PowerShell log?
- Diseña una regla de correlación Wazuh que detecte Kerberoasting (Event ID 4769 con encryption type 0x17 + service account target). Flag: hash de la regla


### 3.3 Escenario 3: "Ghost in the Shell" (Linux Server Compromise + Rootkit)

**Narrativa:** Un servidor Linux expuesto es comprometido via SSH brute force, se instala un rootkit y se establece un canal C2 encubierto.

**Kill Chain:**
1. SSH Brute Force (miles de intentos)
2. Acceso con credenciales válidas
3. Descarga de toolkit malicioso
4. Instalación de rootkit (módulo kernel)
5. Establecimiento de reverse shell / C2
6. Crypto miner deployment
7. Log tampering (intentos de borrar evidencia)

**Máquina víctima:** `lnx-srv` — Container Ubuntu con SSH expuesto + Wazuh Agent + auditd

**Preguntas por nivel:**

**Nivel 1 — Cachorro:**
- ¿Cuántos intentos fallidos de SSH se registraron antes del acceso exitoso?
- ¿Desde qué país se originó el ataque? (GeoIP del Wazuh)
- ¿A qué hora UTC se logró el acceso exitoso?

**Nivel 2 — Cazador:**
- ¿Qué usuario fue comprometido?
- ¿Qué URL se usó para descargar el toolkit malicioso? (completa)
- ¿Qué regla de Wazuh (rule.id y descripción) detectó la modificación de archivos del sistema?

**Nivel 3 — Alfa:**
- ¿Qué módulo del kernel fue cargado como rootkit? (nombre exacto)
- ¿Qué puerto y protocolo usó el canal C2?
- Identifica las reglas de auditd que habrían detectado la carga del módulo kernel

**Nivel 4 — Fenrir:**
- El atacante intentó borrar logs con timestomping. ¿Qué archivo fue modificado y cuál es la discrepancia entre mtime y ctime?
- Reconstruye la cadena completa de IOCs (IPs, hashes, dominios, puertos) del incidente


### 3.4 Escenario 4: "Supply Chain Phantom" (Multi-Vector Advanced)

**Narrativa:** Un ataque supply chain compromete un paquete npm/pip usado internamente, afectando múltiples servidores simultáneamente con un backdoor sofisticado.

**Kill Chain:**
1. Paquete malicioso instalado via dependency confusion
2. Backdoor activado en post-install script
3. Beaconing a C2 vía DNS tunneling
4. Lateral movement entre servidores que comparten el paquete
5. Data staging y exfiltración vía HTTPS
6. Anti-forensics (log rotation manipulation)

**Máquinas víctima:** Todos los containers (ataque multi-host)

**Solo niveles 3-4 (escenario avanzado)**

---

## 4. Datasets y Generación de Logs

### 4.1 Estrategia de Generación

Los datasets son el corazón del BOTS. Se generan ejecutando ataques reales contra las máquinas víctima mientras Wazuh está recolectando.

**Fase 1 — Preparación (Tráfico legítimo de fondo):**
```bash
# Script: generate_baseline.sh
# Genera tráfico normal por 24-48 horas antes del ataque
# - Navegación web legítima (curl/wget aleatorio)
# - SSH logins normales
# - Cron jobs estándar
# - Updates de paquetes
# - Tráfico DNS normal
```

**Fase 2 — Ejecución de Ataques:**
```bash
# Usando Atomic Red Team
# T1190 - Exploit Public-Facing Application
Invoke-AtomicTest T1190

# T1059.001 - PowerShell execution
Invoke-AtomicTest T1059.001

# T1003.001 - LSASS Memory credential dump
Invoke-AtomicTest T1003.001

# Usando CALDERA
# Ejecutar operaciones automatizadas siguiendo adversary profiles
```

**Fase 3 — Export de Datasets:**
```bash
# Exportar índices de Wazuh Indexer
curl -XPOST "https://localhost:9200/wazuh-alerts-*/_search" \
  -H 'Content-Type: application/json' \
  -d '{"query":{"range":{"timestamp":{"gte":"2026-03-01","lte":"2026-03-03"}}}}' \
  --output dataset_scenario1.json

# Snapshot del índice completo
curl -XPUT "https://localhost:9200/_snapshot/wazuhbots_backup" \
  -H 'Content-Type: application/json' \
  -d '{"type":"fs","settings":{"location":"/snapshots/wazuhbots"}}'
```

### 4.2 Estructura de Datasets por Escenario

```
datasets/
├── scenario1_dark_harvest/
│   ├── wazuh-alerts.json          # Alertas de Wazuh
│   ├── wazuh-archives.json        # Logs completos (archives)
│   ├── fim-events.json            # File Integrity Monitoring
│   ├── vulnerability-detector.json # Vulnerabilidades detectadas
│   └── metadata.json              # Timestamps, IPs, flags
├── scenario2_iron_gate/
│   ├── wazuh-alerts.json
│   ├── sysmon-events.json         # Sysmon logs procesados
│   ├── windows-security.json      # Windows Security events
│   └── metadata.json
├── scenario3_ghost_shell/
│   ├── wazuh-alerts.json
│   ├── auditd-events.json         # Linux audit logs
│   ├── osquery-results.json       # OSQuery snapshots
│   └── metadata.json
└── scenario4_supply_chain/
    ├── wazuh-alerts.json
    ├── multi-host-correlation.json
    ├── dns-queries.json
    └── metadata.json
```

---

## 5. Estructura del Proyecto (Repositorio)

```
wazuhbots/
├── docker-compose.yml              # Orquestación principal
├── .env.example                     # Variables de entorno
├── README.md                        # Documentación principal
├── LICENSE                          # MIT License
│
├── docker/                          # Dockerfiles customizados
│   ├── wazuh-manager/
│   │   ├── Dockerfile
│   │   └── config/
│   │       ├── ossec.conf           # Config Wazuh Manager
│   │       ├── local_rules.xml      # Reglas custom para escenarios
│   │       └── decoders/            # Decoders custom
│   ├── wazuh-indexer/
│   │   ├── Dockerfile
│   │   └── config/
│   ├── wazuh-dashboard/
│   │   ├── Dockerfile
│   │   └── config/
│   │       └── saved_objects/       # Dashboards pre-configurados
│   ├── ctfd/
│   │   ├── Dockerfile
│   │   └── config/
│   │       └── ctfd_export.zip      # Challenges pre-cargados
│   ├── nginx/
│   │   ├── Dockerfile
│   │   └── nginx.conf
│   └── victims/
│       ├── web-srv/
│       │   ├── Dockerfile           # Apache + DVWA + Agent
│       │   └── entrypoint.sh
│       ├── dc-srv/
│       │   ├── Dockerfile           # AD simulation + Agent
│       │   └── entrypoint.sh
│       └── lnx-srv/
│           ├── Dockerfile           # Ubuntu + SSH + Agent
│           └── entrypoint.sh
│
├── datasets/                        # Logs pre-generados
│   ├── scenario1_dark_harvest/
│   ├── scenario2_iron_gate/
│   ├── scenario3_ghost_shell/
│   └── scenario4_supply_chain/
│
├── scripts/
│   ├── setup.sh                     # Setup completo automatizado
│   ├── ingest_datasets.py           # Ingestar datasets en Wazuh Indexer
│   ├── generate_attacks.sh          # Ejecutar ataques con Atomic RT
│   ├── generate_flags.py            # Generar flags para CTFd
│   ├── export_datasets.sh           # Exportar snapshots
│   ├── reset_environment.sh         # Reset para nueva competencia
│   └── health_check.sh              # Verificar que todo funciona
│
├── ctfd/
│   ├── challenges/
│   │   ├── scenario1_challenges.json
│   │   ├── scenario2_challenges.json
│   │   ├── scenario3_challenges.json
│   │   └── scenario4_challenges.json
│   ├── hints/
│   │   └── hints_by_level.json
│   └── scoreboard_config.json
│
├── wazuh/
│   ├── rules/
│   │   ├── custom_bots_rules.xml    # Reglas custom para escenarios
│   │   └── correlation_rules.xml
│   ├── decoders/
│   │   └── custom_decoders.xml
│   └── dashboards/
│       ├── bots_overview.ndjson     # Dashboard general BOTS
│       ├── scenario1_dashboard.ndjson
│       ├── scenario2_dashboard.ndjson
│       ├── scenario3_dashboard.ndjson
│       └── investigation_dashboard.ndjson
│
├── caldera/
│   ├── adversary_profiles/
│   │   ├── dark_harvest.yml
│   │   ├── iron_gate.yml
│   │   └── ghost_shell.yml
│   └── abilities/                   # Custom abilities
│
├── docs/
│   ├── DEPLOYMENT.md                # Guía de despliegue
│   ├── FACILITATOR_GUIDE.md         # Guía para organizadores
│   ├── PARTICIPANT_GUIDE.md         # Guía para participantes
│   ├── CREATING_SCENARIOS.md        # Cómo crear nuevos escenarios
│   ├── API_REFERENCE.md             # API para integración
│   └── TROUBLESHOOTING.md
│
└── branding/
    ├── logo/
    ├── banners/
    └── certificates/                # Templates de certificados
```

---

## 6. Docker Compose — Despliegue Completo

```yaml
# docker-compose.yml
version: '3.8'

services:
  # ============================================
  # WAZUH STACK
  # ============================================
  wazuh-manager:
    image: wazuh/wazuh-manager:4.9.0
    container_name: wazuhbots-manager
    hostname: wazuh-manager
    restart: unless-stopped
    ports:
      - "1514:1514"    # Agent communication
      - "1515:1515"    # Agent enrollment
      - "514:514/udp"  # Syslog
      - "55000:55000"  # Wazuh API
    environment:
      INDEXER_URL: https://wazuh-indexer:9200
      INDEXER_USERNAME: admin
      INDEXER_PASSWORD: ${INDEXER_PASSWORD}
      FILEBEAT_SSL_VERIFICATION_MODE: full
      SSL_CERTIFICATE_AUTHORITIES: /etc/ssl/root-ca.pem
      SSL_CERTIFICATE: /etc/ssl/filebeat.pem
      SSL_KEY: /etc/ssl/filebeat-key.pem
    volumes:
      - wazuh_api_configuration:/var/ossec/api/configuration
      - wazuh_etc:/var/ossec/etc
      - wazuh_logs:/var/ossec/logs
      - wazuh_queue:/var/ossec/queue
      - wazuh_var_multigroups:/var/ossec/var/multigroups
      - wazuh_integrations:/var/ossec/integrations
      - wazuh_active_response:/var/ossec/active-response/bin
      - wazuh_agentless:/var/ossec/agentless
      - wazuh_wodles:/var/ossec/wodles
      - filebeat_etc:/etc/filebeat
      - filebeat_var:/var/lib/filebeat
      - ./docker/wazuh-manager/config/local_rules.xml:/var/ossec/etc/rules/local_rules.xml
      - ./docker/wazuh-manager/config/ossec.conf:/wazuh-config-mount/etc/ossec.conf
    networks:
      - wazuhbots-net

  wazuh-indexer:
    image: wazuh/wazuh-indexer:4.9.0
    container_name: wazuhbots-indexer
    hostname: wazuh-indexer
    restart: unless-stopped
    ports:
      - "9200:9200"
    environment:
      OPENSEARCH_JAVA_OPTS: "-Xms${INDEXER_HEAP:-2g} -Xmx${INDEXER_HEAP:-2g}"
    volumes:
      - wazuh_indexer_data:/var/lib/wazuh-indexer
    networks:
      - wazuhbots-net

  wazuh-dashboard:
    image: wazuh/wazuh-dashboard:4.9.0
    container_name: wazuhbots-dashboard
    hostname: wazuh-dashboard
    restart: unless-stopped
    ports:
      - "5601:5601"
    environment:
      INDEXER_USERNAME: admin
      INDEXER_PASSWORD: ${INDEXER_PASSWORD}
      WAZUH_API_URL: https://wazuh-manager
      DASHBOARD_USERNAME: kibanaserver
      DASHBOARD_PASSWORD: ${DASHBOARD_PASSWORD}
    depends_on:
      - wazuh-indexer
      - wazuh-manager
    networks:
      - wazuhbots-net

  # ============================================
  # CTFd PLATFORM
  # ============================================
  ctfd:
    image: ctfd/ctfd:latest
    container_name: wazuhbots-ctfd
    hostname: ctfd
    restart: unless-stopped
    ports:
      - "8000:8000"
    environment:
      UPLOAD_FOLDER: /var/uploads
      DATABASE_URL: mysql+pymysql://ctfd:${CTFD_DB_PASSWORD}@ctfd-db/ctfd
      REDIS_URL: redis://ctfd-redis:6379
      WORKERS: 4
      LOG_FOLDER: /var/log/CTFd
      ACCESS_LOG: "-"
      ERROR_LOG: "-"
      REVERSE_PROXY: "true"
    volumes:
      - ctfd_logs:/var/log/CTFd
      - ctfd_uploads:/var/uploads
    depends_on:
      - ctfd-db
      - ctfd-redis
    networks:
      - wazuhbots-net

  ctfd-db:
    image: mariadb:10.11
    container_name: wazuhbots-ctfd-db
    restart: unless-stopped
    environment:
      MYSQL_ROOT_PASSWORD: ${CTFD_DB_ROOT_PASSWORD}
      MYSQL_USER: ctfd
      MYSQL_PASSWORD: ${CTFD_DB_PASSWORD}
      MYSQL_DATABASE: ctfd
    volumes:
      - ctfd_db_data:/var/lib/mysql
    networks:
      - wazuhbots-net

  ctfd-redis:
    image: redis:7-alpine
    container_name: wazuhbots-ctfd-redis
    restart: unless-stopped
    volumes:
      - ctfd_redis_data:/data
    networks:
      - wazuhbots-net

  # ============================================
  # NGINX REVERSE PROXY
  # ============================================
  nginx:
    image: nginx:alpine
    container_name: wazuhbots-nginx
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./docker/nginx/nginx.conf:/etc/nginx/nginx.conf:ro
      - ./docker/nginx/certs:/etc/nginx/certs:ro
    depends_on:
      - wazuh-dashboard
      - ctfd
    networks:
      - wazuhbots-net

  # ============================================
  # VICTIM MACHINES
  # ============================================
  web-srv:
    build: ./docker/victims/web-srv
    container_name: wazuhbots-web-srv
    hostname: web-srv
    restart: unless-stopped
    environment:
      WAZUH_MANAGER: wazuh-manager
      WAZUH_AGENT_GROUP: victims
    depends_on:
      - wazuh-manager
    networks:
      - wazuhbots-net

  dc-srv:
    build: ./docker/victims/dc-srv
    container_name: wazuhbots-dc-srv
    hostname: dc-srv
    restart: unless-stopped
    environment:
      WAZUH_MANAGER: wazuh-manager
      WAZUH_AGENT_GROUP: victims
    depends_on:
      - wazuh-manager
    networks:
      - wazuhbots-net

  lnx-srv:
    build: ./docker/victims/lnx-srv
    container_name: wazuhbots-lnx-srv
    hostname: lnx-srv
    restart: unless-stopped
    environment:
      WAZUH_MANAGER: wazuh-manager
      WAZUH_AGENT_GROUP: victims
    depends_on:
      - wazuh-manager
    networks:
      - wazuhbots-net

  # ============================================
  # ATTACK SIMULATION
  # ============================================
  caldera:
    image: mitre/caldera:latest
    container_name: wazuhbots-caldera
    hostname: caldera
    restart: unless-stopped
    ports:
      - "8888:8888"
    volumes:
      - ./caldera/adversary_profiles:/usr/src/app/data/adversaries
    networks:
      - wazuhbots-net

# ============================================
# NETWORKS & VOLUMES
# ============================================
networks:
  wazuhbots-net:
    driver: bridge
    ipam:
      config:
        - subnet: 172.25.0.0/24

volumes:
  wazuh_api_configuration:
  wazuh_etc:
  wazuh_logs:
  wazuh_queue:
  wazuh_var_multigroups:
  wazuh_integrations:
  wazuh_active_response:
  wazuh_agentless:
  wazuh_wodles:
  filebeat_etc:
  filebeat_var:
  wazuh_indexer_data:
  ctfd_logs:
  ctfd_uploads:
  ctfd_db_data:
  ctfd_redis_data:
```

---

## 7. Scripts de Automatización

### 7.1 Setup Script Principal

```bash
#!/bin/bash
# scripts/setup.sh — WazuhBOTS Complete Setup
set -euo pipefail

BOLD='\033[1m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
RED='\033[0;31m'
NC='\033[0m'

banner() {
    echo -e "${CYAN}"
    echo "██╗    ██╗ █████╗ ███████╗██╗   ██╗██╗  ██╗██████╗  ██████╗ ████████╗███████╗"
    echo "██║    ██║██╔══██╗╚══███╔╝██║   ██║██║  ██║██╔══██╗██╔═══██╗╚══██╔══╝██╔════╝"
    echo "██║ █╗ ██║███████║  ███╔╝ ██║   ██║███████║██████╔╝██║   ██║   ██║   ███████╗"
    echo "██║███╗██║██╔══██║ ███╔╝  ██║   ██║██╔══██║██╔══██╗██║   ██║   ██║   ╚════██║"
    echo "╚███╔███╔╝██║  ██║███████╗╚██████╔╝██║  ██║██████╔╝╚██████╔╝   ██║   ███████║"
    echo " ╚══╝╚══╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═════╝  ╚═════╝    ╚═╝   ╚══════╝"
    echo -e "${NC}"
    echo -e "${BOLD}Boss of the SOC — Powered by Wazuh | Created by MrHacker${NC}"
    echo ""
}

check_requirements() {
    echo -e "${CYAN}[*] Checking requirements...${NC}"
    
    for cmd in docker docker-compose curl python3; do
        if ! command -v $cmd &> /dev/null; then
            echo -e "${RED}[!] $cmd is required but not installed.${NC}"
            exit 1
        fi
    done
    
    # Check Docker daemon
    if ! docker info &> /dev/null; then
        echo -e "${RED}[!] Docker daemon is not running.${NC}"
        exit 1
    fi
    
    # Check available resources
    TOTAL_MEM=$(free -g | awk '/Mem:/{print $2}')
    if [ "$TOTAL_MEM" -lt 12 ]; then
        echo -e "${RED}[!] WARNING: Less than 12GB RAM available. Recommended: 16GB+${NC}"
        read -p "Continue anyway? (y/N) " -n 1 -r
        echo
        [[ $REPLY =~ ^[Yy]$ ]] || exit 1
    fi
    
    echo -e "${GREEN}[✓] All requirements met.${NC}"
}

generate_env() {
    echo -e "${CYAN}[*] Generating environment file...${NC}"
    
    if [ ! -f .env ]; then
        cp .env.example .env
        # Generate random passwords
        sed -i "s/INDEXER_PASSWORD=.*/INDEXER_PASSWORD=$(openssl rand -base64 24)/" .env
        sed -i "s/DASHBOARD_PASSWORD=.*/DASHBOARD_PASSWORD=$(openssl rand -base64 24)/" .env
        sed -i "s/CTFD_DB_PASSWORD=.*/CTFD_DB_PASSWORD=$(openssl rand -base64 24)/" .env
        sed -i "s/CTFD_DB_ROOT_PASSWORD=.*/CTFD_DB_ROOT_PASSWORD=$(openssl rand -base64 24)/" .env
        echo -e "${GREEN}[✓] Environment file generated with random passwords.${NC}"
    else
        echo -e "${GREEN}[✓] Environment file already exists, skipping.${NC}"
    fi
}

deploy_stack() {
    echo -e "${CYAN}[*] Deploying WazuhBOTS stack...${NC}"
    docker-compose up -d --build
    
    echo -e "${CYAN}[*] Waiting for services to be healthy...${NC}"
    sleep 30
    
    # Health checks
    for service in wazuh-manager wazuh-indexer wazuh-dashboard ctfd; do
        if docker ps --filter "name=wazuhbots-${service}" --filter "status=running" | grep -q "$service"; then
            echo -e "${GREEN}[✓] ${service} is running${NC}"
        else
            echo -e "${RED}[!] ${service} failed to start${NC}"
        fi
    done
}

ingest_datasets() {
    echo -e "${CYAN}[*] Ingesting datasets into Wazuh Indexer...${NC}"
    python3 scripts/ingest_datasets.py --all
    echo -e "${GREEN}[✓] Datasets ingested successfully.${NC}"
}

setup_ctfd() {
    echo -e "${CYAN}[*] Configuring CTFd challenges...${NC}"
    python3 scripts/generate_flags.py
    echo -e "${GREEN}[✓] CTFd challenges loaded.${NC}"
}

main() {
    banner
    check_requirements
    generate_env
    deploy_stack
    ingest_datasets
    setup_ctfd
    
    echo ""
    echo -e "${GREEN}${BOLD}═══════════════════════════════════════════════${NC}"
    echo -e "${GREEN}${BOLD}  WazuhBOTS deployed successfully!${NC}"
    echo -e "${GREEN}${BOLD}═══════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  Wazuh Dashboard:  ${CYAN}https://localhost:5601${NC}"
    echo -e "  CTFd Platform:    ${CYAN}http://localhost:8000${NC}"
    echo -e "  Wazuh API:        ${CYAN}https://localhost:55000${NC}"
    echo -e "  CALDERA:          ${CYAN}http://localhost:8888${NC}"
    echo ""
    echo -e "  ${BOLD}Credentials in .env file${NC}"
    echo ""
}

main "$@"
```

### 7.2 Script de Ingestión de Datasets

```python
#!/usr/bin/env python3
"""
scripts/ingest_datasets.py — Ingest pre-generated datasets into Wazuh Indexer
"""

import json
import os
import sys
import argparse
import requests
from datetime import datetime
from pathlib import Path

requests.packages.urllib3.disable_warnings()

INDEXER_URL = os.getenv("INDEXER_URL", "https://localhost:9200")
INDEXER_USER = os.getenv("INDEXER_USERNAME", "admin")
INDEXER_PASS = os.getenv("INDEXER_PASSWORD", "admin")
DATASETS_DIR = Path(__file__).parent.parent / "datasets"
BULK_SIZE = 500  # Documents per bulk request


def create_index(index_name):
    """Create index with Wazuh-compatible mappings."""
    mappings = {
        "settings": {
            "number_of_shards": 1,
            "number_of_replicas": 0
        }
    }
    resp = requests.put(
        f"{INDEXER_URL}/{index_name}",
        json=mappings,
        auth=(INDEXER_USER, INDEXER_PASS),
        verify=False
    )
    if resp.status_code in (200, 400):  # 400 = already exists
        print(f"  [+] Index {index_name} ready")
    else:
        print(f"  [!] Error creating {index_name}: {resp.text}")


def bulk_ingest(index_name, documents):
    """Bulk ingest documents into OpenSearch."""
    bulk_body = ""
    for doc in documents:
        action = json.dumps({"index": {"_index": index_name}})
        bulk_body += f"{action}\n{json.dumps(doc)}\n"

    resp = requests.post(
        f"{INDEXER_URL}/_bulk",
        data=bulk_body,
        headers={"Content-Type": "application/x-ndjson"},
        auth=(INDEXER_USER, INDEXER_PASS),
        verify=False
    )
    
    if resp.status_code == 200:
        result = resp.json()
        errors = sum(1 for item in result["items"] if item["index"].get("error"))
        return len(result["items"]) - errors
    return 0


def ingest_scenario(scenario_dir):
    """Ingest all JSON files from a scenario directory."""
    scenario_name = scenario_dir.name
    print(f"\n[*] Ingesting scenario: {scenario_name}")
    
    total_docs = 0
    for json_file in scenario_dir.glob("*.json"):
        if json_file.name == "metadata.json":
            continue
        
        index_name = f"wazuhbots-{scenario_name}-{json_file.stem}"
        create_index(index_name)
        
        with open(json_file, "r") as f:
            documents = json.load(f)
        
        if not isinstance(documents, list):
            documents = [documents]
        
        # Bulk ingest in batches
        ingested = 0
        for i in range(0, len(documents), BULK_SIZE):
            batch = documents[i:i + BULK_SIZE]
            ingested += bulk_ingest(index_name, batch)
        
        total_docs += ingested
        print(f"  [+] {json_file.name}: {ingested}/{len(documents)} documents ingested")
    
    return total_docs


def main():
    parser = argparse.ArgumentParser(description="WazuhBOTS Dataset Ingestion")
    parser.add_argument("--all", action="store_true", help="Ingest all scenarios")
    parser.add_argument("--scenario", type=str, help="Specific scenario to ingest")
    args = parser.parse_args()

    print("=" * 60)
    print("  WazuhBOTS — Dataset Ingestion Tool")
    print("=" * 60)

    if args.all:
        scenarios = sorted(DATASETS_DIR.iterdir())
    elif args.scenario:
        scenarios = [DATASETS_DIR / args.scenario]
    else:
        parser.print_help()
        sys.exit(1)

    grand_total = 0
    for scenario_dir in scenarios:
        if scenario_dir.is_dir():
            grand_total += ingest_scenario(scenario_dir)

    print(f"\n{'=' * 60}")
    print(f"  Total documents ingested: {grand_total}")
    print(f"{'=' * 60}")


if __name__ == "__main__":
    main()
```

---

## 8. Configuración de CTFd

### 8.1 Estructura de Challenges

```json
{
  "challenges": [
    {
      "category": "Scenario 1: Dark Harvest",
      "name": "[Pup] Alert Count on Attack Day",
      "description": "¿Cuántas alertas de nivel 'High' se generaron el día del ataque en web-srv?\n\nHint: Filtra por agent.name y rule.level en el Wazuh Dashboard.",
      "value": 100,
      "type": "standard",
      "state": "visible",
      "flags": ["247"],
      "tags": ["level1", "scenario1", "dashboard"],
      "hints": [
        {"content": "Usa el filtro: agent.name: web-srv AND rule.level >= 10", "cost": 25},
        {"content": "El rango de tiempo es 2026-03-01 00:00 a 2026-03-01 23:59 UTC", "cost": 50}
      ]
    },
    {
      "category": "Scenario 1: Dark Harvest",
      "name": "[Hunter] Attacker User-Agent",
      "description": "¿Qué User-Agent utilizó el atacante durante la fase de reconocimiento en web-srv?",
      "value": 200,
      "type": "standard",
      "state": "visible",
      "flags": ["Nikto/2.1.6"],
      "tags": ["level2", "scenario1", "log-analysis"],
      "hints": [
        {"content": "Busca en data.http.user_agent o data.srcip correlacionado con alerts web", "cost": 50}
      ]
    },
    {
      "category": "Scenario 1: Dark Harvest",
      "name": "[Alpha] MITRE Persistence Technique",
      "description": "¿Cuál es el MITRE ATT&CK Technique ID de la técnica de persistencia usada por el atacante?",
      "value": 300,
      "type": "standard",
      "state": "visible",
      "flags": ["T1053.003"],
      "tags": ["level3", "scenario1", "mitre"],
      "hints": [
        {"content": "El atacante creó una tarea programada. Revisa las reglas con rule.mitre.id", "cost": 75}
      ]
    }
  ]
}
```

### 8.2 Sistema de Puntuación

| Elemento | Configuración |
|----------|--------------|
| Scoring | Dinámico (decrece con más solves) |
| Decay | Mínimo 50% del valor original |
| Hints | Cuestan 25-50% del valor de la pregunta |
| First Blood | Bonus de 20% por primer solve |
| Time Bonus | 10% bonus en la primera hora |

---

## 9. Guía de Despliegue Rápido

### Paso 1: Clonar repositorio
```bash
git clone https://github.com/MrHacker-X/wazuhbots.git
cd wazuhbots
```

### Paso 2: Ejecutar setup
```bash
chmod +x scripts/setup.sh
./scripts/setup.sh
```

### Paso 3: Verificar servicios
```bash
./scripts/health_check.sh
```

### Paso 4: Acceder
- **Participantes:** `http://tu-servidor/ctf` → CTFd (registro + challenges)
- **Investigación:** `https://tu-servidor/dashboard` → Wazuh Dashboard (credenciales de solo lectura)
- **Admin:** `https://tu-servidor:55000` → Wazuh API

### Paso 5: Para nueva competencia
```bash
./scripts/reset_environment.sh  # Reset flags, scores, mantiene datasets
```

---

## 10. Dashboards Pre-configurados de Wazuh

### 10.1 Dashboard: BOTS Overview
- Panel de conteo total de alertas por escenario
- Timeline de eventos por hora
- Top 10 reglas activadas
- Mapa de MITRE ATT&CK con técnicas detectadas
- Agentes activos y su estado

### 10.2 Dashboard: Investigation Workspace
- Búsqueda libre con filtros rápidos
- Correlación temporal (timeline visual)
- Detalles de alerta expandibles
- Tabla de eventos raw con campos seleccionables
- Panel de File Integrity Monitoring

### 10.3 Dashboards por Escenario
Cada escenario tiene un dashboard dedicado con:
- Filtros pre-aplicados para el rango temporal del escenario
- Visualizaciones específicas del tipo de ataque
- Saved searches relevantes

---

## 11. Modos de Operación

### 11.1 Modo Entrenamiento (SOC Interno)
- Sin límite de tiempo
- Hints gratuitos
- Acceso a documentation
- Sesiones guiadas por facilitador

### 11.2 Modo Competencia (CTF/Meetup)
- Tiempo limitado (2-4 horas)
- Hints con costo de puntos
- Scoreboard en vivo
- Equipos de 2-4 personas

### 11.3 Modo Autoguiado (Educativo)
- Sin scoreboard competitivo
- Walkthroughs disponibles tras X intentos
- Progresión desbloqueada (nivel N+1 requiere completar N)

### 11.4 Modo Público (CTF Abierto)
- Registro abierto
- Verificación anti-cheating
- Duración de días/semanas
- Rankings globales

---

## 12. Extensibilidad — Creando Nuevos Escenarios

### Template para nuevo escenario:

```yaml
# scenarios/template.yml
scenario:
  name: "Nombre del Escenario"
  codename: "operation_name"
  difficulty: "mixed"  # easy, medium, hard, mixed
  narrative: |
    Descripción narrativa del escenario...
  
  kill_chain:
    - step: 1
      phase: "Initial Access"
      mitre_id: "T1190"
      description: "..."
      wazuh_rules: [31101, 31102]
    - step: 2
      phase: "Execution"
      mitre_id: "T1059"
      description: "..."
      wazuh_rules: [5715]
  
  victims:
    - hostname: "target-srv"
      os: "ubuntu:22.04"
      services: ["apache2", "mysql"]
      wazuh_agent: true
      agent_group: "victims"
  
  questions:
    level1:
      - text: "¿Pregunta nivel 1?"
        flag: "respuesta"
        points: 100
        hints:
          - text: "Pista 1"
            cost: 25
    level2:
      - text: "¿Pregunta nivel 2?"
        flag: "respuesta"
        points: 200
```

---

## 13. Roadmap del Proyecto

### Fase 1 — MVP (Mes 1-2)
- Stack Docker Compose funcional
- Escenarios 1 y 3 (Web + Linux)
- CTFd con challenges básicos
- Dashboards de investigación
- Documentación de despliegue

### Fase 2 — Expansión (Mes 3-4)
- Escenarios 2 y 4 (AD + Supply Chain)
- Generación automatizada de datasets
- Dashboards avanzados por escenario
- Branding y certificados
- API para integración externa

### Fase 3 — Comunidad (Mes 5-6)
- Template system para nuevos escenarios
- Contribuciones de la comunidad
- Plugin CTFd personalizado para Wazuh
- Modo autoguiado con walkthroughs
- Integración con CALDERA automatizada

### Fase 4 — Enterprise (Mes 7+)
- Multi-tenant support
- Reporting automatizado por participante
- Integración con plataformas de training (LMS)
- Escenarios cloud (AWS/Azure/GCP logs)
- Certificaciones y badges

---

## 14. Licencia y Créditos

**WazuhBOTS** es un proyecto open source bajo licencia MIT.

- **Creador:** MrHacker (Kevin Muñoz)
- **Rol:** Wazuh Technology Ambassador
- **Organización:** Condor Business Solutions
- **Powered by:** Wazuh, CTFd, MITRE CALDERA, Atomic Red Team

---

*"En el SOC, no sobrevive el que más herramientas tiene, sino el que mejor investiga."*
— ReconWolf 🐺
