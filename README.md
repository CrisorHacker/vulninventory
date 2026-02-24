<p align="center">
  <h1 align="center">🛡️ VulnInventory</h1>
</p>

<p align="center">
  <strong>Plataforma open source de gestión de vulnerabilidades</strong><br>
  Hecha para equipos de pentesting y consultores de ciberseguridad
</p>

<p align="center">
  <a href="#-inicio-rapido">Inicio rápido</a> •
  <a href="#-caracteristicas">Características</a> •
  <a href="#-capturas">Capturas</a> •
  <a href="#-documentacion">Documentación</a> •
  <a href="#-contribuir">Contribuir</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/license-MIT-blue.svg" />
  <img src="https://img.shields.io/badge/python-3.11+-blue.svg" />
  <img src="https://img.shields.io/badge/react-18+-61dafb.svg" />
  <img src="https://img.shields.io/badge/fastapi-0.100+-009688.svg" />
  <img src="https://img.shields.io/badge/docker-ready-2496ED.svg" />
</p>

---

## 🔍 ¿Qué es VulnInventory?

VulnInventory es una plataforma de gestión de vulnerabilidades diseñada para consultores de ciberseguridad y equipos de pentesting. Centraliza hallazgos, activos y escaneos entre múltiples clientes y proyectos.

- **Gratis y open source** — Sin licencias ni lock‑in
- **Multi‑tenant** — Gestión segura de múltiples organizaciones
- **Importación fácil** — Nessus, Qualys, Burp, SARIF, CSV, JSON
- **CVE‑aware** — Catálogo de vulnerabilidades con integración NVD
- **Enfocado en consultores** — Hecho por pentesters, para pentesters

## ✨ Características

| Categoría | Detalles |
|----------|---------|
| **Hallazgos** | Ciclo de vida completo, CVSS, CWE/OWASP, comentarios, asignaciones |
| **Activos** | Tracking por proyecto, tags de ambiente/criticidad, asociaciones |
| **Escaneos** | Cola con Wapiti, Nuclei, OSV Scanner, VulnAPI |
| **Import/Export** | CSV, JSON, Nessus XML, Burp XML, SARIF |
| **VulnDB** | Diccionario CVE, auto‑completar, templates propios |
| **Multi‑Tenant** | Organizaciones, proyectos, roles (Admin/Analista/Viewer) |
| **Seguridad** | Cookies httpOnly, CSRF, API keys, rate limiting |
| **Auditoría** | Trazabilidad de acciones de usuarios |

## 🧰 Stack

FastAPI · React · PostgreSQL · Redis · Docker

## 📸 Capturas

> Capturas próximamente. Incluiremos dashboard, hallazgos y asistente de importación.

## 🚀 Inicio rápido

### Requisitos
- [Docker](https://docs.docker.com/get-docker/) y [Docker Compose](https://docs.docker.com/compose/install/)

### 1. Clonar

```bash
git clone https://github.com/CrisorHacker/vulninventory.git
cd vulninventory
```

### 2. Configurar

```bash
cp .env.example .env
# REQUERIDO: Cambiar JWT_SECRET por una cadena aleatoria (min 32 chars)
# Generar una: python -c "import secrets; print(secrets.token_urlsafe(48))"
```

### 3. Iniciar

```bash
docker compose up -d
```

### 4. Abrir

Ir a [http://localhost:5173](http://localhost:5173), registrar un usuario y comenzar.

**Puertos por defecto (Docker Compose):**
- UI: `http://localhost:5173`
- API: `http://localhost:8001`

## 📚 Catálogo de vulnerabilidades (opcional)

VulnInventory **no incluye un catálogo precargado**. Cada equipo carga su propio VulnDB desde una fuente externa.
El endpoint de importación espera **JSONL** (un JSON por línea).

### Importar JSONL o CSV

**Ejemplo mínimo (sin datos sensibles):**

- `docs/examples/vulndb_sample.jsonl`
- `docs/examples/vulndb_sample.csv`

**Script de importación (acepta JSONL o CSV):**

```bash
API_BASE_URL=http://localhost:8001 \
API_KEY=TU_API_KEY \
./scripts/import_vulndb.sh docs/examples/vulndb_sample.jsonl
```

CSV:
```bash
API_BASE_URL=http://localhost:8001 \
API_KEY=TU_API_KEY \
./scripts/import_vulndb.sh docs/examples/vulndb_sample.csv
```

**Vía UI:** Hallazgos → 📚 Catálogo → Importar JSONL → Upload file

### Formato JSONL esperado (un JSON por línea)

```json
{"short_id":"CVE-2024-1234","name":"Example RCE","base_score":9.8,"details":"Remote code execution in example library.","recommendations":"Actualizar a la version 1.2.3","ext_references":["https://example.com/advisory"],"cpe":""}
```

Documentación completa: `docs/vulndb-import.md`.

## 🛠️ Desarrollo

```bash
# Backend
cd api && python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
# Levantar DB y Redis: docker compose -f docker-compose.dev.yml up -d
uvicorn app.main:app --reload --port 8000

# Frontend (terminal separado)
cd ui && npm install && npm run dev

# Worker (terminal separado)
cd worker && python worker.py
```

## 📖 Documentación

- [Arquitectura](docs/architecture.md)
- [API Reference](docs/api-reference.md)
- [Deployment](docs/deployment.md)
- [Development](docs/development.md)

## 🤝 Contribuir

¡Contribuciones bienvenidas! Ver [CONTRIBUTING.md](CONTRIBUTING.md).

**Ayuda necesaria:**
- [ ] i18n (UI en inglés)
- [ ] Generación de reportes PDF
- [ ] Adaptadores de escaneo adicionales (Nmap, OpenVAS, Trivy)
- [ ] Cobertura de tests
- [ ] UI responsive/mobile

## 📋 Roadmap

- [x] Organizaciones multi‑tenant
- [x] Ciclo de vida de hallazgos
- [x] Cola de escaneos con worker
- [x] Import/Export (CSV, JSON, Nessus, Burp, SARIF)
- [x] VulnDB catalog
- [x] Audit logging
- [x] Auth con cookies httpOnly + CSRF
- [ ] Generación de reportes PDF
- [ ] Notificaciones Slack/Teams
- [ ] API GraphQL
- [ ] Sistema de plugins para herramientas de escaneo

## 🔒 Seguridad

Reporta vulnerabilidades de forma responsable. Ver [SECURITY.md](SECURITY.md).

**No abras issues públicas para vulnerabilidades de seguridad.**

## 📄 Licencia

MIT — ver [LICENSE](LICENSE).

---

<p align="center">
  Hecho con ❤️ para la comunidad de ciberseguridad
</p>
