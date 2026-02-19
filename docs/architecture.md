# Architecture

## Overview

VulnInventory uses a microservices architecture:

```
┌──────────┐     ┌──────────┐     ┌──────────┐
│    UI    │────▶│   API    │────▶│ Postgres │
│ (React)  │     │(FastAPI) │     │          │
└──────────┘     └────┬─────┘     └──────────┘
                      │
                      ▼
                ┌──────────┐     ┌──────────┐
                │  Redis   │◀───▶│  Worker  │
                │ (Queue)  │     │ (Python) │
                └──────────┘     └──────────┘
```

## Components

- **API (FastAPI):** REST API, auth, multi-tenant, CRUD
- **UI (React/Vite):** SPA frontend
- **Worker (Python):** Scan execution, report parsing
- **PostgreSQL:** Primary data store
- **Redis:** Scan queue, rate limiting

## Data Model

- Organizations → Projects → Assets → Findings
- Users → Memberships (per organization, with roles)
- Scans → Findings (via worker ingestion)
- VulnCatalog (standalone CVE dictionary)
