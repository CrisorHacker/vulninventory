# API Reference

Base URL: `http://localhost:8000`

## Authentication
All endpoints require authentication via httpOnly cookie (browser) or API key (header `X-API-Key`).

## Endpoints

See the interactive Swagger docs at: `http://localhost:8000/docs`

### Auth
- `POST /auth/register` — Register new user + organization
- `POST /auth/login` — Login (sets httpOnly cookie)
- `POST /auth/logout` — Logout (clears cookie)
- `GET /auth/me` — Get current user
- `POST /auth/forgot-password` — Request password reset
- `POST /auth/reset-password` — Reset password with token

### Findings
- `GET /findings?project_id=X` — List findings
- `POST /findings/manual` — Create finding manually
- `PATCH /findings/{id}` — Update finding
- `DELETE /findings/{id}` — Delete finding

### Assets
- `GET /assets?project_id=X` — List assets
- `POST /assets` — Create asset
- `PATCH /assets/{id}` — Update asset
- `DELETE /assets/{id}` — Delete asset

### Scans
- `POST /scans/run` — Queue a scan
- `GET /scans?project_id=X` — List scans

### VulnDB
- `GET /vulndb/search?q=...` — Search catalog
- `POST /vulndb` — Create manual template
- `POST /vulndb/import` — Import JSONL file

### Import/Export
- `POST /import/bulk` — Bulk import findings + assets
- `GET /findings/export?project_id=X&format=csv` — Export findings
