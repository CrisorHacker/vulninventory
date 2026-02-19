# Development Guide

## Prerequisites
- Python 3.11+
- Node.js 20+
- PostgreSQL 16+
- Redis 7+

## Setup

```bash
# Start DB + Redis
docker compose -f docker-compose.dev.yml up -d

# Backend
cd api
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000

# Frontend
cd ui
npm install
npm run dev

# Worker
cd worker
python worker.py
```

## Testing

```bash
cd api
pytest
pytest --cov=app
```

## Linting

```bash
# Backend
pip install ruff black
ruff check api/
black api/

# Frontend
cd ui && npm run lint
```
