<p align="center">
  <h1 align="center">🛡️ VulnInventory</h1>
</p>

<p align="center">
  <strong>Open Source Vulnerability Management Platform</strong><br>
  Built for penetration testing teams and cybersecurity consultants
</p>

<p align="center">
  <a href="#-quick-start">Quick Start</a> •
  <a href="#-features">Features</a> •
  <a href="#-screenshots">Screenshots</a> •
  <a href="#-documentation">Docs</a> •
  <a href="#-contributing">Contributing</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/license-MIT-blue.svg" />
  <img src="https://img.shields.io/badge/python-3.11+-blue.svg" />
  <img src="https://img.shields.io/badge/react-18+-61dafb.svg" />
  <img src="https://img.shields.io/badge/fastapi-0.100+-009688.svg" />
  <img src="https://img.shields.io/badge/docker-ready-2496ED.svg" />
</p>

---

## 🔍 What is VulnInventory?

VulnInventory is a vulnerability management platform designed for cybersecurity consultants and pentesting teams. It centralizes findings, assets, and scans across multiple clients and projects.

- **Free and open source** — No licensing fees, no vendor lock-in
- **Multi-tenant** — Manage multiple clients/organizations securely
- **Import-friendly** — Nessus, Qualys, Burp, SARIF, CSV, JSON, Excel
- **CVE-aware** — Built-in vulnerability catalog with NVD integration
- **Consultant-focused** — Built by pentesters, for pentesters

## ✨ Features

| Category | Details |
|----------|---------|
| **Findings** | Full lifecycle management, CVSS scoring, CWE/OWASP, comments, assignments |
| **Assets** | Per-project tracking, environment/criticality tagging, associations |
| **Scans** | Queue-based with Wapiti, Nuclei, OSV Scanner, VulnAPI |
| **Import/Export** | CSV, JSON, Excel, Nessus XML, Burp XML, SARIF |
| **VulnDB Catalog** | CVE dictionary, auto-fill forms, custom templates |
| **Multi-Tenant** | Organizations, projects, roles (Admin/Analyst/Viewer) |
| **Security** | httpOnly cookies, CSRF protection, scoped API keys, rate limiting |
| **Audit** | Full trail of all user actions |

## 📸 Screenshots

> Add screenshots to `docs/screenshots/` and reference them here.
> Recommended: dashboard, findings, assets, import wizard, vulndb, scans.

## 🚀 Quick Start

### Prerequisites
- [Docker](https://docs.docker.com/get-docker/) and [Docker Compose](https://docs.docker.com/compose/install/)

### 1. Clone

```bash
git clone https://github.com/CrisorHacker/vulninventory.git
cd vulninventory
```

### 2. Configure

```bash
cp .env.example .env
# REQUIRED: Change JWT_SECRET to a random string (min 32 chars)
# Generate one: python -c "import secrets; print(secrets.token_urlsafe(48))"
```

### 3. Start

```bash
docker compose up -d
```

### 4. Open

Go to [http://localhost:5173](http://localhost:5173), register an account, and start working.

## 📚 Vulnerability Catalog (Optional)

VulnInventory includes a built-in vulnerability catalog (VulnDB) that auto-fills forms when creating findings. Populate it with any CVE feed in JSONL format.

### Generate from NVD (free)

```bash
# Install dependency
pip install requests

# Download last 30 days of CVEs:
python scripts/nvd_to_jsonl.py --download --recent --output cves_recent.jsonl

# Download full year (recommended: get a free API key at https://nvd.nist.gov/developers/request-an-api-key):
python scripts/nvd_to_jsonl.py --download --year 2025 --api-key YOUR_KEY --output cves_2025.jsonl

# Convert a local NVD JSON file:
python scripts/nvd_to_jsonl.py --input nvd_feed.json --output cves.jsonl
```

### Import into VulnInventory

**Via UI:** Hallazgos → 📚 Catálogo → Importar JSONL → Upload file

**Via API:**
```bash
curl -X POST http://localhost:8000/vulndb/import \
  -b "access_token=YOUR_COOKIE" \
  -F "file=@cves_2025.jsonl"
```

### Expected JSONL format (one JSON per line)

```json
{"name":"CVE-2025-XXXXX","short_id":"CVE-2025-XXXXX","base_score":7.5,"cvssv3":"CVSS:3.1/AV:N/AC:L/...","cwe_id":89,"cwe_name":"CWE-89","details":{"default":"Description..."},"recommendations":{"default":""},"ext_references":{"default":"- [url](url)"},"exploit":false,"published_date":"2025-01-15T00:00:00Z"}
```

Compatible sources: [NVD](https://nvd.nist.gov/), [OSV.dev](https://osv.dev/), [CVE.org](https://www.cve.org/) — use the included converter script.

## 🛠️ Development

```bash
# Backend
cd api && python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
# Start DB and Redis: docker compose -f docker-compose.dev.yml up -d
uvicorn app.main:app --reload --port 8000

# Frontend (separate terminal)
cd ui && npm install && npm run dev

# Worker (separate terminal)
cd worker && python worker.py
```

## 📖 Documentation

- [Architecture](docs/architecture.md)
- [API Reference](docs/api-reference.md)
- [Deployment](docs/deployment.md)
- [Development](docs/development.md)

## 🤝 Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md).

**Help needed:**
- [ ] i18n (English UI)
- [ ] PDF report generation
- [ ] Additional scan adapters (Nmap, OpenVAS, Trivy)
- [ ] Test coverage
- [ ] React Router + component modularization

## 📋 Roadmap

- [x] Multi-tenant organizations
- [x] Finding lifecycle management
- [x] Scan queue with worker
- [x] Import/Export (CSV, JSON, Excel, Nessus, Burp, SARIF)
- [x] VulnDB catalog
- [x] Audit logging
- [x] httpOnly cookie auth + CSRF
- [ ] PDF report generation
- [ ] Slack/Teams notifications
- [ ] GraphQL API
- [ ] Plugin system for scan tools

## 🔒 Security

Report vulnerabilities responsibly. See [SECURITY.md](SECURITY.md).

**Do NOT open public issues for security vulnerabilities.**

## 📄 License

MIT — see [LICENSE](LICENSE).

---

<p align="center">
  Made with ❤️ for the cybersecurity community
</p>
