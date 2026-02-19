# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)

## [1.0.0] - 2026-02-XX

### Added
- Multi-tenant organizations with projects
- Finding management (create, track, assign, comment)
- Asset management with environment/criticality tagging
- Scan queue with worker (Wapiti, Nuclei, OSV Scanner, VulnAPI)
- Import wizard: CSV, JSON, Nessus XML, Burp XML, SARIF
- Export: CSV, JSON
- Vulnerability catalog (VulnDB) with JSONL import + manual templates
- Role-based team management with invitations
- Audit trail
- Dashboard with severity breakdown
- httpOnly cookie auth + CSRF protection
- Scoped API keys
- Redis rate limiting
- SSRF/Path hardening on scan targets
- NVD-to-JSONL converter script
