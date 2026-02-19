from __future__ import annotations

from datetime import datetime, timedelta
from typing import Iterable

from . import crud, models
from .auth import hash_password
from .db import SessionLocal


def _get_or_create_user(db, email: str, password: str) -> models.User:
    user = crud.get_user_by_email(db, email)
    if user:
        return user
    return crud.create_user(db, email, hash_password(password))


def _get_or_create_org(db, name: str) -> models.Organization:
    org = db.query(models.Organization).filter(models.Organization.name == name).first()
    if org:
        return org
    return crud.create_organization(db, name)


def _get_or_create_project(db, org_id: int, name: str) -> models.Project:
    project = (
        db.query(models.Project)
        .filter(models.Project.organization_id == org_id, models.Project.name == name)
        .first()
    )
    if project:
        return project
    return crud.create_project(db, org_id, name)


def _get_or_create_asset(
    db,
    *,
    project_id: int,
    name: str,
    uri: str,
    asset_type: str,
    owner_email: str,
    environment: str,
    criticality: str,
    tags: list[str],
) -> models.Asset:
    asset = (
        db.query(models.Asset)
        .filter(models.Asset.project_id == project_id, models.Asset.uri == uri)
        .first()
    )
    if asset:
        return asset
    return crud.create_asset(
        db,
        project_id=project_id,
        name=name,
        uri=uri,
        asset_type=asset_type,
        owner_email=owner_email,
        environment=environment,
        criticality=criticality,
        tags=tags,
    )


def _create_scan(
    db,
    *,
    project_id: int,
    tool: str,
    status: str,
    started_at: datetime,
    finished_at: datetime | None,
    metadata: dict,
) -> models.Scan:
    scan = models.Scan(
        tool=tool,
        status=status,
        started_at=started_at,
        finished_at=finished_at,
        scan_metadata=metadata,
        project_id=project_id,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


def _create_scan_logs(db, scan_id: int, lines: Iterable[str]) -> None:
    for line in lines:
        db.add(models.ScanLog(scan_id=scan_id, message=line))
    db.commit()


def _create_audit_logs(db, user_id: int | None, ip: str = "127.0.0.1") -> None:
    now = datetime.utcnow()
    samples = [
        ("POST", "/auth/login", 200, now - timedelta(minutes=35)),
        ("GET", "/orgs", 200, now - timedelta(minutes=34)),
        ("POST", "/orgs/1/projects", 200, now - timedelta(minutes=33)),
        ("POST", "/assets", 200, now - timedelta(minutes=31)),
        ("POST", "/scans/run", 200, now - timedelta(minutes=30)),
        ("GET", "/findings", 200, now - timedelta(minutes=28)),
        ("GET", "/findings/export", 200, now - timedelta(minutes=26)),
        ("GET", "/audit-logs", 200, now - timedelta(minutes=25)),
        ("POST", "/scans/run", 429, now - timedelta(minutes=20)),
        ("PATCH", "/findings/12", 200, now - timedelta(minutes=18)),
        ("GET", "/health", 200, now - timedelta(minutes=15)),
        ("GET", "/scans/7/logs", 200, now - timedelta(minutes=10)),
    ]
    for method, path, status_code, created_at in samples:
        db.add(
            models.AuditLog(
                user_id=user_id,
                method=method,
                path=path,
                status_code=status_code,
                ip=ip,
                created_at=created_at,
            )
        )
    db.commit()


def _make_finding(
    *,
    tool: str,
    rule_id: str,
    title: str,
    severity: str,
    asset: models.Asset,
    status: str = "open",
    description: str = "",
    cwe: str = "",
    owasp: str = "",
    cvss_score: float | None = None,
) -> dict:
    return {
        "source": {"tool": tool, "tool_version": "demo", "rule_id": rule_id},
        "scan": {"scan_type": "web", "status": "succeeded"},
        "asset": {
            "type": asset.type,
            "name": asset.name,
            "uri": asset.uri,
            "project_id": asset.project_id,
        },
        "finding": {
            "type": "vuln",
            "title": title,
            "description": description,
            "severity": severity,
            "status": status,
            "cwe": cwe,
            "owasp": owasp,
            "cvss": {"score": cvss_score or 0.0, "vector": ""},
        },
        "evidence": {"request": "", "response": "", "metadata": {}},
        "timestamps": {"detected_at": datetime.utcnow().isoformat() + "Z"},
    }


def seed_demo() -> None:
    with SessionLocal() as db:
        user = _get_or_create_user(db, "demo@example.com", "DemoSegura123")
        org = _get_or_create_org(db, "SeguridadWeb Demo")
        membership = (
            db.query(models.Membership)
            .filter(models.Membership.user_id == user.id, models.Membership.organization_id == org.id)
            .first()
        )
        if not membership:
            crud.create_membership(db, user.id, org.id, role="owner")

        project = _get_or_create_project(db, org.id, "Inventario Demo")

        asset_web = _get_or_create_asset(
            db,
            project_id=project.id,
            name="Portal Publico",
            uri="http://host.docker.internal:2324",
            asset_type="web_app",
            owner_email="webmaster@demo.local",
            environment="prod",
            criticality="alta",
            tags=["publico", "marketing"],
        )
        asset_api = _get_or_create_asset(
            db,
            project_id=project.id,
            name="API Clientes",
            uri="http://host.docker.internal:5454",
            asset_type="api",
            owner_email="backend@demo.local",
            environment="stage",
            criticality="media",
            tags=["clientes", "rest"],
        )
        asset_repo = _get_or_create_asset(
            db,
            project_id=project.id,
            name="Repositorio Billing",
            uri="repos://git.local/billing",
            asset_type="repo",
            owner_email="devops@demo.local",
            environment="dev",
            criticality="baja",
            tags=["python", "billing"],
        )

        now = datetime.utcnow()
        scan_web = _create_scan(
            db,
            project_id=project.id,
            tool="wapiti",
            status="finished",
            started_at=now - timedelta(minutes=42),
            finished_at=now - timedelta(minutes=38),
            metadata={"target_url": asset_web.uri, "report_path": "/tmp/report.json", "project_id": project.id},
        )
        scan_api = _create_scan(
            db,
            project_id=project.id,
            tool="vulnapi",
            status="failed",
            started_at=now - timedelta(minutes=35),
            finished_at=now - timedelta(minutes=34),
            metadata={"target_url": asset_api.uri, "report_path": "/tmp/report.json", "project_id": project.id},
        )
        scan_repo = _create_scan(
            db,
            project_id=project.id,
            tool="osv",
            status="finished",
            started_at=now - timedelta(minutes=30),
            finished_at=now - timedelta(minutes=28),
            metadata={"target_path": "/src/billing", "report_path": "/tmp/osv.json", "project_id": project.id},
        )
        scan_nuclei = _create_scan(
            db,
            project_id=project.id,
            tool="nuclei",
            status="running",
            started_at=now - timedelta(minutes=8),
            finished_at=None,
            metadata={"target_url": asset_web.uri, "report_path": "/tmp/nuclei.json", "project_id": project.id},
        )

        _create_scan_logs(
            db,
            scan_web.id,
            [
                "Wapiti 3.2.3 iniciado",
                "Analizando rutas principales",
                "Reporte generado en /tmp/report.json",
            ],
        )
        _create_scan_logs(
            db,
            scan_api.id,
            ["VulnAPI inició", "error: No se pudo cargar el OpenAPI"],
        )

        findings = [
            _make_finding(
                tool="wapiti",
                rule_id="xss",
                title="XSS reflejado en /search",
                severity="high",
                asset=asset_web,
                cwe="CWE-79",
                owasp="A03:2021",
                description="Parámetro q refleja HTML sin sanitización.",
                cvss_score=7.1,
            ),
            _make_finding(
                tool="wapiti",
                rule_id="sql_injection",
                title="SQLi en /products",
                severity="critical",
                asset=asset_web,
                cwe="CWE-89",
                owasp="A03:2021",
                description="Parámetro id vulnerable a inyección.",
                cvss_score=9.1,
            ),
            _make_finding(
                tool="vulnapi",
                rule_id="jwt-weak-secret",
                title="JWT secret débil",
                severity="high",
                asset=asset_api,
                cwe="CWE-347",
                owasp="API2:2023",
                description="El secreto JWT es débil o común.",
                cvss_score=8.2,
            ),
            _make_finding(
                tool="osv",
                rule_id="CVE-2024-9999",
                title="Dependencia vulnerable en requirements.txt",
                severity="medium",
                asset=asset_repo,
                cwe="CWE-1104",
                owasp="A06:2021",
                description="Versión vulnerable detectada por OSV.",
                cvss_score=5.4,
            ),
            _make_finding(
                tool="nuclei",
                rule_id="exposed-panel",
                title="Panel de administración expuesto",
                severity="medium",
                asset=asset_web,
                cwe="CWE-200",
                owasp="A05:2021",
                description="Ruta /admin accesible sin restricciones.",
                cvss_score=6.0,
            ),
        ]
        crud.create_findings(db, asset_web, [findings[0], findings[1]], scan_id=scan_web.id)
        api_items = crud.create_findings(db, asset_api, [findings[2]], scan_id=scan_api.id)
        crud.create_findings(db, asset_repo, [findings[3]], scan_id=scan_repo.id)
        web_items = crud.create_findings(db, asset_web, [findings[4]], scan_id=scan_nuclei.id)

        if api_items:
            api_items[0].assignee_user_id = user.id
            db.add(api_items[0])
            db.commit()
        if web_items:
            db.add(
                models.FindingComment(
                    finding_id=web_items[0].id,
                    user_id=user.id,
                    message="Revisar acceso al panel y aplicar autenticacion.",
                    created_at=datetime.utcnow() - timedelta(minutes=5),
                )
            )
            db.commit()

        _create_audit_logs(db, user_id=user.id)
        existing_templates = (
            db.query(models.FindingTemplate)
            .filter(models.FindingTemplate.organization_id == org.id)
            .count()
        )
        if existing_templates == 0:
            db.add_all(
                [
                    models.FindingTemplate(
                        organization_id=org.id,
                        created_by_user_id=user.id,
                        title="A03: Injection",
                        severity="critical",
                        cwe="CWE-89",
                        owasp="A03:2021",
                        description="Entradas no validadas permiten inyeccion.",
                        created_at=datetime.utcnow() - timedelta(days=1),
                    ),
                    models.FindingTemplate(
                        organization_id=org.id,
                        created_by_user_id=user.id,
                        title="API2: Broken Authentication",
                        severity="high",
                        cwe="CWE-287",
                        owasp="API2:2023",
                        description="Autenticacion debil o mal implementada.",
                        created_at=datetime.utcnow() - timedelta(hours=6),
                    ),
                ]
            )
            db.commit()


if __name__ == "__main__":
    seed_demo()
    print("Seed demo aplicado.")
