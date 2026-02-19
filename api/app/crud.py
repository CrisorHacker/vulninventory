from typing import Iterable, Optional

from datetime import datetime
from hashlib import sha256

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import models


def get_or_create_asset(db: Session, uri: str, name: str, asset_type: str, project_id: int) -> models.Asset:
    asset = db.execute(
        select(models.Asset).where(models.Asset.uri == uri, models.Asset.project_id == project_id)
    ).scalar_one_or_none()
    if asset:
        return asset
    asset = models.Asset(uri=uri, name=name, type=asset_type, project_id=project_id)
    db.add(asset)
    db.commit()
    db.refresh(asset)
    return asset


def create_asset(
    db: Session,
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
    asset = models.Asset(
        uri=uri,
        name=name,
        type=asset_type,
        project_id=project_id,
        owner_email=owner_email,
        environment=environment,
        criticality=criticality,
        tags=tags,
    )
    db.add(asset)
    db.commit()
    db.refresh(asset)
    return asset


def update_asset(
    db: Session,
    asset: models.Asset,
    *,
    name: Optional[str] = None,
    uri: Optional[str] = None,
    asset_type: Optional[str] = None,
    owner_email: Optional[str] = None,
    environment: Optional[str] = None,
    criticality: Optional[str] = None,
    tags: Optional[list[str]] = None,
) -> models.Asset:
    if name is not None:
        asset.name = name
    if uri is not None:
        asset.uri = uri
    if asset_type is not None:
        asset.type = asset_type
    if owner_email is not None:
        asset.owner_email = owner_email
    if environment is not None:
        asset.environment = environment
    if criticality is not None:
        asset.criticality = criticality
    if tags is not None:
        asset.tags = tags
    db.add(asset)
    db.commit()
    db.refresh(asset)
    return asset


def delete_asset(db: Session, asset: models.Asset) -> models.Asset:
    db.delete(asset)
    db.commit()
    return asset


def create_raw_report(db: Session, tool: str, payload: dict) -> models.RawReport:
    report = models.RawReport(tool=tool, payload=payload)
    db.add(report)
    db.commit()
    db.refresh(report)
    return report


def create_findings(
    db: Session,
    asset: models.Asset,
    findings: Iterable[dict],
    scan_id: Optional[int] = None,
) -> list[models.Finding]:
    seen: set[str] = set()
    created: list[models.Finding] = []
    for item in findings:
        source = item.get("source", {})
        finding = item.get("finding", {})
        fingerprint = (
            finding.get("fingerprint")
            or _fingerprint_from_item(item)
        )
        if fingerprint:
            if fingerprint in seen:
                continue
            existing = (
                db.execute(
                    select(models.Finding.id).where(
                        models.Finding.asset_id == asset.id,
                        models.Finding.raw["finding"]["fingerprint"].as_string() == fingerprint,
                    )
                )
                .scalar_one_or_none()
            )
            if existing:
                seen.add(fingerprint)
                continue
            seen.add(fingerprint)
        cvss = finding.get("cvss", {}) or {}
        record = models.Finding(
            rule_id=source.get("rule_id", ""),
            title=finding.get("title", ""),
            severity=finding.get("severity", "info"),
            status=finding.get("status", "open"),
            cwe=finding.get("cwe", ""),
            owasp=finding.get("owasp", ""),
            cvss_score=cvss.get("score"),
            cvss_vector=cvss.get("vector", ""),
            description=finding.get("description", ""),
            raw=item,
            asset_id=asset.id,
            scan_id=scan_id,
        )
        db.add(record)
        created.append(record)
    db.commit()
    for record in created:
        db.refresh(record)
    return created


def list_finding_comments(db: Session, finding_id: int) -> list[models.FindingComment]:
    stmt = (
        select(models.FindingComment)
        .where(models.FindingComment.finding_id == finding_id)
        .order_by(models.FindingComment.id.asc())
    )
    return db.execute(stmt).scalars().all()


def create_finding_comment(
    db: Session,
    *,
    finding_id: int,
    user_id: Optional[int],
    message: str,
) -> models.FindingComment:
    comment = models.FindingComment(
        finding_id=finding_id,
        user_id=user_id,
        message=message,
    )
    db.add(comment)
    db.commit()
    db.refresh(comment)
    return comment


def list_finding_templates(db: Session, org_id: int) -> list[models.FindingTemplate]:
    stmt = (
        select(models.FindingTemplate)
        .where(models.FindingTemplate.organization_id == org_id)
        .order_by(models.FindingTemplate.id.desc())
    )
    return db.execute(stmt).scalars().all()


def create_finding_template(
    db: Session,
    *,
    organization_id: int,
    created_by_user_id: Optional[int],
    title: str,
    severity: str,
    cwe: str,
    owasp: str,
    description: str,
) -> models.FindingTemplate:
    template = models.FindingTemplate(
        organization_id=organization_id,
        created_by_user_id=created_by_user_id,
        title=title,
        severity=severity,
        cwe=cwe,
        owasp=owasp,
        description=description,
    )
    db.add(template)
    db.commit()
    db.refresh(template)
    return template


def close_missing_findings(
    db: Session,
    *,
    asset_id: int,
    tool: str,
    current_keys: set[tuple[str, str]],
) -> int:
    stmt = (
        select(models.Finding)
        .where(models.Finding.asset_id == asset_id)
        .where(models.Finding.status.in_(["open", "triaged"]))
        .where(models.Finding.raw["source"]["tool"].as_string() == tool)
    )
    findings = db.execute(stmt).scalars().all()
    closed = 0
    for finding in findings:
        key = (finding.rule_id or "", finding.title or "")
        if key in current_keys:
            continue
        finding.status = "fixed"
        db.add(finding)
        closed += 1
    if closed:
        db.commit()
    return closed


def _fingerprint_from_item(item: dict) -> str:
    parts = [
        item.get("source", {}).get("tool", ""),
        item.get("asset", {}).get("uri", ""),
        item.get("finding", {}).get("title", ""),
        item.get("source", {}).get("rule_id", ""),
    ]
    blob = "|".join(parts).encode("utf-8")
    return "sha256:" + sha256(blob).hexdigest()


def create_scan(db: Session, tool: str, metadata: dict) -> models.Scan:
    project_id = metadata.get("project_id")
    if not project_id:
        raise ValueError("project_id is required")
    scan = models.Scan(tool=tool, scan_metadata=metadata, project_id=project_id)
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


def get_next_scan(db: Session, status: str = "queued") -> models.Scan | None:
    stmt = select(models.Scan).where(models.Scan.status == status).order_by(models.Scan.id.asc())
    return db.execute(stmt).scalar_one_or_none()


def update_scan(
    db: Session,
    scan: models.Scan,
    *,
    status: str | None,
    metadata: dict | None,
    finished_at=None,
) -> models.Scan:
    if status is not None:
        scan.status = status
    if metadata is not None:
        scan.scan_metadata = metadata
    if finished_at is not None:
        scan.finished_at = finished_at
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


def delete_scan(db: Session, scan: models.Scan) -> None:
    db.query(models.ScanLog).filter(models.ScanLog.scan_id == scan.id).delete()
    db.query(models.Finding).filter(models.Finding.scan_id == scan.id).update(
        {models.Finding.scan_id: None}
    )
    db.delete(scan)
    db.commit()


def create_user(db: Session, email: str, password_hash: str) -> models.User:
    user = models.User(email=email, password_hash=password_hash)
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def get_user_by_email(db: Session, email: str) -> models.User | None:
    return db.execute(select(models.User).where(models.User.email == email)).scalar_one_or_none()


def update_user_profile(
    db: Session,
    user: models.User,
    *,
    full_name: Optional[str] = None,
    phone: Optional[str] = None,
    title: Optional[str] = None,
    profile_completed: Optional[bool] = None,
) -> models.User:
    if full_name is not None:
        user.full_name = full_name
    if phone is not None:
        user.phone = phone
    if title is not None:
        user.title = title
    if profile_completed is not None:
        user.profile_completed = profile_completed
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def update_user_password(
    db: Session,
    user: models.User,
    *,
    password_hash: str,
    password_updated_at: datetime,
) -> models.User:
    user.password_hash = password_hash
    user.password_updated_at = password_updated_at
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def create_password_reset(
    db: Session,
    *,
    user_id: int,
    token_hash: str,
    expires_at: datetime,
) -> models.PasswordReset:
    reset = models.PasswordReset(user_id=user_id, token_hash=token_hash, expires_at=expires_at)
    db.add(reset)
    db.commit()
    db.refresh(reset)
    return reset


def get_password_reset_by_hash(db: Session, token_hash: str) -> models.PasswordReset | None:
    return (
        db.execute(select(models.PasswordReset).where(models.PasswordReset.token_hash == token_hash))
        .scalar_one_or_none()
    )


def mark_password_reset_used(db: Session, reset: models.PasswordReset, used_at: datetime) -> models.PasswordReset:
    reset.used_at = used_at
    db.add(reset)
    db.commit()
    db.refresh(reset)
    return reset


def create_user_activity(db: Session, *, user_id: int, action: str, ip: str | None, details: dict | None = None) -> models.UserActivity:
    entry = models.UserActivity(user_id=user_id, action=action, ip=ip, details=details or {})
    db.add(entry)
    db.commit()
    db.refresh(entry)
    return entry


def list_user_activities(db: Session, user_id: int, limit: int = 10) -> list[models.UserActivity]:
    stmt = (
        select(models.UserActivity)
        .where(models.UserActivity.user_id == user_id)
        .order_by(models.UserActivity.id.desc())
        .limit(limit)
    )
    return db.execute(stmt).scalars().all()


def get_notification_preferences(db: Session, user_id: int) -> models.NotificationPreference | None:
    stmt = select(models.NotificationPreference).where(models.NotificationPreference.user_id == user_id)
    return db.execute(stmt).scalar_one_or_none()


def upsert_notification_preferences(
    db: Session,
    *,
    user_id: int,
    critical_vulns: bool,
    assigned_vulns: bool,
    status_updates: bool,
    reports: bool,
    system_alerts: bool,
    channel: str,
) -> models.NotificationPreference:
    prefs = get_notification_preferences(db, user_id)
    if not prefs:
        prefs = models.NotificationPreference(
            user_id=user_id,
            critical_vulns=critical_vulns,
            assigned_vulns=assigned_vulns,
            status_updates=status_updates,
            reports=reports,
            system_alerts=system_alerts,
            channel=channel,
        )
    else:
        prefs.critical_vulns = critical_vulns
        prefs.assigned_vulns = assigned_vulns
        prefs.status_updates = status_updates
        prefs.reports = reports
        prefs.system_alerts = system_alerts
        prefs.channel = channel
        prefs.updated_at = datetime.utcnow()
    db.add(prefs)
    db.commit()
    db.refresh(prefs)
    return prefs


def list_users(db: Session) -> list[models.User]:
    return db.execute(select(models.User).order_by(models.User.id.asc())).scalars().all()


def create_organization(db: Session, name: str) -> models.Organization:
    org = models.Organization(name=name)
    db.add(org)
    db.commit()
    db.refresh(org)
    return org


def create_membership(db: Session, user_id: int, organization_id: int, role: str = "admin") -> models.Membership:
    membership = models.Membership(user_id=user_id, organization_id=organization_id, role=role)
    db.add(membership)
    db.commit()
    db.refresh(membership)
    return membership


def create_project(db: Session, organization_id: int, name: str) -> models.Project:
    project = models.Project(organization_id=organization_id, name=name)
    db.add(project)
    db.commit()
    db.refresh(project)
    return project


def list_projects(db: Session, organization_id: int) -> list[models.Project]:
    stmt = select(models.Project).where(models.Project.organization_id == organization_id)
    return db.execute(stmt).scalars().all()


def list_orgs_for_user(db: Session, user_id: int) -> list[models.Organization]:
    stmt = (
        select(models.Organization)
        .join(models.Membership)
        .where(models.Membership.user_id == user_id)
    )
    return db.execute(stmt).scalars().all()


def list_memberships(db: Session, organization_id: int) -> list[models.Membership]:
    stmt = select(models.Membership).where(models.Membership.organization_id == organization_id)
    return db.execute(stmt).scalars().all()


def update_membership_role(db: Session, membership_id: int, role: str) -> models.Membership | None:
    membership = db.get(models.Membership, membership_id)
    if not membership:
        return None
    membership.role = role
    db.add(membership)
    db.commit()
    db.refresh(membership)
    return membership


def create_invitation(
    db: Session,
    organization_id: int,
    email: str,
    role: str,
    token: str,
    expires_at,
) -> models.Invitation:
    invitation = models.Invitation(
        organization_id=organization_id,
        email=email,
        role=role,
        token=token,
        expires_at=expires_at,
    )
    db.add(invitation)
    db.commit()
    db.refresh(invitation)
    return invitation


def get_invitation_by_token(db: Session, token: str) -> models.Invitation | None:
    return db.execute(select(models.Invitation).where(models.Invitation.token == token)).scalar_one_or_none()


def accept_invitation(db: Session, invitation: models.Invitation) -> models.Invitation:
    invitation.accepted_at = datetime.utcnow()
    db.add(invitation)
    db.commit()
    db.refresh(invitation)
    return invitation


def list_invitations(db: Session, organization_id: int) -> list[models.Invitation]:
    stmt = select(models.Invitation).where(models.Invitation.organization_id == organization_id)
    return db.execute(stmt).scalars().all()


def disable_invitation(db: Session, invitation_id: int, disabled: bool) -> models.Invitation | None:
    invitation = db.get(models.Invitation, invitation_id)
    if not invitation:
        return None
    invitation.disabled = 1 if disabled else 0
    db.add(invitation)
    db.commit()
    db.refresh(invitation)
    return invitation


def remove_membership(db: Session, membership_id: int) -> bool:
    membership = db.get(models.Membership, membership_id)
    if not membership:
        return False
    db.delete(membership)
    db.commit()
    return True


def create_scan_log(db: Session, scan_id: int, message: str) -> models.ScanLog:
    log = models.ScanLog(scan_id=scan_id, message=message)
    db.add(log)
    db.commit()
    db.refresh(log)
    return log


def list_scan_logs(db: Session, scan_id: int) -> list[models.ScanLog]:
    stmt = select(models.ScanLog).where(models.ScanLog.scan_id == scan_id).order_by(models.ScanLog.id.asc())
    return db.execute(stmt).scalars().all()


def create_auth_attempt(db: Session, email: str, ip: str, success: bool) -> models.AuthAttempt:
    attempt = models.AuthAttempt(email=email, ip=ip, success=1 if success else 0)
    db.add(attempt)
    db.commit()
    db.refresh(attempt)
    return attempt


def recent_failed_attempts(db: Session, email: str, ip: str, since: datetime) -> int:
    stmt = (
        select(models.AuthAttempt)
        .where(models.AuthAttempt.email == email)
        .where(models.AuthAttempt.ip == ip)
        .where(models.AuthAttempt.success == 0)
        .where(models.AuthAttempt.created_at >= since)
    )
    return len(db.execute(stmt).scalars().all())


def user_in_org(user: models.User, organization_id: int) -> bool:
    return any(m.organization_id == organization_id for m in user.memberships)


def get_membership_role(db: Session, user_id: int, organization_id: int) -> str | None:
    stmt = select(models.Membership).where(
        models.Membership.user_id == user_id,
        models.Membership.organization_id == organization_id,
    )
    membership = db.execute(stmt).scalar_one_or_none()
    if not membership:
        return None
    return membership.role
