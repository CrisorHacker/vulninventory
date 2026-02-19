import json
import os
import re
from datetime import datetime
from typing import Optional
from urllib.parse import urlsplit, urlunsplit

import csv
import io
import secrets
from hashlib import sha256
from datetime import timedelta

import redis
from fastapi import Depends, FastAPI, File, HTTPException, Query, Request, UploadFile
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import case, desc, func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from . import crud, models, schemas
from .auth import (
    create_access_token,
    create_refresh_token,
    get_current_user,
    get_user_from_refresh,
    hash_password,
    oauth2_scheme,
    password_expired,
    verify_password,
)
from .auth_principal import Principal, ensure_project_access, require_user, resolve_principal
from .db import Base, engine, get_db
from .middleware import AuditLogMiddleware, CSRFMiddleware, RateLimitMiddleware, SecurityHeadersMiddleware

if os.environ.get("DEV_MODE", "false").lower() == "true":
    Base.metadata.create_all(bind=engine)
    import logging

    logging.getLogger("db").warning("create_all() ejecutado en dev mode. Usar Alembic en producción.")

app = FastAPI(title="Vuln Inventory API", version="0.2.0")

redis_url = os.environ.get("REDIS_URL", "redis://redis:6379/0")
redis_client = redis.Redis.from_url(redis_url)

COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "true").lower() == "true"
COOKIE_SAMESITE = os.environ.get("COOKIE_SAMESITE", "lax")
COOKIE_DOMAIN = os.environ.get("COOKIE_DOMAIN") or None
ACCESS_TOKEN_MAX_AGE = int(os.environ.get("JWT_EXPIRES_MIN", "60")) * 60
REFRESH_TOKEN_MAX_AGE = int(os.environ.get("JWT_REFRESH_DAYS", "7")) * 24 * 60 * 60

cors_origins = [origin.strip() for origin in os.environ.get("CORS_ORIGINS", "").split(",") if origin.strip()]
if cors_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-API-Key", "X-CSRF-Token"],
    )

rate_limit = int(os.environ.get("RATE_LIMIT_PER_MIN", "120"))
app.add_middleware(CSRFMiddleware, allowed_origins=cors_origins)
app.add_middleware(RateLimitMiddleware, limit_per_minute=rate_limit)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(AuditLogMiddleware)


def _require_auth(
    token: Optional[str] = Depends(oauth2_scheme),
    request: Request = None,
    db: Session = Depends(get_db),
) -> models.User | None:
    cookie_token = None
    if request:
        cookie_token = request.cookies.get("access_token")
    return get_current_user(token=cookie_token or token, db=db)


def _hash_token(token: str) -> str:
    return sha256(token.encode("utf-8")).hexdigest()


def _require_project_id(project_id: Optional[int]) -> int:
    if project_id is None:
        raise HTTPException(status_code=400, detail="project_id es obligatorio")
    return project_id


def _parse_json_list(value: Optional[str], default: Optional[list] = None) -> list:
    if not value:
        return default or []
    try:
        parsed = json.loads(value)
        if isinstance(parsed, list):
            return parsed
    except json.JSONDecodeError:
        return default or []
    return default or []


def _set_auth_cookies(response: JSONResponse, access_token: str, refresh_token: str) -> JSONResponse:
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite=COOKIE_SAMESITE,
        max_age=ACCESS_TOKEN_MAX_AGE,
        path="/",
        domain=COOKIE_DOMAIN,
    )
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite=COOKIE_SAMESITE,
        max_age=REFRESH_TOKEN_MAX_AGE,
        path="/auth/refresh",
        domain=COOKIE_DOMAIN,
    )
    csrf_token = secrets.token_urlsafe(32)
    response.set_cookie(
        key="csrf_token",
        value=csrf_token,
        httponly=False,
        secure=COOKIE_SECURE,
        samesite=COOKIE_SAMESITE,
        max_age=ACCESS_TOKEN_MAX_AGE,
        path="/",
        domain=COOKIE_DOMAIN,
    )
    return response


def _clear_auth_cookies(response: JSONResponse) -> JSONResponse:
    response.delete_cookie("access_token", path="/", domain=COOKIE_DOMAIN)
    response.delete_cookie("refresh_token", path="/auth/refresh", domain=COOKIE_DOMAIN)
    response.delete_cookie("csrf_token", path="/", domain=COOKIE_DOMAIN)
    return response


def _normalize_asset_uri(uri: Optional[str]) -> str:
    if not uri or "://" not in uri:
        return uri or ""
    parts = urlsplit(uri.strip())
    scheme = parts.scheme.lower()
    hostname = (parts.hostname or "").lower()
    if hostname == "host.docker.internal":
        hostname = "localhost"
    port = parts.port
    if port and ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
        port = None
    netloc = hostname
    if port:
        netloc = f"{hostname}:{port}"
    path = parts.path or "/"
    if path != "/" and path.endswith("/"):
        path = path.rstrip("/")
    return urlunsplit((scheme, netloc, path, parts.query, parts.fragment))


SHELL_INJECTION_PATTERN = re.compile(r"[;&|`$(){}<>\n\r\\\\]")


def _validate_scan_args(args: dict) -> None:
    target_url = args.get("target_url", "")
    if target_url:
        parts = urlsplit(target_url)
        if parts.scheme not in ("http", "https", ""):
            raise HTTPException(status_code=400, detail=f"URL scheme no permitido: {parts.scheme}")
        if SHELL_INJECTION_PATTERN.search(target_url):
            raise HTTPException(status_code=400, detail="URL contiene caracteres no permitidos")

    target_path = args.get("target_path", "")
    if target_path:
        if ".." in target_path or SHELL_INJECTION_PATTERN.search(target_path):
            raise HTTPException(status_code=400, detail="Path contiene caracteres no permitidos")


@app.get("/health")
def health_check() -> dict:
    return {"status": "ok"}


@app.post("/auth/register", response_model=schemas.AuthResponse)
def register_user(payload: schemas.UserCreate, db: Session = Depends(get_db)) -> JSONResponse:
    if os.environ.get("REGISTRATION_ENABLED", "true").lower() != "true":
        raise HTTPException(status_code=403, detail="Registro deshabilitado")
    if crud.get_user_by_email(db, payload.email):
        raise HTTPException(status_code=400, detail="El correo ya está registrado")
    user = crud.create_user(db, payload.email, hash_password(payload.password))
    org = crud.create_organization(db, payload.organization)
    crud.create_membership(db, user.id, org.id, role="admin")
    access_token = create_access_token(user.email)
    refresh_token = create_refresh_token(user.email)
    response = JSONResponse(
        content={
            "user": {"id": user.id, "email": user.email},
            "requires_profile": True,
        }
    )
    return _set_auth_cookies(response, access_token, refresh_token)


@app.post("/auth/login", response_model=schemas.AuthResponse)
def login_user(payload: schemas.LoginRequest, request: Request, db: Session = Depends(get_db)) -> JSONResponse:
    ip = request.client.host if request.client else "unknown"
    block_window = datetime.utcnow() - timedelta(minutes=10)
    failed = crud.recent_failed_attempts(db, payload.email, ip, block_window)
    if failed >= int(os.environ.get("LOGIN_MAX_ATTEMPTS", "5")):
        raise HTTPException(status_code=429, detail="Demasiados intentos")
    user = crud.get_user_by_email(db, payload.email)
    if not user or not verify_password(payload.password, user.password_hash):
        crud.create_auth_attempt(db, payload.email, ip, success=False)
        raise HTTPException(status_code=401, detail="Credenciales inválidas")
    crud.create_auth_attempt(db, payload.email, ip, success=True)
    if password_expired(user):
        raise HTTPException(
            status_code=403,
            detail={"code": "password_expired", "message": "Debe actualizar su contraseña"},
        )
    crud.create_user_activity(db, user_id=user.id, action="Inició sesión", ip=ip)
    access_token = create_access_token(user.email)
    refresh_token = create_refresh_token(user.email)
    response = JSONResponse(
        content={
            "user": {"id": user.id, "email": user.email},
            "requires_profile": not user.profile_completed,
        }
    )
    return _set_auth_cookies(response, access_token, refresh_token)


@app.post("/auth/logout")
def logout_user(request: Request, db: Session = Depends(get_db)) -> JSONResponse:
    try:
        token = request.cookies.get("access_token")
        if token:
            user = get_current_user(token=token, db=db)
            if user:
                ip = request.client.host if request.client else "unknown"
                crud.create_user_activity(db, user_id=user.id, action="Cerró sesión", ip=ip)
    except Exception:
        pass
    response = JSONResponse(content={"message": "Sesión cerrada"})
    return _clear_auth_cookies(response)


@app.post("/auth/refresh", response_model=schemas.AuthResponse)
def refresh_token(request: Request, db: Session = Depends(get_db)) -> JSONResponse:
    refresh = request.cookies.get("refresh_token")
    if not refresh:
        raise HTTPException(status_code=401, detail="No hay refresh token")
    user = get_user_from_refresh(refresh, db)
    access_token = create_access_token(user.email)
    new_refresh = create_refresh_token(user.email)
    response = JSONResponse(
        content={
            "user": {"id": user.id, "email": user.email},
            "requires_profile": not user.profile_completed,
        }
    )
    return _set_auth_cookies(response, access_token, new_refresh)


@app.get("/auth/me")
def auth_me(user: models.User | None = Depends(_require_auth)) -> dict:
    if not user:
        raise HTTPException(status_code=401, detail="Autenticación requerida")
    return {
        "id": user.id,
        "email": user.email,
        "full_name": user.full_name,
        "profile_completed": user.profile_completed,
    }


@app.post("/auth/rotate-password", response_model=schemas.AuthResponse)
def rotate_password(payload: schemas.AuthPasswordRotate, db: Session = Depends(get_db), request: Request = None) -> JSONResponse:
    user = crud.get_user_by_email(db, payload.email)
    if not user or not verify_password(payload.current_password, user.password_hash):
        raise HTTPException(status_code=401, detail="Credenciales inválidas")
    new_hash = hash_password(payload.new_password)
    crud.update_user_password(db, user, password_hash=new_hash, password_updated_at=datetime.utcnow())
    ip = request.client.host if request and request.client else "unknown"
    crud.create_user_activity(db, user_id=user.id, action="Cambió contraseña", ip=ip)
    access_token = create_access_token(user.email)
    refresh_token = create_refresh_token(user.email)
    response = JSONResponse(
        content={
            "user": {"id": user.id, "email": user.email},
            "requires_profile": not user.profile_completed,
        }
    )
    return _set_auth_cookies(response, access_token, refresh_token)


@app.post("/auth/forgot-password", response_model=schemas.ForgotPasswordResponse)
def forgot_password(payload: schemas.ForgotPasswordRequest, db: Session = Depends(get_db)) -> schemas.ForgotPasswordResponse:
    user = crud.get_user_by_email(db, payload.email)
    if not user:
        return schemas.ForgotPasswordResponse(
            message="Si el correo existe, recibirás instrucciones para restablecer tu contraseña."
        )
    token = secrets.token_urlsafe(32)
    expires_at = datetime.utcnow() + timedelta(minutes=30)
    crud.create_password_reset(db, user_id=user.id, token_hash=_hash_token(token), expires_at=expires_at)
    if os.environ.get("DEV_MODE", "false").lower() == "true":
        import logging

        logging.getLogger("auth").warning(f"[DEV] Reset token para {payload.email}: {token}")
    return schemas.ForgotPasswordResponse(
        message="Token generado para recuperación.",
        reset_token=token,
        expires_at=expires_at,
    )


@app.post("/auth/reset-password", response_model=schemas.AuthResponse)
def reset_password(payload: schemas.ResetPasswordRequest, db: Session = Depends(get_db), request: Request = None) -> JSONResponse:
    token_hash = _hash_token(payload.token)
    reset = crud.get_password_reset_by_hash(db, token_hash)
    if not reset or reset.used_at or reset.expires_at < datetime.utcnow():
        raise HTTPException(status_code=400, detail="Token inválido o expirado")
    user = db.get(models.User, reset.user_id)
    if not user:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    new_hash = hash_password(payload.new_password)
    crud.update_user_password(db, user, password_hash=new_hash, password_updated_at=datetime.utcnow())
    crud.mark_password_reset_used(db, reset, used_at=datetime.utcnow())
    ip = request.client.host if request and request.client else "unknown"
    crud.create_user_activity(db, user_id=user.id, action="Restableció contraseña", ip=ip)
    access_token = create_access_token(user.email)
    refresh_token = create_refresh_token(user.email)
    response = JSONResponse(
        content={
            "user": {"id": user.id, "email": user.email},
            "requires_profile": not user.profile_completed,
        }
    )
    return _set_auth_cookies(response, access_token, refresh_token)


@app.get("/users/me", response_model=schemas.UserProfileOut)
def get_profile(
    user: models.User | None = Depends(_require_auth),
) -> schemas.UserProfileOut:
    if not user:
        raise HTTPException(status_code=403, detail="Se requiere token de usuario")
    return schemas.UserProfileOut.model_validate(user)


@app.patch("/users/me/profile", response_model=schemas.UserProfileOut)
def update_profile(
    payload: schemas.UserProfileUpdate,
    user: models.User | None = Depends(_require_auth),
    db: Session = Depends(get_db),
    request: Request = None,
) -> schemas.UserProfileOut:
    if not user:
        raise HTTPException(status_code=403, detail="Se requiere token de usuario")
    if payload.current_password:
        if not verify_password(payload.current_password, user.password_hash):
            raise HTTPException(status_code=401, detail="Contraseña actual inválida")

    full_name = payload.full_name.strip() if payload.full_name is not None else None
    phone = payload.phone.strip() if payload.phone is not None else None
    title = payload.title.strip() if payload.title is not None else None

    if not user.profile_completed:
        if not full_name or not phone or not title:
            raise HTTPException(status_code=400, detail="Nombre, celular y cargo son obligatorios")
    if user.full_name and full_name and full_name != user.full_name:
        raise HTTPException(status_code=400, detail="El nombre completo no es editable")

    updated_full_name = user.full_name or (full_name or "")
    updated_phone = phone if phone is not None else user.phone
    updated_title = title if title is not None else user.title
    completed = bool(updated_full_name and updated_phone and updated_title)

    updated = crud.update_user_profile(
        db,
        user,
        full_name=updated_full_name,
        phone=updated_phone,
        title=updated_title,
        profile_completed=completed,
    )
    ip = request.client.host if request and request.client else "unknown"
    crud.create_user_activity(db, user_id=user.id, action="Actualizó perfil", ip=ip)
    return schemas.UserProfileOut.model_validate(updated)


@app.post("/users/me/password", response_model=schemas.UserProfileOut)
def change_password(
    payload: schemas.PasswordChangeRequest,
    user: models.User | None = Depends(_require_auth),
    db: Session = Depends(get_db),
    request: Request = None,
) -> schemas.UserProfileOut:
    if not user:
        raise HTTPException(status_code=403, detail="Se requiere token de usuario")
    if not verify_password(payload.current_password, user.password_hash):
        raise HTTPException(status_code=401, detail="Contraseña actual inválida")
    new_hash = hash_password(payload.new_password)
    updated = crud.update_user_password(
        db,
        user,
        password_hash=new_hash,
        password_updated_at=datetime.utcnow(),
    )
    ip = request.client.host if request and request.client else "unknown"
    crud.create_user_activity(db, user_id=user.id, action="Actualizó contraseña", ip=ip)
    return schemas.UserProfileOut.model_validate(updated)


@app.get("/users/me/activities", response_model=list[schemas.UserActivityOut])
def list_my_activities(
    limit: int = Query(default=10, ge=1, le=50),
    user: models.User | None = Depends(_require_auth),
    db: Session = Depends(get_db),
) -> list[schemas.UserActivityOut]:
    if not user:
        raise HTTPException(status_code=403, detail="Se requiere token de usuario")
    activities = crud.list_user_activities(db, user.id, limit=limit)
    return [schemas.UserActivityOut.model_validate(item) for item in activities]


@app.get("/users/me/notifications", response_model=schemas.NotificationPreferencesOut)
def get_my_notifications(
    user: models.User | None = Depends(_require_auth),
    db: Session = Depends(get_db),
) -> schemas.NotificationPreferencesOut:
    if not user:
        raise HTTPException(status_code=403, detail="Se requiere token de usuario")
    prefs = crud.get_notification_preferences(db, user.id)
    if not prefs:
        return schemas.NotificationPreferencesOut(
            criticalVulns=True,
            assignedVulns=True,
            statusUpdates=False,
            reports=True,
            systemAlerts=True,
            channel="email",
        )
    return schemas.NotificationPreferencesOut(
        criticalVulns=prefs.critical_vulns,
        assignedVulns=prefs.assigned_vulns,
        statusUpdates=prefs.status_updates,
        reports=prefs.reports,
        systemAlerts=prefs.system_alerts,
        channel=prefs.channel,
    )


@app.patch("/users/me/notifications", response_model=schemas.NotificationPreferencesOut)
def update_my_notifications(
    payload: schemas.NotificationPreferencesUpdate,
    user: models.User | None = Depends(_require_auth),
    db: Session = Depends(get_db),
    request: Request = None,
) -> schemas.NotificationPreferencesOut:
    if not user:
        raise HTTPException(status_code=403, detail="Se requiere token de usuario")
    existing = crud.get_notification_preferences(db, user.id)
    prefs = crud.upsert_notification_preferences(
        db,
        user_id=user.id,
        critical_vulns=payload.criticalVulns if payload.criticalVulns is not None else (existing.critical_vulns if existing else True),
        assigned_vulns=payload.assignedVulns if payload.assignedVulns is not None else (existing.assigned_vulns if existing else True),
        status_updates=payload.statusUpdates if payload.statusUpdates is not None else (existing.status_updates if existing else False),
        reports=payload.reports if payload.reports is not None else (existing.reports if existing else True),
        system_alerts=payload.systemAlerts if payload.systemAlerts is not None else (existing.system_alerts if existing else True),
        channel=payload.channel if payload.channel else (existing.channel if existing else "email"),
    )
    ip = request.client.host if request and request.client else "unknown"
    crud.create_user_activity(db, user_id=user.id, action="Actualizó preferencias de notificación", ip=ip)
    return schemas.NotificationPreferencesOut(
        criticalVulns=prefs.critical_vulns,
        assignedVulns=prefs.assigned_vulns,
        statusUpdates=prefs.status_updates,
        reports=prefs.reports,
        systemAlerts=prefs.system_alerts,
        channel=prefs.channel,
    )


@app.get("/orgs", response_model=list[schemas.OrganizationOut])
def list_orgs(
    principal: Principal = Depends(resolve_principal),
    db: Session = Depends(get_db),
) -> list[schemas.OrganizationOut]:
    user = require_user(principal, db)
    orgs = crud.list_orgs_for_user(db, user.id)
    return [schemas.OrganizationOut.model_validate(org) for org in orgs]


@app.post("/orgs", response_model=schemas.OrganizationOut)
def create_org(
    payload: schemas.OrganizationCreate,
    principal: Principal = Depends(resolve_principal),
    db: Session = Depends(get_db),
) -> schemas.OrganizationOut:
    user = require_user(principal, db)
    try:
        org = crud.create_organization(db, payload.name)
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=400, detail="El cliente ya existe")
    crud.create_membership(db, user.id, org.id, role="owner")
    return schemas.OrganizationOut.model_validate(org)


@app.get("/orgs/{org_id}/members", response_model=schemas.PaginatedResponse)
def list_members(
    org_id: int,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    principal: Principal = Depends(resolve_principal),
    db: Session = Depends(get_db),
) -> schemas.PaginatedResponse:
    user = require_user(principal, db)
    if not crud.user_in_org(user, org_id):
        raise HTTPException(status_code=403, detail="Acceso denegado")
    total = db.execute(
        select(func.count()).select_from(models.Membership).where(models.Membership.organization_id == org_id)
    ).scalar_one()
    memberships = (
        db.query(models.Membership)
        .filter(models.Membership.organization_id == org_id)
        .offset(offset)
        .limit(limit)
        .all()
    )
    results = []
    for membership in memberships:
        member_user = db.get(models.User, membership.user_id)
        if not member_user:
            continue
        results.append(
            schemas.MemberOut(
                id=membership.id,
                user_id=membership.user_id,
                organization_id=membership.organization_id,
                role=membership.role,
                email=member_user.email,
            )
        )
    return schemas.PaginatedResponse(
        items=results,
        total=total,
        limit=limit,
        offset=offset,
        has_more=(offset + limit) < total,
    )


@app.post("/orgs/{org_id}/members", response_model=schemas.MemberOut)
def add_member(
    org_id: int,
    payload: schemas.MemberCreate,
    principal: Principal = Depends(resolve_principal),
    db: Session = Depends(get_db),
) -> schemas.MemberOut:
    user = require_user(principal, db)
    role = crud.get_membership_role(db, user.id, org_id)
    if role not in {"admin", "owner"}:
        raise HTTPException(status_code=403, detail="Se requiere rol de administrador")
    target = crud.get_user_by_email(db, payload.email)
    if not target:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    membership = crud.create_membership(db, target.id, org_id, role=payload.role)
    return schemas.MemberOut(
        id=membership.id,
        user_id=membership.user_id,
        organization_id=membership.organization_id,
        role=membership.role,
        email=target.email,
    )


@app.patch("/orgs/{org_id}/members/{member_id}", response_model=schemas.MemberOut)
def update_member(
    org_id: int,
    member_id: int,
    payload: schemas.MemberUpdate,
    principal: Principal = Depends(resolve_principal),
    db: Session = Depends(get_db),
) -> schemas.MemberOut:
    user = require_user(principal, db)
    role = crud.get_membership_role(db, user.id, org_id)
    if role not in {"admin", "owner"}:
        raise HTTPException(status_code=403, detail="Se requiere rol de administrador")
    membership = crud.update_membership_role(db, member_id, payload.role)
    if not membership:
        raise HTTPException(status_code=404, detail="Membresía no encontrada")
    target = db.get(models.User, membership.user_id)
    return schemas.MemberOut(
        id=membership.id,
        user_id=membership.user_id,
        organization_id=membership.organization_id,
        role=membership.role,
        email=target.email if target else "",
    )


@app.post("/orgs/{org_id}/invites", response_model=schemas.InvitationOut)
def create_invite(
    org_id: int,
    payload: schemas.InvitationCreate,
    principal: Principal = Depends(resolve_principal),
    db: Session = Depends(get_db),
) -> schemas.InvitationOut:
    user = require_user(principal, db)
    role = crud.get_membership_role(db, user.id, org_id)
    if role not in {"admin", "owner"}:
        raise HTTPException(status_code=403, detail="Se requiere rol de administrador")
    token = secrets.token_urlsafe(32)
    expires_at = datetime.utcnow() + timedelta(days=7)
    invitation = crud.create_invitation(db, org_id, payload.email, payload.role, token, expires_at)
    return schemas.InvitationOut.model_validate(invitation)


@app.get("/orgs/{org_id}/invites", response_model=list[schemas.InvitationOut])
def list_invites(
    org_id: int,
    principal: Principal = Depends(resolve_principal),
    db: Session = Depends(get_db),
) -> list[schemas.InvitationOut]:
    user = require_user(principal, db)
    role = crud.get_membership_role(db, user.id, org_id)
    if role not in {"admin", "owner"}:
        raise HTTPException(status_code=403, detail="Se requiere rol de administrador")
    invites = crud.list_invitations(db, org_id)
    return [schemas.InvitationOut.model_validate(invite) for invite in invites]


@app.patch("/orgs/{org_id}/invites/{invite_id}", response_model=schemas.InvitationOut)
def update_invite(
    org_id: int,
    invite_id: int,
    payload: schemas.InvitationUpdate,
    principal: Principal = Depends(resolve_principal),
    db: Session = Depends(get_db),
) -> schemas.InvitationOut:
    user = require_user(principal, db)
    role = crud.get_membership_role(db, user.id, org_id)
    if role not in {"admin", "owner"}:
        raise HTTPException(status_code=403, detail="Se requiere rol de administrador")
    invitation = crud.disable_invitation(db, invite_id, payload.disabled)
    if not invitation:
        raise HTTPException(status_code=404, detail="Invitación no encontrada")
    return schemas.InvitationOut.model_validate(invitation)


@app.get("/invites/{token}", response_model=schemas.InvitationOut)
def get_invite(token: str, db: Session = Depends(get_db)) -> schemas.InvitationOut:
    invitation = crud.get_invitation_by_token(db, token)
    if not invitation:
        raise HTTPException(status_code=404, detail="Invitación no encontrada")
    if invitation.disabled:
        raise HTTPException(status_code=403, detail="Invitación deshabilitada")
    return schemas.InvitationOut.model_validate(invitation)


@app.post("/invites/{token}/accept", response_model=schemas.AuthResponse)
def accept_invite(token: str, payload: schemas.InvitationAccept, db: Session = Depends(get_db)) -> JSONResponse:
    invitation = crud.get_invitation_by_token(db, token)
    if not invitation or invitation.accepted_at or invitation.disabled:
        raise HTTPException(status_code=404, detail="Invitación no válida")
    if invitation.email.lower() != payload.email.lower():
        raise HTTPException(status_code=400, detail="El correo no coincide")
    if invitation.expires_at < datetime.utcnow():
        raise HTTPException(status_code=400, detail="La invitación expiró")
    user = crud.get_user_by_email(db, payload.email)
    if not user:
        user = crud.create_user(db, payload.email, hash_password(payload.password))
    crud.create_membership(db, user.id, invitation.organization_id, role=invitation.role)
    crud.accept_invitation(db, invitation)
    access_token = create_access_token(user.email)
    refresh_token = create_refresh_token(user.email)
    response = JSONResponse(
        content={
            "user": {"id": user.id, "email": user.email},
            "requires_profile": not user.profile_completed,
        }
    )
    return _set_auth_cookies(response, access_token, refresh_token)


@app.delete("/orgs/{org_id}/members/{member_id}")
def remove_member(
    org_id: int,
    member_id: int,
    principal: Principal = Depends(resolve_principal),
    db: Session = Depends(get_db),
) -> dict:
    user = require_user(principal, db)
    role = crud.get_membership_role(db, user.id, org_id)
    if role not in {"admin", "owner"}:
        raise HTTPException(status_code=403, detail="Se requiere rol de administrador")
    if not crud.remove_membership(db, member_id):
        raise HTTPException(status_code=404, detail="Membresía no encontrada")
    return {"status": "removed"}


@app.get("/audit-logs", response_model=schemas.PaginatedResponse)
def list_audit_logs(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    principal: Principal = Depends(resolve_principal),
    db: Session = Depends(get_db),
) -> schemas.PaginatedResponse:
    require_user(principal, db)
    stmt = select(models.AuditLog).order_by(models.AuditLog.id.desc())
    total = db.execute(select(func.count()).select_from(models.AuditLog)).scalar_one()
    logs = db.execute(stmt.offset(offset).limit(limit)).scalars().all()
    items = [schemas.AuditLogOut.model_validate(log) for log in logs]
    return schemas.PaginatedResponse(
        items=items,
        total=total,
        limit=limit,
        offset=offset,
        has_more=(offset + limit) < total,
    )


@app.get("/users", response_model=list[schemas.UserOut])
def list_users(
    org_id: Optional[int] = Query(default=None),
    principal: Principal = Depends(resolve_principal),
    db: Session = Depends(get_db),
) -> list[schemas.UserOut]:
    user = require_user(principal, db)
    if org_id is None:
        raise HTTPException(status_code=400, detail="org_id es obligatorio")
    role = crud.get_membership_role(db, user.id, org_id)
    if role not in {"admin", "owner"}:
        raise HTTPException(status_code=403, detail="Se requiere rol de administrador")
    users = crud.list_users(db)
    return [schemas.UserOut.model_validate(item) for item in users]


@app.post("/orgs/{org_id}/projects", response_model=schemas.ProjectOut)
def create_project(
    org_id: int,
    payload: schemas.ProjectCreate,
    principal: Principal = Depends(resolve_principal),
    db: Session = Depends(get_db),
) -> schemas.ProjectOut:
    user = require_user(principal, db)
    role = crud.get_membership_role(db, user.id, org_id)
    if role not in {"admin", "owner"}:
        raise HTTPException(status_code=403, detail="Se requiere rol de administrador")
    project = crud.create_project(db, org_id, payload.name)
    return schemas.ProjectOut.model_validate(project)


@app.post("/api-keys")
def create_api_key(
    payload: schemas.ApiKeyCreate,
    principal: Principal = Depends(resolve_principal),
    db: Session = Depends(get_db),
) -> dict:
    user = require_user(principal, db)
    role = crud.get_membership_role(db, user.id, payload.org_id)
    if role not in {"admin", "owner"}:
        raise HTTPException(status_code=403, detail="Se requiere rol de administrador")
    raw_key = secrets.token_urlsafe(32)
    key_hash = sha256(raw_key.encode("utf-8")).hexdigest()
    api_key = models.ApiKey(
        name=payload.name,
        key_hash=key_hash,
        org_id=payload.org_id,
        project_ids=json.dumps(payload.project_ids) if payload.project_ids else None,
        roles=json.dumps(payload.roles) if payload.roles else json.dumps(["viewer"]),
        created_by=user.id,
        expires_at=payload.expires_at,
    )
    db.add(api_key)
    db.commit()
    return {
        "id": api_key.id,
        "name": api_key.name,
        "key": raw_key,
        "message": "Guarda esta key, no se mostrará de nuevo",
    }


@app.get("/api-keys", response_model=list[schemas.ApiKeyOut])
def list_api_keys(
    org_id: Optional[int] = Query(default=None),
    principal: Principal = Depends(resolve_principal),
    db: Session = Depends(get_db),
) -> list[schemas.ApiKeyOut]:
    user = require_user(principal, db)
    memberships = db.query(models.Membership).filter(models.Membership.user_id == user.id).all()
    admin_org_ids = {m.organization_id for m in memberships if m.role in {"admin", "owner"}}
    if org_id is not None:
        if org_id not in admin_org_ids:
            raise HTTPException(status_code=403, detail="Se requiere rol de administrador")
        org_filter = org_id
    else:
        if not admin_org_ids:
            raise HTTPException(status_code=403, detail="Se requiere rol de administrador")
        org_filter = None
    stmt = db.query(models.ApiKey).filter(models.ApiKey.is_active.is_(True))
    if org_filter is not None:
        stmt = stmt.filter(models.ApiKey.org_id == org_filter)
    else:
        stmt = stmt.filter(models.ApiKey.org_id.in_(list(admin_org_ids)))
    keys = stmt.order_by(models.ApiKey.created_at.desc()).all()
    output = []
    for key in keys:
        output.append(
            schemas.ApiKeyOut(
                id=key.id,
                name=key.name,
                org_id=key.org_id,
                project_ids=_parse_json_list(key.project_ids),
                roles=_parse_json_list(key.roles, default=["viewer"]),
                is_active=key.is_active,
                last_used_at=key.last_used_at,
                expires_at=key.expires_at,
                created_at=key.created_at,
            )
        )
    return output


@app.delete("/api-keys/{key_id}")
def revoke_api_key(
    key_id: int,
    principal: Principal = Depends(resolve_principal),
    db: Session = Depends(get_db),
) -> dict:
    user = require_user(principal, db)
    key = db.get(models.ApiKey, key_id)
    if not key:
        raise HTTPException(status_code=404, detail="API key no encontrada")
    role = crud.get_membership_role(db, user.id, key.org_id) if key.org_id else None
    if role not in {"admin", "owner"}:
        raise HTTPException(status_code=403, detail="Se requiere rol de administrador")
    key.is_active = False
    db.add(key)
    db.commit()
    return {"detail": "API key revocada"}


@app.get("/orgs/{org_id}/projects", response_model=list[schemas.ProjectOut])
def list_projects(
    org_id: int,
    principal: Principal = Depends(resolve_principal),
    db: Session = Depends(get_db),
) -> list[schemas.ProjectOut]:
    user = require_user(principal, db)
    if not crud.user_in_org(user, org_id):
        raise HTTPException(status_code=403, detail="Acceso denegado")
    projects = crud.list_projects(db, org_id)
    return [schemas.ProjectOut.model_validate(project) for project in projects]


@app.post("/reports/ingest", response_model=list[schemas.FindingOut])
def ingest_report(
    payload: schemas.IngestRequest,
    principal: Principal = Depends(resolve_principal),
    db: Session = Depends(get_db),
) -> list[schemas.FindingOut]:
    report = crud.create_raw_report(db, payload.tool, payload.report)
    del report

    if not payload.findings:
        return []

    first_asset = payload.findings[0].asset or {}
    raw_asset_uri = first_asset.get("uri") or first_asset.get("name") or "unknown"
    asset_uri = _normalize_asset_uri(raw_asset_uri)
    asset_name = first_asset.get("name") or asset_uri or raw_asset_uri
    asset_type = first_asset.get("type") or "api"
    project_id = first_asset.get("project_id")
    if not project_id:
        raise HTTPException(status_code=400, detail="project_id es obligatorio en el asset")
    project_id = int(project_id)
    ensure_project_access(principal, project_id)
    asset = crud.get_or_create_asset(db, asset_uri, asset_name, asset_type, project_id)

    current_keys: set[tuple[str, str]] = set()
    for item in payload.findings:
        source = item.source or {}
        rule_id = source.get("rule_id", "")
        title = (item.finding or {}).get("title", "")
        current_keys.add((rule_id or "", title or ""))
    crud.close_missing_findings(db, asset_id=asset.id, tool=payload.tool, current_keys=current_keys)

    created = crud.create_findings(db, asset, [f.model_dump() for f in payload.findings])
    return [schemas.FindingOut.model_validate(item) for item in created]


@app.get("/findings/export")
def export_findings(
    project_id: Optional[int] = Query(default=None),
    format: str = Query(default="csv"),
    principal: Principal = Depends(resolve_principal),
    db: Session = Depends(get_db),
):
    project_id = _require_project_id(project_id)
    ensure_project_access(principal, project_id)
    stmt = (
        select(models.Finding, models.Asset)
        .join(models.Asset)
        .where(models.Asset.project_id == project_id)
    )
    if format == "json":
        rows = db.execute(stmt).all()
        data = []
        for finding, asset in rows:
            data.append(
                {
                    "id": finding.id,
                    "title": finding.title,
                    "severity": finding.severity,
                    "status": finding.status,
                    "cwe": finding.cwe,
                    "owasp": finding.owasp,
                    "cvss_score": finding.cvss_score,
                    "cvss_vector": finding.cvss_vector,
                    "asset_name": asset.name,
                    "asset_uri": asset.uri,
                }
            )
        return JSONResponse(content=data)

    def generate_csv():
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(
            [
                "id",
                "title",
                "severity",
                "status",
                "cwe",
                "owasp",
                "cvss_score",
                "cvss_vector",
                "asset_name",
                "asset_uri",
            ]
        )
        yield output.getvalue()
        output.seek(0)
        output.truncate(0)

        batch_size = 500
        offset = 0
        while True:
            rows = db.execute(stmt.offset(offset).limit(batch_size)).all()
            if not rows:
                break
            for finding, asset in rows:
                writer.writerow(
                    [
                        finding.id,
                        finding.title,
                        finding.severity,
                        finding.status,
                        finding.cwe,
                        finding.owasp,
                        finding.cvss_score,
                        finding.cvss_vector,
                        asset.name,
                        asset.uri,
                    ]
                )
                yield output.getvalue()
                output.seek(0)
                output.truncate(0)
            offset += batch_size

    return StreamingResponse(
        generate_csv(),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=findings.csv"},
    )


@app.get("/findings", response_model=schemas.PaginatedResponse)
def list_findings(
    severity: Optional[str] = Query(default=None),
    owasp: Optional[str] = Query(default=None),
    cwe: Optional[str] = Query(default=None),
    asset_id: Optional[int] = Query(default=None),
    project_id: Optional[int] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    principal: Principal = Depends(resolve_principal),
    db: Session = Depends(get_db),
) -> schemas.PaginatedResponse:
    project_id = _require_project_id(project_id)
    stmt = select(models.Finding)
    if severity:
        stmt = stmt.where(models.Finding.severity == severity)
    if owasp:
        stmt = stmt.where(models.Finding.owasp == owasp)
    if cwe:
        stmt = stmt.where(models.Finding.cwe == cwe)
    if asset_id:
        stmt = stmt.where(models.Finding.asset_id == asset_id)
    ensure_project_access(principal, project_id)
    stmt = stmt.join(models.Asset).where(models.Asset.project_id == project_id)
    total = db.execute(select(func.count()).select_from(stmt.subquery())).scalar_one()
    results = db.execute(stmt.offset(offset).limit(limit)).scalars().all()
    items = [schemas.FindingOut.model_validate(item) for item in results]
    return schemas.PaginatedResponse(
        items=items,
        total=total,
        limit=limit,
        offset=offset,
        has_more=(offset + limit) < total,
    )


@app.post("/findings/manual", response_model=schemas.FindingOut)
def create_manual_finding(
    payload: schemas.ManualFindingCreate,
    principal: Principal = Depends(resolve_principal),
    db: Session = Depends(get_db),
) -> schemas.FindingOut:
    require_user(principal, db)
    asset = db.get(models.Asset, payload.asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Activo no encontrado")
    ensure_project_access(principal, asset.project_id)
    assignee_id = payload.assignee_user_id
    if assignee_id is not None:
        assignee = db.get(models.User, assignee_id)
        if not assignee:
            raise HTTPException(status_code=404, detail="Usuario asignado no encontrado")
        project = db.get(models.Project, asset.project_id)
        if not project:
            raise HTTPException(status_code=404, detail="Proyecto no encontrado")
        if not crud.user_in_org(assignee, project.organization_id):
            raise HTTPException(status_code=400, detail="El usuario no pertenece a la organización")

    finding = models.Finding(
        rule_id=payload.rule_id or "manual",
        title=payload.title,
        severity=payload.severity,
        status=payload.status,
        cwe=payload.cwe or "",
        owasp=payload.owasp or "",
        cvss_score=None,
        cvss_vector="",
        description=payload.description or "",
        recommendation=payload.recommendation or None,
        references=payload.references or None,
        raw={
            "source": {"tool": "manual", "rule_id": payload.rule_id or "manual"},
            "finding": {
                "title": payload.title,
                "severity": payload.severity,
                "status": payload.status,
                "cwe": payload.cwe or "",
                "owasp": payload.owasp or "",
                "description": payload.description or "",
                "recommendation": payload.recommendation or "",
                "references": payload.references or "",
            },
        },
        asset_id=asset.id,
        scan_id=None,
        assignee_user_id=assignee_id,
    )
    db.add(finding)
    db.commit()
    db.refresh(finding)
    return schemas.FindingOut.model_validate(finding)


@app.post("/import/bulk", response_model=schemas.BulkImportResult)
def import_bulk(
    payload: schemas.BulkImportRequest,
    principal: Principal = Depends(resolve_principal),
    db: Session = Depends(get_db),
) -> schemas.BulkImportResult:
    require_user(principal, db)
    project = db.get(models.Project, payload.project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Proyecto no encontrado")
    ensure_project_access(principal, payload.project_id)

    errors: list[str] = []
    assets_created = 0
    assets_reused = 0
    findings_created = 0
    asset_id_by_name: dict[str, int] = {}

    try:
        for asset in payload.assets:
            name = asset.name.strip()
            uri = (asset.uri or asset.name).strip()
            if not name:
                errors.append("Activo sin nombre")
                continue
            if name in asset_id_by_name:
                errors.append(f"Activo duplicado: {name}")
                continue
            existing = (
                db.query(models.Asset)
                .filter(
                    models.Asset.project_id == payload.project_id,
                    models.Asset.name == name,
                    models.Asset.uri == uri,
                )
                .first()
            )
            if existing:
                asset_id_by_name[name] = existing.id
                assets_reused += 1
                continue
            record = models.Asset(
                name=name,
                uri=uri,
                type=asset.type or "web_app",
                owner_email=asset.owner_email or None,
                environment=asset.environment or None,
                criticality=asset.criticality or None,
                tags=[],
                project_id=payload.project_id,
            )
            db.add(record)
            db.flush()
            asset_id_by_name[name] = record.id
            assets_created += 1

        for finding in payload.findings:
            asset_name = finding.asset_ref.strip()
            if not asset_name:
                errors.append("Hallazgo sin asset_ref")
                continue
            asset_id = asset_id_by_name.get(asset_name)
            if not asset_id:
                matches = (
                    db.query(models.Asset)
                    .filter(
                        models.Asset.project_id == payload.project_id,
                        models.Asset.name == asset_name,
                    )
                    .all()
                )
                if len(matches) == 1:
                    asset_id = matches[0].id
                    asset_id_by_name[asset_name] = asset_id
                    assets_reused += 1
                elif not matches:
                    errors.append(f"asset '{asset_name}' no encontrado")
                    continue
                else:
                    errors.append(f"asset '{asset_name}' es ambiguo")
                    continue

            record = models.Finding(
                rule_id="import",
                title=finding.title,
                severity=finding.severity,
                status=finding.status,
                cwe=finding.cwe or "",
                owasp=finding.owasp or "",
                cvss_score=finding.cvss_score,
                cvss_vector="",
                description=finding.description or "",
                raw={
                    "source": {"tool": "import", "rule_id": "import"},
                    "finding": {
                        "title": finding.title,
                        "severity": finding.severity,
                        "status": finding.status,
                        "cwe": finding.cwe or "",
                        "owasp": finding.owasp or "",
                        "description": finding.description or "",
                        "tags": finding.tags or [],
                        "occurrences": finding.occurrences,
                        "pentester_email": finding.pentester_email or "",
                    },
                },
                asset_id=asset_id,
                scan_id=None,
                assignee_user_id=None,
            )
            db.add(record)
            findings_created += 1

        if errors:
            db.rollback()
            return schemas.BulkImportResult(
                assets_created=0,
                assets_reused=0,
                findings_created=0,
                errors=errors,
            )
        db.commit()
        return schemas.BulkImportResult(
            assets_created=assets_created,
            assets_reused=assets_reused,
            findings_created=findings_created,
            errors=[],
        )
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Error importando: {exc}") from exc


def _score_to_severity(score: Optional[float]) -> str:
    if not score or score == 0:
        return "info"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "info"


def _extract_text(value: object) -> str:
    if isinstance(value, dict):
        return value.get("default") or value.get("en") or next(iter(value.values()), "") or ""
    if isinstance(value, list):
        return ", ".join([str(item) for item in value])
    return str(value) if value is not None else ""


def _extract_urls(text: str) -> str:
    if not text:
        return ""
    urls = re.findall(r"https?://\\S+", text)
    return "\\n".join(urls)


def _parse_iso_date(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


@app.get("/vulndb/search", response_model=schemas.PaginatedResponse)
def search_vulndb(
    q: str = Query(default=""),
    severity: Optional[str] = Query(default=None),
    exploit_only: bool = Query(default=False),
    limit: int = Query(default=15, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    principal: Principal = Depends(resolve_principal),
    db: Session = Depends(get_db),
) -> schemas.PaginatedResponse:
    require_user(principal, db)
    query = q.strip()
    stmt = select(models.VulnCatalog)
    if query:
        pattern = f"%{query}%"
        stmt = stmt.where(
            or_(
                models.VulnCatalog.cve_id.ilike(pattern),
                models.VulnCatalog.name.ilike(pattern),
                models.VulnCatalog.cwe_name.ilike(pattern),
                models.VulnCatalog.description.ilike(pattern),
            )
        )
        exact_match = case(
            (func.lower(models.VulnCatalog.cve_id) == query.lower(), 1),
            else_=0,
        )
        stmt = stmt.order_by(desc(exact_match), desc(models.VulnCatalog.base_score).nullslast())
    else:
        stmt = stmt.order_by(desc(models.VulnCatalog.base_score).nullslast())
    if severity:
        stmt = stmt.where(models.VulnCatalog.severity == severity)
    if exploit_only:
        stmt = stmt.where(models.VulnCatalog.exploit_available.is_(True))
    total = db.execute(select(func.count()).select_from(stmt.subquery())).scalar_one()
    results = db.execute(stmt.offset(offset).limit(limit)).scalars().all()
    output = []
    for item in results:
        description = item.description or ""
        if len(description) > 200:
            description = description[:200] + "..."
        output.append(
            schemas.VulnCatalogSearchOut(
                id=item.id,
                cve_id=item.cve_id,
                name=item.name,
                description=description,
                severity=item.severity,
                base_score=item.base_score,
                cwe_name=item.cwe_name,
                exploit_available=item.exploit_available,
            )
        )
    return schemas.PaginatedResponse(
        items=output,
        total=total,
        limit=limit,
        offset=offset,
        has_more=(offset + limit) < total,
    )


@app.post("/vulndb", response_model=schemas.VulnCatalogOut)
def create_vulndb_entry(
    payload: schemas.VulnCatalogCreate,
    principal: Principal = Depends(resolve_principal),
    db: Session = Depends(get_db),
) -> schemas.VulnCatalogOut:
    require_user(principal, db)
    record = models.VulnCatalog(
        cve_id=payload.cve_id,
        name=payload.name,
        description=payload.description,
        severity=payload.severity,
        base_score=payload.base_score,
        cvss_vector=payload.cvss_vector,
        cwe_id=payload.cwe_id,
        cwe_name=payload.cwe_name,
        cpe=payload.cpe,
        references=payload.references,
        recommendation=payload.recommendation,
        exploit_available=payload.exploit_available,
        published_date=payload.published_date,
        modified_date=payload.modified_date,
        source="manual",
        is_template=True,
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return schemas.VulnCatalogOut.model_validate(record)


@app.get("/vulndb/stats", response_model=schemas.VulnCatalogStats)
def vulndb_stats(
    principal: Principal = Depends(resolve_principal),
    db: Session = Depends(get_db),
) -> schemas.VulnCatalogStats:
    require_user(principal, db)
    total = db.query(models.VulnCatalog).count()
    exploit = db.query(models.VulnCatalog).filter(models.VulnCatalog.exploit_available.is_(True)).count()
    manual_templates = db.query(models.VulnCatalog).filter(models.VulnCatalog.is_template.is_(True)).count()
    rows = (
        db.query(models.VulnCatalog.severity, func.count(models.VulnCatalog.id))
        .group_by(models.VulnCatalog.severity)
        .all()
    )
    by_severity = {severity or "info": count for severity, count in rows}
    return schemas.VulnCatalogStats(
        total=total,
        exploit=exploit,
        manual_templates=manual_templates,
        by_severity=by_severity,
    )


@app.post("/vulndb/import", response_model=schemas.VulnCatalogImportResult)
def import_vulndb(
    file: UploadFile = File(...),
    principal: Principal = Depends(resolve_principal),
    db: Session = Depends(get_db),
) -> schemas.VulnCatalogImportResult:
    require_user(principal, db)
    imported = 0
    updated = 0
    skipped = 0
    errors: list[str] = []
    batch_size = 500
    pending = 0
    while True:
        line = file.file.readline()
        if not line:
            break
        try:
            payload = json.loads(line)
        except json.JSONDecodeError as exc:
            skipped += 1
            errors.append(f"JSON invalido: {exc}")
            continue
        if payload.get("hidden") is True:
            skipped += 1
            continue

        cve_id = payload.get("short_id") or payload.get("name")
        if not cve_id:
            skipped += 1
            errors.append("Entrada sin CVE")
            continue

        name = payload.get("name") or cve_id
        base_score = payload.get("base_score")
        severity = _score_to_severity(base_score)
        description = _extract_text(payload.get("details"))
        recommendation = _extract_text(payload.get("recommendations"))
        references_text = _extract_text(payload.get("ext_references"))
        references = _extract_urls(references_text)
        cpe_value = payload.get("cpe")
        if isinstance(cpe_value, (list, dict)):
            cpe = json.dumps(cpe_value, ensure_ascii=False)
        else:
            cpe = cpe_value or ""

        record = (
            db.query(models.VulnCatalog)
            .filter(models.VulnCatalog.cve_id == cve_id)
            .first()
        )
        if record:
            record.name = name
            record.description = description
            record.severity = severity
            record.base_score = base_score
            record.cvss_vector = payload.get("cvssv3")
            record.cwe_id = payload.get("cwe_id")
            record.cwe_name = payload.get("cwe_name")
            record.cpe = cpe
            record.references = references
            record.recommendation = recommendation
            record.exploit_available = bool(payload.get("exploit"))
            record.published_date = _parse_iso_date(payload.get("published_date"))
            record.modified_date = _parse_iso_date(payload.get("last_modified_date"))
            record.source = "jsonl_import"
            record.is_template = False
            updated += 1
        else:
            record = models.VulnCatalog(
                cve_id=cve_id,
                name=name,
                description=description,
                severity=severity,
                base_score=base_score,
                cvss_vector=payload.get("cvssv3"),
                cwe_id=payload.get("cwe_id"),
                cwe_name=payload.get("cwe_name"),
                cpe=cpe,
                references=references,
                recommendation=recommendation,
                exploit_available=bool(payload.get("exploit")),
                published_date=_parse_iso_date(payload.get("published_date")),
                modified_date=_parse_iso_date(payload.get("last_modified_date")),
                source="jsonl_import",
                is_template=False,
            )
            db.add(record)
            imported += 1

        pending += 1
        if pending >= batch_size:
            try:
                db.commit()
            except Exception as exc:
                db.rollback()
                errors.append(f"Error en batch: {exc}")
            pending = 0

    if pending:
        try:
            db.commit()
        except Exception as exc:
            db.rollback()
            errors.append(f"Error en batch final: {exc}")

    return schemas.VulnCatalogImportResult(
        imported=imported,
        updated=updated,
        skipped=skipped,
        errors=errors,
    )


@app.get("/vulndb/{entry_id}", response_model=schemas.VulnCatalogOut)
def get_vulndb_entry(
    entry_id: int,
    principal: Principal = Depends(resolve_principal),
    db: Session = Depends(get_db),
) -> schemas.VulnCatalogOut:
    require_user(principal, db)
    entry = db.get(models.VulnCatalog, entry_id)
    if not entry:
        raise HTTPException(status_code=404, detail="Entrada no encontrada")
    return schemas.VulnCatalogOut.model_validate(entry)

@app.get("/templates", response_model=list[schemas.FindingTemplateOut])
def list_finding_templates(
    org_id: Optional[int] = Query(default=None),
    principal: Principal = Depends(resolve_principal),
    db: Session = Depends(get_db),
) -> list[schemas.FindingTemplateOut]:
    user = require_user(principal, db)
    if org_id is None:
        raise HTTPException(status_code=400, detail="org_id es obligatorio")
    if not crud.user_in_org(user, org_id):
        raise HTTPException(status_code=403, detail="Acceso denegado")
    templates = crud.list_finding_templates(db, org_id)
    return [schemas.FindingTemplateOut.model_validate(item) for item in templates]


@app.post("/templates", response_model=schemas.FindingTemplateOut)
def create_finding_template(
    payload: schemas.FindingTemplateCreate,
    principal: Principal = Depends(resolve_principal),
    db: Session = Depends(get_db),
) -> schemas.FindingTemplateOut:
    user = require_user(principal, db)
    role = crud.get_membership_role(db, user.id, payload.org_id)
    if role not in {"admin", "owner"}:
        raise HTTPException(status_code=403, detail="Se requiere rol de administrador")
    template = crud.create_finding_template(
        db,
        organization_id=payload.org_id,
        created_by_user_id=user.id,
        title=payload.title,
        severity=payload.severity,
        cwe=payload.cwe or "",
        owasp=payload.owasp or "",
        description=payload.description or "",
    )
    return schemas.FindingTemplateOut.model_validate(template)


@app.patch("/findings/{finding_id}", response_model=schemas.FindingOut)
def update_finding(
    finding_id: int,
    payload: schemas.FindingUpdate,
    principal: Principal = Depends(resolve_principal),
    db: Session = Depends(get_db),
) -> schemas.FindingOut:
    finding = db.get(models.Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Hallazgo no encontrado")
    asset = db.get(models.Asset, finding.asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Activo no encontrado")
    ensure_project_access(principal, asset.project_id)
    if payload.status is not None:
        finding.status = payload.status
    if payload.assignee_user_id is not None:
        assignee = db.get(models.User, payload.assignee_user_id)
        if not assignee:
            raise HTTPException(status_code=404, detail="Usuario asignado no encontrado")
        project = db.get(models.Project, asset.project_id)
        if not project:
            raise HTTPException(status_code=404, detail="Proyecto no encontrado")
        if not crud.user_in_org(assignee, project.organization_id):
            raise HTTPException(status_code=400, detail="El usuario no pertenece a la organización")
        finding.assignee_user_id = payload.assignee_user_id
    db.add(finding)
    db.commit()
    db.refresh(finding)
    return schemas.FindingOut.model_validate(finding)


@app.get("/findings/{finding_id}/comments", response_model=list[schemas.FindingCommentOut])
def list_finding_comments(
    finding_id: int,
    principal: Principal = Depends(resolve_principal),
    db: Session = Depends(get_db),
) -> list[schemas.FindingCommentOut]:
    finding = db.get(models.Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Hallazgo no encontrado")
    asset = db.get(models.Asset, finding.asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Activo no encontrado")
    ensure_project_access(principal, asset.project_id)
    comments = crud.list_finding_comments(db, finding_id)
    return [schemas.FindingCommentOut.model_validate(item) for item in comments]


@app.post("/findings/{finding_id}/comments", response_model=schemas.FindingCommentOut)
def create_finding_comment(
    finding_id: int,
    payload: schemas.FindingCommentCreate,
    principal: Principal = Depends(resolve_principal),
    db: Session = Depends(get_db),
) -> schemas.FindingCommentOut:
    user = require_user(principal, db)
    finding = db.get(models.Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Hallazgo no encontrado")
    asset = db.get(models.Asset, finding.asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Activo no encontrado")
    ensure_project_access(principal, asset.project_id)
    if not payload.message.strip():
        raise HTTPException(status_code=400, detail="El comentario no puede estar vacío")
    comment = crud.create_finding_comment(
        db,
        finding_id=finding_id,
        user_id=user.id,
        message=payload.message.strip(),
    )
    return schemas.FindingCommentOut.model_validate(comment)


@app.get("/assets", response_model=schemas.PaginatedResponse)
def list_assets(
    project_id: Optional[int] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    principal: Principal = Depends(resolve_principal),
    db: Session = Depends(get_db),
) -> schemas.PaginatedResponse:
    project_id = _require_project_id(project_id)
    stmt = select(models.Asset)
    ensure_project_access(principal, project_id)
    stmt = stmt.where(models.Asset.project_id == project_id)
    total = db.execute(select(func.count()).select_from(stmt.subquery())).scalar_one()
    results = db.execute(stmt.offset(offset).limit(limit)).scalars().all()
    items = [schemas.AssetOut.model_validate(item) for item in results]
    return schemas.PaginatedResponse(
        items=items,
        total=total,
        limit=limit,
        offset=offset,
        has_more=(offset + limit) < total,
    )


@app.post("/assets", response_model=schemas.AssetOut)
def create_asset(
    payload: schemas.AssetCreate,
    principal: Principal = Depends(resolve_principal),
    db: Session = Depends(get_db),
) -> schemas.AssetOut:
    ensure_project_access(principal, payload.project_id)
    asset_uri = _normalize_asset_uri(payload.uri)
    asset = crud.create_asset(
        db,
        project_id=payload.project_id,
        name=payload.name,
        uri=asset_uri,
        asset_type=payload.type,
        owner_email=payload.owner_email,
        environment=payload.environment,
        criticality=payload.criticality,
        tags=payload.tags,
    )
    return schemas.AssetOut.model_validate(asset)


@app.patch("/assets/{asset_id}", response_model=schemas.AssetOut)
def update_asset(
    asset_id: int,
    payload: schemas.AssetUpdate,
    principal: Principal = Depends(resolve_principal),
    db: Session = Depends(get_db),
) -> schemas.AssetOut:
    asset = db.get(models.Asset, asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Activo no encontrado")
    ensure_project_access(principal, asset.project_id)
    asset_uri = _normalize_asset_uri(payload.uri) if payload.uri else None
    updated = crud.update_asset(
        db,
        asset,
        name=payload.name,
        uri=asset_uri,
        asset_type=payload.type,
        owner_email=payload.owner_email,
        environment=payload.environment,
        criticality=payload.criticality,
        tags=payload.tags,
    )
    return schemas.AssetOut.model_validate(updated)


@app.delete("/assets/{asset_id}", response_model=schemas.AssetOut)
def delete_asset(
    asset_id: int,
    principal: Principal = Depends(resolve_principal),
    db: Session = Depends(get_db),
) -> schemas.AssetOut:
    asset = db.get(models.Asset, asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Activo no encontrado")
    ensure_project_access(principal, asset.project_id)
    has_findings = db.execute(
        select(models.Finding.id).where(models.Finding.asset_id == asset_id).limit(1)
    ).scalar_one_or_none()
    if has_findings:
        raise HTTPException(
            status_code=400,
            detail="No se puede eliminar un activo con hallazgos asociados",
        )
    deleted = crud.delete_asset(db, asset)
    return schemas.AssetOut.model_validate(deleted)


@app.post("/scans/run", response_model=schemas.ScanOut)
def run_scan(
    payload: schemas.ScanRequest,
    principal: Principal = Depends(resolve_principal),
    db: Session = Depends(get_db),
) -> schemas.ScanOut:
    project_id = payload.args.get("project_id")
    if not project_id:
        raise HTTPException(status_code=400, detail="project_id es obligatorio en args")
    project_id = int(project_id)
    ensure_project_access(principal, project_id)
    _validate_scan_args(payload.args)
    payload.args["project_id"] = project_id
    scan = crud.create_scan(db, payload.tool, payload.args)
    redis_client.rpush("scan_queue", scan.id)
    return schemas.ScanOut.model_validate(scan)


@app.get("/scans/next", response_model=Optional[schemas.ScanOut])
def get_next_scan(
    principal: Principal = Depends(resolve_principal),
    db: Session = Depends(get_db),
) -> Optional[schemas.ScanOut]:
    if not principal.project_ids:
        raise HTTPException(status_code=403, detail="API key sin proyectos asignados")
    scan = (
        db.query(models.Scan)
        .filter(
            models.Scan.status == "queued",
            models.Scan.project_id.in_(list(principal.project_ids)),
        )
        .order_by(models.Scan.id.asc())
        .first()
    )
    if not scan:
        return None
    return schemas.ScanOut.model_validate(scan)


@app.patch("/scans/{scan_id}", response_model=schemas.ScanOut)
def update_scan(
    scan_id: int,
    payload: schemas.ScanUpdate,
    principal: Principal = Depends(resolve_principal),
    db: Session = Depends(get_db),
) -> schemas.ScanOut:
    scan = db.get(models.Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Escaneo no encontrado")
    ensure_project_access(principal, scan.project_id)
    finished_at = payload.finished_at or (datetime.utcnow() if payload.status == "finished" else None)
    updated = crud.update_scan(
        db,
        scan,
        status=payload.status,
        metadata=payload.metadata,
        finished_at=finished_at,
    )
    return schemas.ScanOut.model_validate(updated)


@app.post("/scans/{scan_id}/cancel", response_model=schemas.ScanOut)
def cancel_scan(
    scan_id: int,
    principal: Principal = Depends(resolve_principal),
    db: Session = Depends(get_db),
) -> schemas.ScanOut:
    scan = db.get(models.Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Escaneo no encontrado")
    ensure_project_access(principal, scan.project_id)
    if scan.status not in {"queued", "running"}:
        raise HTTPException(status_code=400, detail="Solo se puede cancelar un escaneo en cola o en ejecución")
    if scan.status == "queued":
        try:
            redis_client.lrem("scan_queue", 0, scan.id)
        except redis.RedisError:
            pass
    metadata = dict(scan.scan_metadata or {})
    metadata["canceled"] = True
    updated = crud.update_scan(
        db,
        scan,
        status="failed",
        metadata=metadata,
        finished_at=datetime.utcnow(),
    )
    crud.create_scan_log(db, scan.id, "Escaneo cancelado por el usuario.")
    return schemas.ScanOut.model_validate(updated)


@app.post("/scans/{scan_id}/logs", response_model=schemas.ScanLogOut)
def add_scan_log(
    scan_id: int,
    payload: schemas.ScanLogCreate,
    principal: Principal = Depends(resolve_principal),
    db: Session = Depends(get_db),
) -> schemas.ScanLogOut:
    scan = db.get(models.Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Escaneo no encontrado")
    ensure_project_access(principal, scan.project_id)
    log = crud.create_scan_log(db, scan_id, payload.message)
    return schemas.ScanLogOut.model_validate(log)


@app.get("/scans/{scan_id}/logs", response_model=list[schemas.ScanLogOut])
def list_scan_logs(
    scan_id: int,
    principal: Principal = Depends(resolve_principal),
    db: Session = Depends(get_db),
) -> list[schemas.ScanLogOut]:
    scan = db.get(models.Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Escaneo no encontrado")
    ensure_project_access(principal, scan.project_id)
    logs = crud.list_scan_logs(db, scan_id)
    return [schemas.ScanLogOut.model_validate(log) for log in logs]


@app.get("/scans", response_model=schemas.PaginatedResponse)
def list_scans(
    project_id: Optional[int] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    principal: Principal = Depends(resolve_principal),
    db: Session = Depends(get_db),
) -> schemas.PaginatedResponse:
    project_id = _require_project_id(project_id)
    stmt = select(models.Scan)
    ensure_project_access(principal, project_id)
    stmt = stmt.where(models.Scan.project_id == project_id)
    total = db.execute(select(func.count()).select_from(stmt.subquery())).scalar_one()
    results = db.execute(stmt.offset(offset).limit(limit)).scalars().all()
    items = [schemas.ScanOut.model_validate(item) for item in results]
    return schemas.PaginatedResponse(
        items=items,
        total=total,
        limit=limit,
        offset=offset,
        has_more=(offset + limit) < total,
    )


@app.get("/scans/{scan_id}", response_model=schemas.ScanOut)
def get_scan(
    scan_id: int,
    principal: Principal = Depends(resolve_principal),
    db: Session = Depends(get_db),
) -> schemas.ScanOut:
    scan = db.get(models.Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Escaneo no encontrado")
    ensure_project_access(principal, scan.project_id)
    return schemas.ScanOut.model_validate(scan)


@app.delete("/scans/{scan_id}")
def delete_scan(
    scan_id: int,
    principal: Principal = Depends(resolve_principal),
    db: Session = Depends(get_db),
) -> dict:
    scan = db.get(models.Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Escaneo no encontrado")
    ensure_project_access(principal, scan.project_id)
    crud.delete_scan(db, scan)
    return {"status": "ok"}
