import hashlib
import json
from datetime import datetime
from typing import Literal, Optional, Set

from fastapi import Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from . import models
from .db import get_db
from .auth import get_current_user, password_expired


class Principal(BaseModel):
    kind: Literal["user", "api_key"]
    user_id: Optional[int] = None
    org_id: Optional[int] = None
    project_ids: Set[int] = set()
    roles: Set[str] = set()
    email: Optional[str] = None


def _parse_json_ids(value: Optional[str]) -> Set[int]:
    if not value:
        return set()
    try:
        return {int(item) for item in json.loads(value)}
    except (TypeError, ValueError, json.JSONDecodeError):
        return set()


def _parse_json_roles(value: Optional[str]) -> Set[str]:
    if not value:
        return {"viewer"}
    try:
        return {str(item) for item in json.loads(value)}
    except (TypeError, ValueError, json.JSONDecodeError):
        return {"viewer"}


def _extract_token(request: Request) -> Optional[str]:
    cookie_token = request.cookies.get("access_token")
    if cookie_token:
        return cookie_token
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        return auth_header[7:]
    return None


def resolve_principal(request: Request, db: Session = Depends(get_db)) -> Principal:
    x_api_key = request.headers.get("X-API-Key")
    if x_api_key:
        key_hash = hashlib.sha256(x_api_key.encode("utf-8")).hexdigest()
        api_key = (
            db.query(models.ApiKey)
            .filter(models.ApiKey.key_hash == key_hash, models.ApiKey.is_active.is_(True))
            .first()
        )
        if not api_key:
            raise HTTPException(status_code=401, detail="API key inválida")
        if api_key.expires_at and api_key.expires_at < datetime.utcnow():
            raise HTTPException(status_code=401, detail="API key expirada")
        api_key.last_used_at = datetime.utcnow()
        db.add(api_key)
        db.commit()
        allowed_projects = _parse_json_ids(api_key.project_ids)
        if not allowed_projects and api_key.org_id:
            org_projects = (
                db.query(models.Project.id)
                .filter(models.Project.organization_id == api_key.org_id)
                .all()
            )
            allowed_projects = {row.id for row in org_projects}
        roles = _parse_json_roles(api_key.roles)
        return Principal(
            kind="api_key",
            org_id=api_key.org_id,
            project_ids=allowed_projects,
            roles=roles,
        )

    token = _extract_token(request)
    if token:
        user = get_current_user(token=token, db=db)
        if password_expired(user):
            raise HTTPException(
                status_code=403,
                detail={"code": "password_expired", "message": "Debe actualizar su contraseña"},
            )
        if not user.profile_completed:
            raise HTTPException(
                status_code=403,
                detail={"code": "profile_incomplete", "message": "Debe completar su perfil"},
            )
        memberships = db.query(models.Membership).filter(models.Membership.user_id == user.id).all()
        org_ids = {m.organization_id for m in memberships}
        roles = {m.role for m in memberships if m.role}
        project_ids = set()
        if org_ids:
            projects = db.query(models.Project.id).filter(models.Project.organization_id.in_(org_ids)).all()
            project_ids = {row.id for row in projects}
        return Principal(
            kind="user",
            user_id=user.id,
            project_ids=project_ids,
            roles=roles,
            email=user.email,
        )

    raise HTTPException(status_code=401, detail="Autenticación requerida")


def ensure_project_access(principal: Principal, project_id: int) -> None:
    if project_id not in principal.project_ids:
        raise HTTPException(status_code=403, detail="Acceso denegado a este proyecto")


def ensure_role(principal: Principal, required_roles: Set[str]) -> None:
    if not principal.roles.intersection(required_roles):
        raise HTTPException(status_code=403, detail="Rol insuficiente")


def require_user(principal: Principal, db: Session) -> models.User:
    if principal.kind != "user" or not principal.user_id:
        raise HTTPException(status_code=403, detail="Se requiere token de usuario")
    user = db.get(models.User, principal.user_id)
    if not user:
        raise HTTPException(status_code=401, detail="Usuario no encontrado")
    return user
