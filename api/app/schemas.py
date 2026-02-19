from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field, field_validator


class AssetOut(BaseModel):
    id: int
    name: str
    uri: str
    type: str
    created_at: datetime
    owner_email: Optional[str] = None
    environment: Optional[str] = None
    criticality: Optional[str] = None
    tags: list[str] = Field(default_factory=list)

    model_config = {"from_attributes": True}

    @field_validator("tags", mode="before")
    @classmethod
    def normalize_tags(cls, value: Any) -> list[str]:
        if value is None:
            return []
        return value


class ScanOut(BaseModel):
    id: int
    tool: str
    status: str
    started_at: datetime
    finished_at: Optional[datetime]
    metadata: dict[str, Any] = Field(alias="scan_metadata")

    model_config = {"populate_by_name": True, "from_attributes": True}


class FindingOut(BaseModel):
    id: int
    rule_id: str
    title: str
    severity: str
    status: str
    cwe: str
    owasp: str
    cvss_score: Optional[float]
    cvss_vector: str
    description: str
    recommendation: Optional[str] = None
    references: Optional[str] = None
    asset_id: int
    scan_id: Optional[int]
    assignee_user_id: Optional[int] = None

    model_config = {"from_attributes": True}


class FindingUpdate(BaseModel):
    status: Optional[str] = None
    assignee_user_id: Optional[int] = None


class ManualFindingCreate(BaseModel):
    asset_id: int
    title: str
    severity: str
    status: str = "open"
    cwe: Optional[str] = None
    owasp: Optional[str] = None
    description: Optional[str] = None
    recommendation: Optional[str] = None
    references: Optional[str] = None
    rule_id: Optional[str] = None
    assignee_user_id: Optional[int] = None


class FindingTemplateCreate(BaseModel):
    org_id: int
    title: str
    severity: str
    cwe: Optional[str] = None
    owasp: Optional[str] = None
    description: Optional[str] = None


class FindingTemplateOut(BaseModel):
    id: int
    organization_id: Optional[int]
    created_by_user_id: Optional[int]
    title: str
    severity: str
    cwe: str
    owasp: str
    description: str
    created_at: datetime

    model_config = {"from_attributes": True}


class AssetCreate(BaseModel):
    project_id: int
    name: str
    uri: str
    type: str
    owner_email: str
    environment: str
    criticality: str
    tags: list[str] = Field(default_factory=list)


class AssetUpdate(BaseModel):
    name: Optional[str] = None
    uri: Optional[str] = None
    type: Optional[str] = None
    owner_email: Optional[str] = None
    environment: Optional[str] = None
    criticality: Optional[str] = None
    tags: Optional[list[str]] = None


class FindingIn(BaseModel):
    source: dict[str, Any] = Field(default_factory=dict)
    asset: dict[str, Any] = Field(default_factory=dict)
    finding: dict[str, Any] = Field(default_factory=dict)
    evidence: dict[str, Any] = Field(default_factory=dict)
    timestamps: dict[str, Any] = Field(default_factory=dict)


class IngestRequest(BaseModel):
    tool: str
    report: dict[str, Any]
    findings: list[FindingIn]


ALLOWED_SCAN_TOOLS = {"wapiti", "osv", "nuclei", "vulnapi", "sarif"}


class ScanRequest(BaseModel):
    tool: str
    args: dict[str, Any] = Field(default_factory=dict)

    @field_validator("tool")
    @classmethod
    def validate_tool(cls, value: str) -> str:
        tool = value.lower().strip()
        if tool not in ALLOWED_SCAN_TOOLS:
            raise ValueError(
                f"Herramienta no permitida: {value}. Permitidas: {', '.join(sorted(ALLOWED_SCAN_TOOLS))}"
            )
        return tool

    @field_validator("args")
    @classmethod
    def validate_args(cls, value: dict[str, Any]) -> dict[str, Any]:
        forbidden_keys = {"command", "cmd", "exec", "shell", "script"}
        found = {key for key in value.keys() if key.lower() in forbidden_keys}
        if found:
            raise ValueError(f"Campos prohibidos en args: {sorted(found)}")
        return value


class ScanUpdate(BaseModel):
    status: Optional[str] = None
    finished_at: Optional[datetime] = None
    metadata: Optional[dict[str, Any]] = None


class UserCreate(BaseModel):
    email: str
    password: str
    organization: str


class LoginRequest(BaseModel):
    email: str
    password: str


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    requires_profile: bool = False


class AuthResponse(BaseModel):
    user: dict[str, Any]
    requires_profile: bool = False


class PaginatedResponse(BaseModel):
    items: list[Any]
    total: int
    limit: int
    offset: int
    has_more: bool


class UserOut(BaseModel):
    id: int
    email: str
    created_at: datetime

    model_config = {"from_attributes": True}


class UserProfileOut(BaseModel):
    id: int
    email: str
    full_name: str
    phone: str
    title: str
    profile_completed: bool
    password_updated_at: datetime
    created_at: datetime

    model_config = {"from_attributes": True}


class UserProfileUpdate(BaseModel):
    full_name: Optional[str] = None
    phone: Optional[str] = None
    title: Optional[str] = None
    current_password: Optional[str] = None


class PasswordChangeRequest(BaseModel):
    current_password: str
    new_password: str


class AuthPasswordRotate(BaseModel):
    email: str
    current_password: str
    new_password: str


class ForgotPasswordRequest(BaseModel):
    email: str


class ForgotPasswordResponse(BaseModel):
    message: str
    reset_token: Optional[str] = None
    expires_at: Optional[datetime] = None


class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str


class ApiKeyCreate(BaseModel):
    name: str
    org_id: int
    project_ids: Optional[list[int]] = None
    roles: list[str] = Field(default_factory=lambda: ["viewer"])
    expires_at: Optional[datetime] = None


class ApiKeyOut(BaseModel):
    id: int
    name: str
    org_id: Optional[int]
    project_ids: Optional[list[int]] = None
    roles: list[str] = Field(default_factory=list)
    is_active: bool
    last_used_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    created_at: datetime

    model_config = {"from_attributes": True}


class NotificationPreferencesOut(BaseModel):
    criticalVulns: bool
    assignedVulns: bool
    statusUpdates: bool
    reports: bool
    systemAlerts: bool
    channel: str


class NotificationPreferencesUpdate(BaseModel):
    criticalVulns: Optional[bool] = None
    assignedVulns: Optional[bool] = None
    statusUpdates: Optional[bool] = None
    reports: Optional[bool] = None
    systemAlerts: Optional[bool] = None
    channel: Optional[str] = None


class UserActivityOut(BaseModel):
    id: int
    action: str
    ip: Optional[str]
    created_at: datetime

    model_config = {"from_attributes": True}


class OrganizationOut(BaseModel):
    id: int
    name: str
    created_at: datetime

    model_config = {"from_attributes": True}


class OrganizationCreate(BaseModel):
    name: str


class ProjectCreate(BaseModel):
    name: str


class ProjectOut(BaseModel):
    id: int
    organization_id: int
    name: str
    created_at: datetime

    model_config = {"from_attributes": True}


class MemberCreate(BaseModel):
    email: str
    role: str = "member"


class MemberUpdate(BaseModel):
    role: str


class MemberOut(BaseModel):
    id: int
    user_id: int
    organization_id: int
    role: str
    email: str

    model_config = {"from_attributes": True}


class InvitationCreate(BaseModel):
    email: str
    role: str = "member"


class InvitationOut(BaseModel):
    id: int
    organization_id: int
    email: str
    role: str
    token: str
    expires_at: datetime
    accepted_at: Optional[datetime]
    disabled: int

    model_config = {"from_attributes": True}


class InvitationUpdate(BaseModel):
    disabled: bool = False


class InvitationAccept(BaseModel):
    email: str
    password: str


class AuditLogOut(BaseModel):
    id: int
    user_id: Optional[int]
    method: str
    path: str
    status_code: int
    ip: str
    created_at: datetime

    model_config = {"from_attributes": True}


class FindingCommentCreate(BaseModel):
    message: str


class FindingCommentOut(BaseModel):
    id: int
    finding_id: int
    user_id: Optional[int]
    message: str
    created_at: datetime

    model_config = {"from_attributes": True}


class ScanLogCreate(BaseModel):
    message: str


class BulkImportAsset(BaseModel):
    name: str
    uri: str = ""
    type: str = "web_app"
    owner_email: str | None = None
    environment: str | None = None
    criticality: str | None = None


class BulkImportFinding(BaseModel):
    title: str
    severity: str
    status: str = "open"
    description: str | None = None
    cwe: str | None = None
    owasp: str | None = Field(default=None, alias="owasp_category")
    cvss_score: float | None = None
    asset_ref: str
    pentester_email: str | None = None
    occurrences: int = 1
    tags: list[str] = []

    model_config = {"populate_by_name": True}


class BulkImportRequest(BaseModel):
    project_id: int
    assets: list[BulkImportAsset]
    findings: list[BulkImportFinding]


class BulkImportResult(BaseModel):
    assets_created: int
    assets_reused: int
    findings_created: int
    errors: list[str]


class VulnCatalogBase(BaseModel):
    cve_id: Optional[str] = None
    name: str
    description: Optional[str] = None
    severity: Optional[str] = None
    base_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    cwe_id: Optional[int] = None
    cwe_name: Optional[str] = None
    cpe: Optional[str] = None
    references: Optional[str] = None
    recommendation: Optional[str] = None
    exploit_available: bool = False
    published_date: Optional[datetime] = None
    modified_date: Optional[datetime] = None
    source: str = "manual"
    is_template: bool = False


class VulnCatalogCreate(VulnCatalogBase):
    pass


class VulnCatalogOut(VulnCatalogBase):
    id: int
    created_at: datetime

    model_config = {"from_attributes": True}


class VulnCatalogSearchOut(BaseModel):
    id: int
    cve_id: Optional[str] = None
    name: str
    description: Optional[str] = None
    severity: Optional[str] = None
    base_score: Optional[float] = None
    cwe_name: Optional[str] = None
    exploit_available: bool = False


class VulnCatalogStats(BaseModel):
    total: int
    exploit: int
    manual_templates: int
    by_severity: dict[str, int]


class VulnCatalogImportResult(BaseModel):
    imported: int
    updated: int
    skipped: int
    errors: list[str]


class ScanLogOut(BaseModel):
    id: int
    scan_id: int
    message: str
    created_at: datetime

    model_config = {"from_attributes": True}
