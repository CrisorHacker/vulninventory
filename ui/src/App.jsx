import { Fragment, useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import UserProfile from "./profile/UserProfile";
import "./Findings.css";
import "./Dashboard.css";
import "./Assets.css";
import "./Scans.css";
import "./Users.css";
import "./Audit.css";
import "./Sidebar.css";
import "./Import.css";

const API_BASE = import.meta.env.VITE_API_BASE_URL || "http://localhost:9292";
function authHeaders() {
  return {};
}

function getCookie(name) {
  const match = document.cookie.match(new RegExp("(^| )" + name + "=([^;]+)"));
  return match ? decodeURIComponent(match[2]) : null;
}

function authFetch(url, options = {}) {
  const method = (options.method || "GET").toUpperCase();
  const headers = new Headers(options.headers || {});
  const isFormData = options.body instanceof FormData;
  if (!isFormData && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }
  if (!["GET", "HEAD", "OPTIONS"].includes(method)) {
    const csrfToken = getCookie("csrf_token");
    if (csrfToken) {
      headers.set("X-CSRF-Token", csrfToken);
    }
  }
  return window.fetch(url, {
    credentials: "include",
    ...options,
    headers,
  });
}

function unwrapItems(data) {
  if (Array.isArray(data)) {
    return data;
  }
  if (data && Array.isArray(data.items)) {
    return data.items;
  }
  return [];
}

function summarizeBySeverity(findings) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const finding of findings) {
    const key = finding.severity || "info";
    if (!counts[key]) {
      counts[key] = 0;
    }
    counts[key] += 1;
  }
  return counts;
}

function groupFindings(findings) {
  const grouped = new Map();
  for (const finding of findings) {
    const key = [
      finding.rule_id || "",
      finding.title || "",
      finding.asset_id || "",
      finding.severity || "",
      finding.owasp || "",
      finding.cwe || "",
    ].join("|");
    if (grouped.has(key)) {
      const existing = grouped.get(key);
      existing.occurrences += 1;
      existing.ids.push(finding.id);
      if (finding.scan_id && !existing.scan_ids.includes(finding.scan_id)) {
        existing.scan_ids.push(finding.scan_id);
      }
      continue;
    }
    grouped.set(key, {
      ...finding,
      occurrences: 1,
      ids: [finding.id],
      scan_ids: finding.scan_id ? [finding.scan_id] : [],
    });
  }
  return Array.from(grouped.values());
}

const severityRank = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const severityLabels = {
  critical: "Crítica",
  high: "Alta",
  medium: "Media",
  low: "Baja",
  info: "Info",
};
// TODO: backend role support for analyst/auditor/viewer.
const roleOptions = [
  {
    value: "owner",
    label: "Propietario",
    icon: "👑",
    description: "Acceso total y administración del cliente",
  },
  {
    value: "admin",
    label: "Admin",
    icon: "🛡",
    description: "Acceso total a todas las funcionalidades del proyecto",
  },
  {
    value: "analyst",
    label: "Analista",
    icon: "📊",
    description: "Gestiona hallazgos, activos y ejecuta escaneos",
  },
  {
    value: "auditor",
    label: "Auditor",
    icon: "🔍",
    description: "Acceso de solo lectura + auditoría completa",
  },
  {
    value: "viewer",
    label: "Viewer",
    icon: "👁",
    description: "Visualización de hallazgos y activos sin edición",
  },
  {
    value: "member",
    label: "Miembro",
    icon: "👤",
    description: "Acceso estándar según permisos del proyecto",
  },
];
const roleColors = {
  admin: { color: "#ef4444", bg: "rgba(239, 68, 68, 0.1)" },
  analyst: { color: "#06b6d4", bg: "rgba(6, 182, 212, 0.1)" },
  auditor: { color: "#eab308", bg: "rgba(234, 179, 8, 0.1)" },
  viewer: { color: "#94a3b8", bg: "rgba(148, 163, 184, 0.1)" },
  owner: { color: "#8b5cf6", bg: "rgba(139, 92, 246, 0.1)" },
  member: { color: "#22c55e", bg: "rgba(34, 197, 94, 0.1)" },
};
const statusLabels = {
  open: "Abierto",
  triaged: "Triado",
  accepted: "Aceptado",
  fixed: "Cerrado",
  false_positive: "Falso positivo",
};
const statusOptions = ["open", "triaged", "accepted", "fixed", "false_positive"];
const scanStatusLabels = {
  queued: "En cola",
  running: "Ejecutando",
  finished: "Finalizado",
  failed: "Fallido",
};
const assetTypeLabels = {
  web_app: "Web",
  api: "API",
  repo: "Repo",
  host: "Host",
  container: "Container",
  network_range: "Red",
};
const envLabels = {
  prod: "Producción",
  stage: "Staging",
  dev: "Desarrollo",
};

function criticalityToBadge(criticality) {
  const map = { alta: "high", media: "medium", baja: "low" };
  return map[criticality] || "info";
}

function formatDuration(ms) {
  const seconds = Math.floor(ms / 1000);
  if (seconds < 60) {
    return `${seconds}s`;
  }
  const minutes = Math.floor(seconds / 60);
  const remainingSeconds = seconds % 60;
  if (minutes < 60) {
    return `${minutes}m ${remainingSeconds}s`;
  }
  const hours = Math.floor(minutes / 60);
  return `${hours}h ${minutes % 60}m`;
}

const EMPTY_ASSET_FORM = {
  name: "",
  type: "web_app",
  uri: "",
  ownerEmail: "",
  environment: "prod",
  criticality: "media",
  tags: "",
};

const CHART_THEME = {
  tooltip: {
    contentStyle: {
      background: "#1a1f2e",
      border: "1px solid rgba(255,255,255,0.12)",
      borderRadius: "8px",
      color: "#e2e8f0",
      fontSize: "13px",
      boxShadow: "0 4px 12px rgba(0,0,0,0.4)",
    },
  },
  grid: {
    strokeDasharray: "3 3",
    stroke: "rgba(255,255,255,0.06)",
  },
  axis: {
    tick: { fill: "#94a3b8", fontSize: 12 },
    axisLine: { stroke: "rgba(255,255,255,0.08)" },
  },
  colors: {
    severity: {
      critical: "#ef4444",
      high: "#f97316",
      medium: "#eab308",
      low: "#22c55e",
      info: "#3b82f6",
    },
    status: {
      open: "#f97316",
      triaged: "#eab308",
      fixed: "#10b981",
      accepted: "#3b82f6",
      false_positive: "#64748b",
    },
    accent: "#06b6d4",
    accentHover: "#22d3ee",
  },
};

const manualTemplates = [
  {
    id: "owasp-web-a01",
    group: "OWASP Web Top 10",
    title: "A01: Broken Access Control",
    owasp: "A01:2021",
    cwe: "CWE-284",
    severity: "high",
    description: "Controles de acceso insuficientes permiten acceder a recursos no autorizados.",
  },
  {
    id: "owasp-web-a02",
    group: "OWASP Web Top 10",
    title: "A02: Cryptographic Failures",
    owasp: "A02:2021",
    cwe: "CWE-319",
    severity: "high",
    description: "Datos sensibles expuestos por cifrado inadecuado o ausente.",
  },
  {
    id: "owasp-web-a03",
    group: "OWASP Web Top 10",
    title: "A03: Injection",
    owasp: "A03:2021",
    cwe: "CWE-89",
    severity: "critical",
    description: "Entradas no validadas permiten inyección de comandos o SQL.",
  },
  {
    id: "owasp-web-a05",
    group: "OWASP Web Top 10",
    title: "A05: Security Misconfiguration",
    owasp: "A05:2021",
    cwe: "CWE-16",
    severity: "medium",
    description: "Configuraciones inseguras o por defecto expuestas.",
  },
  {
    id: "owasp-web-a07",
    group: "OWASP Web Top 10",
    title: "A07: Identification and Authentication Failures",
    owasp: "A07:2021",
    cwe: "CWE-287",
    severity: "high",
    description: "Errores en autenticacion o sesiones.",
  },
  {
    id: "owasp-api-api1",
    group: "OWASP API Top 10",
    title: "API1: Broken Object Level Authorization",
    owasp: "API1:2023",
    cwe: "CWE-639",
    severity: "critical",
    description: "Acceso a objetos sin validar propiedad o permisos.",
  },
  {
    id: "owasp-api-api2",
    group: "OWASP API Top 10",
    title: "API2: Broken Authentication",
    owasp: "API2:2023",
    cwe: "CWE-287",
    severity: "high",
    description: "Autenticacion debil o mal implementada en APIs.",
  },
  {
    id: "owasp-api-api4",
    group: "OWASP API Top 10",
    title: "API4: Unrestricted Resource Consumption",
    owasp: "API4:2023",
    cwe: "CWE-400",
    severity: "medium",
    description: "Falta de limites en recursos o rate limit.",
  },
  {
    id: "cwe-79",
    group: "Top CWE",
    title: "XSS (CWE-79)",
    cwe: "CWE-79",
    severity: "high",
    description: "Entrada no sanitizada permite ejecucion de scripts.",
  },
  {
    id: "cwe-89",
    group: "Top CWE",
    title: "SQL Injection (CWE-89)",
    cwe: "CWE-89",
    severity: "critical",
    description: "Entrada controlada permite inyeccion SQL.",
  },
  {
    id: "cwe-287",
    group: "Top CWE",
    title: "Improper Authentication (CWE-287)",
    cwe: "CWE-287",
    severity: "high",
    description: "Autenticacion insuficiente o incorrecta.",
  },
  {
    id: "cwe-200",
    group: "Top CWE",
    title: "Information Exposure (CWE-200)",
    cwe: "CWE-200",
    severity: "medium",
    description: "Exposicion de informacion sensible.",
  },
];

const IMPORT_FIELDS = {
  title: { label: "Titulo *", required: true, group: "hallazgo" },
  severity: { label: "Severidad *", required: true, group: "hallazgo" },
  status: { label: "Estado", required: false, group: "hallazgo", default: "open" },
  description: { label: "Descripcion", required: false, group: "hallazgo" },
  cwe: { label: "CWE", required: false, group: "hallazgo" },
  owasp_category: { label: "OWASP", required: false, group: "hallazgo" },
  cvss_score: { label: "CVSS Score", required: false, group: "hallazgo" },
  occurrences: { label: "Ocurrencias", required: false, group: "hallazgo", default: 1 },
  tags: { label: "Tags", required: false, group: "hallazgo" },
  asset_name: { label: "Nombre del activo *", required: true, group: "activo" },
  asset_uri: { label: "URI del activo", required: false, group: "activo" },
  asset_type: { label: "Tipo de activo", required: false, group: "activo", default: "web_app" },
  owner_email: { label: "Responsable", required: false, group: "persona" },
  pentester_email: { label: "Pentester", required: false, group: "persona" },
};

const AUTO_MAP_ALIASES = {
  title: [
    "title",
    "titulo",
    "nombre",
    "name",
    "vulnerability",
    "vuln_name",
    "finding",
    "plugin_name",
    "issue_name",
    "advisory_name",
    "cve",
    "cve_id",
  ],
  severity: [
    "severity",
    "severidad",
    "risk",
    "riesgo",
    "risk_level",
    "criticidad",
    "level",
    "threat",
    "base_score_level",
  ],
  status: ["status", "estado", "state"],
  description: [
    "description",
    "descripcion",
    "desc",
    "details",
    "synopsis",
    "detalle",
    "issue_detail",
    "summary",
    "overview",
  ],
  cwe: ["cwe", "cwe_id", "cwe-id", "weakness", "cwe_name", "weakness_id"],
  owasp_category: ["owasp", "owasp_category", "owasp_top_10", "category", "categoria"],
  cvss_score: ["cvss", "cvss_score", "cvss_v3", "cvss3", "score", "cvss_base_score", "base_score", "cvss_base", "cvss_v3_score"],
  occurrences: ["occurrences", "ocurrencias", "count", "instances"],
  tags: ["tags", "etiquetas", "labels"],
  asset_name: ["asset", "asset_name", "activo", "host", "hostname", "target", "objetivo", "ip", "server"],
  asset_uri: ["uri", "url", "asset_uri", "endpoint", "address", "target_url", "ip_address"],
  asset_type: ["type", "asset_type", "tipo", "service"],
  owner_email: ["owner", "responsable", "owner_email", "assigned_to", "assignee"],
  pentester_email: ["pentester", "tester", "pentester_email", "reporter", "found_by"],
};

export default function App() {
  const [findings, setFindings] = useState([]);
  const [assets, setAssets] = useState([]);
  const [orgs, setOrgs] = useState([]);
  const [projects, setProjects] = useState([]);
  const [user, setUser] = useState(null);
  const [authLoading, setAuthLoading] = useState(true);
  const [requiresProfile, setRequiresProfile] = useState(false);
  const [userProfile, setUserProfile] = useState(null);
  const [userActivities, setUserActivities] = useState([]);
  const [notificationPrefs, setNotificationPrefs] = useState(null);
  const [forcePasswordMode, setForcePasswordMode] = useState(false);
  const [forcePasswordForm, setForcePasswordForm] = useState({
    email: "",
    current_password: "",
    new_password: "",
  });
  const [resetMode, setResetMode] = useState(false);
  const [resetEmail, setResetEmail] = useState("");
  const [resetToken, setResetToken] = useState("");
  const [resetNewPassword, setResetNewPassword] = useState("");
  const [resetStatus, setResetStatus] = useState("");
  const [error, setError] = useState("");
  const [severityFilter, setSeverityFilter] = useState("all");
  const [assetFilter, setAssetFilter] = useState("all");
  const [findingScanFilter, setFindingScanFilter] = useState("all");
  const [projectId, setProjectId] = useState(
    () => localStorage.getItem("vi_selectedProject") || ""
  );
  const [orgId, setOrgId] = useState(() => localStorage.getItem("vi_selectedOrg") || "");
  const [authMode, setAuthMode] = useState("login");
  const [authError, setAuthError] = useState("");
  const [authForm, setAuthForm] = useState({ email: "", password: "", organization: "" });
  const [newProjectName, setNewProjectName] = useState("");
  const [selectedUserId, setSelectedUserId] = useState("");
  const [users, setUsers] = useState([]);
  const [newMemberRole, setNewMemberRole] = useState("member");
  const [members, setMembers] = useState([]);
  const [inviteEmail, setInviteEmail] = useState("");
  const [inviteRole, setInviteRole] = useState("member");
  const [invites, setInvites] = useState([]);
  const [scans, setScans] = useState([]);
  const [selectedScan, setSelectedScan] = useState(null);
  const [scanLogs, setScanLogs] = useState([]);
  const [inviteToken, setInviteToken] = useState("");
  const [auditLogs, setAuditLogs] = useState([]);
  const [auditFilters, setAuditFilters] = useState({
    user: "",
    action: "all",
    from: "",
    to: "",
    search: "",
  });
  const [selectedAudit, setSelectedAudit] = useState(null);
  const [newClientName, setNewClientName] = useState("");
  const [inviteAcceptStatus, setInviteAcceptStatus] = useState("");
  const [inviteInfo, setInviteInfo] = useState(null);
  const [memberFilters, setMemberFilters] = useState({ role: "all", search: "" });
  const [inviteFilters, setInviteFilters] = useState({ search: "", showDisabled: false });
  const [showUserModal, setShowUserModal] = useState(false);
  const [userModalTab, setUserModalTab] = useState("existing");
  const [usersTab, setUsersTab] = useState("members");
  const [selectedAsset, setSelectedAsset] = useState(null);
  const [selectedFinding, setSelectedFinding] = useState(null);
  const [selectedFindingStatus, setSelectedFindingStatus] = useState("open");
  const [selectedFindingAssignee, setSelectedFindingAssignee] = useState("");
  const [findingComments, setFindingComments] = useState([]);
  const [newFindingComment, setNewFindingComment] = useState("");
  const [showFindingModal, setShowFindingModal] = useState(false);
  const [showExportMenu, setShowExportMenu] = useState(false);
  const [showImportWizard, setShowImportWizard] = useState(false);
  const [importStep, setImportStep] = useState(1);
  const [importFile, setImportFile] = useState(null);
  const [importFormat, setImportFormat] = useState("auto");
  const [importRawData, setImportRawData] = useState([]);
  const [importColumnMap, setImportColumnMap] = useState({});
  const [importPreview, setImportPreview] = useState({ assets: [], findings: [] });
  const [importResult, setImportResult] = useState(null);
  const [importLoading, setImportLoading] = useState(false);
  const [importErrors, setImportErrors] = useState([]);
  const [importDefaultAssetId, setImportDefaultAssetId] = useState("");
  const [showCatalogModal, setShowCatalogModal] = useState(false);
  const [catalogTab, setCatalogTab] = useState("explore");
  const [vulnSearchQuery, setVulnSearchQuery] = useState("");
  const [vulnSearchResults, setVulnSearchResults] = useState([]);
  const [vulnSearchLoading, setVulnSearchLoading] = useState(false);
  const [showVulnDropdown, setShowVulnDropdown] = useState(false);
  const [selectedCatalogEntry, setSelectedCatalogEntry] = useState(null);
  const [catalogQuery, setCatalogQuery] = useState("");
  const [catalogResults, setCatalogResults] = useState([]);
  const [catalogLoading, setCatalogLoading] = useState(false);
  const [catalogStats, setCatalogStats] = useState(null);
  const [catalogDetail, setCatalogDetail] = useState(null);
  const [catalogImportFile, setCatalogImportFile] = useState(null);
  const [catalogImportLoading, setCatalogImportLoading] = useState(false);
  const [catalogImportResult, setCatalogImportResult] = useState(null);
  const [catalogImportError, setCatalogImportError] = useState("");
  const [catalogTemplateForm, setCatalogTemplateForm] = useState({
    name: "",
    cve_id: "",
    severity: "medium",
    base_score: "",
    cvss_vector: "",
    cwe_id: "",
    cwe_name: "",
    description: "",
    recommendation: "",
    references: "",
    exploit_available: false,
  });
  const [findingModalTab, setFindingModalTab] = useState("manual");
  const [findingTemplateQuery, setFindingTemplateQuery] = useState("");
  const [customTemplates, setCustomTemplates] = useState([]);
  const [templateForm, setTemplateForm] = useState({
    title: "",
    severity: "medium",
    cwe: "",
    owasp: "",
    description: "",
  });
  const [manualFindingForm, setManualFindingForm] = useState({
    asset_id: "",
    title: "",
    severity: "medium",
    status: "open",
    cwe: "",
    owasp: "",
    description: "",
    recommendation: "",
    references: "",
    rule_id: "manual",
    assignee_user_id: "",
  });
  const [activeSection, setActiveSection] = useState("dashboard");
  const [showFullLogs, setShowFullLogs] = useState(false);
  const [showAllAudit, setShowAllAudit] = useState(false);
  const [findingSearch, setFindingSearch] = useState("");
  const [ownerFilter, setOwnerFilter] = useState("all");
  const [assetSearch, setAssetSearch] = useState("");
  const [assetTypeFilter, setAssetTypeFilter] = useState("all");
  const [assetEnvFilter, setAssetEnvFilter] = useState("all");
  const [assetCritFilter, setAssetCritFilter] = useState("all");
  const [showAssetModal, setShowAssetModal] = useState(false);
  const [assetEditTarget, setAssetEditTarget] = useState(null);
  const [showScanWizard, setShowScanWizard] = useState(false);
  const [wizardStep, setWizardStep] = useState(1);
  const [dashboardFilters, setDashboardFilters] = useState({
    asset: "all",
    owner: "all",
    severity: "all",
    status: "all",
    tool: "all",
    vuln: "",
  });
  const [dashboardFiltersOpen, setDashboardFiltersOpen] = useState(true);
  const [trendGranularity, setTrendGranularity] = useState("month");
  const [assetForm, setAssetForm] = useState({ ...EMPTY_ASSET_FORM });
  const [scanForm, setScanForm] = useState({
    assetId: "",
    tool: "vulnapi",
    targetUrl: "",
    targetPath: "",
    reportPath: "/tmp/report.json",
  });
  const [scanFilters, setScanFilters] = useState({ tool: "all", status: "all", search: "" });
  const [showAllScans, setShowAllScans] = useState(false);
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [sidebarMobileOpen, setSidebarMobileOpen] = useState(false);
  const [expandedClients, setExpandedClients] = useState({});
  const [showNewClientModal, setShowNewClientModal] = useState(false);
  const [showNewProjectModal, setShowNewProjectModal] = useState(false);
  const [showIdleWarning, setShowIdleWarning] = useState(false);
  const idleWarningRef = useRef(false);
  const idleWarningTimeoutRef = useRef(null);
  const idleLogoutTimeoutRef = useRef(null);
  const isAuthenticated = Boolean(user);

  function performLogout({ confirm = true } = {}) {
    if (confirm && !window.confirm("¿Cerrar sesión ahora?")) {
      return;
    }
    authFetch(`${API_BASE}/auth/logout`, { method: "POST" }).catch(() => {});
    localStorage.removeItem("vi_selectedOrg");
    localStorage.removeItem("vi_selectedProject");
    setUser(null);
    setRequiresProfile(false);
    setUserProfile(null);
    setForcePasswordMode(false);
    setForcePasswordForm({ email: "", current_password: "", new_password: "" });
    setResetMode(false);
    setResetEmail("");
    setResetToken("");
    setResetNewPassword("");
    setResetStatus("");
    setAuthForm({ email: "", password: "", organization: "" });
    setProjectId("");
    setOrgId("");
    setFindings([]);
    setAssets([]);
    setProjects([]);
    setMembers([]);
    setInvites([]);
    setScans([]);
    setScanLogs([]);
    setSelectedScan(null);
    setSelectedAsset(null);
    setSelectedFinding(null);
    setAuditLogs([]);
    setSelectedAudit(null);
  }

  function handleLogout() {
    performLogout({ confirm: true });
  }

  function handleIdleLogout() {
    performLogout({ confirm: false });
  }

  const resetIdleTimers = useCallback(() => {
    clearTimeout(idleWarningTimeoutRef.current);
    clearTimeout(idleLogoutTimeoutRef.current);
    idleWarningTimeoutRef.current = setTimeout(() => {
      setShowIdleWarning(true);
    }, 13 * 60 * 1000);
    idleLogoutTimeoutRef.current = setTimeout(() => {
      handleIdleLogout();
    }, 15 * 60 * 1000);
  }, []);

  function toggleClientExpanded(orgIdValue) {
    setExpandedClients((prev) => ({ ...prev, [orgIdValue]: !prev[orgIdValue] }));
  }

  useEffect(() => {
    let cancelled = false;
    async function checkAuth() {
      try {
        const response = await authFetch(`${API_BASE}/auth/me`);
        if (!cancelled && response.ok) {
          const data = await response.json();
          setUser(data);
          setRequiresProfile(Boolean(data.profile_completed === false));
        } else if (!cancelled) {
          setUser(null);
        }
      } catch (err) {
        if (!cancelled) {
          setUser(null);
        }
      } finally {
        if (!cancelled) {
          setAuthLoading(false);
        }
      }
    }
    checkAuth();
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    idleWarningRef.current = showIdleWarning;
  }, [showIdleWarning]);

  useEffect(() => {
    if (!isAuthenticated) {
      return undefined;
    }
    resetIdleTimers();
    const events = ["mousemove", "mousedown", "keydown", "scroll", "touchstart"];
    const resetTimer = () => {
      if (idleWarningRef.current) {
        return;
      }
      resetIdleTimers();
    };
    events.forEach((eventName) => {
      window.addEventListener(eventName, resetTimer, { passive: true });
    });
    const handleVisibility = () => {
      if (document.visibilityState === "visible") {
        resetTimer();
      }
    };
    document.addEventListener("visibilitychange", handleVisibility);
    return () => {
      clearTimeout(idleWarningTimeoutRef.current);
      clearTimeout(idleLogoutTimeoutRef.current);
      events.forEach((eventName) => {
        window.removeEventListener(eventName, resetTimer);
      });
      document.removeEventListener("visibilitychange", handleVisibility);
    };
  }, [isAuthenticated, resetIdleTimers]);

  useEffect(() => {
    let cancelled = false;

    async function loadProfile() {
      if (!isAuthenticated) {
        setRequiresProfile(false);
        setUserProfile(null);
        setUserActivities([]);
        setNotificationPrefs(null);
        return;
      }
      try {
        const response = await authFetch(`${API_BASE}/users/me`, {
          headers: authHeaders(),
        });
        if (!response.ok) {
          return;
        }
        const data = await response.json();
        if (!cancelled) {
          setRequiresProfile(!data.profile_completed);
          setUserProfile(data);
        }
      } catch (err) {
        if (!cancelled) {
          setError(err.message || "No se pudo cargar el perfil");
        }
      }
    }

    loadProfile();
    return () => {
      cancelled = true;
    };
  }, [isAuthenticated]);

  useEffect(() => {
    let cancelled = false;

    async function loadUserExtras() {
      if (!isAuthenticated) {
        return;
      }
      try {
        const [activitiesResponse, prefsResponse] = await Promise.all([
          authFetch(`${API_BASE}/users/me/activities?limit=10`, { headers: authHeaders() }),
          authFetch(`${API_BASE}/users/me/notifications`, { headers: authHeaders() }),
        ]);
        if (activitiesResponse.ok) {
          const data = await activitiesResponse.json();
          if (!cancelled) {
            setUserActivities(data);
          }
        }
        if (prefsResponse.ok) {
          const data = await prefsResponse.json();
          if (!cancelled) {
            setNotificationPrefs(data);
          }
        }
      } catch (err) {
        if (!cancelled) {
          setError(err.message || "No se pudieron cargar los datos de usuario");
        }
      }
    }

    loadUserExtras();
    return () => {
      cancelled = true;
    };
  }, [isAuthenticated]);

  useEffect(() => {
    if (requiresProfile) {
      setActiveSection("perfil");
    }
  }, [requiresProfile]);

  useEffect(() => {
    if (orgId) {
      localStorage.setItem("vi_selectedOrg", orgId);
    } else {
      localStorage.removeItem("vi_selectedOrg");
    }
    if (projectId) {
      localStorage.setItem("vi_selectedProject", projectId);
    } else {
      localStorage.removeItem("vi_selectedProject");
    }
  }, [orgId, projectId]);

  useEffect(() => {
    if (orgId) {
      setExpandedClients((prev) => ({ ...prev, [orgId]: true }));
    }
  }, [orgId]);

  useEffect(() => {
    if (!orgId) {
      setProjects([]);
      setProjectId("");
    }
  }, [orgId]);

  useEffect(() => {
    if (!projectId) {
      setFindings([]);
      setAssets([]);
      setScans([]);
    }
  }, [projectId]);

  useEffect(() => {
    if (selectedFinding?.status) {
      setSelectedFindingStatus(selectedFinding.status);
    }
    if (selectedFinding?.assignee_user_id) {
      setSelectedFindingAssignee(String(selectedFinding.assignee_user_id));
    } else {
      setSelectedFindingAssignee("");
    }
  }, [selectedFinding]);

  useEffect(() => {
    if (!scanForm.assetId && assets.length > 0) {
      setScanForm((prev) => ({ ...prev, assetId: String(assets[0].id) }));
    }
  }, [assets, scanForm.assetId]);

  const assetTypeLabels = {
    web_app: "web",
    api: "api",
    repo: "repo",
    host: "host",
    container: "contenedor",
    network_range: "rango",
  };
  const scanToolOptions = [
    { value: "vulnapi", label: "VulnAPI", types: ["web_app", "api"] },
    { value: "wapiti", label: "Wapiti", types: ["web_app"] },
    { value: "nuclei", label: "Nuclei", types: ["web_app", "api"] },
    { value: "osv", label: "OSV", types: ["repo"] },
    { value: "sarif", label: "SARIF", types: ["repo"] },
  ];
  const profileView = useMemo(() => {
    if (!userProfile) {
      return null;
    }
    return {
      name: userProfile.full_name || "Usuario",
      email: userProfile.email,
      phone: userProfile.phone || "",
      position: userProfile.title || "",
      role: "Analista",
      avatar: null,
      activityLog: userActivities.map((item) => ({
        action: item.action,
        timestamp: item.created_at,
        ip: item.ip,
      })),
      notifications:
        notificationPrefs || {
          criticalVulns: true,
          assignedVulns: true,
          statusUpdates: false,
          reports: true,
          systemAlerts: true,
          channel: "email",
        },
    };
  }, [notificationPrefs, userActivities, userProfile]);
  const selectedScanAsset = useMemo(
    () => assets.find((asset) => String(asset.id) === scanForm.assetId) || null,
    [assets, scanForm.assetId],
  );
  const allowedScanTools = useMemo(() => {
    if (!selectedScanAsset) {
      return new Set();
    }
    return new Set(
      scanToolOptions
        .filter((option) => option.types.includes(selectedScanAsset.type))
        .map((option) => option.value),
    );
  }, [scanToolOptions, selectedScanAsset]);

  useEffect(() => {
    if (!selectedScanAsset) {
      return;
    }
    if (!allowedScanTools.has(scanForm.tool)) {
      const fallback = scanToolOptions.find((option) =>
        option.types.includes(selectedScanAsset.type),
      );
      setScanForm((prev) => ({ ...prev, tool: fallback ? fallback.value : "vulnapi" }));
    }
  }, [allowedScanTools, scanForm.tool, scanToolOptions, selectedScanAsset]);

  useEffect(() => {
    let cancelled = false;

    async function load() {
      try {
        if (!isAuthenticated || !projectId || requiresProfile) {
          return;
        }
        const findingsResponse = await authFetch(`${API_BASE}/findings?project_id=${projectId}`, {
          headers: authHeaders(),
        });
        const assetsResponse = await authFetch(`${API_BASE}/assets?project_id=${projectId}`, {
          headers: authHeaders(),
        });
        if (!findingsResponse.ok || !assetsResponse.ok) {
          throw new Error("API no disponible");
        }
        const findingsData = await findingsResponse.json();
        const assetsData = await assetsResponse.json();
        if (!cancelled) {
          setFindings(unwrapItems(findingsData));
          setAssets(unwrapItems(assetsData));
        }
      } catch (err) {
        if (!cancelled) {
          setError(err.message || "No se pudieron cargar los datos");
        }
      }
    }

    load();
    return () => {
      cancelled = true;
    };
  }, [projectId, isAuthenticated, requiresProfile]);

  useEffect(() => {
    let cancelled = false;
    async function loadFindingComments() {
      if (!selectedFinding || !isAuthenticated) {
        return;
      }
      try {
        const response = await authFetch(
          `${API_BASE}/findings/${selectedFinding.id}/comments`,
          { headers: authHeaders() }
        );
        if (!response.ok) {
          throw new Error("No se pudieron cargar los comentarios");
        }
        const data = await response.json();
        if (!cancelled) {
          setFindingComments(data);
        }
      } catch (err) {
        if (!cancelled) {
          setError(err.message || "No se pudieron cargar los comentarios");
        }
      }
    }
    loadFindingComments();
    return () => {
      cancelled = true;
    };
  }, [selectedFinding, isAuthenticated]);

  useEffect(() => {
    let cancelled = false;
    async function loadTemplates() {
      if (!orgId || !isAuthenticated) {
        return;
      }
      try {
        const response = await authFetch(`${API_BASE}/templates?org_id=${orgId}`, {
          headers: authHeaders(),
        });
        if (!response.ok) {
          return;
        }
        const data = await response.json();
        if (!cancelled) {
          setCustomTemplates(data);
        }
      } catch (err) {
        if (!cancelled) {
          setError(err.message || "No se pudieron cargar las plantillas");
        }
      }
    }
    loadTemplates();
    return () => {
      cancelled = true;
    };
  }, [orgId, isAuthenticated]);

  useEffect(() => {
    let cancelled = false;

    async function loadUsers() {
      if (!orgId || !isAuthenticated) {
        return;
      }
      try {
        const response = await authFetch(`${API_BASE}/users?org_id=${orgId}`, {
          headers: authHeaders(),
        });
        if (!response.ok) {
          const errorPayload = await response.json().catch(() => ({}));
          setError(errorPayload.detail || "No se pudieron cargar los usuarios");
          if (!cancelled) {
            setUsers([]);
          }
          return;
        }
        const data = await response.json();
        if (!cancelled) {
          setUsers(data);
        }
      } catch (err) {
        if (!cancelled) {
          setError(err.message || "No se pudieron cargar los usuarios");
        }
      }
    }

    loadUsers();
    return () => {
      cancelled = true;
    };
  }, [orgId, isAuthenticated]);

  const assetMap = useMemo(() => new Map(assets.map((asset) => [asset.id, asset])), [assets]);
  const scanToolMap = useMemo(() => new Map(scans.map((scan) => [scan.id, scan.tool])), [scans]);
  const groupedFindings = useMemo(() => {
    return groupFindings(findings).sort((a, b) => {
      const rankDiff = (severityRank[a.severity] ?? 99) - (severityRank[b.severity] ?? 99);
      if (rankDiff !== 0) {
        return rankDiff;
      }
      return b.occurrences - a.occurrences;
    });
  }, [findings]);
  const filteredMembers = useMemo(() => {
    const search = memberFilters.search.trim().toLowerCase();
    return members.filter((member) => {
      if (memberFilters.role !== "all" && member.role !== memberFilters.role) {
        return false;
      }
      if (!search) {
        return true;
      }
      return member.email.toLowerCase().includes(search);
    });
  }, [members, memberFilters]);

  const filteredInvites = useMemo(() => {
    const search = inviteFilters.search.trim().toLowerCase();
    return invites.filter((invite) => {
      if (!inviteFilters.showDisabled && invite.disabled) {
        return false;
      }
      if (!search) {
        return true;
      }
      return invite.email.toLowerCase().includes(search);
    });
  }, [invites, inviteFilters]);

  const availableUsers = useMemo(() => {
    const memberEmails = new Set(members.map((member) => member.email));
    return users.filter((user) => !memberEmails.has(user.email));
  }, [users, members]);

  useEffect(() => {
    if (!selectedUserId && availableUsers.length > 0) {
      setSelectedUserId(String(availableUsers[0].id));
    }
  }, [availableUsers, selectedUserId]);
  const dashboardFindings = useMemo(() => {
    const query = dashboardFilters.vuln.trim().toLowerCase();
    return findings.filter((finding) => {
      if (dashboardFilters.asset !== "all" && String(finding.asset_id) !== dashboardFilters.asset) {
        return false;
      }
      if (dashboardFilters.owner !== "all") {
        const owner = assetMap.get(finding.asset_id)?.owner_email || "";
        if (owner !== dashboardFilters.owner) {
          return false;
        }
      }
      if (dashboardFilters.severity !== "all" && finding.severity !== dashboardFilters.severity) {
        return false;
      }
      if (dashboardFilters.status !== "all" && finding.status !== dashboardFilters.status) {
        return false;
      }
      if (dashboardFilters.tool !== "all") {
        const tool = scanToolMap.get(finding.scan_id) || "";
        if (tool !== dashboardFilters.tool) {
          return false;
        }
      }
      if (query) {
        const haystack = [
          finding.title,
          finding.cwe,
          finding.owasp,
          finding.rule_id,
        ]
          .filter(Boolean)
          .join(" ")
          .toLowerCase();
        if (!haystack.includes(query)) {
          return false;
        }
      }
      return true;
    });
  }, [findings, dashboardFilters, assetMap, scanToolMap]);

  const dashboardGroupedFindings = useMemo(
    () => groupFindings(dashboardFindings),
    [dashboardFindings],
  );

  const dashboardSeverityCounts = useMemo(
    () => summarizeBySeverity(dashboardGroupedFindings),
    [dashboardGroupedFindings],
  );
  const statusCounts = useMemo(() => {
    const counts = { open: 0, triaged: 0, accepted: 0, fixed: 0, false_positive: 0 };
    dashboardFindings.forEach((finding) => {
      const key = finding.status || "open";
      if (counts[key] === undefined) {
        counts[key] = 0;
      }
      counts[key] += 1;
    });
    return counts;
  }, [dashboardFindings]);
  const assetTypeCounts = useMemo(() => {
    const trackedAssets = new Set(dashboardFindings.map((finding) => finding.asset_id));
    const counts = {};
    assets.forEach((asset) => {
      if (trackedAssets.size > 0 && !trackedAssets.has(asset.id)) {
        return;
      }
      counts[asset.type] = (counts[asset.type] || 0) + 1;
    });
    return counts;
  }, [assets, dashboardFindings]);
  const scanToolCounts = useMemo(() => {
    const counts = {};
    const scanIds = new Set(dashboardFindings.map((finding) => finding.scan_id).filter(Boolean));
    scans.forEach((scan) => {
      if (scanIds.size > 0 && !scanIds.has(scan.id)) {
        return;
      }
      counts[scan.tool] = (counts[scan.tool] || 0) + 1;
    });
    return counts;
  }, [scans, dashboardFindings]);
  const activeDashboardFilterCount = useMemo(() => {
    let count = 0;
    if (dashboardFilters.asset !== "all") {
      count += 1;
    }
    if (dashboardFilters.owner !== "all") {
      count += 1;
    }
    if (dashboardFilters.severity !== "all") {
      count += 1;
    }
    if (dashboardFilters.status !== "all") {
      count += 1;
    }
    if (dashboardFilters.tool !== "all") {
      count += 1;
    }
    if (dashboardFilters.vuln.trim()) {
      count += 1;
    }
    return count;
  }, [dashboardFilters]);
  const topAssets = useMemo(() => {
    const counts = new Map();
    const maxSeverities = new Map();
    dashboardFindings.forEach((finding) => {
      counts.set(finding.asset_id, (counts.get(finding.asset_id) || 0) + 1);
      const current = maxSeverities.get(finding.asset_id);
      const severity = finding.severity || "info";
      if (!current || severityRank[severity] < severityRank[current]) {
        maxSeverities.set(finding.asset_id, severity);
      }
    });
    return Array.from(counts.entries())
      .map(([assetId, total]) => ({
        assetId,
        total,
        name: assetMap.get(assetId)?.name || `Activo ${assetId}`,
        owner: assetMap.get(assetId)?.owner_email || "-",
        maxSeverity: maxSeverities.get(assetId) || "info",
      }))
      .sort((a, b) => b.total - a.total)
      .slice(0, 5);
  }, [dashboardFindings, assetMap]);
  const severityChartData = useMemo(() => {
    return Object.entries(dashboardSeverityCounts)
      .filter(([, value]) => value > 0)
      .map(([key, value]) => ({
        name: severityLabels[key] || key,
        value,
        key,
      }));
  }, [dashboardSeverityCounts]);
  const statusChartData = useMemo(() => {
    return Object.entries(statusCounts)
      .filter(([, value]) => value > 0)
      .map(([key, value]) => ({
        name: statusLabels[key] || key,
        value,
        key,
      }));
  }, [statusCounts]);
  const toolChartData = useMemo(() => {
    return Object.entries(scanToolCounts).map(([key, value]) => ({
      name: key,
      count: value,
    }));
  }, [scanToolCounts]);
  const trendData = useMemo(() => {
    const grouped = {};
    const monthNames = ["Ene", "Feb", "Mar", "Abr", "May", "Jun", "Jul", "Ago", "Sep", "Oct", "Nov", "Dic"];
    const getWeekKey = (date) => {
      const temp = new Date(Date.UTC(date.getFullYear(), date.getMonth(), date.getDate()));
      const day = temp.getUTCDay() || 7;
      temp.setUTCDate(temp.getUTCDate() + 4 - day);
      const yearStart = new Date(Date.UTC(temp.getUTCFullYear(), 0, 1));
      const week = Math.ceil(((temp - yearStart) / 86400000 + 1) / 7);
      return `${temp.getUTCFullYear()}-W${String(week).padStart(2, "0")}`;
    };

    dashboardGroupedFindings.forEach((finding) => {
      if (!finding.created_at) {
        return;
      }
      const date = new Date(finding.created_at);
      if (Number.isNaN(date.getTime())) {
        return;
      }
      let key = "";
      if (trendGranularity === "day") {
        key = `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, "0")}-${String(date.getDate()).padStart(2, "0")}`;
      } else if (trendGranularity === "week") {
        key = getWeekKey(date);
      } else {
        key = `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, "0")}`;
      }
      grouped[key] = (grouped[key] || 0) + 1;
    });

    return Object.entries(grouped)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([key, count]) => {
        if (trendGranularity === "day") {
          const [year, month, day] = key.split("-");
          return {
            name: `${day}/${month}`,
            hallazgos: count,
          };
        }
        if (trendGranularity === "week") {
          const [year, week] = key.split("-W");
          return {
            name: `Sem ${week} ${year.slice(2)}`,
            hallazgos: count,
          };
        }
        const [year, monthNumber] = key.split("-");
        return {
          name: `${monthNames[Number(monthNumber) - 1]} ${year.slice(2)}`,
          hallazgos: count,
        };
      });
  }, [dashboardGroupedFindings, trendGranularity]);
  const heatmapData = useMemo(() => {
    const matrix = {};
    dashboardGroupedFindings.forEach((finding) => {
      const assetName = assetMap.get(finding.asset_id)?.name || `Activo ${finding.asset_id}`;
      if (!matrix[assetName]) {
        matrix[assetName] = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
      }
      const severity = finding.severity || "info";
      matrix[assetName][severity] = (matrix[assetName][severity] || 0) + 1;
    });
    return Object.entries(matrix).map(([asset, severities]) => ({
      asset,
      ...severities,
    }));
  }, [dashboardGroupedFindings, assetMap]);
  const totalSeverityFindings = useMemo(() => {
    return severityChartData.reduce((sum, item) => sum + item.value, 0);
  }, [severityChartData]);
  const totalStatusFindings = useMemo(() => {
    return statusChartData.reduce((sum, item) => sum + item.value, 0);
  }, [statusChartData]);
  const filteredFindings = useMemo(() => {
    return groupedFindings.filter((finding) => {
      if (severityFilter !== "all" && finding.severity !== severityFilter) {
        return false;
      }
      if (assetFilter !== "all" && String(finding.asset_id) !== assetFilter) {
        return false;
      }
      if (findingScanFilter !== "all") {
        const scanId = Number(findingScanFilter);
        if (!finding.scan_ids?.includes(scanId)) {
          return false;
        }
      }
      if (ownerFilter !== "all") {
        const owner = assetMap.get(finding.asset_id)?.owner_email || "";
        if (owner !== ownerFilter) {
          return false;
        }
      }
      if (findingSearch) {
        const query = findingSearch.toLowerCase();
        const haystack = [
          finding.title,
          finding.rule_id,
          finding.owasp,
          finding.cwe,
          assetMap.get(finding.asset_id)?.name,
          assetMap.get(finding.asset_id)?.owner_email,
        ]
          .filter(Boolean)
          .join(" ")
          .toLowerCase();
        if (!haystack.includes(query)) {
          return false;
        }
      }
      return true;
    });
  }, [groupedFindings, severityFilter, assetFilter, findingScanFilter, ownerFilter, findingSearch, assetMap]);

  const allTemplates = useMemo(() => {
    return [
      ...manualTemplates,
      ...customTemplates.map((item) => ({ ...item, group: "Personalizadas" })),
    ];
  }, [customTemplates]);

  const filteredTemplates = useMemo(() => {
    const query = findingTemplateQuery.trim().toLowerCase();
    if (!query) {
      return allTemplates;
    }
    return allTemplates.filter((template) => {
      return [
        template.title,
        template.cwe,
        template.owasp,
        template.group,
      ]
        .filter(Boolean)
        .join(" ")
        .toLowerCase()
        .includes(query);
    });
  }, [findingTemplateQuery, allTemplates]);

  const filteredAssets = useMemo(() => {
    const query = assetSearch.trim().toLowerCase();
    return assets.filter((asset) => {
      if (assetTypeFilter !== "all" && asset.type !== assetTypeFilter) {
        return false;
      }
      if (assetEnvFilter !== "all" && asset.environment !== assetEnvFilter) {
        return false;
      }
      if (assetCritFilter !== "all" && asset.criticality !== assetCritFilter) {
        return false;
      }
      if (!query) {
        return true;
      }
      const tags = Array.isArray(asset.tags) ? asset.tags : [];
      const haystack = [
        asset.name,
        asset.uri,
        asset.owner_email,
        asset.environment,
        asset.criticality,
        asset.type,
        ...tags,
      ]
        .filter(Boolean)
        .join(" ")
        .toLowerCase();
      return haystack.includes(query);
    });
  }, [assets, assetSearch, assetTypeFilter, assetEnvFilter, assetCritFilter]);

  useEffect(() => {
    let cancelled = false;

    async function loadOrgs() {
      if (!isAuthenticated || requiresProfile) {
        return;
      }
      try {
        const response = await authFetch(`${API_BASE}/orgs`, { headers: authHeaders() });
        if (!response.ok) {
          return;
        }
        const data = await response.json();
        if (!cancelled) {
          setOrgs(data);
          if (orgId && !data.some((org) => String(org.id) === String(orgId))) {
            setOrgId("");
            setProjectId("");
          }
        }
      } catch (err) {
        if (!cancelled) {
          setError(err.message || "No se pudieron cargar los clientes");
        }
      }
    }

    loadOrgs();
    return () => {
      cancelled = true;
    };
  }, [orgId, isAuthenticated, requiresProfile]);

  useEffect(() => {
    let cancelled = false;

    async function loadProjects() {
      if (!isAuthenticated || requiresProfile) {
        return;
      }
      if (!orgs.length) {
        setProjects([]);
        return;
      }
      try {
        const responses = await Promise.all(
          orgs.map((org) =>
            authFetch(`${API_BASE}/orgs/${org.id}/projects`, { headers: authHeaders() })
          )
        );
        const payloads = await Promise.all(
          responses.map(async (response) => (response.ok ? response.json() : []))
        );
        if (!cancelled) {
          const merged = payloads.flat();
          setProjects(merged);
          if (projectId && !merged.some((project) => String(project.id) === String(projectId))) {
            setProjectId("");
          }
        }
      } catch (err) {
        if (!cancelled) {
          setError(err.message || "No se pudieron cargar los proyectos");
        }
      }
    }

    loadProjects();
    return () => {
      cancelled = true;
    };
  }, [orgs, projectId, isAuthenticated, requiresProfile]);

  useEffect(() => {
    const handle = setTimeout(() => {
      if (!isAuthenticated) {
        return;
      }
      fetchVulnSearch(vulnSearchQuery, setVulnSearchResults, setVulnSearchLoading);
    }, 300);
    return () => clearTimeout(handle);
  }, [vulnSearchQuery, isAuthenticated]);

  useEffect(() => {
    const handle = setTimeout(() => {
      if (!isAuthenticated || !showCatalogModal) {
        return;
      }
      fetchVulnSearch(catalogQuery, setCatalogResults, setCatalogLoading);
    }, 300);
    return () => clearTimeout(handle);
  }, [catalogQuery, showCatalogModal, isAuthenticated]);

  useEffect(() => {
    if (!showCatalogModal || !isAuthenticated) {
      return;
    }
    loadCatalogStats();
  }, [showCatalogModal, isAuthenticated]);

  useEffect(() => {
    let cancelled = false;

    async function loadScans() {
      if (!isAuthenticated || !projectId || requiresProfile) {
        return;
      }
      try {
        const response = await authFetch(`${API_BASE}/scans?project_id=${projectId}`, {
          headers: authHeaders(),
        });
        if (!response.ok) {
          return;
        }
        const data = await response.json();
        if (!cancelled) {
          setScans(unwrapItems(data));
        }
      } catch (err) {
        if (!cancelled) {
          setError(err.message || "No se pudieron cargar los escaneos");
        }
      }
    }

    loadScans();
    return () => {
      cancelled = true;
    };
  }, [projectId, isAuthenticated, requiresProfile]);

  useEffect(() => {
    if (!isAuthenticated || !projectId || requiresProfile) {
      return undefined;
    }
    const hasRunning = scans.some((scan) => scan.status === "running" || scan.status === "queued");
    if (!hasRunning) {
      return undefined;
    }
    let cancelled = false;
    const interval = setInterval(async () => {
      try {
        const response = await authFetch(`${API_BASE}/scans?project_id=${projectId}`, {
          headers: authHeaders(),
        });
        if (!response.ok) {
          return;
        }
        const data = await response.json();
        if (!cancelled) {
          setScans(unwrapItems(data));
        }
      } catch (err) {
        if (!cancelled) {
          setError(err.message || "No se pudieron actualizar los escaneos");
        }
      }
    }, 5000);
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, [scans, isAuthenticated, projectId, requiresProfile]);

  useEffect(() => {
    let cancelled = false;

    async function loadLogs() {
      if (!isAuthenticated || !selectedScan || requiresProfile) {
        setScanLogs([]);
        return;
      }
      try {
        const response = await authFetch(`${API_BASE}/scans/${selectedScan}/logs`, {
          headers: authHeaders(),
        });
        if (!response.ok) {
          return;
        }
        const data = await response.json();
        if (!cancelled) {
          setScanLogs(data);
        }
      } catch (err) {
        if (!cancelled) {
          setError(err.message || "No se pudieron cargar los logs del escaneo");
        }
      }
    }

    loadLogs();
    return () => {
      cancelled = true;
    };
  }, [selectedScan, isAuthenticated, requiresProfile]);

  useEffect(() => {
    let cancelled = false;

    async function loadAuditLogs() {
      if (!isAuthenticated || requiresProfile) {
        return;
      }
      try {
        const response = await authFetch(`${API_BASE}/audit-logs`, {
          headers: authHeaders(),
        });
        if (!response.ok) {
          return;
        }
        const data = await response.json();
        if (!cancelled) {
          setAuditLogs(unwrapItems(data));
        }
      } catch (err) {
        if (!cancelled) {
          setError(err.message || "No se pudieron cargar los logs de auditoría");
        }
      }
    }

    loadAuditLogs();
    return () => {
      cancelled = true;
    };
  }, [isAuthenticated, requiresProfile]);

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const invite = params.get("invite");
    if (invite) {
      setInviteToken(invite);
    }
  }, []);

  useEffect(() => {
    let cancelled = false;

    async function loadInviteInfo() {
      if (!inviteToken) {
        setInviteInfo(null);
        return;
      }
      try {
        const response = await authFetch(`${API_BASE}/invites/${inviteToken}`);
        if (!response.ok) {
          return;
        }
        const data = await response.json();
        if (!cancelled) {
          setInviteInfo(data);
        }
      } catch (err) {
        if (!cancelled) {
          setError(err.message || "No se pudo cargar la invitación");
        }
      }
    }

    loadInviteInfo();
    return () => {
      cancelled = true;
    };
  }, [inviteToken]);

  useEffect(() => {
    let cancelled = false;

    async function loadMembers() {
      if (!isAuthenticated || !orgId || requiresProfile) {
        return;
      }
      try {
        const response = await authFetch(`${API_BASE}/orgs/${orgId}/members`, {
          headers: authHeaders(),
        });
        if (!response.ok) {
          return;
        }
        const data = await response.json();
        if (!cancelled) {
          setMembers(unwrapItems(data));
        }
      } catch (err) {
        if (!cancelled) {
          setError(err.message || "No se pudieron cargar los miembros");
        }
      }
    }

    loadMembers();
    return () => {
      cancelled = true;
    };
  }, [orgId, isAuthenticated, requiresProfile]);

  useEffect(() => {
    let cancelled = false;

    async function loadInvites() {
      if (!isAuthenticated || !orgId || requiresProfile) {
        return;
      }
      try {
        const response = await authFetch(`${API_BASE}/orgs/${orgId}/invites`, {
          headers: authHeaders(),
        });
        if (!response.ok) {
          return;
        }
        const data = await response.json();
        if (!cancelled) {
          setInvites(unwrapItems(data));
        }
      } catch (err) {
        if (!cancelled) {
          setError(err.message || "No se pudieron cargar las invitaciones");
        }
      }
    }

    loadInvites();
    return () => {
      cancelled = true;
    };
  }, [orgId, isAuthenticated, requiresProfile]);

  async function handleAuthSubmit(event) {
    event.preventDefault();
    setAuthError("");
    const endpoint = authMode === "register" ? "/auth/register" : "/auth/login";
    const payload =
      authMode === "register"
        ? authForm
        : { email: authForm.email, password: authForm.password };
    try {
      const response = await authFetch(`${API_BASE}${endpoint}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      if (!response.ok) {
        const errorPayload = await response.json().catch(() => ({}));
        if (errorPayload?.detail?.code === "password_expired") {
          setForcePasswordMode(true);
          setForcePasswordForm((prev) => ({
            ...prev,
            email: authForm.email,
            current_password: "",
            new_password: "",
          }));
          setAuthError(errorPayload?.detail?.message || "Debe actualizar su contraseña");
          return;
        }
        throw new Error(errorPayload.detail || "Autenticación fallida");
      }
      const data = await response.json();
      setUser(data.user || null);
      setRequiresProfile(Boolean(data.requires_profile));
      setForcePasswordMode(false);
      setProjectId("");
      setOrgId("");
    } catch (err) {
      setAuthError(err.message || "Autenticación fallida");
    }
  }

  async function handleInviteAccept(event) {
    event.preventDefault();
    if (!inviteToken || !authForm.email || !authForm.password) {
      return;
    }
    const response = await authFetch(`${API_BASE}/invites/${inviteToken}/accept`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: authForm.email, password: authForm.password }),
    });
    if (response.ok) {
      const data = await response.json();
      setUser(data.user || null);
      setRequiresProfile(Boolean(data.requires_profile));
      setInviteToken("");
      setInviteAcceptStatus("Invitación aceptada");
    } else {
      setInviteAcceptStatus("La invitación falló");
    }
  }

  async function handleForcePasswordChange(event) {
    event.preventDefault();
    setAuthError("");
    try {
      const response = await authFetch(`${API_BASE}/auth/rotate-password`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(forcePasswordForm),
      });
      if (!response.ok) {
        const errorPayload = await response.json().catch(() => ({}));
        throw new Error(errorPayload.detail || "No se pudo actualizar la contraseña");
      }
      const data = await response.json();
      setUser(data.user || null);
      setRequiresProfile(Boolean(data.requires_profile));
      setForcePasswordMode(false);
    } catch (err) {
      setAuthError(err.message || "No se pudo actualizar la contraseña");
    }
  }

  async function handleForgotPassword(event) {
    event.preventDefault();
    setResetStatus("");
    if (!resetEmail) {
      return;
    }
    try {
      const response = await authFetch(`${API_BASE}/auth/forgot-password`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: resetEmail }),
      });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.detail || "No se pudo generar el token");
      }
      setResetStatus(data.message || "Revisa tu correo para el token de recuperación");
    } catch (err) {
      setResetStatus(err.message || "No se pudo generar el token");
    }
  }

  async function handleResetPassword(event) {
    event.preventDefault();
    setResetStatus("");
    if (!resetToken || !resetNewPassword) {
      return;
    }
    try {
      const response = await authFetch(`${API_BASE}/auth/reset-password`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token: resetToken, new_password: resetNewPassword }),
      });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.detail || "No se pudo restablecer la contraseña");
      }
      setUser(data.user || null);
      setRequiresProfile(Boolean(data.requires_profile));
      setResetMode(false);
      setResetToken("");
      setResetNewPassword("");
      setResetStatus("Contraseña restablecida");
    } catch (err) {
      setResetStatus(err.message || "No se pudo restablecer la contraseña");
    }
  }

  async function handleProfileUpdate(payload) {
    if (!isAuthenticated) {
      throw new Error("Sesión no válida");
    }
    const body = {
      phone: payload.phone,
      title: payload.title,
    };
    if (payload.full_name) {
      body.full_name = payload.full_name;
    }
    const response = await authFetch(`${API_BASE}/users/me/profile`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json", ...authHeaders() },
      body: JSON.stringify(body),
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(data.detail || "No se pudo actualizar el perfil");
    }
    setUserProfile(data);
    setRequiresProfile(!data.profile_completed);
  }

  async function handlePasswordUpdate(payload) {
    if (!isAuthenticated) {
      throw new Error("Sesión no válida");
    }
    const response = await authFetch(`${API_BASE}/users/me/password`, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...authHeaders() },
      body: JSON.stringify(payload),
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(data.detail || "No se pudo actualizar la contraseña");
    }
    setUserProfile((prev) => (prev ? { ...prev, ...data } : data));
  }

  async function handleNotificationSave(payload) {
    if (!isAuthenticated) {
      throw new Error("Sesión no válida");
    }
    const body = payload || notificationPrefs;
    if (!body) {
      return;
    }
    const response = await authFetch(`${API_BASE}/users/me/notifications`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json", ...authHeaders() },
      body: JSON.stringify(body),
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(data.detail || "No se pudieron guardar las preferencias");
    }
    setNotificationPrefs(data);
  }

  async function handleCreateProject() {
    const name = newProjectName.trim();
    if (!orgId || !name) {
      return;
    }
    const response = await authFetch(`${API_BASE}/orgs/${orgId}/projects`, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...authHeaders() },
      body: JSON.stringify({ name }),
    });
    if (response.ok) {
      setNewProjectName("");
      const data = await response.json();
      setProjects((prev) => [...prev, data]);
      setProjectId(String(data.id));
    }
  }

  async function handleCreateOrg() {
    const name = newClientName.trim();
    if (!name) {
      return;
    }
    const response = await authFetch(`${API_BASE}/orgs`, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...authHeaders() },
      body: JSON.stringify({ name }),
    });
    if (response.ok) {
      const data = await response.json();
      setOrgs((prev) => [...prev, data]);
      setOrgId(String(data.id));
      setNewClientName("");
    }
  }

  async function handleAddMember(event) {
    event.preventDefault();
    if (!orgId || !selectedUserId) {
      return;
    }
    const selectedUser = availableUsers.find((user) => String(user.id) === selectedUserId);
    if (!selectedUser) {
      return;
    }
    const response = await authFetch(`${API_BASE}/orgs/${orgId}/members`, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...authHeaders() },
      body: JSON.stringify({ email: selectedUser.email, role: newMemberRole }),
    });
    if (response.ok) {
      const data = await response.json();
      setMembers((prev) => [...prev, data]);
      setSelectedUserId("");
      return;
    }
    const errorPayload = await response.json().catch(() => ({}));
    setError(errorPayload.detail || "No se pudo agregar el miembro");
  }

  async function handleInvite(event) {
    event.preventDefault();
    if (!orgId || !inviteEmail) {
      return;
    }
    const response = await authFetch(`${API_BASE}/orgs/${orgId}/invites`, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...authHeaders() },
      body: JSON.stringify({ email: inviteEmail, role: inviteRole }),
    });
    if (response.ok) {
      const data = await response.json();
      setInvites((prev) => [...prev, data]);
      setInviteEmail("");
      return;
    }
    const errorPayload = await response.json().catch(() => ({}));
    setError(errorPayload.detail || "No se pudo crear la invitación");
  }

  async function handleDisableInvite(inviteId, disabled) {
    if (!orgId) {
      return;
    }
    const response = await authFetch(`${API_BASE}/orgs/${orgId}/invites/${inviteId}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json", ...authHeaders() },
      body: JSON.stringify({ disabled }),
    });
    if (response.ok) {
      const data = await response.json();
      setInvites((prev) => prev.map((invite) => (invite.id === inviteId ? data : invite)));
    }
  }

  function handleCopyInviteLink(invite) {
    const url = `${window.location.origin}?invite=${invite.token}`;
    navigator.clipboard.writeText(url);
  }

  async function handleUpdateMemberRole(memberId, role) {
    if (!orgId) {
      return;
    }
    const response = await authFetch(`${API_BASE}/orgs/${orgId}/members/${memberId}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json", ...authHeaders() },
      body: JSON.stringify({ role }),
    });
    if (response.ok) {
      const data = await response.json();
      setMembers((prev) => prev.map((m) => (m.id === memberId ? data : m)));
    }
  }

  async function handleRemoveMember(memberId) {
    if (!orgId) {
      return;
    }
    const response = await authFetch(`${API_BASE}/orgs/${orgId}/members/${memberId}`, {
      method: "DELETE",
      headers: authHeaders(),
    });
    if (response.ok) {
      setMembers((prev) => prev.filter((member) => member.id !== memberId));
    }
  }

  async function handleScanSubmit(event) {
    event.preventDefault();
    if (!projectId) {
      return;
    }
    if (!selectedScanAsset) {
      setError("Selecciona un activo antes de ejecutar un escaneo");
      return;
    }
    if (!allowedScanTools.has(scanForm.tool)) {
      setError("La herramienta seleccionada no es compatible con el tipo de activo");
      return;
    }
    const args = { project_id: Number(projectId), report_path: scanForm.reportPath };
    if (scanForm.tool === "vulnapi" || scanForm.tool === "wapiti" || scanForm.tool === "nuclei") {
      args.target_url = selectedScanAsset.uri || scanForm.targetUrl;
    } else {
      args.target_path = selectedScanAsset.uri || scanForm.targetPath;
    }
    const response = await authFetch(`${API_BASE}/scans/run`, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...authHeaders() },
      body: JSON.stringify({ tool: scanForm.tool, args }),
    });
    if (response.ok) {
      const data = await response.json();
      setScans((prev) => [data, ...prev]);
      setShowScanModal(false);
    }
  }

  async function handleRerunScan(scan) {
    if (!projectId) {
      return;
    }
    const metadata = { ...(scan.metadata || scan.scan_metadata || {}) };
    if (!metadata.project_id) {
      metadata.project_id = Number(projectId);
    }
    const response = await authFetch(`${API_BASE}/scans/run`, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...authHeaders() },
      body: JSON.stringify({ tool: scan.tool, args: metadata }),
    });
    if (response.ok) {
      const data = await response.json();
      setScans((prev) => [data, ...prev]);
    }
  }

  async function handleDeleteScan(scanId) {
    const response = await authFetch(`${API_BASE}/scans/${scanId}`, {
      method: "DELETE",
      headers: authHeaders(),
    });
    if (response.ok) {
      setScans((prev) => prev.filter((scan) => scan.id !== scanId));
      if (selectedScan === scanId) {
        setSelectedScan(null);
      }
    }
  }

  async function handleCancelScan(scanId) {
    if (!scanId || !isAuthenticated) {
      return;
    }
    if (!window.confirm("¿Cancelar este escaneo en ejecución?")) {
      return;
    }
    const response = await authFetch(`${API_BASE}/scans/${scanId}/cancel`, {
      method: "POST",
      headers: authHeaders(),
    });
    if (response.ok) {
      return;
    }
    const errorPayload = await response.json().catch(() => ({}));
    setError(errorPayload.detail || "No se pudo cancelar el escaneo");
  }

  function handleViewFindings(scanId) {
    setFindingScanFilter(String(scanId));
    setFindingSearch("");
    setSelectedFinding(null);
    setActiveSection("hallazgos");
  }

  async function handleCreateAsset(event) {
    event.preventDefault();
    if (!projectId) {
      return;
    }
    const payload = {
      project_id: Number(projectId),
      name: assetForm.name,
      uri: assetForm.uri,
      type: assetForm.type,
      owner_email: assetForm.ownerEmail,
      environment: assetForm.environment,
      criticality: assetForm.criticality,
      tags: assetForm.tags
        .split(",")
        .map((item) => item.trim())
        .filter(Boolean),
    };
    const response = await authFetch(`${API_BASE}/assets`, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...authHeaders() },
      body: JSON.stringify(payload),
    });
    if (response.ok) {
      const data = await response.json();
      setAssets((prev) => [...prev, data]);
      setAssetForm({ ...EMPTY_ASSET_FORM });
      setShowAssetModal(false);
      setAssetEditTarget(null);
      return data;
    }
    return null;
  }

  async function handleUpdateAsset(event) {
    event.preventDefault();
    if (!assetEditTarget) {
      return null;
    }
    const payload = {
      name: assetForm.name,
      uri: assetForm.uri,
      type: assetForm.type,
      owner_email: assetForm.ownerEmail,
      environment: assetForm.environment,
      criticality: assetForm.criticality,
      tags: assetForm.tags
        .split(",")
        .map((item) => item.trim())
        .filter(Boolean),
    };
    const response = await authFetch(`${API_BASE}/assets/${assetEditTarget.id}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json", ...authHeaders() },
      body: JSON.stringify(payload),
    });
    if (response.ok) {
      const data = await response.json();
      setAssets((prev) => prev.map((asset) => (asset.id === data.id ? data : asset)));
      setSelectedAsset((prev) => (prev?.id === data.id ? data : prev));
      setShowAssetModal(false);
      setAssetEditTarget(null);
      setAssetForm({ ...EMPTY_ASSET_FORM });
      return data;
    }
    return null;
  }

  function handleEditAsset(asset) {
    setAssetEditTarget(asset);
    setAssetForm({
      name: asset.name || "",
      type: asset.type || "web_app",
      uri: asset.uri || "",
      ownerEmail: asset.owner_email || "",
      environment: asset.environment || "prod",
      criticality: asset.criticality || "media",
      tags: Array.isArray(asset.tags) ? asset.tags.join(", ") : "",
    });
    setShowAssetModal(true);
  }

  async function handleDeleteAsset(assetId) {
    if (!assetId || !isAuthenticated) {
      return;
    }
    if (!window.confirm("¿Eliminar este activo?")) {
      return;
    }
    const response = await authFetch(`${API_BASE}/assets/${assetId}`, {
      method: "DELETE",
      headers: authHeaders(),
    });
    if (response.ok) {
      setAssets((prev) => prev.filter((asset) => asset.id !== assetId));
      setSelectedAsset((prev) => (prev?.id === assetId ? null : prev));
      return;
    }
    const errorPayload = await response.json().catch(() => ({}));
    setError(errorPayload.detail || "No se pudo eliminar el activo");
  }

  function openNewAssetModal() {
    setAssetEditTarget(null);
    setAssetForm({ ...EMPTY_ASSET_FORM });
    setShowAssetModal(true);
  }

  function closeAssetModal() {
    setShowAssetModal(false);
    setAssetEditTarget(null);
    setAssetForm({ ...EMPTY_ASSET_FORM });
  }

  function renderAssetTypeIcon(type) {
    switch (type) {
      case "web_app":
        return (
          <svg viewBox="0 0 24 24" aria-hidden="true">
            <circle cx="12" cy="12" r="9" fill="none" stroke="currentColor" strokeWidth="1.5" />
            <path
              d="M3 12h18M12 3c2.5 2.6 2.5 14.4 0 18M12 3c-2.5 2.6-2.5 14.4 0 18"
              fill="none"
              stroke="currentColor"
              strokeWidth="1.5"
            />
          </svg>
        );
      case "api":
        return (
          <svg viewBox="0 0 24 24" aria-hidden="true">
            <path
              d="M8 12h8M12 8v8"
              fill="none"
              stroke="currentColor"
              strokeWidth="1.5"
              strokeLinecap="round"
            />
            <circle cx="12" cy="12" r="9" fill="none" stroke="currentColor" strokeWidth="1.5" />
          </svg>
        );
      case "repo":
        return (
          <svg viewBox="0 0 24 24" aria-hidden="true">
            <path
              d="M7 4h10a2 2 0 0 1 2 2v12l-5-3-5 3-5-3V6a2 2 0 0 1 2-2Z"
              fill="none"
              stroke="currentColor"
              strokeWidth="1.5"
              strokeLinejoin="round"
            />
          </svg>
        );
      case "host":
        return (
          <svg viewBox="0 0 24 24" aria-hidden="true">
            <rect x="3" y="4" width="18" height="12" rx="2" fill="none" stroke="currentColor" strokeWidth="1.5" />
            <path d="M8 20h8" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
          </svg>
        );
      case "container":
        return (
          <svg viewBox="0 0 24 24" aria-hidden="true">
            <rect x="3" y="7" width="18" height="10" rx="2" fill="none" stroke="currentColor" strokeWidth="1.5" />
            <path d="M7 7v10M12 7v10M17 7v10" fill="none" stroke="currentColor" strokeWidth="1.5" />
          </svg>
        );
      case "network_range":
        return (
          <svg viewBox="0 0 24 24" aria-hidden="true">
            <path
              d="M4 12a8 8 0 0 1 16 0"
              fill="none"
              stroke="currentColor"
              strokeWidth="1.5"
              strokeLinecap="round"
            />
            <circle cx="12" cy="12" r="2" fill="none" stroke="currentColor" strokeWidth="1.5" />
            <path d="M12 14v5" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
          </svg>
        );
      default:
        return (
          <svg viewBox="0 0 24 24" aria-hidden="true">
            <circle cx="12" cy="12" r="9" fill="none" stroke="currentColor" strokeWidth="1.5" />
          </svg>
        );
    }
  }

  function downloadBlob(blob, filename) {
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = filename;
    link.click();
    URL.revokeObjectURL(url);
  }

  async function loadExcelJS() {
    const module = await import("exceljs");
    return module.default || module;
  }

  async function downloadImportTemplate(format) {
    const headers = [
      "title",
      "severity",
      "status",
      "description",
      "cwe",
      "owasp_category",
      "cvss_score",
      "occurrences",
      "tags",
      "asset_name",
      "asset_uri",
      "asset_type",
      "owner_email",
      "pentester_email",
    ];
    const sampleRow = {
      title: "SQL Injection",
      severity: "critical",
      status: "open",
      description: "Parametro id vulnerable a inyeccion SQL.",
      cwe: "CWE-89",
      owasp_category: "A03:2021",
      cvss_score: "9.1",
      occurrences: "1",
      tags: "owasp,sqli",
      asset_name: "api-prod",
      asset_uri: "https://api.example.com",
      asset_type: "api",
      owner_email: "owner@example.com",
      pentester_email: "pentester@example.com",
    };
    const emptyRow = Object.fromEntries(headers.map((header) => [header, ""]));

    if (format === "json") {
      const blob = new Blob([JSON.stringify([sampleRow, emptyRow], null, 2)], {
        type: "application/json",
      });
      downloadBlob(blob, "vulninventory_import_template.json");
      return;
    }

    if (format === "xlsx") {
      const ExcelJS = await loadExcelJS();
      const workbook = new ExcelJS.Workbook();
      const sheet = workbook.addWorksheet("Hallazgos");
      sheet.addRow(headers);
      sheet.addRow(headers.map((header) => sampleRow[header] ?? ""));
      sheet.addRow(headers.map(() => ""));
      const buffer = await workbook.xlsx.writeBuffer();
      const blob = new Blob([buffer], {
        type: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
      });
      downloadBlob(blob, "vulninventory_import_template.xlsx");
      return;
    }

    const csvContent = [
      headers.join(","),
      headers.map((header) => `"${String(sampleRow[header] || "").replace(/"/g, '""')}"`).join(","),
      headers.map(() => "\"\"").join(","),
    ].join("\n");
    const blob = new Blob(["\ufeff" + csvContent], { type: "text/csv;charset=utf-8;" });
    downloadBlob(blob, "vulninventory_import_template.csv");
  }

  function exportCSV(data, filename) {
    if (!data.length) {
      return;
    }
    const headers = Object.keys(data[0]);
    const csvContent = [
      headers.join(","),
      ...data.map((row) =>
        headers
          .map((header) => {
            const value = String(row[header] ?? "").replace(/"/g, '""');
            return `"${value}"`;
          })
          .join(",")
      ),
    ].join("\n");
    const blob = new Blob(["\ufeff" + csvContent], { type: "text/csv;charset=utf-8;" });
    downloadBlob(blob, `${filename}.csv`);
  }

  function exportJSON(data, filename) {
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
    downloadBlob(blob, `${filename}.json`);
  }

  async function exportXLSX(data, filename) {
    if (!data.length) {
      return;
    }
    const ExcelJS = await loadExcelJS();
    const workbook = new ExcelJS.Workbook();
    const sheet = workbook.addWorksheet("Hallazgos");
    const headers = Object.keys(data[0]);
    sheet.addRow(headers);
    data.forEach((row) => {
      sheet.addRow(headers.map((header) => row[header] ?? ""));
    });
    const buffer = await workbook.xlsx.writeBuffer();
    const blob = new Blob([buffer], {
      type: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    });
    downloadBlob(blob, `${filename}.xlsx`);
  }

  function handleExport(format) {
    setShowExportMenu(false);
    if (!projectId) {
      return;
    }
    const exportData = filteredFindings.map((finding) => {
      const asset = assets.find((item) => item.id === finding.asset_id);
      return {
        title: finding.title,
        severity: finding.severity,
        status: finding.status,
        description: finding.description || "",
        cwe: finding.cwe || "",
        owasp_category: finding.owasp || "",
        cvss_score: finding.cvss_score || "",
        asset_name: asset?.name || "",
        asset_uri: asset?.uri || "",
        asset_type: asset?.type || "",
        owner_email: asset?.owner_email || "",
        pentester_email: "",
        occurrences: finding.occurrences || 1,
        tags: "",
        created_at: "",
        updated_at: "",
      };
    });
    const projectName =
      projects.find((project) => String(project.id) === String(projectId))?.name || "proyecto";
    const timestamp = new Date().toISOString().split("T")[0];
    const filename = `vulninventory_${projectName}_${timestamp}`;
    if (format === "csv") {
      exportCSV(exportData, filename);
    } else if (format === "json") {
      exportJSON(exportData, filename);
    } else if (format === "xlsx") {
      exportXLSX(exportData, filename);
    }
  }

  function detectFormat(file) {
    const name = file.name.toLowerCase();
    if (name.endsWith(".csv")) return "csv";
    if (name.endsWith(".json")) return "json";
    if (name.endsWith(".xlsx") || name.endsWith(".xls")) return "xlsx";
    if (name.endsWith(".nessus") || name.endsWith(".xml")) return "xml";
    if (name.endsWith(".sarif")) return "sarif";
    return "csv";
  }

  function autoMapColumns(fileColumns) {
    const map = {};
    fileColumns.forEach((col) => {
      const normalized = col.toLowerCase().trim().replace(/[\s-]/g, "_");
      for (const [field, aliases] of Object.entries(AUTO_MAP_ALIASES)) {
        if (aliases.includes(normalized)) {
          map[col] = field;
          break;
        }
      }
    });
    return map;
  }

  function mapSarifLevel(level) {
    const map = { error: "high", warning: "medium", note: "low", none: "info" };
    return map[level] || "medium";
  }

  function parseNessusXML(doc) {
    const rows = [];
    doc.querySelectorAll("ReportHost").forEach((host) => {
      const hostName = host.getAttribute("name");
      host.querySelectorAll("ReportItem").forEach((item) => {
        const severity = Number(item.getAttribute("severity") || "0");
        const sevMap = { 0: "info", 1: "low", 2: "medium", 3: "high", 4: "critical" };
        rows.push({
          title: item.getAttribute("pluginName") || "Sin titulo",
          severity: sevMap[severity] || "info",
          description: item.querySelector("description")?.textContent || "",
          cwe: item.querySelector("cwe")?.textContent || "",
          cvss_score:
            item.querySelector("cvss3_base_score")?.textContent ||
            item.querySelector("cvss_base_score")?.textContent ||
            "",
          asset_name: hostName,
          asset_uri: hostName,
          asset_type: "host",
          port: item.getAttribute("port") || "",
          protocol: item.getAttribute("protocol") || "",
        });
      });
    });
    return rows;
  }

  function parseBurpXML(doc) {
    const rows = [];
    doc.querySelectorAll("issue").forEach((issue) => {
      const severityText = issue.querySelector("severity")?.textContent?.toLowerCase() || "";
      const sevMap = {
        high: "high",
        medium: "medium",
        low: "low",
        information: "info",
        critical: "critical",
      };
      rows.push({
        title: issue.querySelector("name")?.textContent || "Sin titulo",
        severity: sevMap[severityText] || "medium",
        description: issue.querySelector("issueDetail")?.textContent || "",
        asset_name: issue.querySelector("host")?.textContent || "",
        asset_uri: issue.querySelector("host")?.getAttribute("ip") || issue.querySelector("path")?.textContent || "",
        asset_type: "web_app",
      });
    });
    return rows;
  }

  function parseCsvLine(line, delimiter) {
    const values = [];
    let current = "";
    let inQuotes = false;
    for (let i = 0; i < line.length; i += 1) {
      const char = line[i];
      if (char === "\"") {
        const nextChar = line[i + 1];
        if (inQuotes && nextChar === "\"") {
          current += "\"";
          i += 1;
        } else {
          inQuotes = !inQuotes;
        }
      } else if (char === delimiter && !inQuotes) {
        values.push(current);
        current = "";
      } else {
        current += char;
      }
    }
    values.push(current);
    return values.map((value) => value.trim());
  }

  function detectCsvDelimiter(headerLine) {
    const commaCount = (headerLine.match(/,/g) || []).length;
    const semicolonCount = (headerLine.match(/;/g) || []).length;
    return semicolonCount > commaCount ? ";" : ",";
  }

  async function parseImportFile(file) {
    const format = detectFormat(file);
    setImportFormat(format);
    setImportErrors([]);
    try {
      let rows = [];
      if (format === "csv") {
        const text = await file.text();
        const rawLines = text.split(/\r?\n/).filter((line) => line.trim());
        if (rawLines.length === 0) {
          setImportRawData([]);
          return [];
        }
        const headerLine = rawLines[0].replace(/^\uFEFF/, "");
        const delimiter = detectCsvDelimiter(headerLine);
        const headers = parseCsvLine(headerLine, delimiter).map((header) =>
          header.replace(/^"|"$/g, "").trim()
        );
        rows = rawLines.slice(1).map((line) => {
          const values = parseCsvLine(line, delimiter);
          const obj = {};
          headers.forEach((header, index) => {
            const raw = values[index] ?? "";
            obj[header] = raw.replace(/^"|"$/g, "").trim();
          });
          return obj;
        });
      } else if (format === "json") {
        const text = await file.text();
        const parsed = JSON.parse(text);
        rows = Array.isArray(parsed)
          ? parsed
          : parsed.findings || parsed.vulnerabilities || parsed.data || [parsed];
        rows = rows.map((row) => {
          const flat = {};
          Object.entries(row).forEach(([key, val]) => {
            if (val && typeof val === "object" && !Array.isArray(val)) {
              flat[key] = val.default || val.en || Object.values(val)[0] || JSON.stringify(val);
            } else if (Array.isArray(val)) {
              flat[key] = val.join(", ");
            } else {
              flat[key] = val;
            }
          });
          return flat;
        });
      } else if (format === "xlsx") {
        const ExcelJS = await loadExcelJS();
        const buffer = await file.arrayBuffer();
        const workbook = new ExcelJS.Workbook();
        await workbook.xlsx.load(buffer);
        const sheet = workbook.worksheets[0];
        if (!sheet) {
          rows = [];
        } else {
          const headerRow = sheet.getRow(1);
          const headers = headerRow.values
            .slice(1)
            .map((value) => String(value ?? "").trim())
            .filter((value) => value);
          rows = [];
          sheet.eachRow((row, rowNumber) => {
            if (rowNumber === 1) return;
            const values = row.values.slice(1);
            const obj = {};
            headers.forEach((header, index) => {
              const cellValue = values[index];
              if (cellValue && typeof cellValue === "object") {
                obj[header] =
                  cellValue.text ||
                  cellValue.richText?.map((chunk) => chunk.text).join("") ||
                  cellValue.result ||
                  String(cellValue);
              } else {
                obj[header] = cellValue ?? "";
              }
            });
            const hasContent = Object.values(obj).some((value) => String(value).trim());
            if (hasContent) {
              rows.push(obj);
            }
          });
        }
      } else if (format === "sarif") {
        const text = await file.text();
        const sarif = JSON.parse(text);
        rows = [];
        (sarif.runs || []).forEach((run) => {
          const tool = run.tool?.driver?.name || "unknown";
          (run.results || []).forEach((result) => {
            const rule = (run.tool?.driver?.rules || []).find((item) => item.id === result.ruleId);
            rows.push({
              title: result.message?.text || result.ruleId || "Sin titulo",
              severity: mapSarifLevel(result.level),
              description:
                rule?.fullDescription?.text || rule?.shortDescription?.text || "",
              cwe: rule?.properties?.tags?.find((tag) => tag.startsWith("CWE-")) || "",
              asset_name: result.locations?.[0]?.physicalLocation?.artifactLocation?.uri || tool,
              asset_uri: result.locations?.[0]?.physicalLocation?.artifactLocation?.uri || "",
              asset_type: "repo",
              tool,
            });
          });
        });
      } else if (format === "xml") {
        const text = await file.text();
        const parser = new DOMParser();
        const doc = parser.parseFromString(text, "text/xml");
        if (doc.querySelector("NessusClientData_v2") || doc.querySelector("Report")) {
          rows = parseNessusXML(doc);
          setImportFormat("nessus");
        } else if (doc.querySelector("issues") && doc.querySelector("issue")) {
          rows = parseBurpXML(doc);
          setImportFormat("burp");
        }
      }

      setImportRawData(rows);
      if (rows.length > 0) {
        const columns = Object.keys(rows[0]);
        const autoMap = autoMapColumns(columns);
        const missingRequired = ["title", "severity"].filter(
          (field) => !Object.values(autoMap).includes(field)
        );
        if (missingRequired.length > 0) {
          setImportErrors([
            `Faltan encabezados requeridos o no reconocidos: ${missingRequired.join(", ")}`,
            "Puedes continuar con mapeo manual en el paso 2.",
          ]);
        }
        setImportColumnMap(autoMap);
      }
      return rows;
    } catch (err) {
      setImportErrors([`Error al parsear archivo: ${err.message}`]);
      return [];
    }
  }

  function generatePreview() {
    const errors = [];
    const assetMap = new Map();
    const findingsList = [];
    const mappedFields = Object.values(importColumnMap);
    if (!mappedFields.includes("title")) errors.push('El campo "Titulo" es obligatorio');
    if (!mappedFields.includes("severity")) errors.push('El campo "Severidad" es obligatorio');
    const hasAssetNameMapped = mappedFields.includes("asset_name");
    if (errors.length > 0) {
      setImportErrors(errors);
      return;
    }

    const reverseMap = {};
    Object.entries(importColumnMap).forEach(([fileCol, sysField]) => {
      reverseMap[sysField] = fileCol;
    });

    importRawData.forEach((row, index) => {
      const getValue = (field) => {
        const col = reverseMap[field];
        return col ? String(row[col] || "").trim() : IMPORT_FIELDS[field]?.default || "";
      };

      let assetName = getValue("asset_name");
      let assetUri = getValue("asset_uri") || assetName;
      if (!hasAssetNameMapped) {
        if (importDefaultAssetId) {
          const existingAsset = assets.find(
            (asset) => String(asset.id) === String(importDefaultAssetId)
          );
          assetName = existingAsset?.name || "Importacion";
          assetUri = existingAsset?.uri || assetName;
        } else {
          const today = new Date().toISOString().split("T")[0];
          assetName = `Importacion ${today}`;
          assetUri = assetName;
        }
      }
      const assetKey = `${assetName}||${assetUri}`;
      let severity = getValue("severity").toLowerCase();
      const numericScore = Number.parseFloat(severity);
      if (!Number.isNaN(numericScore)) {
        if (numericScore >= 9.0) severity = "critical";
        else if (numericScore >= 7.0) severity = "high";
        else if (numericScore >= 4.0) severity = "medium";
        else if (numericScore > 0) severity = "low";
        else severity = "info";
      }
      const sevNormalize = {
        "critica": "critical",
        "alta": "high",
        "media": "medium",
        "baja": "low",
        "informativa": "info",
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
        "info": "info",
      };
      severity = sevNormalize[severity] || "medium";

      if (assetName && !assetMap.has(assetKey)) {
        const existingAsset = assets.find(
          (asset) => asset.name === assetName && (asset.uri === assetUri || !assetUri)
        );
        assetMap.set(assetKey, {
          name: assetName,
          uri: assetUri,
          type: getValue("asset_type") || "web_app",
          owner_email: getValue("owner_email") || "",
          exists: Boolean(existingAsset) || Boolean(importDefaultAssetId),
          existingId: importDefaultAssetId ? Number(importDefaultAssetId) : existingAsset?.id || null,
        });
      }

      findingsList.push({
        _row: index + 1,
        title: getValue("title"),
        severity,
        status: getValue("status") || "open",
        description: getValue("description"),
        cwe: getValue("cwe"),
        owasp_category: getValue("owasp_category"),
        cvss_score: getValue("cvss_score"),
        occurrences: Number(getValue("occurrences")) || 1,
        tags: getValue("tags"),
        pentester_email: getValue("pentester_email"),
        _assetKey: assetKey,
        _assetName: assetName,
      });
    });

    const invalidRows = findingsList.filter((finding) => !finding.title);
    if (invalidRows.length > 0) {
      errors.push(`${invalidRows.length} filas sin titulo (seran omitidas)`);
    }

    setImportErrors(errors);
    setImportPreview({
      assets: Array.from(assetMap.values()),
      findings: findingsList.filter((finding) => finding.title),
    });
  }

  async function executeImportFallback() {
    const results = { assetsCreated: 0, assetsReused: 0, findingsCreated: 0, errors: [] };
    const assetIdMap = new Map();
    for (const asset of importPreview.assets) {
      if (asset.exists && asset.existingId) {
        assetIdMap.set(`${asset.name}||${asset.uri}`, asset.existingId);
        results.assetsReused += 1;
        continue;
      }
      try {
        const resp = await authFetch(`${API_BASE}/assets`, {
          method: "POST",
          headers: { "Content-Type": "application/json", ...authHeaders() },
          body: JSON.stringify({
            project_id: projectId,
            name: asset.name,
            uri: asset.uri,
            type: asset.type,
            owner_email: asset.owner_email || "",
            environment: "prod",
            criticality: "media",
          }),
        });
        if (!resp.ok) {
          throw new Error(await resp.text());
        }
        const newAsset = await resp.json();
        assetIdMap.set(`${asset.name}||${asset.uri}`, newAsset.id);
        results.assetsCreated += 1;
      } catch (err) {
        results.errors.push(`Error creando activo "${asset.name}": ${err.message}`);
      }
    }

    for (const finding of importPreview.findings) {
      const assetId = assetIdMap.get(finding._assetKey);
      if (!assetId) {
        results.errors.push(`Fila ${finding._row}: No se pudo vincular al activo "${finding._assetName}"`);
        continue;
      }
      try {
        const resp = await authFetch(`${API_BASE}/findings/manual`, {
          method: "POST",
          headers: { "Content-Type": "application/json", ...authHeaders() },
          body: JSON.stringify({
            asset_id: assetId,
            title: finding.title,
            severity: finding.severity,
            status: finding.status,
            description: finding.description,
            cwe: finding.cwe,
            owasp: finding.owasp_category,
          }),
        });
        if (!resp.ok) {
          throw new Error(await resp.text());
        }
        results.findingsCreated += 1;
      } catch (err) {
        results.errors.push(`Fila ${finding._row}: Error creando "${finding.title}": ${err.message}`);
      }
    }
    return results;
  }

  async function reloadAssetsAndFindings() {
    if (!projectId) {
      return;
    }
    try {
      const [assetsResponse, findingsResponse] = await Promise.all([
        authFetch(`${API_BASE}/assets?project_id=${projectId}`, { headers: authHeaders() }),
        authFetch(`${API_BASE}/findings?project_id=${projectId}`, { headers: authHeaders() }),
      ]);
      if (!assetsResponse.ok || !findingsResponse.ok) {
        return;
      }
      const [assetsData, findingsData] = await Promise.all([
        assetsResponse.json(),
        findingsResponse.json(),
      ]);
      setAssets(unwrapItems(assetsData));
      setFindings(unwrapItems(findingsData));
    } catch (err) {
      setError(err.message || "No se pudieron actualizar los datos");
    }
  }

  async function executeImport() {
    setImportLoading(true);
    try {
      const payload = {
        project_id: Number(projectId),
        assets: importPreview.assets.map((asset) => ({
          name: asset.name,
          uri: asset.uri,
          type: asset.type,
          owner_email: asset.owner_email,
          environment: "prod",
          criticality: "media",
        })),
        findings: importPreview.findings.map((finding) => ({
          title: finding.title,
          severity: finding.severity,
          status: finding.status,
          description: finding.description,
          cwe: finding.cwe,
          owasp: finding.owasp_category,
          cvss_score: finding.cvss_score ? Number(finding.cvss_score) : null,
          asset_ref: finding._assetName,
          pentester_email: finding.pentester_email,
          occurrences: finding.occurrences,
          tags: finding.tags ? finding.tags.split(",").map((tag) => tag.trim()) : [],
        })),
      };

      const response = await authFetch(`${API_BASE}/import/bulk`, {
        method: "POST",
        headers: { "Content-Type": "application/json", ...authHeaders() },
        body: JSON.stringify(payload),
      });

      let results;
      if (!response.ok) {
        results = await executeImportFallback();
      } else {
        const data = await response.json();
        results = {
          assetsCreated: data.assets_created,
          assetsReused: data.assets_reused,
          findingsCreated: data.findings_created,
          errors: data.errors || [],
        };
      }

      setImportResult(results);
      setImportStep(4);
      reloadAssetsAndFindings();
    } catch (err) {
      setImportResult({
        assetsCreated: 0,
        assetsReused: 0,
        findingsCreated: 0,
        errors: [`Error general: ${err.message}`],
      });
      setImportStep(4);
    } finally {
      setImportLoading(false);
    }
  }

  function resetImportWizard() {
    setShowImportWizard(false);
    setImportStep(1);
    setImportFile(null);
    setImportRawData([]);
    setImportColumnMap({});
    setImportPreview({ assets: [], findings: [] });
    setImportResult(null);
    setImportErrors([]);
    setImportDefaultAssetId("");
  }

  async function fetchVulnSearch(query, setResults, setLoading) {
    if (!query.trim()) {
      setResults([]);
      return;
    }
    setLoading(true);
    try {
      const response = await authFetch(
        `${API_BASE}/vulndb/search?q=${encodeURIComponent(query)}&limit=15`,
        { headers: authHeaders() }
      );
      if (!response.ok) {
        setResults([]);
        return;
      }
      const data = await response.json();
      setResults(unwrapItems(data));
    } catch (err) {
      setResults([]);
      setError(err.message || "No se pudo buscar en el catalogo");
    } finally {
      setLoading(false);
    }
  }

  async function handleCatalogSelect(entryId) {
    try {
      const response = await authFetch(`${API_BASE}/vulndb/${entryId}`, { headers: authHeaders() });
      if (!response.ok) {
        return;
      }
      const entry = await response.json();
      setCatalogDetail(entry);
      if (showFindingModal) {
        setSelectedCatalogEntry(entry);
        setVulnSearchQuery(entry.cve_id || entry.name || "");
        setShowVulnDropdown(false);
        const extraDetails = [
          entry.recommendation ? `Recomendacion: ${entry.recommendation}` : "",
          entry.references ? `Referencias:\\n${entry.references}` : "",
        ]
          .filter(Boolean)
          .join("\\n\\n");
        setManualFindingForm((prev) => ({
          ...prev,
          title: entry.name || prev.title,
          severity: entry.severity || prev.severity,
          cwe: entry.cwe_name || entry.cwe_id || prev.cwe,
          owasp: prev.owasp,
          description: [entry.description || "", extraDetails].filter(Boolean).join("\\n\\n"),
          recommendation: entry.recommendation || prev.recommendation,
          references: entry.references || prev.references,
          rule_id: entry.cve_id || prev.rule_id,
        }));
      }
    } catch (err) {
      setError(err.message || "No se pudo cargar la vulnerabilidad");
    }
  }

  async function loadCatalogStats() {
    try {
      const response = await authFetch(`${API_BASE}/vulndb/stats`, { headers: authHeaders() });
      if (!response.ok) {
        return;
      }
      const data = await response.json();
      setCatalogStats(data);
    } catch (err) {
      setError(err.message || "No se pudieron cargar las metricas del catalogo");
    }
  }

  async function handleCatalogImport() {
    if (!catalogImportFile) {
      return;
    }
    setCatalogImportLoading(true);
    setCatalogImportError("");
    setCatalogImportResult(null);
    try {
      const formData = new FormData();
      formData.append("file", catalogImportFile);
      const response = await authFetch(`${API_BASE}/vulndb/import`, {
        method: "POST",
        body: formData,
      });
      if (!response.ok) {
        const payload = await response.json().catch(() => ({}));
        throw new Error(payload.detail || "Error importando catalogo");
      }
      const data = await response.json();
      setCatalogImportResult(data);
      loadCatalogStats();
    } catch (err) {
      setCatalogImportError(err.message || "Error importando catalogo");
    } finally {
      setCatalogImportLoading(false);
    }
  }

  async function handleCatalogTemplateSubmit(event) {
    event.preventDefault();
    if (!catalogTemplateForm.name) {
      return;
    }
    try {
      const response = await authFetch(`${API_BASE}/vulndb`, {
        method: "POST",
        headers: { "Content-Type": "application/json", ...authHeaders() },
        body: JSON.stringify({
          ...catalogTemplateForm,
          base_score: catalogTemplateForm.base_score
            ? Number(catalogTemplateForm.base_score)
            : null,
          cwe_id: catalogTemplateForm.cwe_id ? Number(catalogTemplateForm.cwe_id) : null,
          source: "manual",
          is_template: true,
        }),
      });
      if (!response.ok) {
        const payload = await response.json().catch(() => ({}));
        throw new Error(payload.detail || "No se pudo crear la plantilla");
      }
      setCatalogTemplateForm({
        name: "",
        cve_id: "",
        severity: "medium",
        base_score: "",
        cvss_vector: "",
        cwe_id: "",
        cwe_name: "",
        description: "",
        recommendation: "",
        references: "",
        exploit_available: false,
      });
      loadCatalogStats();
    } catch (err) {
      setError(err.message || "No se pudo crear la plantilla");
    }
  }

  function resetCatalogModal() {
    setShowCatalogModal(false);
    setCatalogTab("explore");
    setCatalogQuery("");
    setCatalogResults([]);
    setCatalogDetail(null);
    setCatalogImportFile(null);
    setCatalogImportResult(null);
    setCatalogImportError("");
  }

  const filteredAuditLogs = useMemo(() => {
    const search = auditFilters.search.trim().toLowerCase();
    const userFilter = auditFilters.user.trim();
    const fromDate = auditFilters.from ? new Date(`${auditFilters.from}T00:00:00`) : null;
    const toDate = auditFilters.to ? new Date(`${auditFilters.to}T23:59:59`) : null;
    return auditLogs.filter((log) => {
      if (auditFilters.action !== "all" && log.method !== auditFilters.action) {
        return false;
      }
      if (userFilter && String(log.user_id || "") !== userFilter) {
        return false;
      }
      if (fromDate && new Date(log.created_at) < fromDate) {
        return false;
      }
      if (toDate && new Date(log.created_at) > toDate) {
        return false;
      }
      if (search) {
        const haystack = [
          log.method,
          log.path,
          log.status_code,
          log.ip,
          log.user_id,
        ]
          .filter(Boolean)
          .join(" ")
          .toLowerCase();
        if (!haystack.includes(search)) {
          return false;
        }
      }
      return true;
    });
  }, [auditLogs, auditFilters]);

  const scanLogLines = useMemo(() => {
    const text = scanLogs.map((log) => log.message).join("\n");
    return text ? text.split("\n") : [];
  }, [scanLogs]);

  const scanLogPreview = useMemo(() => {
    if (showFullLogs) {
      return scanLogLines.join("\n");
    }
    return scanLogLines.slice(-200).join("\n");
  }, [scanLogLines, showFullLogs]);

  const scanStatusCounts = useMemo(() => {
    const counts = { queued: 0, running: 0, finished: 0, failed: 0 };
    scans.forEach((scan) => {
      if (counts[scan.status] !== undefined) {
        counts[scan.status] += 1;
      }
    });
    return counts;
  }, [scans]);

  const filteredScans = useMemo(() => {
    const search = scanFilters.search.trim().toLowerCase();
    const list = scans.filter((scan) => {
      if (scanFilters.tool !== "all" && scan.tool !== scanFilters.tool) {
        return false;
      }
      if (scanFilters.status !== "all" && scan.status !== scanFilters.status) {
        return false;
      }
      if (!search) {
        return true;
      }
      const metadata = scan.metadata || scan.scan_metadata || {};
      const target = metadata.target_url || metadata.target_path || metadata.report_path || "";
      return [String(scan.id), scan.tool, scan.status, target]
        .join(" ")
        .toLowerCase()
        .includes(search);
    });
    return list.sort((a, b) => new Date(b.started_at) - new Date(a.started_at));
  }, [scans, scanFilters]);

  const visibleScans = useMemo(() => {
    if (showAllScans) {
      return filteredScans;
    }
    return filteredScans.slice(0, 20);
  }, [filteredScans, showAllScans]);

  const scanFilterOptions = useMemo(() => {
    return [...scans].sort((a, b) => b.id - a.id);
  }, [scans]);

  const auditSummary = useMemo(() => {
    const total = filteredAuditLogs.length;
    const since = Date.now() - 24 * 60 * 60 * 1000;
    const errors24h = filteredAuditLogs.filter(
      (log) => log.status_code >= 400 && new Date(log.created_at).getTime() >= since
    ).length;
    return { total, errors24h };
  }, [filteredAuditLogs]);
  const auditMetrics = useMemo(() => {
    const now = new Date();
    const h24 = new Date(now.getTime() - 24 * 60 * 60 * 1000);
    const recent = filteredAuditLogs.filter((log) => new Date(log.created_at) >= h24);
    const ok24h = recent.filter((log) => log.status_code >= 200 && log.status_code < 400).length;
    const uniqueUsers = new Set(filteredAuditLogs.map((log) => log.user_id).filter(Boolean)).size;
    return {
      total: filteredAuditLogs.length,
      errors24h: auditSummary.errors24h,
      ok24h,
      uniqueUsers,
    };
  }, [auditSummary.errors24h, filteredAuditLogs]);

  const visibleAuditLogs = useMemo(() => {
    const sorted = [...filteredAuditLogs].sort(
      (a, b) => new Date(b.created_at) - new Date(a.created_at)
    );
    if (showAllAudit) {
      return sorted;
    }
    return sorted.slice(0, 50);
  }, [filteredAuditLogs, showAllAudit]);

  async function handleFindingStatusSave() {
    if (!selectedFinding || !isAuthenticated) {
      return;
    }
    const ids = selectedFinding.ids?.length ? selectedFinding.ids : [selectedFinding.id];
    try {
      await Promise.all(
        ids.map((id) =>
          authFetch(`${API_BASE}/findings/${id}`, {
            method: "PATCH",
            headers: { "Content-Type": "application/json", ...authHeaders() },
            body: JSON.stringify({ status: selectedFindingStatus }),
          })
        )
      );
      setFindings((prev) =>
        prev.map((finding) =>
          ids.includes(finding.id) ? { ...finding, status: selectedFindingStatus } : finding
        )
      );
      setSelectedFinding((prev) => (prev ? { ...prev, status: selectedFindingStatus } : prev));
    } catch (err) {
      setError(err.message || "No se pudo actualizar el estado");
    }
  }

  async function handleFindingAssigneeSave() {
    if (!selectedFinding || !isAuthenticated) {
      return;
    }
    const assigneeId = selectedFindingAssignee ? Number(selectedFindingAssignee) : null;
    const response = await authFetch(`${API_BASE}/findings/${selectedFinding.id}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json", ...authHeaders() },
      body: JSON.stringify({ assignee_user_id: assigneeId }),
    });
    if (response.ok) {
      const data = await response.json();
      setFindings((prev) =>
        prev.map((finding) => (finding.id === data.id ? { ...finding, ...data } : finding))
      );
      setSelectedFinding((prev) => (prev ? { ...prev, assignee_user_id: data.assignee_user_id } : prev));
      return;
    }
    const errorPayload = await response.json().catch(() => ({}));
    setError(errorPayload.detail || "No se pudo asignar el hallazgo");
  }

  async function handleFindingCommentSubmit(event) {
    event.preventDefault();
    if (!selectedFinding || !isAuthenticated || !newFindingComment.trim()) {
      return;
    }
    const response = await authFetch(`${API_BASE}/findings/${selectedFinding.id}/comments`, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...authHeaders() },
      body: JSON.stringify({ message: newFindingComment.trim() }),
    });
    if (response.ok) {
      const data = await response.json();
      setFindingComments((prev) => [...prev, data]);
      setNewFindingComment("");
      return;
    }
    const errorPayload = await response.json().catch(() => ({}));
    setError(errorPayload.detail || "No se pudo agregar el comentario");
  }

  async function handleManualFindingSubmit(event) {
    event.preventDefault();
    if (!manualFindingForm.asset_id || !manualFindingForm.title || !manualFindingForm.severity) {
      setError("Completa activo, titulo y severidad");
      return;
    }
    const payload = {
      asset_id: Number(manualFindingForm.asset_id),
      title: manualFindingForm.title,
      severity: manualFindingForm.severity,
      status: manualFindingForm.status,
      cwe: manualFindingForm.cwe || undefined,
      owasp: manualFindingForm.owasp || undefined,
      description: manualFindingForm.description || undefined,
      recommendation: manualFindingForm.recommendation || undefined,
      references: manualFindingForm.references || undefined,
      rule_id: manualFindingForm.rule_id || "manual",
      assignee_user_id: manualFindingForm.assignee_user_id
        ? Number(manualFindingForm.assignee_user_id)
        : undefined,
    };
    const response = await authFetch(`${API_BASE}/findings/manual`, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...authHeaders() },
      body: JSON.stringify(payload),
    });
    if (response.ok) {
      const data = await response.json();
      setFindings((prev) => [...prev, data]);
      setShowFindingModal(false);
      setManualFindingForm({
        asset_id: "",
        title: "",
        severity: "medium",
        status: "open",
        cwe: "",
        owasp: "",
        description: "",
        recommendation: "",
        references: "",
        rule_id: "manual",
        assignee_user_id: "",
      });
      return;
    }
    const errorPayload = await response.json().catch(() => ({}));
    setError(errorPayload.detail || "No se pudo crear el hallazgo manual");
  }

  async function handleTemplateCreate(event) {
    event.preventDefault();
    if (!orgId || !templateForm.title || !templateForm.severity) {
      setError("Completa titulo y severidad para la plantilla");
      return;
    }
    const payload = {
      org_id: Number(orgId),
      title: templateForm.title,
      severity: templateForm.severity,
      cwe: templateForm.cwe || undefined,
      owasp: templateForm.owasp || undefined,
      description: templateForm.description || undefined,
    };
    const response = await authFetch(`${API_BASE}/templates`, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...authHeaders() },
      body: JSON.stringify(payload),
    });
    if (response.ok) {
      const data = await response.json();
      setCustomTemplates((prev) => [data, ...prev]);
      setTemplateForm({ title: "", severity: "medium", cwe: "", owasp: "", description: "" });
      return;
    }
    const errorPayload = await response.json().catch(() => ({}));
    setError(errorPayload.detail || "No se pudo crear la plantilla");
  }

  function applyTemplate(template) {
    setManualFindingForm((prev) => ({
      ...prev,
      title: template.title,
      severity: template.severity,
      cwe: template.cwe || "",
      owasp: template.owasp || "",
      description: template.description || "",
      rule_id: template.cwe || template.owasp || "manual",
    }));
    setFindingModalTab("manual");
  }

  if (authLoading) {
    return (
      <div className="auth-loading">
        <div className="spinner" />
        <p>Verificando sesión...</p>
      </div>
    );
  }

  const hasTopbar = Boolean(isAuthenticated);
  const showSidebar = isAuthenticated && !requiresProfile;
  const selectedOrgName = orgs.find((org) => String(org.id) === String(orgId))?.name;
  const selectedProjectName = projects.find((project) => String(project.id) === String(projectId))?.name;

  return (
    <div className="app">
      {isAuthenticated && (
        <header className="topbar">
          <div className="topbar-left">
            <button
              className="topbar-menu-btn"
              type="button"
              onClick={() => {
                if (window.innerWidth <= 768) {
                  setSidebarMobileOpen((prev) => !prev);
                } else {
                  setSidebarOpen((prev) => !prev);
                }
              }}
            >
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <line x1="3" y1="12" x2="21" y2="12" />
                <line x1="3" y1="6" x2="21" y2="6" />
                <line x1="3" y1="18" x2="21" y2="18" />
              </svg>
            </button>
            <span className="topbar-logo">🔒 VulnInventory</span>
          </div>

          <div className="topbar-context">
            {orgId ? (
              <>
                <span className="topbar-context-client">{selectedOrgName || "Cliente"}</span>
                {projectId ? (
                  <>
                    <span className="topbar-context-sep">/</span>
                    <span className="topbar-context-project">{selectedProjectName || "Proyecto"}</span>
                  </>
                ) : null}
              </>
            ) : (
              <span className="topbar-context-empty">Selecciona un cliente</span>
            )}
          </div>

          <div className="topbar-right">
            <span className="topbar-user">{userProfile?.email || authForm.email || "Usuario"}</span>
            <button className="btn btn-ghost btn-sm" type="button" onClick={handleLogout}>
              Cerrar sesión
            </button>
          </div>
        </header>
      )}

      {showSidebar && (
        <>
          {sidebarMobileOpen && (
            <div className="sidebar-overlay" onClick={() => setSidebarMobileOpen(false)} />
          )}
          <aside
            className={`sidebar ${sidebarOpen ? "" : "sidebar--collapsed"} ${sidebarMobileOpen ? "sidebar--mobile-open" : ""}`}
          >
            <div className="sidebar-section">
              <div className="sidebar-section-header">
                <span className="sidebar-section-title">{sidebarOpen ? "Clientes" : ""}</span>
                <button
                  className="sidebar-add-btn"
                  type="button"
                  title="Nuevo cliente"
                  onClick={() => {
                    setNewClientName("");
                    setShowNewClientModal(true);
                  }}
                >
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <line x1="12" y1="5" x2="12" y2="19" />
                    <line x1="5" y1="12" x2="19" y2="12" />
                  </svg>
                </button>
              </div>

              <div className="sidebar-tree">
                {orgs.map((org) => {
                  const isActive = String(orgId) === String(org.id);
                  const isExpanded = expandedClients[org.id];
                  const orgProjects = projects.filter(
                    (project) => String(project.organization_id) === String(org.id)
                  );

                  return (
                    <div key={org.id} className="sidebar-tree-client">
                      <div
                        className={`sidebar-tree-item sidebar-tree-item--client ${
                          isActive && !projectId ? "sidebar-tree-item--active" : ""
                        }`}
                        onClick={() => {
                          setOrgId(String(org.id));
                          setProjectId("");
                          toggleClientExpanded(org.id);
                          setActiveSection("dashboard");
                          if (window.innerWidth <= 768) {
                            setSidebarMobileOpen(false);
                          }
                        }}
                      >
                        <button
                          className="sidebar-tree-toggle"
                          type="button"
                          onClick={(event) => {
                            event.stopPropagation();
                            toggleClientExpanded(org.id);
                          }}
                        >
                          <svg
                            viewBox="0 0 24 24"
                            fill="none"
                            stroke="currentColor"
                            strokeWidth="2"
                            className={`sidebar-tree-arrow ${isExpanded ? "sidebar-tree-arrow--open" : ""}`}
                          >
                            <polyline points="9 18 15 12 9 6" />
                          </svg>
                        </button>
                        <span className="sidebar-tree-icon">🏢</span>
                        {sidebarOpen && <span className="sidebar-tree-name">{org.name}</span>}
                        {sidebarOpen && orgProjects.length > 0 && (
                          <span className="sidebar-tree-count">{orgProjects.length}</span>
                        )}
                      </div>

                      {isExpanded && sidebarOpen && (
                        <div className="sidebar-tree-projects">
                          {orgProjects.map((project) => {
                            const isProjectActive = String(projectId) === String(project.id);
                            return (
                              <div
                                key={project.id}
                                className={`sidebar-tree-item sidebar-tree-item--project ${
                                  isProjectActive ? "sidebar-tree-item--active" : ""
                                }`}
                                onClick={() => {
                                  setOrgId(String(org.id));
                                  setProjectId(String(project.id));
                                  setActiveSection("dashboard");
                                  if (window.innerWidth <= 768) {
                                    setSidebarMobileOpen(false);
                                  }
                                }}
                              >
                                <span className="sidebar-tree-icon">📁</span>
                                <span className="sidebar-tree-name">{project.name}</span>
                              </div>
                            );
                          })}
                          <div
                            className="sidebar-tree-item sidebar-tree-item--add"
                            onClick={() => {
                              setOrgId(String(org.id));
                              setNewProjectName("");
                              setShowNewProjectModal(true);
                            }}
                          >
                            <span className="sidebar-tree-icon">+</span>
                            {sidebarOpen && <span className="sidebar-tree-name">Nuevo proyecto</span>}
                          </div>
                        </div>
                      )}
                    </div>
                  );
                })}

                {orgs.length === 0 && sidebarOpen && (
                  <div className="sidebar-tree-empty">
                    <p>Sin clientes aún</p>
                  </div>
                )}
              </div>
            </div>

            <div className="sidebar-divider"></div>

            <nav className="sidebar-nav">
              {[
                {
                  key: "dashboard",
                  label: "Dashboard",
                  icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg>',
                },
                {
                  key: "hallazgos",
                  label: "Hallazgos",
                  icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="11" cy="11" r="8"/><path d="M21 21l-4.35-4.35"/></svg>',
                },
                {
                  key: "activos",
                  label: "Activos",
                  icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></svg>',
                },
                {
                  key: "escaneos",
                  label: "Escaneos",
                  icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>',
                },
                {
                  key: "equipo",
                  label: "Usuarios",
                  icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4-4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 00-3-3.87"/><path d="M16 3.13a4 4 0 010 7.75"/></svg>',
                },
                {
                  key: "auditoria",
                  label: "Auditoría",
                  icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>',
                },
              ].map((item) => (
                <button
                  key={item.key}
                  type="button"
                  className={`sidebar-link ${activeSection === item.key ? "sidebar-link--active" : ""}`}
                  onClick={() => {
                    setActiveSection(item.key);
                    if (window.innerWidth <= 768) {
                      setSidebarMobileOpen(false);
                    }
                  }}
                  disabled={!projectId && item.key !== "dashboard"}
                  title={!sidebarOpen ? item.label : undefined}
                >
                  <span className="sidebar-link-icon" dangerouslySetInnerHTML={{ __html: item.icon }} />
                  {sidebarOpen && <span className="sidebar-link-label">{item.label}</span>}
                  {!projectId && item.key !== "dashboard" && sidebarOpen && (
                    <span className="sidebar-link-lock">🔒</span>
                  )}
                </button>
              ))}
            </nav>

            <div className="sidebar-divider"></div>

            <div className="sidebar-footer">
              <button
                type="button"
                className={`sidebar-link ${activeSection === "perfil" ? "sidebar-link--active" : ""}`}
                onClick={() => setActiveSection("perfil")}
              >
                <span className="sidebar-link-icon">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <path d="M20 21v-2a4 4 0 00-4-4H8a4 4 0 00-4-4v2" />
                    <circle cx="12" cy="7" r="4" />
                  </svg>
                </span>
                {sidebarOpen && <span className="sidebar-link-label">Perfil</span>}
              </button>
              <button type="button" className="sidebar-link" onClick={handleLogout}>
                <span className="sidebar-link-icon">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <path d="M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4" />
                    <polyline points="16 17 21 12 16 7" />
                    <line x1="21" y1="12" x2="9" y2="12" />
                  </svg>
                </span>
                {sidebarOpen && <span className="sidebar-link-label">Cerrar sesión</span>}
              </button>
            </div>
          </aside>
        </>
      )}

      <div
        className={`app-layout ${hasTopbar ? "" : "app-layout--no-topbar"} ${
          showSidebar && !sidebarOpen ? "app-layout--collapsed" : ""
        }`}
      >
        <main className={`main-content ${showSidebar ? "" : "main-content--full"}`}>
          {authError ? <div className="error">{authError}</div> : null}
          {error ? (
            <div className="error">{error}</div>
          ) : (
            <>
              {!isAuthenticated ? (
                <section className="auth">
              <div className="auth-card">
                {inviteToken && (
                  <div className="invite-banner">
                    <strong>Invitación detectada.</strong>{" "}
                    {inviteInfo
                      ? `Cliente ${inviteInfo.organization_id} · Rol ${inviteInfo.role}`
                      : "Crea una contraseña para aceptar la invitación."}
                  </div>
                )}
                {forcePasswordMode ? (
                  <form onSubmit={handleForcePasswordChange} className="force-password">
                    <h3>Actualiza tu contraseña</h3>
                    <input className="form-input" type="email" value={forcePasswordForm.email} readOnly />
                    <input className="form-input"
                      type="password"
                      placeholder="contraseña actual"
                      value={forcePasswordForm.current_password}
                      onChange={(event) =>
                        setForcePasswordForm((prev) => ({
                          ...prev,
                          current_password: event.target.value,
                        }))
                      }
                      required
                    />
                    <input className="form-input"
                      type="password"
                      placeholder="nueva contraseña"
                      value={forcePasswordForm.new_password}
                      onChange={(event) =>
                        setForcePasswordForm((prev) => ({
                          ...prev,
                          new_password: event.target.value,
                        }))
                      }
                      required
                    />
                    <button className="btn btn-primary" type="submit">Actualizar contraseña</button>
                  </form>
                ) : resetMode ? (
                  <form onSubmit={handleForgotPassword} className="force-password">
                    <h3>Recuperar contraseña</h3>
                    <input className="form-input"
                      type="email"
                      placeholder="correo"
                      value={resetEmail}
                      onChange={(event) => setResetEmail(event.target.value)}
                      required
                    />
                    <button className="btn btn-primary" type="submit">Generar token</button>
                    {resetStatus ? <p className="status">{resetStatus}</p> : null}
                  </form>
                ) : (
                  <>
                    <div className="auth-toggle">
                  <button
                    type="button"
                    className={`btn btn-secondary ${authMode === "login" ? "active" : ""}`}
                    onClick={() => setAuthMode("login")}
                  >
                    Iniciar sesión
                  </button>
                  <button
                    type="button"
                    className={`btn btn-secondary ${authMode === "register" ? "active" : ""}`}
                    onClick={() => setAuthMode("register")}
                  >
                    Registrarse
                  </button>
                    </div>
                    <form onSubmit={handleAuthSubmit}>
                      <input className="form-input"
                        type="email"
                        placeholder="correo"
                        value={authForm.email}
                        onChange={(event) =>
                          setAuthForm({ ...authForm, email: event.target.value })
                        }
                        required
                      />
                      <input className="form-input"
                        type="password"
                        placeholder="contraseña"
                        value={authForm.password}
                        onChange={(event) =>
                          setAuthForm({ ...authForm, password: event.target.value })
                        }
                        required
                      />
                      {authMode === "register" && (
                        <input className="form-input"
                          type="text"
                          placeholder="cliente"
                          value={authForm.organization}
                          onChange={(event) =>
                            setAuthForm({ ...authForm, organization: event.target.value })
                          }
                          required
                        />
                      )}
                      <button className="btn btn-primary" type="submit">Continuar</button>
                    </form>
                    {authMode === "login" ? (
                      <button
                        type="button"
                        className="btn btn-ghost link-button"
                        onClick={() => {
                          setResetMode(true);
                          setResetEmail(authForm.email);
                          setResetStatus("");
                        }}
                      >
                        Olvidé mi contraseña
                      </button>
                    ) : null}
                  </>
                )}
                {resetMode ? (
                  <form onSubmit={handleResetPassword} className="force-password">
                    <h3>Restablecer contraseña</h3>
                    <input className="form-input"
                      type="text"
                      placeholder="token de recuperación"
                      value={resetToken}
                      onChange={(event) => setResetToken(event.target.value)}
                      required
                    />
                    <input className="form-input"
                      type="password"
                      placeholder="nueva contraseña"
                      value={resetNewPassword}
                      onChange={(event) => setResetNewPassword(event.target.value)}
                      required
                    />
                    <button className="btn btn-primary" type="submit">Restablecer</button>
                    <button
                      type="button"
                      className="link-button"
                      onClick={() => {
                        setResetMode(false);
                        setResetToken("");
                        setResetNewPassword("");
                        setResetStatus("");
                      }}
                    >
                      Volver
                    </button>
                    {resetStatus ? <p className="status">{resetStatus}</p> : null}
                  </form>
                ) : null}
                <form onSubmit={handleInviteAccept} className="invite-accept">
                  <input className="form-input"
                    type="text"
                    placeholder="token de invitación"
                    value={inviteToken}
                    onChange={(event) => setInviteToken(event.target.value)}
                  />
                  <button className="btn btn-primary" type="submit">Aceptar invitación</button>
                </form>
                {inviteAcceptStatus && <p className="status">{inviteAcceptStatus}</p>}
              </div>
            </section>
              ) : null}

              {isAuthenticated ? (
                <>
              {activeSection === "perfil" && (
                <UserProfile
                  requiresProfile={requiresProfile}
                  user={profileView}
                  onProfileSave={handleProfileUpdate}
                  onPasswordSave={handlePasswordUpdate}
                  onNotificationSave={handleNotificationSave}
                />
              )}

              {activeSection === "dashboard" && !orgId && (
                <div className="welcome-screen">
                  <div className="welcome-content">
                    <div className="welcome-logo">🔒</div>
                    <h1 className="welcome-title">VulnInventory</h1>
                    <p className="welcome-subtitle">Plataforma de gestión de vulnerabilidades</p>
                    <div className="welcome-actions">
                      <button
                        className="btn btn-primary"
                        type="button"
                        onClick={() => {
                          setNewClientName("");
                          setShowNewClientModal(true);
                        }}
                      >
                        🏢 Crear primer cliente
                      </button>
                      <p className="welcome-hint">
                        Comienza creando un cliente en el panel lateral para registrar activos y ejecutar escaneos.
                      </p>
                    </div>
                  </div>
                </div>
              )}

              {!projectId && activeSection !== "dashboard" && activeSection !== "perfil" && (
                <div className="context-required">
                  <div className="context-required-content">
                    <svg
                      viewBox="0 0 24 24"
                      fill="none"
                      stroke="currentColor"
                      strokeWidth="2"
                      className="context-required-icon"
                    >
                      <path d="M3 3h7v7H3zM14 3h7v7h-7zM14 14h7v7h-7zM3 14h7v7H3z" />
                    </svg>
                    <h2>Selecciona un proyecto</h2>
                    <p>
                      Elige un cliente y proyecto en el panel lateral para acceder a {activeSection}.
                    </p>
                  </div>
                </div>
              )}

              {activeSection === "dashboard" && orgId && (
            <section className="dashboard-grid">
              <div className="dashboard-header">
                <div>
                  <h2 className="dashboard-title">Dashboard</h2>
                  <p className="dashboard-subtitle">Centro de mando para el inventario de vulnerabilidades</p>
                </div>
              </div>

              <div className="dashboard-kpis">
                <div className="kpi-card">
                  <div className="kpi-icon kpi-icon--findings">
                    <svg viewBox="0 0 24 24" aria-hidden="true">
                      <path
                        d="M12 3l7 3v5c0 4.4-3 8.4-7 10-4-1.6-7-5.6-7-10V6l7-3Z"
                        fill="none"
                        stroke="currentColor"
                        strokeWidth="1.5"
                      />
                      <path
                        d="M9 12h6"
                        fill="none"
                        stroke="currentColor"
                        strokeWidth="1.5"
                        strokeLinecap="round"
                      />
                    </svg>
                  </div>
                  <div className="kpi-content">
                    <span className="kpi-value">{dashboardGroupedFindings.length}</span>
                    <span className="kpi-label">Hallazgos totales</span>
                  </div>
                </div>
                <div className="kpi-card kpi-card--critical">
                  <div className="kpi-icon kpi-icon--critical">
                    <svg viewBox="0 0 24 24" aria-hidden="true">
                      <path
                        d="M12 3l9 16H3L12 3Z"
                        fill="none"
                        stroke="currentColor"
                        strokeWidth="1.5"
                        strokeLinejoin="round"
                      />
                      <path
                        d="M12 9v4"
                        fill="none"
                        stroke="currentColor"
                        strokeWidth="1.5"
                        strokeLinecap="round"
                      />
                      <circle cx="12" cy="16.5" r="1" fill="currentColor" />
                    </svg>
                  </div>
                  <div className="kpi-content">
                    <span className="kpi-value">{dashboardSeverityCounts.critical || 0}</span>
                    <span className="kpi-label">Críticos</span>
                  </div>
                </div>
                <div className="kpi-card">
                  <div className="kpi-icon kpi-icon--open">
                    <svg viewBox="0 0 24 24" aria-hidden="true">
                      <circle cx="12" cy="12" r="9" fill="none" stroke="currentColor" strokeWidth="1.5" />
                      <path
                        d="M12 7v5l3 2"
                        fill="none"
                        stroke="currentColor"
                        strokeWidth="1.5"
                        strokeLinecap="round"
                      />
                    </svg>
                  </div>
                  <div className="kpi-content">
                    <span className="kpi-value">{statusCounts.open || 0}</span>
                    <span className="kpi-label">Abiertos</span>
                  </div>
                </div>
                <div className="kpi-card">
                  <div className="kpi-icon kpi-icon--fixed">
                    <svg viewBox="0 0 24 24" aria-hidden="true">
                      <circle cx="12" cy="12" r="9" fill="none" stroke="currentColor" strokeWidth="1.5" />
                      <path
                        d="M9 12.5 11 14l4-5"
                        fill="none"
                        stroke="currentColor"
                        strokeWidth="1.5"
                        strokeLinecap="round"
                        strokeLinejoin="round"
                      />
                    </svg>
                  </div>
                  <div className="kpi-content">
                    <span className="kpi-value">{statusCounts.fixed || 0}</span>
                    <span className="kpi-label">Cerrados</span>
                  </div>
                </div>
                <div className="kpi-card">
                  <div className="kpi-icon kpi-icon--assets">
                    <svg viewBox="0 0 24 24" aria-hidden="true">
                      <rect x="4" y="5" width="16" height="6" rx="2" fill="none" stroke="currentColor" strokeWidth="1.5" />
                      <rect x="4" y="13" width="16" height="6" rx="2" fill="none" stroke="currentColor" strokeWidth="1.5" />
                    </svg>
                  </div>
                  <div className="kpi-content">
                    <span className="kpi-value">{assets.length}</span>
                    <span className="kpi-label">Activos</span>
                  </div>
                </div>
                <div className="kpi-card">
                  <div className="kpi-icon kpi-icon--scans">
                    <svg viewBox="0 0 24 24" aria-hidden="true">
                      <path
                        d="M12 3a9 9 0 1 1-9 9"
                        fill="none"
                        stroke="currentColor"
                        strokeWidth="1.5"
                        strokeLinecap="round"
                      />
                      <path
                        d="M12 7v5l4 2"
                        fill="none"
                        stroke="currentColor"
                        strokeWidth="1.5"
                        strokeLinecap="round"
                      />
                    </svg>
                  </div>
                  <div className="kpi-content">
                    <span className="kpi-value">{scans.length}</span>
                    <span className="kpi-label">Escaneos</span>
                  </div>
                </div>
              </div>

              <div className="card dashboard-filters-card">
                <button
                  className="dashboard-filters-toggle"
                  type="button"
                  onClick={() => setDashboardFiltersOpen((prev) => !prev)}
                >
                  <span>Filtros</span>
                  <span className="dashboard-filters-count">
                    {activeDashboardFilterCount > 0 ? `${activeDashboardFilterCount} activos` : "Sin filtros"}
                  </span>
                  <svg
                    className={`dashboard-filters-icon ${dashboardFiltersOpen ? "rotated" : ""}`}
                    viewBox="0 0 24 24"
                    aria-hidden="true"
                  >
                    <path
                      d="m6 9 6 6 6-6"
                      fill="none"
                      stroke="currentColor"
                      strokeWidth="1.5"
                      strokeLinecap="round"
                      strokeLinejoin="round"
                    />
                  </svg>
                </button>
                {dashboardFiltersOpen && (
                  <div className="dashboard-filters-body">
                    <div className="form-group">
                      <label className="form-label">Activo</label>
                      <select
                        className="form-select"
                        value={dashboardFilters.asset}
                        onChange={(event) =>
                          setDashboardFilters((prev) => ({ ...prev, asset: event.target.value }))
                        }
                      >
                        <option value="all">Todos</option>
                        {assets.map((asset) => (
                          <option key={asset.id} value={String(asset.id)}>
                            {asset.name}
                          </option>
                        ))}
                      </select>
                    </div>
                    <div className="form-group">
                      <label className="form-label">Responsable</label>
                      <select
                        className="form-select"
                        value={dashboardFilters.owner}
                        onChange={(event) =>
                          setDashboardFilters((prev) => ({ ...prev, owner: event.target.value }))
                        }
                      >
                        <option value="all">Todos</option>
                        {Array.from(new Set(assets.map((asset) => asset.owner_email).filter(Boolean))).map(
                          (owner) => (
                            <option key={owner} value={owner}>
                              {owner}
                            </option>
                          ),
                        )}
                      </select>
                    </div>
                    <div className="form-group">
                      <label className="form-label">Severidad</label>
                      <select
                        className="form-select"
                        value={dashboardFilters.severity}
                        onChange={(event) =>
                          setDashboardFilters((prev) => ({ ...prev, severity: event.target.value }))
                        }
                      >
                        <option value="all">Todas</option>
                        <option value="critical">Crítica</option>
                        <option value="high">Alta</option>
                        <option value="medium">Media</option>
                        <option value="low">Baja</option>
                        <option value="info">Info</option>
                      </select>
                    </div>
                    <div className="form-group">
                      <label className="form-label">Estado</label>
                      <select
                        className="form-select"
                        value={dashboardFilters.status}
                        onChange={(event) =>
                          setDashboardFilters((prev) => ({ ...prev, status: event.target.value }))
                        }
                      >
                        <option value="all">Todos</option>
                        {statusOptions.map((status) => (
                          <option key={status} value={status}>
                            {statusLabels[status] || status}
                          </option>
                        ))}
                      </select>
                    </div>
                    <div className="form-group">
                      <label className="form-label">Herramienta</label>
                      <select
                        className="form-select"
                        value={dashboardFilters.tool}
                        onChange={(event) =>
                          setDashboardFilters((prev) => ({ ...prev, tool: event.target.value }))
                        }
                      >
                        <option value="all">Todas</option>
                        {Array.from(new Set(scans.map((scan) => scan.tool))).map((tool) => (
                          <option key={tool} value={tool}>
                            {tool}
                          </option>
                        ))}
                      </select>
                    </div>
                    <div className="form-group">
                      <label className="form-label">Vulnerabilidad</label>
                      <input
                        className="form-input"
                        type="text"
                        placeholder="título, CWE, OWASP"
                        value={dashboardFilters.vuln}
                        onChange={(event) =>
                          setDashboardFilters((prev) => ({ ...prev, vuln: event.target.value }))
                        }
                      />
                    </div>
                    <div className="form-group dashboard-filters-action">
                      <label className="form-label">&nbsp;</label>
                      <button
                        className="btn btn-secondary"
                        type="button"
                        onClick={() =>
                          setDashboardFilters({
                            asset: "all",
                            owner: "all",
                            severity: "all",
                            status: "all",
                            tool: "all",
                            vuln: "",
                          })
                        }
                      >
                        Limpiar
                      </button>
                    </div>
                  </div>
                )}
              </div>

              <div className="dashboard-charts">
                <div className="chart-card">
                  <h3 className="chart-title">Distribución por Severidad</h3>
                  <div className="chart-wrapper" style={{ height: 280 }}>
                    <ResponsiveContainer width="100%" height="100%">
                      <PieChart>
                        <Pie
                          data={severityChartData}
                          cx="50%"
                          cy="50%"
                          innerRadius={65}
                          outerRadius={95}
                          paddingAngle={3}
                          dataKey="value"
                          stroke="none"
                        >
                          {severityChartData.map((entry) => (
                            <Cell key={entry.key} fill={CHART_THEME.colors.severity[entry.key]} />
                          ))}
                        </Pie>
                        <Tooltip contentStyle={CHART_THEME.tooltip.contentStyle} />
                        <Legend
                          verticalAlign="bottom"
                          iconType="circle"
                          iconSize={8}
                          wrapperStyle={{ fontSize: "12px", color: "#94a3b8" }}
                        />
                      </PieChart>
                    </ResponsiveContainer>
                    <div className="donut-center">
                      <span className="donut-center-value">{totalSeverityFindings}</span>
                      <span className="donut-center-label">Total</span>
                    </div>
                  </div>
                </div>

                <div className="chart-card">
                  <h3 className="chart-title">Hallazgos por Herramienta</h3>
                  <div className="chart-wrapper" style={{ height: 280 }}>
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart data={toolChartData} layout="vertical" margin={{ left: 20 }}>
                        <CartesianGrid
                          strokeDasharray={CHART_THEME.grid.strokeDasharray}
                          stroke={CHART_THEME.grid.stroke}
                          horizontal={false}
                        />
                        <XAxis
                          type="number"
                          tick={CHART_THEME.axis.tick}
                          axisLine={CHART_THEME.axis.axisLine}
                        />
                        <YAxis
                          type="category"
                          dataKey="name"
                          tick={{
                            ...CHART_THEME.axis.tick,
                            fontFamily: "'JetBrains Mono', monospace",
                          }}
                          axisLine={false}
                          tickLine={false}
                          width={90}
                        />
                        <Tooltip
                          contentStyle={CHART_THEME.tooltip.contentStyle}
                          cursor={{ fill: "rgba(6, 182, 212, 0.08)" }}
                        />
                        <Bar dataKey="count" fill={CHART_THEME.colors.accent} radius={[0, 4, 4, 0]} barSize={24} />
                      </BarChart>
                    </ResponsiveContainer>
                  </div>
                </div>

                <div className="chart-card chart-card--wide">
                  <div className="chart-title-row" style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: "12px" }}>
                    <h3 className="chart-title">Tendencia de Hallazgos</h3>
                    <select
                      className="form-select"
                      value={trendGranularity}
                      onChange={(event) => setTrendGranularity(event.target.value)}
                      style={{ maxWidth: "160px", fontSize: "12px", padding: "6px 10px" }}
                    >
                      <option value="day">Dia</option>
                      <option value="week">Semana</option>
                      <option value="month">Mes</option>
                    </select>
                  </div>
                  <div className="chart-wrapper" style={{ height: 300 }}>
                    <ResponsiveContainer width="100%" height="100%">
                      <AreaChart data={trendData} margin={{ top: 10, right: 10, left: 0, bottom: 0 }}>
                        <defs>
                          <linearGradient id="colorHallazgos" x1="0" y1="0" x2="0" y2="1">
                            <stop offset="5%" stopColor={CHART_THEME.colors.accent} stopOpacity={0.3} />
                            <stop offset="95%" stopColor={CHART_THEME.colors.accent} stopOpacity={0} />
                          </linearGradient>
                        </defs>
                        <CartesianGrid
                          strokeDasharray={CHART_THEME.grid.strokeDasharray}
                          stroke={CHART_THEME.grid.stroke}
                          vertical={false}
                        />
                        <XAxis
                          dataKey="name"
                          tick={CHART_THEME.axis.tick}
                          axisLine={CHART_THEME.axis.axisLine}
                          tickLine={false}
                        />
                        <YAxis
                          tick={CHART_THEME.axis.tick}
                          axisLine={false}
                          tickLine={false}
                          allowDecimals={false}
                        />
                        <Tooltip
                          contentStyle={CHART_THEME.tooltip.contentStyle}
                          cursor={{
                            stroke: CHART_THEME.colors.accent,
                            strokeWidth: 1,
                            strokeDasharray: "4 4",
                          }}
                        />
                        <Area
                          type="monotone"
                          dataKey="hallazgos"
                          stroke={CHART_THEME.colors.accent}
                          strokeWidth={2}
                          fill="url(#colorHallazgos)"
                          dot={{ r: 4, fill: CHART_THEME.colors.accent, stroke: "#111827", strokeWidth: 2 }}
                          activeDot={{ r: 6, fill: CHART_THEME.colors.accentHover, stroke: "#111827", strokeWidth: 2 }}
                        />
                      </AreaChart>
                    </ResponsiveContainer>
                  </div>
                </div>

                <div className="chart-card">
                  <h3 className="chart-title">Distribución por Estado</h3>
                  <div className="chart-wrapper" style={{ height: 280 }}>
                    <ResponsiveContainer width="100%" height="100%">
                      <PieChart>
                        <Pie
                          data={statusChartData}
                          cx="50%"
                          cy="50%"
                          innerRadius={65}
                          outerRadius={95}
                          paddingAngle={3}
                          dataKey="value"
                          stroke="none"
                        >
                          {statusChartData.map((entry) => (
                            <Cell key={entry.key} fill={CHART_THEME.colors.status[entry.key]} />
                          ))}
                        </Pie>
                        <Tooltip contentStyle={CHART_THEME.tooltip.contentStyle} />
                        <Legend
                          verticalAlign="bottom"
                          iconType="circle"
                          iconSize={8}
                          wrapperStyle={{ fontSize: "12px", color: "#94a3b8" }}
                        />
                      </PieChart>
                    </ResponsiveContainer>
                    <div className="donut-center">
                      <span className="donut-center-value">{totalStatusFindings}</span>
                      <span className="donut-center-label">Total</span>
                    </div>
                  </div>
                </div>

                <div className="chart-card">
                  <h3 className="chart-title">Activos con más hallazgos</h3>
                  <div className="table-container">
                    <table className="table">
                      <thead>
                        <tr>
                          <th>Activo</th>
                          <th>Severidad máx.</th>
                          <th>Responsable</th>
                          <th>Total</th>
                        </tr>
                      </thead>
                      <tbody>
                        {topAssets.map((asset) => (
                          <tr key={asset.assetId}>
                            <td>
                              <span className="file-path">{asset.name}</span>
                            </td>
                            <td>
                              <span className={`badge badge-${asset.maxSeverity || "info"}`}>
                                {severityLabels[asset.maxSeverity] || "Info"}
                              </span>
                            </td>
                            <td>{asset.owner || "—"}</td>
                            <td className="findings-occurrences">{asset.total}</td>
                          </tr>
                        ))}
                        {topAssets.length === 0 && (
                          <tr>
                            <td colSpan={4}>
                              <div className="empty-state">
                                <p>Sin datos disponibles</p>
                              </div>
                            </td>
                          </tr>
                        )}
                      </tbody>
                    </table>
                  </div>
                </div>

                <div className="chart-card chart-card--wide">
                  <h3 className="chart-title">Mapa de Calor: Activos × Severidad</h3>
                  <div className="heatmap">
                    <div className="heatmap-header">
                      <span className="heatmap-corner" />
                      {["Crítica", "Alta", "Media", "Baja", "Info"].map((label) => (
                        <span key={label} className="heatmap-col-label">{label}</span>
                      ))}
                    </div>
                    {heatmapData.map((row) => {
                      const values = Object.values(row).filter((value) => typeof value === "number");
                      const maxVal = Math.max(1, ...values);
                      return (
                        <div key={row.asset} className="heatmap-row">
                          <span className="heatmap-row-label">{row.asset}</span>
                          {["critical", "high", "medium", "low", "info"].map((sev) => {
                            const value = row[sev] || 0;
                            const intensity = value / maxVal;
                            const alpha = Math.round((intensity * 0.6 + 0.15) * 255)
                              .toString(16)
                              .padStart(2, "0");
                            return (
                              <span
                                key={sev}
                                className="heatmap-cell"
                                style={{
                                  backgroundColor: value > 0
                                    ? `${CHART_THEME.colors.severity[sev]}${alpha}`
                                    : "var(--bg-tertiary)",
                                }}
                                title={`${row.asset}: ${value} ${sev}`}
                              >
                                {value > 0 ? value : ""}
                              </span>
                            );
                          })}
                        </div>
                      );
                    })}
                  </div>
                </div>
              </div>
            </section>
          )}

          {projectId && activeSection === "hallazgos" && (
            <section className={`findings-detail ${selectedFinding ? "has-drawer" : ""}`}>
            <div className="findings-header">
              <div>
                <div className="findings-title-row">
                  <svg className="findings-title-icon" viewBox="0 0 24 24" aria-hidden="true">
                    <path
                      d="M12 3l7 3v5c0 4.4-3 8.4-7 10-4-1.6-7-5.6-7-10V6l7-3Z"
                      fill="none"
                      stroke="currentColor"
                      strokeWidth="1.5"
                      strokeLinejoin="round"
                    />
                    <path
                      d="M9.5 12.5 11 14l3.5-4"
                      fill="none"
                      stroke="currentColor"
                      strokeWidth="1.5"
                      strokeLinecap="round"
                      strokeLinejoin="round"
                    />
                  </svg>
                  <h2 className="findings-title-heading">Hallazgos</h2>
                </div>
                <p className="findings-subtitle">Inventario de vulnerabilidades del proyecto</p>
              </div>
              <div className="findings-header-actions">
                <span className="badge badge-accent">{filteredFindings.length} total</span>
                <div className="dropdown">
                  <button
                    className="btn btn-secondary"
                    type="button"
                    onClick={() => setShowExportMenu((prev) => !prev)}
                  >
                    📤 Exportar
                  </button>
                  {showExportMenu && (
                    <div className="dropdown-menu">
                      <button className="dropdown-item" type="button" onClick={() => handleExport("csv")}>
                        📄 CSV (.csv)
                      </button>
                      <button className="dropdown-item" type="button" onClick={() => handleExport("json")}>
                        📋 JSON (.json)
                      </button>
                      <button className="dropdown-item" type="button" onClick={() => handleExport("xlsx")}>
                        📊 Excel (.xlsx)
                      </button>
                    </div>
                  )}
                </div>
                <button
                  className="btn btn-secondary"
                  type="button"
                  onClick={() => {
                    setShowImportWizard(true);
                    setImportStep(1);
                  }}
                >
                  📥 Importar
                </button>
                <button
                  className="btn btn-secondary"
                  type="button"
                  onClick={() => setShowCatalogModal(true)}
                >
                  📚 Catalogo
                </button>
                <button className="btn btn-primary" type="button" onClick={() => setShowFindingModal(true)}>
                  + Nuevo hallazgo
                </button>
              </div>
            </div>

            <div className="card findings-filters">
              <div className="form-group">
                <label className="form-label">Severidad</label>
                <select className="form-select" value={severityFilter} onChange={(event) => setSeverityFilter(event.target.value)}>
                  <option value="all">Todas</option>
                  <option value="critical">Crítica</option>
                  <option value="high">Alta</option>
                  <option value="medium">Media</option>
                  <option value="low">Baja</option>
                  <option value="info">Info</option>
                </select>
              </div>
              <div className="form-group">
                <label className="form-label">Activo</label>
                <select className="form-select" value={assetFilter} onChange={(event) => setAssetFilter(event.target.value)}>
                  <option value="all">Todos</option>
                  {assets.map((asset) => (
                    <option key={asset.id} value={String(asset.id)}>{asset.name}</option>
                  ))}
                </select>
              </div>
              <div className="form-group">
                <label className="form-label">Responsable</label>
                <select className="form-select" value={ownerFilter} onChange={(event) => setOwnerFilter(event.target.value)}>
                  <option value="all">Todos</option>
                  {Array.from(new Set(assets.map((asset) => asset.owner_email).filter(Boolean))).map(
                    (owner) => (
                      <option key={owner} value={owner}>{owner}</option>
                    ),
                  )}
                </select>
              </div>
              <div className="form-group">
                <label className="form-label">Escaneo</label>
                <select className="form-select" value={findingScanFilter} onChange={(event) => setFindingScanFilter(event.target.value)}>
                  <option value="all">Todos</option>
                  {scanFilterOptions.map((scan) => (
                    <option key={scan.id} value={String(scan.id)}>#{scan.id} {scan.tool}</option>
                  ))}
                </select>
              </div>
              <div className="form-group findings-search">
                <label className="form-label">Buscar</label>
                <div className="findings-search-input">
                  <svg className="findings-search-icon" viewBox="0 0 24 24" aria-hidden="true">
                    <circle cx="11" cy="11" r="7" fill="none" stroke="currentColor" strokeWidth="1.5" />
                    <path d="M20 20l-3.5-3.5" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
                  </svg>
                  <input
                    className="form-input"
                    type="text"
                    placeholder="título, regla, activo, responsable"
                    value={findingSearch}
                    onChange={(event) => setFindingSearch(event.target.value)}
                  />
                </div>
              </div>
            </div>

            <div className="table-container">
              <table className="table findings-table">
                <thead>
                  <tr>
                    <th>Severidad</th>
                    <th>Título</th>
                    <th>Activo</th>
                    <th>Responsable</th>
                    <th>Pentester</th>
                    <th>Estado</th>
                    <th>Ocurrencias</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredFindings.map((finding) => (
                    <tr
                      key={finding.id}
                      className={`findings-row ${selectedFinding?.id === finding.id ? "findings-row--active" : ""}`}
                      onClick={() => setSelectedFinding(finding)}
                    >
                      <td>
                        <span className={`badge badge-${finding.severity}`}>
                          {severityLabels[finding.severity] || finding.severity}
                        </span>
                      </td>
                      <td className="findings-title">
                        <span className="findings-title-text">{finding.title}</span>
                        {finding.cwe && (
                          <span className="cve-id">{finding.cwe}</span>
                        )}
                      </td>
                      <td>
                        <span className="findings-asset-name">
                          {assetMap.get(finding.asset_id)?.name || finding.asset_id}
                        </span>
                      </td>
                      <td>{assetMap.get(finding.asset_id)?.owner_email || "—"}</td>
                      <td>{members.find((m) => m.user_id === finding.assignee_user_id)?.email || "—"}</td>
                      <td>
                        <span className={`findings-status findings-status--${finding.status}`}>
                          {statusLabels[finding.status] || finding.status}
                        </span>
                      </td>
                      <td className="findings-occurrences">{finding.occurrences}</td>
                    </tr>
                  ))}
                  {filteredFindings.length === 0 && (
                    <tr>
                      <td colSpan={7}>
                        <div className="empty-state findings-empty">
                          <svg viewBox="0 0 24 24" aria-hidden="true">
                            <path
                              d="M12 3l7 3v5c0 4.4-3 8.4-7 10-4-1.6-7-5.6-7-10V6l7-3Z"
                              fill="none"
                              stroke="currentColor"
                              strokeWidth="1.5"
                            />
                            <path
                              d="M9 12h6"
                              fill="none"
                              stroke="currentColor"
                              strokeWidth="1.5"
                              strokeLinecap="round"
                            />
                          </svg>
                          <h3>No se encontraron hallazgos</h3>
                          <p>Ajusta los filtros o ejecuta un nuevo escaneo para detectar vulnerabilidades.</p>
                        </div>
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>

            {selectedFinding && (
              <aside className="findings-drawer">
                <div className="findings-drawer-header">
                  <div>
                    <span className={`badge badge-${selectedFinding.severity}`}>
                      {severityLabels[selectedFinding.severity] || selectedFinding.severity}
                    </span>
                    <h3 className="findings-drawer-title">{selectedFinding.title}</h3>
                  </div>
                  <button className="btn btn-ghost btn-sm" onClick={() => setSelectedFinding(null)}>✕</button>
                </div>

                <div className="findings-drawer-body">
                  {selectedFinding.description && (
                    <p className="findings-description">{selectedFinding.description}</p>
                  )}
                  {(selectedFinding.recommendation || selectedFinding.references) && (
                    <div className="findings-recommendations">
                      {selectedFinding.recommendation && (
                        <div className="findings-recommendation-block">
                          <span className="findings-meta-label">Recomendación</span>
                          <p>{selectedFinding.recommendation}</p>
                        </div>
                      )}
                      {selectedFinding.references && (
                        <div className="findings-recommendation-block">
                          <span className="findings-meta-label">Referencias</span>
                          <pre className="findings-references">{selectedFinding.references}</pre>
                        </div>
                      )}
                    </div>
                  )}
                  <div className="findings-meta-grid">
                    <div className="findings-meta-item">
                      <span className="findings-meta-label">OWASP</span>
                      <span className="cve-id">{selectedFinding.owasp || "—"}</span>
                    </div>
                    <div className="findings-meta-item">
                      <span className="findings-meta-label">CWE</span>
                      <span className="cve-id">{selectedFinding.cwe || "—"}</span>
                    </div>
                    <div className="findings-meta-item">
                      <span className="findings-meta-label">Activo</span>
                      <span>{assetMap.get(selectedFinding.asset_id)?.name || "—"}</span>
                    </div>
                    <div className="findings-meta-item">
                      <span className="findings-meta-label">URI</span>
                      <span className="file-path">{assetMap.get(selectedFinding.asset_id)?.uri || "—"}</span>
                    </div>
                    <div className="findings-meta-item">
                      <span className="findings-meta-label">Ocurrencias</span>
                      <span className="findings-occurrences">{selectedFinding.occurrences}</span>
                    </div>
                  </div>

                  <div className="findings-actions">
                    <div className="findings-action-row">
                      <div className="form-group">
                        <label className="form-label">Estado</label>
                        <select className="form-select" value={selectedFindingStatus}
                          onChange={(event) => setSelectedFindingStatus(event.target.value)}>
                          {statusOptions.map((status) => (
                            <option key={status} value={status}>
                              {statusLabels[status] || status}
                            </option>
                          ))}
                        </select>
                      </div>
                      <button className="btn btn-primary btn-sm" onClick={handleFindingStatusSave}>
                        Guardar
                      </button>
                    </div>
                    <div className="findings-action-row">
                      <div className="form-group">
                        <label className="form-label">Pentester</label>
                        <select className="form-select" value={selectedFindingAssignee}
                          onChange={(event) => setSelectedFindingAssignee(event.target.value)}>
                          <option value="">Sin asignar</option>
                          {members.map((member) => (
                            <option key={member.user_id} value={String(member.user_id)}>
                              {member.email}
                            </option>
                          ))}
                        </select>
                      </div>
                      <button className="btn btn-secondary btn-sm" onClick={handleFindingAssigneeSave}>
                        Asignar
                      </button>
                    </div>
                  </div>

                  <div className="findings-comments">
                    <h4>Comentarios</h4>
                    {findingComments.map((comment) => (
                      <div key={comment.id} className="comment-item">
                        <span className="comment-meta">
                          {members.find((member) => member.user_id === comment.user_id)?.email || "Sistema"} ·{" "}
                          {new Date(comment.created_at).toLocaleString()}
                        </span>
                        <p>{comment.message}</p>
                      </div>
                    ))}
                    {findingComments.length === 0 && (
                      <p className="comment-empty">Sin comentarios todavía.</p>
                    )}
                    <form onSubmit={handleFindingCommentSubmit} className="comment-form">
                      <input
                        className="form-input"
                        type="text"
                        placeholder="Agregar comentario"
                        value={newFindingComment}
                        onChange={(event) => setNewFindingComment(event.target.value)}
                      />
                      <button className="btn btn-primary btn-sm" type="submit">Guardar</button>
                    </form>
                  </div>
                </div>
              </aside>
            )}

            {showFindingModal && (
              <div className="modal-backdrop" onClick={() => setShowFindingModal(false)}>
                <div className="modal" onClick={(event) => event.stopPropagation()}>
                  <div className="modal-header">
                    <h3>Nuevo hallazgo</h3>
                    <button className="btn btn-secondary" type="button" onClick={() => setShowFindingModal(false)}>Cerrar</button>
                  </div>
                  <div className="modal-tabs">
                    <button
                      type="button"
                      className={findingModalTab === "manual" ? "active" : ""}
                      onClick={() => setFindingModalTab("manual")}
                    >
                      Manual
                    </button>
                    <button
                      type="button"
                      className={findingModalTab === "templates" ? "active" : ""}
                      onClick={() => setFindingModalTab("templates")}
                    >
                      Plantillas
                    </button>
                  </div>
                  {findingModalTab === "manual" && (
                    <form className="modal-form" onSubmit={handleManualFindingSubmit}>
                      <div className="form-group full findings-catalog-search">
                        <label className="form-label">Buscar en catalogo</label>
                        <input
                          className="form-input"
                          type="text"
                          placeholder="🔍 Buscar CVE, CWE, nombre..."
                          value={vulnSearchQuery}
                          onChange={(event) => {
                            setVulnSearchQuery(event.target.value);
                            setShowVulnDropdown(true);
                          }}
                          onFocus={() => setShowVulnDropdown(true)}
                          onBlur={() => {
                            setTimeout(() => setShowVulnDropdown(false), 150);
                          }}
                          onKeyDown={(event) => {
                            if (event.key === "Escape") {
                              setShowVulnDropdown(false);
                            }
                          }}
                        />
                        {vulnSearchQuery && showVulnDropdown && (
                          <div className="catalog-dropdown">
                            {vulnSearchLoading && <p className="catalog-dropdown-item">Buscando...</p>}
                            {!vulnSearchLoading && vulnSearchResults.length === 0 && (
                              <p className="catalog-dropdown-item">Sin resultados</p>
                            )}
                            {!vulnSearchLoading &&
                              vulnSearchResults.map((entry) => (
                                <button
                                  key={entry.id}
                                  type="button"
                                  className="catalog-dropdown-item"
                                  onClick={() => handleCatalogSelect(entry.id)}
                                >
                                  <span className="catalog-item-title">
                                    {entry.cve_id || entry.name}
                                  </span>
                                  <span className={`badge badge-${entry.severity || "info"}`}>
                                    {entry.severity || "info"}
                                  </span>
                                  {entry.base_score ? (
                                    <span className="catalog-item-score">{entry.base_score}</span>
                                  ) : null}
                                  {entry.exploit_available && <span className="catalog-item-flag">⚡</span>}
                                </button>
                              ))}
                          </div>
                        )}
                        {selectedCatalogEntry && (
                          <div className="catalog-selected-banner">
                            <span>✓ Datos cargados desde {selectedCatalogEntry.cve_id || selectedCatalogEntry.name}</span>
                            <button
                              className="btn btn-ghost btn-sm"
                              type="button"
                              onClick={() => setSelectedCatalogEntry(null)}
                            >
                              Desvincular
                            </button>
                          </div>
                        )}
                      </div>
                      <div className="form-group">
                        <label className="form-label">Activo</label>
                        <select className="form-select"
                          value={manualFindingForm.asset_id}
                          onChange={(event) =>
                            setManualFindingForm((prev) => ({ ...prev, asset_id: event.target.value }))
                          }
                          required
                        >
                          <option value="">Selecciona un activo</option>
                          {assets.map((asset) => (
                            <option key={asset.id} value={String(asset.id)}>
                              {asset.name}
                            </option>
                          ))}
                        </select>
                      </div>
                      <div className="form-group">
                        <label className="form-label">Severidad</label>
                        <select className="form-select"
                          value={manualFindingForm.severity}
                          onChange={(event) =>
                            setManualFindingForm((prev) => ({ ...prev, severity: event.target.value }))
                          }
                          required
                        >
                          <option value="critical">Crítica</option>
                          <option value="high">Alta</option>
                          <option value="medium">Media</option>
                          <option value="low">Baja</option>
                          <option value="info">Info</option>
                        </select>
                      </div>
                      <div className="form-group">
                        <label className="form-label">Estado</label>
                        <select className="form-select"
                          value={manualFindingForm.status}
                          onChange={(event) =>
                            setManualFindingForm((prev) => ({ ...prev, status: event.target.value }))
                          }
                        >
                          {statusOptions.map((status) => (
                            <option key={status} value={status}>
                              {statusLabels[status] || status}
                            </option>
                          ))}
                        </select>
                      </div>
                      <div className="form-group">
                        <label className="form-label">Título</label>
                        <input className="form-input"
                          type="text"
                          value={manualFindingForm.title}
                          onChange={(event) =>
                            setManualFindingForm((prev) => ({ ...prev, title: event.target.value }))
                          }
                          required
                        />
                      </div>
                      <div className="form-group">
                        <label className="form-label">CWE</label>
                        <input className="form-input"
                          type="text"
                          value={manualFindingForm.cwe}
                          onChange={(event) =>
                            setManualFindingForm((prev) => ({ ...prev, cwe: event.target.value }))
                          }
                        />
                      </div>
                      <div className="form-group">
                        <label className="form-label">OWASP</label>
                        <input className="form-input"
                          type="text"
                          value={manualFindingForm.owasp}
                          onChange={(event) =>
                            setManualFindingForm((prev) => ({ ...prev, owasp: event.target.value }))
                          }
                        />
                      </div>
                      <div className="form-group">
                        <label className="form-label">Asignar a</label>
                        <select className="form-select"
                          value={manualFindingForm.assignee_user_id}
                          onChange={(event) =>
                            setManualFindingForm((prev) => ({
                              ...prev,
                              assignee_user_id: event.target.value,
                            }))
                          }
                        >
                          <option value="">Sin asignar</option>
                          {members.map((member) => (
                            <option key={member.user_id} value={String(member.user_id)}>
                              {member.email}
                            </option>
                          ))}
                        </select>
                      </div>
                      <div className="form-group full">
                        <label className="form-label">Descripción</label>
                        <textarea className="form-textarea"
                          value={manualFindingForm.description}
                          onChange={(event) =>
                            setManualFindingForm((prev) => ({
                              ...prev,
                              description: event.target.value,
                            }))
                          }
                          rows={4}
                        />
                      </div>
                      {selectedCatalogEntry && (
                        <div className="form-group full catalog-detail-fields">
                          <div className="catalog-detail-row">
                            <label className="form-label">CVSS Vector</label>
                            <input
                              className="form-input"
                              type="text"
                              value={selectedCatalogEntry.cvss_vector || ""}
                              readOnly
                            />
                          </div>
                          <div className="catalog-detail-row">
                            <label className="form-label">Recomendación</label>
                            <textarea
                              className="form-textarea"
                              rows={2}
                              value={manualFindingForm.recommendation}
                              onChange={(event) =>
                                setManualFindingForm((prev) => ({
                                  ...prev,
                                  recommendation: event.target.value,
                                }))
                              }
                            />
                          </div>
                          <div className="catalog-detail-row">
                            <label className="form-label">Referencias</label>
                            <textarea
                              className="form-textarea"
                              rows={2}
                              value={manualFindingForm.references}
                              onChange={(event) =>
                                setManualFindingForm((prev) => ({
                                  ...prev,
                                  references: event.target.value,
                                }))
                              }
                            />
                          </div>
                          <div className="catalog-detail-row">
                            <label className="form-label">Exploit disponible</label>
                            <input
                              className="form-input"
                              type="text"
                              value={selectedCatalogEntry.exploit_available ? "Sí" : "No"}
                              readOnly
                            />
                          </div>
                        </div>
                      )}
                      <button className="btn btn-primary" type="submit">Guardar hallazgo</button>
                    </form>
                  )}
                  {findingModalTab === "templates" && (
                    <div className="template-panel">
                      <form className="modal-form" onSubmit={handleTemplateCreate}>
                        <div className="form-group">
                          <label className="form-label">Titulo</label>
                          <input className="form-input"
                            type="text"
                            value={templateForm.title}
                            onChange={(event) =>
                              setTemplateForm((prev) => ({ ...prev, title: event.target.value }))
                            }
                            required
                          />
                        </div>
                        <div className="form-group">
                          <label className="form-label">Severidad</label>
                          <select className="form-select"
                            value={templateForm.severity}
                            onChange={(event) =>
                              setTemplateForm((prev) => ({ ...prev, severity: event.target.value }))
                            }
                          >
                            <option value="critical">Crítica</option>
                            <option value="high">Alta</option>
                            <option value="medium">Media</option>
                            <option value="low">Baja</option>
                            <option value="info">Info</option>
                          </select>
                        </div>
                        <div className="form-group">
                          <label className="form-label">CWE</label>
                          <input className="form-input"
                            type="text"
                            value={templateForm.cwe}
                            onChange={(event) =>
                              setTemplateForm((prev) => ({ ...prev, cwe: event.target.value }))
                            }
                          />
                        </div>
                        <div className="form-group">
                          <label className="form-label">OWASP</label>
                          <input className="form-input"
                            type="text"
                            value={templateForm.owasp}
                            onChange={(event) =>
                              setTemplateForm((prev) => ({ ...prev, owasp: event.target.value }))
                            }
                          />
                        </div>
                        <div className="form-group full">
                          <label className="form-label">Descripcion</label>
                          <textarea className="form-textarea"
                            rows={3}
                            value={templateForm.description}
                            onChange={(event) =>
                              setTemplateForm((prev) => ({
                                ...prev,
                                description: event.target.value,
                              }))
                            }
                          />
                        </div>
                        <button className="btn btn-primary" type="submit">Guardar plantilla</button>
                      </form>
                      <div className="template-search">
                        <input className="form-input"
                          type="text"
                          placeholder="Buscar por titulo, CWE u OWASP"
                          value={findingTemplateQuery}
                          onChange={(event) => setFindingTemplateQuery(event.target.value)}
                        />
                      </div>
                      <div className="template-list">
                        {filteredTemplates.map((template) => (
                          <div key={template.id} className="template-card">
                            <div>
                              <strong>{template.title}</strong>
                              <p>{template.group}</p>
                              <span>{template.cwe || template.owasp || ""}</span>
                            </div>
                            <button className="btn btn-secondary" type="button" onClick={() => applyTemplate(template)}>
                              Usar
                            </button>
                          </div>
                        ))}
                        {filteredTemplates.length === 0 && (
                          <p className="comment-empty">Sin plantillas que coincidan.</p>
                        )}
                      </div>
                    </div>
                  )}
                </div>
              </div>
            )}

            {showImportWizard && (
              <div className="wizard-overlay" onClick={resetImportWizard}>
                <div className="wizard-modal import-wizard" onClick={(event) => event.stopPropagation()}>
                  <div className="wizard-header">
                    <h3>📥 Importar hallazgos</h3>
                    <button className="btn btn-ghost" type="button" onClick={resetImportWizard}>
                      ✕
                    </button>
                  </div>

                  <div className="wizard-stepper">
                    {[
                      { n: 1, label: "Archivo" },
                      { n: 2, label: "Mapeo" },
                      { n: 3, label: "Preview" },
                      { n: 4, label: "Resultado" },
                    ].map((step, index) => (
                      <Fragment key={step.n}>
                        {index > 0 && <div className="wizard-step-line"></div>}
                        <div
                          className={`wizard-step ${importStep >= step.n ? "wizard-step--active" : ""} ${
                            importStep > step.n ? "wizard-step--done" : ""
                          }`}
                        >
                          <span className="wizard-step-number">{step.n}</span>
                          <span className="wizard-step-label">{step.label}</span>
                        </div>
                      </Fragment>
                    ))}
                  </div>

                  <div className="wizard-body">
                    {importStep === 1 && (
                      <div className="wizard-panel">
                        <p className="wizard-instruction">Selecciona el archivo con los hallazgos a importar:</p>
                        <div className="import-template-actions">
                          <button
                            className="btn btn-ghost btn-sm"
                            type="button"
                            onClick={() => downloadImportTemplate("csv")}
                          >
                            ⬇️ Descargar plantilla CSV
                          </button>
                          <button
                            className="btn btn-ghost btn-sm"
                            type="button"
                            onClick={() => downloadImportTemplate("json")}
                          >
                            ⬇️ Descargar plantilla JSON
                          </button>
                          <button
                            className="btn btn-ghost btn-sm"
                            type="button"
                            onClick={() => downloadImportTemplate("xlsx")}
                          >
                            ⬇️ Descargar plantilla Excel
                          </button>
                        </div>
                        <div
                          className="import-dropzone"
                          onDragOver={(event) => {
                            event.preventDefault();
                            event.currentTarget.classList.add("import-dropzone--active");
                          }}
                          onDragLeave={(event) => {
                            event.currentTarget.classList.remove("import-dropzone--active");
                          }}
                          onDrop={(event) => {
                            event.preventDefault();
                            event.currentTarget.classList.remove("import-dropzone--active");
                            const file = event.dataTransfer.files[0];
                            if (file) {
                              setImportFile(file);
                              parseImportFile(file);
                            }
                          }}
                          onClick={() => document.getElementById("import-file-input").click()}
                        >
                          <input
                            id="import-file-input"
                            type="file"
                            hidden
                            accept=".csv,.json,.xlsx,.xls,.xml,.nessus,.sarif"
                            onChange={(event) => {
                              const file = event.target.files[0];
                              if (file) {
                                setImportFile(file);
                                parseImportFile(file);
                              }
                            }}
                          />
                          {!importFile ? (
                            <>
                              <svg className="import-dropzone-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
                                <polyline points="17 8 12 3 7 8" />
                                <line x1="12" y1="3" x2="12" y2="15" />
                              </svg>
                              <p>Arrastra un archivo o haz click para seleccionar</p>
                              <span className="import-dropzone-hint">
                                CSV, JSON, Excel, Nessus (.nessus), Burp XML, SARIF
                              </span>
                            </>
                          ) : (
                            <div className="import-file-info">
                              <span className="import-file-icon">
                                {importFormat === "csv" && "📄"}
                                {importFormat === "json" && "📋"}
                                {importFormat === "xlsx" && "📊"}
                                {importFormat === "nessus" && "🔒"}
                                {importFormat === "burp" && "🕷"}
                                {importFormat === "sarif" && "📄"}
                                {importFormat === "xml" && "📄"}
                              </span>
                              <div>
                                <span className="import-file-name">{importFile.name}</span>
                                <span className="import-file-meta">
                                  {(importFile.size / 1024).toFixed(1)} KB · Formato: {importFormat.toUpperCase()} ·{" "}
                                  {importRawData.length} registros detectados
                                </span>
                              </div>
                              <button
                                className="btn btn-ghost btn-sm"
                                type="button"
                                onClick={(event) => {
                                  event.stopPropagation();
                                  setImportFile(null);
                                  setImportRawData([]);
                                  setImportColumnMap({});
                                }}
                              >
                                ✕
                              </button>
                            </div>
                          )}
                        </div>

                        {importErrors.length > 0 && (
                          <div className="import-errors">
                            {importErrors.map((err, idx) => (
                              <p key={idx}>❌ {err}</p>
                            ))}
                          </div>
                        )}
                      </div>
                    )}

                    {importStep === 2 && (
                      <div className="wizard-panel">
                        <p className="wizard-instruction">
                          Verifica que las columnas esten mapeadas. Los campos con <strong>*</strong> son obligatorios.
                        </p>
                        <div className="import-mapping">
                          <h4 className="import-mapping-group">🔍 Datos del hallazgo</h4>
                          {Object.entries(IMPORT_FIELDS)
                            .filter(([, field]) => field.group === "hallazgo")
                            .map(([field, info]) => (
                              <div key={field} className="import-mapping-row">
                                <span className={`import-mapping-label ${info.required ? "import-mapping-label--required" : ""}`}>
                                  {info.label}
                                </span>
                                <select
                                  className="form-select import-mapping-select"
                                  value={
                                    Object.entries(importColumnMap).find(([, value]) => value === field)?.[0] || ""
                                  }
                                  onChange={(event) => {
                                    const newMap = { ...importColumnMap };
                                    Object.keys(newMap).forEach((key) => {
                                      if (newMap[key] === field) delete newMap[key];
                                    });
                                    if (event.target.value) newMap[event.target.value] = field;
                                    setImportColumnMap(newMap);
                                  }}
                                >
                                  <option value="">— No mapear —</option>
                                  {Object.keys(importRawData[0] || {}).map((col) => (
                                    <option key={col} value={col}>
                                      {col}
                                    </option>
                                  ))}
                                </select>
                                <span className="import-mapping-preview">
                                  {(() => {
                                    const col = Object.entries(importColumnMap).find(([, value]) => value === field)?.[0];
                                    return col && importRawData[0] ? importRawData[0][col] || "(vacio)" : "—";
                                  })()}
                                </span>
                              </div>
                            ))}

                          <h4 className="import-mapping-group">🖥 Datos del activo</h4>
                          {Object.entries(IMPORT_FIELDS)
                            .filter(([, field]) => field.group === "activo")
                            .map(([field, info]) => (
                              <div key={field} className="import-mapping-row">
                                <span className={`import-mapping-label ${info.required ? "import-mapping-label--required" : ""}`}>
                                  {info.label}
                                </span>
                                <select
                                  className="form-select import-mapping-select"
                                  value={
                                    Object.entries(importColumnMap).find(([, value]) => value === field)?.[0] || ""
                                  }
                                  onChange={(event) => {
                                    const newMap = { ...importColumnMap };
                                    Object.keys(newMap).forEach((key) => {
                                      if (newMap[key] === field) delete newMap[key];
                                    });
                                    if (event.target.value) newMap[event.target.value] = field;
                                    setImportColumnMap(newMap);
                                  }}
                                >
                                  <option value="">— No mapear —</option>
                                  {Object.keys(importRawData[0] || {}).map((col) => (
                                    <option key={col} value={col}>
                                      {col}
                                    </option>
                                  ))}
                                </select>
                                <span className="import-mapping-preview">
                                  {(() => {
                                    const col = Object.entries(importColumnMap).find(([, value]) => value === field)?.[0];
                                    return col && importRawData[0] ? importRawData[0][col] || "(vacio)" : "—";
                                  })()}
                                </span>
                              </div>
                            ))}

                          <h4 className="import-mapping-group">👤 Personas</h4>
                          {Object.entries(IMPORT_FIELDS)
                            .filter(([, field]) => field.group === "persona")
                            .map(([field, info]) => (
                              <div key={field} className="import-mapping-row">
                                <span className="import-mapping-label">{info.label}</span>
                                <select
                                  className="form-select import-mapping-select"
                                  value={
                                    Object.entries(importColumnMap).find(([, value]) => value === field)?.[0] || ""
                                  }
                                  onChange={(event) => {
                                    const newMap = { ...importColumnMap };
                                    Object.keys(newMap).forEach((key) => {
                                      if (newMap[key] === field) delete newMap[key];
                                    });
                                    if (event.target.value) newMap[event.target.value] = field;
                                    setImportColumnMap(newMap);
                                  }}
                                >
                                  <option value="">— No mapear —</option>
                                  {Object.keys(importRawData[0] || {}).map((col) => (
                                    <option key={col} value={col}>
                                      {col}
                                    </option>
                                  ))}
                                </select>
                                <span className="import-mapping-preview">
                                  {(() => {
                                    const col = Object.entries(importColumnMap).find(([, value]) => value === field)?.[0];
                                    return col && importRawData[0] ? importRawData[0][col] || "(vacio)" : "—";
                                  })()}
                                </span>
                              </div>
                            ))}
                        </div>

                        {!Object.values(importColumnMap).includes("asset_name") && (
                          <div className="import-default-asset">
                            <h4>⚠ Sin campo de activo</h4>
                            <p>
                              Tu archivo no tiene un campo de activo. Selecciona uno existente o se creara uno
                              generico:
                            </p>
                            <select
                              className="form-select"
                              value={importDefaultAssetId}
                              onChange={(event) => setImportDefaultAssetId(event.target.value)}
                            >
                              <option value="">Crear activo generico "Importacion {new Date().toISOString().split("T")[0]}"</option>
                              {assets.map((asset) => (
                                <option key={asset.id} value={asset.id}>
                                  {asset.name} — {asset.uri}
                                </option>
                              ))}
                            </select>
                          </div>
                        )}
                      </div>
                    )}

                    {importStep === 3 && (
                      <div className="wizard-panel">
                        <p className="wizard-instruction">Revisa lo que se va a importar:</p>
                        <div className="import-summary">
                          <div className="import-summary-item">
                            <span className="import-summary-value">{importPreview.findings.length}</span>
                            <span className="import-summary-label">Hallazgos</span>
                          </div>
                          <div className="import-summary-item import-summary-item--new">
                            <span className="import-summary-value">
                              {importPreview.assets.filter((asset) => !asset.exists).length}
                            </span>
                            <span className="import-summary-label">Activos nuevos</span>
                          </div>
                          <div className="import-summary-item import-summary-item--reuse">
                            <span className="import-summary-value">
                              {importPreview.assets.filter((asset) => asset.exists).length}
                            </span>
                            <span className="import-summary-label">Activos existentes</span>
                          </div>
                        </div>

                        <div className="import-severity-breakdown">
                          {["critical", "high", "medium", "low", "info"].map((sev) => {
                            const count = importPreview.findings.filter((finding) => finding.severity === sev).length;
                            return count > 0 ? (
                              <span key={sev} className={`badge badge-${sev}`}>
                                {count} {sev}
                              </span>
                            ) : null;
                          })}
                        </div>

                        <div className="import-preview-table-wrap">
                          <table className="import-preview-table">
                            <thead>
                              <tr>
                                <th>#</th>
                                <th>Titulo</th>
                                <th>Severidad</th>
                                <th>Activo</th>
                                <th>Estado</th>
                              </tr>
                            </thead>
                            <tbody>
                              {importPreview.findings.slice(0, 15).map((finding, idx) => (
                                <tr key={idx}>
                                  <td className="mono">{finding._row}</td>
                                  <td>{finding.title}</td>
                                  <td>
                                    <span className={`badge badge-${finding.severity}`}>{finding.severity}</span>
                                  </td>
                                  <td className="mono">{finding._assetName}</td>
                                  <td>{finding.status}</td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                          {importPreview.findings.length > 15 && (
                            <p className="import-preview-more">
                              ... y {importPreview.findings.length - 15} hallazgos mas
                            </p>
                          )}
                        </div>

                        {importPreview.assets.filter((asset) => !asset.exists).length > 0 && (
                          <div className="import-new-assets">
                            <h4>Se crearan estos activos nuevos:</h4>
                            <div className="import-new-assets-list">
                              {importPreview.assets
                                .filter((asset) => !asset.exists)
                                .map((asset, idx) => (
                                  <div key={idx} className="import-new-asset-item">
                                    <span className="import-new-asset-name">{asset.name}</span>
                                    <span className="import-new-asset-uri mono">{asset.uri}</span>
                                    <span className="badge badge-accent">{asset.type}</span>
                                  </div>
                                ))}
                            </div>
                          </div>
                        )}

                        {importErrors.length > 0 && (
                          <div className="import-warnings">
                            {importErrors.map((err, idx) => (
                              <p key={idx}>⚠️ {err}</p>
                            ))}
                          </div>
                        )}
                      </div>
                    )}

                    {importStep === 4 && importResult && (
                      <div className="wizard-panel">
                        <div
                          className={`import-result ${
                            importResult.errors.length > 0 ? "import-result--partial" : "import-result--success"
                          }`}
                        >
                          <div className="import-result-icon">{importResult.errors.length === 0 ? "✅" : "⚠️"}</div>
                          <h3>
                            {importResult.errors.length === 0
                              ? "Importacion exitosa"
                              : "Importacion completada con alertas"}
                          </h3>
                        </div>

                        <div className="import-result-stats">
                          <div className="import-result-stat">
                            <span className="import-result-stat-value">{importResult.findingsCreated}</span>
                            <span className="import-result-stat-label">Hallazgos creados</span>
                          </div>
                          <div className="import-result-stat">
                            <span className="import-result-stat-value">{importResult.assetsCreated}</span>
                            <span className="import-result-stat-label">Activos nuevos</span>
                          </div>
                          <div className="import-result-stat">
                            <span className="import-result-stat-value">{importResult.assetsReused}</span>
                            <span className="import-result-stat-label">Activos reutilizados</span>
                          </div>
                        </div>

                        {importResult.errors.length > 0 && (
                          <div className="import-result-errors">
                            <h4>Errores ({importResult.errors.length}):</h4>
                            <div className="import-result-error-list">
                              {importResult.errors.map((err, idx) => (
                                <p key={idx}>❌ {err}</p>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>
                    )}
                  </div>

                  <div className="wizard-footer">
                    {importStep > 1 && importStep < 4 && (
                      <button className="btn btn-secondary" type="button" onClick={() => setImportStep((prev) => prev - 1)}>
                        ← Atras
                      </button>
                    )}
                    <div className="wizard-footer-right">
                      <button className="btn btn-ghost" type="button" onClick={resetImportWizard}>
                        {importStep === 4 ? "Cerrar" : "Cancelar"}
                      </button>
                      {importStep === 1 && (
                        <button
                          className="btn btn-primary"
                          type="button"
                          disabled={!importFile || importRawData.length === 0}
                          onClick={() => setImportStep(2)}
                        >
                          Siguiente →
                        </button>
                      )}
                      {importStep === 2 && (
                        <button
                          className="btn btn-primary"
                          type="button"
                          onClick={() => {
                            generatePreview();
                            setImportStep(3);
                          }}
                        >
                          Ver preview →
                        </button>
                      )}
                      {importStep === 3 && (
                        <button
                          className="btn btn-primary"
                          type="button"
                          disabled={importLoading || importPreview.findings.length === 0}
                          onClick={executeImport}
                        >
                          {importLoading
                            ? "⏳ Importando..."
                            : `📥 Importar ${importPreview.findings.length} hallazgos`}
                        </button>
                      )}
                    </div>
                  </div>
                </div>
              </div>
            )}

            {showCatalogModal && (
              <div className="wizard-overlay" onClick={resetCatalogModal}>
                <div className="wizard-modal catalog-modal" onClick={(event) => event.stopPropagation()}>
                  <div className="wizard-header">
                    <h3>📚 Catalogo de vulnerabilidades</h3>
                    <button className="btn btn-ghost" type="button" onClick={resetCatalogModal}>
                      ✕
                    </button>
                  </div>

                  <div className="catalog-tabs">
                    <button
                      className={`catalog-tab ${catalogTab === "explore" ? "catalog-tab--active" : ""}`}
                      type="button"
                      onClick={() => setCatalogTab("explore")}
                    >
                      Explorar
                    </button>
                    <button
                      className={`catalog-tab ${catalogTab === "template" ? "catalog-tab--active" : ""}`}
                      type="button"
                      onClick={() => setCatalogTab("template")}
                    >
                      Nueva plantilla
                    </button>
                    <button
                      className={`catalog-tab ${catalogTab === "import" ? "catalog-tab--active" : ""}`}
                      type="button"
                      onClick={() => setCatalogTab("import")}
                    >
                      Importar JSONL
                    </button>
                  </div>

                  <div className="wizard-body">
                    {catalogTab === "explore" && (
                      <div className="catalog-explore">
                        {catalogStats && (
                          <div className="catalog-stats">
                            <div>
                              <span className="catalog-stat-value">{catalogStats.total}</span>
                              <span className="catalog-stat-label">Total</span>
                            </div>
                            <div>
                              <span className="catalog-stat-value">{catalogStats.exploit}</span>
                              <span className="catalog-stat-label">Exploit</span>
                            </div>
                            <div>
                              <span className="catalog-stat-value">{catalogStats.manual_templates}</span>
                              <span className="catalog-stat-label">Plantillas</span>
                            </div>
                          </div>
                        )}

                        <div className="form-group full">
                          <label className="form-label">Buscar</label>
                          <input
                            className="form-input"
                            type="text"
                            placeholder="CVE, nombre, CWE..."
                            value={catalogQuery}
                            onChange={(event) => setCatalogQuery(event.target.value)}
                          />
                        </div>

                        <div className="catalog-results">
                          {catalogLoading && <p className="text-muted">Buscando...</p>}
                          {!catalogLoading && catalogResults.length === 0 && (
                            <p className="text-muted">Sin resultados.</p>
                          )}
                          {!catalogLoading &&
                            catalogResults.map((entry) => (
                              <button
                                key={entry.id}
                                type="button"
                                className="catalog-result-card"
                                onClick={() => handleCatalogSelect(entry.id)}
                              >
                                <div>
                                  <strong>{entry.cve_id || entry.name}</strong>
                                  <p>{entry.description}</p>
                                </div>
                                <div className="catalog-result-meta">
                                  <span className={`badge badge-${entry.severity || "info"}`}>
                                    {entry.severity || "info"}
                                  </span>
                                  {entry.base_score && (
                                    <span className="catalog-result-score">{entry.base_score}</span>
                                  )}
                                  {entry.exploit_available && <span>⚡</span>}
                                </div>
                              </button>
                            ))}
                        </div>

                        {catalogDetail && (
                          <div className="catalog-detail">
                            <div className="catalog-detail-header">
                              <div>
                                <h4>{catalogDetail.name}</h4>
                                <span className="catalog-detail-sub">
                                  {catalogDetail.cve_id || ""} {catalogDetail.cwe_name ? `· ${catalogDetail.cwe_name}` : ""}
                                </span>
                              </div>
                              <button
                                className="btn btn-secondary btn-sm"
                                type="button"
                                onClick={() => {
                                  setShowFindingModal(true);
                                  setFindingModalTab("manual");
                                  handleCatalogSelect(catalogDetail.id);
                                }}
                              >
                                Usar en hallazgo
                              </button>
                            </div>
                            <p className="catalog-detail-desc">{catalogDetail.description}</p>
                            {catalogDetail.recommendation && (
                              <div className="catalog-detail-block">
                                <h5>Recomendacion</h5>
                                <p>{catalogDetail.recommendation}</p>
                              </div>
                            )}
                            {catalogDetail.references && (
                              <div className="catalog-detail-block">
                                <h5>Referencias</h5>
                                <pre>{catalogDetail.references}</pre>
                              </div>
                            )}
                          </div>
                        )}
                      </div>
                    )}

                    {catalogTab === "template" && (
                      <form className="catalog-template" onSubmit={handleCatalogTemplateSubmit}>
                        <div className="form-group">
                          <label className="form-label">Titulo</label>
                          <input
                            className="form-input"
                            type="text"
                            value={catalogTemplateForm.name}
                            onChange={(event) =>
                              setCatalogTemplateForm((prev) => ({ ...prev, name: event.target.value }))
                            }
                            required
                          />
                        </div>
                        <div className="form-group">
                          <label className="form-label">CVE (opcional)</label>
                          <input
                            className="form-input"
                            type="text"
                            value={catalogTemplateForm.cve_id}
                            onChange={(event) =>
                              setCatalogTemplateForm((prev) => ({ ...prev, cve_id: event.target.value }))
                            }
                          />
                        </div>
                        <div className="form-group">
                          <label className="form-label">Severidad</label>
                          <select
                            className="form-select"
                            value={catalogTemplateForm.severity}
                            onChange={(event) =>
                              setCatalogTemplateForm((prev) => ({ ...prev, severity: event.target.value }))
                            }
                          >
                            <option value="critical">Crítica</option>
                            <option value="high">Alta</option>
                            <option value="medium">Media</option>
                            <option value="low">Baja</option>
                            <option value="info">Info</option>
                          </select>
                        </div>
                        <div className="form-group">
                          <label className="form-label">CVSS Score</label>
                          <input
                            className="form-input"
                            type="number"
                            step="0.1"
                            value={catalogTemplateForm.base_score}
                            onChange={(event) =>
                              setCatalogTemplateForm((prev) => ({ ...prev, base_score: event.target.value }))
                            }
                          />
                        </div>
                        <div className="form-group">
                          <label className="form-label">CVSS Vector</label>
                          <input
                            className="form-input"
                            type="text"
                            value={catalogTemplateForm.cvss_vector}
                            onChange={(event) =>
                              setCatalogTemplateForm((prev) => ({ ...prev, cvss_vector: event.target.value }))
                            }
                          />
                        </div>
                        <div className="form-group">
                          <label className="form-label">CWE ID</label>
                          <input
                            className="form-input"
                            type="number"
                            value={catalogTemplateForm.cwe_id}
                            onChange={(event) =>
                              setCatalogTemplateForm((prev) => ({ ...prev, cwe_id: event.target.value }))
                            }
                          />
                        </div>
                        <div className="form-group">
                          <label className="form-label">CWE Nombre</label>
                          <input
                            className="form-input"
                            type="text"
                            value={catalogTemplateForm.cwe_name}
                            onChange={(event) =>
                              setCatalogTemplateForm((prev) => ({ ...prev, cwe_name: event.target.value }))
                            }
                          />
                        </div>
                        <div className="form-group full">
                          <label className="form-label">Descripcion</label>
                          <textarea
                            className="form-textarea"
                            rows={4}
                            value={catalogTemplateForm.description}
                            onChange={(event) =>
                              setCatalogTemplateForm((prev) => ({ ...prev, description: event.target.value }))
                            }
                          />
                        </div>
                        <div className="form-group full">
                          <label className="form-label">Recomendacion</label>
                          <textarea
                            className="form-textarea"
                            rows={3}
                            value={catalogTemplateForm.recommendation}
                            onChange={(event) =>
                              setCatalogTemplateForm((prev) => ({ ...prev, recommendation: event.target.value }))
                            }
                          />
                        </div>
                        <div className="form-group full">
                          <label className="form-label">Referencias</label>
                          <textarea
                            className="form-textarea"
                            rows={3}
                            value={catalogTemplateForm.references}
                            onChange={(event) =>
                              setCatalogTemplateForm((prev) => ({ ...prev, references: event.target.value }))
                            }
                          />
                        </div>
                        <div className="form-group">
                          <label className="form-label">Exploit disponible</label>
                          <select
                            className="form-select"
                            value={catalogTemplateForm.exploit_available ? "yes" : "no"}
                            onChange={(event) =>
                              setCatalogTemplateForm((prev) => ({
                                ...prev,
                                exploit_available: event.target.value === "yes",
                              }))
                            }
                          >
                            <option value="no">No</option>
                            <option value="yes">Sí</option>
                          </select>
                        </div>
                        <div className="catalog-template-actions">
                          <button className="btn btn-primary" type="submit">
                            Guardar plantilla
                          </button>
                        </div>
                      </form>
                    )}

                    {catalogTab === "import" && (
                      <div className="catalog-import">
                        <div className="form-group full">
                          <label className="form-label">Archivo JSONL</label>
                          <input
                            className="form-input"
                            type="file"
                            accept=".jsonl"
                            onChange={(event) => setCatalogImportFile(event.target.files?.[0] || null)}
                          />
                        </div>
                        {catalogImportError && <p className="text-error">{catalogImportError}</p>}
                        {catalogImportResult && (
                          <div className="catalog-import-result">
                            <p>Importados: {catalogImportResult.imported}</p>
                            <p>Actualizados: {catalogImportResult.updated}</p>
                            <p>Omitidos: {catalogImportResult.skipped}</p>
                          </div>
                        )}
                        <button
                          className="btn btn-primary"
                          type="button"
                          disabled={!catalogImportFile || catalogImportLoading}
                          onClick={handleCatalogImport}
                        >
                          {catalogImportLoading ? "⏳ Importando..." : "Importar"}
                        </button>
                      </div>
                    )}
                  </div>
                </div>
              </div>
            )}
          </section>
          )}

          {projectId && activeSection === "activos" && (
            <section className={`assets ${selectedAsset ? "has-drawer" : ""}`}>
            <div className="assets-header">
              <div>
                <div className="assets-title">
                  <svg className="assets-title-icon" viewBox="0 0 24 24" aria-hidden="true">
                    <rect x="3" y="4" width="18" height="12" rx="2" fill="none" stroke="currentColor" strokeWidth="1.5" />
                    <path d="M8 20h8" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
                  </svg>
                  <h2 className="page-title">Activos</h2>
                </div>
                <p className="page-description">Inventario de activos del proyecto</p>
              </div>
              <div className="assets-header-actions">
                <span className="badge badge-accent">{filteredAssets.length} registrados</span>
                <button className="btn btn-primary" type="button" onClick={openNewAssetModal}>
                  + Nuevo activo
                </button>
              </div>
            </div>

            <div className="card assets-filters">
              <div className="form-group">
                <label className="form-label">Tipo</label>
                <select
                  className="form-select"
                  value={assetTypeFilter}
                  onChange={(event) => setAssetTypeFilter(event.target.value)}
                >
                  <option value="all">Todos</option>
                  <option value="web_app">Web</option>
                  <option value="api">API</option>
                  <option value="repo">Repositorio</option>
                  <option value="host">Host</option>
                  <option value="container">Contenedor</option>
                  <option value="network_range">Rango de red</option>
                </select>
              </div>
              <div className="form-group">
                <label className="form-label">Entorno</label>
                <select
                  className="form-select"
                  value={assetEnvFilter}
                  onChange={(event) => setAssetEnvFilter(event.target.value)}
                >
                  <option value="all">Todos</option>
                  <option value="prod">Producción</option>
                  <option value="stage">Staging</option>
                  <option value="dev">Desarrollo</option>
                </select>
              </div>
              <div className="form-group">
                <label className="form-label">Criticidad</label>
                <select
                  className="form-select"
                  value={assetCritFilter}
                  onChange={(event) => setAssetCritFilter(event.target.value)}
                >
                  <option value="all">Todas</option>
                  <option value="alta">Alta</option>
                  <option value="media">Media</option>
                  <option value="baja">Baja</option>
                </select>
              </div>
              <div className="form-group">
                <label className="form-label">Buscar</label>
                <input
                  className="form-input"
                  type="text"
                  placeholder="nombre, URL, tags, responsable"
                  value={assetSearch}
                  onChange={(event) => setAssetSearch(event.target.value)}
                />
              </div>
            </div>

            <div className="table-container">
              <table className="table assets-table">
                <thead>
                  <tr>
                    <th>Nombre</th>
                    <th>Tipo</th>
                    <th>URI</th>
                    <th>Responsable</th>
                    <th>Entorno</th>
                    <th>Criticidad</th>
                    <th>Tags</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredAssets.map((asset) => {
                    const tags = Array.isArray(asset.tags) ? asset.tags : [];
                    return (
                      <tr
                        key={asset.id}
                        className={`assets-row ${selectedAsset?.id === asset.id ? "assets-row--active" : ""}`}
                        onClick={() => setSelectedAsset(asset)}
                      >
                        <td className="assets-name">
                          <span className="assets-name-icon">{renderAssetTypeIcon(asset.type)}</span>
                          <span className="assets-name-text">{asset.name}</span>
                        </td>
                        <td>
                          <span className="badge badge-accent">
                            {assetTypeLabels[asset.type] || asset.type}
                          </span>
                        </td>
                        <td className="assets-uri">
                          <span className="file-path">{asset.uri}</span>
                        </td>
                        <td>{asset.owner_email || "—"}</td>
                        <td>
                          <span className={`assets-env assets-env--${asset.environment}`}>
                            {envLabels[asset.environment] || asset.environment || "—"}
                          </span>
                        </td>
                        <td>
                          <span className={`badge badge-${criticalityToBadge(asset.criticality)}`}>
                            {asset.criticality || "—"}
                          </span>
                        </td>
                        <td className="assets-tags">
                          {tags.slice(0, 3).map((tag) => (
                            <span key={tag} className="assets-tag">{tag}</span>
                          ))}
                          {tags.length > 3 && (
                            <span className="assets-tag assets-tag--more">+{tags.length - 3}</span>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
              {filteredAssets.length === 0 && (
                <div className="empty-state">
                  <h3>No se encontraron activos</h3>
                  <p>Registra un nuevo activo para comenzar a monitorear vulnerabilidades.</p>
                  <button className="btn btn-primary" type="button" onClick={openNewAssetModal}>
                    + Nuevo activo
                  </button>
                </div>
              )}
            </div>

            {selectedAsset && (
              <aside className="assets-drawer">
                <div className="assets-drawer-header">
                  <div>
                    <span className="assets-drawer-type-icon">
                      {renderAssetTypeIcon(selectedAsset.type)}
                    </span>
                    <h3 className="assets-drawer-title">{selectedAsset.name}</h3>
                    <span className={`badge badge-${criticalityToBadge(selectedAsset.criticality)}`}>
                      {selectedAsset.criticality || "Sin clasificar"}
                    </span>
                  </div>
                  <button className="btn btn-ghost btn-sm" type="button" onClick={() => setSelectedAsset(null)}>✕</button>
                </div>

                <div className="assets-drawer-body">
                  <div className="assets-meta-grid">
                    <div className="assets-meta-item">
                      <span className="assets-meta-label">Tipo</span>
                      <span className="badge badge-accent">
                        {assetTypeLabels[selectedAsset.type] || selectedAsset.type}
                      </span>
                    </div>
                    <div className="assets-meta-item">
                      <span className="assets-meta-label">Entorno</span>
                      <span className={`assets-env assets-env--${selectedAsset.environment}`}>
                        {envLabels[selectedAsset.environment] || "—"}
                      </span>
                    </div>
                    <div className="assets-meta-item assets-meta-item--full">
                      <span className="assets-meta-label">URI</span>
                      <span className="file-path">{selectedAsset.uri}</span>
                    </div>
                    <div className="assets-meta-item assets-meta-item--full">
                      <span className="assets-meta-label">Responsable</span>
                      <span>{selectedAsset.owner_email || "—"}</span>
                    </div>
                    <div className="assets-meta-item assets-meta-item--full">
                      <span className="assets-meta-label">Tags</span>
                      <div className="assets-tags">
                        {Array.isArray(selectedAsset.tags) && selectedAsset.tags.length > 0 ? (
                          selectedAsset.tags.map((tag) => (
                            <span key={tag} className="assets-tag">{tag}</span>
                          ))
                        ) : (
                          <span className="assets-text-muted">Sin tags</span>
                        )}
                      </div>
                    </div>
                  </div>

                  <div className="assets-findings-summary">
                    <h4>Hallazgos vinculados</h4>
                    {(() => {
                      const assetFindings = findings.filter((finding) => finding.asset_id === selectedAsset.id);
                      if (assetFindings.length === 0) {
                        return <p className="assets-text-muted">Sin hallazgos registrados</p>;
                      }
                      const bySeverity = {};
                      assetFindings.forEach((finding) => {
                        const key = finding.severity || "info";
                        bySeverity[key] = (bySeverity[key] || 0) + 1;
                      });
                      return (
                        <div className="assets-findings-badges">
                          <span className="assets-findings-total">{assetFindings.length} total</span>
                          {Object.entries(bySeverity).map(([severity, count]) => (
                            <span key={severity} className={`badge badge-${severity}`}>
                              {count} {severityLabels[severity] || severity}
                            </span>
                          ))}
                        </div>
                      );
                    })()}
                  </div>

                  <div className="assets-drawer-actions">
                    <button className="btn btn-secondary" type="button" onClick={() => handleEditAsset(selectedAsset)}>
                      Editar activo
                    </button>
                    <button
                      className="btn btn-danger"
                      type="button"
                      onClick={() => handleDeleteAsset(selectedAsset.id)}
                    >
                      Eliminar
                    </button>
                  </div>
                </div>
              </aside>
            )}

            {showAssetModal && (
              <div className="modal-overlay" onClick={closeAssetModal}>
                <div className="modal" onClick={(event) => event.stopPropagation()}>
                  <div className="modal-header">
                    <h3>{assetEditTarget ? "Editar activo" : "Nuevo activo"}</h3>
                    <button className="btn btn-ghost" type="button" onClick={closeAssetModal}>✕</button>
                  </div>
                  <form className="modal-form" onSubmit={assetEditTarget ? handleUpdateAsset : handleCreateAsset}>
                    <div className="form-group">
                      <label className="form-label">Nombre del activo *</label>
                      <input
                        className="form-input"
                        type="text"
                        placeholder="ej: api-produccion, web-corporativa"
                        value={assetForm.name}
                        onChange={(event) => setAssetForm({ ...assetForm, name: event.target.value })}
                        required
                      />
                    </div>
                    <div className="form-group">
                      <label className="form-label">Tipo *</label>
                      <select
                        className="form-select"
                        value={assetForm.type}
                        onChange={(event) => setAssetForm({ ...assetForm, type: event.target.value })}
                      >
                        <option value="web_app">Web App</option>
                        <option value="api">API</option>
                        <option value="repo">Repositorio</option>
                        <option value="host">Host</option>
                        <option value="container">Contenedor</option>
                        <option value="network_range">Rango de red</option>
                      </select>
                    </div>
                    <div className="form-group full">
                      <label className="form-label">URL/URI principal *</label>
                      <input
                        className="form-input"
                        type="text"
                        placeholder="https://api.empresa.com o 192.168.1.0/24"
                        value={assetForm.uri}
                        onChange={(event) => setAssetForm({ ...assetForm, uri: event.target.value })}
                        required
                      />
                    </div>
                    <div className="form-group full">
                      <label className="form-label">Correo responsable *</label>
                      <input
                        className="form-input"
                        type="email"
                        placeholder="responsable@empresa.com"
                        value={assetForm.ownerEmail}
                        onChange={(event) => setAssetForm({ ...assetForm, ownerEmail: event.target.value })}
                        required
                      />
                    </div>
                    <div className="form-group">
                      <label className="form-label">Entorno</label>
                      <select
                        className="form-select"
                        value={assetForm.environment}
                        onChange={(event) => setAssetForm({ ...assetForm, environment: event.target.value })}
                      >
                        <option value="prod">Producción</option>
                        <option value="stage">Staging</option>
                        <option value="dev">Desarrollo</option>
                      </select>
                    </div>
                    <div className="form-group">
                      <label className="form-label">Criticidad</label>
                      <select
                        className="form-select"
                        value={assetForm.criticality}
                        onChange={(event) => setAssetForm({ ...assetForm, criticality: event.target.value })}
                      >
                        <option value="alta">Alta</option>
                        <option value="media">Media</option>
                        <option value="baja">Baja</option>
                      </select>
                    </div>
                    <div className="form-group full">
                      <label className="form-label">Tags</label>
                      <input
                        className="form-input"
                        type="text"
                        placeholder="frontend, legacy, cloud (separados por coma)"
                        value={assetForm.tags}
                        onChange={(event) => setAssetForm({ ...assetForm, tags: event.target.value })}
                      />
                      <span className="form-hint">Etiquetas para organizar y filtrar activos</span>
                    </div>
                    <div className="modal-form-actions full">
                      <button className="btn btn-secondary" type="button" onClick={closeAssetModal}>
                        Cancelar
                      </button>
                      <button className="btn btn-primary" type="submit">
                        {assetEditTarget ? "Guardar cambios" : "Guardar activo"}
                      </button>
                    </div>
                  </form>
                </div>
              </div>
            )}
          </section>
          )}

          {projectId && activeSection === "equipo" && (
            <section className="users-section">
              <div className="users-header">
                <div className="users-header-info">
                  <h2 className="users-title">
                    <svg
                      className="users-title-icon"
                      viewBox="0 0 24 24"
                      fill="none"
                      stroke="currentColor"
                      strokeWidth="2"
                      strokeLinecap="round"
                      strokeLinejoin="round"
                    >
                      <path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4-4v2" />
                      <circle cx="9" cy="7" r="4" />
                      <path d="M23 21v-2a4 4 0 00-3-3.87" />
                      <path d="M16 3.13a4 4 0 010 7.75" />
                    </svg>
                    Usuarios
                  </h2>
                  <p className="users-subtitle">Gestión de accesos y permisos del proyecto</p>
                </div>
                <div className="users-header-actions">
                  <span className="badge badge-accent">{members.length} miembros</span>
                  <button
                    className="btn btn-primary"
                    onClick={() => {
                      setShowUserModal(true);
                      setUserModalTab("existing");
                    }}
                  >
                    + Añadir usuario
                  </button>
                </div>
              </div>

              <div className="users-kpis">
                <div className="users-kpi">
                  <span className="users-kpi-icon">👥</span>
                  <span className="users-kpi-value">{members.length}</span>
                  <span className="users-kpi-label">Miembros</span>
                </div>
                <div className="users-kpi">
                  <span className="users-kpi-icon">🛡</span>
                  <span className="users-kpi-value">
                    {members.filter((member) => member.role === "admin" || member.role === "owner").length}
                  </span>
                  <span className="users-kpi-label">Admins</span>
                </div>
                <div className="users-kpi">
                  <span className="users-kpi-icon">📧</span>
                  <span className="users-kpi-value">{invites.filter((invite) => !invite.disabled).length}</span>
                  <span className="users-kpi-label">Invitaciones</span>
                </div>
                <div className="users-kpi">
                  <span className="users-kpi-icon">📊</span>
                  <span className="users-kpi-value">
                    {members.filter((member) => member.role === "analyst").length}
                  </span>
                  <span className="users-kpi-label">Analistas</span>
                </div>
              </div>

              <div className="users-tabs">
                <button
                  className={`users-tab ${usersTab === "members" ? "users-tab--active" : ""}`}
                  onClick={() => setUsersTab("members")}
                >
                  Miembros
                  <span className="users-tab-count">{members.length}</span>
                </button>
                <button
                  className={`users-tab ${usersTab === "invites" ? "users-tab--active" : ""}`}
                  onClick={() => setUsersTab("invites")}
                >
                  Invitaciones
                  <span className="users-tab-count">{invites.filter((invite) => !invite.disabled).length}</span>
                </button>
                <button
                  className={`users-tab ${usersTab === "roles" ? "users-tab--active" : ""}`}
                  onClick={() => setUsersTab("roles")}
                >
                  Roles y permisos
                </button>
              </div>

              {usersTab === "members" && (
                <div className="users-panel">
                  <div className="users-filters">
                    <div className="form-group">
                      <label className="form-label">Rol</label>
                      <select
                        className="form-select"
                        value={memberFilters.role}
                        onChange={(event) =>
                          setMemberFilters((prev) => ({ ...prev, role: event.target.value }))
                        }
                      >
                        <option value="all">Todos</option>
                        <option value="owner">Propietario</option>
                        <option value="admin">Admin</option>
                        <option value="analyst">Analista</option>
                        <option value="auditor">Auditor</option>
                        <option value="viewer">Viewer</option>
                        <option value="member">Miembro</option>
                      </select>
                    </div>
                    <div className="form-group users-filter-search">
                      <label className="form-label">Buscar</label>
                      <input
                        className="form-input"
                        type="text"
                        placeholder="correo electrónico..."
                        value={memberFilters.search}
                        onChange={(event) =>
                          setMemberFilters((prev) => ({ ...prev, search: event.target.value }))
                        }
                      />
                    </div>
                  </div>

                  <div className="users-table-wrap">
                    <table className="users-table">
                      <thead>
                        <tr>
                          <th>Usuario</th>
                          <th>Rol</th>
                          <th>Cambiar rol</th>
                          <th></th>
                        </tr>
                      </thead>
                      <tbody>
                        {filteredMembers.map((member) => {
                          const roleInfo = roleOptions.find((role) => role.value === member.role) || {
                            icon: "👤",
                            label: member.role,
                          };
                          return (
                            <tr key={member.id} className="users-row">
                              <td className="users-cell-user">
                                <div className="users-avatar">
                                  {member.email.charAt(0).toUpperCase()}
                                </div>
                                <div className="users-user-info">
                                  <span className="users-user-email">{member.email}</span>
                                  <span className="users-user-id">ID: {member.user_id}</span>
                                </div>
                              </td>
                              <td>
                                <span
                                  className="users-role-badge"
                                  style={{
                                    color: roleColors[member.role]?.color || "#94a3b8",
                                    background: roleColors[member.role]?.bg || "rgba(148, 163, 184, 0.1)",
                                  }}
                                >
                                  {roleInfo.icon} {roleInfo.label}
                                </span>
                              </td>
                              <td>
                                <select
                                  className="form-select users-role-select"
                                  value={member.role}
                                  onChange={(event) => handleUpdateMemberRole(member.id, event.target.value)}
                                >
                                  <option value="owner">Propietario</option>
                                  <option value="admin">Admin</option>
                                  <option value="analyst">Analista</option>
                                  <option value="auditor">Auditor</option>
                                  <option value="viewer">Viewer</option>
                                  <option value="member">Miembro</option>
                                </select>
                              </td>
                              <td className="users-cell-actions">
                                <button
                                  className="users-action-btn users-action-btn--danger"
                                  title="Eliminar miembro"
                                  onClick={() => {
                                    if (window.confirm(`¿Eliminar a ${member.email} del proyecto?`)) {
                                      handleRemoveMember(member.id);
                                    }
                                  }}
                                >
                                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                    <path d="M3 6h18M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6m3 0V4a2 2 0 012-2h4a2 2 0 012 2v2" />
                                  </svg>
                                </button>
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                    {filteredMembers.length === 0 && (
                      <div className="users-empty">
                        <p>No hay miembros que coincidan con el filtro.</p>
                      </div>
                    )}
                  </div>
                </div>
              )}

              {usersTab === "invites" && (
                <div className="users-panel">
                  <div className="users-filters">
                    <div className="form-group users-filter-search">
                      <label className="form-label">Buscar</label>
                      <input
                        className="form-input"
                        type="text"
                        placeholder="correo electrónico..."
                        value={inviteFilters.search}
                        onChange={(event) =>
                          setInviteFilters((prev) => ({ ...prev, search: event.target.value }))
                        }
                      />
                    </div>
                    <label className="users-filter-toggle">
                      <input
                        type="checkbox"
                        checked={inviteFilters.showDisabled}
                        onChange={() =>
                          setInviteFilters((prev) => ({ ...prev, showDisabled: !prev.showDisabled }))
                        }
                      />
                      <span>Mostrar deshabilitadas</span>
                    </label>
                  </div>

                  <div className="users-table-wrap">
                    <table className="users-table">
                      <thead>
                        <tr>
                          <th>Correo</th>
                          <th>Rol</th>
                          <th>Estado</th>
                          <th>Link</th>
                          <th></th>
                        </tr>
                      </thead>
                      <tbody>
                        {filteredInvites.map((invite) => (
                          <tr key={invite.id} className={`users-row ${invite.disabled ? "users-row--disabled" : ""}`}>
                            <td className="users-cell-user">
                              <div className="users-avatar users-avatar--invite">
                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                  <path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z" />
                                  <polyline points="22,6 12,13 2,6" />
                                </svg>
                              </div>
                              <span className="users-user-email">{invite.email}</span>
                            </td>
                            <td>
                              <span
                                className="users-role-badge"
                                style={{
                                  color: roleColors[invite.role]?.color || "#94a3b8",
                                  background: roleColors[invite.role]?.bg || "rgba(148, 163, 184, 0.1)",
                                }}
                              >
                                {(roleOptions.find((role) => role.value === invite.role) || {}).icon || "👤"}{" "}
                                {(roleOptions.find((role) => role.value === invite.role) || {}).label || invite.role}
                              </span>
                            </td>
                            <td>
                              <span
                                className={`users-invite-status ${
                                  invite.disabled ? "users-invite-status--disabled" : "users-invite-status--active"
                                }`}
                              >
                                <span className="users-invite-dot"></span>
                                {invite.disabled ? "Inactiva" : "Activa"}
                              </span>
                            </td>
                            <td>
                              <button
                                className="btn btn-ghost btn-sm"
                                onClick={() => handleCopyInviteLink(invite)}
                                title="Copiar link de invitación"
                              >
                                📋 Copiar
                              </button>
                            </td>
                            <td className="users-cell-actions">
                              <button
                                className={`users-action-btn ${invite.disabled ? "" : "users-action-btn--warning"}`}
                                title={invite.disabled ? "Habilitar invitación" : "Deshabilitar invitación"}
                                onClick={() => handleDisableInvite(invite.id, !invite.disabled)}
                              >
                                {invite.disabled ? (
                                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                    <polygon points="5 3 19 12 5 21 5 3" />
                                  </svg>
                                ) : (
                                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                    <rect x="6" y="4" width="4" height="16" />
                                    <rect x="14" y="4" width="4" height="16" />
                                  </svg>
                                )}
                              </button>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                    {filteredInvites.length === 0 && (
                      <div className="users-empty">
                        <p>No hay invitaciones {inviteFilters.showDisabled ? "" : "activas"}.</p>
                        <button
                          className="btn btn-primary btn-sm"
                          onClick={() => {
                            setShowUserModal(true);
                            setUserModalTab("invite");
                          }}
                        >
                          📧 Crear invitación
                        </button>
                      </div>
                    )}
                  </div>
                </div>
              )}

              {usersTab === "roles" && (
                <div className="users-panel">
                  <p className="users-roles-description">
                    Matriz de permisos por rol. Define qué puede hacer cada tipo de usuario en el proyecto.
                  </p>
                  <div className="users-table-wrap">
                    <table className="users-table users-roles-table">
                      <thead>
                        <tr>
                          <th>Rol</th>
                          <th>Hallazgos</th>
                          <th>Activos</th>
                          <th>Escaneos</th>
                          <th>Usuarios</th>
                          <th>Auditoría</th>
                        </tr>
                      </thead>
                      <tbody>
                        <tr className="users-row">
                          <td>
                            <span
                              className="users-role-badge"
                              style={{ color: roleColors.owner.color, background: roleColors.owner.bg }}
                            >
                              👑 Propietario
                            </span>
                          </td>
                          <td><span className="users-perm users-perm--full">✓ Total</span></td>
                          <td><span className="users-perm users-perm--full">✓ Total</span></td>
                          <td><span className="users-perm users-perm--full">✓ Total</span></td>
                          <td><span className="users-perm users-perm--full">✓ Total</span></td>
                          <td><span className="users-perm users-perm--full">✓ Total</span></td>
                        </tr>
                        <tr className="users-row">
                          <td>
                            <span
                              className="users-role-badge"
                              style={{ color: roleColors.admin.color, background: roleColors.admin.bg }}
                            >
                              🛡 Admin
                            </span>
                          </td>
                          <td><span className="users-perm users-perm--full">✓ Total</span></td>
                          <td><span className="users-perm users-perm--full">✓ Total</span></td>
                          <td><span className="users-perm users-perm--full">✓ Total</span></td>
                          <td><span className="users-perm users-perm--full">✓ Total</span></td>
                          <td><span className="users-perm users-perm--full">✓ Total</span></td>
                        </tr>
                        <tr className="users-row">
                          <td>
                            <span
                              className="users-role-badge"
                              style={{ color: roleColors.analyst.color, background: roleColors.analyst.bg }}
                            >
                              📊 Analista
                            </span>
                          </td>
                          <td><span className="users-perm users-perm--full">✓ Total</span></td>
                          <td><span className="users-perm users-perm--full">✓ Total</span></td>
                          <td><span className="users-perm users-perm--full">✓ Total</span></td>
                          <td><span className="users-perm users-perm--read">👁 Ver</span></td>
                          <td><span className="users-perm users-perm--read">👁 Ver</span></td>
                        </tr>
                        <tr className="users-row">
                          <td>
                            <span
                              className="users-role-badge"
                              style={{ color: roleColors.auditor.color, background: roleColors.auditor.bg }}
                            >
                              🔍 Auditor
                            </span>
                          </td>
                          <td><span className="users-perm users-perm--read">👁 Ver</span></td>
                          <td><span className="users-perm users-perm--read">👁 Ver</span></td>
                          <td><span className="users-perm users-perm--read">👁 Ver</span></td>
                          <td><span className="users-perm users-perm--none">✗ No</span></td>
                          <td><span className="users-perm users-perm--full">✓ Total</span></td>
                        </tr>
                        <tr className="users-row">
                          <td>
                            <span
                              className="users-role-badge"
                              style={{ color: roleColors.viewer.color, background: roleColors.viewer.bg }}
                            >
                              👁 Viewer
                            </span>
                          </td>
                          <td><span className="users-perm users-perm--read">👁 Ver</span></td>
                          <td><span className="users-perm users-perm--read">👁 Ver</span></td>
                          <td><span className="users-perm users-perm--read">👁 Ver</span></td>
                          <td><span className="users-perm users-perm--none">✗ No</span></td>
                          <td><span className="users-perm users-perm--none">✗ No</span></td>
                        </tr>
                      </tbody>
                    </table>
                  </div>
                  <div className="users-roles-note">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <circle cx="12" cy="12" r="10" />
                      <line x1="12" y1="8" x2="12" y2="12" />
                      <line x1="12" y1="16" x2="12.01" y2="16" />
                    </svg>
          <span>Los permisos se aplican a nivel de proyecto. El propietario del cliente siempre tiene acceso total.</span>
                  </div>
                </div>
              )}

              {showUserModal && (
                <div className="wizard-overlay" onClick={() => setShowUserModal(false)}>
                  <div className="wizard-modal" onClick={(event) => event.stopPropagation()} style={{ maxWidth: "520px" }}>
                    <div className="wizard-header">
                      <h3>Añadir usuario</h3>
                      <button className="btn btn-ghost" onClick={() => setShowUserModal(false)}>✕</button>
                    </div>

                    <div className="users-modal-tabs">
                      <button
                        className={`users-modal-tab ${userModalTab === "existing" ? "users-modal-tab--active" : ""}`}
                        onClick={() => setUserModalTab("existing")}
                      >
                        Agregar existente
                      </button>
                      <button
                        className={`users-modal-tab ${userModalTab === "invite" ? "users-modal-tab--active" : ""}`}
                        onClick={() => setUserModalTab("invite")}
                      >
                        Invitar por correo
                      </button>
                    </div>

                    {userModalTab === "existing" && (
                      <form className="users-modal-body" onSubmit={(event) => { handleAddMember(event); setShowUserModal(false); }}>
                        {availableUsers.length === 0 ? (
                          <div className="users-modal-empty">
                            <p>No hay usuarios registrados disponibles para agregar.</p>
                            <span className="form-hint">Usa la pestaña "Invitar por correo" para enviar una invitación.</span>
                          </div>
                        ) : (
                          <>
                            <p className="users-modal-instruction">Selecciona un usuario registrado:</p>
                            <div className="users-modal-user-list">
                              {availableUsers.map((user) => (
                                <div
                                  key={user.id}
                                  className={`users-modal-user-card ${selectedUserId === String(user.id) ? "users-modal-user-card--selected" : ""}`}
                                  onClick={() => setSelectedUserId(String(user.id))}
                                >
                                  <div className="users-avatar">{user.email.charAt(0).toUpperCase()}</div>
                                  <span className="users-modal-user-email">{user.email}</span>
                                  {selectedUserId === String(user.id) && (
                                    <svg className="users-modal-check" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3">
                                      <path d="M20 6L9 17l-5-5" />
                                    </svg>
                                  )}
                                </div>
                              ))}
                            </div>
                            <div className="form-group">
                              <label className="form-label">Rol</label>
                              <select className="form-select" value={newMemberRole} onChange={(event) => setNewMemberRole(event.target.value)}>
                                {roleOptions.map((role) => (
                                  <option key={role.value} value={role.value}>
                                    {role.icon} {role.label}
                                  </option>
                                ))}
                              </select>
                              <span className="form-hint">
                                {roleOptions.find((role) => role.value === newMemberRole)?.description}
                              </span>
                            </div>
                          </>
                        )}
                        <div className="users-modal-footer">
                          <button className="btn btn-ghost" type="button" onClick={() => setShowUserModal(false)}>
                            Cancelar
                          </button>
                          <button className="btn btn-primary" type="submit" disabled={!selectedUserId || availableUsers.length === 0}>
                            Agregar al proyecto
                          </button>
                        </div>
                      </form>
                    )}

                    {userModalTab === "invite" && (
                      <form className="users-modal-body" onSubmit={(event) => { handleInvite(event); setShowUserModal(false); }}>
                        <div className="form-group">
                          <label className="form-label">Correo electrónico</label>
                          <input
                            className="form-input"
                            type="email"
                            placeholder="usuario@empresa.com"
                            value={inviteEmail}
                            onChange={(event) => setInviteEmail(event.target.value)}
                            required
                          />
                        </div>
                        <div className="form-group">
                          <label className="form-label">Rol</label>
                          <select className="form-select" value={inviteRole} onChange={(event) => setInviteRole(event.target.value)}>
                            {roleOptions.map((role) => (
                              <option key={role.value} value={role.value}>
                                {role.icon} {role.label}
                              </option>
                            ))}
                          </select>
                          <span className="form-hint">
                            {roleOptions.find((role) => role.value === inviteRole)?.description}
                          </span>
                        </div>
                        <div className="users-modal-notice">
                          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                            <path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z" />
                            <polyline points="22,6 12,13 2,6" />
                          </svg>
                          <span>Se generará un link de invitación único para compartir con el usuario.</span>
                        </div>
                        <div className="users-modal-footer">
                          <button className="btn btn-ghost" type="button" onClick={() => setShowUserModal(false)}>
                            Cancelar
                          </button>
                          <button className="btn btn-primary" type="submit">📧 Crear invitación</button>
                        </div>
                      </form>
                    )}
                  </div>
                </div>
              )}
            </section>
          )}

          {projectId && activeSection === "escaneos" && (
          <section className="scans-section">
            <div className="scans-header">
              <div className="scans-header-info">
                <h2 className="scans-title">
                  <svg className="scans-title-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                    <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2" />
                  </svg>
                  Escaneos
                </h2>
                <p className="scans-subtitle">Monitoreo de herramientas de seguridad</p>
              </div>
              <div className="scans-header-actions">
                <span className="badge badge-accent">{filteredScans.length} scans</span>
                <button
                  className="btn btn-primary"
                  type="button"
                  onClick={() => {
                    setShowScanWizard(true);
                    setWizardStep(1);
                  }}
                  disabled={assets.length === 0}
                >
                  ▸ Nuevo scan
                </button>
              </div>
            </div>

            {assets.length === 0 && (
              <div className="scans-notice">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <circle cx="12" cy="12" r="10" />
                  <line x1="12" y1="8" x2="12" y2="12" />
                  <line x1="12" y1="16" x2="12.01" y2="16" />
                </svg>
                <span>Registra al menos un activo antes de ejecutar escaneos.</span>
              </div>
            )}

            <div className="scans-kpis">
              <div className="scans-kpi scans-kpi--queued" onClick={() => setScanFilters((prev) => ({ ...prev, status: "queued" }))}>
                <div className="scans-kpi-icon">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <circle cx="12" cy="12" r="10" />
                    <path d="M12 6v6l4 2" />
                  </svg>
                </div>
                <span className="scans-kpi-value">{scanStatusCounts.queued}</span>
                <span className="scans-kpi-label">En cola</span>
              </div>

              <div
                className={`scans-kpi scans-kpi--running ${scanStatusCounts.running > 0 ? "scans-kpi--pulse" : ""}`}
                onClick={() => setScanFilters((prev) => ({ ...prev, status: "running" }))}
              >
                <div className="scans-kpi-icon">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <path d="M21 12a9 9 0 11-6.219-8.56" />
                  </svg>
                </div>
                <span className="scans-kpi-value">{scanStatusCounts.running}</span>
                <span className="scans-kpi-label">Ejecutando</span>
              </div>

              <div className="scans-kpi scans-kpi--finished" onClick={() => setScanFilters((prev) => ({ ...prev, status: "finished" }))}>
                <div className="scans-kpi-icon">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <path d="M22 11.08V12a10 10 0 11-5.93-9.14" />
                    <path d="M22 4L12 14.01l-3-3" />
                  </svg>
                </div>
                <span className="scans-kpi-value">{scanStatusCounts.finished}</span>
                <span className="scans-kpi-label">Finalizados</span>
              </div>

              <div className="scans-kpi scans-kpi--failed" onClick={() => setScanFilters((prev) => ({ ...prev, status: "failed" }))}>
                <div className="scans-kpi-icon">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <circle cx="12" cy="12" r="10" />
                    <path d="M15 9l-6 6M9 9l6 6" />
                  </svg>
                </div>
                <span className="scans-kpi-value">{scanStatusCounts.failed}</span>
                <span className="scans-kpi-label">Fallidos</span>
              </div>
            </div>

            <div className="scans-filters">
              <div className="form-group">
                <label className="form-label">Herramienta</label>
                <select
                  className="form-select"
                  value={scanFilters.tool}
                  onChange={(event) => setScanFilters((prev) => ({ ...prev, tool: event.target.value }))}
                >
                  <option value="all">Todas</option>
                  {scanToolOptions.map((option) => (
                    <option key={option.value} value={option.value}>{option.label}</option>
                  ))}
                </select>
              </div>
              <div className="form-group">
                <label className="form-label">Estado</label>
                <select
                  className="form-select"
                  value={scanFilters.status}
                  onChange={(event) => setScanFilters((prev) => ({ ...prev, status: event.target.value }))}
                >
                  <option value="all">Todos</option>
                  <option value="queued">En cola</option>
                  <option value="running">Ejecutando</option>
                  <option value="finished">Finalizado</option>
                  <option value="failed">Fallido</option>
                </select>
              </div>
              <div className="form-group scans-filter-search">
                <label className="form-label">Buscar</label>
                <input
                  className="form-input"
                  type="text"
                  placeholder="id, herramienta, objetivo..."
                  value={scanFilters.search}
                  onChange={(event) => setScanFilters((prev) => ({ ...prev, search: event.target.value }))}
                />
              </div>
              <label className="scans-filter-toggle">
                <input type="checkbox" checked={showAllScans} onChange={() => setShowAllScans((prev) => !prev)} />
                <span>Mostrar todos</span>
              </label>
            </div>

            <div className="scans-table-wrap">
              <table className="scans-table">
                <thead>
                  <tr>
                    <th>#</th>
                    <th>Herramienta</th>
                    <th>Estado</th>
                    <th>Activo</th>
                    <th>Objetivo</th>
                    <th>Inicio</th>
                    <th>Duración</th>
                    <th></th>
                  </tr>
                </thead>
                <tbody>
                  {visibleScans.map((scan) => {
                    const meta = scan.metadata || scan.scan_metadata || {};
                    const target = meta.target_url || meta.target_path || meta.report_path || "—";
                    const scanAsset = assets.find((asset) => String(asset.id) === String(scan.asset_id));
                    const started = scan.started_at ? new Date(scan.started_at).toLocaleString() : "—";
                    const duration = scan.started_at && scan.finished_at
                      ? formatDuration(new Date(scan.finished_at) - new Date(scan.started_at))
                      : scan.status === "running" ? "..." : "—";
                    return (
                      <tr
                        key={scan.id}
                        className={`scans-row ${selectedScan === scan.id ? "scans-row--selected" : ""} scans-row--${scan.status}`}
                        onClick={() => setSelectedScan(selectedScan === scan.id ? null : scan.id)}
                      >
                        <td className="scans-cell-id">{scan.id}</td>
                        <td className="scans-cell-tool">{scan.tool}</td>
                        <td>
                          <span className={`scans-badge scans-badge--${scan.status}`}>
                            <span className="scans-badge-dot" />
                            {scanStatusLabels[scan.status]}
                          </span>
                          {scan.status === "running" && (
                            <div className="scans-minibar">
                              <div className="scans-minibar-fill" />
                            </div>
                          )}
                        </td>
                        <td className="scans-cell-asset">{scanAsset?.name || "—"}</td>
                        <td className="scans-cell-target">{target}</td>
                        <td className="scans-cell-date">{started}</td>
                        <td className="scans-cell-duration">{duration}</td>
                        <td className="scans-cell-actions" onClick={(event) => event.stopPropagation()}>
                          <button
                            className="scans-action-btn"
                            type="button"
                            title="Ver hallazgos"
                            onClick={() => handleViewFindings(scan.id)}
                          >
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                              <circle cx="11" cy="11" r="8" />
                              <path d="M21 21l-4.35-4.35" />
                            </svg>
                          </button>
                          <button
                            className="scans-action-btn"
                            type="button"
                            title="Re-ejecutar"
                            onClick={() => handleRerunScan(scan)}
                          >
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                              <path d="M21 12a9 9 0 11-6.219-8.56" />
                            </svg>
                          </button>
                          <button
                            className="scans-action-btn scans-action-btn--danger"
                            type="button"
                            title="Eliminar"
                            onClick={() => {
                              if (window.confirm("¿Eliminar este escaneo?")) {
                                handleDeleteScan(scan.id);
                              }
                            }}
                          >
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                              <path d="M3 6h18" />
                              <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2" />
                            </svg>
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>

              {visibleScans.length === 0 && (
                <div className="scans-empty">
                  <p>No se encontraron escaneos</p>
                  <button className="btn btn-primary btn-sm" type="button" onClick={() => { setShowScanWizard(true); setWizardStep(1); }}>
                    ▸ Nuevo scan
                  </button>
                </div>
              )}
            </div>

            {selectedScan && (() => {
              const scan = scans.find((item) => item.id === selectedScan);
              if (!scan) {
                return null;
              }
              const scanFindings = findings.filter((finding) => finding.scan_id === scan.id);
              return (
                <div className="scans-detail-panel">
                  <div className="scans-detail-header">
                    <h3>
                      Scan <span className="mono">#{scan.id}</span> — {scan.tool}
                    </h3>
                    <button className="btn btn-ghost btn-sm" type="button" onClick={() => setSelectedScan(null)}>✕</button>
                  </div>

                  <div className="scans-detail-body">
                    <div className="scans-detail-meta">
                      <div className="scans-detail-meta-item">
                        <span className="label">Hallazgos</span>
                        <div className="scans-detail-findings">
                          {scanFindings.length === 0 ? (
                            <span className="muted">Ninguno</span>
                          ) : (
                            <>
                              <strong>{scanFindings.length}</strong>
                              {["critical", "high", "medium", "low", "info"].map((severity) => {
                                const count = scanFindings.filter((finding) => finding.severity === severity).length;
                                return count > 0 ? (
                                  <span key={severity} className={`badge badge-${severity}`}>{count}</span>
                                ) : null;
                              })}
                            </>
                          )}
                        </div>
                      </div>
                    </div>

                    <div className="scans-terminal">
                      <div className="scans-terminal-bar">
                        <span className="dot red" />
                        <span className="dot yellow" />
                        <span className="dot green" />
                        <span className="scans-terminal-name">scan-{scan.id}.log</span>
                        {scanLogLines.length > 0 && (
                          <button
                            className="scans-terminal-toggle"
                            type="button"
                            onClick={() => setShowFullLogs((prev) => !prev)}
                          >
                            {showFullLogs ? "Recientes" : "Completos"}
                          </button>
                        )}
                      </div>
                      <pre className="scans-terminal-output">
                        {scanLogPreview || "$ esperando logs..."}
                      </pre>
                    </div>
                  </div>
                </div>
              );
            })()}

            {showScanWizard && (
              <div className="wizard-overlay" onClick={() => { setShowScanWizard(false); setWizardStep(1); }}>
                <div className="wizard-modal" onClick={(event) => event.stopPropagation()}>
                  <div className="wizard-header">
                    <h3>▸ Nuevo escaneo</h3>
                    <button className="btn btn-ghost" type="button" onClick={() => { setShowScanWizard(false); setWizardStep(1); }}>✕</button>
                  </div>

                  <div className="wizard-stepper">
                    <div className={`wizard-step ${wizardStep >= 1 ? "wizard-step--active" : ""} ${wizardStep > 1 ? "wizard-step--done" : ""}`}>
                      <span className="wizard-step-number">1</span>
                      <span className="wizard-step-label">Activo</span>
                    </div>
                    <div className="wizard-step-line" />
                    <div className={`wizard-step ${wizardStep >= 2 ? "wizard-step--active" : ""} ${wizardStep > 2 ? "wizard-step--done" : ""}`}>
                      <span className="wizard-step-number">2</span>
                      <span className="wizard-step-label">Herramienta</span>
                    </div>
                    <div className="wizard-step-line" />
                    <div className={`wizard-step ${wizardStep >= 3 ? "wizard-step--active" : ""}`}>
                      <span className="wizard-step-number">3</span>
                      <span className="wizard-step-label">Confirmar</span>
                    </div>
                  </div>

                  <div className="wizard-body">
                    {wizardStep === 1 && (
                      <div className="wizard-panel">
                        <p className="wizard-instruction">Selecciona el activo que deseas escanear:</p>
                        <div className="wizard-asset-list">
                          {assets.map((asset) => (
                            <div
                              key={asset.id}
                              className={`wizard-asset-card ${scanForm.assetId === String(asset.id) ? "wizard-asset-card--selected" : ""}`}
                              onClick={() => setScanForm((prev) => ({ ...prev, assetId: String(asset.id) }))}
                            >
                              <div className="wizard-asset-icon">
                                {asset.type === "web_app" && "🌐"}
                                {asset.type === "api" && "🔌"}
                                {asset.type === "host" && "🖥"}
                                {asset.type === "repo" && "📦"}
                                {asset.type === "container" && "🐳"}
                                {asset.type === "network_range" && "🔗"}
                              </div>
                              <div className="wizard-asset-info">
                                <span className="wizard-asset-name">{asset.name}</span>
                                <span className="wizard-asset-meta">
                                  {asset.uri} · {assetTypeLabels[asset.type] || asset.type}
                                  {asset.environment ? ` · ${asset.environment}` : ""}
                                </span>
                              </div>
                              <div className="wizard-asset-check">
                                {scanForm.assetId === String(asset.id) && (
                                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3">
                                    <path d="M20 6L9 17l-5-5" />
                                  </svg>
                                )}
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {wizardStep === 2 && (
                      <div className="wizard-panel">
                        <p className="wizard-instruction">
                          Selecciona la herramienta para escanear
                          <strong> {assets.find((asset) => String(asset.id) === scanForm.assetId)?.name}</strong>:
                        </p>
                        <div className="wizard-tool-grid">
                          {scanToolOptions.map((option) => {
                            const isDisabled = !allowedScanTools.has(option.value);
                            const isSelected = scanForm.tool === option.value;
                            return (
                              <div
                                key={option.value}
                                className={`wizard-tool-card ${isSelected ? "wizard-tool-card--selected" : ""} ${isDisabled ? "wizard-tool-card--disabled" : ""}`}
                                onClick={() => !isDisabled && setScanForm((prev) => ({ ...prev, tool: option.value }))}
                              >
                                <span className="wizard-tool-icon">
                                  {option.value === "nuclei" && "☢"}
                                  {option.value === "wapiti" && "🦊"}
                                  {option.value === "vulnapi" && "🔌"}
                                  {option.value === "osv" && "📦"}
                                  {option.value === "sarif" && "📄"}
                                </span>
                                <span className="wizard-tool-name">{option.label}</span>
                                <span className="wizard-tool-types">
                                  {option.types.map((type) => assetTypeLabels[type] || type).join(", ")}
                                </span>
                                {isDisabled && (
                                  <span className="wizard-tool-incompatible">No compatible</span>
                                )}
                                {isSelected && (
                                  <div className="wizard-tool-check">
                                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3">
                                      <path d="M20 6L9 17l-5-5" />
                                    </svg>
                                  </div>
                                )}
                              </div>
                            );
                          })}
                        </div>

                        <div className="wizard-extra-fields">
                          {(scanForm.tool === "vulnapi" || scanForm.tool === "wapiti" || scanForm.tool === "nuclei") && (
                            <div className="form-group">
                              <label className="form-label">URL objetivo</label>
                              <input
                                className="form-input"
                                type="text"
                                placeholder="https://target.com"
                                value={selectedScanAsset?.uri || scanForm.targetUrl}
                                onChange={(event) => setScanForm((prev) => ({ ...prev, targetUrl: event.target.value }))}
                                disabled={Boolean(scanForm.assetId)}
                              />
                              <span className="form-hint">Auto-completado desde el activo</span>
                            </div>
                          )}
                          {(scanForm.tool === "osv" || scanForm.tool === "sarif") && (
                            <div className="form-group">
                              <label className="form-label">Ruta objetivo</label>
                              <input
                                className="form-input"
                                type="text"
                                placeholder="/path/to/project"
                                value={selectedScanAsset?.uri || scanForm.targetPath}
                                onChange={(event) => setScanForm((prev) => ({ ...prev, targetPath: event.target.value }))}
                                disabled={Boolean(scanForm.assetId)}
                              />
                            </div>
                          )}
                          <div className="form-group">
                            <label className="form-label">Ruta del reporte</label>
                            <input
                              className="form-input"
                              type="text"
                              placeholder="/tmp/report.json"
                              value={scanForm.reportPath}
                              onChange={(event) => setScanForm((prev) => ({ ...prev, reportPath: event.target.value }))}
                            />
                          </div>
                        </div>
                      </div>
                    )}

                    {wizardStep === 3 && (() => {
                      const selectedAsset = assets.find((asset) => String(asset.id) === scanForm.assetId);
                      const selectedTool = scanToolOptions.find((tool) => tool.value === scanForm.tool);
                      const meta = scanForm.targetUrl || scanForm.targetPath || selectedAsset?.uri || "—";
                      return (
                        <div className="wizard-panel">
                          <p className="wizard-instruction">Confirma la configuración del escaneo:</p>
                          <div className="wizard-summary">
                            <div className="wizard-summary-row">
                              <span className="wizard-summary-label">Activo</span>
                              <span className="wizard-summary-value">
                                {selectedAsset?.name}
                                <span className="badge badge-accent" style={{ marginLeft: "8px" }}>
                                  {assetTypeLabels[selectedAsset?.type] || selectedAsset?.type}
                                </span>
                              </span>
                            </div>
                            <div className="wizard-summary-row">
                              <span className="wizard-summary-label">Herramienta</span>
                              <span className="wizard-summary-value mono">{selectedTool?.label || scanForm.tool}</span>
                            </div>
                            <div className="wizard-summary-row">
                              <span className="wizard-summary-label">Objetivo</span>
                              <span className="wizard-summary-value mono">{meta}</span>
                            </div>
                            <div className="wizard-summary-row">
                              <span className="wizard-summary-label">Reporte</span>
                              <span className="wizard-summary-value mono">{scanForm.reportPath || "/tmp/report.json"}</span>
                            </div>
                          </div>
                          <div className="wizard-confirm-notice">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                              <circle cx="12" cy="12" r="10" />
                              <line x1="12" y1="8" x2="12" y2="12" />
                              <line x1="12" y1="16" x2="12.01" y2="16" />
                            </svg>
                            <span>El scan se añadirá a la cola y el worker lo ejecutará automáticamente.</span>
                          </div>
                        </div>
                      );
                    })()}
                  </div>

                  <div className="wizard-footer">
                    {wizardStep > 1 && (
                      <button className="btn btn-secondary" type="button" onClick={() => setWizardStep((prev) => prev - 1)}>
                        ← Atrás
                      </button>
                    )}
                    <div className="wizard-footer-right">
                      <button className="btn btn-ghost" type="button" onClick={() => { setShowScanWizard(false); setWizardStep(1); }}>
                        Cancelar
                      </button>
                      {wizardStep < 3 && (
                        <button
                          className="btn btn-primary"
                          type="button"
                          disabled={
                            (wizardStep === 1 && !scanForm.assetId) ||
                            (wizardStep === 2 && (!scanForm.tool || (scanForm.assetId && allowedScanTools.size > 0 && !allowedScanTools.has(scanForm.tool))))
                          }
                          onClick={() => setWizardStep((prev) => prev + 1)}
                        >
                          Siguiente →
                        </button>
                      )}
                      {wizardStep === 3 && (
                        <button
                          className="btn btn-primary"
                          type="button"
                          onClick={(event) => {
                            handleScanSubmit(event);
                            setShowScanWizard(false);
                            setWizardStep(1);
                          }}
                        >
                          ▸ Ejecutar scan
                        </button>
                      )}
                    </div>
                  </div>
                </div>
              </div>
            )}
          </section>
          )}

              {projectId && activeSection === "auditoria" && (
                <section className={`audit-section ${selectedAudit ? "has-drawer" : ""}`}>
                  <div className="audit-header">
                    <div className="audit-header-info">
                      <h2 className="audit-title">
                        <svg
                          className="audit-title-icon"
                          viewBox="0 0 24 24"
                          fill="none"
                          stroke="currentColor"
                          strokeWidth="2"
                          strokeLinecap="round"
                          strokeLinejoin="round"
                        >
                          <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z" />
                          <polyline points="14 2 14 8 20 8" />
                          <line x1="16" y1="13" x2="8" y2="13" />
                          <line x1="16" y1="17" x2="8" y2="17" />
                          <polyline points="10 9 9 9 8 9" />
                        </svg>
                        Auditoría
                      </h2>
                      <p className="audit-subtitle">Registro de actividad y requests del sistema</p>
                    </div>
                    <div className="audit-header-actions">
                      <span className="badge badge-accent">{filteredAuditLogs.length} entradas</span>
                    </div>
                  </div>

                  <div className="audit-kpis">
                    <div className="audit-kpi">
                      <div className="audit-kpi-icon audit-kpi-icon--total">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                          <polyline points="22 12 18 12 15 21 9 3 6 12 2 12" />
                        </svg>
                      </div>
                      <span className="audit-kpi-value">{auditMetrics.total}</span>
                      <span className="audit-kpi-label">Eventos totales</span>
                    </div>
                    <div className="audit-kpi">
                      <div className="audit-kpi-icon audit-kpi-icon--errors">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                          <circle cx="12" cy="12" r="10" />
                          <path d="M15 9l-6 6M9 9l6 6" />
                        </svg>
                      </div>
                      <span className="audit-kpi-value">{auditMetrics.errors24h}</span>
                      <span className="audit-kpi-label">Errores (24h)</span>
                    </div>
                    <div className="audit-kpi">
                      <div className="audit-kpi-icon audit-kpi-icon--ok">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                          <path d="M22 11.08V12a10 10 0 11-5.93-9.14" />
                          <path d="M22 4L12 14.01l-3-3" />
                        </svg>
                      </div>
                      <span className="audit-kpi-value">{auditMetrics.ok24h}</span>
                      <span className="audit-kpi-label">Exitosos (24h)</span>
                    </div>
                    <div className="audit-kpi">
                      <div className="audit-kpi-icon audit-kpi-icon--users">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                          <path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4-4v2" />
                          <circle cx="9" cy="7" r="4" />
                        </svg>
                      </div>
                      <span className="audit-kpi-value">{auditMetrics.uniqueUsers}</span>
                      <span className="audit-kpi-label">Usuarios activos</span>
                    </div>
                  </div>

                  <div className="audit-filters">
                    <div className="form-group">
                      <label className="form-label">Usuario</label>
                      <input
                        className="form-input"
                        type="text"
                        placeholder="ID o email"
                        value={auditFilters.user}
                        onChange={(event) =>
                          setAuditFilters((prev) => ({ ...prev, user: event.target.value }))
                        }
                      />
                    </div>
                    <div className="form-group">
                      <label className="form-label">Método</label>
                      <select
                        className="form-select"
                        value={auditFilters.action}
                        onChange={(event) =>
                          setAuditFilters((prev) => ({ ...prev, action: event.target.value }))
                        }
                      >
                        <option value="all">Todos</option>
                        <option value="GET">GET</option>
                        <option value="POST">POST</option>
                        <option value="PATCH">PATCH</option>
                        <option value="DELETE">DELETE</option>
                        <option value="OPTIONS">OPTIONS</option>
                      </select>
                    </div>
                    <div className="form-group">
                      <label className="form-label">Desde</label>
                      <input
                        className="form-input"
                        type="date"
                        value={auditFilters.from}
                        onChange={(event) =>
                          setAuditFilters((prev) => ({ ...prev, from: event.target.value }))
                        }
                      />
                    </div>
                    <div className="form-group">
                      <label className="form-label">Hasta</label>
                      <input
                        className="form-input"
                        type="date"
                        value={auditFilters.to}
                        onChange={(event) =>
                          setAuditFilters((prev) => ({ ...prev, to: event.target.value }))
                        }
                      />
                    </div>
                    <div className="form-group audit-filter-search">
                      <label className="form-label">Buscar</label>
                      <input
                        className="form-input"
                        type="text"
                        placeholder="ruta, IP, estado..."
                        value={auditFilters.search}
                        onChange={(event) =>
                          setAuditFilters((prev) => ({ ...prev, search: event.target.value }))
                        }
                      />
                    </div>
                    <label className="audit-filter-toggle">
                      <input
                        type="checkbox"
                        checked={showAllAudit}
                        onChange={() => setShowAllAudit((prev) => !prev)}
                      />
                      <span>Todo</span>
                    </label>
                  </div>

                  <div className="audit-table-wrap">
                    <table className="audit-table">
                      <thead>
                        <tr>
                          <th>Hora</th>
                          <th>Usuario</th>
                          <th>Método</th>
                          <th>Ruta</th>
                          <th>Estado</th>
                          <th>IP</th>
                        </tr>
                      </thead>
                      <tbody>
                        {visibleAuditLogs.map((log) => {
                          const isError = log.status_code >= 400;
                          const isSelected = selectedAudit?.id === log.id;
                          return (
                            <tr
                              key={log.id}
                              className={`audit-row ${isSelected ? "audit-row--selected" : ""} ${isError ? "audit-row--error" : ""}`}
                              onClick={() => setSelectedAudit(isSelected ? null : log)}
                            >
                              <td className="audit-cell-time">
                                {new Date(log.created_at).toLocaleTimeString()}
                                <span className="audit-cell-date">
                                  {new Date(log.created_at).toLocaleDateString()}
                                </span>
                              </td>
                              <td className="audit-cell-user">
                                {log.user_id ? (
                                  <span className="audit-user-badge">
                                    <span className="audit-user-avatar">{String(log.user_id).charAt(0)}</span>
                                    {log.user_id}
                                  </span>
                                ) : (
                                  <span className="audit-system-badge">Sistema</span>
                                )}
                              </td>
                              <td>
                                <span className={`audit-method audit-method--${log.method.toLowerCase()}`}>
                                  {log.method}
                                </span>
                              </td>
                              <td className="audit-cell-path">{log.path}</td>
                              <td>
                                <span className={`audit-status ${isError ? "audit-status--error" : "audit-status--ok"}`}>
                                  {log.status_code}
                                </span>
                              </td>
                              <td className="audit-cell-ip">{log.ip || "—"}</td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                    {visibleAuditLogs.length === 0 && (
                      <div className="audit-empty">
                        <p>No se encontraron eventos de auditoría.</p>
                      </div>
                    )}
                  </div>

                  {selectedAudit && (
                    <aside className="audit-drawer">
                      <div className="audit-drawer-header">
                        <div>
                          <span className={`audit-method audit-method--${selectedAudit.method.toLowerCase()}`}>
                            {selectedAudit.method}
                          </span>
                          <h3 className="audit-drawer-title">{selectedAudit.path}</h3>
                        </div>
                        <button className="btn btn-ghost" onClick={() => setSelectedAudit(null)}>✕</button>
                      </div>

                      <div className="audit-drawer-body">
                        <div className={`audit-drawer-status ${selectedAudit.status_code >= 400 ? "audit-drawer-status--error" : "audit-drawer-status--ok"}`}>
                          <span className="audit-drawer-status-code">{selectedAudit.status_code}</span>
                          <span className="audit-drawer-status-text">
                            {selectedAudit.status_code >= 500
                              ? "Server Error"
                              : selectedAudit.status_code >= 400
                                ? "Client Error"
                                : selectedAudit.status_code >= 300
                                  ? "Redirection"
                                  : selectedAudit.status_code >= 200
                                    ? "Success"
                                    : "Info"}
                          </span>
                        </div>

                        <div className="audit-meta-grid">
                          <div className="audit-meta-item">
                            <span className="audit-meta-label">Timestamp</span>
                            <span>{new Date(selectedAudit.created_at).toLocaleString()}</span>
                          </div>
                          <div className="audit-meta-item">
                            <span className="audit-meta-label">Usuario</span>
                            <span>{selectedAudit.user_id ?? "Sistema"}</span>
                          </div>
                          <div className="audit-meta-item">
                            <span className="audit-meta-label">Dirección IP</span>
                            <span className="mono">{selectedAudit.ip || "—"}</span>
                          </div>
                          <div className="audit-meta-item">
                            <span className="audit-meta-label">Método</span>
                            <span className={`audit-method audit-method--${selectedAudit.method.toLowerCase()}`}>
                              {selectedAudit.method}
                            </span>
                          </div>
                        </div>

                        <div className="audit-request-block">
                          <h4>Request</h4>
                          <div className="audit-terminal">
                            <div className="audit-terminal-bar">
                              <span className="dot red"></span>
                              <span className="dot yellow"></span>
                              <span className="dot green"></span>
                              <span className="audit-terminal-name">request</span>
                            </div>
                            <pre className="audit-terminal-output">{`${selectedAudit.method} ${selectedAudit.path} HTTP/1.1\nStatus: ${selectedAudit.status_code}\nUser: ${selectedAudit.user_id ?? "Sistema"}\nIP: ${selectedAudit.ip || "—"}\nTime: ${new Date(selectedAudit.created_at).toISOString()}`}</pre>
                          </div>
                        </div>
                      </div>
                    </aside>
                  )}
                </section>
              )}

              {showNewClientModal && (
                <div className="wizard-overlay" onClick={() => setShowNewClientModal(false)}>
                  <div className="wizard-modal" onClick={(event) => event.stopPropagation()} style={{ maxWidth: "440px" }}>
                    <div className="wizard-header">
                      <h3>🏢 Nuevo cliente</h3>
                      <button className="btn btn-ghost" type="button" onClick={() => setShowNewClientModal(false)}>✕</button>
                    </div>
                    <form
                      className="sidebar-modal-body"
                      onSubmit={(event) => {
                        event.preventDefault();
                        handleCreateOrg();
                        setShowNewClientModal(false);
                      }}
                    >
                      <div className="form-group">
                        <label className="form-label">Nombre del cliente</label>
                        <input
                          className="form-input"
                          type="text"
                          placeholder="Ej: Telefonica Colombia, Banco XYZ"
                          value={newClientName}
                          onChange={(event) => setNewClientName(event.target.value)}
                          required
                          autoFocus
                        />
                        <span className="form-hint">Nombre de la empresa o cliente</span>
                      </div>
                      <div className="sidebar-modal-footer">
                        <button className="btn btn-ghost" type="button" onClick={() => setShowNewClientModal(false)}>
                          Cancelar
                        </button>
                        <button className="btn btn-primary" type="submit" disabled={!newClientName.trim()}>
                          Crear cliente
                        </button>
                      </div>
                    </form>
                  </div>
                </div>
              )}

              {showNewProjectModal && (
                <div className="wizard-overlay" onClick={() => setShowNewProjectModal(false)}>
                  <div className="wizard-modal" onClick={(event) => event.stopPropagation()} style={{ maxWidth: "440px" }}>
                    <div className="wizard-header">
                      <h3>📁 Nuevo proyecto</h3>
                      <button className="btn btn-ghost" type="button" onClick={() => setShowNewProjectModal(false)}>✕</button>
                    </div>
                    <form
                      className="sidebar-modal-body"
                      onSubmit={(event) => {
                        event.preventDefault();
                        handleCreateProject();
                        setShowNewProjectModal(false);
                      }}
                    >
                      <div className="form-group">
                        <label className="form-label">Cliente</label>
                        <input
                          className="form-input"
                          type="text"
                          disabled
                          value={selectedOrgName || ""}
                        />
                      </div>
                      <div className="form-group">
                        <label className="form-label">Nombre del proyecto</label>
                        <input
                          className="form-input"
                          type="text"
                          placeholder="Ej: Pentest Web Q1 2026"
                          value={newProjectName}
                          onChange={(event) => setNewProjectName(event.target.value)}
                          required
                          autoFocus
                        />
                        <span className="form-hint">Nombre del ejercicio o engagement</span>
                      </div>
                      <div className="sidebar-modal-footer">
                        <button className="btn btn-ghost" type="button" onClick={() => setShowNewProjectModal(false)}>
                          Cancelar
                        </button>
                        <button className="btn btn-primary" type="submit" disabled={!orgId || !newProjectName.trim()}>
                          Crear proyecto
                        </button>
                      </div>
                    </form>
                  </div>
                </div>
              )}

              {showIdleWarning && isAuthenticated && (
                <div className="wizard-overlay">
                  <div className="wizard-modal" style={{ maxWidth: "420px" }}>
                    <div className="wizard-header">
                      <h3>Sesión por inactividad</h3>
                    </div>
                    <div className="wizard-body">
                      <p className="wizard-instruction">
                        Llevas 13 minutos sin actividad. Tu sesión se cerrará en 2 minutos si no confirmas.
                      </p>
                    </div>
                    <div className="wizard-footer">
                      <div className="wizard-footer-right">
                        <button
                          className="btn btn-primary"
                          type="button"
                          onClick={() => {
                            setShowIdleWarning(false);
                            resetIdleTimers();
                          }}
                        >
                          Seguir en sesión
                        </button>
                      </div>
                    </div>
                  </div>
                </div>
              )}
                </>
              ) : null}
            </>
          )}
        </main>
      </div>
    </div>
  );
}
