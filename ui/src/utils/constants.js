export const API_URL =
  import.meta.env.VITE_API_BASE_URL || import.meta.env.VITE_API_URL || "http://localhost:9292";

export const SEVERITIES = ["critical", "high", "medium", "low", "info"];

export const STATUSES = ["open", "triaged", "accepted", "fixed", "false_positive"];

export const ASSET_TYPES = ["web_app", "api", "repo", "host", "container", "network_range"];

export const ENVIRONMENTS = ["prod", "stage", "dev"];

export const CRITICALITIES = ["alta", "media", "baja"];

export const SEVERITY_LABELS = {
  critical: "Crítica",
  high: "Alta",
  medium: "Media",
  low: "Baja",
  info: "Info",
};

export const STATUS_LABELS = {
  open: "Abierto",
  triaged: "Triado",
  accepted: "Aceptado",
  fixed: "Cerrado",
  false_positive: "Falso positivo",
};

export const SCAN_STATUS_LABELS = {
  queued: "En cola",
  running: "Ejecutando",
  finished: "Finalizado",
  failed: "Fallido",
};

export const ASSET_TYPE_LABELS = {
  web_app: "Web",
  api: "API",
  repo: "Repo",
  host: "Host",
  container: "Container",
  network_range: "Red",
};

export const ENV_LABELS = {
  prod: "Producción",
  stage: "Staging",
  dev: "Desarrollo",
};
