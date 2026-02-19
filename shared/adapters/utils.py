from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
from typing import Any, Dict
from urllib.parse import urlsplit, urlunsplit


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def map_severity(level: str | None) -> str:
    if not level:
        return "info"
    normalized = level.strip().lower()
    if normalized in {"critical", "high", "medium", "low", "info"}:
        return normalized
    if normalized in {"warn", "warning"}:
        return "medium"
    if normalized in {"error", "severe"}:
        return "high"
    return "info"


def fingerprint_for(finding: Dict[str, Any]) -> str:
    parts = [
        finding.get("source", {}).get("tool", ""),
        finding.get("asset", {}).get("uri", ""),
        finding.get("finding", {}).get("title", ""),
        finding.get("source", {}).get("rule_id", ""),
    ]
    blob = "|".join(parts).encode("utf-8")
    return "sha256:" + sha256(blob).hexdigest()


def normalize_asset_uri(uri: Any) -> str:
    if not isinstance(uri, str):
        return ""
    value = uri.strip()
    if not value or "://" not in value:
        return value
    parts = urlsplit(value)
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


def normalize_base(finding: Dict[str, Any]) -> Dict[str, Any]:
    asset = finding.get("asset")
    if isinstance(asset, dict):
        uri = asset.get("uri")
        name = asset.get("name")
        normalized_uri = normalize_asset_uri(uri)
        if normalized_uri:
            asset["uri"] = normalized_uri
            if not name or name == uri:
                asset["name"] = normalized_uri
        elif isinstance(name, str) and "://" in name:
            asset["uri"] = normalize_asset_uri(name)
    if "timestamps" not in finding:
        finding["timestamps"] = {"detected_at": now_iso()}
    if "finding" in finding and "fingerprint" not in finding["finding"]:
        finding["finding"]["fingerprint"] = fingerprint_for(finding)
    return finding
