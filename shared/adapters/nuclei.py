from __future__ import annotations

from typing import Any, Dict, List

from .utils import map_severity, normalize_base, now_iso


def _extract_version(data: Any) -> str:
    if isinstance(data, dict):
        return str(data.get("nuclei_version") or data.get("version") or data.get("tool_version") or "unknown")
    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                version = item.get("nuclei_version") or item.get("version")
                if version:
                    return str(version)
    return "unknown"


def _iter_entries(data: Any) -> List[Dict[str, Any]]:
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    if isinstance(data, dict):
        for key in ("results", "items", "matches", "findings"):
            value = data.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
        return [data]
    return []


def _normalize_references(value: Any) -> List[str]:
    if isinstance(value, list):
        return [str(item) for item in value if item]
    if isinstance(value, str) and value.strip():
        return [value.strip()]
    return []


def _normalize_tags(value: Any) -> List[str]:
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    return []


def _scan_profile(protocol: str) -> tuple[str, str]:
    proto = protocol.lower().strip()
    if proto in {"http", "https"}:
        return "web", "web_app"
    if proto in {"dns", "tcp", "udp", "network"}:
        return "network", "host"
    return "web", "web_app"


def parse_nuclei_json(data: Any) -> List[Dict[str, Any]]:
    tool_version = _extract_version(data)
    findings: List[Dict[str, Any]] = []

    for entry in _iter_entries(data):
        info = entry.get("info") if isinstance(entry.get("info"), dict) else {}
        protocol = entry.get("type") or info.get("protocol") or ""
        scan_type, asset_type = _scan_profile(str(protocol))

        target = entry.get("matched-at") or entry.get("host") or entry.get("url") or ""
        title = info.get("name") or entry.get("template-id") or entry.get("template") or "Nuclei"
        description = info.get("description") or ""
        severity = map_severity(info.get("severity") or entry.get("severity"))
        rule_id = entry.get("template-id") or entry.get("template") or title

        classification = info.get("classification") if isinstance(info.get("classification"), dict) else {}
        cve = ""
        cwe = ""
        if classification:
            cve_raw = classification.get("cve-id") or classification.get("cve")
            cwe_raw = classification.get("cwe-id") or classification.get("cwe")
            if isinstance(cve_raw, list):
                cve = cve_raw[0] if cve_raw else ""
            elif isinstance(cve_raw, str):
                cve = cve_raw
            if isinstance(cwe_raw, list):
                cwe = cwe_raw[0] if cwe_raw else ""
            elif isinstance(cwe_raw, str):
                cwe = cwe_raw

        tags = _normalize_tags(info.get("tags"))
        references = _normalize_references(info.get("reference") or info.get("references"))
        detected_at = entry.get("timestamp") or now_iso()

        finding = {
            "source": {
                "tool": "nuclei",
                "tool_version": tool_version,
                "rule_id": rule_id,
            },
            "scan": {"scan_type": scan_type, "status": "succeeded"},
            "asset": {
                "type": asset_type,
                "name": target or "nuclei-target",
                "uri": target,
            },
            "finding": {
                "type": "vuln",
                "title": title,
                "description": description,
                "severity": severity,
                "status": "open",
                "cve": cve,
                "cwe": cwe,
            },
            "evidence": {
                "request": entry.get("request") or "",
                "response": entry.get("response") or "",
                "metadata": {
                    "matcher": entry.get("matcher-name") or entry.get("matcher") or "",
                    "template": entry.get("template-id") or "",
                    "template_path": entry.get("template-path") or "",
                    "tags": tags,
                    "extracted_results": entry.get("extracted-results") or [],
                },
            },
            "remediation": {"references": references},
            "timestamps": {"detected_at": detected_at},
        }
        findings.append(normalize_base(finding))

    return findings
