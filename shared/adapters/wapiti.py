from __future__ import annotations

from typing import Any, Dict, List

import re

from .utils import map_severity, normalize_base, now_iso


LEVEL_MAP = {
    0: "info",
    1: "low",
    2: "medium",
    3: "high",
    4: "critical",
}


def _level_to_severity(level: Any) -> str:
    if isinstance(level, int):
        return LEVEL_MAP.get(level, "info")
    if isinstance(level, str) and level.isdigit():
        return LEVEL_MAP.get(int(level), "info")
    return map_severity(str(level))


def _iter_entries(section: Any) -> List[Dict[str, Any]]:
    if isinstance(section, list):
        return [item for item in section if isinstance(item, dict)]
    if isinstance(section, dict):
        items: List[Dict[str, Any]] = []
        for _, value in section.items():
            if isinstance(value, list):
                items.extend([item for item in value if isinstance(item, dict)])
        return items
    return []


def _extract_info(data: Dict[str, Any]) -> Dict[str, Any]:
    infos = data.get("infos", {}) if isinstance(data.get("infos"), dict) else {}
    raw_version = infos.get("version") or data.get("version") or data.get("tool_version", "")
    # Normalize version like "Wapiti 3.0.4" -> "3.0.4"
    match = re.search(r"([0-9]+(?:\\.[0-9]+)*)", str(raw_version))
    version = match.group(1) if match else str(raw_version)
    return {
        "target": infos.get("target") or data.get("target") or data.get("url") or "",
        "version": version,
    }


def parse_wapiti_json(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    info = _extract_info(data)
    target = info["target"]
    tool_version = info["version"]

    findings: List[Dict[str, Any]] = []

    for section_name, section_key in [
        ("vulnerabilities", "vulnerabilities"),
        ("anomalies", "anomalies"),
        ("additionals", "additionals"),
    ]:
        section = data.get(section_key)
        if not isinstance(section, dict):
            continue
        for category, items in section.items():
            for item in _iter_entries(items):
                module = item.get("module") or category or section_name
                title = item.get("info") or module
                level = item.get("level", 0)
                parameter = item.get("parameter") or ""
                method = item.get("method") or ""
                path = item.get("path") or ""

                request = item.get("http_request") or ""
                response = ""
                if isinstance(item.get("detail"), dict):
                    response = item.get("detail", {}).get("response", "")

                finding = {
                    "source": {
                        "tool": "wapiti",
                        "tool_version": tool_version,
                        "rule_id": module,
                    },
                    "scan": {"scan_type": "web", "status": "succeeded"},
                    "asset": {
                        "type": "web_app",
                        "name": target or path or "wapiti-target",
                        "uri": target or path or "",
                    },
                    "finding": {
                        "type": "vuln",
                        "title": title,
                        "description": item.get("info", ""),
                        "severity": _level_to_severity(level),
                        "status": "open",
                    },
                    "evidence": {
                        "request": request or f"{method} {path}".strip(),
                        "response": response,
                        "metadata": {
                            "parameter": parameter,
                            "module": module,
                            "category": category,
                            "section": section_name,
                        },
                    },
                    "timestamps": {"detected_at": now_iso()},
                }
                findings.append(normalize_base(finding))

    # Fallback for minimal/legacy single-entry inputs
    if not findings and isinstance(data, dict):
        module = data.get("module") or "wapiti"
        finding = {
            "source": {
                "tool": "wapiti",
                "tool_version": tool_version,
                "rule_id": module,
            },
            "scan": {"scan_type": "web", "status": "succeeded"},
            "asset": {
                "type": "web_app",
                "name": target or data.get("url", "") or "wapiti-target",
                "uri": target or data.get("url", "") or "",
            },
            "finding": {
                "type": "vuln",
                "title": data.get("title", module),
                "description": data.get("description", ""),
                "severity": _level_to_severity(data.get("level", "info")),
                "status": "open",
            },
            "evidence": {
                "request": data.get("request", ""),
                "response": data.get("response", ""),
                "metadata": {"parameter": data.get("parameter", "")},
            },
            "timestamps": {"detected_at": now_iso()},
        }
        findings.append(normalize_base(finding))

    return findings
