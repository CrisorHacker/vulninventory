from __future__ import annotations

from typing import Any, Dict, List, Optional

from .utils import map_severity, normalize_base, now_iso


def _severity_from_cvss(score: Any) -> str:
    try:
        value = float(score)
    except (TypeError, ValueError):
        return "info"
    if value > 9:
        return "critical"
    if value > 7:
        return "high"
    if value > 4:
        return "medium"
    if value > 0:
        return "low"
    return "info"


def _string_or_first(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        for item in value:
            if isinstance(item, str) and item:
                return item
    return ""


def _extract_owasp(classifications: Dict[str, Any]) -> str:
    owasp = classifications.get("owasp")
    if isinstance(owasp, dict):
        return owasp.get("name", "") or ""
    return _string_or_first(owasp)


def _extract_cwe(classifications: Dict[str, Any]) -> str:
    cwe = classifications.get("cwe")
    if isinstance(cwe, dict):
        return cwe.get("id", "") or ""
    value = _string_or_first(cwe)
    if not value:
        return ""
    return value.split(":", 1)[0].strip()


def _openapi_base_url(openapi: Dict[str, Any]) -> str:
    servers = openapi.get("servers")
    if isinstance(servers, list):
        for server in servers:
            if isinstance(server, dict) and server.get("url"):
                return server["url"]
    return ""


def _parse_reporter(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    base_url = data.get("base_url") or data.get("target") or ""
    reports = data.get("reports")
    if not isinstance(reports, list):
        return findings

    for report in reports:
        if not isinstance(report, dict):
            continue
        issues = report.get("issues") or []
        if not isinstance(issues, list):
            continue
        for issue in issues:
            if not isinstance(issue, dict):
                continue
            status = issue.get("status", "none")
            if status == "passed":
                continue

            cvss = issue.get("cvss") if isinstance(issue.get("cvss"), dict) else {}
            classifications = issue.get("classifications") if isinstance(issue.get("classifications"), dict) else {}
            owasp = _extract_owasp(classifications)
            cwe = _extract_cwe(classifications)

            severity = _severity_from_cvss(cvss.get("score"))
            asset_url = issue.get("url", "") or base_url
            finding = {
                "source": {
                    "tool": "vulnapi",
                    "tool_version": data.get("version", ""),
                    "rule_id": issue.get("id", ""),
                },
                "scan": {"scan_type": "api", "status": "succeeded"},
                "asset": {
                    "type": "api",
                    "name": asset_url or "vulnapi-target",
                    "uri": asset_url,
                },
                "finding": {
                    "type": "misconfig",
                    "title": issue.get("name", ""),
                    "description": "",
                    "severity": severity,
                    "status": "open",
                    "cvss": {"score": cvss.get("score"), "vector": cvss.get("vector", "")},
                    "cwe": cwe,
                    "owasp": owasp,
                },
                "evidence": {
                    "metadata": {
                        "report_id": report.get("id", ""),
                        "report_name": report.get("name", ""),
                    }
                },
                "timestamps": {"detected_at": now_iso()},
            }
            findings.append(normalize_base(finding))

    return findings


def _parse_openapi_paths(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    openapi = data.get("openapi")
    if not isinstance(openapi, dict):
        return findings

    paths = openapi.get("paths")
    if not isinstance(paths, dict):
        return findings

    base_url = _openapi_base_url(openapi) or data.get("base_url") or data.get("target") or ""
    api_name = ""
    info = openapi.get("info")
    if isinstance(info, dict):
        api_name = info.get("title", "") or ""

    for path, methods in paths.items():
        if not isinstance(methods, dict):
            continue
        for method, operation in methods.items():
            if not isinstance(operation, dict):
                continue
            issues = operation.get("issues") or []
            if not isinstance(issues, list):
                continue
            for issue in issues:
                if not isinstance(issue, dict):
                    continue
                status = issue.get("status", "none")
                if status == "passed":
                    continue

                cvss = issue.get("cvss") if isinstance(issue.get("cvss"), dict) else {}
                classifications = (
                    issue.get("classifications") if isinstance(issue.get("classifications"), dict) else {}
                )
                owasp = _extract_owasp(classifications)
                cwe = _extract_cwe(classifications)
                severity = _severity_from_cvss(cvss.get("score"))
                operation_label = f"{str(method).upper()} {path}"
                scan_ids: List[str] = []
                scans = issue.get("scans")
                if isinstance(scans, list):
                    for scan in scans:
                        if isinstance(scan, dict) and scan.get("id"):
                            scan_ids.append(scan["id"])

                finding = {
                    "source": {
                        "tool": "vulnapi",
                        "tool_version": data.get("version", ""),
                        "rule_id": issue.get("id", ""),
                    },
                    "scan": {"scan_type": "api", "status": "succeeded"},
                    "asset": {
                        "type": "api",
                        "name": api_name or base_url or "vulnapi-target",
                        "uri": base_url,
                    },
                    "finding": {
                        "type": "misconfig",
                        "title": issue.get("name", ""),
                        "description": "",
                        "severity": severity,
                        "status": "open",
                        "cvss": {"score": cvss.get("score"), "vector": cvss.get("vector", "")},
                        "cwe": cwe,
                        "owasp": owasp,
                    },
                    "evidence": {
                        "metadata": {
                            "operation": operation_label,
                            "operation_id": operation.get("operationId", ""),
                            "path": path,
                            "method": str(method).upper(),
                            "scan_ids": scan_ids,
                        }
                    },
                    "timestamps": {"detected_at": now_iso()},
                }
                findings.append(normalize_base(finding))

    return findings


def parse_vulnapi_json(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    # New Reporter schema
    if "$schema" in data and isinstance(data.get("reports"), list):
        findings = _parse_reporter(data)
        findings.extend(_parse_openapi_paths(data))
        return findings

    tool_version = data.get("version") or data.get("tool_version", "")
    base_url = data.get("base_url") or data.get("target") or ""

    raw_findings = data.get("findings") or data.get("results") or data.get("vulnerabilities")
    if isinstance(raw_findings, dict):
        raw_findings = [raw_findings]
    if not isinstance(raw_findings, list):
        raw_findings = []

    findings: List[Dict[str, Any]] = []
    for item in raw_findings:
        if not isinstance(item, dict):
            continue
        vulnerability = item.get("vulnerability") or item.get("title") or item.get("name") or "Vulnerability"
        risk = item.get("risk") or item.get("severity") or "info"
        operation = item.get("operation") or item.get("endpoint") or item.get("path") or ""

        finding = {
            "source": {
                "tool": "vulnapi",
                "tool_version": tool_version,
                "rule_id": vulnerability,
            },
            "scan": {"scan_type": "api", "status": "succeeded"},
            "asset": {
                "type": "api",
                "name": base_url or operation or "vulnapi-target",
                "uri": base_url or "",
            },
            "finding": {
                "type": "misconfig",
                "title": vulnerability,
                "description": item.get("details") or item.get("description", ""),
                "severity": map_severity(str(risk)),
                "status": "open",
                "cvss": {"score": item.get("cvss")},
                "owasp": item.get("owasp", ""),
            },
            "evidence": {
                "metadata": {
                    "operation": operation,
                    "raw": item.get("raw", None),
                }
            },
            "timestamps": {"detected_at": now_iso()},
        }
        findings.append(normalize_base(finding))

    return findings
