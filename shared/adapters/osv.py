from __future__ import annotations

from typing import Any, Dict, List

from .utils import map_severity, normalize_base, now_iso


def _extract_cvss(vuln: Dict[str, Any]) -> float | None:
    # OSV advisories may include severity list with CVSS scores
    severities = vuln.get("severity") or []
    for entry in severities:
        if isinstance(entry, dict):
            score = entry.get("score")
            if score is not None:
                try:
                    return float(score)
                except ValueError:
                    continue
    return None


def _severity_from_cvss(score: float | None) -> str:
    if score is None:
        return "info"
    if score > 9:
        return "critical"
    if score > 7:
        return "high"
    if score > 4:
        return "medium"
    if score > 0:
        return "low"
    return "info"


def _iter_osv_results(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    results = data.get("results")
    if isinstance(results, list):
        return [r for r in results if isinstance(r, dict)]
    return []


def parse_osv_json(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    tool_version = data.get("version") or data.get("tool_version", "")

    findings: List[Dict[str, Any]] = []

    # OSV-Scanner v2 JSON: results -> packages -> vulnerabilities
    for result in _iter_osv_results(data):
        source = result.get("source", {}) if isinstance(result.get("source"), dict) else {}
        repo_path = source.get("path") or result.get("path") or ""

        packages = result.get("packages")
        if not isinstance(packages, list):
            continue

        for pkg in packages:
            if not isinstance(pkg, dict):
                continue
            pkg_info = pkg.get("package", {}) if isinstance(pkg.get("package"), dict) else {}
            pkg_name = pkg_info.get("name") or pkg.get("name") or ""
            pkg_version = pkg_info.get("version") or pkg.get("version") or ""

            vulns = pkg.get("vulnerabilities") or []
            if not isinstance(vulns, list):
                continue

            for vuln in vulns:
                if not isinstance(vuln, dict):
                    continue
                osv_id = vuln.get("id") or vuln.get("osv_id") or ""
                aliases = vuln.get("aliases") or []
                cve = next((a for a in aliases if isinstance(a, str) and a.startswith("CVE-")), "")
                summary = vuln.get("summary") or vuln.get("details") or ""

                cvss_score = _extract_cvss(vuln)
                finding = {
                    "source": {
                        "tool": "osv-scanner",
                        "tool_version": tool_version,
                        "rule_id": osv_id,
                    },
                    "scan": {"scan_type": "deps", "status": "succeeded"},
                    "asset": {
                        "type": "repo",
                        "name": repo_path or "repo",
                    },
                    "finding": {
                        "type": "vuln",
                        "title": f"{pkg_name} {osv_id}".strip(),
                        "description": summary,
                        "severity": _severity_from_cvss(cvss_score),
                        "status": "open",
                        "cve": cve,
                        "cvss": {"score": cvss_score},
                    },
                    "evidence": {
                        "metadata": {
                            "package": pkg_name,
                            "version": pkg_version,
                            "ecosystem": pkg_info.get("ecosystem"),
                        }
                    },
                    "timestamps": {"detected_at": now_iso()},
                }
                findings.append(normalize_base(finding))

    # Fallback: top-level vulnerabilities list
    vulns = data.get("vulnerabilities")
    if isinstance(vulns, list) and vulns:
        for vuln in vulns:
            if not isinstance(vuln, dict):
                continue
            osv_id = vuln.get("id") or ""
            finding = {
                "source": {
                    "tool": "osv-scanner",
                    "tool_version": tool_version,
                    "rule_id": osv_id,
                },
                "scan": {"scan_type": "deps", "status": "succeeded"},
                "asset": {"type": "repo", "name": "repo"},
                "finding": {
                    "type": "vuln",
                    "title": osv_id,
                    "description": vuln.get("summary", ""),
                    "severity": "info",
                    "status": "open",
                },
                "timestamps": {"detected_at": now_iso()},
            }
            findings.append(normalize_base(finding))

    return findings
