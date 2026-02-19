from __future__ import annotations

from typing import Any, Dict, List

from .utils import map_severity, normalize_base, now_iso


def parse_sarif(data: Dict[str, Any], tool_name: str = "sarif") -> List[Dict[str, Any]]:
    runs = data.get("runs")
    if not isinstance(runs, list):
        return []

    findings: List[Dict[str, Any]] = []
    for run in runs:
        if not isinstance(run, dict):
            continue
        driver = run.get("tool", {}).get("driver", {}) if isinstance(run.get("tool"), dict) else {}
        tool_version = driver.get("version", "")
        actual_tool_name = driver.get("name", tool_name)

        results = run.get("results")
        if not isinstance(results, list):
            continue

        for result in results:
            if not isinstance(result, dict):
                continue
            rule_id = result.get("ruleId", "")
            message = result.get("message", {})
            title = message.get("text", "") if isinstance(message, dict) else str(message)
            level = result.get("level", "info")

            locations = result.get("locations") or []
            uri = ""
            if isinstance(locations, list) and locations:
                loc = locations[0]
                artifact = loc.get("physicalLocation", {}).get("artifactLocation", {}) if isinstance(loc, dict) else {}
                uri = artifact.get("uri", "") if isinstance(artifact, dict) else ""

            finding = {
                "source": {
                    "tool": actual_tool_name,
                    "tool_version": tool_version,
                    "rule_id": rule_id,
                },
                "scan": {"scan_type": "deps", "status": "succeeded"},
                "asset": {
                    "type": "repo",
                    "name": uri or "repo",
                },
                "finding": {
                    "type": "vuln",
                    "title": title or rule_id,
                    "description": "",
                    "severity": map_severity(level),
                    "status": "open",
                },
                "evidence": {
                    "metadata": {
                        "location": uri,
                    }
                },
                "timestamps": {"detected_at": now_iso()},
            }
            findings.append(normalize_base(finding))

    return findings
