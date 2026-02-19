import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import requests
import redis
from jsonschema import Draft202012Validator

sys.path.append(str(Path(__file__).resolve().parents[1]))

from shared.adapters.nuclei import parse_nuclei_json
from shared.adapters.osv import parse_osv_json
from shared.adapters.sarif import parse_sarif
from shared.adapters.vulnapi import parse_vulnapi_json
from shared.adapters.wapiti import parse_wapiti_json
from .security import validate_scan_path, validate_scan_url, validate_target_path


def load_schema(schema_path: Path) -> dict:
    with schema_path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def validate_findings(findings: list[dict], schema: dict) -> list[str]:
    validator = Draft202012Validator(schema)
    errors = []
    for idx, finding in enumerate(findings):
        for err in validator.iter_errors(finding):
            errors.append(f"item {idx}: {err.message}")
    return errors


def parse_findings(tool: str, payload) -> list[dict]:
    adapters = {
        "nuclei": parse_nuclei_json,
        "vulnapi": parse_vulnapi_json,
        "wapiti": parse_wapiti_json,
        "osv": parse_osv_json,
        "sarif": parse_sarif,
    }
    adapter = adapters.get(tool)
    if not adapter:
        raise SystemExit(f"Unsupported tool: {tool}")
    return adapter(payload)


def post_ingest(api_base_url: str, tool: str, report: dict, findings: list[dict]) -> None:
    url = f"{api_base_url.rstrip('/')}/reports/ingest"
    response = requests.post(
        url,
        json={"tool": tool, "report": report, "findings": findings},
        headers=_auth_headers(),
        timeout=30,
    )
    if response.status_code >= 300:
        raise SystemExit(f"Failed ingest: {response.status_code} {response.text}")


def _auth_headers() -> dict:
    api_key = os.environ.get("API_KEY")
    if not api_key:
        return {}
    return {"X-API-Key": api_key}


def update_scan(api_base_url: str, scan_id: int, payload: dict) -> None:
    url = f"{api_base_url.rstrip('/')}/scans/{scan_id}"
    response = requests.patch(url, json=payload, headers=_auth_headers(), timeout=30)
    if response.status_code == 404:
        return
    if response.status_code >= 300:
        raise SystemExit(f"Failed to update scan: {response.status_code} {response.text}")


def run_command(args_list: list[str]) -> str:
    try:
        result = subprocess.run(args_list, check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as exc:
        output = (exc.stdout or "") + (exc.stderr or "")
        if output:
            raise RuntimeError(output.strip()) from exc
        raise
    return (result.stdout or "") + (result.stderr or "")


def load_report(report_path: str | None, report_payload, tool: str | None = None):
    if report_payload is not None:
        return report_payload
    if not report_path:
        raise SystemExit("Missing report payload or report_path")
    payload_path = Path(report_path)
    if not payload_path.exists():
        raise SystemExit(f"Report path not found: {payload_path}")
    with payload_path.open("r", encoding="utf-8") as handle:
        try:
            return json.load(handle)
        except json.JSONDecodeError:
            if tool != "nuclei":
                raise
            handle.seek(0)
            entries = []
            for idx, raw in enumerate(handle, start=1):
                line = raw.strip()
                if not line:
                    continue
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError as exc:
                    raise SystemExit(f"Invalid JSONL at line {idx}: {exc.msg}") from exc
            if not entries:
                raise SystemExit("Nuclei report is empty")
            return entries


def inject_project_id(findings: list[dict], project_id: str | int) -> list[dict]:
    for finding in findings:
        asset = finding.setdefault("asset", {})
        asset.setdefault("project_id", int(project_id))
    return findings


def handle_scan(api_base_url: str, scan: dict, schema_path: Path) -> None:
    scan_id = scan["id"]
    tool = scan["tool"]
    metadata = scan.get("metadata") or scan.get("scan_metadata") or {}
    update_scan(api_base_url, scan_id, {"status": "running"})

    report_path = metadata.get("report_path")
    report_payload = metadata.get("report")
    project_id = metadata.get("project_id")

    try:
        if tool not in TOOL_BINARIES:
            raise ValueError(f"Herramienta no permitida: {tool}")

        target_url = metadata.get("target_url", "")
        if target_url:
            target_url = validate_scan_url(target_url)

        target_path = metadata.get("target_path", "")
        if target_path:
            target_path = validate_target_path(target_path, base_dir="/app/data/targets")

        if not report_path:
            report_path = f"/app/data/reports/{scan_id}_{tool}.json"
        report_path = validate_scan_path(report_path, base_dir="/app/data/reports")

        safe_metadata = {
            **metadata,
            "target_url": target_url,
            "target_path": target_path,
            "report_path": report_path,
        }

        command = build_safe_args(tool, safe_metadata)
        if command:
            output = run_command(command)
            if output:
                post_scan_log(api_base_url, scan_id, output)

        if not project_id:
            raise SystemExit("project_id is required in scan metadata")
        report = load_report(report_path, report_payload, tool)
        findings = parse_findings(tool, report)
        findings = inject_project_id(findings, project_id)
        if schema_path.exists():
            schema = load_schema(schema_path)
            errors = validate_findings(findings, schema)
            if errors:
                raise SystemExit("Schema validation failed:\n" + "\n".join(errors[:20]))
        post_ingest(api_base_url, tool, report, findings)
        update_scan(
            api_base_url,
            scan_id,
            {"status": "finished", "metadata": {**safe_metadata, "finding_count": len(findings)}},
        )
    except Exception as exc:
        post_scan_log(api_base_url, scan_id, f"error: {exc}")
        update_scan(api_base_url, scan_id, {"status": "failed", "metadata": {**metadata, "error": str(exc)}})
        raise


def poll_scans(api_base_url: str, schema_path: Path, interval: int) -> None:
    while True:
        response = requests.get(
            f"{api_base_url.rstrip('/')}/scans/next",
            headers=_auth_headers(),
            timeout=30,
        )
        response.raise_for_status()
        scan = response.json()
        if not scan:
            time.sleep(interval)
            continue
        try:
            handle_scan(api_base_url, scan, schema_path)
        except Exception as exc:
            print(f"scan {scan.get('id', 'unknown')} failed: {exc}", file=sys.stderr)
            time.sleep(interval)


def post_scan_log(api_base_url: str, scan_id: int, message: str) -> None:
    url = f"{api_base_url.rstrip('/')}/scans/{scan_id}/logs"
    response = requests.post(url, json={"message": message}, headers=_auth_headers(), timeout=30)
    if response.status_code == 404:
        return
    if response.status_code >= 300:
        raise SystemExit(f"Failed to log scan: {response.status_code} {response.text}")


def queue_scans(api_base_url: str, schema_path: Path) -> None:
    redis_url = os.environ.get("REDIS_URL", "redis://redis:6379/0")
    client = redis.Redis.from_url(redis_url)
    while True:
        try:
            result = client.blpop("scan_queue", timeout=30)
        except redis.exceptions.ConnectionError as exc:
            print(f"redis connection error: {exc}", file=sys.stderr)
            time.sleep(2)
            client = redis.Redis.from_url(redis_url)
            continue
        if not result:
            continue
        _, raw_id = result
        scan_id = int(raw_id)
        response = requests.get(
            f"{api_base_url.rstrip('/')}/scans/{scan_id}",
            headers=_auth_headers(),
            timeout=30,
        )
        try:
            if response.status_code == 404:
                print(f"scan {scan_id} not found, skipping", file=sys.stderr)
                continue
            response.raise_for_status()
            scan = response.json()
            handle_scan(api_base_url, scan, schema_path)
        except Exception as exc:
            print(f"scan {scan_id} failed: {exc}", file=sys.stderr)


TOOL_BINARIES = {
    "wapiti": "/usr/bin/wapiti",
    "osv": "/usr/local/bin/osv-scanner",
    "nuclei": "/usr/local/bin/nuclei",
    "vulnapi": "/usr/bin/vulnapi",
    "sarif": "/usr/local/bin/osv-scanner",
}


def build_safe_args(tool: str, metadata: dict) -> list[str] | None:
    binary = TOOL_BINARIES.get(tool)
    if not binary:
        return None
    if tool == "wapiti":
        target_url = metadata.get("target_url")
        report_path = metadata.get("report_path")
        if target_url and report_path:
            return [binary, "-u", target_url, "-f", "json", "-o", report_path]
    if tool == "osv":
        target_path = metadata.get("target_path")
        report_path = metadata.get("report_path")
        if target_path and report_path:
            return [binary, "--format", "json", "--output", report_path, target_path]
    if tool == "vulnapi":
        target_url = metadata.get("target_url")
        report_path = metadata.get("report_path")
        if target_url and report_path:
            if target_url.endswith(".json") or "openapi" in target_url:
                openapi_url = target_url
            else:
                openapi_url = f"{target_url.rstrip('/')}/.well-known/openapi.json"
            return [
                binary,
                "scan",
                "openapi",
                openapi_url,
                "--report-format=json",
                "--report-transport=file",
                f"--report-file={report_path}",
            ]
    if tool == "sarif":
        target_path = metadata.get("target_path")
        report_path = metadata.get("report_path")
        if target_path and report_path:
            return [binary, "--format", "sarif", "--output", report_path, target_path]
    if tool == "nuclei":
        target_url = metadata.get("target_url")
        report_path = metadata.get("report_path")
        if target_url and report_path:
            rate_limit = os.environ.get("NUCLEI_RATE_LIMIT", "50")
            concurrency = os.environ.get("NUCLEI_CONCURRENCY", "10")
            return [
                binary,
                "-u",
                target_url,
                "-jsonl",
                "-o",
                report_path,
                "-rate-limit",
                rate_limit,
                "-c",
                concurrency,
            ]
    return None


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["ingest", "poll", "queue"], default="ingest")
    parser.add_argument("--tool", choices=["vulnapi", "wapiti", "osv", "sarif", "nuclei"])
    parser.add_argument("--input")
    parser.add_argument("--schema", default="/app/shared/schema/finding.schema.json")
    parser.add_argument("--api-base", default=os.environ.get("API_BASE_URL", "http://localhost:8000"))
    parser.add_argument("--interval", type=int, default=15)
    parser.add_argument("--project-id")
    args = parser.parse_args()

    schema_path = Path(args.schema)

    if args.mode == "poll":
        poll_scans(args.api_base, schema_path, args.interval)
        return
    if args.mode == "queue":
        queue_scans(args.api_base, schema_path)
        return

    if not args.tool or not args.input:
        raise SystemExit("--tool and --input are required in ingest mode")

    payload_path = Path(args.input)
    if not payload_path.exists():
        raise SystemExit(f"File not found: {payload_path}")

    with payload_path.open("r", encoding="utf-8") as handle:
        report = json.load(handle)

    project_id = args.project_id or os.environ.get("PROJECT_ID")
    if not project_id:
        raise SystemExit("--project-id or PROJECT_ID is required in ingest mode")

    findings = parse_findings(args.tool, report)
    findings = inject_project_id(findings, project_id)

    if schema_path.exists():
        schema = load_schema(schema_path)
        errors = validate_findings(findings, schema)
        if errors:
            raise SystemExit("Schema validation failed:\n" + "\n".join(errors[:20]))

    post_ingest(args.api_base, args.tool, report, findings)
    print(f"Ingested {len(findings)} findings for {args.tool}")


if __name__ == "__main__":
    main()
