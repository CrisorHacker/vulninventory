#!/usr/bin/env python3
"""
NVD JSON Feed → VulnInventory JSONL Converter

Downloads CVE data from NVD and converts it to VulnInventory's JSONL format
for import into the VulnDB catalog.

Usage:
  # Convert a local NVD JSON file:
  python nvd_to_jsonl.py --input nvdcve-1.1-2026.json --output cves_2026.jsonl

  # Download from NVD API and convert (requires API key for higher rate limits):
  python nvd_to_jsonl.py --download --year 2026 --output cves_2026.jsonl
  python nvd_to_jsonl.py --download --year 2026 --api-key YOUR_NVD_API_KEY --output cves_2026.jsonl

  # Download all recent CVEs (last 30 days):
  python nvd_to_jsonl.py --download --recent --output cves_recent.jsonl

Output format (one JSON per line):
  {"name":"CVE-2026-XXXXX","short_id":"CVE-2026-XXXXX","base_score":7.5,...}
"""

import argparse
import json
import sys
import time
from datetime import datetime, timedelta
from typing import Optional

try:
    import requests
except ImportError:
    print("Install requests: pip install requests")
    sys.exit(1)


NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def parse_nvd_cve(cve_item: dict) -> Optional[dict]:
    """
    Parse a single CVE item from NVD API v2.0 format
    into VulnInventory JSONL format.
    """
    try:
        cve = cve_item.get("cve", cve_item)
        cve_id = cve.get("id", "")

        if not cve_id.startswith("CVE-"):
            return None

        descriptions = cve.get("descriptions", [])
        description_en = ""
        for desc in descriptions:
            if desc.get("lang") == "en":
                description_en = desc.get("value", "")
                break
        if not description_en and descriptions:
            description_en = descriptions[0].get("value", "")

        base_score = 0.0
        cvss_vector = ""
        metrics = cve.get("metrics", {})

        cvss_v31 = metrics.get("cvssMetricV31", [])
        cvss_v30 = metrics.get("cvssMetricV30", [])
        cvss_data_list = cvss_v31 or cvss_v30

        if cvss_data_list:
            primary = None
            for m in cvss_data_list:
                if m.get("type") == "Primary":
                    primary = m
                    break
            if not primary:
                primary = cvss_data_list[0]

            cvss_data = primary.get("cvssData", {})
            base_score = cvss_data.get("baseScore", 0.0)
            cvss_vector = cvss_data.get("vectorString", "")

        cwe_id = None
        cwe_name = ""
        weaknesses = cve.get("weaknesses", [])
        for w in weaknesses:
            for desc in w.get("description", []):
                val = desc.get("value", "")
                if val.startswith("CWE-"):
                    try:
                        cwe_id = int(val.replace("CWE-", ""))
                        cwe_name = val
                    except ValueError:
                        cwe_name = val
                    break
            if cwe_id:
                break

        refs = cve.get("references", [])
        ref_links = []
        for ref in refs:
            url = ref.get("url", "")
            if url:
                ref_links.append(f"- [{url}]({url})")
        references_text = "\n".join(ref_links) if ref_links else ""

        cpe_list = []
        configurations = cve.get("configurations", [])
        for config in configurations:
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    criteria = match.get("criteria", "")
                    if criteria:
                        cpe_list.append(criteria)

        published = cve.get("published", "")
        modified = cve.get("lastModified", "")

        exploit = False
        exploit_indicators = [
            "exploit-db.com",
            "packetstormsecurity",
            "github.com/poc",
            "exploit",
            "metasploit",
        ]
        for ref in refs:
            url = ref.get("url", "").lower()
            tags = [t.lower() for t in ref.get("tags", [])]
            if any(ind in url for ind in exploit_indicators) or "exploit" in tags:
                exploit = True
                break

        return {
            "name": cve_id,
            "short_id": cve_id,
            "base_score": base_score,
            "cvssv3": cvss_vector,
            "cwe_id": cwe_id,
            "cwe_name": cwe_name,
            "details": {"default": description_en},
            "recommendations": {"default": ""},
            "ext_references": {"default": references_text},
            "cpe": json.dumps(cpe_list) if cpe_list else "",
            "exploit": exploit,
            "published_date": published,
            "last_modified_date": modified,
            "auto": True,
            "hidden": False,
        }

    except Exception as e:
        print(
            f"  Warning: Failed to parse {cve_item.get('cve', {}).get('id', '?')}: {e}",
            file=sys.stderr,
        )
        return None


def convert_nvd_file(input_path: str, output_path: str) -> int:
    """Convert a local NVD JSON file to JSONL."""
    print(f"Reading {input_path}...")

    with open(input_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    vulnerabilities = data.get("vulnerabilities", [])

    if not vulnerabilities:
        cve_items = data.get("CVE_Items", [])
        if cve_items:
            print("Detected NVD v1.1 format — converting...")
            vulnerabilities = [{"cve": item.get("cve", {})} for item in cve_items]

    if not vulnerabilities:
        print("Error: No CVE items found in file.", file=sys.stderr)
        return 0

    count = 0
    with open(output_path, "w", encoding="utf-8") as out:
        for item in vulnerabilities:
            parsed = parse_nvd_cve(item)
            if parsed:
                out.write(json.dumps(parsed, ensure_ascii=False) + "\n")
                count += 1

    print(f"Converted {count} CVEs → {output_path}")
    return count


def download_nvd(
    output_path: str, year: int = None, recent: bool = False, api_key: str = None
) -> int:
    """Download CVEs from NVD API v2.0 and convert to JSONL."""

    headers = {}
    if api_key:
        headers["apiKey"] = api_key
        delay = 0.6
    else:
        delay = 6.0
        print("⚠ No API key provided. Using public rate limit (slow).")
        print("  Get a free API key at: https://nvd.nist.gov/developers/request-an-api-key")

    params = {
        "resultsPerPage": 2000,
        "startIndex": 0,
    }

    if recent:
        end = datetime.utcnow()
        start = end - timedelta(days=30)
        params["pubStartDate"] = start.strftime("%Y-%m-%dT00:00:00.000")
        params["pubEndDate"] = end.strftime("%Y-%m-%dT23:59:59.999")
        print("Downloading CVEs from last 30 days...")
    elif year:
        params["pubStartDate"] = f"{year}-01-01T00:00:00.000"
        params["pubEndDate"] = f"{year}-12-31T23:59:59.999"
        print(f"Downloading CVEs for year {year}...")
    else:
        print("Error: Specify --year or --recent", file=sys.stderr)
        return 0

    total_results = None
    count = 0

    with open(output_path, "w", encoding="utf-8") as out:
        while True:
            print(f"  Fetching startIndex={params['startIndex']}...", end=" ")

            try:
                resp = requests.get(NVD_API_BASE, params=params, headers=headers, timeout=30)
                resp.raise_for_status()
                data = resp.json()
            except Exception as e:
                print(f"\n  Error: {e}", file=sys.stderr)
                break

            if total_results is None:
                total_results = data.get("totalResults", 0)
                print(f"Total: {total_results} CVEs")

            vulnerabilities = data.get("vulnerabilities", [])
            if not vulnerabilities:
                print("done")
                break

            batch = 0
            for item in vulnerabilities:
                parsed = parse_nvd_cve(item)
                if parsed:
                    out.write(json.dumps(parsed, ensure_ascii=False) + "\n")
                    count += 1
                    batch += 1

            print(f"got {batch}")

            params["startIndex"] += len(vulnerabilities)

            if params["startIndex"] >= total_results:
                break

            time.sleep(delay)

    print(f"\nTotal: {count} CVEs → {output_path}")
    return count


def main():
    parser = argparse.ArgumentParser(
        description="NVD → VulnInventory JSONL Converter",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Convert local NVD JSON file:
  python nvd_to_jsonl.py --input nvdcve.json --output cves.jsonl

  # Download from NVD API (last 30 days):
  python nvd_to_jsonl.py --download --recent --output cves_recent.jsonl

  # Download full year with API key:
  python nvd_to_jsonl.py --download --year 2025 --api-key YOUR_KEY --output cves_2025.jsonl

Import into VulnInventory:
  UI:  Hallazgos → 📚 Catálogo → Importar JSONL
  API: curl -X POST http://localhost:8000/vulndb/import -F "file=@cves.jsonl"
        """,
    )

    parser.add_argument("--input", "-i", help="Local NVD JSON file to convert")
    parser.add_argument("--output", "-o", required=True, help="Output JSONL file path")
    parser.add_argument("--download", "-d", action="store_true", help="Download from NVD API")
    parser.add_argument("--year", "-y", type=int, help="Year to download (with --download)")
    parser.add_argument("--recent", "-r", action="store_true", help="Download last 30 days")
    parser.add_argument("--api-key", "-k", help="NVD API key (recommended, free at nvd.nist.gov)")

    args = parser.parse_args()

    if args.input:
        convert_nvd_file(args.input, args.output)
    elif args.download:
        download_nvd(args.output, year=args.year, recent=args.recent, api_key=args.api_key)
    else:
        parser.print_help()
        print("\nError: Specify --input or --download", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
