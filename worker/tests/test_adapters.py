import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.append(str(ROOT))

from shared.adapters.vulnapi import parse_vulnapi_json
from shared.adapters.osv import parse_osv_json


class AdapterTests(unittest.TestCase):
    def test_vulnapi_openapi(self) -> None:
        data = {
            "$schema": "schema",
            "openapi": {
                "paths": {
                    "/pets": {
                        "get": {
                            "operationId": "listPets",
                            "issues": [
                                {
                                    "id": "security_misconfiguration.http_headers_csp_missing",
                                    "name": "CSP Header is not set",
                                    "cvss": {"score": 5.1, "vector": "CVSS:4.0/..."},
                                    "classifications": {"owasp": "API8:2023 Security Misconfiguration"},
                                    "status": "failed",
                                }
                            ],
                        }
                    }
                }
            },
            "reports": [],
        }
        findings = parse_vulnapi_json(data)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["finding"]["severity"], "medium")

    def test_osv_minimal(self) -> None:
        data = {"results": [{"packages": []}]}
        findings = parse_osv_json(data)
        self.assertIsInstance(findings, list)


if __name__ == "__main__":
    unittest.main()
