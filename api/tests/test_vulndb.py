class TestVulnDB:
    def test_create_manual_template(self, auth_with_profile):
        resp = auth_with_profile.post(
            "/vulndb",
            json={
                "name": "Hardcoded Credentials",
                "description": "Credentials found in source code.",
                "severity": "high",
                "base_score": 7.5,
                "cwe_id": 798,
                "cwe_name": "CWE-798: Use of Hard-coded Credentials",
                "source": "manual",
                "is_template": True,
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["name"] == "Hardcoded Credentials"

    def test_search_vulndb(self, auth_with_profile):
        auth_with_profile.post(
            "/vulndb",
            json={
                "name": "CVE-2025-12345",
                "cve_id": "CVE-2025-12345",
                "description": "Remote code execution in example library.",
                "severity": "critical",
                "base_score": 9.8,
            },
        )
        resp = auth_with_profile.get("/vulndb/search?q=CVE-2025-12345")
        assert resp.status_code == 200
        results = resp.json().get("items", [])
        assert len(results) >= 1
        assert results[0]["cve_id"] == "CVE-2025-12345"

    def test_vulndb_stats(self, auth_with_profile):
        resp = auth_with_profile.get("/vulndb/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert "total" in data
        assert "by_severity" in data
