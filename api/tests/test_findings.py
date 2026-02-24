class TestFindings:
    def test_create_manual_finding(self, auth_with_profile, asset_id):
        resp = auth_with_profile.post(
            "/findings/manual",
            json={
                "asset_id": asset_id,
                "title": "SQL Injection en login",
                "severity": "critical",
                "status": "open",
                "cwe": "CWE-89",
                "description": "El parámetro username es vulnerable a SQL injection.",
                "recommendation": "Usar prepared statements.",
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["title"] == "SQL Injection en login"
        assert data["severity"] == "critical"
        assert data["asset_id"] == asset_id

    def test_list_findings(self, auth_with_profile, project_id, asset_id):
        auth_with_profile.post(
            "/findings/manual",
            json={
                "asset_id": asset_id,
                "title": "XSS Reflejado",
                "severity": "high",
            },
        )
        resp = auth_with_profile.get(f"/findings?project_id={project_id}")
        assert resp.status_code == 200
        payload = resp.json()
        findings = payload.get("items", [])
        assert len(findings) >= 1
        assert findings[0]["title"] == "XSS Reflejado"

    def test_update_finding(self, auth_with_profile, asset_id):
        create_resp = auth_with_profile.post(
            "/findings/manual",
            json={
                "asset_id": asset_id,
                "title": "IDOR",
                "severity": "high",
            },
        )
        finding_id = create_resp.json()["id"]
        resp = auth_with_profile.patch(
            f"/findings/{finding_id}",
            json={
                "status": "fixed",
            },
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "fixed"

    def test_finding_comments(self, auth_with_profile, asset_id):
        create_resp = auth_with_profile.post(
            "/findings/manual",
            json={
                "asset_id": asset_id,
                "title": "SSRF",
                "severity": "critical",
            },
        )
        finding_id = create_resp.json()["id"]
        resp = auth_with_profile.post(
            f"/findings/{finding_id}/comments",
            json={
                "message": "Confirmado con Burp Suite.",
            },
        )
        assert resp.status_code == 200
        resp = auth_with_profile.get(f"/findings/{finding_id}/comments")
        assert resp.status_code == 200
        assert len(resp.json()) >= 1
