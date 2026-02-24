class TestAssets:
    def test_create_asset(self, auth_with_profile, project_id):
        resp = auth_with_profile.post(
            "/assets",
            json={
                "project_id": project_id,
                "name": "API Gateway",
                "uri": "https://api.example.com",
                "type": "api",
                "owner_email": "devops@example.com",
                "environment": "prod",
                "criticality": "alta",
                "tags": [],
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["name"] == "API Gateway"
        assert data["type"] == "api"

    def test_list_assets(self, auth_with_profile, project_id, asset_id):
        resp = auth_with_profile.get(f"/assets?project_id={project_id}")
        assert resp.status_code == 200
        payload = resp.json()
        assets = payload.get("items", [])
        assert len(assets) >= 1

    def test_update_asset(self, auth_with_profile, asset_id):
        resp = auth_with_profile.patch(
            f"/assets/{asset_id}",
            json={
                "criticality": "media",
            },
        )
        assert resp.status_code == 200
        assert resp.json()["criticality"] == "media"

    def test_delete_asset_with_findings_fails(self, auth_with_profile, asset_id):
        auth_with_profile.post(
            "/findings/manual",
            json={
                "asset_id": asset_id,
                "title": "Test Finding",
                "severity": "low",
            },
        )
        resp = auth_with_profile.delete(f"/assets/{asset_id}")
        assert resp.status_code == 400
        assert "hallazgos asociados" in resp.json()["detail"]
