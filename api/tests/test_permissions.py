class TestMultiTenant:
    def _login_other_user(self, client):
        resp = client.post(
            "/auth/register",
            json={
                "email": "other@example.com",
                "password": "Password123!",
                "organization": "Other Org",
            },
        )
        assert resp.status_code == 200
        resp = client.post(
            "/auth/login",
            json={
                "email": "other@example.com",
                "password": "Password123!",
            },
        )
        assert resp.status_code == 200
        csrf = client.cookies.get("csrf_token")
        if csrf:
            client.headers.update(
                {
                    "X-CSRF-Token": csrf,
                    "Origin": "http://localhost:3000",
                }
            )
        return client

    def test_cannot_access_other_org_project(self, client, auth_with_profile, project_id):
        other_client = self._login_other_user(client)
        resp = other_client.patch(
            "/users/me/profile",
            json={
                "full_name": "Other User",
                "phone": "+57 300 0000000",
                "title": "Analyst",
            },
        )
        assert resp.status_code == 200
        resp = other_client.get(f"/findings?project_id={project_id}")
        assert resp.status_code == 403

    def test_cannot_access_other_org_assets(self, client, auth_with_profile, project_id):
        other_client = self._login_other_user(client)
        resp = other_client.patch(
            "/users/me/profile",
            json={
                "full_name": "Other User",
                "phone": "+57 300 0000000",
                "title": "Analyst",
            },
        )
        assert resp.status_code == 200
        resp = other_client.get(f"/assets?project_id={project_id}")
        assert resp.status_code == 403
