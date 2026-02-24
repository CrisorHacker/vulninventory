class TestRegister:
    def test_register_success(self, client):
        resp = client.post(
            "/auth/register",
            json={
                "email": "new@example.com",
                "password": "Password123!",
                "organization": "New Org",
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "user" in data

    def test_register_duplicate_email(self, client, registered_user):
        resp = client.post(
            "/auth/register",
            json={
                "email": registered_user["email"],
                "password": "Password123!",
                "organization": "Another Org",
            },
        )
        assert resp.status_code == 400
        assert "ya está registrado" in resp.json()["detail"]

    def test_register_disabled(self, client, monkeypatch):
        monkeypatch.setenv("REGISTRATION_ENABLED", "false")
        resp = client.post(
            "/auth/register",
            json={
                "email": "blocked@example.com",
                "password": "Password123!",
                "organization": "New Org",
            },
        )
        assert resp.status_code == 403


class TestLogin:
    def test_login_success(self, client, registered_user):
        resp = client.post(
            "/auth/login",
            json={
                "email": registered_user["email"],
                "password": registered_user["password"],
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "user" in data

    def test_login_wrong_password(self, client, registered_user):
        resp = client.post(
            "/auth/login",
            json={
                "email": registered_user["email"],
                "password": "WrongPassword!",
            },
        )
        assert resp.status_code == 401

    def test_login_nonexistent_user(self, client):
        resp = client.post(
            "/auth/login",
            json={
                "email": "nobody@example.com",
                "password": "Password123!",
            },
        )
        assert resp.status_code == 401


class TestForgotPassword:
    def test_forgot_password_existing_user(self, client, registered_user):
        resp = client.post(
            "/auth/forgot-password",
            json={
                "email": registered_user["email"],
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "reset_token" in data
        assert data["reset_token"]

    def test_forgot_password_nonexistent_user(self, client):
        resp = client.post(
            "/auth/forgot-password",
            json={
                "email": "nobody@example.com",
            },
        )
        assert resp.status_code == 200
        assert resp.json().get("reset_token") is None


class TestProtectedEndpoints:
    def test_unauthenticated_access(self, client):
        endpoints = [
            ("get", "/orgs"),
            ("get", "/findings?project_id=1"),
            ("get", "/assets?project_id=1"),
            ("get", "/users/me"),
        ]
        for method, path in endpoints:
            resp = getattr(client, method)(path)
            assert resp.status_code in [401, 403], f"{method} {path} debería requerir auth"
