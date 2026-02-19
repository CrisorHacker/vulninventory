import os
import unittest
import uuid

from fastapi.testclient import TestClient

os.environ["DATABASE_URL"] = "sqlite:///./test.db"
os.environ["REGISTRATION_ENABLED"] = "true"
os.environ["JWT_SECRET"] = "testsecret"

from app.main import app


class AuthTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = TestClient(app)

    def test_register_and_login(self) -> None:
        email = f"user-{uuid.uuid4().hex}@example.com"
        payload = {"email": email, "password": "Password123", "organization": "Acme"}
        response = self.client.post("/auth/register", json=payload)
        self.assertEqual(response.status_code, 200)
        self.assertIn("access_token", response.json())

        login = self.client.post("/auth/login", json={"email": email, "password": "Password123"})
        self.assertEqual(login.status_code, 200)
        self.assertIn("access_token", login.json())


if __name__ == "__main__":
    unittest.main()
