import os

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

os.environ["DATABASE_URL"] = "sqlite://"
os.environ["REDIS_URL"] = "redis://localhost:6379/0"
os.environ["JWT_SECRET"] = "test-secret-for-testing-only-minimum-32-characters-long"
os.environ["DEV_MODE"] = "false"
os.environ["API_KEY"] = "test-api-key-for-worker"
os.environ["REGISTRATION_ENABLED"] = "true"
os.environ["COOKIE_SECURE"] = "false"
os.environ["CORS_ORIGINS"] = "http://localhost:3000"
os.environ["RATE_LIMIT_PER_MIN"] = "0"
os.environ["AUDIT_LOGS_ENABLED"] = "false"

from app.db import Base, get_db
from app.main import app

engine = create_engine(
    "sqlite://",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture(autouse=True)
def setup_db():
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def client():
    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture
def registered_user(client):
    resp = client.post(
        "/auth/register",
        json={
            "email": "test@example.com",
            "password": "TestPassword123!",
            "organization": "Test Org",
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    return {
        "email": "test@example.com",
        "password": "TestPassword123!",
        "cookies": resp.cookies,
        **data,
    }


@pytest.fixture
def auth_client(client, registered_user):
    resp = client.post(
        "/auth/login",
        json={
            "email": registered_user["email"],
            "password": registered_user["password"],
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


@pytest.fixture
def auth_with_profile(auth_client):
    resp = auth_client.patch(
        "/users/me/profile",
        json={
            "full_name": "Test User",
            "phone": "+57 300 1234567",
            "title": "Pentester",
        },
    )
    assert resp.status_code == 200
    return auth_client


@pytest.fixture
def project_id(auth_with_profile):
    orgs = auth_with_profile.get("/orgs").json()
    org_id = orgs[0]["id"]
    resp = auth_with_profile.post(f"/orgs/{org_id}/projects", json={"name": "Test Project"})
    assert resp.status_code == 200
    return resp.json()["id"]


@pytest.fixture
def asset_id(auth_with_profile, project_id):
    resp = auth_with_profile.post(
        "/assets",
        json={
            "project_id": project_id,
            "name": "Test App",
            "uri": "https://testapp.example.com",
            "type": "web_app",
            "owner_email": "owner@example.com",
            "environment": "prod",
            "criticality": "alta",
            "tags": [],
        },
    )
    assert resp.status_code == 200
    return resp.json()["id"]
