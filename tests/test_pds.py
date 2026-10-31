import os
import pytest
import sqlite3
from pathlib import Path
import tempfile
import sys

# Ensure PDS app can be imported
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import app, init_db, db

@pytest.fixture
def client(monkeypatch):
    temp_dir = tempfile.TemporaryDirectory()
    temp_path = Path(temp_dir.name)
    db_file = temp_path / "test_pds.sqlite3"
    upload_path = temp_path / "uploads"
    upload_path.mkdir(parents=True, exist_ok=True)

    monkeypatch.setattr("app.DB_PATH", db_file)
    monkeypatch.setattr("app.UPLOAD_DIR", upload_path)
    monkeypatch.setattr("app.DATA_DIR", temp_path)
    
    app.config["TESTING"] = True
    app.config["SECRET_KEY"] = "test-secret-key-super-secure"
    
    with app.app_context():
        init_db()

    with app.test_client() as test_client:
        yield test_client

    temp_dir.cleanup()

def register_and_login(client, username="alice_tester", password="SecurePassword123!"):
    # 1. Register
    with client.session_transaction() as sess:
        sess["_csrf"] = "test_token"
    reg_resp = client.post("/auth", data={
        "_csrf": "test_token",
        "action": "register",
        "username": username,
        "password": password
    }, follow_redirects=True)
    assert reg_resp.status_code == 200

    # 2. Login
    with client.session_transaction() as sess:
        sess["_csrf"] = "test_token"
    login_resp = client.post("/auth", data={
        "_csrf": "test_token",
        "action": "login",
        "username": username,
        "password": password
    }, follow_redirects=True)
    assert login_resp.status_code == 200
    return login_resp

def test_homepage(client):
    """Verify landing page renders successfully."""
    response = client.get("/")
    assert response.status_code == 200
    assert b"ProblemBridge" in response.data

def test_auth_validation_rules(client):
    """Verify password complexity checks."""
    with client.session_transaction() as sess:
        sess["_csrf"] = "test_token"
    
    # Too short password
    resp = client.post("/auth", data={
        "_csrf": "test_token",
        "action": "register",
        "username": "short_user",
        "password": "Ab1"
    }, follow_redirects=True)
    assert b"at least 10 characters long" in resp.data

    # Missing uppercase/digit
    resp2 = client.post("/auth", data={
        "_csrf": "test_token",
        "action": "register",
        "username": "simple_user",
        "password": "passwordwithoutdigits"
    }, follow_redirects=True)
    assert b"one uppercase letter" in resp2.data

def test_csrf_protection(client):
    """Verify that requests missing CSRF tokens are rejected with 400."""
    response = client.post("/auth", data={
        "action": "login",
        "username": "attacker",
        "password": "Password123!"
    })
    assert response.status_code == 400

def test_problem_deployment_and_detail(client):
    """Verify problem deployment, DB storage, and detail viewing."""
    register_and_login(client, username="deployer_bob", password="Password123!")

    with client.session_transaction() as sess:
        csrf = sess["_csrf"]

    post_resp = client.post("/post", data={
        "_csrf": csrf,
        "problem_type": "Free",
        "category": "Artificial Intelligence and Machine Learning",
        "title": "Build a Resilient Rate Limiter",
        "statement": "Need an efficient in-memory token bucket rate limiter.",
        "description": "Must handle sliding windows and per-IP tracking cleanly in Python.",
        "requirements": "Python 3.10+",
        "skills": "Python, Algorithms"
    }, follow_redirects=True)
    assert post_resp.status_code == 200
    assert b"Build a Resilient Rate Limiter" in post_resp.data

def test_solution_submission_and_review_workflow(client):
    """Test full cycle: Deploy problem -> Submit solution -> Review and Accept."""
    # Deployer publishes problem
    register_and_login(client, username="deployer_charles", password="Password123!")
    with client.session_transaction() as sess:
        csrf = sess["_csrf"]

    client.post("/post", data={
        "_csrf": csrf,
        "problem_type": "Free",
        "category": "Web Development",
        "title": "Optimize SQLite Queries",
        "statement": "Need composite index optimization.",
        "description": "Detailed explanation of index creation."
    }, follow_redirects=True)

    # Logout deployer
    with client.session_transaction() as sess:
        csrf = sess["_csrf"]
    client.post("/logout", data={"_csrf": csrf}, follow_redirects=True)

    # Solver logs in and submits solution
    register_and_login(client, username="solver_diana", password="Password123!")
    with client.session_transaction() as sess:
        csrf = sess["_csrf"]

    solve_resp = client.post("/problem/1/solve", data={
        "_csrf": csrf,
        "explanation": "Here is a complete architectural solution with composite B-Tree indexes.",
        "implementation": "CREATE INDEX idx_name ON table(col1, col2);",
        "advantages": "Reduces query execution from O(N) to O(log N)."
    }, follow_redirects=True)
    assert solve_resp.status_code == 200
    assert b"submitted for deployer review" in solve_resp.data

    # Logout solver
    with client.session_transaction() as sess:
        csrf = sess["_csrf"]
    client.post("/logout", data={"_csrf": csrf}, follow_redirects=True)

    # Deployer logs back in to accept solution
    register_and_login(client, username="deployer_charles", password="Password123!")
    with client.session_transaction() as sess:
        csrf = sess["_csrf"]

    review_resp = client.post("/solution/1/status", data={
        "_csrf": csrf,
        "status": "Accepted",
        "review_feedback": "Exceptional work and clear benchmarks!"
    }, follow_redirects=True)
    assert review_resp.status_code == 200
    assert b"Solution marked as &#39;Accepted&#39;" in review_resp.data

    # Verify problem appears in solved showcase
    solved_resp = client.get("/solved")
    assert b"solver_diana" in solved_resp.data
    assert b"Optimize SQLite Queries" in solved_resp.data

def test_unauthorized_solution_status_update(client):
    """Verify IDOR security: a non-deployer cannot accept/reject solutions."""
    register_and_login(client, username="deployer_eve", password="Password123!")
    with client.session_transaction() as sess:
        csrf = sess["_csrf"]

    client.post("/post", data={
        "_csrf": csrf,
        "problem_type": "Free",
        "category": "Data Science",
        "title": "Data Pipeline Cleaning",
        "statement": "Clean pandas pipeline.",
        "description": "Detailed explanation."
    }, follow_redirects=True)

    # Malicious user attempts to review solution
    register_and_login(client, username="attacker_frank", password="Password123!")
    with client.session_transaction() as sess:
        csrf = sess["_csrf"]

    attack_resp = client.post("/solution/1/status", data={
        "_csrf": csrf,
        "status": "Accepted"
    })
    # Must be forbidden (403) or not found (404)
    assert attack_resp.status_code in (403, 404)
