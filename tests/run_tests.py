import unittest
import tempfile
import sqlite3
from pathlib import Path
import sys

# Ensure application can be imported
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import app

class TestPDSApplication(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp_dir.name)
        
        app.DB_PATH = self.temp_path / "test_pds.sqlite3"
        app.UPLOAD_DIR = self.temp_path / "uploads"
        app.UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
        app.DATA_DIR = self.temp_path
        
        app.app.config["TESTING"] = True
        app.app.config["SECRET_KEY"] = "super-secret-key-12345"
        
        with app.app.app_context():
            app.init_db()

        self.client = app.app.test_client()

    def tearDown(self):
        self.temp_dir.cleanup()

    def _login(self, username="alice", password="Password123!"):
        # Register
        with self.client.session_transaction() as sess:
            sess["_csrf"] = "csrf_test_token"
        self.client.post("/auth", data={
            "_csrf": "csrf_test_token",
            "action": "register",
            "username": username,
            "password": password
        }, follow_redirects=True)

        # Login
        with self.client.session_transaction() as sess:
            sess["_csrf"] = "csrf_test_token"
        return self.client.post("/auth", data={
            "_csrf": "csrf_test_token",
            "action": "login",
            "username": username,
            "password": password
        }, follow_redirects=True)

    def test_01_index_page(self):
        """Test landing page renders and displays platform stats."""
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"ProblemBridge", resp.data)
        self.assertIn(b"Enterprise Challenge Platform", resp.data)

    def test_02_password_policy(self):
        """Test password validation rules (length, uppercase, lowercase, digit)."""
        with self.client.session_transaction() as sess:
            sess["_csrf"] = "csrf_test_token"
        
        # Too short
        r1 = self.client.post("/auth", data={
            "_csrf": "csrf_test_token",
            "action": "register",
            "username": "short_user",
            "password": "Ab1"
        }, follow_redirects=True)
        self.assertIn(b"at least 10 characters long", r1.data)

        # No digits/uppercase
        r2 = self.client.post("/auth", data={
            "_csrf": "csrf_test_token",
            "action": "register",
            "username": "simple_user",
            "password": "alllowercasepassword"
        }, follow_redirects=True)
        self.assertIn(b"one uppercase letter", r2.data)

    def test_03_csrf_enforcement(self):
        """Ensure missing CSRF tokens cause a 400 Bad Request."""
        resp = self.client.post("/auth", data={
            "action": "login",
            "username": "hacker",
            "password": "Password123!"
        })
        self.assertEqual(resp.status_code, 400)

    def test_04_problem_deployment(self):
        """Deploy problem and verify database storage and public ID."""
        self._login(username="deployer_bob", password="Password123!")

        with self.client.session_transaction() as sess:
            csrf = sess["_csrf"]

        resp = self.client.post("/post", data={
            "_csrf": csrf,
            "problem_type": "Free",
            "category": "Web Development",
            "title": "Scale WebSocket Service",
            "statement": "Need WebSocket scaling architecture.",
            "description": "Comprehensive specifications for 100k concurrent connections.",
            "skills": "Python, Redis, WebSockets"
        }, follow_redirects=True)
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Scale WebSocket Service", resp.data)

    def test_05_solution_submission_and_atomic_acceptance(self):
        """Full end-to-end lifecycle test for submission, review, and atomic acceptance."""
        # 1. Bob posts problem
        self._login(username="deployer_bob", password="Password123!")
        with self.client.session_transaction() as sess:
            csrf = sess["_csrf"]
        self.client.post("/post", data={
            "_csrf": csrf,
            "problem_type": "Free",
            "category": "Artificial Intelligence and Machine Learning",
            "title": "LLM Inference Cache",
            "statement": "Cache LLM embeddings to reduce latency.",
            "description": "Complete architecture."
        }, follow_redirects=True)

        # Logout Bob
        with self.client.session_transaction() as sess:
            csrf = sess["_csrf"]
        self.client.post("/logout", data={"_csrf": csrf}, follow_redirects=True)

        # 2. Alice submits solution
        self._login(username="solver_alice", password="Password123!")
        with self.client.session_transaction() as sess:
            csrf = sess["_csrf"]
        sol_resp = self.client.post("/problem/1/solve", data={
            "_csrf": csrf,
            "explanation": "Here is an in-memory cosine similarity caching layer using FAISS.",
            "implementation": "import faiss\nindex = faiss.IndexFlatIP(768)",
            "advantages": "Sub-10ms response time on cache hits."
        }, follow_redirects=True)
        self.assertEqual(sol_resp.status_code, 200)
        self.assertIn(b"submitted for deployer review", sol_resp.data)

        # Logout Alice
        with self.client.session_transaction() as sess:
            csrf = sess["_csrf"]
        self.client.post("/logout", data={"_csrf": csrf}, follow_redirects=True)

        # 3. Bob accepts solution
        self._login(username="deployer_bob", password="Password123!")
        with self.client.session_transaction() as sess:
            csrf = sess["_csrf"]
        review_resp = self.client.post("/solution/1/status", data={
            "_csrf": csrf,
            "status": "Accepted",
            "review_feedback": "Approved! Excellent architectural proposal."
        }, follow_redirects=True)
        self.assertEqual(review_resp.status_code, 200)
        self.assertIn(b"Accepted", review_resp.data)

        # 4. Check solved showcase reflects completed work
        solved_resp = self.client.get("/solved")
        self.assertEqual(solved_resp.status_code, 200)
        self.assertIn(b"solver_alice", solved_resp.data)
        self.assertIn(b"LLM Inference Cache", solved_resp.data)

    def test_06_idor_protection(self):
        """Ensure third-party users cannot accept/review other deployer solutions."""
        # 1. Eve deploys problem
        self._login(username="deployer_eve", password="Password123!")
        with self.client.session_transaction() as sess:
            csrf = sess["_csrf"]
        self.client.post("/post", data={
            "_csrf": csrf,
            "problem_type": "Free",
            "category": "Healthcare",
            "title": "Medical Imaging Pipeline",
            "statement": "Need DICOM image normalization.",
            "description": "DICOM normalization pipeline."
        }, follow_redirects=True)

        with self.client.session_transaction() as sess:
            csrf = sess["_csrf"]
        self.client.post("/logout", data={"_csrf": csrf}, follow_redirects=True)

        # 2. Diana submits solution
        self._login(username="solver_diana2", password="Password123!")
        with self.client.session_transaction() as sess:
            csrf = sess["_csrf"]
        self.client.post("/problem/1/solve", data={
            "_csrf": csrf,
            "explanation": "Here is an open source DICOM parser solution with numpy arrays.",
            "implementation": "import pydicom",
            "advantages": "Safe and compliant."
        }, follow_redirects=True)

        with self.client.session_transaction() as sess:
            csrf = sess["_csrf"]
        self.client.post("/logout", data={"_csrf": csrf}, follow_redirects=True)

        # 3. Attacker Frank logs in and attempts to review Diana's solution on Eve's problem
        self._login(username="attacker_frank", password="Password123!")
        with self.client.session_transaction() as sess:
            csrf = sess["_csrf"]
        attack_resp = self.client.post("/solution/1/status", data={
            "_csrf": csrf,
            "status": "Accepted"
        })
        self.assertEqual(attack_resp.status_code, 403)

    def test_07_rate_limiting_enforcement(self):
        """Ensure high-frequency requests trigger 429 Too Many Requests."""
        app.app.config["TEST_RATE_LIMIT"] = True
        app.rate_limits.clear()
        with self.client.session_transaction() as sess:
            sess["_csrf"] = "csrf_test_token"
        
        # Fire rapid requests to /auth
        status_codes = []
        for i in range(20):
            r = self.client.post("/auth", data={
                "_csrf": "csrf_test_token",
                "action": "login",
                "username": f"user_{i}",
                "password": "Password123!"
            })
            status_codes.append(r.status_code)
        
        self.assertIn(429, status_codes)
        app.app.config["TEST_RATE_LIMIT"] = False

if __name__ == "__main__":
    unittest.main()
