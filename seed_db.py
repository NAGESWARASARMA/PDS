"""
Seed script for PDS AI.
Populates default admin and solver accounts plus sample challenges.
"""
import sqlite3
from datetime import datetime, timezone, timedelta
from pathlib import Path
from werkzeug.security import generate_password_hash

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "instance" / "pds.sqlite3"
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

def seed():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys = ON")
    
    # Ensure tables exist
    import app
    with app.app.app_context():
        app.init_db()

    now_iso = now()

    # 1. Seed Users
    admin_pw = generate_password_hash("AdminPass123!", method="scrypt")
    solver_pw = generate_password_hash("SolverPass123!", method="scrypt")

    conn.execute("""
        INSERT OR REPLACE INTO users (id, username, password_hash, bio, created_at)
        VALUES (1, 'admin', ?, 'Lead System Architect & Deployer', ?)
    """, (admin_pw, now_iso))

    conn.execute("""
        INSERT OR REPLACE INTO users (id, username, password_hash, bio, created_at)
        VALUES (2, 'solver', ?, 'Full-Stack Developer & Algorithm Specialist', ?)
    """, (solver_pw, now_iso))

    # 2. Seed Sample Challenges
    deadline_iso = (datetime.now(timezone.utc) + timedelta(days=14)).isoformat(timespec="minutes")

    conn.execute("""
        INSERT OR IGNORE INTO problems (
            id, public_id, user_id, title, statement, description, category,
            requirements, expected_result, skills, instructions, problem_type,
            reward, deadline, duration, deliverables, acceptance_criteria, status, views, created_at
        ) VALUES (
            1, 'AI-CHALLENGE-01', 1,
            'Real-Time Semantic Cache for LLM Embeddings',
            'Develop an in-memory vector similarity cache for high-frequency LLM queries to cut latency.',
            'When users query identical or semantically similar prompts, re-invoking the model causes unnecessary GPU cost and 1-2s latency. We need an approximate nearest neighbor (ANN) caching layer with sub-10ms response time.',
            'Artificial Intelligence and Machine Learning',
            'Python 3.10+, FAISS or USearch, Redis or SQLite fallback',
            'A modular caching decorator with similarity thresholding',
            'Python, Vectors, FAISS, Cache Design',
            'Submit proof-of-concept benchmarks comparing cache hit vs miss latency.',
            'Paid', 350.00, ?, '2 weeks', 'Source code + benchmark report',
            'Must achieve >90% precision on paraphrase evaluation set.',
            'Open', 42, ?
        )
    """, (deadline_iso, now_iso))

    conn.execute("""
        INSERT OR IGNORE INTO problems (
            id, public_id, user_id, title, statement, description, category,
            requirements, expected_result, skills, instructions, problem_type,
            reward, deadline, duration, deliverables, acceptance_criteria, status, views, created_at
        ) VALUES (
            2, 'WEB-CHALLENGE-02', 1,
            'Distributed WebSocket Broker with Pub/Sub',
            'Design a lightweight WebSocket coordination service for real-time collaboration.',
            'The system currently supports localized chat, but needs horizontal scaling across multiple instances with Redis Pub/Sub integration.',
            'Web Development',
            'Zero drop messages during node restart, reconnect fallback',
            'Connection manager and subscriber pool',
            'WebSockets, Python, AsyncIO',
            'Include test suite simulating 1,000 concurrent socket connections.',
            'Free', NULL, NULL, '1 week', 'Broker implementation + Dockerfile',
            'Passes automated concurrent load tests without memory leaks.',
            'Open', 19, ?
        )
    """, (now_iso,))

    conn.commit()
    conn.close()
    print("Database successfully seeded with demo accounts and challenges!")

if __name__ == "__main__":
    seed()
