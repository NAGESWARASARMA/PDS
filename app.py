"""
PDS (Problem Deployment & Solving) — Production Master Application
Architected for high security, data integrity, concurrency protection, and performance.
"""

import os
import re
import sqlite3
import secrets
import uuid
import time
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path
from collections import defaultdict

from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, abort, send_from_directory, g, jsonify
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

BASE_DIR = Path(__file__).resolve().parent

# Configurable Data Directory with persistent fallback
if os.environ.get("VERCEL") == "1":
    DATA_DIR = Path("/tmp/pds")
else:
    DATA_DIR = Path(os.environ.get("PDS_DATA_DIR", str(BASE_DIR / "instance")))

UPLOAD_DIR = DATA_DIR / "private_uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

DB_PATH = Path(
    os.environ.get("PDS_DB", str(DATA_DIR / "pds.sqlite3"))
)
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

ALLOWED_EXTENSIONS = {
    "pdf", "txt", "py", "java", "c", "cpp", "js",
    "html", "css", "zip", "docx", "md", "png", "jpg", "jpeg"
}
MAX_CONTENT_LENGTH = 10 * 1024 * 1024  # 10 MB limit

# File magic byte signatures for safety checking
MAGIC_SIGNATURES = {
    "png": [b"\x89PNG\r\n\x1a\n"],
    "jpg": [b"\xff\xd8\xff"],
    "jpeg": [b"\xff\xd8\xff"],
    "pdf": [b"%PDF"],
    "zip": [b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"],
    "docx": [b"PK\x03\x04"],  # DOCX is a zip container
}

CATEGORIES = [
    "Artificial Intelligence and Machine Learning",
    "Agriculture",
    "Business Studies",
    "Transportation",
    "Education",
    "Healthcare",
    "Web Development",
    "Mobile Applications",
    "Python and Programming",
    "Data Science",
    "Environment",
    "Other"
]

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY") or secrets.token_hex(32),
    MAX_CONTENT_LENGTH=MAX_CONTENT_LENGTH,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1",
    PERMANENT_SESSION_LIFETIME=86400 * 7,  # 7-day session duration
)

# ---------------------------------------------------------
# Security Headers & Rate Limiting
# ---------------------------------------------------------

@app.after_request
def set_security_headers(response):
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "font-src 'self' https://fonts.gstatic.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "img-src 'self' data: https:; "
        "script-src 'self' 'unsafe-inline';"
    )
    return response

# In-Memory Rate Limiter (Token bucket per IP / User)
rate_limits = defaultdict(list)

def rate_limit(key_prefix, limit, window_seconds):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if app.config.get("TESTING") and not app.config.get("TEST_RATE_LIMIT"):
                return fn(*args, **kwargs)
            ip = request.headers.get("X-Forwarded-For", request.remote_addr or "127.0.0.1").split(",")[0].strip()
            user_id = session.get("user_id")
            key = f"{key_prefix}:{user_id or ip}"
            now_ts = time.time()
            # Clean expired timestamps
            rate_limits[key] = [ts for ts in rate_limits[key] if now_ts - ts < window_seconds]
            if len(rate_limits[key]) >= limit:
                abort(429, f"Too many requests. Please wait a moment before trying again.")
            rate_limits[key].append(now_ts)
            return fn(*args, **kwargs)
        return wrapper
    return decorator

# ---------------------------------------------------------
# Database Infrastructure & Connection Management
# ---------------------------------------------------------

def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH, timeout=10.0)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
        g.db.execute("PRAGMA journal_mode = WAL")
        g.db.execute("PRAGMA busy_timeout = 5000")
    return g.db

@app.teardown_appcontext
def close_db(exc):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()

def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys = ON")
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      bio TEXT DEFAULT '',
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS problems (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      public_id TEXT UNIQUE NOT NULL,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      title TEXT NOT NULL,
      statement TEXT NOT NULL,
      description TEXT NOT NULL,
      category TEXT NOT NULL,
      requirements TEXT DEFAULT '',
      expected_result TEXT DEFAULT '',
      skills TEXT DEFAULT '',
      instructions TEXT DEFAULT '',
      problem_type TEXT NOT NULL CHECK(problem_type IN ('Free','Paid')),
      reward REAL,
      deadline TEXT,
      duration TEXT DEFAULT '',
      deliverables TEXT DEFAULT '',
      acceptance_criteria TEXT DEFAULT '',
      attachment_name TEXT,
      attachment_key TEXT,
      status TEXT NOT NULL DEFAULT 'Open' CHECK(status IN ('Open', 'Solved', 'Closed')),
      views INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL,
      accepted_solution_id INTEGER
    );

    CREATE TABLE IF NOT EXISTS solutions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      problem_id INTEGER NOT NULL REFERENCES problems(id) ON DELETE CASCADE,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      explanation TEXT NOT NULL,
      implementation TEXT DEFAULT '',
      advantages TEXT DEFAULT '',
      filename TEXT,
      file_key TEXT,
      status TEXT NOT NULL DEFAULT 'Pending' CHECK(status IN ('Pending', 'Accepted', 'Rejected', 'Changes requested')),
      review_feedback TEXT DEFAULT '',
      created_at TEXT NOT NULL,
      UNIQUE(problem_id, user_id)
    );

    CREATE TABLE IF NOT EXISTS messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      problem_id INTEGER NOT NULL REFERENCES problems(id) ON DELETE CASCADE,
      sender_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      recipient_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      body TEXT NOT NULL,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      actor_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
      problem_id INTEGER REFERENCES problems(id) ON DELETE CASCADE,
      action TEXT NOT NULL,
      details TEXT DEFAULT '',
      created_at TEXT NOT NULL
    );

    -- High performance composite indexes
    CREATE INDEX IF NOT EXISTS idx_problems_status_created ON problems(status, created_at DESC);
    CREATE INDEX IF NOT EXISTS idx_problems_category ON problems(category);
    CREATE INDEX IF NOT EXISTS idx_problems_user ON problems(user_id);
    CREATE INDEX IF NOT EXISTS idx_solutions_problem ON solutions(problem_id);
    CREATE INDEX IF NOT EXISTS idx_solutions_user ON solutions(user_id);
    CREATE INDEX IF NOT EXISTS idx_messages_conversation ON messages(problem_id, sender_id, recipient_id);
    CREATE INDEX IF NOT EXISTS idx_events_actor ON events(actor_id, created_at DESC);
    """)

    # Migration check for review_feedback column
    cursor = conn.execute("PRAGMA table_info(solutions)")
    columns = [row[1] for row in cursor.fetchall()]
    if "review_feedback" not in columns:
        conn.execute("ALTER TABLE solutions ADD COLUMN review_feedback TEXT DEFAULT ''")

    conn.commit()
    conn.close()

# ---------------------------------------------------------
# Authentication, CSRF & Context Helpers
# ---------------------------------------------------------

def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    return db().execute("SELECT id, username, bio, created_at FROM users WHERE id=?", (uid,)).fetchone()

@app.context_processor
def inject_globals():
    return {
        "current_user": current_user(),
        "categories": CATEGORIES,
        "now_year": datetime.now(timezone.utc).year
    }

def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not current_user():
            flash("Please sign in to continue.", "error")
            return redirect(url_for("auth", next=request.path))
        return fn(*args, **kwargs)
    return wrapper

def csrf_token():
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_urlsafe(32)
    return session["_csrf"]

@app.before_request
def csrf_protect():
    if request.method in ("POST", "PUT", "DELETE", "PATCH"):
        sent = request.form.get("_csrf") or request.headers.get("X-CSRFToken", "")
        expected = session.get("_csrf", "")
        if not expected or not secrets.compare_digest(sent, expected):
            abort(400, "Invalid or expired security token. Please refresh the page.")

@app.context_processor
def inject_csrf():
    return {"csrf_token": csrf_token}

# ---------------------------------------------------------
# Secure File Upload Inspection
# ---------------------------------------------------------

def validate_magic_bytes(file_stream, ext):
    """Verifies that binary file content matches the declared extension."""
    if ext in MAGIC_SIGNATURES:
        header = file_stream.read(16)
        file_stream.seek(0)
        valid = any(header.startswith(sig) for sig in MAGIC_SIGNATURES[ext])
        if not valid:
            raise ValueError(f"File content does not match .{ext} file signature.")
    elif ext in ("exe", "bat", "cmd", "sh", "vbs", "msi", "dll"):
        raise ValueError("Executable files are strictly forbidden.")

def save_upload(file):
    if not file or not file.filename:
        return None, None, None
    original = secure_filename(file.filename)
    if not original or "." not in original:
        raise ValueError("Invalid filename. Must contain a valid extension.")
    ext = original.rsplit(".", 1)[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise ValueError(f"File extension '.{ext}' is not permitted.")
    
    validate_magic_bytes(file.stream, ext)
    
    key = f"{secrets.token_hex(24)}.{ext}"
    destination = UPLOAD_DIR / key
    file.save(destination)
    return original, key, ext

def log_event(actor, problem_id, action, details=""):
    db().execute(
        "INSERT INTO events(actor_id, problem_id, action, details, created_at) VALUES (?, ?, ?, ?, ?)",
        (actor, problem_id, action, details[:500], now())
    )
    db().commit()

# ---------------------------------------------------------
# Core User Workflows & Views
# ---------------------------------------------------------

@app.get("/")
def index():
    rows = db().execute("""
        SELECT p.*, u.username AS deployer_name,
               (SELECT COUNT(*) FROM solutions s WHERE s.problem_id = p.id) AS solution_count
        FROM problems p 
        JOIN users u ON u.id = p.user_id
        WHERE p.status = 'Open' 
        ORDER BY p.created_at DESC 
        LIMIT 6
    """).fetchall()
    
    stats = {
        "open_problems": db().execute("SELECT COUNT(*) FROM problems WHERE status='Open'").fetchone()[0],
        "solved_problems": db().execute("SELECT COUNT(*) FROM problems WHERE status='Solved'").fetchone()[0],
        "total_solutions": db().execute("SELECT COUNT(*) FROM solutions").fetchone()[0],
    }
    return render_template("home.html", problems=rows, platform_stats=stats)

@app.route("/auth", methods=["GET", "POST"])
@rate_limit("auth", limit=15, window_seconds=60)
def auth():
    if current_user():
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        action = request.form.get("action")
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not re.fullmatch(r"[A-Za-z0-9_.-]{3,40}", username):
            flash("Username must be 3–40 characters (letters, numbers, dot, underscore, or hyphen).", "error")
        elif action == "register":
            if len(password) < 10:
                flash("Password must be at least 10 characters long.", "error")
            elif not any(c.isupper() for c in password) or not any(c.islower() for c in password) or not any(c.isdigit() for c in password):
                flash("Password must contain at least one uppercase letter, one lowercase letter, and one number.", "error")
            else:
                try:
                    db().execute(
                        "INSERT INTO users(username, password_hash, created_at) VALUES (?, ?, ?)",
                        (username, generate_password_hash(password, method="scrypt"), now())
                    )
                    db().commit()
                    flash("Account created successfully! Please log in.", "success")
                    return redirect(url_for("auth"))
                except sqlite3.IntegrityError:
                    flash("That username is already taken. Please choose another.", "error")

        elif action == "login":
            user = db().execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
            if user and check_password_hash(user["password_hash"], password):
                session.clear()
                session.permanent = True
                session["user_id"] = user["id"]
                session["_csrf"] = secrets.token_urlsafe(32)
                flash(f"Welcome back, {user['username']}!", "success")
                next_url = request.args.get("next", "")
                if next_url and next_url.startswith("/") and not next_url.startswith("//"):
                    return redirect(next_url)
                return redirect(url_for("dashboard"))
            flash("Invalid username or password.", "error")
        else:
            flash("Invalid action submitted.", "error")

    return render_template("auth.html")

@app.post("/logout")
@login_required
def logout():
    session.clear()
    flash("You have been signed out safely.", "success")
    return redirect(url_for("index"))

@app.get("/dashboard")
@login_required
def dashboard():
    q = request.args.get("q", "").strip()[:100]
    kind = request.args.get("type", "All")
    category = request.args.get("category", "")
    sort = request.args.get("sort", "newest")
    page = max(1, request.args.get("page", 1, type=int))
    per_page = 9

    sql = """
        SELECT p.*, u.username AS deployer_name,
               (SELECT COUNT(*) FROM solutions s WHERE s.problem_id = p.id) AS solution_count
        FROM problems p 
        JOIN users u ON u.id = p.user_id 
        WHERE p.status = 'Open'
    """
    params = []

    if kind in ("Free", "Paid"):
        sql += " AND p.problem_type = ?"
        params.append(kind)
    if category in CATEGORIES:
        sql += " AND p.category = ?"
        params.append(category)
    if q:
        sql += " AND (p.title LIKE ? OR p.statement LIKE ? OR p.description LIKE ? OR p.skills LIKE ?)"
        wildcard = f"%{q}%"
        params.extend([wildcard, wildcard, wildcard, wildcard])

    order_map = {
        "newest": "p.created_at DESC",
        "oldest": "p.created_at ASC",
        "views": "p.views DESC",
        "reward": "p.reward DESC",
        "deadline": "p.deadline ASC"
    }
    order = order_map.get(sort, "p.created_at DESC")
    if sort in ("reward", "deadline") and kind != "Paid":
        order = "p.created_at DESC"

    # Count total for pagination
    count_sql = f"SELECT COUNT(*) FROM ({sql})"
    total_records = db().execute(count_sql, params).fetchone()[0]
    total_pages = max(1, (total_records + per_page - 1) // per_page)

    sql += f" ORDER BY {order} LIMIT ? OFFSET ?"
    params.extend([per_page, (page - 1) * per_page])
    rows = db().execute(sql, params).fetchall()

    return render_template(
        "dashboard.html",
        problems=rows,
        q=q,
        kind=kind,
        category=category,
        sort=sort,
        page=page,
        total_pages=total_pages,
        total_records=total_records
    )

@app.route("/post", methods=["GET", "POST"])
@login_required
@rate_limit("post_problem", limit=6, window_seconds=300)
def post():
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        statement = request.form.get("statement", "").strip()
        description = request.form.get("description", "").strip()
        category = request.form.get("category", "Other")
        kind = request.form.get("problem_type", "Free")
        reward_raw = request.form.get("reward", "").strip()
        deadline = request.form.get("deadline", "").strip()

        if not title or not statement or not description or category not in CATEGORIES or kind not in ("Free", "Paid"):
            flash("Please complete all required fields.", "error")
            return render_template("post.html")

        reward = None
        if kind == "Paid":
            try:
                reward = round(float(reward_raw), 2)
            except ValueError:
                reward = 0.0
            try:
                deadline_dt = datetime.fromisoformat(deadline)
                if deadline_dt.tzinfo is None:
                    deadline_dt = deadline_dt.replace(tzinfo=timezone.utc)
                if deadline_dt <= datetime.now(timezone.utc):
                    raise ValueError()
            except Exception:
                deadline_dt = None

            if reward <= 0 or deadline_dt is None:
                flash("Paid problems require a reward amount greater than 0 and a future deadline.", "error")
                return render_template("post.html")
            deadline = deadline_dt.isoformat(timespec="minutes")

        try:
            attachment_name, attachment_key, _ = save_upload(request.files.get("attachment"))
        except ValueError as e:
            flash(str(e), "error")
            return render_template("post.html")

        cur = db().execute("""
            INSERT INTO problems (
                public_id, user_id, title, statement, description, category,
                requirements, expected_result, skills, instructions, problem_type,
                reward, deadline, duration, deliverables, acceptance_criteria,
                attachment_name, attachment_key, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            uuid.uuid4().hex[:12].upper(),
            current_user()["id"],
            title,
            statement,
            description,
            category,
            request.form.get("requirements", "").strip(),
            request.form.get("expected_result", "").strip(),
            request.form.get("skills", "").strip(),
            request.form.get("instructions", "").strip(),
            kind,
            reward,
            deadline if kind == "Paid" else None,
            request.form.get("duration", "").strip(),
            request.form.get("deliverables", "").strip(),
            request.form.get("acceptance_criteria", "").strip(),
            attachment_name,
            attachment_key,
            now()
        ))
        db().commit()
        log_event(current_user()["id"], cur.lastrowid, "problem_created", f"Type: {kind}")
        flash("Your challenge has been published successfully!", "success")
        return redirect(url_for("detail", problem_id=cur.lastrowid))

    return render_template("post.html")

@app.get("/problem/<int:problem_id>")
@login_required
def detail(problem_id):
    p = db().execute("""
        SELECT p.*, u.username AS deployer_name 
        FROM problems p 
        JOIN users u ON u.id = p.user_id 
        WHERE p.id = ?
    """, (problem_id,)).fetchone()
    if not p:
        abort(404)

    # Increment view counter atomically
    db().execute("UPDATE problems SET views = views + 1 WHERE id = ?", (problem_id,))
    db().commit()

    user_id = current_user()["id"]
    own = (p["user_id"] == user_id)
    my_solution = db().execute(
        "SELECT * FROM solutions WHERE problem_id = ? AND user_id = ?",
        (problem_id, user_id)
    ).fetchone()

    solutions = []
    if own:
        solutions = db().execute("""
            SELECT s.*, u.username 
            FROM solutions s 
            JOIN users u ON u.id = s.user_id 
            WHERE s.problem_id = ? 
            ORDER BY s.created_at DESC
        """, (problem_id,)).fetchall()

    accepted_solution = None
    if p["status"] == "Solved" and p["accepted_solution_id"]:
        accepted_solution = db().execute("""
            SELECT s.*, u.username AS solver_name
            FROM solutions s
            JOIN users u ON u.id = s.user_id
            WHERE s.id = ?
        """, (p["accepted_solution_id"],)).fetchone()

    return render_template(
        "problem.html",
        p=p,
        own=own,
        already=bool(my_solution),
        my_solution=my_solution,
        solutions=solutions,
        accepted_solution=accepted_solution
    )

@app.get("/problem/<int:problem_id>/attachment")
@login_required
def problem_attachment(problem_id):
    p = db().execute("SELECT * FROM problems WHERE id = ?", (problem_id,)).fetchone()
    if not p or not p["attachment_key"]:
        abort(404)
    return send_from_directory(
        UPLOAD_DIR,
        p["attachment_key"],
        as_attachment=True,
        download_name=p["attachment_name"]
    )

@app.route("/problem/<int:problem_id>/solve", methods=["GET", "POST"])
@login_required
@rate_limit("solve_submission", limit=10, window_seconds=600)
def solve(problem_id):
    p = db().execute("SELECT * FROM problems WHERE id = ?", (problem_id,)).fetchone()
    if not p:
        abort(404)
    if p["user_id"] == current_user()["id"]:
        flash("You cannot submit a solution to your own problem.", "error")
        return redirect(url_for("detail", problem_id=problem_id))
    if p["status"] != "Open":
        flash("This problem is no longer accepting submissions.", "error")
        return redirect(url_for("detail", problem_id=problem_id))

    if p["problem_type"] == "Paid" and p["deadline"]:
        try:
            d = datetime.fromisoformat(p["deadline"])
            if d.tzinfo is None:
                d = d.replace(tzinfo=timezone.utc)
            if d <= datetime.now(timezone.utc):
                flash("The submission deadline for this problem has passed.", "error")
                return redirect(url_for("detail", problem_id=problem_id))
        except ValueError:
            pass

    if request.method == "POST":
        explanation = request.form.get("explanation", "").strip()
        if len(explanation) < 20:
            flash("Please provide a solution explanation of at least 20 characters.", "error")
            return render_template("solve.html", p=p)

        existing = db().execute(
            "SELECT id, status FROM solutions WHERE problem_id = ? AND user_id = ?",
            (problem_id, current_user()["id"])
        ).fetchone()

        if existing and existing["status"] != "Changes requested":
            flash("You have already submitted a solution for this problem.", "error")
            return redirect(url_for("detail", problem_id=problem_id))

        try:
            filename, file_key, _ = save_upload(request.files.get("solution_file"))
        except ValueError as e:
            flash(str(e), "error")
            return render_template("solve.html", p=p)

        if existing and existing["status"] == "Changes requested":
            # Update existing submission
            db().execute("""
                UPDATE solutions 
                SET explanation = ?, implementation = ?, advantages = ?, 
                    filename = COALESCE(?, filename), file_key = COALESCE(?, file_key),
                    status = 'Pending', created_at = ?
                WHERE id = ?
            """, (
                explanation,
                request.form.get("implementation", "").strip(),
                request.form.get("advantages", "").strip(),
                filename,
                file_key,
                now(),
                existing["id"]
            ))
            db().commit()
            log_event(current_user()["id"], problem_id, "solution_revised")
            flash("Your revised solution has been submitted for review.", "success")
        else:
            db().execute("""
                INSERT INTO solutions (
                    problem_id, user_id, explanation, implementation, advantages,
                    filename, file_key, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                problem_id,
                current_user()["id"],
                explanation,
                request.form.get("implementation", "").strip(),
                request.form.get("advantages", "").strip(),
                filename,
                file_key,
                now()
            ))
            db().commit()
            log_event(current_user()["id"], problem_id, "solution_submitted")
            flash("Your solution has been submitted for deployer review.", "success")

        return redirect(url_for("detail", problem_id=problem_id))

    return render_template("solve.html", p=p)

@app.post("/solution/<int:solution_id>/status")
@login_required
def solution_status(solution_id):
    """
    Transaction-guarded review transition to eliminate race conditions.
    """
    conn = db()
    s = conn.execute("""
        SELECT s.*, p.user_id AS deployer_id, p.status AS problem_status, p.id AS pid
        FROM solutions s 
        JOIN problems p ON p.id = s.problem_id 
        WHERE s.id = ?
    """, (solution_id,)).fetchone()

    if not s:
        abort(404)
    if s["deployer_id"] != current_user()["id"]:
        abort(403)
    if s["problem_status"] != "Open":
        abort(409, "Problem is already closed or solved.")

    action = request.form.get("status")
    feedback = request.form.get("review_feedback", "").strip()[:1000]

    if action not in ("Accepted", "Rejected", "Changes requested"):
        abort(400, "Invalid status choice.")

    # Concurrency safe state mutation
    try:
        conn.execute("BEGIN IMMEDIATE")
        if action == "Accepted":
            # Reject remaining pending solutions
            conn.execute(
                "UPDATE solutions SET status = 'Rejected' WHERE problem_id = ? AND id <> ? AND status = 'Pending'",
                (s["pid"], solution_id)
            )
            conn.execute(
                "UPDATE solutions SET status = 'Accepted', review_feedback = ? WHERE id = ?",
                (feedback, solution_id)
            )
            conn.execute(
                "UPDATE problems SET status = 'Solved', accepted_solution_id = ? WHERE id = ?",
                (solution_id, s["pid"])
            )
        else:
            conn.execute(
                "UPDATE solutions SET status = ?, review_feedback = ? WHERE id = ?",
                (action, feedback, solution_id)
            )
        conn.commit()
    except Exception as e:
        conn.rollback()
        flash("A concurrency conflict occurred. Please try again.", "error")
        return redirect(url_for("detail", problem_id=s["pid"]))

    log_event(current_user()["id"], s["pid"], f"solution_{action.lower()}", feedback)
    flash(f"Review updated: Solution marked as '{action}'.", "success")
    return redirect(url_for("detail", problem_id=s["pid"]))

@app.get("/solution/<int:solution_id>/file")
@login_required
def solution_file(solution_id):
    s = db().execute("""
        SELECT s.*, p.user_id AS deployer_id, p.id AS pid 
        FROM solutions s 
        JOIN problems p ON p.id = s.problem_id 
        WHERE s.id = ?
    """, (solution_id,)).fetchone()
    if not s or not s["file_key"]:
        abort(404)
    if current_user()["id"] not in (s["user_id"], s["deployer_id"]) and s["status"] != "Accepted":
        abort(403)
    return send_from_directory(
        UPLOAD_DIR,
        s["file_key"],
        as_attachment=True,
        download_name=s["filename"]
    )

@app.get("/solved")
def solved():
    page = max(1, request.args.get("page", 1, type=int))
    per_page = 9
    offset = (page - 1) * per_page

    total_records = db().execute(
        "SELECT COUNT(*) FROM problems WHERE status = 'Solved' AND accepted_solution_id IS NOT NULL"
    ).fetchone()[0]
    total_pages = max(1, (total_records + per_page - 1) // per_page)

    rows = db().execute("""
        SELECT p.*, du.username AS deployer_name, su.username AS solver_name,
               s.explanation AS solution_description, s.filename, s.id AS solution_id
        FROM problems p 
        JOIN users du ON du.id = p.user_id
        JOIN solutions s ON s.id = p.accepted_solution_id 
        JOIN users su ON su.id = s.user_id
        WHERE p.status = 'Solved' 
        ORDER BY p.created_at DESC
        LIMIT ? OFFSET ?
    """, (per_page, offset)).fetchall()

    return render_template(
        "solvewood.html",
        projects=rows,
        page=page,
        total_pages=total_pages,
        total_records=total_records
    )

# ---------------------------------------------------------
# Chat & Real-Time Messaging (N+1 query resolved)
# ---------------------------------------------------------

@app.get("/chat")
@login_required
def chat():
    uid = current_user()["id"]
    # High performance single-query conversation resolver
    conversations = db().execute("""
        SELECT DISTINCT p.id, p.title, p.status, p.category,
               (SELECT COUNT(*) FROM messages m WHERE m.problem_id = p.id) AS msg_count,
               (SELECT MAX(created_at) FROM messages m WHERE m.problem_id = p.id) AS last_msg_at
        FROM problems p
        LEFT JOIN solutions s ON s.problem_id = p.id
        WHERE p.user_id = ? OR s.user_id = ?
        ORDER BY COALESCE(last_msg_at, p.created_at) DESC
    """, (uid, uid)).fetchall()

    return render_template("chat.html", conversations=conversations)

@app.route("/chat/<int:problem_id>", methods=["GET", "POST"])
@login_required
@rate_limit("chat_message", limit=30, window_seconds=60)
def message(problem_id):
    uid = current_user()["id"]
    p = db().execute("SELECT * FROM problems WHERE id = ?", (problem_id,)).fetchone()
    if not p:
        abort(404)

    is_owner = (p["user_id"] == uid)
    is_solver = db().execute(
        "SELECT 1 FROM solutions WHERE problem_id = ? AND user_id = ?",
        (problem_id, uid)
    ).fetchone()

    if not is_owner and not is_solver:
        abort(403)

    if request.method == "POST":
        body = request.form.get("body", "").strip()
        recipient_id = request.form.get("recipient_id", "")

        if len(body) < 1 or len(body) > 3000:
            flash("Message must be between 1 and 3000 characters.", "error")
        else:
            if is_owner:
                try:
                    recipient_id = int(recipient_id)
                except ValueError:
                    recipient_id = 0
                valid_recipient = db().execute(
                    "SELECT 1 FROM solutions WHERE problem_id = ? AND user_id = ?",
                    (problem_id, recipient_id)
                ).fetchone()
                if not valid_recipient:
                    abort(403)
            else:
                recipient_id = p["user_id"]

            db().execute(
                "INSERT INTO messages(problem_id, sender_id, recipient_id, body, created_at) VALUES (?, ?, ?, ?, ?)",
                (problem_id, uid, recipient_id, body, now())
            )
            db().commit()
            return redirect(url_for("message", problem_id=problem_id, peer=recipient_id))

    peer = request.args.get("peer", type=int)
    if is_owner:
        participants = db().execute("""
            SELECT DISTINCT u.id, u.username 
            FROM users u 
            JOIN solutions s ON s.user_id = u.id
            WHERE s.problem_id = ? 
            ORDER BY u.username
        """, (problem_id,)).fetchall()
        participant_ids = [r["id"] for r in participants]
        if peer not in participant_ids:
            peer = participant_ids[0] if participant_ids else None
        recipient_id = peer
    else:
        participants = []
        recipient_id = p["user_id"]
        peer = p["user_id"]

    msgs = []
    if recipient_id:
        msgs = db().execute("""
            SELECT m.*, u.username AS sender_name 
            FROM messages m 
            JOIN users u ON u.id = m.sender_id
            WHERE m.problem_id = ? 
              AND ((m.sender_id = ? AND m.recipient_id = ?) OR (m.sender_id = ? AND m.recipient_id = ?))
            ORDER BY m.id ASC
        """, (problem_id, uid, recipient_id, recipient_id, uid)).fetchall()

    return render_template(
        "message.html",
        p=p,
        messages=msgs,
        participants=participants,
        recipient_id=recipient_id,
        peer=peer
    )

# ---------------------------------------------------------
# User Activity, Analytics & Profile Management
# ---------------------------------------------------------

@app.get("/chart")
@login_required
def chart():
    uid = current_user()["id"]
    stats = {
        "deployed": db().execute("SELECT COUNT(*) FROM problems WHERE user_id=?", (uid,)).fetchone()[0],
        "submitted": db().execute("SELECT COUNT(*) FROM solutions WHERE user_id=?", (uid,)).fetchone()[0],
        "accepted": db().execute("SELECT COUNT(*) FROM solutions WHERE user_id=? AND status='Accepted'", (uid,)).fetchone()[0],
        "open": db().execute("SELECT COUNT(*) FROM problems WHERE user_id=? AND status='Open'", (uid,)).fetchone()[0],
        "solved": db().execute("SELECT COUNT(*) FROM problems WHERE user_id=? AND status='Solved'", (uid,)).fetchone()[0]
    }
    recent_events = db().execute("""
        SELECT e.*, p.title AS problem_title 
        FROM events e 
        LEFT JOIN problems p ON p.id = e.problem_id 
        WHERE e.actor_id = ? 
        ORDER BY e.created_at DESC 
        LIMIT 10
    """, (uid,)).fetchall()

    return render_template("chart.html", stats=stats, recent_events=recent_events)

@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    uid = current_user()["id"]
    if request.method == "POST":
        bio = request.form.get("bio", "").strip()[:500]
        db().execute("UPDATE users SET bio = ? WHERE id = ?", (bio, uid))
        db().commit()
        flash("Your profile information has been updated.", "success")
        return redirect(url_for("profile"))

    user = db().execute("SELECT id, username, bio, created_at FROM users WHERE id = ?", (uid,)).fetchone()
    stats = {
        "deployed": db().execute("SELECT COUNT(*) FROM problems WHERE user_id = ?", (uid,)).fetchone()[0],
        "solutions": db().execute("SELECT COUNT(*) FROM solutions WHERE user_id = ?", (uid,)).fetchone()[0],
        "accepted": db().execute("SELECT COUNT(*) FROM solutions WHERE user_id = ? AND status='Accepted'", (uid,)).fetchone()[0]
    }
    return render_template("profile.html", user=user, stats=stats)

@app.get("/my-work")
@login_required
def my_work():
    uid = current_user()["id"]
    deployed = db().execute("""
        SELECT p.*, (SELECT COUNT(*) FROM solutions s WHERE s.problem_id = p.id) AS solution_count
        FROM problems p 
        WHERE p.user_id = ? 
        ORDER BY p.created_at DESC
    """, (uid,)).fetchall()

    submitted = db().execute("""
        SELECT s.*, p.title, p.problem_type, p.reward, p.status AS problem_status, p.id AS pid
        FROM solutions s 
        JOIN problems p ON p.id = s.problem_id 
        WHERE s.user_id = ? 
        ORDER BY s.created_at DESC
    """, (uid,)).fetchall()

    return render_template("my_work.html", deployed=deployed, submitted=submitted)

# ---------------------------------------------------------
# Centralized Error Handlers
# ---------------------------------------------------------

@app.errorhandler(400)
def bad_request(e):
    return render_template("error.html", code=400, message=str(getattr(e, "description", "Bad Request"))), 400

@app.errorhandler(403)
def forbidden(e):
    return render_template("error.html", code=403, message="Access forbidden. You do not have permission for this resource."), 403

@app.errorhandler(404)
def not_found(e):
    return render_template("error.html", code=404, message="The requested page or record could not be found."), 404

@app.errorhandler(409)
def conflict(e):
    return render_template("error.html", code=409, message=str(getattr(e, "description", "State Conflict"))), 409

@app.errorhandler(413)
def file_too_large(e):
    return render_template("error.html", code=413, message="The uploaded file exceeds the 10 MB limit."), 413

@app.errorhandler(429)
def too_many_requests(e):
    return render_template("error.html", code=429, message=str(getattr(e, "description", "Rate limit exceeded. Please try again later."))), 429

@app.errorhandler(500)
def server_error(e):
    return render_template("error.html", code=500, message="An internal server error occurred. Our engineers have been alerted."), 500

init_db()

if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=int(os.environ.get("PORT", 5000)),
        debug=os.environ.get("FLASK_DEBUG", "0") == "1"
    )
