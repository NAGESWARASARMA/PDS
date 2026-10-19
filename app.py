import os, re, sqlite3, secrets, uuid
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path
from flask import Flask, render_template, request, redirect, url_for, session, flash, abort, send_from_directory, g
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

BASE_DIR = Path(__file__).resolve().parent

# Use writable temporary storage on Vercel.
if os.environ.get("VERCEL") == "1":
    DATA_DIR = Path("/tmp/problembridge_ai")
else:
    DATA_DIR = BASE_DIR / "instance"

DATA_DIR.mkdir(parents=True, exist_ok=True)

UPLOAD_DIR = DATA_DIR / "private_uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

DB_PATH = Path(
    os.environ.get(
        "PROBLEMBRIDGE_DB",
        str(DATA_DIR / "problembridge.sqlite3")
    )
)
DB_PATH.parent.mkdir(parents=True, exist_ok=True)
ALLOWED_EXTENSIONS = {"pdf","txt","py","java","c","cpp","js","html","css","zip","docx","md","png","jpg","jpeg"}
MAX_CONTENT_LENGTH = 10 * 1024 * 1024

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY") or secrets.token_hex(32),
    MAX_CONTENT_LENGTH=MAX_CONTENT_LENGTH,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE","0") == "1",
)
CATEGORIES = ["Artificial Intelligence and Machine Learning","Agriculture","Business Studies","Transportation","Education","Healthcare","Web Development","Mobile Applications","Python and Programming","Data Science","Environment","Other"]

def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db

@app.teardown_appcontext
def close_db(exc):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()

def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.executescript("""
    PRAGMA foreign_keys=ON;
    CREATE TABLE IF NOT EXISTS users(
      id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL, bio TEXT DEFAULT '', created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS problems(
      id INTEGER PRIMARY KEY AUTOINCREMENT, public_id TEXT UNIQUE NOT NULL,
      user_id INTEGER NOT NULL REFERENCES users(id), title TEXT NOT NULL,
      statement TEXT NOT NULL, description TEXT NOT NULL, category TEXT NOT NULL,
      requirements TEXT DEFAULT '', expected_result TEXT DEFAULT '', skills TEXT DEFAULT '',
      instructions TEXT DEFAULT '', problem_type TEXT NOT NULL CHECK(problem_type IN ('Free','Paid')),
      reward REAL, deadline TEXT, duration TEXT DEFAULT '', deliverables TEXT DEFAULT '',
      acceptance_criteria TEXT DEFAULT '', attachment_name TEXT, attachment_key TEXT,
      status TEXT NOT NULL DEFAULT 'Open', views INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL, accepted_solution_id INTEGER
    );
    CREATE TABLE IF NOT EXISTS solutions(
      id INTEGER PRIMARY KEY AUTOINCREMENT, problem_id INTEGER NOT NULL REFERENCES problems(id),
      user_id INTEGER NOT NULL REFERENCES users(id), explanation TEXT NOT NULL,
      implementation TEXT DEFAULT '', advantages TEXT DEFAULT '', filename TEXT, file_key TEXT,
      status TEXT NOT NULL DEFAULT 'Pending', created_at TEXT NOT NULL,
      UNIQUE(problem_id,user_id)
    );
    CREATE TABLE IF NOT EXISTS messages(
      id INTEGER PRIMARY KEY AUTOINCREMENT, problem_id INTEGER NOT NULL REFERENCES problems(id),
      sender_id INTEGER NOT NULL REFERENCES users(id), recipient_id INTEGER NOT NULL REFERENCES users(id),
      body TEXT NOT NULL, created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS events(
      id INTEGER PRIMARY KEY AUTOINCREMENT, actor_id INTEGER REFERENCES users(id),
      problem_id INTEGER REFERENCES problems(id), action TEXT NOT NULL, details TEXT DEFAULT '',
      created_at TEXT NOT NULL
    );
    """)
    conn.commit()
    conn.close()

def current_user():
    uid = session.get("user_id")
    if not uid: return None
    return db().execute("SELECT id, username, bio FROM users WHERE id=?", (uid,)).fetchone()

@app.context_processor
def inject_user():
    return {"current_user": current_user(), "categories": CATEGORIES}

def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not current_user():
            flash("Please log in to continue.", "error")
            return redirect(url_for("auth", next=request.path))
        return fn(*args, **kwargs)
    return wrapper

def csrf_token():
    if "_csrf" not in session: session["_csrf"] = secrets.token_urlsafe(32)
    return session["_csrf"]

@app.before_request
def csrf_protect():
    if request.method == "POST":
        sent = request.form.get("_csrf", "")
        expected = session.get("_csrf", "")
        if not expected or not secrets.compare_digest(sent, expected):
            abort(400, "Invalid or expired form token. Refresh the page and try again.")

@app.context_processor
def inject_csrf():
    return {"csrf_token": csrf_token}

def save_upload(file):
    if not file or not file.filename: return None, None, None
    original = secure_filename(file.filename)
    if not original or "." not in original: raise ValueError("Invalid filename.")
    ext = original.rsplit(".",1)[1].lower()
    if ext not in ALLOWED_EXTENSIONS: raise ValueError("That file type is not allowed.")
    key = secrets.token_hex(24) + "." + ext
    file.save(UPLOAD_DIR / key)
    return original, key, ext

def log_event(actor, problem_id, action, details=""):
    db().execute("INSERT INTO events(actor_id,problem_id,action,details,created_at) VALUES(?,?,?,?,?)",
                 (actor, problem_id, action, details[:500], now()))
    db().commit()

@app.get("/")
def index():
    rows = db().execute("""SELECT p.*,u.username AS deployer_name FROM problems p JOIN users u ON u.id=p.user_id
      WHERE p.status='Open' ORDER BY p.created_at DESC LIMIT 6""").fetchall()
    return render_template("home.html", problems=rows)

@app.route("/auth", methods=["GET","POST"])
def auth():
    if request.method == "POST":
        action = request.form.get("action")
        username = request.form.get("username","").strip()
        password = request.form.get("password","")
        if not re.fullmatch(r"[A-Za-z0-9_.-]{3,40}", username):
            flash("Username must be 3–40 characters: letters, numbers, dot, underscore or hyphen.", "error")
        elif action == "register":
            if len(password) < 10:
                flash("Use a password with at least 10 characters.", "error")
            else:
                try:
                    db().execute("INSERT INTO users(username,password_hash,created_at) VALUES(?,?,?)",
                                 (username, generate_password_hash(password), now()))
                    db().commit()
                    flash("Account created. Please log in.", "success")
                    return redirect(url_for("auth"))
                except sqlite3.IntegrityError:
                    flash("That username is already in use.", "error")
        elif action == "login":
            user = db().execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
            if user and check_password_hash(user["password_hash"], password):
                session.clear()
                session["user_id"] = user["id"]
                session["_csrf"] = secrets.token_urlsafe(32)
                flash("Welcome back.", "success")
                return redirect(request.args.get("next") if request.args.get("next","").startswith("/") and not request.args.get("next","").startswith("//") else url_for("dashboard"))
            flash("Invalid username or password.", "error")
        else:
            flash("Invalid request.", "error")
    return render_template("auth.html")

@app.post("/logout")
@login_required
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("index"))

@app.get("/dashboard")
@login_required
def dashboard():
    q = request.args.get("q","").strip()[:100]
    kind = request.args.get("type","All")
    category = request.args.get("category","")
    sort = request.args.get("sort","newest")
    sql = """SELECT p.*,u.username AS deployer_name,
      (SELECT COUNT(*) FROM solutions s WHERE s.problem_id=p.id) AS solution_count
      FROM problems p JOIN users u ON u.id=p.user_id WHERE p.status='Open'"""
    params=[]
    if kind in ("Free","Paid"): sql += " AND p.problem_type=?"; params.append(kind)
    if category in CATEGORIES: sql += " AND p.category=?"; params.append(category)
    if q:
        sql += " AND (p.title LIKE ? OR p.statement LIKE ? OR p.description LIKE ? OR p.category LIKE ? OR p.skills LIKE ?)"
        params += [f"%{q}%"]*5
    order = {"newest":"p.created_at DESC","oldest":"p.created_at ASC","views":"p.views DESC","reward":"p.reward DESC","deadline":"p.deadline ASC"}.get(sort,"p.created_at DESC")
    if sort in ("reward","deadline") and kind != "Paid": order="p.created_at DESC"
    sql += " ORDER BY " + order
    rows=db().execute(sql,params).fetchall()
    return render_template("dashboard.html", problems=rows, q=q, kind=kind, category=category, sort=sort)

@app.route("/post", methods=["GET","POST"])
@login_required
def post():
    if request.method == "POST":
        title=request.form.get("title","").strip()
        statement=request.form.get("statement","").strip()
        description=request.form.get("description","").strip()
        category=request.form.get("category","Other")
        kind=request.form.get("problem_type","Free")
        reward_raw=request.form.get("reward","").strip()
        deadline=request.form.get("deadline","").strip()
        if not title or not statement or not description or category not in CATEGORIES or kind not in ("Free","Paid"):
            flash("Please complete all required fields.", "error")
        else:
            reward=None
            if kind=="Paid":
                try: reward=float(reward_raw)
                except ValueError: reward=0
                try:
                    deadline_dt=datetime.fromisoformat(deadline)
                    if deadline_dt.tzinfo is None: deadline_dt=deadline_dt.replace(tzinfo=timezone.utc)
                    if deadline_dt <= datetime.now(timezone.utc): raise ValueError()
                except Exception:
                    deadline_dt=None
                if reward <= 0 or deadline_dt is None:
                    flash("Paid problems need a positive reward and a future deadline.", "error")
                    return render_template("post.html")
                deadline=deadline_dt.isoformat(timespec="minutes")
            try:
                attachment_name, attachment_key, _ = save_upload(request.files.get("attachment"))
            except ValueError as e:
                flash(str(e),"error"); return render_template("post.html")
            cur=db().execute("""INSERT INTO problems(public_id,user_id,title,statement,description,category,requirements,
              expected_result,skills,instructions,problem_type,reward,deadline,duration,deliverables,acceptance_criteria,
              attachment_name,attachment_key,created_at)
              VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
              (uuid.uuid4().hex[:12].upper(),current_user()["id"],title,statement,description,category,
               request.form.get("requirements","").strip(),request.form.get("expected_result","").strip(),
               request.form.get("skills","").strip(),request.form.get("instructions","").strip(),kind,reward,
               deadline if kind=="Paid" else None,request.form.get("duration","").strip(),
               request.form.get("deliverables","").strip(),request.form.get("acceptance_criteria","").strip(),
               attachment_name,attachment_key,now()))
            db().commit()
            log_event(current_user()["id"],cur.lastrowid,"problem_created",kind)
            flash("Problem published.", "success")
            return redirect(url_for("detail",problem_id=cur.lastrowid))
    return render_template("post.html")

@app.get("/problem/<int:problem_id>")
@login_required
def detail(problem_id):
    p=db().execute("""SELECT p.*,u.username AS deployer_name FROM problems p JOIN users u ON u.id=p.user_id WHERE p.id=?""",(problem_id,)).fetchone()
    if not p: abort(404)
    db().execute("UPDATE problems SET views=views+1 WHERE id=?",(problem_id,)); db().commit()
    own = p["user_id"] == current_user()["id"]
    already = db().execute("SELECT id FROM solutions WHERE problem_id=? AND user_id=?",(problem_id,current_user()["id"])).fetchone()
    solutions=[]
    if own:
        solutions=db().execute("""SELECT s.*,u.username FROM solutions s JOIN users u ON u.id=s.user_id WHERE s.problem_id=? ORDER BY s.created_at DESC""",(problem_id,)).fetchall()
    return render_template("problem.html",p=p,own=own,already=bool(already),solutions=solutions)

@app.get("/problem/<int:problem_id>/attachment")
@login_required
def problem_attachment(problem_id):
    p=db().execute("SELECT * FROM problems WHERE id=?",(problem_id,)).fetchone()
    if not p or not p["attachment_key"]: abort(404)
    return send_from_directory(UPLOAD_DIR,p["attachment_key"],as_attachment=True,download_name=p["attachment_name"])

@app.route("/problem/<int:problem_id>/solve", methods=["GET","POST"])
@login_required
def solve(problem_id):
    p=db().execute("SELECT * FROM problems WHERE id=?",(problem_id,)).fetchone()
    if not p: abort(404)
    if p["user_id"] == current_user()["id"]: abort(403)
    if p["status"] != "Open": flash("This problem is no longer accepting submissions.","error"); return redirect(url_for("detail",problem_id=problem_id))
    if p["problem_type"]=="Paid" and p["deadline"]:
        try:
            d=datetime.fromisoformat(p["deadline"])
            if d.tzinfo is None: d=d.replace(tzinfo=timezone.utc)
            if d <= datetime.now(timezone.utc): abort(403)
        except ValueError: abort(403)
    if request.method=="POST":
        explanation=request.form.get("explanation","").strip()
        if len(explanation)<20:
            flash("Please provide a solution explanation of at least 20 characters.","error")
        elif db().execute("SELECT 1 FROM solutions WHERE problem_id=? AND user_id=?",(problem_id,current_user()["id"])).fetchone():
            flash("You have already submitted a solution for this problem.","error")
        else:
            try: filename,file_key,_=save_upload(request.files.get("solution_file"))
            except ValueError as e: flash(str(e),"error"); return render_template("solve.html",p=p)
            db().execute("""INSERT INTO solutions(problem_id,user_id,explanation,implementation,advantages,filename,file_key,created_at)
                         VALUES(?,?,?,?,?,?,?,?)""",(problem_id,current_user()["id"],explanation,
                         request.form.get("implementation","").strip(),request.form.get("advantages","").strip(),
                         filename,file_key,now()))
            db().commit(); log_event(current_user()["id"],problem_id,"solution_submitted")
            flash("Solution submitted for deployer review.","success")
            return redirect(url_for("detail",problem_id=problem_id))
    return render_template("solve.html",p=p)

@app.post("/solution/<int:solution_id>/status")
@login_required
def solution_status(solution_id):
    s=db().execute("""SELECT s.*,p.user_id AS deployer_id,p.status AS problem_status,p.problem_type,p.id AS pid
      FROM solutions s JOIN problems p ON p.id=s.problem_id WHERE s.id=?""",(solution_id,)).fetchone()
    if not s: abort(404)
    if s["deployer_id"] != current_user()["id"]: abort(403)
    action=request.form.get("status")
    if action not in ("Accepted","Rejected","Changes requested"): abort(400)
    if s["problem_status"]!="Open": abort(409)
    if action=="Accepted":
        db().execute("UPDATE solutions SET status='Rejected' WHERE problem_id=? AND id<>? AND status='Pending'",(s["pid"],solution_id))
        db().execute("UPDATE solutions SET status='Accepted' WHERE id=?",(solution_id,))
        db().execute("UPDATE problems SET status='Solved',accepted_solution_id=? WHERE id=?",(solution_id,s["pid"]))
    else:
        db().execute("UPDATE solutions SET status=? WHERE id=?",(action,solution_id))
    db().commit(); log_event(current_user()["id"],s["pid"],"solution_"+action.lower())
    flash("Review status updated. Any reward/payment arrangement remains outside PDS.","success")
    return redirect(url_for("detail",problem_id=s["pid"]))

@app.get("/chart")
@login_required
def chart():
    uid=current_user()["id"]
    deployed=db().execute("SELECT COUNT(*) FROM problems WHERE user_id=?",(uid,)).fetchone()[0]
    submitted=db().execute("SELECT COUNT(*) FROM solutions WHERE user_id=?",(uid,)).fetchone()[0]
    accepted=db().execute("SELECT COUNT(*) FROM solutions WHERE user_id=? AND status='Accepted'",(uid,)).fetchone()[0]
    open_count=db().execute("SELECT COUNT(*) FROM problems WHERE user_id=? AND status='Open'",(uid,)).fetchone()[0]
    solved_count=db().execute("SELECT COUNT(*) FROM problems WHERE user_id=? AND status='Solved'",(uid,)).fetchone()[0]
    return render_template("chart.html",stats={"deployed":deployed,"submitted":submitted,"accepted":accepted,"open":open_count,"solved":solved_count})


@app.get("/solved")
def solved():
    rows=db().execute("""SELECT p.*,du.username AS deployer_name,su.username AS solver_name,
      s.explanation AS solution_description,s.filename,s.id AS solution_id
      FROM problems p JOIN users du ON du.id=p.user_id
      JOIN solutions s ON s.id=p.accepted_solution_id JOIN users su ON su.id=s.user_id
      WHERE p.status='Solved' ORDER BY p.created_at DESC""").fetchall()
    return render_template("solvewood.html",projects=rows)

@app.get("/solution/<int:solution_id>/file")
@login_required
def solution_file(solution_id):
    s=db().execute("""SELECT s.*,p.user_id AS deployer_id,p.id AS pid FROM solutions s JOIN problems p ON p.id=s.problem_id WHERE s.id=?""",(solution_id,)).fetchone()
    if not s or not s["file_key"]: abort(404)
    if current_user()["id"] not in (s["user_id"],s["deployer_id"]) and s["status"]!="Accepted": abort(403)
    return send_from_directory(UPLOAD_DIR,s["file_key"],as_attachment=True,download_name=s["filename"])

@app.get("/chat")
@login_required
def chat():
    uid=current_user()["id"]
    rows=db().execute("""SELECT DISTINCT p.id,p.title FROM problems p JOIN messages m ON m.problem_id=p.id
      WHERE m.sender_id=? OR m.recipient_id=? UNION SELECT DISTINCT p.id,p.title FROM problems p
      JOIN solutions s ON s.problem_id=p.id WHERE p.user_id=? OR s.user_id=? ORDER BY title""",(uid,uid,uid,uid)).fetchall()
    # Only show problem conversations where user is deployer or submitted solver.
    allowed=[]
    for row in rows:
        p=db().execute("SELECT user_id FROM problems WHERE id=?",(row["id"],)).fetchone()
        submitted=db().execute("SELECT 1 FROM solutions WHERE problem_id=? AND user_id=?",(row["id"],uid)).fetchone()
        if p and (p["user_id"]==uid or submitted): allowed.append(row)
    return render_template("chat.html",conversations=allowed)

@app.route("/chat/<int:problem_id>", methods=["GET","POST"])
@login_required
def message(problem_id):
    uid=current_user()["id"]
    p=db().execute("SELECT * FROM problems WHERE id=?",(problem_id,)).fetchone()
    if not p: abort(404)
    submitted=db().execute("SELECT 1 FROM solutions WHERE problem_id=? AND user_id=?",(problem_id,uid)).fetchone()
    if p["user_id"]!=uid and not submitted: abort(403)
    peer_id=p["user_id"] if uid!=p["user_id"] else None
    if request.method=="POST":
        body=request.form.get("body","").strip()
        recipient_id=request.form.get("recipient_id","")
        if len(body)<1 or len(body)>3000:
            flash("Messages must contain 1–3000 characters.","error")
        else:
            if p["user_id"]==uid:
                try: recipient_id=int(recipient_id)
                except ValueError: recipient_id=0
                if not db().execute("SELECT 1 FROM solutions WHERE problem_id=? AND user_id=?",(problem_id,recipient_id)).fetchone():
                    abort(403)
            else: recipient_id=p["user_id"]
            db().execute("INSERT INTO messages(problem_id,sender_id,recipient_id,body,created_at) VALUES(?,?,?,?,?)",(problem_id,uid,recipient_id,body,now()))
            db().commit()
            return redirect(url_for("message",problem_id=problem_id,peer=recipient_id))
    peer=request.args.get("peer",type=int)
    if p["user_id"]==uid:
        participants=db().execute("""SELECT DISTINCT u.id,u.username FROM users u JOIN solutions s ON s.user_id=u.id
          WHERE s.problem_id=? ORDER BY u.username""",(problem_id,)).fetchall()
        if peer not in [r["id"] for r in participants]: peer=participants[0]["id"] if participants else None
        recipient_id=peer
    else:
        participants=[]
        recipient_id=p["user_id"]
        peer=p["user_id"]
    msgs=[]
    if recipient_id:
        msgs=db().execute("""SELECT m.*,u.username AS sender_name FROM messages m JOIN users u ON u.id=m.sender_id
          WHERE m.problem_id=? AND ((m.sender_id=? AND m.recipient_id=?) OR (m.sender_id=? AND m.recipient_id=?))
          ORDER BY m.id ASC""",(problem_id,uid,recipient_id,recipient_id,uid)).fetchall()
    return render_template("message.html",p=p,messages=msgs,participants=participants,recipient_id=recipient_id,peer=peer)

@app.route("/profile", methods=["GET","POST"])
@login_required
def profile():
    uid=current_user()["id"]
    if request.method=="POST":
        bio=request.form.get("bio","").strip()[:500]
        db().execute("UPDATE users SET bio=? WHERE id=?",(bio,uid)); db().commit()
        flash("Profile updated.","success"); return redirect(url_for("profile"))
    user=db().execute("SELECT id,username,bio,created_at FROM users WHERE id=?",(uid,)).fetchone()
    stats={
      "deployed":db().execute("SELECT COUNT(*) FROM problems WHERE user_id=?",(uid,)).fetchone()[0],
      "solutions":db().execute("SELECT COUNT(*) FROM solutions WHERE user_id=?",(uid,)).fetchone()[0],
      "accepted":db().execute("SELECT COUNT(*) FROM solutions WHERE user_id=? AND status='Accepted'",(uid,)).fetchone()[0]
    }
    return render_template("profile.html",user=user,stats=stats)

@app.get("/my-work")
@login_required
def my_work():
    uid=current_user()["id"]
    deployed=db().execute("SELECT * FROM problems WHERE user_id=? ORDER BY created_at DESC",(uid,)).fetchall()
    submitted=db().execute("""SELECT s.*,p.title,p.problem_type,p.reward,p.status AS problem_status,p.id AS pid
      FROM solutions s JOIN problems p ON p.id=s.problem_id WHERE s.user_id=? ORDER BY s.created_at DESC""",(uid,)).fetchall()
    return render_template("my_work.html",deployed=deployed,submitted=submitted)

@app.errorhandler(413)
def too_large(e): return "Upload too large. Maximum size is 10 MB.",413

@app.errorhandler(403)
def forbidden(e): return render_template("error.html",code=403,message="You do not have permission to access this resource."),403

@app.errorhandler(404)
def not_found(e): return render_template("error.html",code=404,message="The requested page was not found."),404

init_db()
if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG","0")=="1")
