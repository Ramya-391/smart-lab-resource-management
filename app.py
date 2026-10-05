import os
import sqlite3
from datetime import datetime
from functools import wraps

from flask import (Flask, g, redirect, render_template, request,
                   session, url_for, flash)
from jinja2 import DictLoader
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-me-in-production")
DB_PATH = os.environ.get("DB_PATH", "lab.db")

STATUSES = ["Available", "In Use", "Under Maintenance"]

# ---------------------------------------------------------------- database
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_):
    db = g.pop("db", None)
    if db:
        db.close()


def init_db():
    db = sqlite3.connect(DB_PATH)
    db.executescript("""
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'student');
    CREATE TABLE IF NOT EXISTS resources(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        category TEXT NOT NULL,
        quantity INTEGER NOT NULL DEFAULT 1,
        location TEXT,
        status TEXT NOT NULL DEFAULT 'Available');
    CREATE TABLE IF NOT EXISTS allocations(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        resource_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        allocated_at TEXT NOT NULL,
        returned_at TEXT);
    """)
    db.commit()
    db.close()


# ----------------------------------------------------------------- helpers
def login_required(f):
    @wraps(f)
    def wrapper(*a, **kw):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return f(*a, **kw)
    return wrapper


def admin_required(f):
    @wraps(f)
    def wrapper(*a, **kw):
        if session.get("role") != "admin":
            flash("Admin access only.", "error")
            return redirect(url_for("dashboard"))
        return f(*a, **kw)
    return wrapper


def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M")


# ------------------------------------------------------------------ routes
@app.route("/")
def index():
    return redirect(url_for("dashboard" if "user_id" in session else "login"))


@app.route("/health")
def health():
    return "OK", 200  # used by the load balancer health check


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form["name"].strip()
        email = request.form["email"].strip().lower()
        pw = request.form["password"]
        role = request.form.get("role", "student")
        if role not in ("student", "faculty", "admin"):
            role = "student"
        if not name or not email or len(pw) < 6:
            flash("Fill all fields (password min 6 characters).", "error")
        else:
            try:
                get_db().execute(
                    "INSERT INTO users(name,email,password,role) VALUES(?,?,?,?)",
                    (name, email, generate_password_hash(pw), role))
                get_db().commit()
                flash("Registered! Please login.", "ok")
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                flash("Email already registered.", "error")
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"].strip().lower()
        user = get_db().execute(
            "SELECT * FROM users WHERE email=?", (email,)).fetchone()
        if user and check_password_hash(user["password"], request.form["password"]):
            session.update(user_id=user["id"], name=user["name"], role=user["role"])
            return redirect(url_for("dashboard"))
        flash("Invalid email or password.", "error")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    q = request.args.get("q", "").strip()
    status = request.args.get("status", "")
    sql = "SELECT * FROM resources WHERE 1=1"
    args = []
    if q:
        sql += " AND (name LIKE ? OR category LIKE ? OR location LIKE ?)"
        args += [f"%{q}%"] * 3
    if status in STATUSES:
        sql += " AND status=?"
        args.append(status)
    resources = get_db().execute(sql + " ORDER BY name", args).fetchall()
    stats = {s: get_db().execute(
        "SELECT COUNT(*) FROM resources WHERE status=?", (s,)).fetchone()[0]
        for s in STATUSES}
    return render_template("dashboard.html", resources=resources, q=q,
                           status=status, statuses=STATUSES, stats=stats)


@app.route("/resource/add", methods=["GET", "POST"])
@login_required
@admin_required
def add_resource():
    if request.method == "POST":
        f = request.form
        get_db().execute(
            "INSERT INTO resources(name,category,quantity,location,status) "
            "VALUES(?,?,?,?,?)",
            (f["name"].strip(), f["category"].strip(),
             int(f.get("quantity") or 1), f["location"].strip(),
             f.get("status", "Available")))
        get_db().commit()
        flash("Resource added.", "ok")
        return redirect(url_for("dashboard"))
    return render_template("add_resource.html", statuses=STATUSES)


@app.route("/resource/<int:rid>/status", methods=["POST"])
@login_required
@admin_required
def set_status(rid):
    status = request.form["status"]
    if status in STATUSES:
        get_db().execute("UPDATE resources SET status=? WHERE id=?", (status, rid))
        get_db().commit()
        flash("Status updated.", "ok")
    return redirect(url_for("dashboard"))


@app.route("/resource/<int:rid>/request", methods=["POST"])
@login_required
def request_resource(rid):
    db = get_db()
    r = db.execute("SELECT * FROM resources WHERE id=?", (rid,)).fetchone()
    if r and r["status"] == "Available":
        db.execute("INSERT INTO allocations(resource_id,user_id,allocated_at) "
                   "VALUES(?,?,?)", (rid, session["user_id"], now()))
        db.execute("UPDATE resources SET status='In Use' WHERE id=?", (rid,))
        db.commit()
        flash(f"{r['name']} allocated to you.", "ok")
    else:
        flash("Resource is not available.", "error")
    return redirect(url_for("dashboard"))


@app.route("/resource/<int:rid>/return", methods=["POST"])
@login_required
def return_resource(rid):
    db = get_db()
    alloc = db.execute(
        "SELECT * FROM allocations WHERE resource_id=? AND returned_at IS NULL",
        (rid,)).fetchone()
    if alloc and (alloc["user_id"] == session["user_id"]
                  or session.get("role") == "admin"):
        db.execute("UPDATE allocations SET returned_at=? WHERE id=?",
                   (now(), alloc["id"]))
        db.execute("UPDATE resources SET status='Available' WHERE id=?", (rid,))
        db.commit()
        flash("Resource returned.", "ok")
    else:
        flash("You cannot return this resource.", "error")
    return redirect(url_for("dashboard"))


@app.route("/history")
@login_required
def history():
    sql = """SELECT a.*, r.name AS resource, u.name AS user
             FROM allocations a
             JOIN resources r ON r.id=a.resource_id
             JOIN users u ON u.id=a.user_id"""
    args = ()
    if session.get("role") != "admin":
        sql += " WHERE a.user_id=?"
        args = (session["user_id"],)
    rows = get_db().execute(sql + " ORDER BY a.id DESC", args).fetchall()
    return render_template("history.html", rows=rows)


# --------------------------------------------------------------- templates
BASE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Smart Lab Resource Management</title>
<style>
*{box-sizing:border-box}body{margin:0;font-family:Segoe UI,Arial,sans-serif;background:#f3f6fb;color:#1f2937}
nav{background:#1e3a8a;color:#fff;padding:12px 24px;display:flex;gap:18px;align-items:center;flex-wrap:wrap}
nav a{color:#fff;text-decoration:none}nav .brand{font-weight:700;font-size:18px;margin-right:auto}
main{max-width:1000px;margin:24px auto;padding:0 16px}
.card{background:#fff;border-radius:10px;padding:20px;box-shadow:0 1px 4px rgba(0,0,0,.08);margin-bottom:18px}
input,select{padding:9px;border:1px solid #cbd5e1;border-radius:6px;width:100%;margin:4px 0 12px}
.row{display:flex;gap:10px;flex-wrap:wrap}.row>*{flex:1;min-width:140px}
button,.btn{background:#2563eb;color:#fff;border:0;padding:9px 16px;border-radius:6px;cursor:pointer;text-decoration:none;font-size:14px}
button.red{background:#dc2626}button.grey{background:#64748b}
table{width:100%;border-collapse:collapse}th,td{padding:10px;border-bottom:1px solid #e5e7eb;text-align:left;font-size:14px}
th{background:#eef2ff}.tag{padding:3px 10px;border-radius:12px;font-size:12px;color:#fff}
.Available{background:#16a34a}.In\\ Use{background:#f59e0b}.Under\\ Maintenance{background:#dc2626}
.flash{padding:10px 14px;border-radius:6px;margin-bottom:12px}.ok{background:#dcfce7}.error{background:#fee2e2}
.stats{display:flex;gap:14px;flex-wrap:wrap}.stat{flex:1;min-width:120px;text-align:center}
.stat b{font-size:28px;display:block}form.inline{display:inline}
</style></head><body>
<nav><span class="brand">Smart Lab Resource Management</span>
{% if session.user_id %}
<a href="{{ url_for('dashboard') }}">Resources</a>
{% if session.role == 'admin' %}<a href="{{ url_for('add_resource') }}">Add Resource</a>{% endif %}
<a href="{{ url_for('history') }}">History</a>
<span>{{ session.name }} ({{ session.role }})</span>
<a href="{{ url_for('logout') }}">Logout</a>
{% endif %}</nav>
<main>
{% with msgs = get_flashed_messages(with_categories=true) %}
{% for cat, m in msgs %}<div class="flash {{ cat }}">{{ m }}</div>{% endfor %}{% endwith %}
{% block body %}{% endblock %}
</main></body></html>"""

LOGIN = """{% extends 'base.html' %}{% block body %}
<div class="card" style="max-width:400px;margin:40px auto"><h2>Login</h2>
<form method="post"><label>Email</label><input name="email" type="email" required>
<label>Password</label><input name="password" type="password" required>
<button>Login</button> <a href="{{ url_for('register') }}">New user? Register</a></form></div>
{% endblock %}"""

REGISTER = """{% extends 'base.html' %}{% block body %}
<div class="card" style="max-width:400px;margin:40px auto"><h2>Register</h2>
<form method="post"><label>Name</label><input name="name" required>
<label>Email</label><input name="email" type="email" required>
<label>Password (min 6)</label><input name="password" type="password" required>
<label>Role</label><select name="role"><option>student</option><option>faculty</option><option>admin</option></select>
<button>Register</button> <a href="{{ url_for('login') }}">Back to login</a></form></div>
{% endblock %}"""

DASHBOARD = """{% extends 'base.html' %}{% block body %}
<div class="card stats">{% for s in statuses %}
<div class="stat"><b>{{ stats[s] }}</b>{{ s }}</div>{% endfor %}</div>
<div class="card"><form class="row" method="get">
<input name="q" placeholder="Search name, category, location" value="{{ q }}">
<select name="status"><option value="">All status</option>
{% for s in statuses %}<option {{ 'selected' if s == status }}>{{ s }}</option>{% endfor %}</select>
<button>Search</button></form></div>
<div class="card" style="overflow-x:auto"><table>
<tr><th>Name</th><th>Category</th><th>Qty</th><th>Location</th><th>Status</th><th>Action</th></tr>
{% for r in resources %}<tr>
<td>{{ r.name }}</td><td>{{ r.category }}</td><td>{{ r.quantity }}</td><td>{{ r.location }}</td>
<td><span class="tag {{ r.status }}">{{ r.status }}</span></td><td>
{% if r.status == 'Available' %}
<form class="inline" method="post" action="{{ url_for('request_resource', rid=r.id) }}"><button>Request</button></form>
{% elif r.status == 'In Use' %}
<form class="inline" method="post" action="{{ url_for('return_resource', rid=r.id) }}"><button class="grey">Return</button></form>
{% endif %}
{% if session.role == 'admin' %}
<form class="inline" method="post" action="{{ url_for('set_status', rid=r.id) }}">
<select name="status" style="width:auto;margin:0" onchange="this.form.submit()">
{% for s in statuses %}<option {{ 'selected' if s == r.status }}>{{ s }}</option>{% endfor %}</select></form>
{% endif %}</td></tr>
{% else %}<tr><td colspan="6">No resources found.</td></tr>{% endfor %}
</table></div>{% endblock %}"""

ADD = """{% extends 'base.html' %}{% block body %}
<div class="card" style="max-width:500px"><h2>Add Resource</h2>
<form method="post"><label>Resource name</label><input name="name" required>
<label>Category</label><input name="category" placeholder="Computer / Instrument / Tool" required>
<div class="row"><div><label>Quantity</label><input name="quantity" type="number" min="1" value="1"></div>
<div><label>Status</label><select name="status">{% for s in statuses %}<option>{{ s }}</option>{% endfor %}</select></div></div>
<label>Location</label><input name="location" placeholder="Lab 1, Shelf A">
<button>Save</button></form></div>{% endblock %}"""

HISTORY = """{% extends 'base.html' %}{% block body %}
<div class="card" style="overflow-x:auto"><h2>Usage History</h2><table>
<tr><th>Resource</th><th>User</th><th>Allocated</th><th>Returned</th></tr>
{% for r in rows %}<tr><td>{{ r.resource }}</td><td>{{ r.user }}</td>
<td>{{ r.allocated_at }}</td><td>{{ r.returned_at or 'In use' }}</td></tr>
{% else %}<tr><td colspan="4">No history yet.</td></tr>{% endfor %}</table></div>{% endblock %}"""

app.jinja_loader = DictLoader({
    "base.html": BASE, "login.html": LOGIN, "register.html": REGISTER,
    "dashboard.html": DASHBOARD, "add_resource.html": ADD, "history.html": HISTORY,
})

init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)
