"""WAFinity demo target: a deliberately VULNERABLE web app for testing the gateway.

*** For local training only. It contains real SQL-injection and XSS flaws on purpose. ***
It only listens on 127.0.0.1 and uses fake data. Never deploy it or expose it to a network.

Run:  python demo_backend/demo_vulnerable_app.py        (serves http://127.0.0.1:5001)
Then browse it THROUGH the gateway:  http://127.0.0.1:8080
"""
import sqlite3

from flask import Flask, jsonify, redirect, request

app = Flask(__name__)

_db = sqlite3.connect(":memory:", check_same_thread=False)
_db.executescript("""
CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, email TEXT, secret TEXT);
INSERT INTO users VALUES (1,'alice','alice@example.com','alice-secret-token'),
                         (2,'bob','bob@example.com','bob-secret-token'),
                         (3,'carol','carol@example.com','carol-secret-token');
""")

PAGE = """<!DOCTYPE html><html><head><meta charset="utf-8"><title>Demo Shop (vulnerable)</title>
<style>body{{font-family:Arial,sans-serif;max-width:720px;margin:30px auto;padding:0 16px}}
.warn{{background:#fff3cd;border:1px solid #e0c36a;padding:8px 12px;border-radius:6px}}
input{{padding:6px}} pre{{background:#f4f4f4;padding:10px;overflow:auto}}</style></head><body>
<p class="warn">Deliberately vulnerable training app. Local use only.</p>{body}</body></html>"""


@app.route("/")
def index():
    return PAGE.format(body="""
<h1>Demo Shop</h1>
<h3>Search (reflected XSS)</h3>
<form action="/search"><input name="q" placeholder="search products"> <button>Search</button></form>
<h3>User lookup (SQL injection)</h3>
<form action="/users"><input name="name" placeholder="alice"> <button>Look up</button></form>
<h3>Other</h3><p><a href="/old">/old (redirect)</a> | POST JSON to /api/echo</p>""")


@app.route("/search")
def search():
    q = request.args.get("q", "")
    return PAGE.format(body=f"<h1>Results for: {q}</h1><p>No products found.</p><a href='/'>Back</a>")  # VULNERABLE: unescaped


@app.route("/users")
def users():
    name = request.args.get("name", "")
    query = f"SELECT id, name, email FROM users WHERE name = '{name}'"   # VULNERABLE: string-built SQL
    try:
        rows = _db.execute(query).fetchall()
        result = "<br>".join(f"#{r[0]} {r[1]} &lt;{r[2]}&gt;" for r in rows) or "No match."
    except sqlite3.Error as exc:
        result = f"SQL error: {exc}"
    return PAGE.format(body=f"<h1>User lookup</h1><pre>{query}</pre><p>{result}</p><a href='/'>Back</a>")


@app.route("/api/echo", methods=["POST"])
def echo():
    return jsonify({"you_sent": request.get_json(silent=True), "x_forwarded_for": request.headers.get("X-Forwarded-For")})


@app.route("/old")
def old():
    return redirect("http://127.0.0.1:5001/", code=302)      # absolute URL: lets the gateway rewrite Location


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5001, debug=False)
