"""vulnshop - intentionally vulnerable Flask demo app for ShipCheck.

DO NOT DEPLOY. This app exists only as a target fixture: each route contains
one deliberate vulnerability from the ShipCheck MVP's four classes, so the
scan pipeline has something real to exploit, fix and re-verify.

Routes and their planted bug (+ the deterministic marker that proves it):
  POST /login     SQL injection       -> 'admin@vulnshop.local' in response
  GET  /export    command injection   -> 'uid=' in response
  GET  /download  path traversal       -> 'root:' in response (/etc/passwd)
  GET  /search    reflected XSS         -> '<script>alert(1)</script>' reflected
"""

import os
import sqlite3
import subprocess

from flask import Flask, request

app = Flask(__name__)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def _db() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE users (id INTEGER, username TEXT, email TEXT, password TEXT)")
    conn.executemany(
        "INSERT INTO users VALUES (?, ?, ?, ?)",
        [
            (1, "admin", "admin@vulnshop.local", "s3cr3t"),
            (2, "alice", "alice@vulnshop.local", "hunter2"),
        ],
    )
    return conn


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    conn = _db()
    # VULN (SQLi): user input concatenated straight into the query.
    query = (
        "SELECT username, email FROM users "
        "WHERE username = '%s' AND password = '%s'" % (username, password)
    )
    rows = conn.execute(query).fetchall()
    if rows:
        return "Welcome: " + ", ".join(f"{u} <{e}>" for u, e in rows)
    return "Invalid credentials", 401


@app.route("/export")
def export():
    ip = request.args.get("ip", "127.0.0.1")
    # VULN (command injection): unsanitized value in a shell string.
    result = subprocess.run(
        "ping -c 1 " + ip, shell=True, capture_output=True, text=True, timeout=5
    )
    return "<pre>" + result.stdout + result.stderr + "</pre>"


@app.route("/download")
def download():
    filename = request.args.get("file", "readme.txt")
    # VULN (path traversal): no normalization or prefix check.
    path = os.path.join(BASE_DIR, "files", filename)
    with open(path) as handle:
        return handle.read()


@app.route("/search")
def search():
    query = request.args.get("q", "")
    # VULN (reflected XSS): user input echoed into HTML unescaped.
    return "<h1>Results for " + query + "</h1>"


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="127.0.0.1", port=port)
