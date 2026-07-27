"""
ModSecLabs target web application.

A deliberately simple Flask app used as the "origin" server that sits
behind the OWASP ModSecurity CRS (nginx) container. It is intentionally
naive so that, WITHOUT a WAF, attacks like reflected XSS, SQL-injection
patterns, path traversal and Log4Shell-style JNDI lookups reach the
application. The whole point of the labs is to watch ModSecurity stop
these requests before they ever get here.

Do NOT deploy this app on the public internet. It is a lab target.
"""
from flask import Flask, request, render_template_string, jsonify
import os

app = Flask(__name__)

# A fake "user database" so SQL-injection demos have something to talk about.
FAKE_USERS = {
    "alice": "alice@example.com",
    "bob": "bob@example.com",
}

PAGE = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>ModSecLabs Target App</title>
  <style>
    /* HackTheBox-inspired dark theme */
    body { font-family: 'JetBrains Mono','Fira Code',ui-monospace,Menlo,Consolas,monospace;
           max-width: 780px; margin: 2rem auto; padding: 0 1rem;
           color:#a4b1cd; background:#141d2b; }
    h1 { color:#9fef00; letter-spacing:.5px; text-shadow:0 0 12px rgba(159,239,0,.35); }
    h3 { color:#c5d1eb; }
    p { color:#a4b1cd; }
    .card { border:1px solid #2f3f5f; border-radius:10px; padding:1rem 1.25rem;
            margin:1rem 0; background:#1a2332; box-shadow:0 0 0 1px rgba(159,239,0,.04); }
    input { padding:.5rem; width:60%; border:1px solid #2f3f5f; border-radius:6px;
            background:#111927; color:#e5ecf7; }
    input:focus { outline:none; border-color:#9fef00; box-shadow:0 0 8px rgba(159,239,0,.3); }
    button { padding:.5rem 1rem; border:0; border-radius:6px; background:#9fef00;
             color:#111927; font-weight:700; cursor:pointer; }
    button:hover { background:#b6ff33; }
    code { background:#0d1522; color:#9fef00; padding:.1rem .35rem; border-radius:4px;
           border:1px solid #22304a; }
    a { color:#9fef00; }
    .banner { background:#111927; color:#9fef00; padding:.45rem .9rem; border-radius:6px;
              display:inline-block; border:1px solid #9fef00;
              box-shadow:0 0 14px rgba(159,239,0,.2); }
    .muted { color:#5c6b8a; }
  </style>
</head>
<body>
  <span class="banner">🛡️ ModSecLabs &mdash; behind OWASP CRS</span>
  <h1>Target Web Application</h1>
  <p>This tiny app is the origin server the labs attack. If you can read this
     through <code>http://localhost:8080</code>, your request passed the WAF.</p>

  <div class="card">
    <h3>1. Reflected search (XSS playground)</h3>
    <form action="/search" method="get">
      <input name="q" placeholder="Search term..." value="">
      <button type="submit">Search</button>
    </form>
  </div>

  <div class="card">
    <h3>2. User lookup (SQL-injection playground)</h3>
    <form action="/login" method="get">
      <input name="user" placeholder="username e.g. alice">
      <button type="submit">Look up</button>
    </form>
  </div>

  <div class="card">
    <h3>3. File viewer (path-traversal playground)</h3>
    <form action="/file" method="get">
      <input name="name" placeholder="report.txt">
      <button type="submit">Open</button>
    </form>
  </div>

  <p class="muted" style="font-size:.85rem">Endpoints: <code>/search?q=</code> ·
     <code>/login?user=</code> · <code>/file?name=</code> ·
     <code>/api/log</code> (POST) · <code>/healthz</code></p>
</body>
</html>
"""


@app.route("/")
def index():
    return PAGE


@app.route("/search")
def search():
    # Reflects user input straight back into HTML -> classic reflected XSS
    # sink. ModSecurity CRS rule family 941 is what should stop the payload
    # before it ever reaches this line.
    q = request.args.get("q", "")
    return render_template_string(
        "<h2>Results for: " + q + "</h2><p>No results found.</p>"
    )


@app.route("/login")
def login():
    # Simulates a lookup that, in a real app, would be a raw SQL query like
    #   SELECT email FROM users WHERE name = '<user>'
    # We do NOT actually run SQL, but we echo the "query" so you can see the
    # injection payload. CRS rule family 942 targets these patterns.
    user = request.args.get("user", "")
    simulated_sql = "SELECT email FROM users WHERE name = '%s'" % user
    email = FAKE_USERS.get(user)
    return jsonify(
        {
            "simulated_query": simulated_sql,
            "result": email if email else "no such user",
        }
    )


@app.route("/file")
def file_view():
    # Naive file reader -> path traversal sink. CRS rule family 930 targets
    # ../ style payloads.
    name = request.args.get("name", "report.txt")
    base = os.path.join(os.path.dirname(__file__), "data")
    target = os.path.join(base, name)  # intentionally NOT sanitised
    try:
        with open(target, "r", encoding="utf-8", errors="replace") as fh:
            return "<pre>" + fh.read() + "</pre>"
    except Exception as exc:  # noqa: BLE001
        return "<pre>Could not open file: %s</pre>" % exc, 404


@app.route("/api/log", methods=["POST", "GET"])
def api_log():
    # Stand-in for a service that logs a request header/field. Used in the
    # Log4Shell (CVE-2021-44228) virtual-patching lab: the JNDI payload is
    # what a vulnerable logger would try to resolve. Here we just echo it.
    ua = request.headers.get("X-Api-Version", "")
    payload = request.values.get("data", "")
    return jsonify({"logged_version": ua, "logged_data": payload, "status": "ok"})


@app.route("/healthz")
def healthz():
    return "ok\n"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
