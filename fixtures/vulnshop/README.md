# vulnshop — ShipCheck demo fixture

> ⚠️ **Intentionally vulnerable. Do not deploy.** This is a target app for
> ShipCheck to attack, fix and re-verify — the PRD's primary demo fixture.

A ~60-line Flask app with one deliberate bug per ShipCheck MVP vulnerability
class. Each has a deterministic marker that proves exploitation.

| Route | Class | Example payload | Marker |
|-------|-------|-----------------|--------|
| `POST /login` | SQL injection | `username=admin' OR '1'='1' -- ` | `admin@vulnshop.local` |
| `GET /export?ip=` | Command injection | `8.8.8.8; id` | `uid=` |
| `GET /download?file=` | Path traversal | `../../../../etc/passwd` | `root:` |
| `GET /search?q=` | Reflected XSS | `<script>alert(1)</script>` | reflected unescaped |

## Run it

```bash
pip install -r fixtures/vulnshop/requirements.txt
PORT=5000 python fixtures/vulnshop/app.py
```

Then, e.g.:

```bash
curl -s "http://127.0.0.1:5000/search?q=<script>alert(1)</script>"
```

## Regression gate

`test_app.py` holds the app's legitimate behaviour. ShipCheck runs it inside
the sandbox as the FR-6 regression gate: a proposed fix must keep these tests
green while closing the exploit (the "No PASS, No PR" rule).

```bash
pytest fixtures/vulnshop/test_app.py
```
