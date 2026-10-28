"""Functional tests for vulnshop.

These assert the app's legitimate behaviour still works. ShipCheck runs this
suite inside the sandbox as the FR-6 regression gate: a proposed fix must keep
these green (the exploit must close without breaking the feature).
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from app import app  # noqa: E402


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


def test_login_with_valid_credentials(client):
    resp = client.post("/login", data={"username": "admin", "password": "s3cr3t"})
    assert resp.status_code == 200
    assert b"admin@vulnshop.local" in resp.data


def test_login_with_wrong_password_is_rejected(client):
    resp = client.post("/login", data={"username": "admin", "password": "nope"})
    assert resp.status_code == 401


def test_search_returns_results_header(client):
    resp = client.get("/search?q=shoes")
    assert resp.status_code == 200
    assert b"Results for shoes" in resp.data


def test_download_serves_safe_file(client):
    resp = client.get("/download?file=readme.txt")
    assert resp.status_code == 200
    assert b"normal, safe download" in resp.data
