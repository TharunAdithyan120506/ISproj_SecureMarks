"""Every test module gets its own throw-away database, keys and app instance, so
tests never touch the demo's data/ or secrets/ folders."""
from __future__ import annotations

import secrets
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from middleware.main import create_app  # noqa: E402
from middleware.settings import load_settings  # noqa: E402
from scripts.setup_demo import load_accounts, run_setup  # noqa: E402
from sdk.client import SecureClient, load_signing_key  # noqa: E402

DEVICES = {"teacher": "teacher-laptop", "student": "student-laptop", "ctrl": "ctrl-pc", "admin": "admin-pc",
           "attacker": "attacker"}


@pytest.fixture(scope="module")
def settings(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("securemarks")
    s = load_settings(env_file=tmp / "missing.env", jwt_secret=secrets.token_hex(32), db_path=tmp / "test.db",
                      secrets_dir=tmp / "secrets", client_keys_dir=tmp / "client_keys",
                      captures_dir=tmp / "captures", console_trace=False, demo_mode=True)
    run_setup(s, reset=True, quiet=True, tls=False)
    return s


@pytest.fixture(scope="module")
def app(settings):
    application = create_app(settings)
    yield application
    application.state.sm.db.dispose()


@pytest.fixture(scope="module")
def http(app):
    with TestClient(app) as client:
        yield client


@pytest.fixture(autouse=True)
def _fresh_buckets(request):
    if "app" in request.fixturenames:
        request.getfixturevalue("app").state.sm.limiter.reset()


@pytest.fixture(scope="module")
def accounts(settings):
    return load_accounts(settings)


@pytest.fixture
def client_for(http, accounts):
    """client_for("t104") -> logged-in SecureClient talking to the in-process app."""
    def make(username: str, device: str | None = None) -> SecureClient:
        role = accounts[username]["role"]
        c = SecureClient("http://testserver", None, device or DEVICES[role], http=http, save_last_request=False)
        res = c.login(username, accounts[username]["password"])
        assert res.ok, res.summary()
        return c
    return make


@pytest.fixture(scope="module")
def teacher_key(settings, accounts):
    return load_signing_key("t104", accounts["t104"]["password"], keys_dir=settings.client_keys_dir)
