import pytest


@pytest.fixture(autouse=True)
def isolated_home(tmp_path, monkeypatch):
    """Keep audit logs and state out of the real home folder."""
    monkeypatch.setenv("AGENTGUARD_HOME", str(tmp_path / "ag"))
    monkeypatch.delenv("AGENTGUARD_POLICY", raising=False)
    return tmp_path / "ag"
