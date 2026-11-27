"""The Claude Code plugin: manifests, the stdlib-only hook runner and lite CLI."""

import json
import os
import subprocess
import sys
from pathlib import Path

import yaml

import agentguard
from agentguard import policy as P

ROOT = Path(__file__).resolve().parents[1]
HOOK = ROOT / "hooks" / "agentguard_hook.py"
LITE = ROOT / "scripts" / "agentguard_lite.py"


def _bare(script, *args, stdin="", env_home):
    # -S skips site-packages, so PyYAML and click are unavailable, as on a fresh machine.
    env = {**os.environ, "AGENTGUARD_HOME": str(env_home), "CLAUDE_PLUGIN_ROOT": str(ROOT)}
    return subprocess.run([sys.executable, "-S", str(script), *args], input=stdin, capture_output=True,
                          text=True, env=env, timeout=60)


def test_manifest_versions_match_package():
    plugin = json.loads((ROOT / ".claude-plugin" / "plugin.json").read_text())
    market = json.loads((ROOT / ".claude-plugin" / "marketplace.json").read_text())
    assert plugin["name"] == "agent-guard"
    assert plugin["version"] == agentguard.__version__
    assert market["plugins"][0]["version"] == agentguard.__version__
    assert market["plugins"][0]["source"] == "./"


def test_hooks_json_points_at_runner():
    hooks = json.loads((ROOT / "hooks" / "hooks.json").read_text())["hooks"]
    assert set(hooks) == {"UserPromptSubmit", "PreToolUse", "PostToolUse"}
    for entries in hooks.values():
        assert "${CLAUDE_PLUGIN_ROOT}/hooks/agentguard_hook.py" in entries[0]["hooks"][0]["command"]


def test_simple_yaml_parser_matches_pyyaml_on_default_policy():
    text = P.default_policy_text()
    assert P._parse_simple_yaml(text) == yaml.safe_load(text)


def test_simple_yaml_parser_rejects_mappings_in_lists():
    import pytest
    with pytest.raises(ValueError):
        P._parse_simple_yaml("custom_rules:\n  - id: x\n    pattern: y\n")


def test_hook_blocks_without_third_party_packages(tmp_path):
    event = {"hook_event_name": "PreToolUse", "session_id": "p1", "cwd": str(tmp_path),
             "tool_name": "Bash", "tool_input": {"command": "rm -rf ~"}}
    out = _bare(HOOK, stdin=json.dumps(event), env_home=tmp_path / "ag")
    assert out.returncode == 0, out.stderr
    assert json.loads(out.stdout)["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_hook_reads_simple_policy_without_pyyaml(tmp_path):
    (tmp_path / ".agentguard.yaml").write_text("mode: monitor\n")
    event = {"hook_event_name": "PreToolUse", "session_id": "p2", "cwd": str(tmp_path),
             "tool_name": "Bash", "tool_input": {"command": "rm -rf ~"}}
    out = _bare(HOOK, stdin=json.dumps(event), env_home=tmp_path / "ag")
    assert out.returncode == 0 and out.stdout == "", out.stderr   # monitor mode: logged, not blocked


def test_hook_fails_open_on_bad_input(tmp_path):
    out = _bare(HOOK, stdin="not json", env_home=tmp_path / "ag")
    assert out.returncode == 0 and out.stdout == ""
    assert "allowing call" in out.stderr


def test_lite_cli_verify_and_report(tmp_path):
    home = tmp_path / "ag"
    event = {"hook_event_name": "PreToolUse", "session_id": "p3", "cwd": str(tmp_path),
             "tool_name": "Read", "tool_input": {"file_path": "/home/u/.aws/credentials"}}
    _bare(HOOK, stdin=json.dumps(event), env_home=home)
    verify = _bare(LITE, "verify", env_home=home)
    assert verify.returncode == 0 and verify.stdout.startswith("OK: 1 records")
    report = _bare(LITE, "report", env_home=home)
    assert "credential_access" in report.stdout
    check = _bare(LITE, "check", "Bash", "q chat --trust-all-tools", env_home=home)
    assert check.stdout.startswith("BLOCK")
