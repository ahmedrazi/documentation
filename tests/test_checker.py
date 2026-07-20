#!/usr/bin/env python3
"""Tests for the NX-OS compliance checker.

Runs under pytest (`pytest -q tests`) or standalone (`python3 tests/test_checker.py`).
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import nxos_compliance_checker as nx  # noqa: E402


def _cfg(text: str) -> nx.DeviceConfig:
    return nx.DeviceConfig(hostname="test", raw=text, source="mem")


def _checker(check: dict) -> nx.ComplianceChecker:
    return nx.ComplianceChecker({"checks": [check]})


# --- strategy handlers ------------------------------------------------------

def test_presence_pass_and_fail():
    c = _checker({"id": "T1", "check_type": "presence", "severity": "HIGH",
                  "pattern": r"^feature ssh"})
    assert c.run(_cfg("feature ssh"))[0].status == "PASS"
    assert c.run(_cfg("feature telnet"))[0].status == "FAIL"


def test_absence_pass_and_fail():
    c = _checker({"id": "T2", "check_type": "absence", "severity": "CRITICAL",
                  "pattern": r"^feature telnet"})
    assert c.run(_cfg("feature ssh"))[0].status == "PASS"
    assert c.run(_cfg("feature telnet"))[0].status == "FAIL"


def test_value_threshold():
    c = _checker({"id": "T3", "check_type": "value", "severity": "HIGH",
                  "pattern": r"^ssh key rsa (\d+)", "operator": ">=", "threshold": 2048})
    assert c.run(_cfg("ssh key rsa 2048 force"))[0].status == "PASS"
    assert c.run(_cfg("ssh key rsa 1024 force"))[0].status == "FAIL"
    # Not configured at all -> FAIL, not crash.
    assert c.run(_cfg("hostname x"))[0].status == "FAIL"


def test_value_range():
    c = _checker({"id": "T4", "check_type": "value_range", "severity": "MEDIUM",
                  "pattern": r"^\s*exec-timeout (\d+)", "min": 1, "max": 15})
    assert c.run(_cfg("  exec-timeout 10"))[0].status == "PASS"
    assert c.run(_cfg("  exec-timeout 0"))[0].status == "FAIL"
    assert c.run(_cfg("  exec-timeout 99"))[0].status == "FAIL"


def test_vty_lines():
    c = _checker({"id": "T5", "check_type": "vty_lines", "severity": "HIGH",
                  "pattern": r"^transport input ssh"})
    good = "line vty\n  transport input ssh\n  exec-timeout 10 0"
    bad = "line vty\n  transport input telnet ssh"
    assert c.run(_cfg(good))[0].status == "PASS"
    assert c.run(_cfg(bad))[0].status == "FAIL"
    # No vty block at all -> FAIL.
    assert c.run(_cfg("hostname x"))[0].status == "FAIL"


def test_interface_absent_mode():
    c = _checker({"id": "T6", "check_type": "interface", "severity": "MEDIUM",
                  "mode": "absent", "interface_filter": r"^interface Ethernet",
                  "pattern": r"^ip redirects"})
    clean = "interface Ethernet1/1\n  no ip redirects\n  ip address 1.1.1.1/30"
    dirty = "interface Ethernet1/1\n  ip redirects"
    assert c.run(_cfg(clean))[0].status == "PASS"
    assert c.run(_cfg(dirty))[0].status == "FAIL"


def test_unknown_check_type_is_error_not_crash():
    c = _checker({"id": "T7", "check_type": "nope", "severity": "LOW"})
    assert c.run(_cfg("anything"))[0].status == "ERROR"


def test_bad_regex_is_error_not_crash():
    c = _checker({"id": "T8", "check_type": "presence", "severity": "LOW",
                  "pattern": r"("})  # invalid regex
    assert c.run(_cfg("anything"))[0].status == "ERROR"


# --- scoring / grading ------------------------------------------------------

def test_grade_thresholds():
    assert nx.grade_for(94.6) == "A"
    assert nx.grade_for(90.0) == "A"
    assert nx.grade_for(85) == "B"
    assert nx.grade_for(72) == "C"
    assert nx.grade_for(61) == "D"
    assert nx.grade_for(9.9) == "F"


def test_weighted_scoring():
    checks = [
        {"id": "C", "check_type": "presence", "severity": "CRITICAL", "pattern": "yes"},
        {"id": "L", "check_type": "presence", "severity": "LOW", "pattern": "no"},
    ]
    checker = nx.ComplianceChecker({"checks": checks})
    cfg = _cfg("yes")  # CRITICAL passes, LOW fails
    report = nx.DeviceReport("h", "s", checker.run(cfg), "t").score()
    # earned 10 (critical) of 12 total -> 83.3%
    assert report.percentage == 83.3
    assert report.passed == 1 and report.failed == 1
    assert report.severity_failures["LOW"] == 1


# --- ndjson output shape ----------------------------------------------------

def test_ndjson_one_summary_plus_n_checks():
    checks = [{"id": f"C{i}", "check_type": "presence", "severity": "LOW",
               "pattern": "x"} for i in range(3)]
    checker = nx.ComplianceChecker({"checks": checks})
    report = nx.DeviceReport("h", "s", checker.run(_cfg("x")), "t").score()
    out = nx.render_ndjson([report]).strip().split("\n")
    assert len(out) == 4  # 1 summary + 3 checks
    first = json.loads(out[0])
    assert first["event_type"] == "compliance_summary"
    assert json.loads(out[1])["event_type"] == "compliance_check"


def test_policy_file_loads_and_scans():
    """The shipped policy + sample configs produce differentiated grades."""
    root = os.path.join(os.path.dirname(__file__), "..")
    policy = nx.load_policy(os.path.join(root, "policy", "nxos_policy.yaml"))
    checker = nx.ComplianceChecker(policy)
    core = nx.DeviceConfig.from_file(os.path.join(root, "configs", "switch-core-01.cfg"))
    edge = nx.DeviceConfig.from_file(os.path.join(root, "configs", "switch-edge-02.cfg"))
    core_r = nx.DeviceReport(core.hostname, core.source, checker.run(core), "t").score()
    edge_r = nx.DeviceReport(edge.hostname, edge.source, checker.run(edge), "t").score()
    assert core_r.grade in ("A", "B")
    assert edge_r.grade == "F"
    assert core_r.percentage > edge_r.percentage
    # No check should ERROR against the real configs.
    assert core_r.errored == 0 and edge_r.errored == 0


def _run_standalone():
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    passed = 0
    for fn in fns:
        fn()
        passed += 1
        print(f"  ok  {fn.__name__}")
    print(f"\n{passed}/{len(fns)} tests passed")


if __name__ == "__main__":
    _run_standalone()
