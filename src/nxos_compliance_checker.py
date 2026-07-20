#!/usr/bin/env python3
"""
NX-OS Compliance Checker
========================

Automated security compliance auditing for Cisco NX-OS device configurations.

Reads NX-OS ``.cfg`` files, evaluates them against a YAML-defined security
policy (116-style checks across 10 categories), scores the result with an
A-F letter grade, and emits the findings in one of four formats:

    console  human-readable report (default)
    json     single structured document (summary + results)
    csv      one row per check
    ndjson   newline-delimited JSON, one event per line -- ready for a
             Splunk Universal Forwarder (1 summary event + N check events)

Design (mirrors the architecture deck):

    * Strategy pattern   -- ``check_type`` routes to a handler method, so new
                            check types are added without touching existing code.
    * Template method    -- security checks live in YAML, not in Python, so
                            security teams can edit policy without coding.
    * Factory pattern    -- the output format selects the appropriate exporter.

The tool has a single third-party dependency: PyYAML.

Example
-------
    python3 nxos_compliance_checker.py \
        --config-dir ./configs \
        --policy ./policy/nxos_policy.yaml \
        --format ndjson \
        --output compliance.ndjson
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import os
import re
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

try:
    import yaml
except ImportError:  # pragma: no cover - friendly message instead of a traceback
    sys.stderr.write(
        "error: PyYAML is required. Install it with:  pip install pyyaml\n"
    )
    raise SystemExit(2)


# --------------------------------------------------------------------------- #
# Severity model
# --------------------------------------------------------------------------- #

# Weighted importance of a failed check. Higher weight => a failure costs more
# of the compliance score. These weights turn the raw pass/fail counts into a
# risk-weighted percentage.
SEVERITY_WEIGHTS: Dict[str, int] = {
    "CRITICAL": 10,
    "HIGH": 7,
    "MEDIUM": 4,
    "LOW": 2,
}

VALID_SEVERITIES = tuple(SEVERITY_WEIGHTS.keys())

# Letter-grade thresholds on the weighted percentage (inclusive lower bound).
GRADE_THRESHOLDS: List[Tuple[float, str]] = [
    (90.0, "A"),
    (80.0, "B"),
    (70.0, "C"),
    (60.0, "D"),
    (0.0, "F"),
]

STATUS_PASS = "PASS"
STATUS_FAIL = "FAIL"
STATUS_ERROR = "ERROR"  # malformed check definition / evaluation error


def grade_for(percentage: float) -> str:
    """Return the A-F letter grade for a weighted percentage."""
    for threshold, letter in GRADE_THRESHOLDS:
        if percentage >= threshold:
            return letter
    return "F"


# --------------------------------------------------------------------------- #
# Config model
# --------------------------------------------------------------------------- #


@dataclass
class ConfigBlock:
    """A top-level config line plus its indented child lines.

    NX-OS configs are line oriented; sub-sections (``interface ...``,
    ``line vty ...``) are expressed with indentation. This captures that
    parent/child relationship so ``interface`` and ``vty_lines`` checks can
    reason about a block rather than the whole file.
    """

    header: str
    children: List[str] = field(default_factory=list)

    @property
    def text(self) -> str:
        return "\n".join([self.header, *self.children])


class DeviceConfig:
    """Parsed representation of a single NX-OS configuration file."""

    def __init__(self, hostname: str, raw: str, source: str):
        self.hostname = hostname
        self.raw = raw
        self.source = source
        self.lines: List[str] = raw.splitlines()
        self.blocks: List[ConfigBlock] = self._parse_blocks(self.lines)

    @staticmethod
    def _parse_blocks(lines: List[str]) -> List[ConfigBlock]:
        blocks: List[ConfigBlock] = []
        current: Optional[ConfigBlock] = None
        for line in lines:
            if not line.strip() or line.lstrip().startswith("!"):
                continue
            indented = line[0] in " \t"
            if indented and current is not None:
                current.children.append(line.strip())
            else:
                current = ConfigBlock(header=line.strip())
                blocks.append(current)
        return blocks

    @classmethod
    def from_file(cls, path: str) -> "DeviceConfig":
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            raw = fh.read()
        hostname = cls._hostname_from(raw) or os.path.splitext(os.path.basename(path))[0]
        return cls(hostname=hostname, raw=raw, source=path)

    @staticmethod
    def _hostname_from(raw: str) -> Optional[str]:
        match = re.search(r"^hostname\s+(\S+)", raw, re.MULTILINE)
        return match.group(1) if match else None

    def blocks_matching(self, header_pattern: str) -> List[ConfigBlock]:
        rx = re.compile(header_pattern)
        return [b for b in self.blocks if rx.search(b.header)]


# --------------------------------------------------------------------------- #
# Check result model
# --------------------------------------------------------------------------- #


@dataclass
class CheckResult:
    check_id: str
    category: str
    severity: str
    description: str
    status: str
    message: str
    remediation: str = ""
    weight: int = 0

    def as_dict(self) -> Dict[str, Any]:
        return asdict(self)


# --------------------------------------------------------------------------- #
# The compliance engine (Strategy pattern)
# --------------------------------------------------------------------------- #


class ComplianceChecker:
    """Evaluates a DeviceConfig against a set of policy checks.

    ``check_type`` selects the handler via ``self.check_methods`` -- the
    strategy table. Adding a new check type is a matter of writing a handler
    and registering it here; no existing handler changes.
    """

    def __init__(self, policy: Dict[str, Any]):
        self.policy = policy
        self.checks: List[Dict[str, Any]] = policy.get("checks", [])
        # Strategy table: check_type -> handler(config, check) -> (status, message)
        self.check_methods = {
            "presence": self.check_presence,
            "absence": self.check_absence,
            "value": self.check_value,
            "value_range": self.check_value_range,
            "vty_lines": self.check_vty_lines,
            "interface": self.check_interface,
        }

    # -- dispatch ---------------------------------------------------------- #

    def run(self, config: DeviceConfig) -> List[CheckResult]:
        results: List[CheckResult] = []
        for check in self.checks:
            results.append(self._execute_check(config, check))
        return results

    def _execute_check(self, config: DeviceConfig, check: Dict[str, Any]) -> CheckResult:
        check_id = str(check.get("id", "UNKNOWN"))
        category = str(check.get("category", "Uncategorized"))
        severity = str(check.get("severity", "MEDIUM")).upper()
        description = str(check.get("description", ""))
        remediation = str(check.get("remediation", ""))
        weight = SEVERITY_WEIGHTS.get(severity, SEVERITY_WEIGHTS["MEDIUM"])

        check_type = check.get("check_type")
        handler = self.check_methods.get(check_type)

        if handler is None:
            status, message = STATUS_ERROR, f"unknown check_type: {check_type!r}"
        else:
            try:
                status, message = handler(config, check)
            except re.error as exc:
                status, message = STATUS_ERROR, f"invalid regex: {exc}"
            except Exception as exc:  # keep one bad check from aborting the scan
                status, message = STATUS_ERROR, f"evaluation error: {exc}"

        return CheckResult(
            check_id=check_id,
            category=category,
            severity=severity,
            description=description,
            status=status,
            message=message,
            remediation=remediation if status != STATUS_PASS else "",
            weight=weight,
        )

    # -- strategy handlers ------------------------------------------------- #

    def check_presence(self, config: DeviceConfig, check: Dict[str, Any]) -> Tuple[str, str]:
        """PASS when the pattern is found somewhere in the config."""
        pattern = check["pattern"]
        if re.search(pattern, config.raw, re.MULTILINE):
            return STATUS_PASS, f"required pattern present: {pattern}"
        return STATUS_FAIL, f"required pattern missing: {pattern}"

    def check_absence(self, config: DeviceConfig, check: Dict[str, Any]) -> Tuple[str, str]:
        """PASS when the pattern is NOT found (e.g. an insecure feature)."""
        pattern = check["pattern"]
        match = re.search(pattern, config.raw, re.MULTILINE)
        if match:
            return STATUS_FAIL, f"forbidden pattern present: {match.group(0).strip()}"
        return STATUS_PASS, f"forbidden pattern absent: {pattern}"

    def check_value(self, config: DeviceConfig, check: Dict[str, Any]) -> Tuple[str, str]:
        """Extract a numeric capture group and compare it to a threshold."""
        pattern = check["pattern"]
        operator = check.get("operator", ">=")
        threshold = float(check["threshold"])
        match = re.search(pattern, config.raw, re.MULTILINE)
        if not match:
            return STATUS_FAIL, f"value not configured (pattern: {pattern})"
        value = float(match.group(1))
        if _compare(value, operator, threshold):
            return STATUS_PASS, f"value {value:g} {operator} {threshold:g}"
        return STATUS_FAIL, f"value {value:g} violates {operator} {threshold:g}"

    def check_value_range(self, config: DeviceConfig, check: Dict[str, Any]) -> Tuple[str, str]:
        """Extract a numeric capture group and confirm it is within [min, max]."""
        pattern = check["pattern"]
        low = float(check["min"])
        high = float(check["max"])
        match = re.search(pattern, config.raw, re.MULTILINE)
        if not match:
            return STATUS_FAIL, f"value not configured (pattern: {pattern})"
        value = float(match.group(1))
        if low <= value <= high:
            return STATUS_PASS, f"value {value:g} within [{low:g}, {high:g}]"
        return STATUS_FAIL, f"value {value:g} outside [{low:g}, {high:g}]"

    def check_vty_lines(self, config: DeviceConfig, check: Dict[str, Any]) -> Tuple[str, str]:
        """Verify every ``line vty`` block contains a required sub-pattern."""
        pattern = check["pattern"]
        blocks = config.blocks_matching(r"^line vty")
        if not blocks:
            return STATUS_FAIL, "no 'line vty' block configured"
        rx = re.compile(pattern)
        offenders = [b.header for b in blocks if not any(rx.search(c) for c in b.children)]
        if offenders:
            return STATUS_FAIL, f"missing '{pattern}' on: {', '.join(offenders)}"
        return STATUS_PASS, f"all vty lines satisfy '{pattern}'"

    def check_interface(self, config: DeviceConfig, check: Dict[str, Any]) -> Tuple[str, str]:
        """Per-interface setting check.

        ``mode: present`` (default) -> the sub-pattern must appear in every
        matched interface block.  ``mode: absent`` -> it must appear in none.
        ``interface_filter`` narrows which interface headers are examined.
        """
        pattern = check["pattern"]
        mode = check.get("mode", "present")
        iface_filter = check.get("interface_filter", r"^interface ")
        blocks = config.blocks_matching(iface_filter)
        if not blocks:
            return STATUS_FAIL, f"no interfaces match {iface_filter!r}"
        rx = re.compile(pattern)
        if mode == "absent":
            offenders = [b.header for b in blocks if any(rx.search(c) for c in b.children)]
            if offenders:
                return STATUS_FAIL, f"forbidden '{pattern}' on: {', '.join(offenders)}"
            return STATUS_PASS, f"no interface has '{pattern}'"
        offenders = [b.header for b in blocks if not any(rx.search(c) for c in b.children)]
        if offenders:
            return STATUS_FAIL, f"missing '{pattern}' on: {', '.join(offenders)}"
        return STATUS_PASS, f"all interfaces satisfy '{pattern}'"


def _compare(value: float, operator: str, threshold: float) -> bool:
    ops = {
        ">=": value >= threshold,
        "<=": value <= threshold,
        ">": value > threshold,
        "<": value < threshold,
        "==": value == threshold,
        "!=": value != threshold,
    }
    if operator not in ops:
        raise ValueError(f"unsupported operator: {operator!r}")
    return ops[operator]


# --------------------------------------------------------------------------- #
# Scoring
# --------------------------------------------------------------------------- #


@dataclass
class DeviceReport:
    hostname: str
    source: str
    results: List[CheckResult]
    scanned_at: str

    # populated by score()
    total_checks: int = 0
    passed: int = 0
    failed: int = 0
    errored: int = 0
    earned_weight: int = 0
    total_weight: int = 0
    percentage: float = 0.0
    grade: str = "F"
    severity_failures: Dict[str, int] = field(default_factory=dict)
    category_summary: Dict[str, Dict[str, int]] = field(default_factory=dict)

    def score(self) -> "DeviceReport":
        self.total_checks = len(self.results)
        self.severity_failures = {s: 0 for s in VALID_SEVERITIES}
        self.category_summary = {}
        for r in self.results:
            cat = self.category_summary.setdefault(
                r.category, {"pass": 0, "fail": 0, "error": 0}
            )
            if r.status == STATUS_PASS:
                self.passed += 1
                self.earned_weight += r.weight
                cat["pass"] += 1
            elif r.status == STATUS_FAIL:
                self.failed += 1
                self.severity_failures[r.severity] = (
                    self.severity_failures.get(r.severity, 0) + 1
                )
                cat["fail"] += 1
            else:
                self.errored += 1
                cat["error"] += 1
            # Errored checks still count toward the denominator so a broken
            # check definition cannot silently inflate the score.
            self.total_weight += r.weight
        self.percentage = (
            round(100.0 * self.earned_weight / self.total_weight, 1)
            if self.total_weight
            else 0.0
        )
        self.grade = grade_for(self.percentage)
        return self


# --------------------------------------------------------------------------- #
# Exporters (Factory pattern)
# --------------------------------------------------------------------------- #

RESET = "\033[0m"
COLORS = {
    "PASS": "\033[32m",
    "FAIL": "\033[31m",
    "ERROR": "\033[33m",
    "A": "\033[32m",
    "B": "\033[32m",
    "C": "\033[33m",
    "D": "\033[33m",
    "F": "\033[31m",
    "dim": "\033[2m",
    "bold": "\033[1m",
}


def _c(text: str, key: str, use_color: bool) -> str:
    if not use_color:
        return text
    return f"{COLORS.get(key, '')}{text}{RESET}"


def render_console(reports: List[DeviceReport], use_color: bool = True) -> str:
    out = io.StringIO()
    out.write(_c("NX-OS Compliance Report", "bold", use_color) + "\n")
    out.write("=" * 60 + "\n")
    for rep in reports:
        out.write("\n")
        out.write(
            _c(f"Device: {rep.hostname}", "bold", use_color)
            + _c(f"  ({rep.source})", "dim", use_color)
            + "\n"
        )
        grade_line = (
            f"Grade: {_c(rep.grade, rep.grade, use_color)}  "
            f"Score: {rep.percentage:g}%  "
            f"Pass: {rep.passed}/{rep.total_checks}  "
            f"Fail: {rep.failed}"
        )
        if rep.errored:
            grade_line += f"  Error: {rep.errored}"
        out.write(grade_line + "\n")
        sev = rep.severity_failures
        out.write(
            "Failures by severity: "
            + f"CRITICAL={sev.get('CRITICAL', 0)} "
            + f"HIGH={sev.get('HIGH', 0)} "
            + f"MEDIUM={sev.get('MEDIUM', 0)} "
            + f"LOW={sev.get('LOW', 0)}\n"
        )
        # Only show failures/errors in the console detail -- keeps it scannable.
        problems = [r for r in rep.results if r.status != STATUS_PASS]
        if problems:
            out.write("-" * 60 + "\n")
            for r in problems:
                out.write(
                    f"  {_c(r.status, r.status, use_color)}  "
                    f"[{r.severity}] {r.check_id} ({r.category})\n"
                    f"      {r.description}\n"
                    f"      -> {r.message}\n"
                )
                if r.remediation:
                    out.write(f"      fix: {r.remediation}\n")
        else:
            out.write(_c("  All checks passed.\n", "PASS", use_color))
    out.write("\n" + "=" * 60 + "\n")
    fleet = _fleet_summary(reports)
    out.write(
        f"Fleet: {fleet['devices']} device(s), "
        f"avg score {fleet['avg_percentage']:g}%, "
        f"{fleet['total_failures']} total failures\n"
    )
    return out.getvalue()


def _fleet_summary(reports: List[DeviceReport]) -> Dict[str, Any]:
    devices = len(reports)
    avg = round(sum(r.percentage for r in reports) / devices, 1) if devices else 0.0
    total_failures = sum(r.failed for r in reports)
    grade_dist: Dict[str, int] = {}
    for r in reports:
        grade_dist[r.grade] = grade_dist.get(r.grade, 0) + 1
    return {
        "devices": devices,
        "avg_percentage": avg,
        "total_failures": total_failures,
        "grade_distribution": grade_dist,
    }


def _summary_record(rep: DeviceReport) -> Dict[str, Any]:
    return {
        "event_type": "compliance_summary",
        "hostname": rep.hostname,
        "source": rep.source,
        "scanned_at": rep.scanned_at,
        "grade": rep.grade,
        "percentage": rep.percentage,
        "total_checks": rep.total_checks,
        "passed": rep.passed,
        "failed": rep.failed,
        "errored": rep.errored,
        "severity_failures": rep.severity_failures,
    }


def _check_record(rep: DeviceReport, r: CheckResult) -> Dict[str, Any]:
    rec = {
        "event_type": "compliance_check",
        "hostname": rep.hostname,
        "scanned_at": rep.scanned_at,
        "check_id": r.check_id,
        "category": r.category,
        "severity": r.severity,
        "status": r.status,
        "description": r.description,
        "message": r.message,
    }
    if r.remediation:
        rec["remediation"] = r.remediation
    return rec


def render_json(reports: List[DeviceReport]) -> str:
    doc = {
        "generated_at": reports[0].scanned_at if reports else _now(),
        "summary": _fleet_summary(reports),
        "devices": [
            {
                "summary": _summary_record(rep),
                "results": [r.as_dict() for r in rep.results],
            }
            for rep in reports
        ],
    }
    return json.dumps(doc, indent=2)


def render_csv(reports: List[DeviceReport]) -> str:
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(
        ["hostname", "grade", "percentage", "check_id", "category",
         "severity", "status", "description", "message", "remediation"]
    )
    for rep in reports:
        for r in rep.results:
            writer.writerow(
                [rep.hostname, rep.grade, rep.percentage, r.check_id, r.category,
                 r.severity, r.status, r.description, r.message, r.remediation]
            )
    return out.getvalue()


def render_ndjson(reports: List[DeviceReport]) -> str:
    """One JSON object per line: 1 summary event + N check events per device.

    This is the format the Splunk Universal Forwarder ingests -- each line
    becomes an independent, searchable Splunk event (SHOULD_LINEMERGE=false).
    """
    lines: List[str] = []
    for rep in reports:
        lines.append(json.dumps(_summary_record(rep)))
        for r in rep.results:
            lines.append(json.dumps(_check_record(rep, r)))
    return "\n".join(lines) + ("\n" if lines else "")


EXPORTERS = {
    "console": render_console,
    "json": render_json,
    "csv": render_csv,
    "ndjson": render_ndjson,
}


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_policy(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as fh:
        policy = yaml.safe_load(fh)
    if not isinstance(policy, dict) or "checks" not in policy:
        raise ValueError("policy file must be a mapping containing a 'checks' list")
    return policy


def gather_configs(config: Optional[str], config_dir: Optional[str]) -> List[str]:
    paths: List[str] = []
    if config:
        paths.append(config)
    if config_dir:
        for name in sorted(os.listdir(config_dir)):
            if name.endswith(".cfg") or name.endswith(".conf") or name.endswith(".txt"):
                paths.append(os.path.join(config_dir, name))
    return paths


def scan(paths: Iterable[str], checker: ComplianceChecker) -> List[DeviceReport]:
    reports: List[DeviceReport] = []
    scanned_at = _now()
    for path in paths:
        device = DeviceConfig.from_file(path)
        results = checker.run(device)
        report = DeviceReport(
            hostname=device.hostname,
            source=device.source,
            results=results,
            scanned_at=scanned_at,
        ).score()
        reports.append(report)
    return reports


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nxos_compliance_checker.py",
        description="Automated NX-OS security compliance auditing.",
    )
    src = parser.add_argument_group("input")
    src.add_argument("--config", help="path to a single NX-OS .cfg file")
    src.add_argument("--config-dir", help="directory of NX-OS .cfg files to scan")
    parser.add_argument(
        "--policy",
        default=os.environ.get("NXOS_POLICY", "policy/nxos_policy.yaml"),
        help="path to the YAML policy file (default: policy/nxos_policy.yaml)",
    )
    parser.add_argument(
        "--format",
        choices=sorted(EXPORTERS.keys()),
        default="console",
        help="output format (default: console)",
    )
    parser.add_argument(
        "--output",
        help="write output to this file instead of stdout",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="disable ANSI color in console output",
    )
    parser.add_argument(
        "--fail-under",
        type=float,
        default=None,
        metavar="PCT",
        help="exit non-zero if any device scores under PCT (for CI/cron gating)",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    if not args.config and not args.config_dir:
        sys.stderr.write("error: provide --config and/or --config-dir\n")
        return 2

    try:
        policy = load_policy(args.policy)
    except (OSError, ValueError, yaml.YAMLError) as exc:
        sys.stderr.write(f"error: could not load policy {args.policy!r}: {exc}\n")
        return 2

    paths = gather_configs(args.config, args.config_dir)
    if not paths:
        sys.stderr.write("error: no config files found to scan\n")
        return 2

    checker = ComplianceChecker(policy)
    try:
        reports = scan(paths, checker)
    except OSError as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 2

    exporter = EXPORTERS[args.format]
    if args.format == "console":
        use_color = not args.no_color and (
            args.output is None and sys.stdout.isatty()
        )
        rendered = exporter(reports, use_color=use_color)
    else:
        rendered = exporter(reports)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(rendered)
        sys.stderr.write(
            f"wrote {args.format} for {len(reports)} device(s) to {args.output}\n"
        )
    else:
        sys.stdout.write(rendered)
        if not rendered.endswith("\n"):
            sys.stdout.write("\n")

    if args.fail_under is not None:
        worst = min((r.percentage for r in reports), default=0.0)
        if worst < args.fail_under:
            sys.stderr.write(
                f"compliance gate: lowest score {worst:g}% < {args.fail_under:g}%\n"
            )
            return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
