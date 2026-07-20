# NX-OS Compliance Checker — Single-Box Deployment

Automated security compliance auditing for Cisco **NX-OS** device
configurations, packaged to run entirely on **one Linux box** (built and
tested for Ubuntu / Killercoda).

The original design in `NXOS_Compliance_Presentation.pptx` was a distributed
system: NX-OS devices → Splunk Universal Forwarder → Splunk indexer + dashboards.
This repo turns that architecture into a self-contained deployment you can run,
demo, and extend on a single node — with an optional path to a real Splunk
instance when you want it.

```
NX-OS .cfg files ──▶ compliance checker (Python + YAML policy) ──▶ NDJSON
                                                                      │
                          ┌───────────────────────────────────────────┤
                          ▼                                           ▼
             Splunk-style HTML dashboard                    real Splunk (optional)
             (zero dependencies, :8000)                     props/inputs + dashboard XML
```

---

## Quick start (native — no Docker, best for Killercoda)

```bash
./setup.sh            # install PyYAML in a venv, run a scan, write NDJSON
# then serve the dashboard:
cd dashboard && python3 -m http.server 8000   # open http://localhost:8000
```

Or with `make`:

```bash
make scan        # console report + refresh dashboard data
make dashboard   # scan, then serve the dashboard on :8000
make test        # run the test suite
```

One-liner that also serves the dashboard in the foreground:

```bash
./setup.sh --serve
```

## Quick start (Docker Compose)

```bash
docker compose up --build checker      # scan configs -> output/compliance.ndjson
docker compose up -d dashboard         # dashboard at http://localhost:8000
docker compose --profile splunk up -d  # OPTIONAL real Splunk at http://localhost:8001
```

## Run on Killercoda

The `killercoda/` folder is a ready-to-import scenario (Ubuntu backend). It
clones the repo, installs dependencies, and walks through: install → read the
report → open the dashboard → edit the policy. Point a Killercoda scenario repo
at these files, or just paste the step commands into any Ubuntu node.

---

## Using the checker

```bash
python3 src/nxos_compliance_checker.py --config-dir configs --format console
python3 src/nxos_compliance_checker.py --config switch.cfg   --format json  --output report.json
python3 src/nxos_compliance_checker.py --config-dir configs  --format ndjson --output output/compliance.ndjson
```

| Flag | Purpose |
|------|---------|
| `--config FILE` | scan a single `.cfg` |
| `--config-dir DIR` | scan every `.cfg`/`.conf`/`.txt` in a directory |
| `--policy FILE` | YAML policy (default `policy/nxos_policy.yaml`) |
| `--format` | `console` \| `json` \| `csv` \| `ndjson` |
| `--output FILE` | write to a file instead of stdout |
| `--fail-under PCT` | exit non-zero if any device scores under `PCT` (CI/cron gate) |
| `--no-color` | plain console output |

### Output formats

- **console** — human-readable report; shows only failures + remediation.
- **json** — one document: fleet summary + per-device results.
- **csv** — one row per check (spreadsheet / BI friendly).
- **ndjson** — one JSON object per line: **1 summary event + N check events per
  device**. This is what a Splunk forwarder ingests.

### Scoring

Each check has a severity that sets its weight:

| Severity | Weight |
|----------|--------|
| CRITICAL | 10 |
| HIGH | 7 |
| MEDIUM | 4 |
| LOW | 2 |

`score = 100 × (sum of passed weights) / (sum of all weights)`, graded:
**A ≥ 90, B ≥ 80, C ≥ 70, D ≥ 60, F < 60**.

---

## The policy (`policy/nxos_policy.yaml`)

Security checks live in YAML — **security teams edit rules without touching
Python** (template-method design). Supported `check_type`s:

| check_type | Meaning | Key fields |
|------------|---------|-----------|
| `presence` | pattern **must** exist | `pattern` |
| `absence` | pattern must **not** exist | `pattern` |
| `value` | extract a number, compare to a threshold | `pattern`, `operator`, `threshold` |
| `value_range` | extracted number within `[min, max]` | `pattern`, `min`, `max` |
| `vty_lines` | required setting on every `line vty` block | `pattern` |
| `interface` | per-interface setting present/absent | `pattern`, `mode`, `interface_filter` |

Adding a new check type is a small handler in `ComplianceChecker.check_methods`
(strategy pattern) — existing checks are untouched.

> **Coverage note:** the deck targets **116 checks across 10 categories**. This
> repo ships a curated, fully-working representative set (~39 checks) covering
> every category and every check type. Growing it to the full 116 is pure YAML.

Categories: System Hardening · Management Plane · Control Plane · Data Plane ·
Network Services · Monitoring · IPv6 Security · VTY/Console · Interface · BGP.

---

## Splunk integration (optional)

For the full stack on the same box:

```bash
docker compose --profile splunk up -d      # Splunk Free, UI on :8001
# login: admin / ${SPLUNK_PASSWORD:-Changeme123!}
```

Splunk artifacts in `splunk/`:

- `props.conf` — `SHOULD_LINEMERGE=false`, `KV_MODE=json`, JSON timestamp.
- `inputs.conf` — monitors `/opt/nxos-compliance/output/*.ndjson` into index
  `dcn-compliance`.
- `nxos_compliance_dashboard.xml` — device summary, grade pie, severity bars,
  stacked per-device failures, and a click-to-drilldown failing-checks table.

Sample search:

```
index=dcn-compliance sourcetype=nxos_compliance event_type=compliance_check status=FAIL severity=CRITICAL
```

---

## Automating scans

Cron a scan every 30 minutes (native install):

```cron
*/30 * * * * cd /opt/nxos-compliance && make scan >> /var/log/nxos-compliance.log 2>&1
```

CI gate (fails the build if any device is below 80%):

```bash
python3 src/nxos_compliance_checker.py --config-dir configs --fail-under 80
```

---

## Layout

```
src/nxos_compliance_checker.py   the checker (strategy/template/factory patterns)
policy/nxos_policy.yaml          the security policy (edit here)
configs/                         sample NX-OS configs (one hardened, one weak)
dashboard/index.html             zero-dependency Splunk-style dashboard
splunk/                          props.conf, inputs.conf, dashboard XML
killercoda/                      ready-to-run Killercoda scenario
tests/test_checker.py            test suite (pytest or standalone)
setup.sh / run_scan.sh / Makefile   native single-box tooling
Dockerfile / docker-compose.yml     containerized deployment (+ splunk profile)
```

## Requirements

- Python 3.8+ and `PyYAML` (installed by `setup.sh` / `make install`).
- Optional: Docker + Docker Compose for the containerized / Splunk paths.
