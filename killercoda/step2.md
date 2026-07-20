# Read the compliance report

Run the console report again on its own:

```bash
make report
```{{exec}}

Each device gets a **letter grade (A–F)** and a **risk-weighted score**. The two
sample devices are deliberately different:

- `switch-core-01` — a hardened config → **grade A**
- `switch-edge-02` — telnet on, plaintext passwords, SNMP `public/private`,
  no logging → **grade F**

Failures are grouped by severity (**CRITICAL / HIGH / MEDIUM / LOW**) and each
one prints the exact **remediation command**.

Try the other output formats — same data, different shape:

```bash
make json | head -30
```{{exec}}

```bash
make csv | head
```{{exec}}

```bash
head -3 output/compliance.ndjson
```{{exec}}

The **NDJSON** file is the key one: one JSON object per line — one summary event
plus one event per check, per device. That is exactly what a Splunk Universal
Forwarder ingests (`SHOULD_LINEMERGE=false`, `KV_MODE=json`).
