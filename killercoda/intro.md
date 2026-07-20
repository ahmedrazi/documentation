# NX-OS Compliance Checker — Single Box

This scenario runs the **entire** NX-OS security compliance stack on one Ubuntu
node — no Cisco hardware, no separate Splunk indexer, no forwarders.

You get:

- A Python **compliance checker** that parses NX-OS `.cfg` files and evaluates
  them against a YAML security policy (CIS / Cisco hardening / NIST).
- **A–F grades** with risk-weighted scoring by severity.
- Four output formats: **console, JSON, CSV, NDJSON**.
- A zero-dependency **Splunk-style dashboard** you open in the browser.

The original architecture was distributed (devices → forwarder → Splunk
indexer). Here everything is collapsed onto **one Linux box** so you can run,
demo, and extend it in minutes.

Click **START** — the environment clones the project for you.
