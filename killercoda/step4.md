# Edit policy & re-scan

The whole point of the template-driven design: **security teams edit YAML, not
Python.** Let's add a check.

Open the policy:

```bash
cd /root/documentation
cat policy/nxos_policy.yaml | head -60
```{{exec}}

Append a new check that forbids the insecure `feature nxapi http` (cleartext
API). Everything you need — check type, severity, remediation — is data:

```bash
cat >> policy/nxos_policy.yaml <<'EOF'

  - id: NX-MP-099
    category: Management Plane
    severity: HIGH
    description: "NX-API must not be served over cleartext HTTP"
    check_type: absence
    pattern: '^nxapi http port'
    remediation: "no nxapi http ; nxapi https port 443"
EOF
```{{exec}}

Re-scan — no code changed, the new rule is live:

```bash
make report
```{{exec}}

You can also point the scanner at your **own** configs:

```bash
python3 src/nxos_compliance_checker.py --config /path/to/switch.cfg --format console
```

Add more checks the same way to grow toward full coverage.
