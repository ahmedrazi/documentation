# NX-OS Compliance Checker -- single-box convenience targets.
# Usage: make <target>

PY      ?= python3
VENV    := .venv
VPY     := $(VENV)/bin/python3
CONFIGS ?= configs
POLICY  ?= policy/nxos_policy.yaml
PORT    ?= 8000

.PHONY: help
help:                 ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
	  | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

$(VPY):
	$(PY) -m venv $(VENV)
	$(VENV)/bin/pip install --quiet --disable-pip-version-check -r requirements.txt

.PHONY: install
install: $(VPY)       ## Create venv and install dependencies (PyYAML)

.PHONY: scan
scan: install         ## Run a scan: console report + refresh dashboard NDJSON
	@mkdir -p output
	$(VPY) src/nxos_compliance_checker.py --config-dir $(CONFIGS) --policy $(POLICY) --format console --no-color
	$(VPY) src/nxos_compliance_checker.py --config-dir $(CONFIGS) --policy $(POLICY) --format ndjson --output output/compliance.ndjson
	cp -f output/compliance.ndjson dashboard/compliance.ndjson

.PHONY: report
report: install       ## Print the console report only
	$(VPY) src/nxos_compliance_checker.py --config-dir $(CONFIGS) --policy $(POLICY) --format console --no-color

.PHONY: json csv ndjson
json: install         ## Emit JSON to stdout
	$(VPY) src/nxos_compliance_checker.py --config-dir $(CONFIGS) --policy $(POLICY) --format json
csv: install          ## Emit CSV to stdout
	$(VPY) src/nxos_compliance_checker.py --config-dir $(CONFIGS) --policy $(POLICY) --format csv
ndjson: install       ## Emit NDJSON to stdout
	$(VPY) src/nxos_compliance_checker.py --config-dir $(CONFIGS) --policy $(POLICY) --format ndjson

.PHONY: dashboard
dashboard: scan       ## Scan, then serve the dashboard on $(PORT)
	@echo "==> Dashboard at http://localhost:$(PORT)  (Ctrl-C to stop)"
	cd dashboard && $(PY) -m http.server $(PORT)

.PHONY: test
test: install         ## Run the test suite
	$(VPY) -m pytest -q tests || $(VPY) tests/test_checker.py

.PHONY: docker
docker:               ## Build image and run scan + dashboard via docker compose
	docker compose up --build checker
	docker compose up -d dashboard
	@echo "==> Dashboard at http://localhost:8000"

.PHONY: splunk
splunk:               ## Bring up the optional real Splunk stack
	docker compose --profile splunk up -d
	@echo "==> Splunk UI at http://localhost:8001 (admin / $${SPLUNK_PASSWORD:-Changeme123!})"

.PHONY: clean
clean:                ## Remove venv and generated output
	rm -rf $(VENV) output/*.ndjson dashboard/compliance.ndjson
