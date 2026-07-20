# Install & run your first scan

The project has been cloned to `/root/documentation`. Move into it:

```bash
cd /root/documentation
```{{exec}}

Install dependencies and run the first scan in one step:

```bash
./setup.sh
```{{exec}}

This creates a Python virtualenv, installs **PyYAML** (the only dependency),
scans the two sample switch configs in `configs/`, and writes NDJSON output to
`output/compliance.ndjson`.

> The checker itself is pure Python + one library — light enough for any node.

You should see a console compliance report scroll past, ending with a fleet
summary. In the next step we'll read it.
