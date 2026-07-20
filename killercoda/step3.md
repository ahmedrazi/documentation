# Open the dashboard

Instead of a full Splunk install, this box ships a **zero-dependency,
Splunk-style dashboard** that reads the same NDJSON.

Refresh the data and serve the dashboard:

```bash
make scan
cd dashboard && python3 -m http.server 8000
```{{exec}}

Now open the web preview on **port 8000**:

`{{TRAFFIC_HOST1_8000}}`

Or use the Killercoda toolbar: **+ → Select port to view on Host 1 → 8000**.

You'll see:

- **Device summary** table with grades and pass/fail counts
- **Grade distribution** and **failures by severity** charts
- A **drilldown** table — filter by device/severity and click any failing check
  to see the message and the fix

Press **Ctrl-C** in the terminal to stop the server when you're done.

> Want the *real* Splunk instead? The repo includes
> `splunk/props.conf`, `splunk/inputs.conf`, a dashboard XML, and a
> `docker compose --profile splunk up -d` target — bring it up on a larger node.
