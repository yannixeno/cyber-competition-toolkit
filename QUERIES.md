# Quick searches: pick the question you need answered

[60-minute plan](README.md) · [Timeline](TIMELINE.md)

Set the incident's **absolute time window** first. Replace example hosts/IPs/values. These examples are not tested against the event; check actual fields. No results may mean missing data or the wrong filter.

## ELK: what happened on this host?

Run in **Kibana Discover with KQL selected**. Start with the host, inspect a record, then narrow.

```text
host.name: "LAB-WIN11"
```

Sort oldest first. Look at time, user, executable, command line, parent/process ID or GUID, and source event ID. Save the raw event reference with useful findings.

### What ran?

Requires collected Sysmon process events:

```text
host.name: "LAB-WIN11" and winlog.channel: "Microsoft-Windows-Sysmon/Operational" and winlog.event_id: "1"
```

Find the suspicious process, then follow its parent and children. Prefer a process GUID/entity ID; PIDs get reused. If only Security auditing is available, look for channel Security / event 4688 instead.

### What did that process do next?

If the raw Sysmon GUID fields are present:

```text
host.name: "LAB-WIN11" and winlog.channel: "Microsoft-Windows-Sysmon/Operational" and (winlog.event_data.ProcessGuid: "REPLACE-GUID" or winlog.event_data.ParentProcessGuid: "REPLACE-GUID")
```

Inspect the event type and details: network, DNS, files, children, or registry activity. Field mappings and sensor settings vary.

### Was persistence installed?

Service installation:

```text
host.name: "LAB-WIN11" and winlog.channel: "System" and winlog.event_id: "7045"
```

Task creation/update:

```text
host.name: "LAB-WIN11" and winlog.channel: "Security" and winlog.event_id: ("4698" or "4702")
```

Check the actual service path or task action. Legitimate installs match too. Registration does not prove execution.

### Where else did this hash appear?

Only works if hashes were indexed. Run separately as needed:

```text
process.hash.sha256: "REPLACE-SHA256"
file.hash.sha256: "REPLACE-SHA256"
```

Check host/time/context for every match. Same bytes under another name do not prove execution.

## Velociraptor: what is on the host?

Select the right client; check hostname/OS/last seen. Start with existing results, then collect only what answers your question.

- **Running now:** processes, full paths, command lines, parents, start times, and connections.
- **Suspicious file:** acquire a copy, record original path and SHA-256. Preserve collection/flow ID.
- **Restarts itself:** check services, task actions, startup/Run keys, and WMI subscriptions; on Linux, cron/systemd/SSH keys where relevant.
- **Past activity:** collect relevant event logs and execution artifacts if ELK lacks history. Current state alone cannot establish historical creation/execution times.

Artifact names to check in the installed catalog: Windows.Network.Netstat, Windows.System.Services, Windows.System.TaskScheduler. Review parameters/limits on one host before expanding.

Minimal VQL in an **endpoint** query context:

```sql
SELECT * FROM pslist()
```

This shows live processes, not history. The server context can inspect the server instead of the victim.

## Arkime: what did the host contact?

Run in **Arkime Sessions**, not Kibana.

All sessions involving the host:

```text
ip == 192.0.2.10
```

Traffic to a candidate destination:

```text
ip.src == 192.0.2.10 && ip.dst == 198.51.100.20
```

DNS and visible HTTP:

```text
ip == 192.0.2.10 && protocols == dns
ip == 192.0.2.10 && protocols == http
host.dns == "*example*"
```

Open session details. Record endpoints, first/last times, session ID, and actual packet/message time if available. Match the tuple/time to endpoint logs before assigning a process. HTTPS can hide URLs/content. Check historical host-IP mapping and time-bounding mode; use overlap mode if available to include long sessions crossing your window.

## One finding = one next check

Example: **ELK found a process start → endpoint checks its path/hash → Arkime checks related traffic → lead adds evidence-backed timeline rows.**

For fields/event meanings, use the tools' built-in help and the official references linked in the older tool guides. Do not open all the old documents during the sprint.
