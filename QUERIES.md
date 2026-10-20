# Quick sheet: find, inspect, test

[Plan](README.md) · [Timeline](TIMELINE.md)

Set the incident's **absolute time window** first. Replace sample hostnames/IPs. Check actual fields; these examples have not been tested in the competition. Empty results can mean missing data or wrong filters.

## 1. ELK: what happened and when?

Use **Kibana Discover → KQL**. Start with the host:

```text
host.name: "LAB-WIN11"
```

Sort oldest first. Read the timestamp, user, path, command line, parent, process identifier, and source event ID.

**What ran?** Requires collected Sysmon events:

```text
host.name: "LAB-WIN11" and winlog.channel: "Microsoft-Windows-Sysmon/Operational" and winlog.event_id: "1"
```

Follow the process's parent and children. Prefer GUID/entity IDs; PIDs get reused. If only Security auditing exists, check Security / 4688 instead.

**What did this process do?** If raw Sysmon GUID fields exist:

```text
host.name: "LAB-WIN11" and winlog.channel: "Microsoft-Windows-Sysmon/Operational" and (winlog.event_data.ProcessGuid: "REPLACE-GUID" or winlog.event_data.ParentProcessGuid: "REPLACE-GUID")
```

Look for file/registry changes, DNS, connections, and children. Fields depend on the pipeline and enabled logs.

**New service or task?** Run separately:

```text
host.name: "LAB-WIN11" and winlog.channel: "System" and winlog.event_id: "7045"
host.name: "LAB-WIN11" and winlog.channel: "Security" and winlog.event_id: ("4698" or "4702")
```

Inspect the service path/task action. Legitimate installs match too; registration is not execution.

**Same sample elsewhere?** Only works where hashes are indexed:

```text
process.hash.sha256: "REPLACE-SHA256"
file.hash.sha256: "REPLACE-SHA256"
```

## 2. Velociraptor: what is on the host?

Select the correct client; check OS/last seen. Review existing results, then collect only what answers your question.

- **Process:** full path, command line, parent, user, start time, connections.
- **File:** acquire a copy; record original path, SHA-256, and collection ID.
- **Persistence:** inspect service/task actions, startup/Run keys, and WMI; Linux cron/systemd/SSH keys where relevant.
- **History:** collect relevant logs if ELK lacks them. A live snapshot is not process history.

Check installed artifacts: Windows.Network.Netstat, Windows.System.Services, Windows.System.TaskScheduler. Review parameters/limits and test on one host first.

Minimal VQL in an **endpoint** query context:

```sql
SELECT * FROM pslist()
```

This shows processes now. Server context may inspect the server instead of the victim.

## 3. Arkime: what did it contact?

Use **Arkime Sessions**. Run separately:

```text
ip == 192.0.2.10
ip.src == 192.0.2.10 && ip.dst == 198.51.100.20
ip == 192.0.2.10 && protocols == dns
host.dns == "*example*"
```

Open session details. Save session ID, endpoints/ports, first/last time, and packet/message time where available. Check host-IP mapping and time-bounding; overlap mode can include long sessions crossing the window. HTTPS can hide content. Match endpoint evidence before naming the responsible process.

## 4. Static and dynamic analysis

![Static analysis produces leads; dynamic analysis observes a controlled lab run; both feed company evidence checks](sample-analysis.png)

**Static — 3–5 minutes. Inspect without running.**

1. Record original path, file type, size, and SHA-256. Preserve a copy.
2. For PE files, use PEStudio: signature, strings, imports, sections/packing clues. Use the provided matching tool for scripts/other formats.
3. Share candidate domains, paths, commands, and persistence names immediately. Strings/imports alone do not prove behavior. Check online lookup settings before disclosing samples/indicators externally.

**Dynamic — 5–8 minutes. Observe a controlled run.**

1. Use the provided isolated VM/sandbox, clean snapshot/reset point, and approved network setup. Record lab host, clock, sample hash, and baseline.
2. Start recording **before** launch: sandbox telemetry or provided process/file/registry monitor and packet capture. If supplied, Procmon helps track processes and file/registry changes. Arkime only sees lab traffic if that traffic is captured.
3. Follow the lab's launch procedure. Note command/user/start/end. Watch child processes, dropped files, persistence, DNS, and connections.
4. Save logs/report, packet evidence, and dropped-file hashes before resetting through the lab procedure.
5. Label results **LAB RUN**. Hunt the observed indicators in company evidence. Never insert lab timestamps as the company's original activity.

No lab, no sample, or no visible behavior? Record the limitation and move on. No behavior does not mean benign. Do not spend the hour building a sandbox or forcing execution.

**Handoff:** sample hash → clues → observed lab behavior → matching company evidence.

References: [KQL](https://www.elastic.co/docs/reference/query-languages/kql), [Arkime help](https://github.com/arkime/arkime/blob/main/viewer/vueapp/src/components/help/Help.vue), [Velociraptor](https://docs.velociraptor.app/docs/), [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon), [PEStudio](https://www.winitor.com/), [Procmon](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon). Extra tools are optional if provided, not installations to perform during the hour.
