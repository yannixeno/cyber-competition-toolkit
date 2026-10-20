# Answer the question. Use the right query.

[Plan](README.md) · [Timeline](TIMELINE.md)

Keep the README open for the plan. Use this page as a technical reference: jump to the current question, choose a tool, run a targeted check, and save the evidence. Do not run every query.

**Jump to:** [Who?](#1-who-was-affected) · [File?](#2-what-was-the-file) · [When?](#3-when-did-it-start) · [How?](#4-how-did-it-arrive-and-run) · [Behavior?](#5-what-did-it-do) · [Contacts?](#6-what-did-it-contact) · [Other hosts?](#7-was-anyone-else-affected) · [Evidence?](#8-can-we-prove-the-answers) · [Artifact picker](#velociraptor-artifact-picker)

## Before copying

- Replace example hosts, users, files, PID 4242, domains, IPs, hashes, GUIDs, and dates. Set an **absolute incident time window** first.
- **ELK:** Kibana Discover, **KQL** selected. Examples assume ECS/Winlogbeat-style mappings. Inspect a real event first; use the actual event ID and user/path fields.
- **Arkime:** Sessions search bar, **Arkime expressions**. Check Help → Fields and time-bounding mode. Malcolm/Zeek fields may be absent.
- **Velociraptor:** select the correct endpoint for artifact collection. The VQL below must execute **on that endpoint**, using the provided client VQL/Shell facility or a client artifact. A normal server-side notebook can run pslist/glob/netstat against the server, not the victim. For previously collected results, use that collection's notebook-generated source query.
- Run examples **separately**. Windows artifacts below are Windows-specific. Review installed definitions, parameters, permissions, and collection errors; do not assume current documentation matches the installed version.
- Examples are documentation-informed, **not event-tested detections**. No results can mean missing data, wrong filters, or an offline client.

## 1. Who was affected?

### ELK: host, account, and logon context

```text
host.name: "LAB-WIN11"
```

```text
host.name: "LAB-WIN11" and user.name: "analyst"
```

```text
host.name: "LAB-WIN11" and winlog.channel: "Security" and winlog.event_id: ("4624" or "4625" or "4648")
```

Read raw target/subject username, domain, logon type/session, source IP, and process context. user.name can represent different actors depending on the pipeline. A logged-on account is not automatically the sample's user.

### Velociraptor: account tied to the live process

**Artifacts:** Windows.System.Pslist; Windows.Sys.Users for registry profile evidence (not logon proof or a complete directory inventory).

```sql
SELECT Pid, Ppid, Name, Exe, CommandLine, Username, CreateTime
FROM pslist()
WHERE Name =~ '(?i)suspect'
```

Remove WHERE if you need an initial snapshot. If it already exited, use historical events.

### Arkime: identify the host behind a lead

```text
ip == 192.0.2.10
```

Map the IP to a host **at the event time**. Arkime generally cannot infer a Windows user from an IP alone.

**Save:** account/domain, host/client ID, IP-at-event, and source record.

## 2. What was the file?

### Velociraptor: process, exact path, hash, and signature

**Artifact:** Windows.System.Pslist. Narrow ProcessRegex, PidRegex, ExePathRegex, or CommandLineRegex where available; enrichment can cost time.

```sql
SELECT * FROM Artifact.Windows.System.Pslist(
  ProcessRegex='(?i)^suspect[.]exe$')
```

Inspect one known PID:

```sql
SELECT Pid, Ppid, Name, Exe, CommandLine, Username, CreateTime
FROM pslist(pid=4242)
```

Hash/signature for one exact file:

```sql
SELECT OSPath, Size, hash(path=OSPath) AS Hash,
       authenticode(filename=OSPath) AS Signature
FROM glob(globs='C:/Users/analyst/Downloads/suspect.exe')
WHERE NOT IsDir
```

Expand Hash for SHA256. No row may mean a missing/inaccessible file; inspect errors. Acquire a copy through approved VFS/file collection and preserve the flow ID. Current bytes can differ from what executed earlier. Signed does not mean benign; unsigned does not mean malware.

### ELK: recorded file/process identity

```text
host.name: "LAB-WIN11" and process.name: "suspect.exe"
```

```text
process.hash.sha256: "REPLACE-SHA256" or file.hash.sha256: "REPLACE-SHA256"
```

Inspect process.executable, command line, user, parent, and historical hash. Raw Sysmon may instead expose winlog.event_data.Image/CommandLine/Hashes. For exact paths, use the document's filter control to avoid escaping mistakes.

### Arkime: possible file delivery, if HTTP is visible

```text
ip == 192.0.2.10 && http.uri == "*suspect.exe*"
```

Inspect request/response and packet evidence. HTTPS may hide the URI/content. A matching URL does not prove the file reached disk or ran.

**Save:** full path, name/type/size, SHA-256, acquisition and historical references.

## 3. When did it start?

### ELK: first observed execution

```text
host.name: "LAB-WIN11" and winlog.channel: "Microsoft-Windows-Sysmon/Operational" and winlog.event_id: "1"
```

Add process.name or the actual raw Image field after checking mappings. If Sysmon is absent but Security process auditing exists:

```text
host.name: "LAB-WIN11" and winlog.channel: "Security" and winlog.event_id: "4688"
```

Sort occurrence time ascending. Widen backward; record retention limits. A bounded time query, once @timestamp is verified as event time:

```text
host.name: "LAB-WIN11" and @timestamp >= "2026-10-19T13:00:00Z" and @timestamp <= "2026-10-19T15:00:00Z"
```

### Velociraptor: scoped EVTX and Prefetch

**Artifact:** Windows.EventLogs.Evtx. Limit EvtxGlob, StartDate, EndDate, and IDRegex rather than parsing all logs/VSS.

```sql
SELECT * FROM Artifact.Windows.EventLogs.Evtx(
  EvtxGlob='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx',
  IDRegex='^1$',
  StartDate='2026-10-19T13:00:00Z',
  EndDate='2026-10-19T15:00:00Z')
```

Fallback execution evidence where Prefetch exists:

```sql
SELECT * FROM Artifact.Windows.Forensics.Prefetch(
  binaryRegex='(?i)^suspect[.]exe$')
```

Read run times/count. Prefetch Hash/hashRegex is **not executable SHA-256**. Missing Prefetch is not proof of no execution. Amcache/Shimcache alone do not conclusively prove execution.

### Arkime: first related communication

```text
ip.src == 192.0.2.10 && ip.dst == 198.51.100.20
```

Sort first-packet time and widen backward. Session time is not automatically malware execution time. Use packet/message timestamps where available.

**Save:** earliest supported execution, parent, original timestamp/zone, timeline row, and coverage limits.

## 4. How did it arrive and run?

### ELK: parent/child chain and scripts

Discovery lead where ECS parents exist (normal applications also match):

```text
host.name: "LAB-WIN11" and process.parent.name: (winword.exe or excel.exe or outlook.exe or explorer.exe)
```

Known Sysmon instance and its children, where raw GUID fields exist:

```text
host.name: "LAB-WIN11" and winlog.channel: "Microsoft-Windows-Sysmon/Operational" and (winlog.event_data.ProcessGuid: "REPLACE-GUID" or winlog.event_data.ParentProcessGuid: "REPLACE-GUID")
```

PowerShell script blocks, if logging is enabled:

```text
host.name: "LAB-WIN11" and winlog.channel: "Microsoft-Windows-PowerShell/Operational" and winlog.event_id: "4104"
```

Read complete commands/multipart scripts without executing them. Follow earlier file arrival, extraction, browser, service, or remote logon evidence. Do not assume phishing.

### Velociraptor: live parent and direct children

```sql
SELECT Pid, Ppid, Name, Exe, CommandLine, Username, CreateTime,
       { SELECT Pid, Name, Exe, CommandLine FROM pslist(pid=Ppid) } AS Parent
FROM pslist(pid=4242)
```

```sql
SELECT Pid, Ppid, Name, Exe, CommandLine, Username, CreateTime
FROM pslist()
WHERE Ppid = 4242
```

Live-only: exited parents and reused PIDs can mislead. Historical process GUIDs/start times establish the incident chain more reliably.

### Arkime: arrival leads

```text
host.http == "example.com"
```

```text
ip == 192.0.2.10 && http.uri == "*download*"
```

Match host, time, file identity, and process context. Nearby timestamps alone do not establish causation.

**Save:** arrival evidence, parent/child instances, commands, and explicitly unknown links.

## 5. What did it do?

![Static clues and observed lab behavior both need company evidence checks](sample-analysis.png)

### Velociraptor: persistence artifacts

Review each installed definition/parameters and run only what answers the next question. Each call is separate:

```sql
SELECT * FROM Artifact.Windows.System.Services()
```

```sql
SELECT * FROM Artifact.Windows.System.TaskScheduler()
```

```sql
SELECT * FROM Artifact.Windows.Sys.StartupItems()
```

```sql
SELECT * FROM Artifact.Windows.Persistence.PermanentWMIEvents()
```

Read actual executable/arguments/account, task XML/actions/principal/triggers, Run/startup targets, and WMI filters/consumers/bindings. WMI's artifact follows bindings and may omit unlinked components. Presence now, registration then, and successful execution are different claims.

### ELK: files, registry, WMI, tasks, services

File creation:

```text
host.name: "LAB-WIN11" and winlog.channel: "Microsoft-Windows-Sysmon/Operational" and winlog.event_id: "11"
```

Registry and WMI subscription activity:

```text
host.name: "LAB-WIN11" and winlog.channel: "Microsoft-Windows-Sysmon/Operational" and winlog.event_id: ("12" or "13" or "14" or "19" or "20" or "21")
```

Services installed:

```text
host.name: "LAB-WIN11" and winlog.channel: "System" and winlog.event_id: "7045"
```

Tasks created/updated:

```text
host.name: "LAB-WIN11" and winlog.channel: "Security" and winlog.event_id: ("4698" or "4702")
```

Security log cleared:

```text
host.name: "LAB-WIN11" and winlog.channel: "Security" and winlog.event_id: "1102"
```

Narrow by candidate GUID/path/user/time. Normal software matches too. Preserve complete changed values/actions. Event IDs require their channel/provider context.

### Static: 3–5 minutes

1. Preserve the sample and record path/type/size/SHA-256.
2. For PE files, use PEStudio: strings/imports/signature/sections/packing clues. Use the provided matching tool for other formats.
3. Share candidate domains/paths/commands/persistence names. Strings/imports suggest capability, not observed behavior. Check lookup settings before disclosing samples/indicators externally.

### Dynamic: 5–8 minutes, provided isolated lab

1. Confirm clean snapshot/reset point and approved network setup. Record lab host/clock/sample hash/baseline.
2. Start sandbox/monitor logs and packet capture **before launch**. If supplied, Procmon records process/file/registry changes. Arkime sees the run only if lab traffic is captured.
3. Use the lab launch procedure. Record command/user/start/end; watch children, dropped files, registry/persistence, DNS, and connections.
4. Save logs/report, packet references, and dropped-file hashes before lab reset.
5. Keep a separate **LAB RUN** record; check indicators against company evidence. A short inactive test is not proof of benignness. No lab/sample? Record the limit and continue; do not build a sandbox during the hour.

**Save:** static clues, observed lab behavior, and separately supported company behavior.

## 6. What did it contact?

### Velociraptor: current sockets and process

**Artifact:** Windows.Network.Netstat.

```sql
SELECT * FROM Artifact.Windows.Network.Netstat()
```

Raw Windows sockets for one live process:

```sql
SELECT Pid, Status, Laddr, Raddr, Timestamp
FROM netstat()
WHERE Pid = 4242
```

Save local/remote tuple and collection time. Closed historical connections need historical events, not a live snapshot.

### ELK: historical network and DNS

```text
host.name: "LAB-WIN11" and winlog.channel: "Microsoft-Windows-Sysmon/Operational" and winlog.event_id: ("3" or "22")
```

Add the known ProcessGuid where present. Sysmon network events depend on configuration. ECS pivots where mapped:

```text
source.ip: "192.0.2.10" or destination.ip: "192.0.2.10"
```

```text
destination.ip: "198.51.100.20" and destination.port: 443
```

```text
dns.question.name: "example.com"
```

### Arkime: host, DNS, HTTP, TLS, volume

All sessions and a specific connection:

```text
ip == 192.0.2.10
```

```text
ip.src == 192.0.2.10 && ip.dst == 198.51.100.20 && port.dst == 443
```

DNS and candidate name:

```text
ip == 192.0.2.10 && protocols == dns
```

```text
host.dns == "*example*"
```

Visible HTTP host, URI, user-agent, and errors:

```text
host.http == "example.com"
```

```text
http.uri == "*suspect.exe*"
```

```text
http.user-agent == "*PowerShell*"
```

```text
http.statuscode >= 400 && http.statuscode < 500
```

TLS sessions:

```text
ip == 192.0.2.10 && protocols == tls
```

Larger source-side transfers, illustrative 10 MB on-wire threshold:

```text
ip.src == 192.0.2.10 && bytes.src > 10000000
```

That threshold is triage, not an exfiltration rule; bytes.src includes overhead and source orientation needs checking. Periodic traffic can be legitimate monitoring. HTTPS can hide content.

Open details; preserve sensor/session IDs, tuple, interval, packet/message times where available, and query/bounding mode. Overlap mode can include long sessions crossing the window. Account for NAT/proxies, DHCP changes, encryption, and capture gaps. DNS does not prove a later connection; Arkime alone generally cannot name the executable.

**Save:** destination/domain/port, interval, process attribution if supported, packet/session evidence.

## 7. Was anyone else affected?

### ELK: remove the host filter, keep the strong indicator

```text
process.hash.sha256: "REPLACE-SHA256" or file.hash.sha256: "REPLACE-SHA256"
```

```text
process.name: "suspect.exe"
```

```text
dns.question.name: "example.com" or destination.ip: "198.51.100.20"
```

Names/shared IPs are weaker than exact hashes plus execution context. For possible lateral activity:

```text
winlog.channel: "Security" and winlog.event_id: "4624" and source.ip: "192.0.2.10"
```

Review target host, account/domain, logon type/session, and subsequent process evidence. Authentication alone does not prove lateral execution.

### Velociraptor: bounded hash check on candidate clients

Use indexed logs first. If needed, check a small likely directory on selected endpoints:

```sql
SELECT OSPath, hash(path=OSPath).SHA256 AS SHA256
FROM glob(globs='C:/Users/*/Downloads/*.exe')
WHERE NOT IsDir AND SHA256 = 'REPLACE-SHA256'
```

This checks direct .exe files in Downloads only—not recursively, other extensions, or the whole disk. Change scope to the case. Do not hash every disk by default. Record online/completed/failed clients; a match on disk is not execution proof.

### Arkime: other sources and possible remote access

```text
ip.dst == 198.51.100.20
```

```text
host.dns == "example.com"
```

Group by source IP in SPI views/graphs, then map each host at the time. Candidate remote-access sessions:

```text
ip.src == 192.0.2.10 && (port.dst == 445 || port.dst == 3389 || port.dst == 22)
```

Normal administration also matches. Ports alone do not prove login, execution, or compromise.

**Save:** confirmed/suspicious hosts, each host's occurrence times, evidence, and coverage gaps.

## 8. Can we prove the answers?

Use [TIMELINE.md](TIMELINE.md). Save exact query/parameters, absolute bounds, source event/session/flow IDs, and preserved evidence locations. Keep original time/zone and distinguish occurrence, collection, ingestion, and lab-run times. Check export limits and errors.

Minute 45: stop broad hunting. Minute 55: verify exact answers and submit.

## Velociraptor artifact picker

**Select client → New Collection → search artifact → review parameters → collect → check results/logs → save flow ID.** Do not collect everything. Start with Pslist + Netstat for live leads, then the one history/persistence collection needed next.

- **Windows.System.Pslist:** process paths/users/commands and hash/signature enrichment. Narrow ProcessRegex/PidRegex/ExePathRegex/CommandLineRegex where available.
- **Windows.Sys.Users:** registry profile evidence; not a specific logon event or proof of execution.
- **Windows.Network.Netstat:** live sockets and owning process name/PID.
- **Windows.EventLogs.Evtx:** historical events. Scope EvtxGlob, StartDate, EndDate, IDRegex; avoid all-log/VSS sweeps by default.
- **Windows.Forensics.Prefetch:** execution clues/run times where present. binaryRegex filters executable names; dateAfter/dateBefore limit times. Prefetch hash is not file SHA-256.
- **Windows.System.Services:** executable/account/configuration. Optional Calculate_hashes and CertificateInfo add work; target candidates.
- **Windows.System.TaskScheduler:** task definitions/actions/user context. Review AlsoUpload for original XML; avoid unrelated command-binary uploads by default.
- **Windows.Sys.StartupItems:** Run keys and startup-folder targets/arguments.
- **Windows.Persistence.PermanentWMIEvents:** linked filters/consumers/bindings; unlinked components may need separate investigation.
- **Windows.System.Amcache:** historical program/file clues; presence alone does not prove execution.
- **Windows.Registry.AppCompatCache:** compatibility-cache clues; presence alone does not prove execution.

Missing artifact? Search the installed catalog by purpose, read its definition, and choose the equivalent. Do not guess parameters or install an entire community pack mid-event.

## No results / query errors

Check host/OS/client context, data view, absolute time/timezone, language, actual fields/artifacts, enabled logging, endpoint errors/online state, retention, encryption, NAT, and capture coverage. Test with a known matching event. A valid query returning zero rows is not a detection test.

## Official references

Documentation reviewed 2026-10-20 UTC. Installed versions were not supplied; no endpoint queries or searches have been executed against the event.

- [VQL fundamentals](https://docs.velociraptor.app/docs/vql/fundamentals/), [pslist](https://docs.velociraptor.app/vql_reference/popular/pslist/), [glob](https://docs.velociraptor.app/vql_reference/popular/glob/), [authenticode](https://docs.velociraptor.app/vql_reference/windows/authenticode/)
- [Pslist artifact](https://docs.velociraptor.app/artifact_references/pages/windows.system.pslist/), [users](https://docs.velociraptor.app/artifact_references/pages/windows.sys.users/), [Netstat](https://docs.velociraptor.app/artifact_references/pages/windows.network.netstat/)
- [EVTX artifact](https://docs.velociraptor.app/artifact_references/pages/windows.eventlogs.evtx/), [Prefetch](https://docs.velociraptor.app/artifact_references/pages/windows.forensics.prefetch/), [execution evidence](https://docs.velociraptor.app/docs/forensic/evidence_of_execution/)
- [Services](https://docs.velociraptor.app/artifact_references/pages/windows.system.services/), [tasks](https://docs.velociraptor.app/artifact_references/pages/windows.system.taskscheduler/), [startup](https://docs.velociraptor.app/artifact_references/pages/windows.sys.startupitems/), [WMI](https://docs.velociraptor.app/artifact_references/pages/windows.persistence.permanentwmievents/)
- [Arkime help](https://github.com/arkime/arkime/blob/main/viewer/vueapp/src/components/help/Help.vue), [Malcolm comparison](https://malcolm.fyi/docs/queries-cheat-sheet.html), [HTTP field definitions](https://github.com/arkime/arkime/blob/main/capture/parsers/http.c)
- [KQL](https://www.elastic.co/docs/reference/query-languages/kql), [Winlogbeat fields](https://www.elastic.co/docs/reference/beats/winlogbeat/exported-fields-winlog), [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon), [PEStudio](https://www.winitor.com/), [Procmon](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)

## Most useful queries — competition quick reference

**Start here during the hour.** Pick the row that answers your next question; do not run every row. These are prioritized for the team's unidentified-malware and timeline scenario, not guaranteed detection rules.

**Replace:** `LAB-WIN11` = affected host; `4242` = candidate PID; `192.0.2.10` = affected IP; `198.51.100.20` / `example.com` = candidate destination; `suspect.exe`, paths, dates, GUIDs, and hashes = case values. Set an absolute time range first. Full guidance and field alternatives are above.

**Run in the right place:** Velociraptor VQL on the selected endpoint (not a normal server notebook); Arkime expressions in Sessions; ELK queries in Kibana Discover with KQL selected. Windows artifacts/logs below require Windows and the relevant collection. Every query is an example, not event-tested.

| Tool | Question / use | Copyable query | Save or check |
|---|---|---|---|
| **Velociraptor · VQL** | Who ran it? What file/command? | `SELECT Pid, Ppid, Name, Exe, CommandLine, Username, CreateTime FROM pslist()` | Candidate PID, parent, full path, user, command, start time. Live snapshot only; narrow with `WHERE Name =~ '(?i)suspect'` if needed. |
| **Velociraptor · VQL** | What are the exact file bytes? | `SELECT OSPath, Size, hash(path=OSPath) AS Hash FROM glob(globs='C:/Users/analyst/Downloads/suspect.exe') WHERE NOT IsDir` | Expand Hash for SHA256; preserve original path and a collected copy. Current bytes may differ from past execution. |
| **Velociraptor · artifact/VQL** | What connections are open now? | `SELECT * FROM Artifact.Windows.Network.Netstat()` | Local/remote IPs and ports, owning PID/name, collection time. Closed historical connections will be absent. |
| **Velociraptor · artifact/VQL** | Is a task launching it? | `SELECT * FROM Artifact.Windows.System.TaskScheduler()` | Task name, action/arguments, principal, triggers, and XML where collected. Present task does not prove it ran. |
| **Velociraptor · artifact/VQL** | Is a service launching it? | `SELECT * FROM Artifact.Windows.System.Services()` | Actual binary/arguments, account, and configuration. Correlate installation/execution history. |
| **Velociraptor · artifact/VQL** | Is WMI relaunching it? | `SELECT * FROM Artifact.Windows.Persistence.PermanentWMIEvents()` | Linked filter, consumer, and binding; unlinked components may be missed. |
| **Velociraptor · artifact/VQL** | When did it run if ELK lacks history? | `SELECT * FROM Artifact.Windows.EventLogs.Evtx(EvtxGlob='C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx', IDRegex='^1$', StartDate='2026-10-19T13:00:00Z', EndDate='2026-10-19T15:00:00Z')` | Replace dates and inspect candidate path/GUID/user/parent. Scope the log/time; event 1 means process creation in this Sysmon channel. |
| **Arkime · Sessions** | What traffic belongs to this host? | `ip == 192.0.2.10` | Session IDs, first/last times, endpoints/ports; verify the IP belonged to that host then. |
| **Arkime · Sessions** | Did it connect to this destination? | `ip.src == 192.0.2.10 && ip.dst == 198.51.100.20` | Matching tuple and occurrence interval. Correlate endpoint evidence before naming the process. |
| **Arkime · Sessions** | What DNS did it generate? | `ip == 192.0.2.10 && protocols == dns` | Query/answer, times, session evidence. DNS does not establish a later connection. |
| **Arkime · Sessions** | Who looked up this domain? | `host.dns == "example.com"` | Source hosts and event times; map each IP to its host at that time. |
| **Arkime · Sessions** | Was the candidate downloaded over visible HTTP? | `ip == 192.0.2.10 && http.uri == "*suspect.exe*"` | Actual request/response and packet time where available. HTTPS can hide URI/content; a URL match is not execution proof. |
| **Arkime · Sessions** | Were there possible remote-access connections? | `ip.src == 192.0.2.10 && port.dst == [22, 445, 3389]` | Destination hosts/time for SSH/SMB/RDP-port leads. Normal administration matches too; port alone does not prove success or compromise. |
| **ELK · KQL** | What happened on the host? | `host.name: "LAB-WIN11"` | Sort event time; inspect actual user, process, source dataset, and raw record. |
| **ELK · KQL** | When did a process start? | `host.name: "LAB-WIN11" and winlog.channel: "Microsoft-Windows-Sysmon/Operational" and winlog.event_id: "1"` | Candidate path/hash, original time, user, ProcessGuid and parent. Narrow to the candidate; say earliest observed. |
| **ELK · KQL** | What did this process launch or do? | `host.name: "LAB-WIN11" and winlog.channel: "Microsoft-Windows-Sysmon/Operational" and (winlog.event_data.ProcessGuid: "REPLACE-GUID" or winlog.event_data.ParentProcessGuid: "REPLACE-GUID")` | Instance-linked events and children. Requires these raw GUID fields; do not join on PID alone. |
| **ELK · KQL** | Did it create files? | `host.name: "LAB-WIN11" and winlog.channel: "Microsoft-Windows-Sysmon/Operational" and winlog.event_id: "11"` | File path, creating process, occurrence time, source event. File creation is not execution. |
| **ELK · KQL** | What DNS/connections occurred historically? | `host.name: "LAB-WIN11" and winlog.channel: "Microsoft-Windows-Sysmon/Operational" and winlog.event_id: ("3" or "22")` | Process GUID, DNS/tuple, event time; match Arkime. Logging/configuration may omit these events. |
| **ELK · KQL** | Which account logged on or failed? | `host.name: "LAB-WIN11" and winlog.channel: "Security" and winlog.event_id: ("4624" or "4625" or "4648")` | Target/subject account and domain, logon type/session, source IP. Login alone is not malware execution. |
| **ELK · KQL** | Does the same hash appear on other hosts? | `process.hash.sha256: "REPLACE-SHA256" or file.hash.sha256: "REPLACE-SHA256"` | Other host names/times and execution context. Requires indexed hashes; file presence alone is not compromise. |

**If you only have a few minutes:** host activity → process/user/path → exact hash → related network evidence → tasks/services if indicated → same indicator on other hosts. Add each supported answer to the timeline immediately.

**For every useful hit:** record full occurrence time + host + observed fact + exact source/event/session/collection reference. Keep lab-run findings separate. Preserve original timestamps; unknown timezone/clock is not UTC. No results may mean a visibility gap.

