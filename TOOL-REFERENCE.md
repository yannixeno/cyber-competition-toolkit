> Preserved original reference. Start with [README.md](README.md) and [PLAYBOOK.md](PLAYBOOK.md). Use [TIMELINE.md](TIMELINE.md) for the canonical timeline schema and evidence interpretation. This older guide is retained for its command examples.

# Cyber Competition Toolkit

Private working field guide for Arkime, Velociraptor, ELK, malware triage, and team investigations.

**Status:** Starter reference. Queries and commands have not been executed against the competition environment. Verify field names, tool versions, permissions, and telemetry before relying on results. No competition rules have been supplied or verified; record them before the event.

## Quick navigation

- [First 15 minutes](#first-15-minutes)
- [Arkime](#arkime)
- [Velociraptor](#velociraptor)
- [ELK / Kibana](#elk--kibana)
- [Windows and Linux triage](#windows-and-linux-triage)
- [PEStudio malware triage](#pestudio-malware-triage)
- [Investigation playbooks](#investigation-playbooks)
- [Evidence and handoffs](#evidence-and-handoffs)
- [Troubleshooting](#troubleshooting)
- [Official references](#official-references)

## First 15 minutes

1. Read scoring, scope, permitted tools, outside assistance/AI, internet use, evidence export, and remediation rules. Do not assume this repository is permitted.
2. Record event start/end, displayed timezone, evidence timezone, clock offsets, monitored subnets, hostnames, and tool versions. Use UTC in the shared timeline; preserve original timestamps and offsets.
3. Assign a lead, network analyst, endpoint analyst, log analyst, and evidence/submission owner. Combine roles if the team is smaller. Give every question an owner.
4. Confirm access to Arkime sessions and packet detail, an online Velociraptor client, and a known ELK event. Identify missing sensors and retention limits.
5. Read the question before collecting data. Write the hypothesis and the exact fact needed: account, host, path, hash, destination, first-seen time, or persistence mechanism.
6. Start with narrow time/host filters. Save each useful query with its time range and results. Use a second source to validate decisive findings when available.
7. Reserve time to verify submissions and resolve uncertain answers. Mark facts, hypotheses, and unknowns separately.

Before the event, clone this private repo locally or download its ZIP from Code. Open the Markdown locally and confirm the guide is usable without internet. Never store secrets, endpoint keys, raw PCAPs, collected samples, or live answers here by default. A private repository still sends its contents to GitHub.

## Arkime

**Where:** Arkime Sessions search bar. This is Arkime expression syntax, not KQL, Lucene, or a Wireshark display filter.

Set the time window first. Replace documentation IPs/domains below. Check your instance's Help → Fields and search autocomplete; Malcolm may add Zeek/Suricata fields absent in standalone Arkime.

### Host and network pivots

All expressions below are starter examples; expected output is matching session metadata, not proof of compromise.

~~~text
ip == 192.0.2.10
ip.src == 192.0.2.10
ip.dst == 198.51.100.20
ip.src == 192.0.2.0/24
ip == 192.0.2.10 && port.dst == 443
ip == 192.0.2.10 && (port.dst == 445 || port.dst == 3389)
port == [22, 80, 443, 445, 3389]
~~~

The first expression matches an IP through Arkime's special IP alias; source/destination fields narrow direction. Do not automatically equate source with attacker or destination with victim.

### Protocol and application pivots

~~~text
protocols == dns
protocols == http
protocols == tls
host.dns == "*example*"
host.http == "example.com"
http.statuscode >= 400 && http.statuscode < 500
http.statuscode == EXISTS!
~~~

DNS filters require decoded DNS metadata; HTTP filters require visible, parsed HTTP. HTTPS generally hides request paths, bodies, and status codes without decryption. A domain match can be benign. A 4xx response can be routine browsing or a scanner.

### Working a suspicious session

1. Record the session ID, timestamps, source/destination IPs and ports, protocol, and sensor.
2. Open session detail. Examine DNS, HTTP headers, TLS metadata, byte counts, and available payload.
3. Search the same host before and after the event. Use SPI views/graphs to inspect common destinations and activity over time.
4. For repeated callbacks, compare intervals, duration, byte counts, DNS names, and endpoint process evidence. Regular timing alone does not establish command-and-control.
5. Export only the scoped sessions/PCAP allowed by the rules. Hash the exported file and record filters/time bounds.
6. Correlate with endpoint and log timestamps. NAT, proxies, DHCP changes, packet loss, and asymmetric capture can complicate attribution.

## Velociraptor

**Where:** Client collection UI for a known endpoint; VQL in an appropriate notebook or query context. Confirm the client ID maps to the intended hostname and OS.

Start on one host. Inspect artifact descriptions, parameters, source, and resource limits before collection. Hashing many binaries, recursive file collection, and fleet hunts can be expensive. Record the collection/flow ID, artifact version, parameters, start/end times, and errors.

### Initial endpoint collection

- Processes: PID, parent PID, creation time, command line, executable path, user, and signatures/hashes where collected.
- Connections: local/remote endpoints and associated process. Live connections can disappear before collection.
- Persistence: services, scheduled tasks, Run/RunOnce, startup folders, and WMI subscriptions; Linux cron/systemd/SSH configuration as relevant.
- Historical evidence: relevant EVTX, PowerShell logs, file metadata, Prefetch, Amcache, and registry evidence when available.
- File acquisition: target the exact suspicious file or log. Preserve original path and hash the acquired copy.

### Artifact starting points

Confirm availability and parameters in the installed artifact catalog before collecting:

- `Windows.Network.Netstat`: Windows connection information.
- `Windows.System.TaskScheduler`: scheduled task investigation.
- `Windows.System.Services`: service investigation.
- `Windows.Registry.AppCompatCache` and `Windows.System.Amcache`: historical program/file evidence. Presence alone does not prove execution.

The names above are artifact identifiers, not filesystem paths. Search the UI catalog by name. Use the official references below to review their current definitions. Community Artifact Exchange content should be reviewed and tested individually; do not import everything during the event.

### Minimal VQL example

Read-only process enumeration in a supported endpoint query context:

~~~sql
SELECT * FROM pslist()
~~~

Expected output: current process rows available to the collector's privileges. This is a live snapshot, not process history. The server's own process list is not the endpoint's process list; verify execution context.

Offline collectors are an option only if rules allow and normal clients are unavailable. Build for the target OS with only needed artifacts, test on a lab host, and retain collection containers outside this repo. Do not commit embedded configurations or credentials.

## ELK / Kibana

**Where:** Kibana Discover with **KQL** selected. These are filters, not sequence detections. They assume ECS-style mappings or Winlogbeat fields; inspect a known event and adjust to your actual pipeline.

1. Choose the correct data view and time field (usually @timestamp).
2. Verify a known event is present before treating zero matches as meaningful.
3. Inspect host.name, user.name, source.ip, destination.ip, event.code, winlog.event_id, winlog.channel, process.*, and message.
4. Distinguish event time from ingestion time. Preserve original timestamp/offset.

### Basic pivots — ECS fields required

~~~text
host.name: "LAB-WIN11"
user.name: "analyst"
source.ip: "192.0.2.10" or destination.ip: "192.0.2.10"
process.name: (powershell.exe or pwsh.exe or cmd.exe)
process.hash.sha256: "REPLACE_WITH_SHA256"
http.response.status_code >= 400 and http.response.status_code < 500
~~~

Each returns matching documents only when those fields are populated. Shells and HTTP errors are common legitimate activity. Hash filtering requires indexed file/process hashes; it cannot search uncollected files.

### Windows events — channel/provider and collection required

Prefer the actual event ID field observed in your data. Examples below use winlog.event_id. If event.code is your equivalent, substitute after verifying a sample event.

~~~text
winlog.channel: "Security" and winlog.event_id: "4625"
winlog.channel: "Security" and winlog.event_id: "4624"
winlog.channel: "Security" and winlog.event_id: ("4720" or "4728" or "4732" or "4756")
winlog.channel: "System" and winlog.event_id: "7045"
winlog.channel: "Security" and winlog.event_id: ("4698" or "4702")
winlog.channel: "Security" and winlog.event_id: "1102"
winlog.channel: "Microsoft-Windows-PowerShell/Operational" and winlog.event_id: "4104"
winlog.channel: "Microsoft-Windows-Sysmon/Operational" and winlog.event_id: ("1" or "3" or "11" or "22")
~~~

Interpretation: 4625 failed logon; 4624 successful logon; 4720 account creation; 4728/4732/4756 group additions; 7045 service installation; 4698/4702 task creation/update; 1102 Security audit log cleared; 4104 PowerShell script block logging. Group events do not automatically mean administrator access: examine the actual target group and membership.

Sysmon 1/3/11/22 concern process creation/network connection/file creation/DNS respectively. Event availability depends on installed sensors, configuration, auditing, and forwarding. Event IDs are not globally unique across providers.

To investigate failure followed by success, filter the same account/host/source and sort chronologically; KQL alone does not establish that sequence. Inspect logon type, account domain, caller, and target. Linux SSH/sudo and application logs may only expose message until parsed; inspect the actual schema instead of assuming Windows fields.

## Windows and Linux triage

These local commands are inspection starting points, not automated remediation. Permissions and OS versions affect output. Running tools changes some host state; record collection activity.

### Windows PowerShell

~~~powershell
Get-Date -Format o
Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,ExecutablePath,CommandLine
Get-NetTCPConnection | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess
Get-CimInstance Win32_Service | Select-Object Name,State,StartMode,PathName,StartName
Get-ScheduledTask | Select-Object TaskPath,TaskName,State,Actions
Get-CimInstance -Namespace root/subscription -ClassName __EventFilter
Get-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer
Get-CimInstance -Namespace root/subscription -ClassName ActiveScriptEventConsumer
Get-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding
Get-FileHash -Algorithm SHA256 -LiteralPath 'C:\Path\suspect.exe'
Get-AuthenticodeSignature -LiteralPath 'C:\Path\suspect.exe'
~~~

Match executable identity and launch mechanisms across filenames. PID reuse means a matching PID at a different time may be a different process. A valid signature does not prove benign behavior; an unsigned file is not automatically malware. WMI enumeration shown is not an exhaustive persistence check.

### Linux shell

~~~bash
date -u --iso-8601=seconds
ps auxww
ss -tunap
systemctl list-unit-files --type=service
systemctl list-timers --all
crontab -l
ls -la /etc/cron.d /etc/cron.daily
journalctl --since '2026-10-19 00:00:00' --until '2026-10-20 00:00:00' --utc
sha256sum -- /path/to/suspect
~~~

Replace dates and paths. crontab -l covers the current user's crontab, not every user's. ss process details may need elevated privileges. journalctl applies only where the journal exists and retains the requested interval. Inspect SSH authorized_keys, service unit contents, and other users' scheduled jobs when relevant and allowed. Do not remove a service or key solely because its name is unfamiliar.

## PEStudio malware triage

Analyze a preserved copy on the designated analysis workstation. Static inspection does not intentionally execute the sample, but use an isolated lab and follow event policy. Check tool reputation/lookup settings before opening competition material; do not upload samples or indicators to external services unless permitted.

1. Record original host/path, acquisition time, size, and SHA-256. Hash the copy to confirm identity.
2. Inspect PE architecture, headers, timestamps, version metadata, and signature. Compile timestamps can be forged.
3. Review sections, entropy, entry point, imports, exports, and resources. Packing indicators and unusual sections are leads, not verdicts.
4. Extract strings: domains/IPs, URLs, paths, mutex names, service/task names, registry keys, and commands. Strings can be stale, decoys, or library content.
5. Group imports by possible behavior such as networking, process manipulation, registry modification, or cryptography. Imports suggest capability, not observed behavior; dynamic resolution can hide imports.
6. Pivot verified indicators into Arkime, Velociraptor, and ELK. Search hashes across alternate filenames; inspect parent processes and every known persistence mechanism.
7. State the conclusion and confidence: suspicious characteristics, corroborated activity, remaining unknowns. Escalate to controlled dynamic analysis only when the event permits and the lab is ready.

## Investigation playbooks

### Suspicious download or executable

- Arkime: identify host, request/response metadata where visible, destination, and download interval.
- Endpoint: preserve file identity, process ancestry, command line, user, and persistence evidence.
- ELK: find process/file/DNS events around the interval; build a timeline.
- Validate: downloading a file does not prove it executed. Record the exact execution evidence or mark execution unconfirmed.

### Suspected credential compromise

- ELK: find failed/successful logons, source IPs, logon types, account changes, and privileged group membership.
- Endpoint: inspect sessions, process activity, and changes attributable to the account.
- Arkime: examine related remote access and subsequent communications.
- Validate: separate normal admin access from activity tied to the suspected incident; account for NAT, jump hosts, and clock offsets.

### Persistence investigation

- Record complete service command line, task XML/actions, registry values, or WMI filter/consumer/binding before changes.
- Resolve referenced paths and hash files. Multiple launchers may reference one payload under different names.
- Correlate creation/modification times with logs and process history.
- If remediation is in scope, preserve evidence first, document the approved change, verify required services, and check for recurrence. Observation-only drills may prohibit remediation entirely.

### Suspected beaconing or exfiltration

- Arkime: compare periodicity, destination diversity, direction, duration, and byte counts against a baseline.
- Endpoint: identify the process responsible and relevant local files.
- ELK: correlate DNS, process, file/archive, and authentication activity.
- Validate: updates, backups, monitoring, and legitimate uploads can resemble these patterns. Large traffic alone does not prove data theft; encrypted traffic may prevent content confirmation.

## Evidence and handoffs

Use the reusable templates in [templates](templates). Keep live evidence and answers outside the repository unless the event explicitly permits GitHub storage.

For every finding record: question ID, owner, host/user, time range/timezone, hypothesis, exact query and filters, tool/collection/session IDs, original paths, evidence hashes, observed facts, interpretation, confidence, gaps, and next step. Another teammate should be able to reproduce the answer.

An answer should state the requested fact precisely, identify its supporting evidence, and distinguish initial observation from confirmed earliest activity. Preserve originals; work from copies. Save screenshots with enough context to show host, time, and query without exposing credentials.

## Troubleshooting

- No results: check time window/timezone, data view, host spelling, field name, sensor coverage, retention, permissions, and ingestion delays. Try a known-good event.
- Arkime metadata but no packets: check packet retention, sensor permissions, capture availability, and whether this record originated from a log integration rather than captured sessions.
- Empty endpoint collection: check client online state, last-seen time, OS compatibility, collection errors, parameters, and privileges.
- Unexpected query error: confirm language selection. Arkime expressions, VQL, KQL, Lucene, and Wireshark filters are not interchangeable.
- Contradictory timestamps: compare event vs ingestion time, source clock offset, timezone, process start time, and capture timestamps.

## Official references

Consulted for starter syntax/workflow; documentation changes and the competition may use older versions. Link to references rather than copying entire third-party guides.

- [Malcolm query syntax comparison](https://malcolm.fyi/docs/queries-cheat-sheet.html)
- [Arkime help source](https://github.com/arkime/arkime/blob/main/viewer/vueapp/src/components/help/Help.vue)
- [Arkime FAQ](https://arkime.com/faq)
- [Velociraptor documentation](https://docs.velociraptor.app/docs/)
- [Collecting artifacts](https://docs.velociraptor.app/docs/clients/artifacts/)
- [Artifact Exchange](https://docs.velociraptor.app/exchange/)
- [Offline collections](https://docs.velociraptor.app/docs/deployment/offline_collections/)
- [Evidence of execution](https://docs.velociraptor.app/docs/forensic/evidence_of_execution/)
- [VQL pslist](https://docs.velociraptor.app/vql_reference/popular/pslist/)
- [Elastic KQL reference](https://www.elastic.co/docs/reference/query-languages/kql)
- [Winlogbeat field reference](https://www.elastic.co/docs/reference/beats/winlogbeat/exported-fields-winlog)
- [Microsoft Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [Microsoft Windows security auditing](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/advanced-security-auditing)
- [PEStudio vendor](https://www.winitor.com/)

## Validation record

- Documentation reviewed: 2026-10-20 UTC.
- Competition tool versions: not supplied.
- Target-environment query execution: not performed.
- Sample collection verification: not performed.
- Event-specific rules review: pending supplied rules.

When testing, record tool/version, query, fields present, sample input, expected/actual outcome, tester, and date. A zero-result query is not a successful detection test; include a known matching example and a nonmatching example.
