# ELK / Kibana: reconstruct historical activity

[Start](README.md) · [Timeline schema](TIMELINE.md)

## Prepare Discover

Choose the correct data view, **KQL** language, and absolute incident time window. Confirm a known event exists. Inspect a document's raw fields before assuming ECS/Winlogbeat mappings. KQL filters documents; it does not establish an ordered attack sequence.

Add columns for the actual available equivalents of @timestamp, host.name/host.id, user.name, event.code or winlog.event_id, winlog.channel/provider, process/entity/parent IDs, executable/command line, source/destination IPs and ports, and message. Preserve _index/_id, original provider/channel/record ID, and the original timestamp when exporting. UI timestamp rendering may use the browser timezone.

## Query cards

Examples below are **not event-tested**. Replace LAB-WIN11, usernames, GUIDs, domains, and documentation IPs. In each card record the absolute bounds and data view. Expected results are candidate events, not automatic malicious verdicts. If event.code is used instead of winlog.event_id, verify an actual record before substituting.

### E-01 — Establish the anchor host's activity

Required: populated host.name. Start around the known observation; widen in documented increments.

```text
host.name: "LAB-WIN11"
```

Return chronological events and coverage bounds. Next: inspect the strongest candidate and pivot to parent/process/file/network fields. Normal business activity matches. An empty result can mean wrong host mapping, time, data view, or missing forwarding.

### E-02 — Process creation and parent chain

Required: Sysmon Operational events or Security process creation auditing.

```text
host.name: "LAB-WIN11" and winlog.channel: "Microsoft-Windows-Sysmon/Operational" and winlog.event_id: "1"
```

Alternative where Security process creation is collected:

```text
host.name: "LAB-WIN11" and winlog.channel: "Security" and winlog.event_id: "4688"
```

Record creation time, executable, command line, user, process/parent identifiers, hashes if present, and source record ID. For 4688, command-line detail depends on policy; process IDs may be rendered differently from other sources. Convert only after checking format. Normal shell/admin processes are expected.

If raw Sysmon fields exist, follow a known process instance:

```text
host.name: "LAB-WIN11" and winlog.channel: "Microsoft-Windows-Sysmon/Operational" and (winlog.event_data.ProcessGuid: "REPLACE-GUID" or winlog.event_data.ParentProcessGuid: "REPLACE-GUID")
```

Use the event's actual casing and mapped fields. If process.entity_id exists, pivot on it after checking which source generates it. Do not assume a vendor entity ID equals Sysmon's raw GUID. Follow parent creation events backward and child instances forward.

### E-03 — Network, DNS, and files associated with execution

Required: configured Sysmon forwarding; network logging may be disabled.

```text
host.name: "LAB-WIN11" and winlog.channel: "Microsoft-Windows-Sysmon/Operational" and winlog.event_id: ("3" or "11" or "22")
```

Review event-specific fields, process instance, tuple/domain/path, and occurrence time. Next: match network events with Arkime and file/process evidence with the endpoint collection. A file-create event does not by itself supply its content hash or prove execution.

With ECS fields populated, candidate-wide pivots include:

```text
source.ip: "192.0.2.10" or destination.ip: "192.0.2.10"
process.hash.sha256: "REPLACE_WITH_SHA256"
file.hash.sha256: "REPLACE_WITH_SHA256"
dns.question.name: "example.com"
process.name: (powershell.exe or pwsh.exe or cmd.exe)
```

Each depends on its own data source/mapping. A hash query cannot find an unindexed file. Process names, shared IPs, and common domains can produce benign matches. Prefer exact indicators and inspect context.

### E-04 — Persistence and changes

```text
host.name: "LAB-WIN11" and winlog.channel: "System" and winlog.event_id: "7045"
host.name: "LAB-WIN11" and winlog.channel: "Security" and winlog.event_id: ("4698" or "4702")
host.name: "LAB-WIN11" and winlog.channel: "Microsoft-Windows-Sysmon/Operational" and winlog.event_id: ("12" or "13" or "14" or "19" or "20" or "21")
```

Required: matching provider/channel and configured collection. Inspect service binary/account, task XML/actions/principal, registry target/data, and WMI definitions/bindings. Export underlying detail. Installation/registration is not successful execution. Legitimate software installs and management tools commonly match.

### E-05 — Scripts and authentication

```text
host.name: "LAB-WIN11" and winlog.channel: "Microsoft-Windows-PowerShell/Operational" and winlog.event_id: "4104"
winlog.channel: "Security" and winlog.event_id: ("4624" or "4625" or "4648")
winlog.channel: "Security" and winlog.event_id: ("4720" or "4728" or "4732" or "4756")
winlog.channel: "Security" and winlog.event_id: "1102"
```

Required: respective auditing/forwarding. Examine actual script text, user/domain, source, target, logon type/session ID, target group, and caller. Reassemble multipart script records where possible, preserving ordering/IDs. Audit-log clearing or group changes require actor/context review. KQL filtering for failures and success does not prove that one followed the other; sort and correlate the underlying records.

### E-06 — Linux or application logs without ECS fields

Start with one known event and inspect how host, timestamp, program, and message are represented. If host.name/message exist, a starting filter is:

```text
host.name: "LAB-LINUX" and (message: "sshd" or message: "sudo")
```

This is a broad text filter, not a reliable success/failure parser. Confirm raw text, authentication method, account, source, process, and time. Absence may reflect a different dataset/field or missing audit/journal coverage. Use supplied parsed fields when available.

## Event meanings to verify in the source

- Sysmon: 1 process creation; 3 network connection; 11 file create; 12–14 registry activity; 19–21 WMI subscription activity; 22 DNS query. Configuration determines visibility.
- Security: 4688 process creation; 4624/4625 logon success/failure; 4648 explicit credentials attempted; 4698/4702 scheduled task created/updated; 4720 account created; 4728/4732/4756 group membership added; 1102 Security audit log cleared.
- System/Service Control Manager: 7045 service installed.
- PowerShell Operational: 4104 script block logging.

Always include provider/channel context; event IDs are not globally unique. Group membership events do not inherently mean administrator membership. Authentication success does not prove malware execution. Use original event semantics rather than assigning every event an attack label.

## Convert results to the timeline

1. Save the exact query, data view, absolute bounds, language, and timezone.
2. Expand the document; identify occurrence time, ingestion/agent timestamps, event provider/record ID, host identity, and related process/logon IDs.
3. Preserve/export all necessary rows and columns. Check export row limits/truncation and compare counts; do not mistake a visible page for complete results.
4. Add factual occurrence rows with evidence IDs. Keep original time and derived UTC separate.
5. Requery around each key milestone and expand backward/forward. Record earliest/latest observed with the searched coverage bounds.
6. Correlate independent packet/endpoint evidence. The same EVTX record re-exported by Velociraptor remains one source.

## Zero-results / query-error checklist

Check correct language, absolute window/timezone, data view/time field, actual host field, event ID type/mapping, provider/channel, sensor configuration, ingestion delay, retention, privileges, and missing fields. Wildcard behavior depends on mappings/settings; prefer exact values first. Never use no hits as evidence of a clean company without coverage validation.

## References

- [KQL syntax](https://www.elastic.co/docs/reference/query-languages/kql)
- [Winlogbeat fields](https://www.elastic.co/docs/reference/beats/winlogbeat/exported-fields-winlog)
- [ECS event times](https://www.elastic.co/docs/reference/ecs/ecs-event)
- [Microsoft Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [Microsoft Security auditing](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/advanced-security-auditing)
