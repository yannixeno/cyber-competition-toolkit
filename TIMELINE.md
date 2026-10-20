# Build the incident timeline from the first observation

[Start](README.md) · [Investigation order](PLAYBOOK.md) · [Report](REPORT-TEMPLATE.md)

The timeline is a derived evidence index, not the original evidence. Keep raw exports unchanged. One owner merges contributions; every analyst preserves the source references needed to reproduce their rows. Use this schema instead of the older minimal header in templates/README.md.

## Three distinct times

- **Occurrence:** when the source says the activity happened. Verify the field's meaning.
- **Observation/collection:** when a sensor or investigator observed or collected it.
- **Ingestion:** when it arrived in the search platform.

Do not substitute collection or ingestion time for occurrence time. In a current process snapshot, process start time and snapshot time are different. A persistence definition observed today may have an unknown creation time.

In ECS, @timestamp ordinarily represents event occurrence; event.created and event.ingested describe later processing stages. Check the actual pipeline and original event because parsing can be wrong. Arkime first/last packet timestamps bound the recorded session; database time is not the time a payload executed. A long session is an interval, not a single packet action.

## Canonical row schema

Store in a shared worksheet, CSV, JSON, or the event's supplied platform. Field names below define a logical schema; they are not assumed to be fields in any tool.

- **timeline_id:** stable team ID, e.g. T-001; IDs do not change when rows are sorted.
- **event_time_utc / event_end_utc:** normalized occurrence time or interval end; leave unknown rather than inventing it.
- **original_time / original_timezone:** exact raw timestamp representation and known offset/zone. Record unknown explicitly.
- **time_basis:** process start, Windows event SystemTime, packet timestamp, file creation metadata, task registration event, collection observation, etc.
- **time_precision / clock_offset_seconds / time_uncertainty:** source precision, measured source-minus-reference offset if known, and uncertainty. Unknown offset is not zero.
- **host_id / hostname / ip_at_event / user:** source identity and the time-bounded host-IP mapping.
- **process_instance / parent_instance:** process GUID/entity ID; if absent, host + PID + process start time with its limitations.
- **action:** factual verb, e.g. process-created, DNS-query, connection-observed, task-registered, investigator-collected.
- **object / sha256 / src_dst_tuple:** relevant path/domain/registry/task/service/hash/network endpoints and protocol.
- **source_tool / source_dataset / source_record_id:** tool, original provider/channel/file, and document/record/session/packet/collection ID.
- **evidence_ids / evidence_locator / evidence_sha256:** references to preserved exports and exact location within them. The export's hash differs from a malware sample's hash.
- **query_and_bounds:** exact query, absolute time window, timezone, index/data view, Arkime bounding mode, or collection parameters.
- **observed_fact / interpretation:** separate what the record says from your explanation.
- **status / confidence_reason / related_ids / analyst / review:** observed, inferred, disputed, or unknown; supporting reason; related timeline IDs; owner; reviewer.

Use one row per meaningful source-backed action. A file, process, or IOC inventory is not a substitute for occurrence rows. Candidate/benign leads can remain in a working timeline, tagged appropriately, without entering the final malicious sequence.

## Normalize without erasing uncertainty

1. Preserve the original timestamp and timezone. Use the date-specific offset; do not assume the current local offset applies to an older incident.
2. Convert known offsets to UTC. Example: 2026-10-19T10:00:00-04:00 becomes 2026-10-19T14:00:00Z.
3. Measure clock offset using a reliable reference when possible. Define offset = source clock minus reference clock. Normalize to reference by **subtracting** that offset after timezone conversion. A clock 120 seconds fast requires subtracting 120 seconds.
4. Record how/when offset was measured and its uncertainty. A present measurement may not establish historical drift; do not silently apply it to all past events.
5. Preserve timestamp precision. Rounded seconds are not millisecond ordering. For equal or overlapping times use source-local event sequence/record IDs where meaningful; Windows record IDs do not establish order across different channels or hosts.
6. Keep unknown timezone/clock values unknown until resolved. Use interval ordering or explicit ambiguity rather than false precision. Do not add a Z suffix to an unconverted local time.
7. If normalization changes later, retain the raw values and note the revision; update derived rows without modifying source evidence.

## Correlate events across tools

### Process identity

Prefer host identity + ProcessGuid or process.entity_id. Inspect parent identifiers and command lines. If only PID is available, constrain to host, start time, and lifetime; PIDs are reused. Do not join yesterday's event to today's live process solely by PID.

### Network identity

Match time overlap + host/IP mapping + protocol + source/destination IPs and ports. Account for NAT/proxies and sensor vantage point. Arkime alone generally cannot name the endpoint executable. Link to a Sysmon/endpoint event or label process attribution unknown.

### File identity

Exact SHA-256 ties identical acquired bytes across filenames. Filename/path alone is weaker. An on-disk file's current hash may not match the bytes that executed earlier; historical process hashes help resolve replacement. Hash equality does not prove both copies executed.

### Independent corroboration and deduplication

The same EVTX record parsed in ELK and Velociraptor is one original source, not two independent observations. Group using host, channel/provider, record ID, occurrence time, and event content; retain both export references. Do not deduplicate different actions merely because they share a timestamp or hash.

### Cause versus proximity

Use parent/child instance links, process-to-network links, file identity, task actions, logon session context, and packet content where available. Timing supports a relationship; timing alone does not establish delivery, execution, C2, lateral movement, or data theft.

## Clearly synthetic worked example

These are invented training observations, not findings from the competition. E-001 etc. illustrate evidence references; they do not refer to real collected files. No actual hash is supplied.

1. **T-001 — 2026-10-19T14:00:00Z:** Arkime packet evidence E-001 shows HOST-A receiving an HTTP object from example.com. Statement: transfer observed. Whether the object became a particular disk file still requires correlation.
2. **T-002 — 14:00:02Z:** Sysmon file-create event E-002 identifies a candidate file on HOST-A and the creating process. Statement: file creation observed; original source time retained.
3. **T-003 — 14:00:05Z:** Sysmon process-create event E-003 records that path, process GUID G-1, parent GUID G-0, user, and a recorded SHA-256. Statement: execution observed. Connect delivery to execution only if the file identity/context supports it.
4. **T-004 — 14:00:08Z:** Task registration evidence E-004 references that path. Statement: task registered. This does not prove the task ran.
5. **T-005 — 14:00:10Z:** Sysmon network event E-005 ties G-1 to a destination tuple; Arkime E-006 captures a matching session. Statement: process-attributed outbound connection observed. Its command-and-control purpose remains unconfirmed without further evidence.
6. **T-006 — 14:20:00Z:** Velociraptor E-007 acquires the current disk file and confirms its SHA-256 matches E-003. Statement: same bytes observed on disk at collection time; 14:20 is not first execution.

A final narrative must preserve those distinctions rather than turning the six rows into an unsupported claim of initial access, successful persistence, and confirmed C2.

## Velociraptor timeline option

If the installed version exposes it, use the Notebooks.Timelines template / timeline UI to combine collected time-series results. Select the real occurrence Timestamp and a useful Message, preserve original fields and collection IDs, and keep components identifiable. Verify that rows were not assigned collection time accidentally. Do not assume ELK/Arkime imports are automatic. The shared worksheet remains a fallback if permissions/version differ.

## Review before submission

- [ ] Original timestamp/zone and occurrence basis retained.
- [ ] UTC normalization and offset signs reviewed; uncertain order marked.
- [ ] First/last seen bounded by actual retention and query coverage.
- [ ] Host/IP/process identity joins supported.
- [ ] Duplicated forwarded events consolidated without losing references.
- [ ] Each major claim links to raw evidence and an exact record/packet location.
- [ ] Current observations do not masquerade as historical creation/execution.
- [ ] Investigator and containment actions identified separately.
- [ ] Narrative, sample report, affected-host list, and submitted answers agree.

## References

- [Elastic event timestamp/sequence fields](https://www.elastic.co/docs/reference/ecs/ecs-event)
- [Arkime time-bounding options](https://arkime.com/apiv3)
- [Velociraptor timelines](https://docs.velociraptor.app/blog/2024/2024-09-12-timelines/)
- [Velociraptor notebook templates](https://docs.velociraptor.app/docs/notebooks/templates/)
