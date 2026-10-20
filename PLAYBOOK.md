# Investigation playbook: first briefing to final timeline

[Start](README.md) · [Timeline rules](TIMELINE.md) · [ELK](ELK.md) · [Endpoint](VELOCIRAPTOR.md) · [Network](ARKIME.md)

Run this as an iterative investigation. Each phase has a required output; assign unresolved work rather than stalling the whole team. Time budgets below are suggested proportions of available investigation time, not official rules.

## Phase 0 — Establish scope and a common clock

**Goal:** Know what you can investigate and whether the three tools describe the same systems and times. Suggested budget: first 10%.

1. Read the company briefing and questions. Extract named hosts, users, symptoms, approximate onset, business services, and prohibited actions.
2. Identify the operating systems, provided tools, available log sources, network capture boundaries, and retention. Confirm whether evidence is historical, live, or both.
3. In each tool, locate a known host/event. Map hostname, Velociraptor client ID, stable host identifier, IP address, and the interval in which that IP belongs to it. DHCP/NAT/proxies can break simple IP joins.
4. Record UI timezone, source timezone/offset, event time field, source clock health, and earliest/latest available evidence. Different source coverage is a gap, not proof that nothing happened.
5. Copy the [timeline schema](TIMELINE.md) into the event-approved workspace. Also maintain an evidence manifest, host/IOC list, question queue, and investigator-action log.
6. Assign analyst roles and evidence IDs. Use source/time references rather than renaming originals into an imagined sequence.

**Output:** case ID, scope/coverage note, host identity map, clock assumptions, empty timeline, and assigned questions.

## Phase 1 — Find the first useful anchor

**Goal:** Obtain one reproducible suspicious observation. Suggested budget: next 15%.

### If the briefing gives a lead

- **Host or user:** ELK history around the reported interval; endpoint snapshot; Arkime sessions for its IP at that time.
- **IP or domain:** Arkime sessions/DNS → host attribution at the event time → endpoint/process history.
- **File or hash:** endpoint exact path/hash → historical file/process events → related network activity.
- **Alert only:** inspect the underlying event and rule context. Treat its timestamp as detection time until occurrence time is verified.
- **Timestamp only:** search a bounded interval around it, across host/process/auth/network sources. Expand in stages.

### If there is no useful lead

1. ELK analyst checks source inventory and looks for unusual parent/child processes, scripts, execution from user-writable locations, new persistence, authentication anomalies, or visible security alerts. A rarity is a lead, not a verdict.
2. Network analyst uses Arkime SPI views/graphs to compare hosts, protocols, destinations, DNS names, traffic volumes, and repeated connections in the supplied incident interval. Compare candidates with normal company services and peers.
3. Endpoint analyst selects a host tied to a symptom or a network/log lead. Capture processes and connections, then inspect the suspicious process's full path, ancestry, user, hash/signature, and persistence references.
4. If stuck, verify sensors and widen time coverage before inventing broader detections. Create a list of the strongest candidates and assign one check to each. Do not recursively hash or collect every disk as a default.

**Output:** anchor A-001 with original timestamp, host identity, indicator, query/time bounds, raw evidence reference, confidence, and the next cross-tool check. Record the anchor as a source-backed row, even if later judged benign.

## Phase 2 — Preserve the anchor and capture volatile context

**Goal:** Retain the evidence needed to reproduce and extend the lead.

1. Preserve the original event/export, endpoint collection results, and session metadata. Record tool/version, source IDs, exact query, filters, capture boundary, and export time. Hash exported evidence files.
2. On relevant live endpoints, collect process list, command lines/parents, start times, users, connections, and associated executable paths first. Record snapshot time separately from process start time.
3. Acquire the suspicious file/script and relevant persistence definitions through the provided collector. Preserve original location, metadata, acquisition time, hash, and collection/flow ID. Store binaries separately from the repository.
4. Collect relevant historical logs early if rollover is a concern. If memory-only execution/injection is suspected, document the gap and use memory collection only if available, permitted, and within resources. Do not equate a missing disk file with absence of malware.
5. Do not delete or disable the candidate during an analysis-only task. If active damage requires authorized containment, record what was done and when before continuing.

**Output:** evidence manifest entries plus a volatile snapshot. A snapshot collected now does not show what was running hours earlier.

## Phase 3 — Reconstruct backward: arrival and first execution

**Goal:** Explain how the anchor came to exist, without assuming phishing or a download.

1. Start with an absolute window around the anchor (for example ±15 minutes). Use a larger window if the scenario suggests slower activity. Widen backward until the lead is explained or the coverage boundary is reached.
2. Find the candidate process's creation event. Record host, process GUID/entity ID, PID, start time, parent GUID/PID, executable, command line, user/logon context, and event record.
3. Follow the parent backward. A browser, office app, shell, service host, installer, management tool, or remote session suggests different arrival paths; verify the actual chain.
4. Look for file creation/download, archive extraction, script execution, authentication, email/web/application evidence where supplied. A browser request followed by a process event is a possible chain; match path/hash/command and source identity before claiming causation.
5. Arkime analyst locates DNS and transfer sessions before execution. Packet/HTTP-object times, where visible, are more specific than whole-session endpoints. HTTPS without decryption may leave the exact URL or contents unknown.
6. Endpoint analyst corroborates with historical artifacts, target file metadata, and collected logs. Prefetch can support execution; Amcache/Shimcache presence by itself is not execution proof. File timestamps can be changed or describe copying rather than original arrival.
7. Add each supported milestone to the timeline. Label the earliest as **earliest observed within available coverage**, not automatically patient zero or the first compromise.

**Output:** supported arrival/entry hypothesis, first observed execution, parent chain, and explicit gaps. Unknown entry vector is an acceptable result if evidence does not establish it.

## Phase 4 — Reconstruct forward: behavior and persistence

**Goal:** Determine what happened after execution.

1. Follow child process GUIDs/entity IDs; examine commands, dropped files, registry changes, service/task creation, DNS, connections, and security-tool interference if logged.
2. Compare the file's hash across names and paths. A renamed copy may be the same binary; a changed hash may be a different version or file. Do not collapse all similarly named files.
3. Inspect services, task actions/XML, Run/RunOnce/startup entries, and WMI filter/consumer/binding relationships. On Linux check cron, systemd services/timers, startup files, and SSH keys as relevant. Preserve complete definitions.
4. Separate **persistence created**, **persistence currently present**, and **persistence executed**. Each requires different evidence. A current scheduled task alone does not establish its original creation time or a successful run.
5. Analyze the preserved sample using [MALWARE-ANALYSIS.md](MALWARE-ANALYSIS.md). Assign extracted values candidate-IOC status, then validate them in logs/endpoints/traffic.
6. Record observed effects. Imports, strings, reputation, and ATT&CK labels can guide checks; they do not prove capabilities were used or identify a malware family conclusively.

**Output:** process/file/persistence chain, sample summary, observed behavior versus suspected capabilities, and updated timeline rows.

## Phase 5 — Correlate communications and scope the company

**Goal:** Identify related systems/accounts and assess impact. Phases 3–5 usually consume the main 50% of investigation time.

1. Match endpoint/log network events with Arkime on host identity, protocol, source/destination tuple, and overlapping time. Include source port when available. Host IP plus nearby time alone is weak process attribution.
2. Check DNS answers at that time; domains change IPs and IPs host multiple services. Record both the DNS observation and resulting connection separately.
3. For repeated outbound sessions, compare timing, sizes, response patterns, and the responsible process. Keep the timeline description factual until C2 behavior is corroborated.
4. Hunt the confirmed hash, distinctive paths/commands, persistence names/definitions, and validated domains across other logged hosts. Then perform narrowly scoped endpoint collections on matches. Track which hosts were actually covered.
5. Check possible lateral movement: source-to-target remote connections, target logon context, remote service/task/process activity, and matching payload identity. Remote access alone does not prove lateral execution. Investigate legitimate administration as an alternative.
6. Check possible collection/exfiltration: archive/staging commands, relevant file access if logged, upload/request metadata, and network transfer. Large outbound traffic or archive creation alone is not confirmed exfiltration. Report encrypted-content and attribution limits.
7. For each new affected host, repeat backward/forward reconstruction. Classify confirmed compromised, suspicious, no matching evidence in covered sources, or not assessed. Keep these distinct.

**Output:** affected host/account list, source-to-target relationships, evidence-supported impact, IOC sweep results with coverage, and a company-wide timeline.

## Phase 6 — Merge, challenge, and resolve the timeline

**Goal:** Turn multiple evidence streams into one defensible chronology.

1. Apply [TIMELINE.md](TIMELINE.md) clock and schema rules. Preserve raw exports. Sort derived normalized times only after timezone/offset checks.
2. Deduplicate the same original event forwarded through multiple tools. Keep all evidence references on one event rather than counting it as independent corroboration.
3. Review identity joins, process-instance joins, network tuples, timestamp meaning, and uncertainty. Keep overlapping/ambiguous intervals rather than forcing an exact order.
4. Ask of every causal statement: what connects these events besides proximity? Mark unsupported links as hypotheses and assign one resolving check.
5. Challenge the narrative: could this be authorized administration, a shared service, a clock problem, a duplicated event, or an analysis action?
6. Annotate unexplained gaps and coverage boundaries. Add investigator actions as a separate category so they cannot be mistaken for attacker activity.

**Output:** reviewed canonical timeline, evidence IDs, confidence/reasoning, unresolved questions, and a short incident narrative that agrees with the rows.

## Phase 7 — Containment and recovery, only if requested

For an investigation-only drill, produce recommendations and proceed to reporting. Do not change scenario systems simply because this phase exists.

When response actions are in scope: choose host isolation, specific destination blocking, credential/session action, or disabling a verified malicious launcher based on observed behavior and required company services. Preserve evidence when feasible, document authorization and rollback/recovery, timestamp every action, then verify the intended effect. If rebuilding is needed, record that decision rather than claiming deleting one file removes every foothold.

Check required business functionality, recurrence of process/persistence/network indicators, other known affected hosts, and residual visibility gaps. A quiet host immediately after action is not proof of eradication. Report the observation period and remaining uncertainty.

**Output:** action/verification rows or clearly labeled proposed actions, business checks, and residual risk.

## Phase 8 — Final report and competition submission

Reserve the final 25% for review, targeted gap resolution, and reporting.

1. Complete [REPORT-TEMPLATE.md](REPORT-TEMPLATE.md): summary, scope, timeline, execution chain, sample findings, affected systems, impact, response if any, gaps, and evidence index.
2. For each question supply the exact requested field and format: hash algorithm, full path, domain versus IP, account domain, UTC timestamp/precision, or artifact identifier.
3. A second teammate reproduces critical answers from preserved evidence. Verify that the report does not upgrade a candidate into a confirmed claim.
4. State missing data and coverage limits. Malware-family attribution and initial access can remain unresolved while the timeline is useful.
5. Confirm submissions/receipts and deliver files to the approved location. Keep sample binaries separate from the narrative.

**Done means:** each major conclusion is traceable to evidence, the timeline retains time/identity caveats, host scope is documented, and the team can explain what it knows and what it cannot establish.
