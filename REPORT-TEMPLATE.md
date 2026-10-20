# Incident report — blank submission template

Copy to the event-approved workspace. This is a blank structure, not a report of an actual incident. Use [TIMELINE.md](TIMELINE.md) for the canonical row schema and [templates/README.md](templates/README.md) for supporting forms.

## Case details

- Case / simulated company / event:
- Team / authors / reviewer:
- Investigation and evidence coverage intervals:
- Report date/time and version:
- Scope / permitted actions / rules reference:
- Tools/versions and unavailable sources:

## Executive summary

State what is confirmed, affected systems, observed impact, current status, and the most important uncertainty. Avoid naming a malware family unless attribution is supported. Distinguish observed compromise from suspected hosts.

## Key findings

For each: finding ID, factual conclusion, affected host/user, occurrence time or interval, confidence/reason, timeline IDs, and evidence IDs. Keep candidate indicators out of confirmed findings unless clearly labeled.

## Incident timeline

Attach the canonical normalized timeline and raw-evidence index. Summarize these milestones where evidence supports them:

1. Earliest observed related activity, with retention/query coverage boundaries.
2. Arrival/entry evidence and alternatives; unknown if unestablished.
3. First observed execution and complete process/parent context.
4. Observed file changes, children, persistence registration and execution.
5. DNS/communications and process attribution where supported.
6. Scope expansion, other hosts/accounts, and evidence of any lateral movement.
7. Confirmed impact; distinguish collection/staging/transfer from confirmed exfiltration.
8. Investigator actions and authorized containment/recovery, if any.

For each milestone include normalized UTC, original time/zone, exact time basis, confidence, source locator, and evidence references. Preserve ambiguous order instead of forcing a sequence.

## Execution and persistence chain

- Host identity and historical IP mapping:
- User/domain/logon context:
- Parent and child process instance IDs, paths, commands, hashes:
- Service/task/registry/WMI or Linux persistence definition:
- Registration evidence versus observed current state versus execution:
- What is established and what remains inferred:

## Malware analysis

- Sample ID, original host/path, type/size/SHA-256:
- Acquisition method/time and evidence integrity:
- Static findings and candidate indicators:
- Observed behavior linked to timeline evidence:
- Family attribution, if supported, and rationale:
- Dynamic analysis performed? If so, separate lab observations:
- Limitations:

## Scope and impact

List each host/account with classification: confirmed affected, suspicious, no matching evidence within checked coverage, or unassessed. State which tools/sources/time intervals were checked. Explain confidence in cross-host links and the evidence supporting any access, movement, damage, or transfer claim.

## Response and recovery

If not authorized/performed, label this section **recommendations only**. Otherwise include exact action, operator, authorization, UTC time, evidence preserved, business checks, recurrence checks, observation period, and residual risk. Do not equate one deleted file or quiet connection window with full eradication.

## Gaps and alternative explanations

- Missing sensors/logs/packets, retention limits, parse/collection failures:
- Clock uncertainty, unknown timezone, NAT/DHCP/proxy identity issues:
- Conflicting timestamps/records and resolution:
- Claims not established, plausible alternatives, and the next resolving check:

## Evidence index

For every cited item: evidence ID, original source/host/path, source record or packet locator, collection/export parameters and bounds, acquired UTC time, collector, preserved location, size, and SHA-256 of the evidence file. Keep samples separate from report attachments unless specifically required.

## Competition answers

For each question: question ID, exact answer/format, timezone/hash algorithm/full-path requirements, supporting timeline/evidence IDs, reviewer, submission status/receipt, and any qualification the format allows. Do not silently invent precision to satisfy an input format.

## Final review

- [ ] Timeline and narrative describe the same sequence and scope.
- [ ] Critical answers reproduced by another teammate.
- [ ] Occurrence, collection, ingestion, and lab-analysis times kept distinct.
- [ ] Candidate capabilities and family attribution not overstated.
- [ ] Duplicate forwarded records not counted as independent sources.
- [ ] Every major conclusion has a preserved evidence locator.
- [ ] Missing stages and visibility limits stated plainly.
- [ ] Event-approved submission location/format and receipts checked.
