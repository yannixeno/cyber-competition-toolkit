# Unidentified Malware Investigation Playbook

**Mission:** A simulated company has unidentified malware. Use **Arkime, Velociraptor, and ELK** to establish what happened, identify affected systems, explain the malware's observed behavior, and deliver an evidence-backed incident timeline.

**The timeline is the central product.** Start it immediately. Every analyst contributes source-backed events throughout the investigation; do not wait until the end to reconstruct the story.

This playbook is tailored to the scenario supplied by the team. It does not predict a specific malware family, operating system, entry vector, or past competition scenario. Historical competition content and event-specific rules have not been verified. Query examples are documentation-informed starting points, not tests against the event's environment.

## Start here during the event

1. **Open [PLAYBOOK.md](PLAYBOOK.md).** Follow phases 0–8 in order; return to earlier phases when a new lead appears.
2. **Create the shared timeline using [TIMELINE.md](TIMELINE.md).** Assign one timeline owner and preserve source timestamps, event IDs, and uncertainty.
3. **Identify the initial lead.** Start with the given host, alert, IP, user, filename, or time. If there is no lead, use the discovery branch in phase 1.
4. **Work three evidence streams:** [ELK history](ELK.md), [Velociraptor endpoints](VELOCIRAPTOR.md), and [Arkime network traffic](ARKIME.md). Exchange concrete pivots, not just screenshots.
5. **Analyze a preserved sample with [MALWARE-ANALYSIS.md](MALWARE-ANALYSIS.md)** when a candidate is found. Feed verified indicators back into the three streams.
6. **Scope every newly discovered host and account.** Repeat the evidence loop until scope and remaining gaps are documented.
7. **Finish with [REPORT-TEMPLATE.md](REPORT-TEMPLATE.md).** Review the timeline and evidence before submitting answers. Containment/recovery is conditional on the scenario's instructions.

## What each analyst returns

- **Lead / timeline owner:** priorities, evidence ledger, clock assumptions, deduplicated timeline, gaps, final review. With a small team, combine roles.
- **ELK analyst:** historical process/file/authentication/persistence events, event and record identifiers, original event times, and relevant surrounding activity.
- **Endpoint analyst:** host-to-client identity, live process/connection snapshot, acquired files and hashes, persistence definitions, historical artifacts, collection IDs and errors.
- **Network analyst:** host identity at the relevant time, session/packet times, DNS and connections, transfers where visible, session IDs and scoped PCAP evidence.
- **Sample analyst, if capacity permits:** exact sample identity, static findings, indicators to hunt, and what is suggested versus observed. This role can sit with endpoint analysis.

Each handoff states **host + UTC interval + indicator + exact evidence reference + requested next check**. Hold brief merges at natural checkpoints; a ten-minute cadence is a starting suggestion, not an event requirement.

## Questions the final timeline should answer

- What is the earliest *observed* related activity, and how far back does coverage extend?
- How did the file or script arrive? What evidence supports an entry vector?
- Was it executed? By which user, parent, process instance, command line, and time?
- What children, dropped files, registry changes, tasks, services, or other persistence followed?
- Which domains/IPs were contacted, when, and by what process where attribution is available?
- Which other hosts/accounts are affected, and what evidence connects them?
- What impact is established: execution only, persistence, access, lateral movement, file changes, or confirmed transfer?
- What remains unknown? What did investigators change, if remediation was permitted?

Not every incident contains every stage. Do not invent missing stages or force events into a presumed attack sequence. A defensible unknown is better than an unsupported answer.

## Use the guide efficiently

- [PLAYBOOK.md](PLAYBOOK.md): start-to-finish investigation and decision points.
- [TIMELINE.md](TIMELINE.md): canonical schema, clock normalization, source correlation, example, and quality checks.
- [ARKIME.md](ARKIME.md): network discovery and packet/session-to-timeline workflow.
- [VELOCIRAPTOR.md](VELOCIRAPTOR.md): endpoint discovery, collection priorities, artifacts, and historical evidence.
- [ELK.md](ELK.md): query cards, event interpretation, process ancestry, and historical reconstruction.
- [MALWARE-ANALYSIS.md](MALWARE-ANALYSIS.md): PEStudio/static analysis and evidence-driven pivot loop.
- [REPORT-TEMPLATE.md](REPORT-TEMPLATE.md): final incident report and submission checklist.
- [templates/README.md](templates/README.md): existing environment, finding, IOC, evidence, validation, and handoff forms. Use **TIMELINE.md as the canonical timeline schema**; the old minimal CSV header is superseded.
- [TOOL-REFERENCE.md](TOOL-REFERENCE.md): preserved original cheat sheet and local Windows/Linux inspection commands. The new playbook takes precedence for investigation order and timeline handling.

## Before collecting

Confirm scope, allowed tools/exports, outside lookups/AI, evidence storage, submission format, and whether remediation is allowed. Keep live evidence, sample binaries, secrets, and completed answers in the event-approved workspace, outside GitHub unless expressly allowed. Existing ignore rules reduce accidental additions but do not prevent forced adds or remove tracked content.

Prefer provided tooling. Preserve evidence before changes when feasible. Active destructive behavior may require immediate authorized containment; record the decision and evidence lost. Do not reboot, kill suspected processes, disable services, or execute a sample simply to see what happens.

## Validation and limitations

- Updated for the team's unidentified-malware and timeline-building scenario: **2026-10-20 UTC**.
- Official documentation is linked in the individual guides; field names and artifact availability must be checked locally.
- No event environment, live sample, log bundle, or tool versions were supplied. Runtime detections and collection success are **not verified**.
- No extra deployment, paid services, or external analysis platforms are required by this playbook.
- Download/clone a local copy before the competition and rehearse using benign lab data.
