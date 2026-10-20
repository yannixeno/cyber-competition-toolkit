# One shared timeline

[60-minute plan](README.md) · [Quick searches](QUERIES.md)

Start immediately. Pick one person to merge/review rows. Everyone contributes findings with evidence as they investigate. Keep raw exports in the event-approved evidence location.

## Copy these five columns

| Time (UTC) | Host | What happened | Evidence | Notes |
|---|---|---|---|---|
| | | | | |

**Evidence:** record the tool, event/session/collection ID, saved export, and exact record/packet location. A screenshot can help, but keep the underlying record where available.

**Notes:** original timestamp/timezone, important path/hash/user/process ID, uncertainty, or the next check. If timezone/clock is unknown, leave UTC unresolved and retain the raw time here. Do not pretend a local timestamp is UTC.

## Invented example — not competition findings

| Time (UTC) | Host | What happened | Evidence | Notes |
|---|---|---|---|---|
| 14:00:05 | HOST-A | Candidate executable started | ELK: saved process event E-01 | Full date: 2026-10-19; original time had Z; record path, parent GUID and hash |
| 14:00:08 | HOST-A | Task registered referencing that path | ELK: saved task event E-02 | Registration observed; task execution not confirmed |
| 14:00:10–14:00:12 | HOST-A | Outbound connection observed | Arkime: session E-03 | Destination/ports recorded; purpose and process attribution not yet confirmed |

Use **full dates and times** in real rows: 2026-10-19T14:00:05Z. Use start/end times for intervals.

## Write facts in plain language

Good: “Process started from this path under this user.”

Too strong without more evidence: “The attacker stole credentials.”

Strings/imports in PEStudio suggest things to check; they are not company events. Keep sample-analysis notes separately and add only observed incident activity to this timeline. Label investigator/response actions clearly if included.

## Before submitting

- Sort by occurrence time, not collection/ingestion time.
- Check timezone/clock differences; mark uncertain ordering.
- Merge duplicate copies of the same original event; keep both references.
- Connect events using process identity, file hash, or network tuple/time—not nearby timestamps alone.
- Say “earliest observed” when earlier history is missing.
- Match each important claim to evidence. Mark unknowns.

**At minute 45:** stop broad hunting and finish the story. **At minute 55:** verify answers and submit.

This five-column format replaces the earlier large timeline schema for the one-hour event. Keep extra source detail in exports and notes rather than adding more required columns.
