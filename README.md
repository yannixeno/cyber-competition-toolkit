# Find the malware. Build the timeline. 60 minutes.

**Scenario:** A simulated company has unidentified malware. Your job is to explain what happened using Arkime, Velociraptor, and ELK.

**Use just three files:** this plan, [QUERIES.md](QUERIES.md), and [TIMELINE.md](TIMELINE.md). The older documents are optional reference; you do not need to read them during the hour.

## Split the work

- **ELK:** find when things happened and what launched what.
- **Velociraptor:** check the affected host, processes, files, and persistence.
- **Arkime:** find related DNS, connections, and transfers.
- **Lead:** keep the timeline, assign the next checks, and submit. Combine roles for a smaller team.

Everyone shares: **host + time + finding + evidence + next check**. Add findings as you go. Do not save timeline writing for the end.

## 0–5 minutes: get oriented

Read the briefing and questions. Note the supplied host, user, IP, file, or time. Confirm scope, timezone, available logs, and whether changes are allowed. Start the shared timeline and open the three tools.

## 5–20 minutes: get one solid lead

Start with the supplied clue. If none is given:

- ELK: check process activity around the reported incident. Look for unusual parents/commands or new services/tasks.
- Arkime: look for a company host with unusual destinations, downloads, or repeated connections.
- Velociraptor: inspect the strongest candidate host's processes and connections; get the full path, command line, and hash of a suspicious file.

**By minute 15, share your strongest lead.** If stuck, check time filters and missing data, then switch to another lead. Do not spend the whole hour in one search.

## 20–35 minutes: trace backward and forward

For the suspicious process/file, answer:

1. How did it arrive, if the evidence shows that?
2. When did it run, what launched it, and under which user?
3. What did it create or change? What lets it restart?
4. What did it contact afterward?

Use ELK for history, Velociraptor for host evidence, and Arkime for traffic. Preserve relevant exports/sample hashes. If PEStudio is provided, quickly check the preserved sample for useful strings/imports and test those leads in the other tools. Do not get stuck chasing a malware-family name or executing the sample.

## 35–45 minutes: check the rest of the company

Search other hosts for the confirmed hash, distinctive command/path, persistence entry, and verified destination. Check each match's context. Add affected hosts and their own event times to the timeline. Record coverage gaps.

## 45–55 minutes: finish the story

Stop broad hunting. Sort the timeline in UTC, remove duplicate copies of the same event, and check the evidence for each important claim. Resolve only gaps that change an answer. Mark unknowns clearly.

## 55–60 minutes: verify and submit

One teammate checks the exact answers against evidence; another submits. Check timestamp format, full paths, usernames, hash algorithm, and submission receipts.

**Final story:** earliest observed activity → arrival if known → execution → changes/persistence → communications → other affected hosts → impact and unknowns. Include only stages supported by evidence.

## Keep these distinctions straight

- Collection time is not execution time. Keep original timestamps; convert to UTC only when the timezone is known.
- A suspicious connection is not automatically C2. A large upload is not automatically data theft.
- A task present now does not prove when it was created or that it ran.
- Preserve evidence. Change systems only when the scenario allows/requires it; record any actions.

Query examples need local field/version checks. This is a practical sprint plan, not verified competition rules or a prediction of the malware.
