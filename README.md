# Malware investigation: 60 minutes

**Find the malware, explain what happened, and build a timeline with evidence.**

Use [QUERIES.md](QUERIES.md) for searches and sample analysis. Fill in [TIMELINE.md](TIMELINE.md) as you work.

![The one-hour plan, including parallel static and dynamic analysis](60-minute-plan.png)

## Who does what?

- **ELK analyst:** find past activity—what ran, when, and what launched it.
- **Endpoint analyst:** use Velociraptor to check processes, files, hashes, and persistence.
- **Network analyst:** use Arkime to check DNS, connections, and transfers.
- **Sample analyst:** inspect the sample, then observe a controlled run in the provided analysis lab.
- **Lead:** maintain the timeline and submit answers. Combine roles to fit your team.

Share **host + time + finding + evidence + next check**. Work in parallel; nobody waits for the whole team to finish a tool.

## Follow the clock

**0–5: Get ready.** Read the briefing/questions. Check scope, timezone, log coverage, allowed actions, and the provided analysis lab. Start the shared timeline.

**5–20: Find a lead.** Start with the supplied clue. Without one, check unusual processes/commands, new tasks/services, and unusual traffic. Share your best lead by minute 15. Check filters or switch leads if stuck.

**20–35: Trace and analyze.** Follow the suspicious file/process backward to arrival and execution, then forward to children, persistence, and connections. At the same time, one analyst does **3–5 minutes of static analysis**, then **5–8 minutes of dynamic observation** in the lab. Start sooner if the sample is ready. Follow the short checklist in QUERIES.md.

**35–45: Check other hosts.** Search confirmed hashes, distinctive commands/paths, persistence entries, and verified destinations. Check the context of every match.

**45–55: Finish the timeline.** Stop broad hunting. Order the evidence, check the important claims, and mark unknowns. Lab results stay separate from company events.

**55–60: Verify and submit.** Check exact paths, users, timestamps, hashes, evidence, and submission receipts.

## What should your story explain?

**Arrival, if known → execution → changes/persistence → communications → other affected hosts → impact.** Leave unsupported stages unknown.

## Four rules to remember

1. Keep evidence and add findings as you go. Collection time is not execution time.
2. Static clues suggest behavior; dynamic tests show lab behavior. Confirm both against company evidence.
3. Run samples only in the designated isolated analysis lab using its procedure. If unavailable, document the limit and continue investigating.
4. A suspicious connection is not automatically C2; a large transfer is not automatically theft.

This guide matches the team's supplied scenario. Tool versions, competition rules, and runtime queries have not been verified. Pictures are instructional diagrams, not screenshots or actual findings. Store live evidence/samples in the event-approved location, outside this repo unless allowed.
