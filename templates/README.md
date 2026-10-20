# Competition templates

Copy these blank templates into the event-approved working location. Do not commit completed answers, raw evidence, or secrets without permission under the event rules.

## Environment and rules

- Event/date and rules URL/version:
- Rules reviewed by / UTC time:
- Scope: hosts, subnets, accounts, excluded systems:
- Allowed tools, internet, external lookups, AI, collaboration:
- Evidence export/storage rules:
- Remediation permitted? Restrictions:
- Submission format, scoring, penalties, deadline:
- Timezones and measured clock offsets:
- Arkime version / capture coverage / packet retention:
- Velociraptor version / client coverage / privileges:
- ELK version / data views / timestamp fields / schemas:
- Missing logs, sensors, or permissions:
- Team roles and communication channel:

## Finding / question worksheet

- Finding ID / competition question ID:
- Owner / status / priority:
- Requested fact:
- Hypothesis:
- Host / client ID / user / IP:
- Investigation start/end in UTC:
- Original evidence timezone / offset:
- Tool / version / query language:
- Query, time filter, data view, parameters:

~~~text
PASTE EXACT QUERY HERE
~~~

- Session / collection flow / document / event record IDs:
- Observed facts (describe exact field/value):
- Evidence original path and local preserved copy:
- Acquisition method and UTC time:
- Evidence SHA-256:
- Interpretation:
- Confidence and reason:
- Corroborating independent source:
- Gaps / conflicting evidence:
- Proposed answer with required precision:
- Reviewer / verification UTC time:
- Submission status / receipt / next step:

## Timeline CSV header

Save as timeline.csv in the approved evidence workspace. Quote CSV fields containing commas or newlines. Preserve original timestamps alongside normalized UTC; do not invent timestamp precision.

~~~csv
utc_time,original_time,original_timezone,clock_offset_seconds,host,user,source_tool,record_id,action,observed_fact,evidence_path,sha256,analyst,confidence
~~~

## IOC CSV header

Separate observed indicators from candidates. Document where each appeared and what it establishes; an IP shared by legitimate services is not automatically malicious.

~~~csv
indicator_type,value,host,first_seen_utc,last_seen_utc,source_record,evidence_path,context,status,confidence,analyst
~~~

## Evidence manifest CSV header

~~~csv
evidence_id,original_host,original_path,collection_method,collection_id,collected_utc,collector,stored_path,size_bytes,sha256,notes
~~~

Keep originals immutable where practical. Record each copy/transfer and verify hashes; hash integrity does not itself establish provenance or a complete chain of custody.

## Query validation card

- Query ID / purpose:
- Tool / version / language / execution context:
- Required data source, fields, and privileges:
- Exact query and parameters:
- Known matching sample and expected result:
- Actual matching result:
- Known nonmatching sample and expected result:
- Actual nonmatching result:
- Missing-field / unavailable-data behavior:
- Likely benign matches:
- Runtime / resource impact:
- Tested by / UTC date:
- Status: untested / syntax checked / lab tested / event verified:

## Shift handoff

- Outgoing / incoming analyst and UTC time:
- Current question and owner:
- Confirmed facts with evidence IDs:
- Working hypothesis:
- Exact last useful query and time bounds:
- Collections running / results pending:
- Changes made and validation:
- Blockers:
- Next specific check:
- Submission deadline / urgency:

## Remediation record (only when permitted)

- Affected host / service:
- Evidence preserved / hashes:
- Scope/rules authorization:
- Exact intended change:
- Dependencies and required scored services:
- Recovery / rollback approach:
- Actual action / operator / UTC time:
- Post-change checks:
- Recurrence check:
- Outcome / residual risk:
