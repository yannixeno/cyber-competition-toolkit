# Velociraptor: endpoint identity, execution, and persistence

[Start](README.md) · [Timeline schema](TIMELINE.md) · [Local command fallback](TOOL-REFERENCE.md)

## Establish collection context

1. Search for the intended client; verify client ID, hostname, OS, last seen, and IP information. Current IP does not automatically establish the historical address.
2. Open the client's collection interface and review existing results before launching more. The exact UI and artifacts vary by version.
3. For each artifact inspect description/source, parameters, required privileges, collection scope, and limits. Run on one relevant host first, inspect errors, then expand only as needed.
4. Record client/flow/collection ID, artifact name/version or definition hash, parameters, collection start/end, and errors. Preserve result exports and acquired-file hashes.

## Collection order for an unidentified-malware host

### 1. Volatile context

Collect current processes with ancestry/command line/start time/user/path, current network connections and owning processes, and logged-on user/session context where available. A live snapshot is time-sensitive; record the observation time separately from each process's start time.

Minimal read-only VQL in a supported **endpoint execution context**:

```sql
SELECT * FROM pslist()
```

Expected: current process rows accessible to that collector. Availability/fields depend on OS, privileges, and version. Running the same plugin in a server context may inspect the server rather than the endpoint. This query does not reconstruct historical processes, detect hidden processes comprehensively, or hash every executable.

### 2. Candidate identity and preservation

Resolve exact paths and command lines, acquire suspicious files/scripts through the approved file collection/VFS mechanism, and record size, SHA-256, source host/path, metadata, acquisition time, and flow ID. Check signatures where applicable. Avoid opening/executing the sample on the business host.

Match the live process to a historical creation event if possible. A current file could have replaced the originally executed bytes; compare historical recorded hashes. A missing file does not exclude memory-only execution or deletion.

### 3. Persistence

Inspect service executable/arguments/account/start mode; scheduled task XML/actions/principal/triggers; Run/RunOnce/startup values; WMI filters, consumers, and bindings. On Linux inspect cron entries, systemd units/timers, relevant startup files, and SSH authorized_keys with their user context.

Preserve each definition. Resolve referenced files and alternate launchers; disabling one launcher would not establish that every launch mechanism is removed. Distinguish definition present now from historical registration and actual execution.

### 4. Historical reconstruction

Collect scoped Windows EVTX/PowerShell logs and execution/file artifacts; on Linux inspect authentication/audit/journal and application logs where provided. Set time and path limits when supported. Do not enable new auditing and expect past history to appear.

Prioritize sources that answer a specific timeline question: process start, file appearance, task registration, service installation, authentication, DNS, or connection. Historical filesystem metadata is a lead with its own timestamp semantics; it is not automatically an execution event.

## Artifact starting points

Check each identifier in the installed catalog; this list does not guarantee availability or identical output fields:

- Windows.Network.Netstat — inspect network connections.
- Windows.System.Services — inspect service configuration.
- Windows.System.TaskScheduler — inspect scheduled tasks.
- Windows.Registry.AppCompatCache — historical application compatibility evidence.
- Windows.System.Amcache — historical program/file evidence.

Search installed artifact descriptions for process listing, EVTX, Prefetch, WMI, autoruns, registry, MFT/USN, Linux logs, and specific acquisition needs. Prefer built-in reviewed artifacts. Do not import an entire community exchange or start a broad hunt without reviewing scope/resource cost.

Artifact availability is one check; correct parameters, target OS, permissions, time coverage, and parser success are separate checks. Unsuccessful or empty collections must be documented.

## Interpreting endpoint evidence

- Process creation logs support execution at the recorded time and identify an instance; PID alone is reusable.
- Prefetch can support execution when present and parsed correctly; its absence is not proof of no execution.
- Amcache/Shimcache entries alone are not conclusive execution proof.
- A file creation/write timestamp may reflect transfer/copy/restoration or manipulation. Preserve its exact meaning and compare with event history.
- A currently configured service/task shows persistence potential; a registration event and execution evidence answer different questions.
- A suspicious signature, path, parent, or hash is a lead to corroborate; it is not a standalone malware verdict.

## Expand to other hosts

1. Use high-specificity validated indicators from the first host/sample: exact hashes, distinctive commands, persistence definitions, or paths plus other context.
2. Check historical logs across hosts, then collect narrowly on candidates. Test the collection on one client before a hunt.
3. Record which clients were online, which completed, failed, or were excluded. No matching result on covered clients is not a fleet-wide clean bill.
4. For each new match, establish its own first/last observed occurrence and process/persistence chain. Do not copy the first host's timeline onto another host.

## Timeline handoff

Return occurrence time and time basis, observation/collection time, host/client ID, process/parent instance, user, path/hash, action, raw record/collection ID, evidence locator, and gaps. If only current-state evidence exists, label the event **observed at collection**, with historical creation time unknown.

## Timeline UI and offline fallback

If available, use Notebooks.Timelines to combine time-series collections with explicit Timestamp/Message fields; retain source components and identifiers. This supplements the canonical timeline and does not automatically correlate all tools.

If remote collection is unavailable, use a tested offline collector only if permitted. Choose OS/artifacts, test on benign data, collect within resource limits, and preserve the container. Do not commit its embedded configuration or keys. Local command fallbacks are in TOOL-REFERENCE.md; document their execution as investigator activity.

## References

- [Collection workflow](https://docs.velociraptor.app/docs/clients/artifacts/)
- [pslist plugin](https://docs.velociraptor.app/vql_reference/popular/pslist/)
- [Artifact Exchange](https://docs.velociraptor.app/exchange/)
- [Evidence of execution](https://docs.velociraptor.app/docs/forensic/evidence_of_execution/)
- [Offline collections](https://docs.velociraptor.app/docs/deployment/offline_collections/)
- [Timelines](https://docs.velociraptor.app/blog/2024/2024-09-12-timelines/)
