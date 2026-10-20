# Arkime: network evidence for the timeline

[Start](README.md) · [Timeline schema](TIMELINE.md)

## Before the first query

Use the Arkime Sessions search bar. Set an **absolute** time range and record the UI timezone. Check Help → Fields/autocomplete for available aliases. These expressions are Arkime syntax, not KQL/Lucene. Malcolm-specific Zeek/Suricata fields may be absent.

Choose time bounding deliberately. First/last packet modes filter by a session endpoint; a session-overlap mode, if available, finds sessions spanning the window. A mode requiring both endpoints inside can omit a long session. Database time describes indexing, not incident occurrence. Record the selected mode with every export.

## No known indicator: discover a host to investigate

1. Start in the briefing's interval; confirm sessions exist for company hosts.
2. Use SPI views/graphs to inspect destination IPs/ports, protocol mix, DNS/HTTP hosts, and traffic concentration.
3. Compare a candidate against peer hosts and expected company services. Look for unusual destinations, download-related traffic, repeated outbound sessions, or unexpected remote-access paths.
4. Assign a narrow next check: identify the host at that time and ask the endpoint/log analyst to identify the associated process/activity. Do not label uncommon traffic malicious without corroboration.

## Copyable pivot cards

All examples are **untested in the event**. Replace documentation IPs and domains. Expected result is matching sessions, not a malware verdict. Check field availability before use.

### A-01: all traffic involving the anchor host

Required: IP fields and capture coverage. Use in the absolute incident window.

```text
ip == 192.0.2.10
```

Output: session ID/sensor, first/last packet times, endpoints/ports/protocol, byte counts. Next: select a suspicious session and pass its tuple/time to ELK. Benign matches include all normal host activity. An IP may belong to different hosts over time.

### A-02: candidate destination and outbound connection

```text
ip.src == 192.0.2.10 && ip.dst == 198.51.100.20
ip.src == 192.0.2.10 && port.dst == 443
```

Required: source/destination fields. Output: related session intervals. Next: compare historical process-network events. Source/destination orientation and proxies need verification; port 443 does not itself prove HTTPS or C2.

### A-03: DNS and visible HTTP

```text
ip == 192.0.2.10 && protocols == dns
host.dns == "*example*"
ip == 192.0.2.10 && protocols == http
host.http == "example.com"
http.statuscode >= 400 && http.statuscode < 500
```

Required: parsed protocol metadata and relevant capture. Output: candidate query/host/status fields. Next: examine DNS answers and associated connections at the same time. DNS may be cached or encrypted; HTTP errors may be benign; HTTPS usually hides URLs/bodies/status without decryption. A DNS answer is not a subsequent connection.

### A-04: possible internal remote access

```text
ip.src == 192.0.2.10 && (port.dst == 445 || port.dst == 3389 || port.dst == 22)
```

Required: tuple fields. Output: candidate SMB/RDP/SSH-port sessions. Next: target-host logons and process/service/task activity. Legitimate administration can match; protocol ports do not establish successful login or execution.

## Turn a session into evidence

1. Record exact query, absolute bounds, bounding mode, timezone, sensor, session ID, endpoints, protocol, and first/last timestamps.
2. Open session detail; inspect decoded headers, DNS answers, TLS metadata, and available payload. Document what encryption/capture gaps conceal.
3. For a claimed download or request, locate the actual packet/message timestamp if packet evidence is available. Do not assign the session's first packet to every action in it.
4. Export scoped metadata and, if permitted, PCAP for relevant sessions. Record export scope, original session references, byte counts, acquisition time, and evidence file SHA-256.
5. Add timeline rows for actual observations: DNS query, connection interval, HTTP request/response, or visible transfer. Preserve intervals when exact action time is unavailable.
6. Match to endpoint/log evidence on host identity, protocol, tuple, and overlapping time. Arkime typically lacks executable identity; mark it unknown until corroborated.

## Repeated communications and transfers

For suspected beaconing, compare intervals, jitter, request/response sizes, destinations, and endpoint process context. Keep repeated observations or an evidence-linked interval summary; avoid generating thousands of unreviewed timeline rows. Updates and monitoring can be periodic.

For suspected exfiltration, establish direction, destination, process/context, and any visible content or upload evidence. Bytes sent are not necessarily payload bytes. Large outbound traffic alone cannot prove which files left or that theft occurred.

## When searches fail

Check time zone/bounding, capture retention, sensor vantage, missing protocols/fields, NAT, IPv6, packet loss, and whether a Malcolm record is log-derived. Widen the window in documented steps. Metadata with no PCAP may still support a session observation, but cannot support an unobserved payload claim.

## Timeline contribution checklist

- Host/IP mapping at the event time.
- Session interval plus packet/message time where available.
- Sensor/session ID and export/packet locator.
- Query, bounds, timezone, bounding mode.
- Factual network observation, attribution limits, and next endpoint/log check.

## References

- [Malcolm query comparison](https://malcolm.fyi/docs/queries-cheat-sheet.html)
- [Arkime search help source](https://github.com/arkime/arkime/blob/main/viewer/vueapp/src/components/help/Help.vue)
- [Arkime API and bounding semantics](https://arkime.com/apiv3)
- [Arkime FAQ](https://arkime.com/faq)
