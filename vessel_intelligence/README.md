# Vessel Network Intelligence

An offline Python + tshark + SQLite analyzer and interactive localhost dashboard. All charts, styles, table controls and graph code are bundled. No CDN, cloud service or Internet connection is used for analysis. MarineTraffic links are optional external lookups.

## Version 2: continuous captures and satellite integration

Double-click **Start Dashboard.cmd**, select the Windows input directory, and keep the console open. This is a local long-running process, not an installed Windows service. Ctrl+C stops it; reopening resumes the persistent registry. No production watch folder has been selected on your behalf.

- Supports `.pcap`, `.pcapng` and `.done`, case-insensitively, through one complete pipeline. The original is never renamed or converted. A `.done` name is not proof of completion.
- Polls every 5 seconds and waits for unchanged size and modification time for 30 seconds. Validates with a TShark read and a full capinfos traversal, then hashes with bounded buffers. Size/mtime changes during processing invalidate that attempt. A producer that pauses longer than the stability interval can still resume later: configure a longer interval or have the producer finish files before publishing them.
- Registry states: WAITING_FOR_FILE, VALIDATING, QUEUED, PROCESSING, COMPLETED, FAILED, DUPLICATE and SUPERSEDED. One worker processes files sequentially; arrivals during a scan are discovered on the next queue cycle. Invalid files do not stop later files. Identical SHA-256 content is not analyzed twice, even under another extension. Modified files become new revisions; interrupted work is retried after restart. Completed old revisions remain historical evidence.
- Capture Files refreshes every five seconds, with extension/status filters and links into each completed analysis. The registry stores original path/name, extension, detected format, encapsulation, bytes, mtime, SHA-256, parser version, status, progress/error and capture timing/counts.
- Historical candidate profiles join matching NAS/site and namespace evidence across captures. Accounting identifiers give cross-file session candidates with source-specific IP windows and frames. **They do not merge packet streams or extend assignments across capture gaps.** Non-identical overlapping captures are not packet-deduplicated; historical totals are observed sums, not billing figures. Single-capture identities can be Low confidence even when their grouping key matches across files.

```powershell
python watcher.py "D:\PCAP_DATA" --out "D:\vessel-results" --stable-seconds 30 --poll-seconds 5
python server.py --registry "D:\vessel-results\registry.sqlite" --port 8768
```

Use `--recursive` to include subfolders. `--once` runs one discovery/queue cycle for diagnostics. Select an output directory outside the incoming folder. The source path must remain available for isolated packet export; reports and database metadata can be viewed without it.

### Satellite evidence and packet diagnostics

The integrated output for the supplied source is `integrated_capture/`; `analyzed_capture/` remains the earlier strict-RADIUS baseline. Satellite custom JSON and packet comments are read from the original PCAPNG, including files named `.done`. Exact section + communication-session + stream identifiers link RADIUS packets to terminal metadata, then to other explicitly annotated packets. Conflicting terminal IDs, stream start times or vessel candidates cause that key to be excluded. Packet time must be at or after the recorded stream start. This producer's metadata timestamps are epoch microseconds; other scales remain unsupported rather than guessed. Unsupported custom block indexing disables satellite joins while the standard TShark pipeline continues.

Satellite traffic has **Medium terminal-bearer candidate attribution**, not subscriber attribution. Negative session IDs refer to `satellite_mapping`, never RADIUS accounting sessions. Each packet carries its own annotation; no time-only continuity is invented. Opposite-direction stream keys remain separate unless directly evidenced; a missing downlink mapping can produce zero attributed download without implying no download occurred. DNS inference remains scoped to the same assignment or satellite mapping. Terminal positions are raw telemetry observations, not MarineTraffic positions or independently verified vessel locations. Satellite name remains Unknown unless a corresponding parent record supplies it.

Packet Diagnostics retains TShark TCP retransmission/lost-segment/out-of-order flags and RTP sequence gaps, duplicates and reordering/restart indications. **None proves network packet loss**: capture drops, truncated visibility and sender restart can produce similar observations. No unsupported loss percentage, RF fault, congestion cause, MOS score or satellite impairment is invented. STUN/TURN and other detectable protocols appear in protocol/packet metadata; this release does not reconstruct every protocol's full application state machine.

Packet evidence includes original filename, frame and source hash. Export Satellite evidence JSON for the raw custom metadata and RADIUS linkage. Isolated captures contain selected packet blocks plus RADIUS; noncopy satellite custom blocks are preserved in the original and JSON sidecar, not copied into a newly derived capture. Source frame numbers in evidence are authoritative; exported captures get new reader frame numbers.

The offline HTML snapshot includes first 500 rows per table and session/satellite mapping evidence. The local server provides full pagination and CSV exports. MarineTraffic remains an optional operator-verified external panel.

## Start with the supplied capture

Double-click **Start Dashboard.cmd** in the parent directory. Keep its console open while using the dashboard. Select a vessel/site candidate, then open RADIUS Sessions, IP Assignment Windows or RADIUS Identities. Click a row for raw attributes, original frame references and correlation reasons.

The generated `integrated_capture/report.html` opens directly without a Python server. It includes the first 500 rows per table per vessel and up to 100 sessions of raw evidence per candidate. For large datasets, use the launcher for full pagination, global search, uncapped CSV downloads and isolated PCAP export. The dashboard always labels snapshot limits. Snapshot CSV exports cover the embedded rows only; server CSV exports cover every matching row.

## Requirements

- Python 3.11 or newer (3.12 tested).
- Wireshark with `tshark` and `capinfos` installed, either on PATH or in `C:\Program Files\Wireshark`.
- Optional `python -m pip install -r requirements.txt` enables structured X.509 certificate decoding. Without cryptography, raw certificate bytes and visible SAN metadata remain available; CN and issuer stay Unknown.
- Sufficient free disk for the SQLite database and RADIUS PDML. The original PCAP is read-only. No packet list is loaded into RAM. SQLite uses a 32 MB page cache and disk-backed temporary work; tshark maintains its own dissector/stream state, which can grow on high-flow captures.

## Analyze another PCAP

Double-click **Analyze New Capture.cmd** to select a local capture, or from this source directory:

```powershell
python core.py "D:\captures\capture.pcapng" --out "D:\analysis\capture-01"
python server.py "D:\analysis\capture-01\analysis.sqlite" --port 8765
```

Open `http://127.0.0.1:8765`. The server binds only to loopback and serves read-only APIs. The analyzer rejects an existing output database to avoid overwriting results. Each new capture needs a new output directory. Logs report stage, processed packets, percentage, current detected protocol, RADIUS sessions, identity candidates, assigned IP count and elapsed time. The RADIUS pass may take time before a match is encountered.

For keys that you are authorized to use, add `--keylog "D:\keys\sslkeys.log"`. No TLS decryption is attempted without this argument. QUIC Initial dissection follows tshark's ordinary publicly derivable Initial handshake decoding.

## Correlation policy

1. Extract all RADIUS packets to streamed PDML. Keep every RADIUS field's name, displayed value, raw hex, offset and length, including vendor-specific and unknown attributes. Hash the original capture with SHA-256. Packet timestamps remain exact integer nanoseconds in SQLite, with original timestamp strings in packet raw fields. The UI displays UTC to milliseconds; CSV/database values retain nanoseconds.
2. Group probable site identities by the exact NAS-Identifier, NAS-IP and encapsulating endpoint pair. Agreement between Called-Station-Id and NAS-Identifier earns Medium confidence in a probable site/vessel label. This is not proof of a registered physical vessel. Different users at the same site do not become different vessels. An account without site evidence stays an unresolved Low-confidence identity. IMO/MMSI candidates require explicit labels; IMO checksum is validated. No unlabelled numeric account is treated as MMSI/IMO.
3. Scope accounting sessions by site, NAS, tunnel namespace, Acct-Session-Id, username and Calling-Station-Id. Split on session-ID reuse, accounting uptime rollback, new Start, prior Stop or observed NAS On/Off. Link RADIUS responses only through tshark's request-frame relationship and matching endpoints/context. Authentication records without a supported accounting interval are retained but do not authorize IP attribution.
4. Create **strict observed assignment windows**: first to last accounting observation of the same address within a session. An IP change ends the previous run at its last observation; the intervening gap stays unassigned. A single interim record is a point observation and authorizes no extrapolated interval. Start/Stop times and uptime-derived estimated session start are separate columns. Accounting delay corrects event time while capture time and raw Event-Timestamp remain unchanged. Uptime alone is not evidence that an address was assigned for the whole prior session.
5. Match the innermost IPv4/IPv6 header plus time and the exact encapsulation namespace. Decode Framed-IPv6-Prefix and Interface-Id where present. Prefix-based relationships are assignment evidence, not proof of an individual host. Overlapping sessions claiming an address in one namespace are excluded as ambiguous, even when their site label agrees. Private addresses in different tunnels are not interchangeable. Bare and tunneled observations are not silently joined.
6. **No inferred NAT translation.** A tunnel's outer source is not automatically assigned to a vessel's client. If the framed client address is not visible in packet headers, carrier traffic remains unattributed. Hidden-host direction stays unknown. Upload/download mean from/to the observed assigned IP. Internal means both observed endpoints map to the same site; each internal frame is counted once for that site. Traffic between two identified sites can appear once in each site's profile, so site totals are not a globally deduplicated sum.
7. Scan all packets once for application metadata and attribution after constructing all site mappings. Store only attributable packet rows, plus global protocol counts and assignment-address visibility counts. Raw full packet contents stay in the original capture. All detected protocols are discovered from tshark's protocol stack, not restricted to a fixed list. Primary application bins are mutually exclusive; complete stacks remain in raw rows. Tunnels/outer transports are not counted as client applications.
8. Use session-scoped tshark streams for flows. QUIC connection numbers can join migrations within a RADIUS session; a unique already-observed QUIC association can carry over to subsequent packets on its UDP stream. CIDs remain available as evidence. Unrecognized traffic before the Initial or across a new RADIUS session is not retroactively inferred. QUIC streams with ambiguous connection associations do not use a guessed alias.
9. DNS-based flow relationships require a single-question successful response, tshark's matching query reference, both frames attributed to the same subscriber session, a response before connection start and an unexpired minimum response TTL. Multi-question, failed, unsolicited or unmatched responses remain raw DNS observations. Conflicting DNS names without SNI/Host remain ambiguous. DNS query counts count unique query frames.
10. Service labels use bounded domain suffix rules, HTTP authorities, TLS SNI or structurally visible certificate names. No geolocation, reverse lookup, IP owner or cloud ASN implies an application. DNS plus SNI agreement is High service confidence; single hostname/certificate or DNS-only evidence is Medium. Identity confidence and network/service confidence are distinct. Byte totals are assigned at **connection level**; they do not identify individual encrypted HTTP/2 or HTTP/3 requests on multiplexed connections. Mixed observed service identities stay mixed.

## What the interface includes

- Searchable candidate selector, complete accounting identities and session/IP timelines.
- Identity evidence, observed address list, KPIs and separate external-record panel.
- Packet and byte protocol distribution, connection/domain/destination/service tables.
- DNS, TLS, ALPN, certificate and QUIC metadata where visible.
- Clickable traffic timeline, communication graph and usage charts (10-second bins, hourly totals, session usage, direction, domains, services, destinations and protocols).
- Search by account, station, session, IP, port, domain, protocol and service. Filters apply to columns present in the current table. Sorting is explicitly for the displayed page.
- Packet/session/flow drill-down. Flow evidence API includes a paginated packet list with `offset` and total count; correlated traffic CSV provides all supporting rows. Unknown/unattributed capture traffic is not exposed as vessel activity.
- Streaming CSVs and isolated original PCAP/PCAPNG export with supporting RADIUS requests/responses. Only Section/Interface metadata is copied; unrelated secrets/name resolution blocks are excluded. Exported capture frame numbers are renumbered by readers; the traffic/identity CSV preserves original source frame numbers. Export isolation reads the source once, retaining selected packet blocks unchanged. Wireshark-visible custom blocks participate in source frame numbering; unfamiliar record types cause an export error rather than uncertain frame selection.

## Export / rebuild / external enrichment

```powershell
python manage.py "D:\analysis\capture-01\analysis.sqlite" export --vessel 1 --directory "D:\analysis\vessel-1"
python manage.py "D:\analysis\capture-01\analysis.sqlite" report
python manage.py "D:\analysis\capture-01\analysis.sqlite" external --vessel 1 --json verified-vessel.json
```

Copy `external.example.json`, fill only verified fields and provide the actual MarineTraffic URL, verification time and match evidence. This command only changes the `external` table and rebuilds the report. It cannot change observed names, sessions, IP windows or network totals. The application never scrapes around a login or access restriction; unverified matches remain Unknown. External photos are source links, not downloaded or silently embedded.

## Data model and auditing

`vessels`, `radius`, `sessions`, `assignments`, `packets`, `links`, `flows`, `dns`, `tls`, `audit`, `capture_protocols`, `address_visibility`, `external`, `meta`.

Raw facts live in `radius.raw` and `packets.raw`; derived links carry reasons/confidence and point back to assignments and frames. RADIUS counters combine Gigawords and Octets; displayed totals are cumulative NAS observations, and deltas are emitted only for non-decreasing counters with at least two observations. Counter resets yield Unknown delta. They are not substituted for captured traffic bytes. Packet byte totals include headers and tunnel overhead and are not unique payload/billing volume; duplicate capture interfaces are not heuristically deduplicated. Original `frame.cap_len` and `frame.len` are both retained for truncated captures.

The dashboard is an analysis aid, not a proof that a NAS hostname is a registered vessel. A single 82-second capture can be insufficient to map the traffic of an identified site. Supply adjacent accounting captures and authenticated NAT/topology evidence for further investigation; this version deliberately has no unchecked manual IP-mapping override.

## Validation

```powershell
python -m unittest -v test_core
```

Tests cover strict boundaries, missing Start/Stop, dynamic-IP gaps, same-IP overlapping sessions, tunnel namespaces, NAS reboot, multiple users/site, session-ID reuse, DNS TTL and query linkage, DNS/SNI agreement, suffix spoofing, mixed IPv4/IPv6 encapsulation, QUIC stream/session separation, byte-exact isolated export, and a generated PCAP passed through real tshark.

## References

- [tshark manual](https://www.wireshark.org/docs/man-pages/tshark) — field extraction and protocol dissection.
- [MarineTraffic vessel search](https://support.marinetraffic.com/en/articles/9552755-search-for-vessels) — operator search by name, IMO and MMSI.

The synthetic tests contain invented **test fixtures only**, never mixed into the supplied capture's database or report.


## Content reconstruction

Open the **Content Reconstruction** tab in the local dashboard. Select Image, Video, HTTP, Email, SMS, Ports 5002/5003 or Attachment. Inspect an item for original frames, timestamps, raw metadata, SHA-256 and downloadable bytes. Images preview locally; supported complete video objects can play locally. Email is downloadable as `.eml`, with MIME attachments recovered separately. HTTP text is escaped and downloaded content cannot execute as dashboard HTML.

The default scope requires every contributing frame to share the same vessel/session mapping. **Whole capture** explicitly includes unattributed evidence; it does not establish vessel ownership. Recoverable content is an exposure candidate, not proof of an unauthorized leak.

Ports 5002/5003 are inspected as possible custom SMS feeds. Only structurally valid complete SMPP submit/deliver PDUs or native SMS dissector evidence receive an SMS label. Unknown vendor payloads remain raw evidence until their schema is known. Multipart SMS segments are not combined. Encrypted content requires valid supplied session keys. HTTP range fragments are not claimed as full videos; HTTP/2 and HTTP/3 body reconstruction and cross-capture media/transport stitching are not implemented.

Recovery uses a streamed TShark pass with limits of 32 MiB per object, 1 GiB stored content per capture and 25,000 artifact records. Limits and decoder failures are shown as partial results. Earlier completed captures are upgraded by the background reconstruction worker; new analyses include recovery automatically. To retry partial recovery manually, run `python reconstruction.py PATH_TO_ANALYSIS_SQLITE`. The standalone HTML snapshot points to the local launcher for content browsing; content bytes are stored beside the database, not embedded in HTML. Content-page metadata exports as JSON.

Use Start Dashboard.cmd and select the input folder on the destination machine. The watcher preserves original captures.
