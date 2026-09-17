# Satellite Intelligence 3.0

Satellite Intelligence is the new application name. Existing vessel identities, RADIUS sessions, attribution rules, reconstruction, exports and databases are retained. The repository name remains `vessel-network-intelligence` so existing links keep working.

## Open the application

Run **Start Dashboard.cmd**, select the input folder, and open a completed capture from the Capture Files page. This now opens the Satellite Intelligence workspace. Existing vessel URLs (`/?capture=...`) continue to work. The new workspace is `/intelligence?capture=...`.

The first overview shows capture totals, explicit satellite names and vessel/site candidates. Select a satellite for its subnetworks, bands, spots, terminal IDs, communication sessions, raw positions and evidence. The JSON export includes original frame references. Orbital slot, NORAD ID and independently verified operator remain Unknown when unsupported.

**Unresolved satellite** is a coverage bucket, not an invented spacecraft. Streams whose section/communication-session has no unambiguous satellite-name definition go there. Explicit parent joins never use the filename, a shared terminal ID or a NAS name as a substitute for a satellite identity. Satellite traffic charts currently cover existing unambiguous vessel/terminal frame mappings, not every packet in the satellite capture. The UI states that coverage beside the totals.

## Integration with “Diagnose satellite telemetry tab”

The actual Python dashboard from that task is bundled as `vessel_intelligence/legacy_dashboard.py`. Its complete 16-tab interface is retained, with new branding and a capture-path startup argument. The new web workspace opens it through **Advanced desktop tools → Open full Python dashboard for this capture**. It opens on the machine running the local server; click Analyze in that window. It runs its own capture-level analysis and does not inherit the current vessel selection.

| Function | Browser workspace | Original desktop workspace |
|---|---|---|
| Satellite telemetry and profiles | New named/unresolved satellite profiles, raw records, mapped charts and exports | Dynamic custom-block field table and original extraction fallbacks |
| Vessel profiles / RADIUS | Existing conservative vessel dashboard retained | Original RADIUS packet view |
| Protocols, DNS, TLS, sessions | Existing vessel dashboard plus capture overview | Original whole-capture views |
| Upload behavior | Existing mapped flow bytes and evidence | Original logical-session, burst and upload analysis |
| HTTP / files / images / video / email | Existing Content Reconstruction with vessel/capture scopes | Original HTTP and file workflows |
| STUN/TURN | Searchable decoded packet evidence, transaction IDs and response fields where supplied by TShark | Original transaction grouping and drill-down |
| SS7 / Diameter / GTP | Decoded signaling packet evidence | Original SS7 signaling views |
| Subscriber / SMS | Observed subscriber fields; original content reconstruction still validates custom-port SMPP | Original subscriber/SMS workflows |
| SIP/RTP/RTCP | Decoded protocol evidence and scoped static G.711 playback | Original SIP/SDP correlation, dynamic-codec and audio export tools |
| CCTV / RTSP | RTSP evidence; RTP alone is not classified as a camera | Original RTSP and supported video extraction workflows |
| Raw data and exports | Raw fields in every drill-down and JSON page exports | Original Raw Data tab, copy row/cell and visible CSV export |

Not every original desktop workflow has been rewritten as browser controls. The bundled desktop workspace provides full access to those specialist functions. Its heuristic labels are analyst leads and must not override the stricter vessel correlation. Pillow and matplotlib are optional for richer desktop previews/charts; FFmpeg is needed for some desktop codec/video conversions. These optional components are not bundled in the source upgrade. Existing offline v2 installers/wheels remain sufficient for the new browser workspace and basic desktop interface.

## Background protocol indexing

New capture analyses perform a streamed TShark PDML pass for signaling and media evidence. Existing completed registry entries are indexed by `intelligence_worker.py`, started by the folder launcher. The UI shows Pending, Processing, Complete or Partial/failed. SQLite stores packet metadata and supported audio payloads without loading the complete capture into Python memory. This additional index consumes disk space. TShark reassembly memory and processing time still depend on capture complexity.

To index one existing database manually, with no other indexing worker modifying it:

```powershell
& '.\.venv\Scripts\python.exe' '.\vessel_intelligence\intelligence.py' 'D:\VesselResults\capture\analysis.sqlite'
```

This verifies the original capture SHA-256 first. Keep the original capture available at the database's recorded path. Failed extraction preserves partial observations with a visible status; after resolving the error, the same command retries the incomplete index. The background worker attempts each database once, avoiding repeated failures.

## Audio and interpretation limits

Browser audio uses only TShark-decoded RTP with static payload type 0 (PCMU) or 8 (PCMA), grouped by capture section/interface, UDP stream, endpoints, SSRC and payload type. It excludes packets explicitly decoded as SRTP/DTLS. Timestamp gaps become silence, duplicate sequence/timestamp pairs are skipped, and playback is bounded to 300 seconds from the first observed media timestamp. Dynamic codecs and explicitly encrypted media remain metadata-only in the browser. Unsupported or opaque media is not recovered speech. The source capture can lack call beginnings, signaling, reverse traffic or continuous speech. Native SIP/SDP fields in the evidence support manual review; no timing-only SIP-to-RTP join is asserted by the new browser tables.

Whole-capture scope is distinct from vessel scope. Satellite protocol scope includes only frames already associated through the satellite mapping; it is not a claim that all packets belong to that spacecraft. Packet observations and producer-reported satellite identity are not proof of leaks, successful application use, specific RF paths or physical vessel identity.

## Upgrade and validation

Stop the running launcher/server before replacing application files. Back up the complete analysis output directory while stopped. Apply the source upgrade to the existing installation folder, preserving its `.venv`, original captures, `watch_data` and reconstructed objects. Restart **Start Dashboard.cmd**. SQLite additions are additive; existing vessel tables are not rewritten by the protocol index. Do not replace an existing database with an empty one.

All 31 automated tests pass, including the original 27 vessel/reconstruction/watcher tests and four added satellite/media tests. Tests cover conflicting satellite definitions, capture-section isolation, unknown satellite identity, G.711 timing gaps/duplicates, vessel audio scope and refusal to classify generic RTP as CCTV. The original desktop initializes all 16 tabs. A clean offline-machine acceptance test and codec-specific desktop playback verification are still required on the deployment machine.
