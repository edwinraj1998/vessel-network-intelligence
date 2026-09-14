# Vessel Network Intelligence

Python, TShark and SQLite application for offline multi-vessel PCAP analysis with an interactive localhost dashboard.

## Features

- RADIUS identities, accounting sessions and time-scoped IP mappings.
- Evidence-scoped satellite telemetry and cross-protocol correlation.
- DNS, TLS/QUIC metadata, application classification and packet drill-down.
- HTTP, images, video objects, email and validated SMS content reconstruction.
- Folder monitoring for PCAP, PCAPNG and PCAP-content DONE files.
- Local exports and optional, separately labelled MarineTraffic enrichment.

## Install from source on Windows x64

Install Python 3.12 with pip and Tcl/Tk, and Wireshark with TShark, capinfos and editcap. Keep Wireshark in its standard installation directory or add it to PATH.

From this repository folder, on a connected preparation machine:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-offline.txt
.\.venv\Scripts\python.exe vessel_intelligence\preflight.py
```

Run **Start Dashboard.cmd**, select the capture folder and keep the console open. Browse http://127.0.0.1:8768/captures and open a completed capture.

## Offline deployment

Read [the full deployment guide](DEPLOYMENT_GUIDE.md). Installers and wheels are deliberately excluded from Git. The guide describes the separately prepared offline release ZIP, which includes them. For a source checkout, prepare the required wheels on a connected Windows x64/Python 3.12 machine before transfer:

```powershell
py -3.12 -m pip download --only-binary=:all: --dest wheels -r requirements-offline.txt
```

Also obtain the Python and Wireshark full installers identified in THIRD_PARTY_NOTICES.txt. Transfer the source, wheels and installers to the destination; install the runtimes, then run Setup Offline.cmd. Release ZIP verification instructions apply only to the separately supplied ZIP/manifest.

## Validation and limitations

Run **Run Validation Tests.cmd**. The 27 included tests passed with Python 3.12.2 and Wireshark 4.6.7 on Windows. A clean offline-machine install remains a destination acceptance check.

Do not infer a vessel solely from a username or custom SMS port. Attribution follows session and frame evidence; unattributed content remains separate. Partial video objects are not complete movies. Proprietary SMS protocols require a known schema. Encrypted content requires valid keys and supported decoding. No full HTTP/2 or HTTP/3 body recovery, cross-file transport stitching or multi-GB performance benchmark is claimed.

No production captures, recovered media, databases, session keys or machine-specific registry are included in this repository.
