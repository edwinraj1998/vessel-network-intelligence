# Vessel Network Intelligence 2.1.0 — offline Windows deployment

Release date: 14 September 2026. Target: Windows 10/11 x64 (Intel/AMD), Python 3.12. This is a local application with a browser interface, not a Windows service. Internet is not required for setup or analysis with this bundle. MarineTraffic links are optional and require internet when opened.

## 1. Prepare the offline machine

Use a 64-bit Windows machine and an installed Edge, Chrome or Firefox browser. A practical starting configuration is 16 GB RAM, four CPU cores and an SSD. Reserve at least 10 GB free space plus your captures; plan additional space for SQLite, temporary dissection data and recovered objects. These are planning estimates, not a multi-GB benchmark. TShark reassembly memory can grow with capture complexity even though Python streams packets.

You need permission to install Python and Wireshark. Normal analysis should run as your regular user in a writable folder. No inbound firewall rule, live-capture driver, cloud account or server is needed.

## 2. Transfer and verify the release

Copy `Vessel_Intelligence_2.1.0_Offline_Windows_x64.zip` and its `.sha256` file to removable media, then to the offline machine. On the destination, run this in PowerShell and compare the result to the checksum file:

```powershell
Get-FileHash -Algorithm SHA256 .\Vessel_Intelligence_2.1.0_Offline_Windows_x64.zip
```

Right-click the ZIP, choose **Extract All**, and extract to a permanent writable location such as `C:\VesselIntelligence`. Open the extracted folder containing `Setup Offline.cmd`. Do not run from inside the ZIP. Avoid Program Files, network shares and synchronized folders for analysis output.

From PowerShell in that folder, run `& '.\Verify Release.ps1'`. Expected result: `PASS: all release files match the manifest.` If your organization blocks local PowerShell scripts, ask its administrator to perform verification under its approved procedure; you can also compare individual file hashes with `MANIFEST.json`. The manifest detects changed files; it is not a digital signature of this application.

## 3. Install the included Python runtime

Open `installers\python-3.12.10-amd64.exe`. On the first page, enable **Add python.exe to PATH**. Use Customize Installation and retain **pip**, **tcl/tk and IDLE** and the **Python launcher**. Complete installation. The file/folder selection windows require Tcl/Tk. Close any old terminals after installation.

If Python 3.12 x64 is already installed with those components, you can use it. This wheel bundle is specifically for Python 3.12 on Windows x64. ARM64 and other Python minor versions are not covered by this release.

Installer source: [Python 3.12.10 release](https://www.python.org/downloads/release/python-31210/). The included full installer works offline; do not substitute an online installer manager.

## 4. Install the included Wireshark tools

Open `installers\Wireshark-4.6.7-x64.exe`. Install the command-line tools including **TShark**, **capinfos** and **editcap**. Keep the default installation directory `C:\Program Files\Wireshark` for automatic discovery. Skip optional **Npcap** and **USBPcap** installation: this application reads existing capture files. If you choose a different Wireshark directory, add it to PATH before launching the application.

Installer source: [Wireshark official release archive](https://www.wireshark.org/download/win64/all-versions/). This version matches the development decoder baseline. Versions are pinned for reproducibility; this guide does not claim they are the latest security releases. Review upgrades separately against the included tests.

## 5. Set up the application without internet

Double-click **Setup Offline.cmd**. It finds Python 3.12, creates a private `.venv` folder, installs the bundled wheels using `--no-index`, and checks dependencies. It does not fetch packages online. Wait for `Setup complete. Run Start Dashboard.cmd.`

If setup fails, leave the console open and read the error. Do not continue until **Check Installation.cmd** reports PASS. Installed optional certificate support consists of cryptography 46.0.5, cffi 2.1.1 and pycparser 3.0. All required wheels are included.

Do not move the application after setup: virtual environments contain absolute paths. To install elsewhere, extract a fresh copy there and repeat setup.

## 6. Validate on the destination

Double-click **Run Validation Tests.cmd**. Expected result: **27 tests, OK**. Tests create temporary synthetic captures and exercise real TShark, RADIUS correlation, IP reuse, satellite evidence, watcher behavior, HTTP recovery, custom-port SMPP validation and SMTP gap/conflict rejection. Test fixtures are not vessel evidence and do not enter your real registry.

This release was checked on the development Windows machine using Python 3.12.2 and Wireshark 4.6.7, with bundled wheels installed using `--no-index`. The included Python 3.12.10 installer has not been installed into a separate clean offline VM here. Run the destination checks above before relying on the deployment.

## 7. Start the dashboard and choose the capture folder

Create a local input folder, for example `D:\VesselCaptures`. Copy `.pcap`, `.pcapng` or `.done` files into it. A `.done` file must contain actual PCAP/PCAPNG bytes. Original captures are preserved.

Double-click **Start Dashboard.cmd**. Select your input folder when prompted. The browser opens:

```text
http://127.0.0.1:8768/captures
```

Keep the console open. The watcher checks the folder, waits for approximately 30 seconds of unchanged size/time, and processes files sequentially. Large captures can take many minutes. For long incoming copies, finish copying outside the watched folder and move the completed file into it; a pause during copying can otherwise look stable. The default launcher scans the selected folder, not its subfolders.

This release does not contain Edwin's absolute input path or an old registry. Choose the correct folder on each machine. Identical file content is marked Duplicate. The status page shows processing stages, failures and completed analyses. Open a completed filename to view the dashboard.

## 8. Inspect vessel profiles and reconstructed content

Select a vessel/site candidate. Review its RADIUS identity, confidence, session/IP assignment windows and satellite evidence before interpreting traffic. Unknown values remain Unknown. Satellite bearer mappings do not establish individual subscriber identity.

Open **Content Reconstruction** and select Image, Video, HTTP, Email, SMS, Ports 5002/5003 or Attachment. Click **Inspect / reconstruct** for frame numbers, raw metadata, timestamps, completeness and downloads. The default scope requires matching vessel/session evidence across contributing frames. **Whole capture** includes unattributed items; those items must not be assumed to belong to the selected vessel.

Images preview locally; supported recovered videos can play. HTTP byte ranges may be fragments, not complete movies. Email can be downloaded as `.eml`; named MIME attachments are separate artifacts. Ports 5002/5003 are not automatically SMS: only valid SMPP payloads or native SMS dissection justify that label. Proprietary feeds need a known schema. Multipart SMS merging, HTTP/2–HTTP/3 body reconstruction and cross-file stream stitching are not implemented. Recovered content is not, by itself, proof of an unauthorized leak.

Recovery limits: 32 MiB per object, 1 GiB stored content per capture, 25,000 artifact records. Limit hits and errors show partial status. Encrypted content remains encrypted without valid user-supplied keys. MarineTraffic enrichment is optional, external and unavailable while disconnected.

## 9. Single-file analysis, existing results and exports

Use **Analyze One Capture.cmd** to select one capture without monitoring a folder. It creates a timestamped `analysis_*` directory and opens its dashboard on port 8769 after analysis. Use **Open Saved Analysis.cmd** to choose an existing `analysis.sqlite`.

Use the dashboard export controls for CSV tables, content-page JSON, isolated capture exports and an HTML report. Recovered content downloads come from its inspection dialog. The HTML report is an offline snapshot; content files are not embedded. Full content browsing needs the local server plus the database and `reconstructed` folder.

For supplied TLS session keys, run from PowerShell in the release folder:

```powershell
& '.\.venv\Scripts\python.exe' '.\vessel_intelligence\core.py' 'D:\VesselCaptures\capture.pcapng' --out 'D:\VesselResults\capture-with-keys' --keylog 'D:\Keys\session.keys'
```

Choose a new output directory. Then open its `analysis.sqlite` using **Open Saved Analysis.cmd**. Key availability does not guarantee every encrypted protocol/body can be recovered.

## 10. Stop, restart, backup and upgrade

Press **Ctrl+C** in the launcher console to stop the watcher and its child processes. Closing just the browser does not stop processing. After stopping, start again with **Start Dashboard.cmd** and select the same folder; the persistent registry resumes work and avoids reprocessing completed identical files. Failed files are not automatically retried forever: inspect their logs and use single-file analysis after fixing the problem.

Folder analyses live in `watch_data`, including `registry.sqlite`, per-capture `analysis.sqlite`, `report.html`, `reconstructed` and diagnostic logs. Back up the entire output directory only after stopping workers, along with the original captures. Do not copy only an active SQLite main file while ignoring its WAL. Preserve original absolute capture paths if reopening migrated databases: isolated PCAP export and reconstruction retries need the original source. The simplest migration is to copy captures and reanalyze into a fresh registry on the destination.

For an upgrade, stop this version, back up data, extract the new release to a separate folder and set it up there. Keep the old release for rollback. Do not overwrite a running installation or copy a `.venv` between computers. No automatic startup service or scheduled task is installed by this release.

## 11. Troubleshooting

| Symptom | Action |
|---|---|
| Python not found / Microsoft Store opens | Re-run the included Python installer with PATH and launcher selected, then open a new console. |
| tkinter missing | Modify the Python installation and add Tcl/Tk. |
| tshark, capinfos or editcap missing | Modify Wireshark installation to include tools; use the default directory or correct PATH. |
| Package installer attempts the internet | Use Setup Offline.cmd, not a generic pip install command. The supplied script uses local wheels only. |
| Port already in use | Stop the earlier instance. Or run `.venv\Scripts\python.exe vessel_intelligence\launch_watch.py --port 8770` from the release folder and use that port. |
| Waiting for file | Allow the stability window; verify the file has finished copying and is in the selected folder. |
| Failed capture | Inspect that capture's `pipeline.log` and decoder logs in watch_data; check format, truncation, free disk and source changes. |
| No vessels / no attributed content | Inspect RADIUS and coverage evidence; missing session evidence is not repaired by assigning all traffic to a vessel. Use explicit whole-capture content scope where appropriate. |
| Partial reconstruction | Inspect `reconstruction-tshark.log`. To retry after fixing the cause, run `.venv\Scripts\python.exe vessel_intelligence\reconstruction.py PATH_TO_ANALYSIS_SQLITE` while no other worker is modifying that database. |
| Report opens but content downloads do not | Start the local dashboard with the database and reconstructed folder present. |
| Browser cannot connect | Keep the launcher running; check its console and open the exact localhost URL. The server binds only to this machine. |

Keep `MANIFEST.json`, the release ZIP checksum, test results and source capture hashes with your deployment records. See `THIRD_PARTY_NOTICES.txt` for bundled component provenance and licenses.
