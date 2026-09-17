#!/usr/bin/env python3
"""
Satellite Intelligence — Advanced Desktop - A comprehensive network analysis tool
Uses standard tkinter with ttk for maximum compatibility

Session Hierarchy:
1. Packet level - Individual packets from PCAP
2. Transport-flow level - TCP streams / UDP five-tuple flows
3. Logical application-session level - Correlated streams into one upload session
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import subprocess
import json
import csv
import os
import threading
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Tuple
import re
import mimetypes
import tempfile
import shutil
import base64
import io
import time
import struct
import urllib.parse
import urllib.error
import urllib.request

try:
    from PIL import Image, ImageTk
    HAS_PIL = True
except Exception:
    HAS_PIL = False

try:
    import matplotlib
    matplotlib.use("TkAgg")
    from matplotlib.figure import Figure
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
    HAS_MATPLOTLIB = True
except Exception:
    HAS_MATPLOTLIB = False


class SharedCaptureDownloadError(Exception):
    """Raised when a shared URL cannot be downloaded as a capture file."""


@dataclass
class PacketRecord:
    """Lightweight per-packet record for time-series analysis (packet level)"""
    time: float          # frame.time_epoch
    is_upload: bool       # True = client->server
    payload_len: int      # tcp.len or udp payload length (excludes headers)
    frame_len: int        # full frame length
    is_retransmission: bool = False


@dataclass
class TransportFlow:
    """Represents a single TCP stream or UDP flow (transport-flow level)"""
    flow_id: str  # tcp.stream or udp.stream number
    protocol: str  # TCP, UDP, QUIC
    src_ip: str
    dst_ip: str
    src_port: str
    dst_port: str
    packets: int = 0
    bytes_sent: int = 0  # Client to server
    bytes_recv: int = 0  # Server to client
    start_time: float = 0.0
    end_time: float = 0.0
    sni: str = ""
    quic_dcid: str = ""  # QUIC Destination Connection ID
    quic_scid: str = ""  # QUIC Source Connection ID
    # Per-packet records for time-series / upload-event detection
    packet_records: List["PacketRecord"] = field(default_factory=list)


@dataclass
class UploadEvent:
    """A distinct upload burst inside a session (upload-event level)"""
    event_id: str                 # e.g. Session-001-Upload-01
    session_id: str
    flow_ids: List[str] = field(default_factory=list)  # tcp.X / udp.X involved
    protocol: str = ""
    client_ip: str = ""
    server_ip: str = ""
    server_name: str = ""
    client_ports: Set[str] = field(default_factory=set)
    server_port: str = ""
    quic_cids: Set[str] = field(default_factory=set)

    start_time: float = 0.0
    end_time: float = 0.0
    duration: float = 0.0

    upload_packets: int = 0
    upload_payload_bytes: int = 0
    download_bytes: int = 0

    peak_upload_bps: float = 0.0     # peak bytes/sec
    avg_upload_bps: float = 0.0      # average bytes/sec
    upload_ratio: float = 0.0
    num_peaks: int = 0
    confidence: float = 0.0
    fingerprint: str = ""

    # Time-series slice for this event: list of (t, up_bytes, down_bytes)
    timeline: List[Tuple[float, int, int]] = field(default_factory=list)
    

@dataclass 
class LogicalSession:
    """Represents a logical application session (correlated flows)"""
    session_id: str
    client_ip: str
    server_ips: Set[str] = field(default_factory=set)
    server_name: str = ""  # SNI or resolved hostname
    protocol: str = ""  # TCP, QUIC, Mixed
    
    # Associated transport flows
    tcp_streams: List[str] = field(default_factory=list)
    udp_streams: List[str] = field(default_factory=list)
    quic_connection_ids: Set[str] = field(default_factory=set)
    client_ports: Set[str] = field(default_factory=set)
    
    # Aggregated statistics
    total_upload_bytes: int = 0
    total_download_bytes: int = 0
    total_packets: int = 0
    
    # Timing
    start_time: float = 0.0
    end_time: float = 0.0
    
    # Classification
    classification: str = ""
    upload_ratio: float = 0.0
    
    # Raw flows for details
    flows: List[TransportFlow] = field(default_factory=list)

    # Nested upload events detected within this session
    upload_events: List[UploadEvent] = field(default_factory=list)
    # Session-level time-series buckets: list of (t, up_bytes, down_bytes, up_pkts, down_pkts)
    io_timeline: List[Tuple[float, int, int, int, int]] = field(default_factory=list)


class PCAPIntelligenceDashboard:
    def __init__(self, root):
        self.root = root
        self.root.title("Satellite Intelligence — Advanced Desktop")
        self.root.geometry("1680x980")
        self.root.minsize(1320, 820)
        
        # Modern SOC dashboard palette (keys preserved for backward compatibility)
        self.colors = {
            'bg': '#07111f',          # app background
            'fg': '#f4f7fb',          # primary text
            'muted': '#9fb0c4',       # secondary text
            'accent': '#2f7dff',      # primary action blue
            'accent_hover': '#5b9bff',
            'success': '#28d497',
            'warning': '#f2b84b',
            'danger': '#ff6b7a',
            'card_bg': '#0d1a2b',     # surfaces / cards
            'surface2': '#142238',    # elevated surface
            'border': '#23324a',      # borders / dividers
            'selection': '#1f4ed8',   # selected row / nav
            'heading': '#101d30',     # table headers
            'teal': '#17c6d6',
            'violet': '#a66cff',
            'rose': '#ff4fb8',
        }
        
        # Configure root
        self.root.configure(bg=self.colors['bg'])

        # Modern defaults for classic tk widgets (Text, etc.) - visual only
        self.root.option_add("*Text.relief", "flat")
        self.root.option_add("*Text.borderWidth", 0)
        self.root.option_add("*Text.highlightThickness", 0)
        self.root.option_add("*Text.padX", 12)
        self.root.option_add("*Text.padY", 10)
        self.root.option_add("*Text.insertBackground", self.colors['fg'])
        self.root.option_add("*Text.selectBackground", self.colors['selection'])
        self.root.option_add("*Text.selectForeground", self.colors['fg'])
        self.root.option_add("*Menu.activeBackground", self.colors['accent'])
        self.root.option_add("*Menu.activeForeground", "#ffffff")
        
        # Configure ttk styles
        self.setup_styles()
        
        # State variables
        self.pcap_file = tk.StringVar()
        self.tshark_path = tk.StringVar(value=self._find_tshark())
        # Companion Wireshark CLI tools (discovered next to tshark)
        self.mergecap_path = self._find_companion_tool("mergecap")
        self.capinfos_path = self._find_companion_tool("capinfos")
        # Multi-file / merge state
        self.selected_files = []      # source files chosen for a merge
        self.merged_file = None       # path of the last generated merged capture
        self.merged_source_files = [] # original source files for the last merge
        self.analysis_results = {}
        self.analysis_completed = False
        self.is_analyzing = False
        
        # Create main UI
        self.create_menu()
        self.create_main_layout()
        self.create_status_bar()
        
    def _find_tshark(self):
        """Find TShark executable in common locations"""
        import shutil
        
        # Check if tshark is in PATH
        tshark_in_path = shutil.which("tshark")
        if tshark_in_path:
            return tshark_in_path
        
        # Common Wireshark installation paths on Windows
        common_paths = [
            r"C:\Program Files\Wireshark\tshark.exe",
            r"C:\Program Files (x86)\Wireshark\tshark.exe",
            r"D:\Program Files\Wireshark\tshark.exe",
            r"D:\Wireshark\tshark.exe",
            os.path.expanduser(r"~\AppData\Local\Programs\Wireshark\tshark.exe"),
        ]
        
        for path in common_paths:
            if os.path.exists(path):
                print(f"Found TShark at: {path}")
                return path
        
        # Not found - return default and let user configure
        print("WARNING: TShark not found. Please configure path via Settings > Configure TShark Path")
        return "tshark"

    def _find_companion_tool(self, name):
        """
        Locate a Wireshark CLI companion tool (e.g. 'mergecap', 'capinfos').
        Prefers the folder where TShark lives so we use a consistent install.
        Returns the tool name (bare) as a last resort so PATH can still work.
        """
        import shutil
        exe = name + (".exe" if os.name == "nt" else "")

        # 1) Same directory as the configured TShark
        tshark = self.tshark_path.get() if hasattr(self, "tshark_path") else ""
        if tshark and os.path.exists(tshark):
            candidate = os.path.join(os.path.dirname(tshark), exe)
            if os.path.exists(candidate):
                return candidate

        # 2) On PATH
        found = shutil.which(name)
        if found:
            return found

        # 3) Common Wireshark install dirs
        for base in (r"C:\Program Files\Wireshark", r"C:\Program Files (x86)\Wireshark",
                     r"D:\Program Files\Wireshark", r"D:\Wireshark",
                     os.path.expanduser(r"~\AppData\Local\Programs\Wireshark")):
            candidate = os.path.join(base, exe)
            if os.path.exists(candidate):
                return candidate

        return name

    def setup_styles(self):
        """Configure ttk styles for a warm modern dark theme."""
        style = ttk.Style()
        style.theme_use('clam')

        c = self.colors
        base_font = ("Segoe UI", 10)
        bold_font = ("Segoe UI", 10, "bold")
        small_font = ("Segoe UI", 9)

        # Base
        style.configure('.', background=c['bg'], foreground=c['fg'],
                        font=base_font, borderwidth=0, focuscolor=c['bg'])
        style.configure('TFrame', background=c['bg'])
        style.configure('TLabel', background=c['bg'], foreground=c['fg'], font=base_font)
        style.configure('Muted.TLabel', background=c['bg'], foreground=c['muted'],
                        font=small_font)

        # Labelframe -> subtle card container
        style.configure('TLabelframe', background=c['bg'], foreground=c['fg'],
                        bordercolor=c['border'], relief='solid', borderwidth=1)
        style.configure('TLabelframe.Label', background=c['bg'],
                        foreground=c['warning'], font=("Segoe UI Semibold", 9, "bold"))

        # Notebook -> flat modern tabs
        style.configure('TNotebook', background=c['bg'], borderwidth=0, tabmargins=[2, 8, 2, 0])
        style.configure('TNotebook.Tab', background=c['bg'], foreground=c['muted'],
                        padding=[18, 10], font=("Segoe UI Semibold", 10), borderwidth=0)
        style.map('TNotebook.Tab',
                  background=[('selected', c['card_bg']), ('active', c['surface2'])],
                  foreground=[('selected', c['accent']), ('active', c['fg'])],
                  expand=[('selected', [0, 0, 0, 0])])
        style.configure('Sidebar.TNotebook', background=c['bg'], borderwidth=0)
        try:
            style.layout('Sidebar.TNotebook.Tab', [])
        except tk.TclError:
            pass

        # Buttons -> flat, rounded feel with hover states
        style.configure('TButton', background=c['surface2'], foreground=c['fg'],
                        padding=[10, 6], font=("Segoe UI Semibold", 9, "bold"),
                        borderwidth=0, relief='flat')
        style.map('TButton',
                  background=[('active', '#3a3028'), ('pressed', c['border'])],
                  foreground=[('disabled', c['muted'])])

        style.configure('Accent.TButton', background=c['accent'], foreground='#ffffff',
                        padding=[14, 7], font=("Segoe UI Semibold", 9, "bold"))
        style.map('Accent.TButton', background=[('active', c['accent_hover']),
                                                ('pressed', c['accent_hover'])])

        # Compact variants (for dense toolbars/config rows)
        style.configure('Compact.TButton', background=c['accent'], foreground='#ffffff',
                        padding=[8, 3], font=("Segoe UI Semibold", 8, "bold"))
        style.map('Compact.TButton', background=[('active', c['accent_hover']),
                                                 ('pressed', c['accent_hover'])])
        style.configure('Compact.TEntry', fieldbackground=c['surface2'], foreground=c['fg'],
                        bordercolor=c['border'], insertcolor=c['fg'],
                        padding=2, relief='flat')
        style.map('Compact.TEntry', bordercolor=[('focus', c['accent'])])
        style.configure('Compact.TLabel', background=c['bg'], foreground=c['muted'],
                        font=small_font)
        style.configure('Success.TButton', background=c['success'], foreground='#08130d',
                        padding=[16, 8], font=bold_font)
        style.map('Success.TButton', background=[('active', '#48c596'), ('pressed', '#48c596')])
        style.configure('Warning.TButton', background=c['warning'], foreground='#1b1407')
        style.map('Warning.TButton', background=[('active', '#ffd06f')])
        style.configure('Danger.TButton', background=c['danger'], foreground='#ffffff')
        style.map('Danger.TButton', background=[('active', '#ff8585')])

        # Entries
        style.configure('TEntry', fieldbackground=c['surface2'], foreground=c['fg'],
                        bordercolor=c['border'], insertcolor=c['fg'],
                        padding=5, relief='flat')
        style.map('TEntry', bordercolor=[('focus', c['accent'])])

        # Checkbutton
        style.configure('TCheckbutton', background=c['bg'], foreground=c['fg'], font=base_font)
        style.map('TCheckbutton', foreground=[('active', c['accent'])],
                  background=[('active', c['bg'])])

        # Combobox (if used)
        style.configure('TCombobox', fieldbackground=c['surface2'], background=c['surface2'],
                        foreground=c['fg'], arrowcolor=c['muted'], bordercolor=c['border'])

        # Treeview -> modern table
        style.configure('Treeview', background=c['card_bg'], foreground=c['fg'],
                        fieldbackground=c['card_bg'], borderwidth=0,
                        rowheight=30, font=base_font)
        style.map('Treeview',
                  background=[('selected', c['selection'])],
                  foreground=[('selected', c['fg'])])
        style.configure('Treeview.Heading', background=c['heading'], foreground=c['muted'],
                        font=("Segoe UI Semibold", 9, "bold"), relief='flat', padding=[8, 6],
                        borderwidth=0)
        style.map('Treeview.Heading', background=[('active', c['surface2'])],
                  foreground=[('active', c['accent'])])

        # Scrollbars -> slim, flat
        for orient in ('Vertical', 'Horizontal'):
            style.configure(f'{orient}.TScrollbar', background=c['surface2'],
                            troughcolor=c['bg'], bordercolor=c['bg'],
                            arrowcolor=c['muted'], relief='flat', borderwidth=0)
            style.map(f'{orient}.TScrollbar', background=[('active', c['border'])])

        # Progress bar
        style.configure('TProgressbar', background=c['accent'], troughcolor=c['surface2'],
                        bordercolor=c['surface2'], lightcolor=c['accent'],
                        darkcolor=c['accent'], thickness=7)

        # Paned window sash
        style.configure('TPanedwindow', background=c['bg'])
        style.configure('Sash', sashthickness=6, background=c['border'])

    def _table_sort_value(self, value):
        """Return a stable sort key for numbers, sizes, percentages, and text."""
        if value is None:
            return (3, "")
        text = str(value).strip()
        if not text:
            return (3, "")

        cleaned = text.replace(",", "")
        if cleaned.endswith("%"):
            try:
                return (0, float(cleaned[:-1]))
            except ValueError:
                pass

        m = re.fullmatch(r"(-?\d+(?:\.\d+)?)\s*(B|KB|MB|GB|TB)?", cleaned, re.I)
        if m:
            num = float(m.group(1))
            unit = (m.group(2) or "").upper()
            scale = {"": 1, "B": 1, "KB": 1024, "MB": 1024 ** 2,
                     "GB": 1024 ** 3, "TB": 1024 ** 4}
            return (0, num * scale.get(unit, 1))

        try:
            return (0, float(cleaned))
        except ValueError:
            pass

        for fmt in ("%Y-%m-%d %H:%M:%S", "%b %d, %Y %H:%M:%S",
                    "%H:%M:%S", "%M:%S"):
            try:
                return (1, datetime.strptime(text[:19], fmt).timestamp())
            except ValueError:
                continue
        return (2, text.casefold())

    def _sort_treeview(self, tree, col, reverse=False):
        """Sort a Treeview column and keep headings clickable."""
        if col == "#0":
            rows = [(self._table_sort_value(tree.item(iid, "text")), iid)
                    for iid in tree.get_children("")]
        else:
            rows = [(self._table_sort_value(tree.set(iid, col)), iid)
                    for iid in tree.get_children("")]
        rows.sort(key=lambda x: x[0], reverse=reverse)
        for index, (_, iid) in enumerate(rows):
            tree.move(iid, "", index)

        headings = getattr(tree, "_heading_text", {})
        for c, text in headings.items():
            arrow = " \u25be" if c == col and reverse else (" \u25b4" if c == col else "")
            tree.heading(c, text=text + arrow,
                         command=lambda c=c: self._sort_treeview(tree, c, c == col and not reverse))

    def _setup_tree_columns(self, tree, columns, headings=None, widths=None,
                            numeric_cols=None, stretch_cols=None, tree_heading=None,
                            tree_width=None):
        """Apply consistent sortable headings and stable column alignment."""
        headings = headings or columns
        widths = widths or [120] * len(columns)
        numeric_cols = set(numeric_cols or ())
        stretch_cols = set(stretch_cols or ())
        tree._heading_text = {}

        if tree_heading is not None:
            tree._heading_text["#0"] = tree_heading
            tree.heading("#0", text=tree_heading,
                         command=lambda: self._sort_treeview(tree, "#0", False))
            if tree_width is not None:
                tree.column("#0", width=tree_width, minwidth=80,
                            anchor=tk.W, stretch=("#0" in stretch_cols))

        for col, heading, width in zip(columns, headings, widths):
            tree._heading_text[col] = heading
            tree.heading(col, text=heading,
                         command=lambda c=col: self._sort_treeview(tree, c, False))
            anchor = tk.E if col in numeric_cols else tk.W
            min_width = 0 if width == 0 else min(width, 80)
            tree.column(col, width=width, minwidth=min_width, anchor=anchor,
                        stretch=(col in stretch_cols))

    def _add_tree_scrollbars(self, parent, tree, horizontal=True):
        """Attach table scrollbars without changing table behavior."""
        vs = ttk.Scrollbar(parent, orient=tk.VERTICAL, command=tree.yview)
        if horizontal:
            hs = ttk.Scrollbar(parent, orient=tk.HORIZONTAL, command=tree.xview)
            tree.configure(yscrollcommand=vs.set, xscrollcommand=hs.set)
            vs.pack(side=tk.RIGHT, fill=tk.Y)
            hs.pack(side=tk.BOTTOM, fill=tk.X)
        else:
            tree.configure(yscrollcommand=vs.set)
            vs.pack(side=tk.RIGHT, fill=tk.Y)
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self._attach_tree_context_menu(tree)
        return vs

    def _attach_tree_context_menu(self, tree):
        """Add copy/export conveniences to analysis tables."""
        if getattr(tree, "_context_menu_attached", False):
            return
        tree._context_menu_attached = True
        menu = tk.Menu(tree, tearoff=0, bg=self.colors['card_bg'], fg=self.colors['fg'],
                       activebackground=self.colors['accent'], activeforeground="#ffffff")
        menu.add_command(label="Copy Cell", command=lambda t=tree: self._copy_tree_cell(t))
        menu.add_command(label="Copy Row", command=lambda t=tree: self._copy_tree_row(t))
        menu.add_separator()
        menu.add_command(label="Export Visible Rows to CSV...",
                         command=lambda t=tree: self._export_tree_visible_csv(t))
        tree._context_menu = menu
        tree._context_iid = ""
        tree._context_col = ""
        tree.bind("<Button-3>", lambda e, t=tree: self._show_tree_context_menu(e, t), add="+")
        tree.bind("<Control-c>", lambda e, t=tree: self._copy_tree_row(t), add="+")

    def _show_tree_context_menu(self, event, tree):
        """Open a table context menu and remember the clicked cell."""
        iid = tree.identify_row(event.y)
        col = tree.identify_column(event.x)
        tree._context_iid = iid or (tree.selection()[0] if tree.selection() else "")
        tree._context_col = col
        if iid:
            tree.selection_set(iid)
            tree.focus(iid)
        try:
            tree._context_menu.tk_popup(event.x_root, event.y_root)
        finally:
            tree._context_menu.grab_release()
        return "break"

    def _tree_display_columns(self, tree):
        """Return visible logical column ids, including the tree column when shown."""
        cols = []
        show = str(tree.cget("show") or "")
        if "tree" in show:
            cols.append("#0")
        cols.extend(list(tree.cget("columns") or ()))
        return cols

    def _tree_heading_text(self, tree, col):
        """Return the clean heading label for a table column."""
        if col == "#0":
            return getattr(tree, "_heading_text", {}).get("#0", "Item")
        return getattr(tree, "_heading_text", {}).get(col, col)

    def _tree_cell_text(self, tree, iid, col):
        """Read a cell value from a Treeview."""
        if not iid:
            return ""
        if col == "#0":
            return str(tree.item(iid, "text") or "")
        if col.startswith("#"):
            try:
                idx = int(col[1:]) - 1
                logical = list(tree.cget("columns") or ())[idx]
                return str(tree.set(iid, logical) or "")
            except Exception:
                return ""
        return str(tree.set(iid, col) or "")

    def _copy_to_clipboard(self, text, status_msg="Copied to clipboard"):
        """Copy text and update status without interrupting the workflow."""
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.update_status(status_msg)

    def _copy_tree_cell(self, tree):
        """Copy the right-clicked table cell."""
        iid = getattr(tree, "_context_iid", "") or (tree.selection()[0] if tree.selection() else "")
        col = getattr(tree, "_context_col", "") or "#1"
        text = self._tree_cell_text(tree, iid, col)
        self._copy_to_clipboard(text, "Copied table cell")

    def _copy_tree_row(self, tree):
        """Copy the selected table row as tab-separated values."""
        iid = getattr(tree, "_context_iid", "") or (tree.selection()[0] if tree.selection() else "")
        if not iid:
            return
        cols = self._tree_display_columns(tree)
        values = [self._tree_cell_text(tree, iid, col) for col in cols]
        self._copy_to_clipboard("\t".join(values), "Copied table row")

    def _export_tree_visible_csv(self, tree):
        """Export currently visible top-level table rows to CSV."""
        path = filedialog.asksaveasfilename(
            title="Export visible table rows",
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")])
        if not path:
            return
        cols = self._tree_display_columns(tree)
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([self._tree_heading_text(tree, col) for col in cols])
            for iid in tree.get_children(""):
                writer.writerow([self._tree_cell_text(tree, iid, col) for col in cols])
        self.update_status(f"Exported table rows: {os.path.basename(path)}")

    def _available_tshark_fields(self):
        """Return dissector field names supported by the installed TShark."""
        if hasattr(self, "_tshark_fields_cache"):
            return self._tshark_fields_cache
        fields = set()
        try:
            cmd = [self.tshark_path.get(), "-G", "fields"]
            result = subprocess.run(cmd, capture_output=True, text=True,
                                    encoding="utf-8", errors="replace", timeout=45)
            for line in result.stdout.splitlines():
                if not line.startswith("F\t"):
                    continue
                parts = line.split("\t")
                if len(parts) > 2 and parts[2]:
                    fields.add(parts[2])
        except Exception:
            fields = set()
        self._tshark_fields_cache = fields
        return fields

    def _filter_tshark_fields(self, fields):
        """Keep base pseudo-fields and installed dissector fields only."""
        base_fields = {"frame.number", "frame.time", "frame.time_epoch",
                       "_ws.col.protocol", "_ws.col.info", "ip.src", "ip.dst",
                       "ipv6.src", "ipv6.dst"}
        available = self._available_tshark_fields()
        if not available:
            return list(dict.fromkeys(fields))
        return [f for f in dict.fromkeys(fields) if f in base_fields or f in available]

    def _iter_command_lines(self, cmd, timeout=300, max_lines=300000):
        """
        Stream command stdout line-by-line to avoid large capture_output buffers.
        Raises TimeoutExpired on timeout and stops after max_lines as a safety cap.
        """
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, encoding="utf-8", errors="replace")
        start = time.monotonic()
        lines = 0
        try:
            assert proc.stdout is not None
            for line in proc.stdout:
                if timeout and time.monotonic() - start > timeout:
                    proc.kill()
                    raise subprocess.TimeoutExpired(cmd, timeout)
                yield line
                lines += 1
                if max_lines and lines >= max_lines:
                    proc.kill()
                    break
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
        finally:
            try:
                if proc.stdout:
                    proc.stdout.close()
            except Exception:
                pass
            if proc.poll() is None:
                proc.kill()
        
    def create_menu(self):
        """Create the menu bar"""
        menubar = tk.Menu(self.root, bg=self.colors['card_bg'], fg=self.colors['fg'])
        self.root.config(menu=menubar)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0, bg=self.colors['card_bg'], fg=self.colors['fg'])
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Open PCAP...", command=self.browse_pcap, accelerator="Ctrl+O")
        file_menu.add_command(label="Open Shared URL...", command=self.open_shared_url)
        file_menu.add_command(label="Merge Files...", command=self.open_merge_dialog, accelerator="Ctrl+M")
        file_menu.add_separator()
        file_menu.add_command(label="Export Results...", command=self.export_results)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        
        # Analysis menu
        analysis_menu = tk.Menu(menubar, tearoff=0, bg=self.colors['card_bg'], fg=self.colors['fg'])
        menubar.add_cascade(label="Analysis", menu=analysis_menu)
        analysis_menu.add_command(label="Run Full Analysis", command=self.run_full_analysis)
        analysis_menu.add_separator()
        analysis_menu.add_command(label="Protocol Distribution", command=lambda: self.run_specific_analysis("protocol"))
        analysis_menu.add_command(label="Upload Behavior", command=lambda: self.run_specific_analysis("upload"))
        analysis_menu.add_command(label="DNS Analysis", command=lambda: self.run_specific_analysis("dns"))
        analysis_menu.add_command(label="TLS Analysis", command=lambda: self.run_specific_analysis("tls"))
        
        # Settings menu
        settings_menu = tk.Menu(menubar, tearoff=0, bg=self.colors['card_bg'], fg=self.colors['fg'])
        menubar.add_cascade(label="Settings", menu=settings_menu)
        settings_menu.add_command(label="Configure TShark Path...", command=self.configure_tshark)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0, bg=self.colors['card_bg'], fg=self.colors['fg'])
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About", command=self.show_about)
        
        # Keyboard shortcuts
        self.root.bind("<Control-o>", lambda e: self.browse_pcap())
        self.root.bind("<Control-m>", lambda e: self.open_merge_dialog())
        
    def create_main_layout(self):
        """Create the main application layout"""
        # Main container
        main_container = ttk.Frame(self.root, padding=(16, 14, 16, 12))
        main_container.pack(fill=tk.BOTH, expand=True)

        # App header with compact capture source controls
        header = tk.Frame(main_container, bg=self.colors['bg'])
        header.pack(fill=tk.X, pady=(0, 8))
        left_header = tk.Frame(header, bg=self.colors['bg'], width=270)
        left_header.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 12))
        left_header.pack_propagate(False)

        brand = tk.Frame(left_header, bg=self.colors['accent'], width=4, height=58)
        brand.pack(side=tk.LEFT, padx=(0, 14), pady=(4, 0))
        brand.pack_propagate(False)
        title_block = tk.Frame(left_header, bg=self.colors['bg'])
        title_block.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        title = tk.Label(title_block, text="Satellite Intelligence — Advanced Desktop",
                         font=("Segoe UI Semibold", 18, "bold"),
                         bg=self.colors['bg'], fg=self.colors['fg'], anchor="w")
        title.pack(fill=tk.X)
        subtitle = tk.Label(title_block, text="Network capture analysis & upload behavior",
                            font=("Segoe UI", 9),
                            bg=self.colors['bg'], fg=self.colors['muted'], anchor="w")
        subtitle.pack(fill=tk.X, pady=(5, 0))

        source_holder = ttk.Frame(header)
        source_holder.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.create_file_section(source_holder)

        # Main workbench: left navigation + hidden notebook content pages
        workbench = ttk.Frame(main_container)
        workbench.pack(fill=tk.BOTH, expand=True)

        self.sidebar_shell = tk.Frame(workbench, bg=self.colors['card_bg'], width=74)
        self.sidebar_shell.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 12))
        self.sidebar_shell.pack_propagate(False)

        self.sidebar_canvas = tk.Canvas(
            self.sidebar_shell, bg=self.colors['card_bg'],
            highlightthickness=0, borderwidth=0)
        self.sidebar_scroll = ttk.Scrollbar(
            self.sidebar_shell, orient=tk.VERTICAL,
            command=self.sidebar_canvas.yview)
        self.sidebar = tk.Frame(self.sidebar_canvas, bg=self.colors['card_bg'])
        self.sidebar_window = self.sidebar_canvas.create_window(
            (0, 0), window=self.sidebar, anchor="nw")
        self.sidebar_canvas.configure(yscrollcommand=self.sidebar_scroll.set)
        self.sidebar_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.sidebar_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.sidebar.bind("<Configure>", self._update_sidebar_scrollregion)
        self.sidebar_canvas.bind("<Configure>", self._resize_sidebar_window)
        self.sidebar_shell.bind("<Enter>", self._activate_sidebar_mousewheel)
        self.sidebar_shell.bind("<Leave>", self._deactivate_sidebar_mousewheel)
        self.sidebar_canvas.bind("<Enter>", self._activate_sidebar_mousewheel)
        self.sidebar_canvas.bind("<Leave>", self._deactivate_sidebar_mousewheel)
        self.sidebar.bind("<Enter>", self._activate_sidebar_mousewheel)
        self.sidebar.bind("<Leave>", self._deactivate_sidebar_mousewheel)
        self.sidebar_canvas.bind("<MouseWheel>", self._on_sidebar_mousewheel)
        self.sidebar.bind("<MouseWheel>", self._on_sidebar_mousewheel)

        content = ttk.Frame(workbench)
        content.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.page_header = tk.Frame(content, bg=self.colors['card_bg'], height=42)
        self.page_header.pack(fill=tk.X, pady=(0, 8))
        self.page_header.pack_propagate(False)
        self.current_page_label = tk.Label(
            self.page_header, text="Overview", anchor="w",
            bg=self.colors['card_bg'], fg=self.colors['fg'],
            font=("Segoe UI Semibold", 12, "bold"))
        self.current_page_label.pack(side=tk.LEFT, fill=tk.Y, padx=(14, 8))
        self.current_page_hint = tk.Label(
            self.page_header,
            text="Right-click any table row to copy cells, copy rows, or export visible rows",
            anchor="e", bg=self.colors['card_bg'], fg=self.colors['muted'],
            font=("Segoe UI", 8))
        self.current_page_hint.pack(side=tk.RIGHT, fill=tk.Y, padx=(8, 14))

        self.notebook = ttk.Notebook(content, style='Sidebar.TNotebook')
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Create tabs
        self.create_overview_tab()
        self.create_protocol_tab()
        self.create_upload_tab()
        self.create_dns_tab()
        self.create_tls_tab()
        self.create_sessions_tab()
        self.create_http_tab()
        self.create_files_tab()
        self.create_stun_tab()
        self.create_radius_tab()
        self.create_ss7_signaling_tab()
        self.create_ss7_tab()
        self.create_voip_tab()
        self.create_cctv_tab()
        self.create_satellite_tab()
        self.create_raw_data_tab()
        self._build_sidebar_navigation()

    def _create_top_kpis(self, parent):
        """Create the top dashboard KPI strip."""
        self.top_kpis = {}
        items = [
            ("Packets Analyzed", "0", "Total packets", self.colors['accent']),
            ("TLS Connections", "0", "Analyzed", self.colors['success']),
            ("Uploads Detected", "0", "Sessions", self.colors['violet']),
            ("RADIUS Packets", "0", "Found", self.colors['warning']),
            ("Capture Time", "0s", "Duration", self.colors['teal']),
        ]
        strip = tk.Frame(parent, bg=self.colors['bg'])
        strip.pack(side=tk.LEFT, fill=tk.X, expand=True)
        for title, value, caption, color in items:
            card = tk.Frame(strip, bg=self.colors['border'], height=104)
            card.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 8))
            card.pack_propagate(False)
            inner = tk.Frame(card, bg=self.colors['card_bg'], padx=16, pady=12)
            inner.pack(fill=tk.BOTH, expand=True, padx=1, pady=1)
            tk.Label(inner, text=title, bg=self.colors['card_bg'], fg=self.colors['fg'],
                     font=("Segoe UI Semibold", 9, "bold"), anchor="w").pack(fill=tk.X)
            value_label = tk.Label(inner, text=value, bg=self.colors['card_bg'], fg=color,
                                   font=("Segoe UI Semibold", 20, "bold"), anchor="w")
            value_label.pack(fill=tk.X, pady=(5, 0))
            tk.Label(inner, text=caption, bg=self.colors['card_bg'], fg=self.colors['muted'],
                     font=("Segoe UI", 8), anchor="w").pack(fill=tk.X)
            self.top_kpis[title] = value_label

    def _update_sidebar_scrollregion(self, event=None):
        """Keep sidebar scroll region matched to its content."""
        self.sidebar_canvas.configure(scrollregion=self.sidebar_canvas.bbox("all"))

    def _resize_sidebar_window(self, event):
        """Keep sidebar content width matched to canvas width."""
        self.sidebar_canvas.itemconfigure(self.sidebar_window, width=event.width)

    def _on_sidebar_mousewheel(self, event):
        """Scroll sidebar with mouse wheel."""
        if getattr(event, "num", None) == 4:
            direction = -1
        elif getattr(event, "num", None) == 5:
            direction = 1
        else:
            delta = getattr(event, "delta", 0)
            direction = -1 if delta > 0 else 1
        self.sidebar_canvas.yview_scroll(direction, "units")
        return "break"

    def _activate_sidebar_mousewheel(self, event=None):
        """Route wheel events to the sidebar while the pointer is over it."""
        self.root.bind_all("<MouseWheel>", self._on_sidebar_mousewheel)
        self.root.bind_all("<Button-4>", self._on_sidebar_mousewheel)
        self.root.bind_all("<Button-5>", self._on_sidebar_mousewheel)

    def _deactivate_sidebar_mousewheel(self, event=None):
        """Stop routing global wheel events once the pointer leaves the sidebar."""
        self.root.unbind_all("<MouseWheel>")
        self.root.unbind_all("<Button-4>")
        self.root.unbind_all("<Button-5>")

    def _build_sidebar_navigation(self):
        """Create left-side navigation for notebook pages."""
        c = self.colors
        self.nav_buttons = {}

        title = tk.Label(self.sidebar, text="NAVIGATION", bg=c['card_bg'], fg=c['warning'],
                         font=("Segoe UI Semibold", 9, "bold"), anchor="w")
        title.pack(fill=tk.X, padx=14, pady=(14, 8))

        nav_items = [
            ("⌂  Overview", 0),
            ("◎  Protocols", 1),
            ("⇧  Upload Behavior", 2),
            ("◇  DNS", 3),
            ("▣  TLS", 4),
            ("≋  Sessions", 5),
            ("☰  HTTP Content", 6),
            ("▧  Files & Images", 7),
            ("◌  STUN", 8),
            ("◆  RADIUS", 9),
            ("♙  Subscriber Leaks", 10),
            ("☎  VoIP SIP/RTP", 11),
            ("▣  CCTV", 12),
            ("✧  Satellite", 13),
            ("▤  Raw Data", 14),
        ]

        for label, index in nav_items:
            btn = tk.Label(
                self.sidebar, text=label, anchor="w", cursor="hand2",
                bg=c['card_bg'], fg=c['muted'],
                font=("Segoe UI", 10), padx=14, pady=8)
            btn.pack(fill=tk.X, padx=8, pady=1)
            btn.bind("<Button-1>", lambda e, i=index: self._select_nav(i))
            btn.bind("<Enter>", lambda e, b=btn: self._hover_nav_button(b, True))
            btn.bind("<Leave>", lambda e, b=btn: self._hover_nav_button(b, False))
            btn.bind("<MouseWheel>", self._on_sidebar_mousewheel)
            self.nav_buttons[index] = btn

        tk.Frame(self.sidebar, bg=c['border'], height=1).pack(fill=tk.X, padx=14, pady=(12, 10))
        hint = tk.Label(
            self.sidebar,
            text="Tip: use Quick only for very large captures. Detailed mode keeps upload graphs.",
            bg=c['card_bg'], fg=c['muted'], wraplength=170, justify=tk.LEFT,
            font=("Segoe UI", 8))
        hint.pack(fill=tk.X, padx=14, pady=(0, 12))

        export_btn = tk.Label(
            self.sidebar, text="⇩  Export Report", anchor="w", cursor="hand2",
            bg=c['surface2'], fg=c['fg'], font=("Segoe UI Semibold", 9, "bold"),
            padx=14, pady=8)
        export_btn.pack(fill=tk.X, padx=10, pady=(0, 12), side=tk.BOTTOM)
        export_btn.bind("<Button-1>", lambda e: self.export_results())
        export_btn.bind("<MouseWheel>", self._on_sidebar_mousewheel)

        self.notebook.bind("<<NotebookTabChanged>>", lambda e: self._sync_nav_selection())
        self._sync_nav_selection()

    def _build_sidebar_navigation(self):
        """Create website-style left navigation for notebook pages."""
        c = self.colors
        self.nav_buttons = {}

        title = tk.Label(self.sidebar, text="NAVIGATION", bg=c['card_bg'], fg=c['teal'],
                         font=("Segoe UI Semibold", 9, "bold"), anchor="w")
        title.pack(fill=tk.X, padx=18, pady=(18, 10))

        nav_items = [
            ("Overview", 0),
            ("Protocols", 1),
            ("Upload Behavior", 2),
            ("DNS", 3),
            ("TLS", 4),
            ("Sessions", 5),
            ("HTTP Content", 6),
            ("Files & Images", 7),
            ("STUN", 8),
            ("RADIUS", 9),
            ("Subscriber Leaks", 10),
            ("VoIP SIP/RTP", 11),
            ("CCTV", 12),
            ("Satellite", 13),
            ("Raw Data", 14),
        ]

        for label, index in nav_items:
            btn = tk.Label(
                self.sidebar, text=label, anchor="w", cursor="hand2",
                bg=c['card_bg'], fg=c['muted'],
                font=("Segoe UI", 10), padx=18, pady=10)
            btn.pack(fill=tk.X, padx=10, pady=2)
            btn.bind("<Button-1>", lambda e, i=index: self._select_nav(i))
            btn.bind("<Enter>", lambda e, b=btn: self._hover_nav_button(b, True))
            btn.bind("<Leave>", lambda e, b=btn: self._hover_nav_button(b, False))
            btn.bind("<MouseWheel>", self._on_sidebar_mousewheel)
            self.nav_buttons[index] = btn

        tk.Frame(self.sidebar, bg=c['border'], height=1).pack(fill=tk.X, padx=18, pady=(14, 12))
        hint = tk.Label(
            self.sidebar,
            text="Detailed mode keeps upload graphs. Use Quick only for very large captures.",
            bg=c['card_bg'], fg=c['muted'], wraplength=200, justify=tk.LEFT,
            font=("Segoe UI", 8))
        hint.pack(fill=tk.X, padx=18, pady=(0, 14))

        export_btn = tk.Label(
            self.sidebar, text="Export Report", anchor="w", cursor="hand2",
            bg=c['surface2'], fg=c['fg'], font=("Segoe UI Semibold", 9, "bold"),
            padx=18, pady=11)
        export_btn.pack(fill=tk.X, padx=12, pady=(0, 14), side=tk.BOTTOM)
        export_btn.bind("<Button-1>", lambda e: self.export_results())
        export_btn.bind("<MouseWheel>", self._on_sidebar_mousewheel)

        self.notebook.bind("<<NotebookTabChanged>>", lambda e: self._sync_nav_selection())
        self._sync_nav_selection()

    def _select_nav(self, index):
        """Select a content page from the sidebar."""
        try:
            self.notebook.select(index)
        except tk.TclError:
            return
        self._sync_nav_selection()

    def _hover_nav_button(self, button, active):
        """Subtle hover state for sidebar labels."""
        if getattr(button, "_selected", False):
            return
        button.configure(bg=self.colors['surface2'] if active else self.colors['card_bg'],
                         fg=self.colors['fg'] if active else self.colors['muted'])

    def _sync_nav_selection(self):
        """Reflect current notebook page in the sidebar."""
        try:
            current = self.notebook.index(self.notebook.select())
        except tk.TclError:
            current = 0
        for index, btn in getattr(self, "nav_buttons", {}).items():
            selected = index == current
            btn._selected = selected
            btn.configure(
                bg=self.colors['selection'] if selected else self.colors['card_bg'],
                fg=self.colors['accent'] if selected else self.colors['muted'],
                font=("Segoe UI Semibold", 10, "bold") if selected else ("Segoe UI", 10))

    def _build_sidebar_navigation(self):
        """Create compact text navigation within the narrow sidebar."""
        c = self.colors
        self.nav_buttons = {}
        self.nav_tooltip = None

        tk.Frame(self.sidebar, bg=c['accent'], width=4, height=58).pack(
            anchor="n", pady=(10, 8))

        nav_items = [
            ("Overview", "Overview", 0),
            ("Protocol", "Protocols", 1),
            ("Upload", "Upload Behavior", 2),
            ("CONTENT", None, None),
            ("DNS", "DNS", 3),
            ("TLS", "TLS", 4),
            ("Session", "Sessions", 5),
            ("HTTP", "HTTP Content", 6),
            ("Files", "Files & Images", 7),
            ("IDENTITY", None, None),
            ("STUN", "STUN", 8),
            ("RADIUS", "RADIUS", 9),
            ("SS7", "SS7 Signaling", 10),
            ("Sub Leak", "Subscriber Leaks", 11),
            ("VoIP", "VoIP SIP/RTP", 12),
            ("SIGNAL", None, None),
            ("CCTV", "CCTV", 13),
            ("Satellite", "Satellite", 14),
            ("Raw", "Raw Data", 15),
        ]
        self._page_names = {index: label for _, label, index in nav_items if index is not None}

        for short_label, label, index in nav_items:
            if index is None:
                section = tk.Label(
                    self.sidebar, text=short_label, anchor="center",
                    bg=c['card_bg'], fg=c['muted'],
                    font=("Segoe UI Semibold", 6, "bold"),
                    padx=0, pady=2)
                section.pack(fill=tk.X, padx=4, pady=(7, 1))
                section.bind("<Enter>", self._activate_sidebar_mousewheel)
                section.bind("<Leave>", self._deactivate_sidebar_mousewheel)
                section.bind("<MouseWheel>", self._on_sidebar_mousewheel)
                continue
            btn = tk.Label(
                self.sidebar, text=short_label, anchor="center", cursor="hand2",
                bg=c['card_bg'], fg=c['muted'],
                font=("Segoe UI Semibold", 7, "bold"), padx=0, pady=6,
                wraplength=56, justify=tk.CENTER)
            btn._tooltip_text = label
            btn.pack(fill=tk.X, padx=5, pady=1)
            btn.bind("<Button-1>", lambda e, i=index: self._select_nav(i))
            btn.bind("<Enter>", lambda e, b=btn: self._hover_nav_button(b, True))
            btn.bind("<Leave>", lambda e, b=btn: self._hover_nav_button(b, False))
            btn.bind("<MouseWheel>", self._on_sidebar_mousewheel)
            self.nav_buttons[index] = btn

        tk.Frame(self.sidebar, bg=c['border'], height=1).pack(fill=tk.X, padx=12, pady=(12, 10))
        export_btn = tk.Label(
            self.sidebar, text="Export", anchor="center", cursor="hand2",
            bg=c['surface2'], fg=c['fg'], font=("Segoe UI Semibold", 7, "bold"),
            padx=0, pady=9, wraplength=56, justify=tk.CENTER)
        export_btn._tooltip_text = "Export Report"
        export_btn.pack(fill=tk.X, padx=8, pady=(0, 12), side=tk.BOTTOM)
        export_btn.bind("<Button-1>", lambda e: self.export_results())
        export_btn.bind("<Enter>", lambda e, b=export_btn: self._hover_nav_button(b, True))
        export_btn.bind("<Leave>", lambda e, b=export_btn: self._hover_nav_button(b, False))
        export_btn.bind("<MouseWheel>", self._on_sidebar_mousewheel)

        self.notebook.bind("<<NotebookTabChanged>>", lambda e: self._sync_nav_selection())
        self._sync_nav_selection()

    def _show_nav_tooltip(self, widget):
        """Show the module name beside an icon-only sidebar item."""
        self._hide_nav_tooltip()
        text = getattr(widget, "_tooltip_text", "")
        if not text:
            return
        x = widget.winfo_rootx() + widget.winfo_width() + 10
        y = widget.winfo_rooty() + max(0, (widget.winfo_height() - 30) // 2)
        tip = tk.Toplevel(self.root)
        tip.wm_overrideredirect(True)
        tip.wm_geometry(f"+{x}+{y}")
        label = tk.Label(
            tip, text=text, bg=self.colors['surface2'], fg=self.colors['fg'],
            font=("Segoe UI Semibold", 9), padx=12, pady=7,
            highlightthickness=1, highlightbackground=self.colors['border'])
        label.pack()
        self.nav_tooltip = tip

    def _hide_nav_tooltip(self):
        """Hide sidebar tooltip if it is visible."""
        tip = getattr(self, "nav_tooltip", None)
        if tip is not None:
            try:
                tip.destroy()
            except tk.TclError:
                pass
        self.nav_tooltip = None

    def _hover_nav_button(self, button, active):
        """Hover state and tooltip for compact sidebar icons."""
        if active:
            self._activate_sidebar_mousewheel()
            self._show_nav_tooltip(button)
        else:
            self._hide_nav_tooltip()
            self._deactivate_sidebar_mousewheel()
        if getattr(button, "_selected", False):
            return
        button.configure(bg=self.colors['surface2'] if active else self.colors['card_bg'],
                         fg=self.colors['fg'] if active else self.colors['muted'])

    def _sync_nav_selection(self):
        """Reflect current notebook page in the compact sidebar."""
        try:
            current = self.notebook.index(self.notebook.select())
        except tk.TclError:
            current = 0
        page_name = getattr(self, "_page_names", {}).get(current)
        if page_name and hasattr(self, "current_page_label"):
            self.current_page_label.config(text=page_name)
        for index, btn in getattr(self, "nav_buttons", {}).items():
            selected = index == current
            btn._selected = selected
            btn.configure(
                bg=self.colors['selection'] if selected else self.colors['card_bg'],
                fg="#ffffff" if selected else self.colors['muted'])
        
    def create_file_section(self, parent):
        """Create the file selection section"""
        file_frame = ttk.LabelFrame(parent, text=" Capture Source ", padding=(10, 6))
        file_frame.pack(fill=tk.X, pady=(0, 6))

        command_row = ttk.Frame(file_frame)
        command_row.pack(fill=tk.X)

        # File path entry
        ttk.Entry(command_row, textvariable=self.pcap_file).pack(
            side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))

        # Browse / source actions
        ttk.Button(command_row, text="Browse", command=self.browse_pcap,
                   style='Compact.TButton').pack(side=tk.LEFT, padx=(0, 6))
        ttk.Button(command_row, text="Open URL...", command=self.open_shared_url,
                   style='Compact.TButton').pack(side=tk.LEFT, padx=(0, 6))
        ttk.Button(command_row, text="Merge Files\u2026", command=self.open_merge_dialog,
                   style='Compact.TButton').pack(side=tk.LEFT, padx=(0, 6))

        # Analyze button and mode
        self.analyze_btn = ttk.Button(command_row, text="\u25B6  Analyze",
                                      command=self.run_full_analysis, style='Accent.TButton')
        self.analyze_btn.pack(side=tk.LEFT, padx=(0, 6))
        self.quick_mode = tk.BooleanVar(value=False)
        quick_check = ttk.Checkbutton(command_row, text="Quick", variable=self.quick_mode)
        quick_check.pack(side=tk.LEFT, padx=(0, 10))

        # Progress section on its own row to keep the command bar readable
        progress_row = tk.Frame(file_frame, bg=self.colors['bg'])
        progress_row.pack(fill=tk.X, pady=(5, 0))
        
        # Progress info label
        self.progress_info = tk.Label(progress_row, text="", font=("Segoe UI Semibold", 8),
                                       bg=self.colors['bg'], fg=self.colors['accent'])
        self.progress_info.pack(side=tk.LEFT, anchor=tk.W)

        self.progress_pct = tk.Label(progress_row, text="0%", font=("Segoe UI", 8, "bold"),
                                      bg=self.colors['bg'], fg=self.colors['success'])
        self.progress_pct.pack(side=tk.RIGHT, padx=(10, 0))

        self.progress = ttk.Progressbar(file_frame, mode='determinate', maximum=100)
        self.progress.pack(fill=tk.X, pady=(2, 0))
        
    def create_overview_tab(self):
        """Create the overview/summary tab"""
        overview_frame = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(overview_frame, text=" Overview ")
        
        # Stats cards row
        cards_frame = ttk.Frame(overview_frame)
        cards_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Create stat cards
        self.stat_cards = {}
        stats = [
            ("Total Packets", "0", self.colors['accent']),
            ("Total Bytes", "0 B", self.colors['success']),
            ("Duration", "0s", self.colors['warning']),
            ("Unique IPs", "0", self.colors['rose']),
            ("Protocols", "0", self.colors['teal'])
        ]
        
        for i, (label, value, color) in enumerate(stats):
            card = self.create_stat_card(cards_frame, label, value, color)
            card.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
            self.stat_cards[label] = card
            
        # Summary text area
        summary_frame = ttk.LabelFrame(overview_frame, text=" Analysis Summary ", padding=10)
        summary_frame.pack(fill=tk.BOTH, expand=True)
        
        self.summary_text = tk.Text(summary_frame, height=20, wrap=tk.WORD, font=("Consolas", 10),
                                    bg=self.colors['card_bg'], fg=self.colors['fg'], insertbackground=self.colors['fg'])
        summary_scroll = ttk.Scrollbar(summary_frame, orient=tk.VERTICAL, command=self.summary_text.yview)
        self.summary_text.configure(yscrollcommand=summary_scroll.set)
        
        self.summary_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        summary_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.summary_text.insert("1.0", "Load a PCAP file to begin analysis...")
        self.summary_text.config(state=tk.DISABLED)
        
    def create_stat_card(self, parent, label, value, color):
        """Create a warm modern statistics card widget."""
        # Outer wrapper acts as a 1px border via background bleed
        card = tk.Frame(parent, bg=self.colors['border'])
        card.pack_propagate(False)
        card.configure(height=120)

        # Colored accent bar on top
        accent_bar = tk.Frame(card, bg=color, height=4)
        accent_bar.pack(fill=tk.X, side=tk.TOP)

        inner = tk.Frame(card, bg=self.colors['card_bg'], padx=18, pady=16)
        inner.pack(fill=tk.BOTH, expand=True)

        # Description label (small, muted, on top)
        desc_label = tk.Label(inner, text=label.upper(), font=("Segoe UI Semibold", 9, "bold"),
                              bg=self.colors['card_bg'], fg=self.colors['muted'],
                              anchor="w")
        desc_label.pack(fill=tk.X, anchor=tk.W)

        # Value label (large, colored)
        value_label = tk.Label(inner, text=value, font=("Segoe UI Semibold", 25, "bold"),
                               bg=self.colors['card_bg'], fg=color, anchor="w")
        value_label.pack(fill=tk.X, anchor=tk.W, pady=(7, 0))

        # Store references for updating
        card.value_label = value_label
        card.desc_label = desc_label

        return card
        
    def create_protocol_tab(self):
        """Create the protocol analysis tab"""
        protocol_frame = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(protocol_frame, text=" Protocols ")

        bar = ttk.Frame(protocol_frame)
        bar.pack(fill=tk.X, pady=(0, 6))
        ttk.Button(bar, text="Export Protocols...", style='Compact.TButton',
                   command=self.export_protocols).pack(side=tk.RIGHT)
        
        # Split into left (tree) and right (details)
        paned = ttk.PanedWindow(protocol_frame, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True)
        
        # Left - Protocol tree
        left_frame = ttk.LabelFrame(paned, text=" Protocol Distribution ", padding=5)
        paned.add(left_frame, weight=1)
        
        # Treeview for protocols
        columns = ("Protocol", "Packets", "Bytes", "Percentage")
        self.protocol_tree = ttk.Treeview(left_frame, columns=columns, show="headings", height=20)
        self._setup_tree_columns(
            self.protocol_tree, columns, widths=(160, 110, 120, 110),
            numeric_cols=("Packets", "Bytes", "Percentage"))
        self._add_tree_scrollbars(left_frame, self.protocol_tree)
        
        # Right - Protocol details
        right_frame = ttk.LabelFrame(paned, text=" Protocol Details ", padding=5)
        paned.add(right_frame, weight=1)
        
        self.protocol_details = tk.Text(right_frame, wrap=tk.WORD, font=("Consolas", 10),
                                        bg=self.colors['card_bg'], fg=self.colors['fg'])
        proto_detail_scroll = ttk.Scrollbar(right_frame, orient=tk.VERTICAL, command=self.protocol_details.yview)
        self.protocol_details.configure(yscrollcommand=proto_detail_scroll.set)
        
        self.protocol_details.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        proto_detail_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Bind selection event
        self.protocol_tree.bind("<<TreeviewSelect>>", self.on_protocol_select)
        
    def create_upload_tab(self):
        """Upload behavior tab: nested sessions -> upload events + I/O graph"""
        upload_frame = ttk.Frame(self.notebook, padding=8)
        self.notebook.add(upload_frame, text=" Upload Behavior ")

        # ---- Configurable detection parameters (compact single row) ----
        cfg = ttk.Frame(upload_frame)
        cfg.pack(fill=tk.X, pady=(0, 6))

        def add_cfg(parent, label, default, width=5):
            ttk.Label(parent, text=label, style='Compact.TLabel').pack(side=tk.LEFT, padx=(8, 2))
            e = ttk.Entry(parent, width=width, style='Compact.TEntry')
            e.insert(0, str(default))
            e.pack(side=tk.LEFT)
            return e

        self.cfg_bucket = add_cfg(cfg, "Bucket(s):", "1.0")
        self.cfg_min_payload = add_cfg(cfg, "Min Payload(B):", "5000", 7)
        self.cfg_min_duration = add_cfg(cfg, "Min Dur(s):", "2.0")
        self.cfg_idle_gap = add_cfg(cfg, "Idle Gap(s):", "4.0")
        self.cfg_bps_threshold = add_cfg(cfg, "Bytes/s:", "2000", 7)
        self.cfg_min_ratio = add_cfg(cfg, "Up:Down:", "1.0")

        ttk.Button(cfg, text="Detect Uploads", style='Compact.TButton',
                   command=self.detect_uploads).pack(side=tk.LEFT, padx=(14, 0))
        # keep legacy attr used elsewhere
        self.upload_threshold = self.cfg_min_payload

        # ---- Main split: left tree, right details+graph ----
        main_paned = ttk.PanedWindow(upload_frame, orient=tk.HORIZONTAL)
        main_paned.pack(fill=tk.BOTH, expand=True)

        # Left: nested Session -> Upload Event tree
        left = ttk.LabelFrame(main_paned, text=" Sessions -> Upload Events ", padding=4)
        main_paned.add(left, weight=3)

        columns = ("Detail", "Proto", "Server/SNI", "Streams", "Events",
                   "Upload", "Download", "Duration", "Conf")
        self.upload_tree = ttk.Treeview(left, columns=columns, show="tree headings", height=18)
        col_widths = {"Detail": 0, "Proto": 55, "Server/SNI": 160, "Streams": 90,
                      "Events": 55, "Upload": 85, "Download": 85, "Duration": 70, "Conf": 45}
        self._setup_tree_columns(
            self.upload_tree, columns,
            widths=[col_widths.get(c, 80) for c in columns],
            numeric_cols=("Streams", "Events", "Upload", "Download", "Duration", "Conf"),
            stretch_cols=("Server/SNI",),
            tree_heading="Session / Upload Event", tree_width=180)
        self._add_tree_scrollbars(left, self.upload_tree)

        # Right: vertical split of graph (top) + details (bottom)
        right = ttk.PanedWindow(main_paned, orient=tk.VERTICAL)
        main_paned.add(right, weight=2)

        graph_frame = ttk.LabelFrame(right, text=" I/O Graph (select a session) ", padding=4)
        right.add(graph_frame, weight=3)
        self.graph_container = graph_frame
        self.io_canvas = None
        if not HAS_MATPLOTLIB:
            ttk.Label(graph_frame,
                      text="matplotlib not available - install it for graphs").pack()

        details_frame = ttk.LabelFrame(right, text=" Details ", padding=4)
        right.add(details_frame, weight=2)
        self.session_details = tk.Text(details_frame, height=10, wrap=tk.WORD,
                                        font=("Consolas", 9),
                                        bg=self.colors['card_bg'], fg=self.colors['fg'])
        detail_scroll = ttk.Scrollbar(details_frame, orient=tk.VERTICAL,
                                       command=self.session_details.yview)
        self.session_details.configure(yscrollcommand=detail_scroll.set)
        self.session_details.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        detail_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        self.upload_tree.bind("<<TreeviewSelect>>", self.on_upload_session_select)
        
    def create_dns_tab(self):
        """Create the DNS analysis tab"""
        dns_frame = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(dns_frame, text=" DNS ")
        
        # Split view
        paned = ttk.PanedWindow(dns_frame, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True)
        
        # Left - DNS queries
        left_frame = ttk.LabelFrame(paned, text=" DNS Queries ", padding=5)
        paned.add(left_frame, weight=1)
        
        columns = ("Domain", "Query Type", "Response", "Count")
        self.dns_tree = ttk.Treeview(left_frame, columns=columns, show="headings", height=20)
        self._setup_tree_columns(
            self.dns_tree, columns, widths=(260, 110, 260, 90),
            numeric_cols=("Count",), stretch_cols=("Domain", "Response"))
        self._add_tree_scrollbars(left_frame, self.dns_tree)
        
        # Right - DNS stats
        right_frame = ttk.LabelFrame(paned, text=" DNS Statistics ", padding=5)
        paned.add(right_frame, weight=1)
        
        self.dns_stats = tk.Text(right_frame, wrap=tk.WORD, font=("Consolas", 10),
                                 bg=self.colors['card_bg'], fg=self.colors['fg'])
        dns_stats_scroll = ttk.Scrollbar(right_frame, orient=tk.VERTICAL, command=self.dns_stats.yview)
        self.dns_stats.configure(yscrollcommand=dns_stats_scroll.set)
        
        self.dns_stats.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        dns_stats_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
    def create_tls_tab(self):
        """Create the TLS analysis tab"""
        tls_frame = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(tls_frame, text=" TLS ")
        
        # TLS connections tree
        columns = ("Server Name", "TLS Version", "Cipher Suite", "Certificate", "Count")
        self.tls_tree = ttk.Treeview(tls_frame, columns=columns, show="headings", height=25)
        self._setup_tree_columns(
            self.tls_tree, columns, widths=(260, 120, 280, 180, 90),
            numeric_cols=("Count",), stretch_cols=("Server Name", "Cipher Suite"))
        self._add_tree_scrollbars(tls_frame, self.tls_tree)
        
    def create_sessions_tab(self):
        """Create the sessions/flows tab"""
        sessions_frame = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(sessions_frame, text=" Sessions ")
        
        # Filter controls
        filter_frame = ttk.Frame(sessions_frame)
        filter_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(filter_frame, text="Filter:").pack(side=tk.LEFT)
        self.session_filter = ttk.Entry(filter_frame, width=40)
        self.session_filter.pack(side=tk.LEFT, padx=5)
        ttk.Button(filter_frame, text="Apply", command=self.filter_sessions).pack(side=tk.LEFT)
        
        # Sessions tree
        columns = ("Session ID", "Src IP", "Src Port", "Dst IP", "Dst Port", "Protocol", "Packets", "Bytes", "Duration")
        self.sessions_tree = ttk.Treeview(sessions_frame, columns=columns, show="headings", height=20)
        self._setup_tree_columns(
            self.sessions_tree, columns,
            widths=(110, 150, 80, 150, 80, 90, 100, 110, 100),
            numeric_cols=("Src Port", "Dst Port", "Packets", "Bytes", "Duration"))
        self._add_tree_scrollbars(sessions_frame, self.sessions_tree)
        
    def create_raw_data_tab(self):
        """Create the raw data/packets tab"""
        raw_frame = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(raw_frame, text=" Raw Data ")
        
        # Raw output text
        self.raw_text = tk.Text(raw_frame, wrap=tk.NONE, font=("Consolas", 9),
                                bg=self.colors['card_bg'], fg=self.colors['fg'])
        
        # Scrollbars
        raw_scroll_y = ttk.Scrollbar(raw_frame, orient=tk.VERTICAL, command=self.raw_text.yview)
        raw_scroll_x = ttk.Scrollbar(raw_frame, orient=tk.HORIZONTAL, command=self.raw_text.xview)
        self.raw_text.configure(yscrollcommand=raw_scroll_y.set, xscrollcommand=raw_scroll_x.set)
        
        raw_scroll_y.pack(side=tk.RIGHT, fill=tk.Y)
        raw_scroll_x.pack(side=tk.BOTTOM, fill=tk.X)
        self.raw_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

    def create_http_tab(self):
        """HTTP content / potential data-leak inspection tab."""
        http_frame = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(http_frame, text=" HTTP Content ")

        bar = ttk.Frame(http_frame)
        bar.pack(fill=tk.X, pady=(0, 6))
        self.http_summary = tk.Label(bar, text="HTTP transactions: 0",
                                     font=("Segoe UI", 9, "bold"),
                                     bg=self.colors['bg'], fg=self.colors['accent'])
        self.http_summary.pack(side=tk.LEFT)
        ttk.Button(bar, text="Export HTTP...", style='Compact.TButton',
                   command=self.export_http).pack(side=tk.RIGHT)

        paned = ttk.PanedWindow(http_frame, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True)

        left = ttk.LabelFrame(paned, text=" HTTP Transactions ", padding=5)
        paned.add(left, weight=3)
        cols = ("no", "time", "method", "host", "uri", "code", "type",
                "length", "cred")
        headings = ("#", "Time", "Method", "Host", "URI/Location",
                    "Status", "Content-Type", "Length", "Leak")
        widths = (50, 130, 65, 150, 240, 60, 130, 80, 120)
        self.http_tree = ttk.Treeview(left, columns=cols, show="headings", height=18)
        self._setup_tree_columns(
            self.http_tree, cols, headings, widths,
            numeric_cols=("no", "code", "length"), stretch_cols=("uri",))
        self._add_tree_scrollbars(left, self.http_tree)
        self.http_tree.tag_configure("leak", foreground=self.colors['danger'])
        self.http_tree.tag_configure("plain", foreground=self.colors['warning'])

        right = ttk.LabelFrame(paned, text=" Request / Response Content ", padding=5)
        paned.add(right, weight=2)
        self.http_detail = tk.Text(right, wrap=tk.WORD, font=("Consolas", 9),
                                   bg=self.colors['card_bg'], fg=self.colors['fg'])
        hds = ttk.Scrollbar(right, orient=tk.VERTICAL, command=self.http_detail.yview)
        self.http_detail.configure(yscrollcommand=hds.set)
        self.http_detail.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        hds.pack(side=tk.RIGHT, fill=tk.Y)
        self.http_tree.bind("<<TreeviewSelect>>", self.on_http_select)

    def create_files_tab(self):
        """Extracted HTTP files / binary content + image preview tab."""
        files_frame = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(files_frame, text=" Files & Images ")

        bar = ttk.Frame(files_frame)
        bar.pack(fill=tk.X, pady=(0, 6))
        self.files_summary = tk.Label(bar, text="Extracted files: 0   Images: 0",
                                      font=("Segoe UI", 9, "bold"),
                                      bg=self.colors['bg'], fg=self.colors['accent'])
        self.files_summary.pack(side=tk.LEFT)
        ttk.Button(bar, text="Save Selected", style='Compact.TButton',
                   command=self.save_extracted_file).pack(side=tk.LEFT, padx=4)
        ttk.Button(bar, text="View Image", style='Compact.TButton',
                   command=self.view_extracted_image).pack(side=tk.LEFT, padx=4)

        paned = ttk.PanedWindow(files_frame, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True)

        left = ttk.LabelFrame(paned, text=" Extracted HTTP Content ", padding=5)
        paned.add(left, weight=3)
        cols = ("no", "frame", "time", "src", "dst", "code", "type", "size", "ext", "uri")
        headings = ("#", "Frame", "Time", "Source", "Destination", "Status",
                    "Content-Type", "Size", "Ext", "URI")
        widths = (40, 70, 130, 140, 140, 60, 150, 80, 60, 280)
        self.files_tree = ttk.Treeview(left, columns=cols, show="headings", height=18)
        self._setup_tree_columns(
            self.files_tree, cols, headings, widths,
            numeric_cols=("no", "frame", "code", "size"), stretch_cols=("uri",))
        self._add_tree_scrollbars(left, self.files_tree)
        self.files_tree.tag_configure("image", foreground=self.colors['success'])
        self.files_tree.bind("<<TreeviewSelect>>", self.on_files_select)

        right = ttk.LabelFrame(paned, text=" Preview ", padding=5)
        paned.add(right, weight=2)
        self.image_preview = tk.Label(right, text="Select an extracted image to preview",
                                      bg=self.colors['card_bg'], fg=self.colors['muted'],
                                      justify=tk.CENTER, wraplength=300)
        self.image_preview.pack(fill=tk.BOTH, expand=True)

        self.files_detail = tk.Text(right, wrap=tk.WORD, font=("Consolas", 9),
                                    bg=self.colors['card_bg'], fg=self.colors['fg'],
                                    height=8)
        fds = ttk.Scrollbar(right, orient=tk.VERTICAL, command=self.files_detail.yview)
        self.files_detail.configure(yscrollcommand=fds.set)
        self.files_detail.pack(fill=tk.X, pady=(4, 0))
        fds.pack(fill=tk.X)

    def create_stun_tab(self):
        """STUN/TURN transaction and application-identification tab."""
        stun_frame = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(stun_frame, text=" STUN ")

        bar = ttk.Frame(stun_frame)
        bar.pack(fill=tk.X, pady=(0, 6))
        self.stun_summary = tk.Label(bar, text="STUN packets: 0   Transactions: 0",
                                     font=("Segoe UI", 9, "bold"),
                                     bg=self.colors['bg'], fg=self.colors['accent'])
        self.stun_summary.pack(side=tk.LEFT)
        ttk.Button(bar, text="Export STUN...", style='Compact.TButton',
                   command=self.export_stun).pack(side=tk.RIGHT)

        paned = ttk.PanedWindow(stun_frame, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True)

        left = ttk.LabelFrame(paned, text=" STUN Transactions ", padding=5)
        paned.add(left, weight=3)
        cols = ("txid", "app", "frames", "packets", "methods", "src", "dst",
                "mapped", "username", "software", "rtt")
        headings = ("VID / Transaction ID", "Application", "Frames", "Packets",
                    "Method/Class", "Source", "Destination", "Mapped Address",
                    "Username", "Software", "RTT (ms)")
        widths = (230, 150, 130, 80, 150, 170, 170, 170, 180, 180, 90)
        self.stun_tree = ttk.Treeview(left, columns=cols, show="headings", height=18)
        self._setup_tree_columns(
            self.stun_tree, cols, headings, widths,
            numeric_cols=("packets", "rtt"), stretch_cols=("txid", "username", "software"))
        self._add_tree_scrollbars(left, self.stun_tree)
        self.stun_tree.bind("<<TreeviewSelect>>", self.on_stun_select)

        right = ttk.LabelFrame(paned, text=" Transaction Detail ", padding=5)
        paned.add(right, weight=2)
        self.stun_detail = tk.Text(right, wrap=tk.WORD, font=("Consolas", 9),
                                   bg=self.colors['card_bg'], fg=self.colors['fg'])
        sds = ttk.Scrollbar(right, orient=tk.VERTICAL, command=self.stun_detail.yview)
        self.stun_detail.configure(yscrollcommand=sds.set)
        self.stun_detail.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sds.pack(side=tk.RIGHT, fill=tk.Y)

    def create_radius_tab(self):
        """RADIUS packet extraction and CSID/ECI correlation tab."""
        radius_frame = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(radius_frame, text=" RADIUS ")

        top_bar = ttk.Frame(radius_frame)
        top_bar.pack(fill=tk.X, pady=(0, 6))
        self.radius_summary = tk.Label(top_bar, text="RADIUS packets: 0   CSID/ECI correlations: 0",
                                       font=("Segoe UI", 9, "bold"),
                                       bg=self.colors['bg'], fg=self.colors['accent'])
        self.radius_summary.pack(side=tk.LEFT)
        ttk.Button(top_bar, text="Export RADIUS...", style='Compact.TButton',
                   command=self.export_radius).pack(side=tk.RIGHT)

        vpaned = ttk.PanedWindow(radius_frame, orient=tk.VERTICAL)
        vpaned.pack(fill=tk.BOTH, expand=True)

        pkt_frame = ttk.LabelFrame(vpaned, text=" RADIUS Packets ", padding=5)
        vpaned.add(pkt_frame, weight=3)
        pkt_cols = ("frame", "time", "code", "status", "connection", "src", "dst",
                    "username", "imsi", "imei", "mcc_mnc", "calling_station_id", "called_station_id",
                    "nas_ip", "framed_ip", "nas_port_type", "session_time")
        pkt_headings = ("Frame", "Time", "Code", "Status", "Type", "Source", "Destination",
                        "User-Name", "IMSI", "IMEI / IMEISV", "MCC / MNC",
                        "Calling-Station-Id", "Called-Station-Id",
                        "NAS IP", "Framed IP", "NAS Port Type", "Session Time")
        pkt_widths = (70, 145, 110, 90, 90, 140, 140, 220, 150, 160, 190,
                      180, 180, 140, 140, 130, 110)
        self.radius_tree = ttk.Treeview(pkt_frame, columns=pkt_cols, show="headings", height=10)
        self._setup_tree_columns(
            self.radius_tree, pkt_cols, pkt_headings, pkt_widths,
            numeric_cols=("frame", "session_time"),
            stretch_cols=("username", "mcc_mnc", "calling_station_id", "called_station_id"))
        self._add_tree_scrollbars(pkt_frame, self.radius_tree)
        self.radius_tree.tag_configure("reject", foreground=self.colors['danger'])
        self.radius_tree.tag_configure("accept", foreground=self.colors['success'])
        self.radius_tree.bind("<<TreeviewSelect>>", self.on_radius_select)

        corr_frame = ttk.LabelFrame(vpaned, text=" Calling-Station-Id / ECI Correlation ", padding=5)
        vpaned.add(corr_frame, weight=2)
        cpaned = ttk.PanedWindow(corr_frame, orient=tk.HORIZONTAL)
        cpaned.pack(fill=tk.BOTH, expand=True)

        corr_left = ttk.Frame(cpaned)
        cpaned.add(corr_left, weight=3)
        corr_cols = ("calling_station_id", "eci", "method", "radius_frame", "gtp_frame",
                     "delta", "username", "imsi", "imei", "mcc_mnc", "msisdn", "radius_ip", "gtp_ip")
        corr_headings = ("Calling-Station-Id", "ECI", "Match", "RADIUS Frame", "GTPv2 Frame",
                         "Delta(s)", "User-Name", "IMSI", "IMEI / IMEISV", "MCC / MNC",
                         "MSISDN", "RADIUS IP", "GTPv2 IP")
        corr_widths = (180, 120, 105, 100, 100, 80, 220, 150, 160, 190, 150, 160, 160)
        self.radius_corr_tree = ttk.Treeview(corr_left, columns=corr_cols, show="headings", height=8)
        self._setup_tree_columns(
            self.radius_corr_tree, corr_cols, corr_headings, corr_widths,
            numeric_cols=("radius_frame", "gtp_frame", "delta"),
            stretch_cols=("calling_station_id", "username"))
        self._add_tree_scrollbars(corr_left, self.radius_corr_tree)
        self.radius_corr_tree.bind("<<TreeviewSelect>>", self.on_radius_correlation_select)

        detail_frame = ttk.LabelFrame(cpaned, text=" Detail ", padding=5)
        cpaned.add(detail_frame, weight=2)
        self.radius_detail = tk.Text(detail_frame, wrap=tk.WORD, font=("Consolas", 9),
                                     bg=self.colors['card_bg'], fg=self.colors['fg'])
        rds = ttk.Scrollbar(detail_frame, orient=tk.VERTICAL, command=self.radius_detail.yview)
        self.radius_detail.configure(yscrollcommand=rds.set)
        self.radius_detail.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        rds.pack(side=tk.RIGHT, fill=tk.Y)

    def create_ss7_signaling_tab(self):
        """SS7/SIGTRAN decoded signaling analysis tab."""
        ss7_frame = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(ss7_frame, text=" SS7 ")

        bar = ttk.Frame(ss7_frame)
        bar.pack(fill=tk.X, pady=(0, 6))
        self.ss7_sig_summary = tk.Label(
            bar, text="SS7 packets: 0   MAP: 0   TCAP: 0   SCCP: 0   ISUP: 0",
            font=("Segoe UI", 9, "bold"),
            bg=self.colors['bg'], fg=self.colors['accent'])
        self.ss7_sig_summary.pack(side=tk.LEFT)
        ttk.Button(bar, text="Export SS7...", style='Compact.TButton',
                   command=self.export_ss7_signaling).pack(side=tk.RIGHT)

        paned = ttk.PanedWindow(ss7_frame, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True)

        left = ttk.LabelFrame(paned, text=" Decoded SS7 / SIGTRAN Packets ", padding=5)
        paned.add(left, weight=4)
        cols = ("frame", "time", "stack", "layers", "src", "dst",
                "opc", "dpc", "sls", "calling_gt", "called_gt",
                "calling_ssn", "called_ssn", "tcap_ids", "map_operation",
                "isup_cic", "call_from", "call_to", "imsi", "imei",
                "msisdn", "mcc_mnc", "location", "sms_text", "ussd",
                "result_cause", "info")
        headings = ("Frame", "Time", "Stack", "Layers", "Source", "Destination",
                    "OPC", "DPC", "SLS", "Calling GT", "Called GT",
                    "Calling SSN", "Called SSN", "TCAP IDs", "MAP Operation",
                    "ISUP CIC", "Call From", "Call To", "IMSI", "IMEI",
                    "MSISDN", "MCC / MNC", "Location", "SMS Text", "USSD",
                    "Result / Cause", "Info")
        widths = (75, 145, 115, 150, 135, 135, 80, 80, 60, 160, 160,
                  90, 90, 150, 180, 90, 150, 150, 150, 150, 150,
                  180, 220, 260, 180, 180, 260)
        self.ss7_sig_tree = ttk.Treeview(left, columns=cols, show="headings", height=18)
        self._setup_tree_columns(
            self.ss7_sig_tree, cols, headings, widths,
            numeric_cols=("frame", "opc", "dpc", "sls", "isup_cic"),
            stretch_cols=("info", "sms_text", "location", "map_operation"))
        self._add_tree_scrollbars(left, self.ss7_sig_tree)
        self.ss7_sig_tree.tag_configure("leak", foreground=self.colors['danger'])
        self.ss7_sig_tree.tag_configure("sms", foreground=self.colors['warning'])
        self.ss7_sig_tree.bind("<<TreeviewSelect>>", self.on_ss7_signaling_select)

        right = ttk.LabelFrame(paned, text=" Packet Detail / Raw Decoded Fields ", padding=5)
        paned.add(right, weight=2)
        self.ss7_sig_detail = tk.Text(right, wrap=tk.WORD, font=("Consolas", 9),
                                      bg=self.colors['card_bg'], fg=self.colors['fg'])
        sds = ttk.Scrollbar(right, orient=tk.VERTICAL, command=self.ss7_sig_detail.yview)
        self.ss7_sig_detail.configure(yscrollcommand=sds.set)
        self.ss7_sig_detail.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sds.pack(side=tk.RIGHT, fill=tk.Y)

    def create_ss7_tab(self):
        """Subscriber identifier, SMS, and mobile-core leak tab."""
        ss7_frame = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(ss7_frame, text=" Subscriber Leaks ")

        bar = ttk.Frame(ss7_frame)
        bar.pack(fill=tk.X, pady=(0, 6))
        self.ss7_summary = tk.Label(bar, text="Subscriber leak records: 0   Leaks: 0",
                                    font=("Segoe UI", 9, "bold"),
                                    bg=self.colors['bg'], fg=self.colors['accent'])
        self.ss7_summary.pack(side=tk.LEFT)
        ttk.Button(bar, text="Export Subscriber Leaks...", style='Compact.TButton',
                   command=self.export_ss7).pack(side=tk.RIGHT)

        paned = ttk.PanedWindow(ss7_frame, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True)

        left = ttk.LabelFrame(paned, text=" Subscriber / SMS / BTS Leak Records ", padding=5)
        paned.add(left, weight=3)
        cols = ("frame", "time", "stack", "operation", "leaks",
                "rrc_message", "rrc_domain", "nas_message", "mobile_identity",
                "lai", "classmark", "rrc_context", "radio_context",
                "imsi", "imei", "msisdn", "mcc_mnc", "area_code", "bts_cell", "sms_text", "sms_from",
                "sms_to", "apn", "src", "dst")
        headings = ("Frame", "Time", "Stack", "Operation", "Leaks",
                    "RRC Message", "CN Domain", "NAS / DTAP", "Mobile Identity",
                    "LAI", "Classmark", "RRC Context", "Radio Context",
                    "IMSI", "IMEI / MEI", "MSISDN", "MCC / MNC", "Area Codes", "BTS / Cell / Location",
                    "SMS Text", "SMS From", "SMS To", "APN", "Source", "Destination")
        widths = (70, 145, 140, 160, 170, 150, 100, 190, 180,
                  220, 230, 220, 240, 150, 150, 150, 130, 180, 230,
                  260, 140, 140, 170, 140, 140)
        self.ss7_tree = ttk.Treeview(left, columns=cols, show="headings", height=18)
        self._setup_tree_columns(
            self.ss7_tree, cols, headings, widths,
            numeric_cols=("frame",),
            stretch_cols=("sms_text", "operation", "leaks", "bts_cell", "area_code",
                          "nas_message", "lai", "classmark", "rrc_context", "radio_context"))
        self._add_tree_scrollbars(left, self.ss7_tree)
        self.ss7_tree.tag_configure("critical", foreground=self.colors['danger'])
        self.ss7_tree.tag_configure("warning", foreground=self.colors['warning'])
        self.ss7_tree.bind("<<TreeviewSelect>>", self.on_ss7_select)

        right = ttk.LabelFrame(paned, text=" Record Detail / Summary ", padding=5)
        paned.add(right, weight=2)
        self.ss7_detail = tk.Text(right, wrap=tk.WORD, font=("Consolas", 9),
                                  bg=self.colors['card_bg'], fg=self.colors['fg'])
        sds = ttk.Scrollbar(right, orient=tk.VERTICAL, command=self.ss7_detail.yview)
        self.ss7_detail.configure(yscrollcommand=sds.set)
        self.ss7_detail.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sds.pack(side=tk.RIGHT, fill=tk.Y)

    def create_voip_tab(self):
        """SIP signalling + RTP media stream analysis tab."""
        voip_frame = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(voip_frame, text=" VoIP (SIP/RTP) ")

        # Top bar with summary and buttons
        top_bar = ttk.Frame(voip_frame)
        top_bar.pack(fill=tk.X, pady=(0, 6))
        self.voip_summary = tk.Label(top_bar, text="SIP messages: 0   RTP streams: 0",
                                     font=("Segoe UI", 9, "bold"),
                                     bg=self.colors['bg'], fg=self.colors['accent'])
        self.voip_summary.pack(side=tk.LEFT)

        vpaned = ttk.PanedWindow(voip_frame, orient=tk.VERTICAL)
        vpaned.pack(fill=tk.BOTH, expand=True)

        # SIP signalling
        sip_frame = ttk.LabelFrame(vpaned, text=" SIP Signalling ", padding=5)
        vpaned.add(sip_frame, weight=1)

        # SIP toolbar
        sip_bar = ttk.Frame(sip_frame)
        sip_bar.pack(fill=tk.X, pady=(0, 4))
        ttk.Button(sip_bar, text="Export SIP...", style='Compact.TButton',
                   command=self.export_sip).pack(side=tk.RIGHT, padx=2)

        sip_cols = ("no", "time", "src", "dst", "method", "from", "to", "callid")
        sip_head = ("#", "Time", "Source", "Destination", "Method/Status",
                    "From", "To", "Call-ID")
        sip_w = (50, 120, 150, 150, 130, 170, 170, 200)
        self.sip_tree = ttk.Treeview(sip_frame, columns=sip_cols, show="headings", height=7)
        self._setup_tree_columns(
            self.sip_tree, sip_cols, sip_head, sip_w,
            numeric_cols=("no",), stretch_cols=("callid",))
        self._add_tree_scrollbars(sip_frame, self.sip_tree)

        # RTP media streams
        rtp_frame = ttk.LabelFrame(vpaned, text=" RTP Media Streams ", padding=5)
        vpaned.add(rtp_frame, weight=1)

        # RTP toolbar
        rtp_bar = ttk.Frame(rtp_frame)
        rtp_bar.pack(fill=tk.X, pady=(0, 4))
        ttk.Button(rtp_bar, text="▶ Play Selected Stream", style='Compact.TButton',
                   command=self.play_rtp_stream).pack(side=tk.LEFT, padx=2)
        ttk.Button(rtp_bar, text="Export as WAV...", style='Compact.TButton',
                   command=self.export_rtp_wav).pack(side=tk.LEFT, padx=2)
        self.rtp_status = tk.Label(rtp_bar, text="", font=("Segoe UI", 8),
                                   bg=self.colors['bg'], fg=self.colors['muted'])
        self.rtp_status.pack(side=tk.LEFT, padx=10)

        rtp_cols = ("ssrc", "src", "dst", "payload", "callid", "media",
                    "packets", "lost", "maxjitter", "duration")
        rtp_head = ("SSRC", "Source", "Destination", "Codec/PT", "SIP Call-ID",
                    "Media Security", "Packets", "Lost", "Max Jitter (ms)", "Wall Time (s)")
        rtp_w = (110, 160, 160, 150, 220, 110, 80, 70, 120, 100)
        self.rtp_tree = ttk.Treeview(rtp_frame, columns=rtp_cols, show="headings", height=7)
        self._setup_tree_columns(
            self.rtp_tree, rtp_cols, rtp_head, rtp_w,
            numeric_cols=("packets", "lost", "maxjitter", "duration"),
            stretch_cols=("callid",))
        self._add_tree_scrollbars(rtp_frame, self.rtp_tree)
        self.rtp_tree.tag_configure("loss", foreground=self.colors['danger'])
        self.rtp_tree.tag_configure("secure", foreground=self.colors['warning'])

    def create_cctv_tab(self):
        """CCTV/RTSP/RTP stream discovery and best-effort video decode tab."""
        cctv_frame = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(cctv_frame, text=" CCTV ")

        bar = ttk.Frame(cctv_frame)
        bar.pack(fill=tk.X, pady=(0, 6))
        self.cctv_summary = tk.Label(bar, text="CCTV records: 0   Verified H.264 RTP: 0",
                                     font=("Segoe UI", 9, "bold"),
                                     bg=self.colors['bg'], fg=self.colors['accent'])
        self.cctv_summary.pack(side=tk.LEFT)
        ttk.Button(bar, text="Open Video", style='Compact.TButton',
                   command=self.open_cctv_video).pack(side=tk.LEFT, padx=4)
        ttk.Button(bar, text="Export CCTV...", style='Compact.TButton',
                   command=self.export_cctv).pack(side=tk.RIGHT)

        paned = ttk.PanedWindow(cctv_frame, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True)

        left = ttk.LabelFrame(paned, text=" CCTV / Video Streams ", padding=5)
        paned.add(left, weight=3)
        cols = ("kind", "frames", "src", "dst", "proto", "codec", "pt",
                "ssrc", "packets", "decoded", "video_file", "notes")
        headings = ("Type", "Frames", "Source", "Destination", "Protocol", "Codec",
                    "PT", "SSRC", "Packets", "Decoded", "Video File", "Notes")
        widths = (90, 120, 150, 150, 95, 100, 60, 110, 80, 80, 240, 260)
        self.cctv_tree = ttk.Treeview(left, columns=cols, show="headings", height=18)
        self._setup_tree_columns(
            self.cctv_tree, cols, headings, widths,
            numeric_cols=("packets", "pt"),
            stretch_cols=("video_file", "notes"))
        self._add_tree_scrollbars(left, self.cctv_tree)
        self.cctv_tree.tag_configure("decoded", foreground=self.colors['success'])
        self.cctv_tree.tag_configure("warning", foreground=self.colors['warning'])
        self.cctv_tree.bind("<<TreeviewSelect>>", self.on_cctv_select)

        right = ttk.LabelFrame(paned, text=" Detail / Decode Notes ", padding=5)
        paned.add(right, weight=2)
        self.cctv_detail = tk.Text(right, wrap=tk.WORD, font=("Consolas", 9),
                                   bg=self.colors['card_bg'], fg=self.colors['fg'])
        cds = ttk.Scrollbar(right, orient=tk.VERTICAL, command=self.cctv_detail.yview)
        self.cctv_detail.configure(yscrollcommand=cds.set)
        self.cctv_detail.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        cds.pack(side=tk.RIGHT, fill=tk.Y)

    def create_satellite_tab(self):
        """Satellite / PCAPNG Custom-Block embedded-JSON telemetry tab."""
        sat_frame = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(sat_frame, text=" Satellite ")

        bar = ttk.Frame(sat_frame)
        bar.pack(fill=tk.X, pady=(0, 6))
        self.sat_summary = tk.Label(bar, text="Custom-block telemetry records: 0",
                                    font=("Segoe UI", 9, "bold"),
                                    bg=self.colors['bg'], fg=self.colors['accent'])
        self.sat_summary.pack(side=tk.LEFT)
        ttk.Button(bar, text="Export CSV/JSON...", style='Compact.TButton',
                   command=self.export_satellite).pack(side=tk.RIGHT)

        paned = ttk.PanedWindow(sat_frame, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True)

        left = ttk.LabelFrame(paned, text=" Telemetry Records ", padding=5)
        paned.add(left, weight=3)
        # Column set is dynamic; start with common satellite fields and grow.
        self._sat_base_cols = ("frame_no", "epoch_time", "id", "type",
                               "satellite-name", "satellite-sub-network-name",
                               "interface", "source", "destination",
                               "frequency-band", "capture_source_file",
                               "extraction_source")
        self.sat_tree = ttk.Treeview(left, columns=self._sat_base_cols,
                                     show="headings", height=18)
        self._setup_tree_columns(
            self.sat_tree, self._sat_base_cols,
            widths=(80, 150, 120, 120, 170, 220, 120, 190, 190, 120, 190, 190),
            numeric_cols=("frame_no", "epoch_time"))
        self._add_tree_scrollbars(left, self.sat_tree)

        right = ttk.LabelFrame(paned, text=" Record Detail / Summary ", padding=5)
        paned.add(right, weight=2)
        self.sat_detail = tk.Text(right, wrap=tk.WORD, font=("Consolas", 9),
                                  bg=self.colors['card_bg'], fg=self.colors['fg'])
        sds = ttk.Scrollbar(right, orient=tk.VERTICAL, command=self.sat_detail.yview)
        self.sat_detail.configure(yscrollcommand=sds.set)
        self.sat_detail.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sds.pack(side=tk.RIGHT, fill=tk.Y)
        self.sat_tree.bind("<<TreeviewSelect>>", self.on_satellite_select)

    def create_status_bar(self):
        """Create the status bar"""
        # Thin top divider
        divider = tk.Frame(self.root, bg=self.colors['border'], height=1)
        divider.pack(fill=tk.X, side=tk.BOTTOM)

        self.status_bar = tk.Frame(self.root, bg=self.colors['card_bg'])
        self.status_bar.pack(fill=tk.X, side=tk.BOTTOM)

        # Accent status indicator dot
        self.status_dot = tk.Label(self.status_bar, text="\u25CF", padx=10, pady=6,
                                    bg=self.colors['card_bg'], fg=self.colors['success'],
                                    font=("Segoe UI", 9))
        self.status_dot.pack(side=tk.LEFT)

        self.status_label = tk.Label(self.status_bar, text="Ready", padx=0, pady=6,
                                     bg=self.colors['card_bg'], fg=self.colors['fg'],
                                     font=("Segoe UI", 9))
        self.status_label.pack(side=tk.LEFT)

        self.file_info_label = tk.Label(self.status_bar, text="", padx=12, pady=6,
                                        bg=self.colors['card_bg'], fg=self.colors['muted'],
                                        font=("Segoe UI", 9))
        self.file_info_label.pack(side=tk.RIGHT)
        
    def browse_pcap(self):
        """Open file dialog to select a single PCAP/PCAPNG file."""
        filename = filedialog.askopenfilename(
            title="Select PCAP File",
            filetypes=[
                ("Capture files", "*.pcap *.pcapng *.cap *.done *.pcapng.gz *.pcap.gz"),
                ("DONE capture files", "*.done"),
                ("All files", "*.*")
            ]
        )
        if filename:
            self._load_single_file(filename)

    def open_shared_url(self):
        """Prompt for a public OneDrive/SharePoint/shared capture URL."""
        win = tk.Toplevel(self.root)
        win.title("Open Shared Capture URL")
        win.transient(self.root)
        win.grab_set()
        win.configure(bg=self.colors['bg'])
        win.geometry("620x150")

        ttk.Label(win, text="Shared URL").pack(anchor=tk.W, padx=12, pady=(12, 4))
        url_var = tk.StringVar(value=self.pcap_file.get() if self._is_url(self.pcap_file.get()) else "")
        entry = ttk.Entry(win, textvariable=url_var, width=90)
        entry.pack(fill=tk.X, padx=12)
        entry.focus_set()

        note = tk.Label(win,
                        text="Public OneDrive/SharePoint download links are supported. Private links may require browser sign-in first.",
                        bg=self.colors['bg'], fg=self.colors['muted'], anchor=tk.W)
        note.pack(fill=tk.X, padx=12, pady=(6, 0))

        buttons = ttk.Frame(win)
        buttons.pack(fill=tk.X, padx=12, pady=12)

        def use_url():
            url = url_var.get().strip()
            if not self._is_url(url):
                messagebox.showwarning("Invalid URL", "Please enter an http or https capture URL.")
                return
            self._load_single_file(url)
            win.destroy()

        ttk.Button(buttons, text="Use URL", command=use_url, style='Accent.TButton').pack(side=tk.RIGHT, padx=(6, 0))
        ttk.Button(buttons, text="Cancel", command=win.destroy).pack(side=tk.RIGHT)
        win.bind("<Return>", lambda _e: use_url())

    def _load_single_file(self, filename):
        """Set the active capture file and update the file info labels."""
        if filename != self.merged_file:
            self.merged_source_files = []
        self.pcap_file.set(filename)
        if self._is_url(filename):
            parsed = urllib.parse.urlparse(filename)
            shown = parsed.netloc or "shared URL"
            self.update_status(f"Loaded shared URL: {shown}")
            self.file_info_label.config(text=f"Shared URL: {shown}")
        else:
            self.update_status(f"Loaded: {os.path.basename(filename)}")
            try:
                size_str = self.format_bytes(os.path.getsize(filename))
            except OSError:
                size_str = "?"
            self.file_info_label.config(text=f"File: {os.path.basename(filename)} ({size_str})")

    @staticmethod
    def _is_url(value):
        parsed = urllib.parse.urlparse(str(value or "").strip())
        return parsed.scheme in ("http", "https") and bool(parsed.netloc)

    @staticmethod
    def _error_text(exc, fallback="Unknown error"):
        text = str(exc or "").strip()
        if not text or text.lower() == "none":
            text = repr(exc)
        if not text or text.lower() == "none":
            text = fallback
        return text

    @staticmethod
    def _shared_download_url(url):
        """Make common shared links prefer file download over browser preview."""
        parsed = urllib.parse.urlparse(url)
        query = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
        host = parsed.netloc.lower()
        if "sharepoint.com" in host and parsed.path.lower().endswith("/forms/allitems.aspx"):
            source_url = query.get("id") or query.get("RootFolder")
            if source_url:
                marker = "/forms/allitems.aspx"
                idx = parsed.path.lower().rfind(marker)
                site_path = parsed.path[:idx] if idx >= 0 else parsed.path.rsplit("/", 2)[0]
                parsed = parsed._replace(
                    path=f"{site_path}/_layouts/15/download.aspx",
                    query=urllib.parse.urlencode({"SourceUrl": source_url}))
                return urllib.parse.urlunparse(parsed)
        if "1drv.ms" in host or "sharepoint.com" in host or "onedrive.live.com" in host:
            query.setdefault("download", "1")
            parsed = parsed._replace(query=urllib.parse.urlencode(query))
        return urllib.parse.urlunparse(parsed)

    @staticmethod
    def _filename_from_response(response, url):
        disp = response.headers.get("Content-Disposition", "")
        match = re.search(r'filename\*?=(?:UTF-8\'\')?"?([^";]+)', disp, re.I)
        if match:
            return urllib.parse.unquote(match.group(1)).strip()
        name = os.path.basename(urllib.parse.urlparse(response.geturl() or url).path)
        return urllib.parse.unquote(name) if name else "shared_capture.pcapng"

    def _prepare_capture_for_analysis(self, pcap_path):
        """Return a local capture path, downloading public shared URLs when needed."""
        if not self._is_url(pcap_path):
            return pcap_path

        url = self._shared_download_url(pcap_path)
        self.root.after(0, lambda: self.progress_info.config(text="Downloading shared capture..."))
        req = urllib.request.Request(url, headers={
            "User-Agent": "Mozilla/5.0 PCAP-Dashboard/1.0",
            "Accept": "application/octet-stream,*/*",
        })
        try:
            with urllib.request.urlopen(req, timeout=120) as response:
                ctype = response.headers.get("Content-Type", "").lower()
                filename = self._filename_from_response(response, url)
                ext = os.path.splitext(filename)[1] or ".pcapng"
                safe_name = re.sub(r"[^A-Za-z0-9._-]+", "_", os.path.splitext(filename)[0]).strip("._") or "shared_capture"
                download_dir = os.path.join(tempfile.gettempdir(), "pcap_dashboard_downloads")
                os.makedirs(download_dir, exist_ok=True)
                dest = os.path.join(download_dir, f"{safe_name}{ext}")
                with open(dest, "wb") as out:
                    shutil.copyfileobj(response, out)
        except urllib.error.HTTPError as e:
            if e.code in (401, 403):
                raise SharedCaptureDownloadError(
                    "SharePoint/OneDrive blocked the download with HTTP 403/401.\n\n"
                    "This usually means the link is private or it is a SharePoint library-view URL, "
                    "not a direct public file download.\n\n"
                    "Use one of these options:\n"
                    "1. Open the link in your browser, download or sync the capture, then Browse to the local .pcapng/.done file.\n"
                    "2. Create a share link that allows anonymous download.\n"
                    "3. Use SharePoint's direct file download link instead of AllItems.aspx."
                ) from e
            reason = e.reason or e.msg or "HTTP error"
            raise SharedCaptureDownloadError(f"Shared URL download failed: HTTP {e.code} {reason}") from e
        except Exception as e:
            raise SharedCaptureDownloadError(
                f"Shared URL download failed: {self._error_text(e, type(e).__name__)}") from e
        if ctype.startswith("text/html") or os.path.getsize(dest) < 64:
            raise SharedCaptureDownloadError(
                "The shared URL returned an HTML page instead of a capture file.\n\n"
                "Open the link in your browser and download/sync the actual .pcapng/.done file, "
                "or use a direct download link.")
        self.root.after(0, lambda: self.file_info_label.config(
            text=f"Downloaded: {os.path.basename(dest)} ({self.format_bytes(os.path.getsize(dest))})"))
        return dest


    # ==================================================================
    #  MULTI-FILE MERGE (validate -> mergecap -> analyze)
    # ==================================================================
    def open_merge_dialog(self):
        """Select multiple captures, validate them, then merge and analyze."""
        files = filedialog.askopenfilenames(
            title="Select Capture Files to Merge (PCAP / PCAPNG / DONE)",
            filetypes=[
                ("Capture files", "*.pcap *.pcapng *.cap *.done *.pcapng.gz *.pcap.gz"),
                ("DONE capture files", "*.done"),
                ("All files", "*.*")
            ]
        )
        files = list(files)
        if not files:
            return
        if len(files) == 1:
            # Nothing to merge - just load the single file
            self._load_single_file(files[0])
            messagebox.showinfo("Single File",
                                "Only one file selected - loaded directly (no merge needed).")
            return

        self.selected_files = files
        self._build_validation_dialog(files)

    def _build_validation_dialog(self, files):
        """Create the validation/merge Toplevel window and kick off validation."""
        dlg = tk.Toplevel(self.root)
        dlg.title(f"Validate & Merge - {len(files)} files")
        dlg.configure(bg=self.colors['bg'])
        dlg.geometry("1150x560")
        dlg.transient(self.root)

        header = tk.Label(dlg, text=f"Pre-merge validation of {len(files)} capture file(s)",
                          font=("Segoe UI Semibold", 13, "bold"),
                          bg=self.colors['bg'], fg=self.colors['fg'])
        header.pack(anchor=tk.W, padx=14, pady=(12, 2))
        sub = tk.Label(dlg,
                       text="Validating with capinfos... originals are never modified.",
                       font=("Segoe UI", 9), bg=self.colors['bg'], fg=self.colors['muted'])
        sub.pack(anchor=tk.W, padx=14, pady=(0, 8))

        # Results table
        table_frame = ttk.Frame(dlg)
        table_frame.pack(fill=tk.BOTH, expand=True, padx=14)
        cols = ("file", "status", "packets", "start", "end", "duration",
                "encap", "precision", "ifaces", "size", "notes")
        headings = ("File", "Status", "Packets", "Start", "End", "Duration (s)",
                    "Encap", "Time Prec.", "Ifaces", "Size", "Notes")
        widths = (200, 90, 80, 150, 150, 95, 70, 90, 60, 90, 220)
        tree = ttk.Treeview(table_frame, columns=cols, show="headings", height=14)
        self._setup_tree_columns(
            tree, cols, headings, widths,
            numeric_cols=("packets", "duration", "ifaces", "size"),
            stretch_cols=("file", "notes"))
        self._add_tree_scrollbars(table_frame, tree)
        tree.tag_configure("ok", foreground=self.colors['success'])
        tree.tag_configure("warn", foreground=self.colors['warning'])
        tree.tag_configure("bad", foreground=self.colors['danger'])

        item_ids = []
        for f in files:
            iid = tree.insert("", tk.END, values=(os.path.basename(f), "queued...",
                                                  "", "", "", "", "", "", "", "", ""))
            item_ids.append(iid)

        # Footer: status + buttons
        footer = ttk.Frame(dlg)
        footer.pack(fill=tk.X, padx=14, pady=10)
        status_var = tk.StringVar(value="Validating...")
        status_lbl = tk.Label(footer, textvariable=status_var, font=("Segoe UI", 9),
                              bg=self.colors['bg'], fg=self.colors['accent'])
        status_lbl.pack(side=tk.LEFT)

        merge_btn = ttk.Button(footer, text="Merge Valid Files & Analyze",
                               style='Accent.TButton', state=tk.DISABLED)
        merge_btn.pack(side=tk.RIGHT, padx=(8, 0))
        ttk.Button(footer, text="Close", command=dlg.destroy).pack(side=tk.RIGHT)

        # Validate in background so the UI stays responsive for many files
        state = {"validations": [None] * len(files)}

        def safe_after(fn):
            # Schedule a UI update that silently no-ops if the dialog/tree was
            # closed by the user before the background worker finished.
            def wrapped():
                try:
                    if dlg.winfo_exists() and tree.winfo_exists():
                        fn()
                except tk.TclError:
                    pass
            self.root.after(0, wrapped)

        def worker():
            valid_count = 0
            for idx, path in enumerate(files):
                safe_after(lambda i=idx: tree.set(item_ids[i], "status", "checking..."))
                info = self._validate_capture(path)
                state["validations"][idx] = info
                if info["ok"]:
                    valid_count += 1

                tag = "ok" if info["ok"] else ("warn" if info["readable"] else "bad")
                vals = (
                    os.path.basename(path),
                    info["status"], info["packets"], info["start"], info["end"],
                    info["duration"], info["encap"], info["precision"],
                    info["ifaces"], info["size"], info["notes"],
                )
                safe_after(lambda i=idx, v=vals, t=tag: (
                    tree.item(item_ids[i], values=v, tags=(t,))))
                safe_after(lambda d=idx + 1: status_var.set(
                    f"Validated {d}/{len(files)}..."))

            def finish():
                ok = valid_count
                bad = len(files) - ok
                status_var.set(f"Done - {ok} valid, {bad} unreadable/problematic.")
                if ok >= 2:
                    merge_btn.config(state=tk.NORMAL)
                    merge_btn.config(command=lambda: self._start_merge(
                        files, state["validations"], dlg, status_var))
                elif ok == 1:
                    status_var.set(f"Done - only 1 valid file; nothing to merge.")
            safe_after(finish)

        threading.Thread(target=worker, daemon=True).start()

    def _validate_capture(self, path):
        """
        Validate a single capture file with capinfos. Returns a dict of
        parsed metadata plus readability / integrity flags. Never modifies
        the source file (capinfos is read-only).
        """
        info = {
            "path": path, "readable": False, "ok": False, "status": "unreadable",
            "packets": "", "start": "", "end": "", "duration": "", "encap": "",
            "precision": "", "ifaces": "", "size": "", "notes": "",
        }
        try:
            size = os.path.getsize(path)
            info["size"] = self.format_bytes(size)
        except OSError:
            info["notes"] = "File not accessible"
            return info

        try:
            proc = subprocess.run([self.capinfos_path, "-M", path],
                                  capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=180)
        except FileNotFoundError:
            info["notes"] = "capinfos not found"
            return info
        except subprocess.TimeoutExpired:
            info["notes"] = "capinfos timed out"
            return info
        except Exception as e:
            info["notes"] = f"capinfos error: {e}"
            return info

        out = proc.stdout or ""
        err = (proc.stderr or "").strip()

        fields = {}
        for line in out.splitlines():
            if ":" in line:
                key, _, val = line.partition(":")
                fields[key.strip()] = val.strip()

        info["packets"] = fields.get("Number of packets", "")
        info["encap"] = fields.get("File encapsulation", "")
        info["precision"] = fields.get("File timestamp precision", "")
        info["ifaces"] = fields.get("Number of interfaces in file", "1")
        info["start"] = fields.get("Earliest packet time", "")
        info["end"] = fields.get("Latest packet time", "")
        dur = fields.get("Capture duration", "")
        info["duration"] = dur.replace(" seconds", "").strip()
        ftype = fields.get("File type", "")

        # Readability / integrity assessment
        info["readable"] = (proc.returncode == 0 and bool(info["packets"]))
        problems = []
        low = (out + "\n" + err).lower()
        for kw in ("cut short", "damaged", "appears to be", "truncat",
                   "less than", "not a", "unrecognized", "error"):
            if kw in low:
                problems.append("possible truncation/corruption")
                break
        if err:
            problems.append(err.splitlines()[0][:60])

        try:
            if info["packets"] and int(info["packets"]) == 0:
                problems.append("no packets")
        except ValueError:
            pass

        if info["readable"] and not problems:
            info["ok"] = True
            info["status"] = "valid"
        elif info["readable"]:
            info["ok"] = True   # still mergeable, but flag it
            info["status"] = "warning"
        else:
            info["ok"] = False
            info["status"] = "unreadable"
            if not problems:
                problems.append("capinfos could not read file")

        # Compose notes (type + any problems)
        note_bits = []
        if ftype:
            note_bits.append(ftype)
        note_bits.extend(problems)
        info["notes"] = "; ".join(note_bits)
        return info

    def _start_merge(self, files, validations, dlg, status_var):
        """Ask for an output path and merge the valid files via mergecap."""
        valid_files = [v["path"] for v in validations if v and v["ok"]]
        skipped = [os.path.basename(v["path"]) for v in validations if v and not v["ok"]]

        if len(valid_files) < 2:
            messagebox.showwarning("Not Enough Valid Files",
                                   "Need at least 2 valid files to merge.", parent=dlg)
            return

        if skipped:
            proceed = messagebox.askyesno(
                "Skip Problematic Files?",
                f"{len(skipped)} file(s) will be SKIPPED (unreadable):\n\n"
                + "\n".join(skipped[:15]) + ("\n..." if len(skipped) > 15 else "")
                + f"\n\nMerge the remaining {len(valid_files)} valid file(s)?",
                parent=dlg)
            if not proceed:
                return

        done_inputs = all(os.path.splitext(path)[1].lower() == ".done"
                          for path in valid_files)
        default_ext = ".done" if done_inputs else ".pcapng"
        default_name = "merged_capture.done" if done_inputs else "merged_capture.pcapng"

        # asksaveasfilename warns before overwriting an existing file
        out_path = filedialog.asksaveasfilename(
            title="Save Merged Capture As",
            defaultextension=default_ext,
            initialfile=default_name,
            initialdir=os.path.dirname(valid_files[0]),
            filetypes=[
                ("DONE capture", "*.done"),
                ("PCAPNG", "*.pcapng"),
                ("All files", "*.*"),
            ],
            confirmoverwrite=True,
            parent=dlg,
        )
        if not out_path:
            return

        # Guard: don't let the output collide with any source file
        norm_out = os.path.normcase(os.path.abspath(out_path))
        for src in valid_files:
            if os.path.normcase(os.path.abspath(src)) == norm_out:
                messagebox.showerror(
                    "Invalid Output",
                    "The merged output cannot be one of the source files.", parent=dlg)
                return

        status_var.set("Merging with mergecap...")
        threading.Thread(target=self._do_merge,
                         args=(valid_files, validations, out_path, dlg, status_var),
                         daemon=True).start()

    def _do_merge(self, valid_files, validations, out_path, dlg, status_var):
        """
        Run mergecap to build a consolidated PCAPNG.
        mergecap merges packets in chronological order by default, preserves
        original timestamps and per-file interfaces, and never touches inputs.
        """
        # The dialog may be closed by the user while this runs in the
        # background, so always resolve a parent window that is still alive.
        def live_parent():
            try:
                if dlg is not None and dlg.winfo_exists():
                    return dlg
            except tk.TclError:
                pass
            return self.root

        def set_status(msg):
            try:
                status_var.set(msg)
            except tk.TclError:
                pass

        cmd = [self.mergecap_path, "-F", "pcapng", "-w", out_path] + valid_files
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=1800)
        except FileNotFoundError:
            self.root.after(0, lambda: (set_status("Merge failed: mergecap not found."),
                                        messagebox.showerror(
                "mergecap Not Found",
                "mergecap was not found. Ensure Wireshark is installed.",
                parent=live_parent())))
            return
        except subprocess.TimeoutExpired:
            self.root.after(0, lambda: (set_status("Merge timed out."),
                                        messagebox.showerror(
                "Merge Timeout", "mergecap took too long and was aborted.",
                parent=live_parent())))
            return
        except Exception as e:
            self.root.after(0, lambda: (set_status("Merge failed."),
                                        messagebox.showerror(
                "Merge Error", f"mergecap failed: {e}", parent=live_parent())))
            return

        if proc.returncode != 0 or not os.path.exists(out_path):
            err = (proc.stderr or "unknown error").strip()
            self.root.after(0, lambda: (set_status("Merge failed."),
                                        messagebox.showerror(
                "Merge Failed", f"mergecap returned an error:\n\n{err}",
                parent=live_parent())))
            return

        # Verify merged output and report packet totals
        merged_info = self._validate_capture(out_path)
        merged_pkts = merged_info.get("packets", "?")
        expected_pkts = 0
        packet_count_complete = True
        for item in validations:
            if not item or not item.get("ok"):
                continue
            try:
                expected_pkts += int(str(item.get("packets", "")).replace(",", ""))
            except (TypeError, ValueError):
                packet_count_complete = False
        try:
            merged_pkts_int = int(str(merged_pkts).replace(",", ""))
        except (TypeError, ValueError):
            merged_pkts_int = None
        packet_match = (packet_count_complete and merged_pkts_int == expected_pkts)

        def done():
            self.merged_file = out_path
            self.merged_source_files = list(valid_files)
            self._load_single_file(out_path)
            self.file_info_label.config(
                text=f"Merged {len(valid_files)} files -> "
                     f"{os.path.basename(out_path)} ({merged_info.get('size','?')})")
            if packet_match:
                verify_text = (
                    f"Packet verification: OK\n"
                    f"Source packet sum: {expected_pkts:,}\n"
                    f"Merged packets:    {merged_pkts_int:,}"
                )
                set_status(f"Merged OK - {merged_pkts} packets verified. Starting analysis...")
                show_msg = messagebox.showinfo
                title = "Merge Complete"
            else:
                if packet_count_complete:
                    verify_text = (
                        "Packet verification: WARNING\n"
                        f"Source packet sum: {expected_pkts:,}"
                    )
                else:
                    verify_text = (
                        "Packet verification: WARNING\n"
                        "Source packet sum: unavailable"
                    )
                verify_text += f"\nMerged packets:    {merged_pkts}"
                verify_text += "\n\nPlease inspect the source/merged files before relying on this merge."
                set_status("Merged, but packet count verification did not match.")
                show_msg = messagebox.showwarning
                title = "Merge Complete - Verify Packet Count"
            show_msg(
                title,
                f"Merged {len(valid_files)} file(s) into:\n{out_path}\n\n"
                f"{verify_text}\n\n"
                f"Source files were left unchanged.\n\n"
                f"Output content is PCAPNG for Wireshark/Tshark compatibility; "
                f"the filename extension may be .done when selected.\n\n"
                f"Tip: each source keeps its own interface block in the PCAPNG, so "
                f"frame.interface_id / interface name identifies the contributing capture.",
                parent=live_parent())
            # Close the dialog if it is still open
            try:
                if dlg is not None and dlg.winfo_exists():
                    dlg.destroy()
            except tk.TclError:
                pass
            self.run_full_analysis()

        self.root.after(0, done)

    def run_full_analysis(self):
        """Run complete PCAP analysis"""
        if not self.pcap_file.get():
            messagebox.showwarning("No File Selected", "Please select a PCAP file first.")
            return
            
        if self.is_analyzing:
            return
            
        self.is_analyzing = True
        self.analysis_completed = False
        self.analysis_results = {}
        if hasattr(self, "upload_tree"):
            self.upload_tree.delete(*self.upload_tree.get_children())
        self._session_lookup = {}
        self.progress['value'] = 0
        self.progress_pct.config(text="0%")
        self.progress_info.config(text="Counting packets...")
        self.analyze_btn.config(state=tk.DISABLED)
        self.update_status("Analyzing PCAP file...")
        
        # Run analysis in background thread
        thread = threading.Thread(target=self._analyze_pcap)
        thread.daemon = True
        thread.start()
        
    def _analyze_pcap(self):
        """Background thread for PCAP analysis"""
        try:
            pcap_path = self._prepare_capture_for_analysis(self.pcap_file.get())
            
            # First, get total packet count
            self.root.after(0, lambda: self.progress_info.config(text="Counting packets in PCAP..."))
            total_packets = self._get_packet_count(pcap_path)
            self.analysis_results["total_packet_count"] = total_packets
            
            # If packet count is 0, try to get it from protocol analysis
            if total_packets == 0:
                self.root.after(0, lambda: self._update_progress(5, 0, "Reading PCAP file..."))
            else:
                self.root.after(0, lambda: self._update_progress(5, total_packets, f"Found {total_packets:,} packets"))
            
            # Run TShark analysis with progress updates
            self.root.after(0, lambda: self._update_progress(10, total_packets, "Running protocol analysis..."))
            self._analyze_protocols(pcap_path)
            
            # Update packet count from protocol analysis if we didn't get it before
            if total_packets == 0 and "protocols" in self.analysis_results:
                protocols = self.analysis_results.get("protocols", {})
                if protocols:
                    # Get frame count from first protocol (usually 'frame' or 'eth')
                    for proto in ["frame", "eth", "ip"]:
                        if proto in protocols:
                            total_packets = protocols[proto].get("frames", 0)
                            self.analysis_results["total_packet_count"] = total_packets
                            break
                    if total_packets == 0:
                        # Just use the first protocol's frame count
                        first_proto = next(iter(protocols.values()), {})
                        total_packets = first_proto.get("frames", 0)
                        self.analysis_results["total_packet_count"] = total_packets
            
            self.root.after(0, lambda: self._update_progress(30, total_packets, "Analyzing DNS traffic..."))
            self._analyze_dns(pcap_path)
            
            self.root.after(0, lambda: self._update_progress(50, total_packets, "Analyzing TLS connections..."))
            self._analyze_tls(pcap_path)
            
            self.root.after(0, lambda: self._update_progress(70, total_packets, "Extracting sessions..."))
            self._analyze_sessions(pcap_path)
            
            self.root.after(0, lambda: self._update_progress(80, total_packets, "Calculating statistics..."))
            self._calculate_statistics(pcap_path)

            self.root.after(0, lambda: self._update_progress(84, total_packets, "Inspecting HTTP content..."))
            self._analyze_http(pcap_path)

            self.root.after(0, lambda: self._update_progress(88, total_packets, "Extracting HTTP files / images..."))
            self._analyze_files(pcap_path)

            self.root.after(0, lambda: self._update_progress(91, total_packets, "Analyzing STUN/TURN transactions..."))
            self._analyze_stun(pcap_path)

            self.root.after(0, lambda: self._update_progress(92, total_packets, "Analyzing RADIUS authentication/accounting..."))
            self._analyze_radius(pcap_path)

            self.root.after(0, lambda: self._update_progress(93, total_packets, "Analyzing SS7 signaling..."))
            self._analyze_ss7_signaling(pcap_path)

            self.root.after(0, lambda: self._update_progress(94, total_packets, "Analyzing subscriber/SMS leaks..."))
            self._analyze_ss7_gsm_map(pcap_path)

            self.root.after(0, lambda: self._update_progress(95, total_packets, "Analyzing SIP/RTP (VoIP)..."))
            self._analyze_voip(pcap_path)

            self.root.after(0, lambda: self._update_progress(97, total_packets, "Analyzing CCTV / RTSP video..."))
            self._analyze_cctv(pcap_path)

            self.root.after(0, lambda: self._update_progress(98, total_packets, "Extracting satellite custom blocks..."))
            self._analyze_satellite(pcap_path)

            self.root.after(0, lambda: self._update_progress(100, total_packets, "Analysis complete!"))
            
            # Update UI on main thread
            self.root.after(0, self._update_ui_after_analysis)
            
        except MemoryError:
            self.root.after(0, lambda: messagebox.showerror(
                "Memory Limit",
                "Analysis ran out of memory while reading TShark output.\n\n"
                "The dashboard now streams the largest analyzers, but this "
                "capture may still be too large for one pass. Try Quick mode "
                "or split the capture."))
        except SharedCaptureDownloadError as e:
            msg = self._error_text(e, "Shared URL could not be downloaded.")
            self.root.after(0, lambda msg=msg: messagebox.showerror(
                "Shared URL Access",
                msg))
        except Exception as e:
            msg = self._error_text(e, type(e).__name__)
            self.root.after(0, lambda msg=msg: messagebox.showerror("Error", f"Analysis failed: {msg}"))
        finally:
            self.root.after(0, self._finish_analysis)
    
    def _get_packet_count(self, pcap_path):
        """Get total packet count from PCAP file"""
        tshark = self.tshark_path.get()
        
        # Check if tshark exists
        if not os.path.exists(tshark) and tshark == "tshark":
            self.root.after(0, lambda: self.progress_info.config(
                text="TShark not found! Configure via Settings > Configure TShark Path"))
            return 0
        
        try:
            normalized_path = str(pcap_path or "")
            is_network_path = normalized_path.startswith("\\\\") or normalized_path.startswith("//")

            # Try capinfos first (faster) - it's in same folder as tshark
            # On UNC/admin shares capinfos can block on network I/O, so skip it and
            # allow the protocol/statistics analyzers to populate the count.
            capinfos_path = os.path.join(os.path.dirname(tshark), "capinfos.exe") if os.path.dirname(tshark) else "capinfos"
            if os.path.exists(capinfos_path) and not is_network_path:
                cmd = [capinfos_path, "-c", pcap_path]
                try:
                    result = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30)
                    if result.returncode == 0:
                        for line in result.stdout.split("\n"):
                            if "Number of packets" in line:
                                match = re.search(r"(\d+)", line.split(":")[-1])
                                if match:
                                    return int(match.group(1))
                except subprocess.TimeoutExpired:
                    print("Packet count via capinfos timed out; continuing with TShark fallback.")
            
            # Fallback to tshark with io,stat
            cmd3 = [tshark, "-r", pcap_path, "-q", "-z", "io,stat,0"]
            try:
                result3 = subprocess.run(cmd3, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60)
                for line in result3.stdout.split("\n"):
                    # Match pattern like: | 0 <> 123 | 5000 | 1234567 |
                    match = re.search(r"\|\s*\d+(?:\.\d+)?\s*<>\s*[\d.]+\s*\|\s*(\d+)\s*\|", line)
                    if match:
                        return int(match.group(1))
            except subprocess.TimeoutExpired:
                print("Packet count via tshark io,stat timed out; continuing analysis without pre-count.")
            
            # Another fallback - count frame numbers
            if is_network_path:
                return 0
            cmd2 = [tshark, "-r", pcap_path, "-T", "fields", "-e", "frame.number"]
            try:
                result2 = subprocess.run(cmd2, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120)
                if result2.stdout.strip():
                    lines = [l for l in result2.stdout.strip().split("\n") if l]
                    return len(lines)
            except subprocess.TimeoutExpired:
                print("Packet count via frame-number fallback timed out; continuing analysis without pre-count.")
            
            return 0
        except FileNotFoundError:
            self.root.after(0, lambda: messagebox.showwarning(
                "TShark Not Found", 
                f"TShark not found at: {tshark}\n\nPlease install Wireshark or configure the correct path via Settings > Configure TShark Path"))
            return 0
        except Exception as e:
            print(f"Error getting packet count: {e}")
            return 0
    
    def _update_progress(self, percentage, total_packets, status_msg):
        """Update progress bar and info labels"""
        self.progress['value'] = percentage
        self.progress_pct.config(text=f"{percentage}%")
        self.progress_info.config(text=f"Total Packets: {total_packets:,} | {status_msg}")
        self.update_status(status_msg)

    @staticmethod
    def _first_int_value(value, default=0):
        """Parse the first integer from a TShark field that may contain comma-separated values."""
        text = str(value or "").strip()
        if not text:
            return default
        match = re.search(r"-?\d+", text)
        if not match:
            return default
        try:
            return int(match.group(0))
        except ValueError:
            return default

    def _is_signaling_only_capture(self, pcap_path=""):
        """Return True when this looks like SS7/SIGTRAN rather than upload-session traffic."""
        protocols = self.analysis_results.get("protocols", {}) or {}
        if not protocols:
            return "ss7" in str(pcap_path or "").lower()
        lower = {str(k).lower(): v for k, v in protocols.items()}

        def frames(name):
            data = lower.get(name, {})
            try:
                return int(data.get("frames", 0))
            except Exception:
                return 0

        signaling_frames = sum(frames(name) for name in (
            "sctp", "m3ua", "mtp3", "sccp", "tcap", "gsm_map", "gsm_sms", "isup", "bssap", "gsm_a"
        ))
        tcp_frames = frames("tcp")
        udp_frames = frames("udp")
        path_hint = "ss7" in str(pcap_path or "").lower()
        ss7_core_frames = sum(frames(name) for name in (
            "m3ua", "mtp3", "sccp", "tcap", "gsm_map", "gsm_sms", "isup"
        ))
        return (
            signaling_frames > 0 and tcp_frames == 0 and udp_frames == 0
        ) or (
            ss7_core_frames > 0 and path_hint
        ) or (
            ss7_core_frames >= 1000 and ss7_core_frames >= max(tcp_frames, udp_frames)
        )
            
    def _analyze_protocols(self, pcap_path):
        """Analyze protocol distribution"""
        try:
            cmd = [self.tshark_path.get(), "-r", pcap_path, "-q", "-z", "io,phs"]
            result = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120)
            self.analysis_results["protocols_raw"] = result.stdout
            
            # Parse protocol hierarchy
            protocols = {}
            for line in result.stdout.split("\n"):
                match = re.search(r"(\S+)\s+frames:(\d+)\s+bytes:(\d+)", line)
                if match:
                    proto, frames, bytes_count = match.groups()
                    protocols[proto] = {"frames": int(frames), "bytes": int(bytes_count)}
                    
            self.analysis_results["protocols"] = protocols
        except Exception:
            self.analysis_results["protocols"] = {}
            
    def _analyze_dns(self, pcap_path):
        """Analyze DNS queries and responses"""
        try:
            cmd = [self.tshark_path.get(), "-r", pcap_path, "-Y", "dns",
                   "-T", "fields", "-e", "dns.qry.name", "-e", "dns.qry.type",
                   "-e", "dns.a", "-e", "dns.aaaa"]
            result = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120)
            
            dns_queries = defaultdict(lambda: {"count": 0, "responses": set(), "types": set()})
            for line in result.stdout.strip().split("\n"):
                if line:
                    parts = line.split("\t")
                    if len(parts) >= 1 and parts[0]:
                        domain = parts[0]
                        dns_queries[domain]["count"] += 1
                        if len(parts) >= 2:
                            dns_queries[domain]["types"].add(parts[1])
                        if len(parts) >= 3 and parts[2]:
                            dns_queries[domain]["responses"].add(parts[2])
                        if len(parts) >= 4 and parts[3]:
                            dns_queries[domain]["responses"].add(parts[3])
                            
            self.analysis_results["dns"] = dict(dns_queries)
        except Exception:
            self.analysis_results["dns"] = {}
            
    def _analyze_tls(self, pcap_path):
        """Analyze TLS connections"""
        try:
            cmd = [self.tshark_path.get(), "-r", pcap_path, "-Y", "tls.handshake.type == 1",
                   "-T", "fields", "-e", "tls.handshake.extensions_server_name",
                   "-e", "tls.handshake.version", "-e", "tls.handshake.ciphersuite"]
            result = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120)
            
            tls_connections = defaultdict(lambda: {"count": 0, "versions": set(), "ciphers": set()})
            for line in result.stdout.strip().split("\n"):
                if line:
                    parts = line.split("\t")
                    if len(parts) >= 1 and parts[0]:
                        sni = parts[0]
                        tls_connections[sni]["count"] += 1
                        if len(parts) >= 2:
                            tls_connections[sni]["versions"].add(parts[1])
                        if len(parts) >= 3:
                            tls_connections[sni]["ciphers"].add(parts[2])
                            
            self.analysis_results["tls"] = dict(tls_connections)
        except Exception:
            self.analysis_results["tls"] = {}
            
    def _analyze_sessions(self, pcap_path):
        """
        Extract and correlate TCP/UDP/QUIC sessions into logical application sessions.
        
        Session Hierarchy:
        1. Packet level - Individual packets
        2. Transport-flow level - TCP streams / UDP flows  
        3. Logical application-session level - Correlated flows
        """
        if self._is_signaling_only_capture(pcap_path):
            note = "Session/upload analysis skipped: capture is SS7/SIGTRAN-focused; TCP/UDP upload flows are not relevant."
            self.analysis_results["session_analysis_mode"] = "skipped-signaling"
            self.analysis_results["session_analysis_notes"] = [note]
            self.analysis_results["transport_flows"] = []
            self.analysis_results["logical_sessions"] = []
            self.analysis_results["sessions"] = []
            print(note)
            self.root.after(0, lambda: self.progress_info.config(text=note))
            return

        # Use quick mode if checkbox is checked
        if self.quick_mode.get():
            return self._analyze_sessions_quick(pcap_path)

        # Detailed mode is required for Upload Behavior, upload-event bursts,
        # and the per-session I/O graph. Keep the old working behavior unless
        # the user explicitly checks Quick.
        self.analysis_results["session_analysis_mode"] = "detailed"
        
        tshark = self.tshark_path.get()
        transport_flows: List[TransportFlow] = []
        
        try:
            # ===== STEP 1: Extract all transport flows with detailed info =====
            self.root.after(0, lambda: self.progress_info.config(text="Extracting TCP streams (detailed mode)..."))
            
            # Get detailed TCP stream info (payload len + retransmission for accurate uploads)
            cmd_tcp = [tshark, "-r", pcap_path, "-T", "fields",
                       "-e", "tcp.stream", "-e", "ip.src", "-e", "ip.dst",
                       "-e", "tcp.srcport", "-e", "tcp.dstport",
                       "-e", "frame.len", "-e", "tcp.len", "-e", "frame.time_epoch",
                       "-e", "tls.handshake.extensions_server_name",
                       "-e", "tcp.analysis.retransmission",
                       "-e", "ipv6.src", "-e", "ipv6.dst",
                       "-Y", "tcp"]
            result_tcp = subprocess.run(cmd_tcp, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=180)
            
            # Parse TCP flows
            tcp_streams = defaultdict(lambda: {
                "packets": [], "src_ips": set(), "dst_ips": set(),
                "src_ports": set(), "dst_ports": set(), "snis": set(),
                "bytes_sent": 0, "bytes_recv": 0, "times": [],
                "records": []
            })
            
            for line in result_tcp.stdout.strip().split("\n"):
                if line:
                    parts = line.split("\t")
                    if len(parts) >= 8 and parts[0]:
                        stream_id = parts[0]
                        # Prefer IPv4; fall back to IPv6 (ipv6.src/dst at 10/11)
                        src_ip = parts[1] or (parts[10] if len(parts) > 10 else "")
                        dst_ip = parts[2] or (parts[11] if len(parts) > 11 else "")
                        src_port, dst_port = parts[3], parts[4]
                        frame_len = self._first_int_value(parts[5])
                        payload_len = self._first_int_value(parts[6])
                        timestamp = float(parts[7]) if parts[7] else 0
                        sni = parts[8] if len(parts) > 8 and parts[8] else ""
                        is_retrans = bool(parts[9]) if len(parts) > 9 and parts[9] else False
                        
                        s = tcp_streams[stream_id]
                        s["src_ips"].add(src_ip)
                        s["dst_ips"].add(dst_ip)
                        s["src_ports"].add(src_port)
                        s["dst_ports"].add(dst_port)
                        s["times"].append(timestamp)
                        if sni:
                            s["snis"].add(sni)
                        
                        # Determine direction (first packet's src is client)
                        if not s["packets"]:
                            s["client_ip"] = src_ip
                            s["server_ip"] = dst_ip
                        
                        is_upload = (src_ip == s.get("client_ip"))
                        if is_upload:
                            s["bytes_sent"] += frame_len
                        else:
                            s["bytes_recv"] += frame_len
                        
                        s["packets"].append({
                            "src": src_ip, "dst": dst_ip, "len": frame_len, "time": timestamp
                        })
                        s["records"].append(PacketRecord(
                            time=timestamp, is_upload=is_upload,
                            payload_len=payload_len, frame_len=frame_len,
                            is_retransmission=is_retrans
                        ))
            
            # Convert to TransportFlow objects
            for stream_id, data in tcp_streams.items():
                if data["packets"]:
                    times = data["times"]
                    flow = TransportFlow(
                        flow_id=f"tcp.{stream_id}",
                        protocol="TCP",
                        src_ip=data.get("client_ip", ""),
                        dst_ip=data.get("server_ip", ""),
                        src_port=",".join(sorted(data["src_ports"])),
                        dst_port=",".join(sorted(data["dst_ports"])),
                        packets=len(data["packets"]),
                        bytes_sent=data["bytes_sent"],
                        bytes_recv=data["bytes_recv"],
                        start_time=min(times) if times else 0,
                        end_time=max(times) if times else 0,
                        sni=",".join(data["snis"]) if data["snis"] else "",
                        packet_records=data["records"]
                    )
                    transport_flows.append(flow)
            
            # ===== STEP 2: Extract QUIC/UDP flows =====
            self.root.after(0, lambda: self.progress_info.config(text="Extracting QUIC/UDP streams..."))
            
            # Extract IETF QUIC (quic.*) AND Google QUIC (gquic.*) - both over UDP
            cmd_udp = [tshark, "-r", pcap_path, "-T", "fields",
                       "-e", "udp.stream", "-e", "ip.src", "-e", "ip.dst",
                       "-e", "udp.srcport", "-e", "udp.dstport",
                       "-e", "frame.len", "-e", "udp.length", "-e", "frame.time_epoch",
                       "-e", "tls.handshake.extensions_server_name",
                       "-e", "quic.dcid", "-e", "quic.scid",
                       "-e", "gquic.cid", "-e", "gquic.tag.sni",
                       "-e", "frame.protocols",
                       "-e", "ipv6.src", "-e", "ipv6.dst",
                       "-Y", "udp"]
            result_udp = subprocess.run(cmd_udp, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=180)
            
            udp_streams = defaultdict(lambda: {
                "packets": [], "src_ips": set(), "dst_ips": set(),
                "src_ports": set(), "dst_ports": set(), "snis": set(),
                "dcids": set(), "scids": set(), "gcids": set(),
                "bytes_sent": 0, "bytes_recv": 0, "times": [],
                "is_quic": False, "is_gquic": False,
                "records": []
            })
            
            for line in result_udp.stdout.strip().split("\n"):
                if line:
                    parts = line.split("\t")
                    if len(parts) >= 8 and parts[0]:
                        stream_id = parts[0]
                        # Prefer IPv4; fall back to IPv6 (ipv6.src/dst at 14/15)
                        src_ip = parts[1] or (parts[14] if len(parts) > 14 else "")
                        dst_ip = parts[2] or (parts[15] if len(parts) > 15 else "")
                        src_port, dst_port = parts[3], parts[4]
                        frame_len = self._first_int_value(parts[5])
                        # udp.length includes 8-byte UDP header; subtract for payload
                        udp_len = self._first_int_value(parts[6])
                        payload_len = max(0, udp_len - 8)
                        timestamp = float(parts[7]) if parts[7] else 0
                        sni = parts[8] if len(parts) > 8 and parts[8] else ""
                        dcid = parts[9] if len(parts) > 9 and parts[9] else ""
                        scid = parts[10] if len(parts) > 10 and parts[10] else ""
                        gcid = parts[11] if len(parts) > 11 and parts[11] else ""
                        gquic_sni = parts[12] if len(parts) > 12 and parts[12] else ""
                        protocols = parts[13] if len(parts) > 13 and parts[13] else ""
                        
                        s = udp_streams[stream_id]
                        s["src_ips"].add(src_ip)
                        s["dst_ips"].add(dst_ip)
                        s["src_ports"].add(src_port)
                        s["dst_ports"].add(dst_port)
                        s["times"].append(timestamp)
                        
                        # SNI can come from TLS (IETF QUIC) or gquic.tag.sni (gQUIC)
                        if sni:
                            s["snis"].add(sni)
                        if gquic_sni:
                            s["snis"].add(gquic_sni)
                        if dcid:
                            s["dcids"].add(dcid)
                            s["is_quic"] = True
                        if scid:
                            s["scids"].add(scid)
                            s["is_quic"] = True
                        # Google QUIC detection
                        if gcid:
                            s["gcids"].add(gcid)
                            s["is_gquic"] = True
                        if "gquic" in protocols:
                            s["is_gquic"] = True
                        elif "quic" in protocols:
                            s["is_quic"] = True
                        
                        # Check if QUIC by port (443 UDP)
                        if dst_port == "443" or src_port == "443":
                            s["is_quic"] = True
                        
                        if not s["packets"]:
                            s["client_ip"] = src_ip
                            s["server_ip"] = dst_ip
                        
                        is_upload = (src_ip == s.get("client_ip"))
                        if is_upload:
                            s["bytes_sent"] += frame_len
                        else:
                            s["bytes_recv"] += frame_len
                        
                        s["packets"].append({
                            "src": src_ip, "dst": dst_ip, "len": frame_len, "time": timestamp
                        })
                        s["records"].append(PacketRecord(
                            time=timestamp, is_upload=is_upload,
                            payload_len=payload_len, frame_len=frame_len,
                            is_retransmission=False
                        ))
            
            for stream_id, data in udp_streams.items():
                if data["packets"]:
                    times = data["times"]
                    # gQUIC takes precedence for labeling; else IETF QUIC; else UDP
                    if data["is_gquic"]:
                        protocol = "gQUIC"
                    elif data["is_quic"]:
                        protocol = "QUIC"
                    else:
                        protocol = "UDP"
                    # Merge IETF + gQUIC connection IDs for correlation
                    all_dcids = set(data["dcids"]) | set(data["gcids"])
                    flow = TransportFlow(
                        flow_id=f"udp.{stream_id}",
                        protocol=protocol,
                        src_ip=data.get("client_ip", ""),
                        dst_ip=data.get("server_ip", ""),
                        src_port=",".join(sorted(data["src_ports"])),
                        dst_port=",".join(sorted(data["dst_ports"])),
                        packets=len(data["packets"]),
                        bytes_sent=data["bytes_sent"],
                        bytes_recv=data["bytes_recv"],
                        start_time=min(times) if times else 0,
                        end_time=max(times) if times else 0,
                        sni=",".join(data["snis"]) if data["snis"] else "",
                        quic_dcid=",".join(sorted(all_dcids)) if all_dcids else "",
                        quic_scid=",".join(data["scids"]) if data["scids"] else "",
                        packet_records=data["records"]
                    )
                    transport_flows.append(flow)
            
            # Build IP -> hostname map so flows without their own SNI
            # (e.g. TLS session resumption, no ClientHello captured) can still
            # resolve a server name from sibling flows or DNS responses.
            self._ip_hostname_map = self._build_ip_hostname_map(transport_flows)

            # ===== STEP 3: Correlate flows into logical sessions =====
            self.root.after(0, lambda: self.progress_info.config(text="Correlating into logical sessions..."))
            logical_sessions = self._correlate_flows_to_sessions(transport_flows)
            
            # ===== STEP 4: Detect upload events within each session =====
            self.root.after(0, lambda: self.progress_info.config(text="Detecting upload events (bursts)..."))
            for session in logical_sessions:
                self._detect_upload_events(session)
            
            # Store results
            self.analysis_results["transport_flows"] = transport_flows
            self.analysis_results["logical_sessions"] = logical_sessions
            
            # Also create legacy format for backward compatibility
            self.analysis_results["sessions"] = self._convert_to_legacy_format(logical_sessions)
            
            total_events = sum(len(s.upload_events) for s in logical_sessions)
            print(f"Found {len(transport_flows)} transport flows -> "
                  f"{len(logical_sessions)} logical sessions -> {total_events} upload events")
            
        except subprocess.TimeoutExpired as e:
            print(f"Detailed session analysis timed out: {e}")
            self.root.after(0, lambda: self.progress_info.config(
                text="Detailed session extraction timed out; using quick session mode..."))
            self._analyze_sessions_quick(pcap_path)
            self.analysis_results["session_analysis_mode"] = "quick-timeout-fallback"
        except Exception as e:
            print(f"Error analyzing sessions: {e}")
            self.analysis_results["transport_flows"] = []
            self.analysis_results["logical_sessions"] = []
            self.analysis_results["sessions"] = []
    
    @staticmethod
    def _parse_bytes_value(value: str, unit: str) -> int:
        """Convert a TShark byte value + unit (bytes/kB/MB/GB) into an int of bytes."""
        try:
            num = float(value)
        except ValueError:
            return 0
        u = (unit or "bytes").lower()
        mult = {"bytes": 1, "kb": 1000, "mb": 1000 * 1000,
                "gb": 1000 * 1000 * 1000}.get(u, 1)
        return int(num * mult)

    def _parse_conv_line(self, line: str):
        """
        Parse a TShark 'conv' table row.
        Format: A:portA <-> B:portB  <-Frames <-Bytes u  ->Frames ->Bytes u  ...
        TShark column order is '<-' (B->A) THEN '->' (A->B).
        Returns dict with upload(=A->B) / download(=B->A) bytes, or None.
        """
        m = re.search(r"(\S+):(\d+)\s+<->\s+(\S+):(\d+)\s+(.*)", line)
        if not m:
            return None
        src_ip, src_port, dst_ip, dst_port, rest = m.groups()
        tokens = rest.split()
        # Collect (number, unit) pairs: number then optional unit word
        nums = []  # list of (value, unit)
        i = 0
        while i < len(tokens):
            tok = tokens[i]
            if re.match(r"^[\d.]+$", tok):
                unit = ""
                if i + 1 < len(tokens) and tokens[i + 1].lower() in (
                        "bytes", "kb", "mb", "gb"):
                    unit = tokens[i + 1]
                    i += 1
                nums.append((tok, unit))
            i += 1
        # Expected: <-Frames <-Bytes ->Frames ->Bytes TotalFrames TotalBytes ...
        if len(nums) < 6:
            return None
        down_frames = int(float(nums[0][0]))
        down_bytes = self._parse_bytes_value(nums[1][0], nums[1][1])
        up_frames = int(float(nums[2][0]))
        up_bytes = self._parse_bytes_value(nums[3][0], nums[3][1])
        return {
            "src_ip": src_ip, "src_port": src_port,
            "dst_ip": dst_ip, "dst_port": dst_port,
            "upload_bytes": up_bytes, "download_bytes": down_bytes,
            "packets": up_frames + down_frames,
        }

    def _analyze_sessions_quick(self, pcap_path):
        """
        Quick session analysis using TShark conversation statistics.
        Faster but less detailed - uses conv,tcp and conv,udp instead of packet extraction.
        """
        tshark = self.tshark_path.get()
        sessions = []
        sni_lookup = {}
        quick_notes = []

        try:
            self.root.after(0, lambda: self.progress_info.config(text="Quick mode: Getting TCP conversations..."))
            cmd_tcp = [tshark, "-r", pcap_path, "-q", "-z", "conv,tcp"]
            try:
                for line in self._iter_command_lines(cmd_tcp, timeout=300, max_lines=250000):
                    c = self._parse_conv_line(line)
                    if not c:
                        continue
                    sessions.append({
                        "session_id": f"TCP-{len(sessions)+1:04d}",
                        "src_ip": c["src_ip"], "src_port": c["src_port"],
                        "dst_ip": c["dst_ip"], "dst_port": c["dst_port"],
                        "protocol": "TCP",
                        "packets": c["packets"],
                        "upload_bytes": c["upload_bytes"],
                        "download_bytes": c["download_bytes"],
                        "tcp_streams": [f"tcp.{len(sessions)}"],
                        "udp_streams": [],
                        "quic_cids": [],
                        "client_ports": [c["src_port"]],
                        "sni": "",
                        "start_time": 0,
                        "end_time": 0,
                        "flow_count": 1,
                    })
            except subprocess.TimeoutExpired:
                quick_notes.append("TCP conversation scan reached time limit; keeping partial TCP sessions.")

            self.root.after(0, lambda: self.progress_info.config(text="Quick mode: Getting UDP/QUIC conversations..."))
            cmd_udp = [tshark, "-r", pcap_path, "-q", "-z", "conv,udp"]
            try:
                for line in self._iter_command_lines(cmd_udp, timeout=300, max_lines=250000):
                    c = self._parse_conv_line(line)
                    if not c:
                        continue
                    protocol = "QUIC" if c["dst_port"] == "443" or c["src_port"] == "443" else "UDP"
                    sessions.append({
                        "session_id": f"{protocol}-{len(sessions)+1:04d}",
                        "src_ip": c["src_ip"], "src_port": c["src_port"],
                        "dst_ip": c["dst_ip"], "dst_port": c["dst_port"],
                        "protocol": protocol,
                        "packets": c["packets"],
                        "upload_bytes": c["upload_bytes"],
                        "download_bytes": c["download_bytes"],
                        "tcp_streams": [],
                        "udp_streams": [f"udp.{len(sessions)}"],
                        "quic_cids": [],
                        "client_ports": [c["src_port"]],
                        "sni": "",
                        "start_time": 0,
                        "end_time": 0,
                        "flow_count": 1,
                    })
            except subprocess.TimeoutExpired:
                quick_notes.append("UDP conversation scan reached time limit; keeping partial UDP sessions.")

            self.root.after(0, lambda: self.progress_info.config(text="Quick mode: Getting SNI information..."))
            cmd_sni = [tshark, "-r", pcap_path, "-Y", "tls.handshake.type == 1",
                       "-T", "fields", "-e", "ip.src", "-e", "ip.dst", "-e", "tcp.dstport",
                       "-e", "tls.handshake.extensions_server_name",
                       "-e", "ipv6.src", "-e", "ipv6.dst"]
            try:
                for line in self._iter_command_lines(cmd_sni, timeout=90, max_lines=50000):
                    if not line:
                        continue
                    parts = line.split("\t")
                    if len(parts) >= 4 and parts[3]:
                        src = parts[0] or (parts[4] if len(parts) > 4 else "")
                        dst = parts[1] or (parts[5] if len(parts) > 5 else "")
                        sni_lookup[(src, dst, parts[2])] = parts[3]
            except subprocess.TimeoutExpired:
                quick_notes.append("TLS SNI enrichment skipped after 90 seconds.")

            cmd_quic = [tshark, "-r", pcap_path, "-Y", "quic",
                        "-T", "fields", "-e", "ip.src", "-e", "ip.dst", "-e", "udp.dstport",
                        "-e", "tls.handshake.extensions_server_name",
                        "-e", "ipv6.src", "-e", "ipv6.dst"]
            try:
                for line in self._iter_command_lines(cmd_quic, timeout=90, max_lines=50000):
                    if not line:
                        continue
                    parts = line.split("\t")
                    if len(parts) >= 4 and parts[3]:
                        src = parts[0] or (parts[4] if len(parts) > 4 else "")
                        dst = parts[1] or (parts[5] if len(parts) > 5 else "")
                        key = (src, dst, parts[2])
                        if key not in sni_lookup:
                            sni_lookup[key] = parts[3]
            except subprocess.TimeoutExpired:
                quick_notes.append("QUIC SNI enrichment skipped after 90 seconds.")

            for session in sessions:
                key1 = (session["src_ip"], session["dst_ip"], session["dst_port"])
                key2 = (session["dst_ip"], session["src_ip"], session["src_port"])
                if key1 in sni_lookup:
                    session["sni"] = sni_lookup[key1]
                elif key2 in sni_lookup:
                    session["sni"] = sni_lookup[key2]

                upload = session["upload_bytes"]
                download = session["download_bytes"]
                ratio = upload / download if download > 0 else float('inf')
                session["upload_ratio"] = ratio
                if ratio > 2:
                    session["classification"] = "Heavy Upload"
                elif ratio > 1:
                    session["classification"] = "Upload Dominant"
                elif ratio > 0.5:
                    session["classification"] = "Balanced"
                else:
                    session["classification"] = "Download Dominant"

            sessions.sort(key=lambda s: s["upload_bytes"], reverse=True)
            self.analysis_results["sessions"] = sessions
            self.analysis_results["transport_flows"] = []
            self.analysis_results["logical_sessions"] = []
            self.analysis_results["session_quick_notes"] = quick_notes

            print(f"Quick mode: Found {len(sessions)} sessions")
            for note in quick_notes:
                print(f"Quick mode note: {note}")

        except Exception as e:
            print(f"Error in quick session analysis: {e}")
            self.analysis_results["sessions"] = sessions
            self.analysis_results["transport_flows"] = []
            self.analysis_results["logical_sessions"] = []
            self.analysis_results["session_quick_notes"] = quick_notes + [str(e)]
    
    def _build_ip_hostname_map(self, flows: List[TransportFlow]) -> Dict[str, str]:
        """
        Map server IP -> hostname using (1) DNS answers and (2) SNI observed on
        any flow to that IP. SNI takes precedence over DNS. Used as a fallback
        for flows that carry no SNI of their own.
        """
        ip_to_host: Dict[str, str] = {}
        # From DNS responses (lower priority)
        for domain, info in self.analysis_results.get("dns", {}).items():
            for resp in info.get("responses", []):
                for ip in str(resp).split(","):
                    ip = ip.strip()
                    if ip and ip not in ip_to_host:
                        ip_to_host[ip] = domain
        # From observed SNI on flows (higher priority - overwrite DNS)
        for flow in flows:
            if flow.sni and flow.dst_ip:
                ip_to_host[flow.dst_ip] = flow.sni.split(",")[0]
        return ip_to_host

    def _resolve_server_name(self, server_ips: Set[str]) -> str:
        """Resolve a set of server IPs to hostnames via the IP->hostname map."""
        mapping = getattr(self, "_ip_hostname_map", {}) or {}
        resolved = set()
        for ip in server_ips:
            host = mapping.get(ip)
            if host:
                resolved.add(host)
        return ",".join(sorted(resolved))

    def _correlate_flows_to_sessions(self, flows: List[TransportFlow], 
                                      inactivity_timeout: float = 30.0) -> List[LogicalSession]:
        """
        Correlate transport flows into logical application sessions.
        
        Correlation rules:
        - Same client IP + Same SNI/server name = same session
        - Same QUIC Connection IDs = same session (even with port changes)
        - Flows within inactivity_timeout of each other = same session
        - Same destination infrastructure (IP range) = potential same session
        """
        if not flows:
            return []
        
        # Group flows by correlation key
        # Key: (client_ip, server_name_or_ip)
        session_groups = defaultdict(list)
        
        # Also track QUIC connection IDs for correlation
        quic_cid_to_flows = defaultdict(list)
        
        for flow in flows:
            # Determine client and server
            client_ip = flow.src_ip
            server_ip = flow.dst_ip
            server_name = flow.sni if flow.sni else server_ip
            
            # Primary grouping: client_ip + server_name
            key = (client_ip, server_name)
            session_groups[key].append(flow)
            
            # Track QUIC CIDs for additional correlation
            if flow.quic_dcid:
                for cid in flow.quic_dcid.split(","):
                    if cid:
                        quic_cid_to_flows[cid].append(flow)
            if flow.quic_scid:
                for cid in flow.quic_scid.split(","):
                    if cid:
                        quic_cid_to_flows[cid].append(flow)
        
        # Merge groups that share QUIC Connection IDs
        merged_groups = self._merge_quic_groups(session_groups, quic_cid_to_flows)
        
        # Create LogicalSession objects
        logical_sessions = []
        session_counter = 1
        
        for key, group_flows in merged_groups.items():
            if not group_flows:
                continue
            
            # Further split by time gaps (inactivity timeout)
            time_split_groups = self._split_by_inactivity(group_flows, inactivity_timeout)
            
            for sub_flows in time_split_groups:
                session = self._create_logical_session(
                    session_id=f"APP-{session_counter:04d}",
                    flows=sub_flows
                )
                logical_sessions.append(session)
                session_counter += 1
        
        # Sort by upload bytes descending
        logical_sessions.sort(key=lambda s: s.total_upload_bytes, reverse=True)
        
        return logical_sessions
    
    def _merge_quic_groups(self, session_groups, quic_cid_to_flows):
        """Merge session groups that share QUIC Connection IDs"""
        # For now, return as-is; full implementation would use Union-Find
        # to merge groups sharing CIDs
        return session_groups
    
    def _split_by_inactivity(self, flows: List[TransportFlow], 
                              timeout: float) -> List[List[TransportFlow]]:
        """Split flows into groups based on inactivity timeout"""
        if not flows:
            return []
        
        # Sort by start time
        sorted_flows = sorted(flows, key=lambda f: f.start_time)
        
        groups = []
        current_group = [sorted_flows[0]]
        last_end_time = sorted_flows[0].end_time
        
        for flow in sorted_flows[1:]:
            # Check if this flow starts within timeout of last flow's end
            if flow.start_time - last_end_time <= timeout:
                current_group.append(flow)
                last_end_time = max(last_end_time, flow.end_time)
            else:
                groups.append(current_group)
                current_group = [flow]
                last_end_time = flow.end_time
        
        if current_group:
            groups.append(current_group)
        
        return groups
    
    def _create_logical_session(self, session_id: str, 
                                 flows: List[TransportFlow]) -> LogicalSession:
        """Create a LogicalSession from a list of correlated flows"""
        if not flows:
            return None
        
        # Aggregate data from all flows
        client_ip = flows[0].src_ip
        server_ips = set()
        server_names = set()
        tcp_streams = []
        udp_streams = []
        quic_cids = set()
        client_ports = set()
        protocols = set()
        
        total_upload = 0
        total_download = 0
        total_packets = 0
        start_time = float('inf')
        end_time = 0
        
        for flow in flows:
            server_ips.add(flow.dst_ip)
            if flow.sni:
                server_names.add(flow.sni)
            
            if flow.flow_id.startswith("tcp."):
                tcp_streams.append(flow.flow_id)
            else:
                udp_streams.append(flow.flow_id)
            
            if flow.quic_dcid:
                quic_cids.update(flow.quic_dcid.split(","))
            if flow.quic_scid:
                quic_cids.update(flow.quic_scid.split(","))
            
            for port in flow.src_port.split(","):
                client_ports.add(port)
            
            protocols.add(flow.protocol)
            
            total_upload += flow.bytes_sent
            total_download += flow.bytes_recv
            total_packets += flow.packets
            
            if flow.start_time > 0:
                start_time = min(start_time, flow.start_time)
            if flow.end_time > 0:
                end_time = max(end_time, flow.end_time)
        
        # Determine primary server name.
        # Priority: SNI observed on this session's flows -> IP->hostname
        # fallback (sibling-flow SNI / DNS) -> raw server IPs.
        if server_names:
            server_name = ",".join(sorted(server_names))
        else:
            resolved = self._resolve_server_name(server_ips)
            server_name = resolved if resolved else ",".join(sorted(server_ips))
        
        # Determine protocol (gQUIC = Google QUIC, also over UDP)
        has_quic = "QUIC" in protocols
        has_gquic = "gQUIC" in protocols
        has_tcp = "TCP" in protocols
        if (has_quic or has_gquic) and has_tcp:
            protocol = "Mixed"
        elif has_gquic and has_quic:
            protocol = "QUIC/gQUIC"
        elif has_gquic:
            protocol = "gQUIC"
        elif has_quic:
            protocol = "QUIC"
        elif has_tcp:
            protocol = "TCP"
        else:
            protocol = "UDP"
        
        # Calculate upload ratio and classification
        upload_ratio = total_upload / total_download if total_download > 0 else float('inf')
        if upload_ratio > 2:
            classification = "Heavy Upload"
        elif upload_ratio > 1:
            classification = "Upload Dominant"
        elif upload_ratio > 0.5:
            classification = "Balanced"
        else:
            classification = "Download Dominant"
        
        return LogicalSession(
            session_id=session_id,
            client_ip=client_ip,
            server_ips=server_ips,
            server_name=server_name,
            protocol=protocol,
            tcp_streams=tcp_streams,
            udp_streams=udp_streams,
            quic_connection_ids=quic_cids,
            client_ports=client_ports,
            total_upload_bytes=total_upload,
            total_download_bytes=total_download,
            total_packets=total_packets,
            start_time=start_time if start_time != float('inf') else 0,
            end_time=end_time,
            classification=classification,
            upload_ratio=upload_ratio,
            flows=flows
        )
    
    def _convert_to_legacy_format(self, logical_sessions: List[LogicalSession]) -> List[dict]:
        """Convert LogicalSession objects to legacy dict format for backward compatibility"""
        legacy = []
        for session in logical_sessions:
            legacy.append({
                "session_id": session.session_id,
                "src_ip": session.client_ip,
                "dst_ip": ",".join(sorted(session.server_ips)),
                "dst_port": "443",  # Most common
                "protocol": session.protocol,
                "sni": session.server_name,
                "upload_bytes": session.total_upload_bytes,
                "download_bytes": session.total_download_bytes,
                "packets": session.total_packets,
                "tcp_streams": session.tcp_streams,
                "udp_streams": session.udp_streams,
                "quic_cids": list(session.quic_connection_ids),
                "client_ports": list(session.client_ports),
                "start_time": session.start_time,
                "end_time": session.end_time,
                "classification": session.classification,
                "upload_ratio": session.upload_ratio,
                "flow_count": len(session.flows),
                "upload_event_count": len(session.upload_events),
                "_session_obj": session
            })
        return legacy

    # ==================================================================
    #  UPLOAD-EVENT DETECTION (multiple upload bursts within a session)
    # ==================================================================
    def _get_upload_config(self):
        """Read configurable upload-event detection parameters from the UI."""
        def _get(attr, default):
            try:
                return float(getattr(self, attr).get())
            except (AttributeError, ValueError, tk.TclError):
                return default
        return {
            "bucket": _get("cfg_bucket", 1.0),              # time bucket (sec)
            "min_payload": _get("cfg_min_payload", 5000),    # min uploaded bytes to keep event
            "min_duration": _get("cfg_min_duration", 2.0),   # min event duration (sec)
            "idle_gap": _get("cfg_idle_gap", 4.0),           # idle gap to split events (sec)
            "bps_threshold": _get("cfg_bps_threshold", 2000),  # bytes/sec active threshold
            "min_ratio": _get("cfg_min_ratio", 1.0),         # upload:download ratio for a bucket to be "upload"
        }

    def _build_io_timeline(self, records: List[PacketRecord], bucket: float,
                            t0: float) -> Dict[int, Dict[str, int]]:
        """Group packet records into time buckets. Returns {bucket_index: stats}."""
        buckets: Dict[int, Dict[str, int]] = defaultdict(
            lambda: {"up_bytes": 0, "down_bytes": 0, "up_pkts": 0,
                     "down_pkts": 0, "up_payload": 0, "max_pkt": 0})
        for r in records:
            idx = int((r.time - t0) / bucket)
            b = buckets[idx]
            if r.is_upload:
                b["up_bytes"] += r.frame_len
                b["up_pkts"] += 1
                # Exclude retransmissions from counted payload volume
                if not r.is_retransmission:
                    b["up_payload"] += r.payload_len
            else:
                b["down_bytes"] += r.frame_len
                b["down_pkts"] += 1
            if r.frame_len > b["max_pkt"]:
                b["max_pkt"] = r.frame_len
        return buckets

    def _detect_upload_events(self, session: LogicalSession):
        """
        Detect multiple distinct upload bursts inside a single logical session.
        The session (TCP stream / QUIC connection) is preserved; events are nested.
        """
        cfg = self._get_upload_config()
        bucket = max(0.01, cfg["bucket"])

        # Gather all packet records across the session's flows
        all_records: List[PacketRecord] = []
        for flow in session.flows:
            all_records.extend(flow.packet_records)
        if not all_records:
            session.upload_events = []
            return

        all_records.sort(key=lambda r: r.time)
        t0 = all_records[0].time

        # Build session-level I/O timeline (stored for graphing)
        buckets = self._build_io_timeline(all_records, bucket, t0)
        max_idx = max(buckets.keys()) if buckets else 0
        session.io_timeline = []
        for i in range(max_idx + 1):
            b = buckets.get(i, {"up_bytes": 0, "down_bytes": 0,
                                 "up_pkts": 0, "down_pkts": 0})
            session.io_timeline.append(
                (t0 + i * bucket, b["up_bytes"], b["down_bytes"],
                 b["up_pkts"], b["down_pkts"]))

        # Determine which buckets are "active" upload buckets
        active_bytes = cfg["bps_threshold"] * bucket   # threshold per bucket
        idle_buckets_to_split = max(1, int(round(cfg["idle_gap"] / bucket)))

        active = []
        for i in range(max_idx + 1):
            b = buckets.get(i)
            if not b:
                active.append(False)
                continue
            up = b["up_payload"]
            down = b["down_bytes"]
            ratio_ok = (up >= down * cfg["min_ratio"]) if down > 0 else True
            active.append(up >= active_bytes and ratio_ok)

        # Group consecutive active buckets, allowing small idle gaps
        events_idx: List[Tuple[int, int]] = []
        i = 0
        n = len(active)
        while i < n:
            if active[i]:
                start = i
                gap = 0
                j = i
                last_active = i
                while j < n:
                    if active[j]:
                        last_active = j
                        gap = 0
                    else:
                        gap += 1
                        if gap > idle_buckets_to_split:
                            break
                    j += 1
                events_idx.append((start, last_active))
                i = j
            else:
                i += 1

        # Build UploadEvent objects, filtering noise
        upload_events: List[UploadEvent] = []
        ev_num = 0
        for (start_i, end_i) in events_idx:
            seg_records = [r for r in all_records
                           if start_i <= int((r.time - t0) / bucket) <= end_i]
            up_records = [r for r in seg_records if r.is_upload and not r.is_retransmission]
            up_payload = sum(r.payload_len for r in up_records)
            down_bytes = sum(r.frame_len for r in seg_records if not r.is_upload)

            ev_start = t0 + start_i * bucket
            ev_end = t0 + (end_i + 1) * bucket
            duration = ev_end - ev_start

            # Noise filtering: enforce min payload + min duration
            if up_payload < cfg["min_payload"] or duration < cfg["min_duration"]:
                continue

            ev_num += 1
            # Per-event timeline + peak rate
            ev_timeline: List[Tuple[float, int, int]] = []
            peak_bps = 0.0
            num_peaks = 0
            for bi in range(start_i, end_i + 1):
                b = buckets.get(bi, {"up_bytes": 0, "down_bytes": 0})
                up_b = b.get("up_bytes", 0)
                dn_b = b.get("down_bytes", 0)
                ev_timeline.append((t0 + bi * bucket, up_b, dn_b))
                bps = up_b / bucket
                if bps > peak_bps:
                    peak_bps = bps
                if bps >= active_bytes / bucket:
                    num_peaks += 1

            avg_bps = up_payload / duration if duration > 0 else 0
            ratio = up_payload / down_bytes if down_bytes > 0 else float('inf')

            client_ports = set()
            flow_ids = set()
            quic_cids = set(session.quic_connection_ids)
            for flow in session.flows:
                if any(start_i <= int((r.time - t0) / bucket) <= end_i
                       for r in flow.packet_records):
                    flow_ids.add(flow.flow_id)
                    for p in flow.src_port.split(","):
                        client_ports.add(p)

            event = UploadEvent(
                event_id=f"{session.session_id}-Upload-{ev_num:02d}",
                session_id=session.session_id,
                flow_ids=sorted(flow_ids),
                protocol=session.protocol,
                client_ip=session.client_ip,
                server_ip=",".join(sorted(session.server_ips)),
                server_name=session.server_name,
                client_ports=client_ports,
                server_port="443",
                quic_cids=quic_cids,
                start_time=ev_start,
                end_time=ev_end,
                duration=duration,
                upload_packets=len(up_records),
                upload_payload_bytes=up_payload,
                download_bytes=down_bytes,
                peak_upload_bps=peak_bps,
                avg_upload_bps=avg_bps,
                upload_ratio=ratio,
                num_peaks=num_peaks,
                timeline=ev_timeline,
            )
            event.confidence = self._score_upload_confidence(event, cfg)
            event.fingerprint = self._fingerprint_event(event, seg_records)
            upload_events.append(event)

        session.upload_events = upload_events

    def _score_upload_confidence(self, event: UploadEvent, cfg) -> float:
        """Heuristic confidence score (0-100) that this is a genuine upload."""
        score = 0.0
        # Payload volume
        if event.upload_payload_bytes >= cfg["min_payload"] * 10:
            score += 30
        elif event.upload_payload_bytes >= cfg["min_payload"]:
            score += 20
        # Duration
        if event.duration >= cfg["min_duration"] * 3:
            score += 20
        elif event.duration >= cfg["min_duration"]:
            score += 10
        # Upload dominance
        if event.upload_ratio == float('inf') or event.upload_ratio >= 3:
            score += 30
        elif event.upload_ratio >= 1:
            score += 20
        elif event.upload_ratio >= 0.5:
            score += 10
        # Sustained peaks
        if event.num_peaks >= 3:
            score += 20
        elif event.num_peaks >= 1:
            score += 10
        return min(100.0, score)

    def _fingerprint_event(self, event: UploadEvent, seg_records) -> str:
        """Compact upload fingerprint string for an event."""
        up_sizes = [r.payload_len for r in seg_records
                    if r.is_upload and r.payload_len > 0]
        avg_sz = int(sum(up_sizes) / len(up_sizes)) if up_sizes else 0
        max_sz = max(up_sizes) if up_sizes else 0
        return (f"{event.protocol}|dur={event.duration:.1f}s|"
                f"bytes={event.upload_payload_bytes}|peak={int(event.peak_upload_bps)}Bps|"
                f"avgpkt={avg_sz}|maxpkt={max_sz}|peaks={event.num_peaks}|"
                f"sni={event.server_name[:30]}")

    def _calculate_statistics(self, pcap_path):
        """Calculate overall statistics"""
        try:
            cmd = [self.tshark_path.get(), "-r", pcap_path, "-q", "-z", "io,stat,0"]
            result = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120)
            
            stats = {"total_packets": 0, "total_bytes": 0, "duration": 0}
            
            for line in result.stdout.split("\n"):
                match = re.search(r"\|\s*(\d+)\s*<>\s*(\d+)\s*\|\s*(\d+)\s*\|\s*(\d+)\s*\|", line)
                if match:
                    stats["total_packets"] = int(match.group(3))
                    stats["total_bytes"] = int(match.group(4))
                    
            # Get capture duration
            cmd3 = [self.tshark_path.get(), "-r", pcap_path, "-T", "fields", "-e", "frame.time_relative"]
            result3 = subprocess.run(cmd3, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120)
            times = [float(t) for t in result3.stdout.strip().split("\n") if t]
            if times:
                stats["duration"] = max(times)
                
            # Count unique IPs (IPv4 + IPv6)
            cmd4 = [self.tshark_path.get(), "-r", pcap_path, "-T", "fields",
                    "-e", "ip.src", "-e", "ip.dst", "-e", "ipv6.src", "-e", "ipv6.dst"]
            result4 = subprocess.run(cmd4, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120)
            ips = set()
            for line in result4.stdout.strip().split("\n"):
                for field in line.split("\t"):
                    for ip in field.split(","):
                        ip = ip.strip()
                        if ip:
                            ips.add(ip)
            stats["unique_ips"] = len(ips)
            
            self.analysis_results["stats"] = stats
        except Exception:
            self.analysis_results["stats"] = {"total_packets": 0, "total_bytes": 0, "duration": 0, "unique_ips": 0}

    # ------------------------------------------------------------------
    # HTTP content / data-leak inspection
    # ------------------------------------------------------------------
    @staticmethod
    def _hex_to_text(hex_str):
        """Decode a tshark bytes field (hex, optionally colon-separated) to text."""
        if not hex_str:
            return ""
        hex_str = hex_str.replace(":", "").strip()
        if not hex_str or len(hex_str) % 2 != 0:
            return hex_str
        try:
            return bytes.fromhex(hex_str).decode("utf-8", errors="replace")
        except ValueError:
            return hex_str

    @staticmethod
    def _hex_to_bytes(hex_str):
        """Decode a tshark bytes field (hex, optionally colon-separated) to raw bytes."""
        if not hex_str:
            return b""
        hex_str = hex_str.replace(":", "").strip()
        if not hex_str or len(hex_str) % 2 != 0:
            return b""
        try:
            return bytes.fromhex(hex_str)
        except ValueError:
            return b""

    @staticmethod
    def _magic_extension(data):
        """Infer file extension from magic bytes."""
        if data.startswith(b"\xff\xd8\xff"):
            return ".jpg"
        if data.startswith(b"\x89PNG\r\n\x1a\n"):
            return ".png"
        if data.startswith((b"GIF87a", b"GIF89a")):
            return ".gif"
        if data.startswith(b"RIFF") and data[8:12] == b"WEBP":
            return ".webp"
        if data.startswith(b"BM"):
            return ".bmp"
        if data.startswith(b"\x25\x50\x44\x46"):
            return ".pdf"
        if data.startswith(b"PK\x03\x04") or data.startswith(b"PK\x05\x06"):
            return ".zip"
        if data[:4] == b"\x1aE\xdf\xa3":
            return ".mkv"
        if data[:4] == b"ftyp":
            return ".mp4"
        return ""

    def _analyze_http(self, pcap_path):
        """
        Extract HTTP transactions (requests + responses) and flag plaintext
        content that may leak sensitive data (credentials, cookies, form posts).
        """
        transactions = []
        try:
            tshark = self.tshark_path.get()
            cmd = [tshark, "-r", pcap_path, "-Y", "http", "-T", "fields",
                   "-e", "frame.number", "-e", "frame.time",
                   "-e", "ip.src", "-e", "ip.dst",
                   "-e", "ipv6.src", "-e", "ipv6.dst",
                   "-e", "http.request.method", "-e", "http.host",
                   "-e", "http.request.uri", "-e", "http.request.full_uri",
                   "-e", "http.response.code", "-e", "http.response.phrase",
                   "-e", "http.content_type", "-e", "http.content_length",
                   "-e", "http.authorization", "-e", "http.authbasic",
                   "-e", "http.cookie", "-e", "http.set_cookie",
                   "-e", "http.user_agent", "-e", "http.referer",
                   "-e", "http.location", "-e", "http.file_data",
                   "-E", "separator=\t", "-E", "occurrence=a", "-E", "aggregator=,"]
            result = subprocess.run(cmd, capture_output=True, text=True,
                                    encoding="utf-8", errors="replace", timeout=240)
            for line in result.stdout.split("\n"):
                if not line.strip():
                    continue
                p = line.split("\t")
                p += [""] * (23 - len(p))
                (fno, ftime, ip4s, ip4d, ip6s, ip6d, method, host, uri, full_uri,
                 code, phrase, ctype, clen, auth, authbasic, cookie, setcookie,
                 ua, referer, location, filedata) = p[:22]
                src = ip4s or ip6s
                dst = ip4d or ip6d

                # Leak heuristics (all HTTP here is cleartext -> inherently risky)
                leaks = []
                if auth or authbasic:
                    leaks.append("CREDENTIALS")
                if cookie or setcookie:
                    leaks.append("COOKIE")
                low_uri = (full_uri or uri).lower()
                if any(k in low_uri for k in ("password", "passwd", "token",
                                              "apikey", "api_key", "auth", "sessionid")):
                    leaks.append("URI-SECRET")
                if method == "POST":
                    leaks.append("POST-BODY")
                leak_label = ", ".join(leaks) if leaks else "cleartext"

                body = self._hex_to_text(filedata) if filedata else ""
                transactions.append({
                    "frame": fno, "time": ftime, "src": src, "dst": dst,
                    "method": method, "host": host,
                    "uri": full_uri or uri or location,
                    "code": f"{code} {phrase}".strip(),
                    "content_type": ctype, "length": clen,
                    "authorization": auth or authbasic,
                    "cookie": cookie, "set_cookie": setcookie,
                    "user_agent": ua, "referer": referer,
                    "leak": leak_label, "leaks": leaks, "body": body,
                })
        except Exception:
            pass
        self.analysis_results["http"] = transactions

    # ------------------------------------------------------------------
    # Extracted files / binary content / images
    # ------------------------------------------------------------------
    @staticmethod
    def _ext_from_mime(mime):
        """Return a safe extension from a MIME type, or empty."""
        if not mime:
            return ""
        mime = mime.split(";")[0].strip().lower()
        ext = mimetypes.guess_extension(mime)
        if ext:
            return ext
        # Fallbacks
        if mime.startswith("image/"):
            subtype = mime.split("/")[-1]
            return "." + subtype
        return ""

    @staticmethod
    def _is_image(ext, data, content_type=""):
        """Detect if extracted data is an image."""
        if ext.lower() in (".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp"):
            return True
        if content_type and content_type.startswith("image/"):
            return True
        return bool(PCAPIntelligenceDashboard._magic_extension(data) in (
            ".jpg", ".png", ".gif", ".webp", ".bmp"))

    def _analyze_files(self, pcap_path):
        """
        Extract HTTP response bodies (images, binary downloads, etc.) from pcap.
        Writes each payload to a temp file and stores metadata for the UI.
        """
        extracted = []
        temp_dir = None
        try:
            # Clean up any previous extraction run
            old = getattr(self, "_files_temp_dir", None)
            if old and os.path.isdir(old):
                shutil.rmtree(old, ignore_errors=True)
            temp_dir = tempfile.mkdtemp(prefix="pcd_extracted_")
            self._files_temp_dir = temp_dir

            tshark = self.tshark_path.get()
            cmd = [tshark, "-r", pcap_path, "-Y", "http.file_data",
                   "-T", "fields",
                   "-e", "frame.number", "-e", "frame.time",
                   "-e", "ip.src", "-e", "ip.dst",
                   "-e", "ipv6.src", "-e", "ipv6.dst",
                   "-e", "http.response.code",
                   "-e", "http.content_type", "-e", "http.content_length",
                   "-e", "http.request.uri", "-e", "http.request.full_uri",
                   "-e", "http.host",
                   "-e", "http.file_data",
                   "-E", "separator=\t", "-E", "occurrence=a", "-E", "aggregator=,"]
            result = subprocess.run(cmd, capture_output=True, text=True,
                                    encoding="utf-8", errors="replace", timeout=240)
            for i, line in enumerate(result.stdout.split("\n")):
                if not line.strip():
                    continue
                p = line.split("\t")
                p += [""] * (13 - len(p))
                (fno, ftime, ip4s, ip4d, ip6s, ip6d,
                 code, ctype, clen, uri, full_uri, host,
                 filedata) = p[:13]
                src = ip4s or ip6s
                dst = ip4d or ip6d

                # file_data may contain multiple reassembled pieces separated by ','
                pieces = [x.strip() for x in (filedata or "").split(",") if x.strip()]
                raw = b"".join(PCAPIntelligenceDashboard._hex_to_bytes(part) for part in pieces)
                if not raw:
                    continue

                size = len(raw)
                ext = self._ext_from_mime(ctype) or self._magic_extension(raw) or ".bin"
                filename = f"frame_{fno or i}_{i}{ext}"
                filepath = os.path.join(temp_dir, filename)
                try:
                    with open(filepath, "wb") as f:
                        f.write(raw)
                except OSError:
                    continue

                is_image = self._is_image(ext, raw, ctype)
                extracted.append({
                    "frame": fno, "time": ftime, "src": src, "dst": dst,
                    "code": code, "content_type": ctype, "length": clen,
                    "size": size, "ext": ext, "uri": full_uri or uri,
                    "host": host, "path": filepath, "is_image": is_image,
                })
        except Exception:
            pass
        self.analysis_results["files"] = extracted

    # ------------------------------------------------------------------
    # STUN / TURN transaction analysis
    # ------------------------------------------------------------------
    @staticmethod
    def _stun_method_name(value):
        """Map common STUN/TURN method codes to readable names."""
        mapping = {
            "0x0001": "Binding",
            "0x0003": "Allocate",
            "0x0004": "Refresh",
            "0x0006": "Send",
            "0x0007": "Data",
            "0x0008": "CreatePermission",
            "0x0009": "ChannelBind",
        }
        text = str(value or "").strip()
        return mapping.get(text.lower(), text)

    @staticmethod
    def _stun_class_name(value):
        """Map common STUN class codes to readable names."""
        mapping = {
            "0x0000": "Request",
            "0x0010": "Indication",
            "0x0100": "Success Response",
            "0x0110": "Error Response",
        }
        text = str(value or "").strip()
        return mapping.get(text.lower(), text)

    @staticmethod
    def _join_unique(values, limit=6):
        """Join non-empty unique values while preserving first-seen order."""
        seen = []
        for value in values:
            text = str(value or "").strip()
            if text and text not in seen:
                seen.append(text)
        if len(seen) > limit:
            return ", ".join(seen[:limit]) + f" +{len(seen) - limit}"
        return ", ".join(seen)

    def _identify_stun_application(self, pkt):
        """Infer likely STUN/TURN application from attributes and ports."""
        haystack = " ".join(str(pkt.get(k, "")) for k in (
            "username", "realm", "software", "info", "ms_version",
            "ms_connection_id", "ms_turn_session_id", "ms_mux_turn_session_id",
            "sip_call_id", "google_network_id", "google_network_cost"
        )).lower()
        ports = {str(pkt.get("src_port", "")), str(pkt.get("dst_port", ""))}

        if any(pkt.get(k) for k in ("ms_version", "ms_connection_id",
                                    "ms_turn_session_id", "ms_mux_turn_session_id",
                                    "sip_call_id")):
            return "Microsoft Teams/Skype ICE"
        if "teams" in haystack or "skype" in haystack or "lync" in haystack:
            return "Microsoft Teams/Skype ICE"
        if pkt.get("google_network_id") or pkt.get("google_network_cost") or "google" in haystack:
            return "Google/WebRTC STUN"
        if "discord" in haystack:
            return "Discord/WebRTC"
        if "zoom" in haystack:
            return "Zoom/WebRTC"
        if "webrtc" in haystack or "libnice" in haystack or "pion" in haystack:
            return "WebRTC ICE"
        if ports & {"3478", "3479", "5349"}:
            return "STUN/TURN"
        if ports & {"19302", "19305", "19307"}:
            return "Google STUN"
        return "Unknown STUN/ICE"

    def _analyze_stun(self, pcap_path):
        """Extract STUN/TURN packets and group them by transaction ID."""
        packets = []
        transactions = []
        try:
            tshark = self.tshark_path.get()
            fields = [
                "frame.number", "frame.time_epoch", "_ws.col.info",
                "ip.src", "ip.dst", "ipv6.src", "ipv6.dst",
                "udp.srcport", "udp.dstport", "tcp.srcport", "tcp.dstport",
                "frame.len", "stun.id", "stun.type", "stun.type.method",
                "stun.type.class", "stun.response-to", "stun.response-in",
                "stun.time", "stun.att.username", "stun.att.realm",
                "stun.att.software", "stun.att.ipv4", "stun.att.ipv6",
                "stun.att.port", "stun.att.ms.version",
                "stun.att.ms.connection_id", "stun.att.ms.turn_session_id",
                "stun.att.ms.multiplexed_turn_session_id",
                "stun.att.sip_call_id", "stun.att.google.network_id",
                "stun.att.google.network_cost",
            ]
            cmd = [tshark, "-r", pcap_path, "-Y", "stun", "-T", "fields"]
            for field in fields:
                cmd += ["-e", field]
            cmd += ["-E", "separator=\t", "-E", "occurrence=a", "-E", "aggregator=,"]
            for line in self._iter_command_lines(cmd, timeout=0, max_lines=200000):
                if not line.strip():
                    continue
                parts = line.split("\t")
                parts += [""] * (len(fields) - len(parts))
                row = dict(zip(fields, parts[:len(fields)]))
                src = row.get("ip.src") or row.get("ipv6.src")
                dst = row.get("ip.dst") or row.get("ipv6.dst")
                sport = row.get("udp.srcport") or row.get("tcp.srcport")
                dport = row.get("udp.dstport") or row.get("tcp.dstport")
                mapped_ip = row.get("stun.att.ipv4") or row.get("stun.att.ipv6")
                mapped_port = row.get("stun.att.port")
                pkt = {
                    "frame": row.get("frame.number", ""),
                    "time": row.get("frame.time_epoch", ""),
                    "info": row.get("_ws.col.info", ""),
                    "src": src,
                    "dst": dst,
                    "src_port": sport,
                    "dst_port": dport,
                    "length": row.get("frame.len", ""),
                    "transaction_id": row.get("stun.id", ""),
                    "message_type": row.get("stun.type", ""),
                    "method": self._stun_method_name(row.get("stun.type.method", "")),
                    "class": self._stun_class_name(row.get("stun.type.class", "")),
                    "response_to": row.get("stun.response-to", ""),
                    "response_in": row.get("stun.response-in", ""),
                    "rtt": row.get("stun.time", ""),
                    "username": row.get("stun.att.username", ""),
                    "realm": row.get("stun.att.realm", ""),
                    "software": row.get("stun.att.software", ""),
                    "mapped_address": f"{mapped_ip}:{mapped_port}" if mapped_ip and mapped_port else mapped_ip,
                    "ms_version": row.get("stun.att.ms.version", ""),
                    "ms_connection_id": row.get("stun.att.ms.connection_id", ""),
                    "ms_turn_session_id": row.get("stun.att.ms.turn_session_id", ""),
                    "ms_mux_turn_session_id": row.get("stun.att.ms.multiplexed_turn_session_id", ""),
                    "sip_call_id": row.get("stun.att.sip_call_id", ""),
                    "google_network_id": row.get("stun.att.google.network_id", ""),
                    "google_network_cost": row.get("stun.att.google.network_cost", ""),
                }
                pkt["application"] = self._identify_stun_application(pkt)
                packets.append(pkt)

            grouped = defaultdict(list)
            for pkt in packets:
                key = pkt.get("transaction_id") or f"frame-{pkt.get('frame')}"
                grouped[key].append(pkt)

            for txid, group in grouped.items():
                group.sort(key=lambda p: float(p.get("time") or 0))
                apps = [p.get("application") for p in group]
                methods = [f"{p.get('method','')}/{p.get('class','')}".strip("/")
                           for p in group]
                rtts = []
                for p in group:
                    try:
                        if p.get("rtt"):
                            rtts.append(float(p["rtt"]) * 1000)
                    except ValueError:
                        pass
                transactions.append({
                    "transaction_id": txid,
                    "frames": self._join_unique([p.get("frame") for p in group], limit=10),
                    "packets": len(group),
                    "src": f"{group[0].get('src')}:{group[0].get('src_port')}",
                    "dst": f"{group[0].get('dst')}:{group[0].get('dst_port')}",
                    "methods": self._join_unique(methods, limit=6),
                    "mapped_address": self._join_unique([p.get("mapped_address") for p in group], limit=4),
                    "username": self._join_unique([p.get("username") for p in group], limit=3),
                    "realm": self._join_unique([p.get("realm") for p in group], limit=3),
                    "software": self._join_unique([p.get("software") for p in group], limit=3),
                    "application": self._join_unique(apps, limit=3),
                    "rtt_ms": f"{min(rtts):.3f}" if rtts else "",
                    "packets_detail": group,
                })

            transactions.sort(key=lambda t: t.get("packets", 0), reverse=True)
        except Exception:
            pass
        self.analysis_results["stun_packets"] = packets
        self.analysis_results["stun_transactions"] = transactions

    # ------------------------------------------------------------------
    # RADIUS authentication/accounting and CSID/ECI correlation
    # ------------------------------------------------------------------
    _RADIUS_CODE_NAMES = {
        "1": "Access-Request",
        "2": "Access-Accept",
        "3": "Access-Reject",
        "4": "Accounting-Request",
        "5": "Accounting-Response",
        "11": "Access-Challenge",
        "12": "Status-Server",
        "13": "Status-Client",
        "40": "Disconnect-Request",
        "41": "Disconnect-ACK",
        "42": "Disconnect-NAK",
        "43": "CoA-Request",
        "44": "CoA-ACK",
        "45": "CoA-NAK",
    }

    @staticmethod
    def _digits_only(value):
        text = re.sub(r"\D+", "", str(value or ""))
        return text or ""

    @classmethod
    def _radius_code_name(cls, value):
        text = str(value or "").strip()
        return cls._RADIUS_CODE_NAMES.get(text, text)

    @staticmethod
    def _radius_connection_type(username):
        text = str(username or "").lower()
        if "@wlan." in text or "wlan" in text or "wifi" in text:
            return "WiFi"
        if "@mobile" in text or "mobile" in text or "ims" in text:
            return "Mobile"
        return "Unknown"

    def _format_radius_mcc_mnc(self, value, label="MCC-MNC"):
        """Format RADIUS 3GPP MCC/MNC strings with country/operator context."""
        text = str(value or "").strip()
        if not text:
            return ""
        digits = self._digits_only(text)
        if len(digits) >= 5:
            mcc = digits[:3]
            mnc = digits[3:]
            return self._format_mobile_area(label, mcc, mnc, "", "")
        return f"{label} {text}"

    @staticmethod
    def _time_delta(a, b):
        try:
            return abs(float(a) - float(b))
        except Exception:
            return None

    def _analyze_radius(self, pcap_path):
        """Extract RADIUS packets and correlate Calling-Station-Id with GTPv2 ECI."""
        radius_rows = []
        gtp_rows = []
        correlations = []
        try:
            tshark = self.tshark_path.get()
            radius_fields = self._filter_tshark_fields([
                "frame.number", "frame.time_epoch", "_ws.col.info",
                "eth.src", "eth.dst", "ip.src", "ip.dst", "ipv6.src", "ipv6.dst",
                "udp.srcport", "udp.dstport", "radius.code", "radius.id",
                "radius.User_Name", "radius.Calling_Station_Id", "radius.Called_Station_Id",
                "radius.NAS_IP_Address", "radius.NAS_IPv6_Address", "radius.NAS_Port",
                "radius.NAS_Port_Id", "radius.NAS_Port_Type", "radius.Framed_IP_Address",
                "radius.Framed-IP-Address", "radius.Framed_IPv6_Address", "radius.Acct_Session_Id",
                "radius.Acct_Multi_Session_Id", "radius.Acct_Status_Type",
                "radius.Acct_Session_Time", "radius.Acct_Input_Octets",
                "radius.Acct_Output_Octets", "radius.Acct_Input_Packets",
                "radius.Acct_Output_Packets", "radius.Location_Information",
                "radius.Location_Data", "radius.Alc_MsIsdn", "radius.Alc_APN_Name",
                "radius.Alc_Wlan_APN_Name", "radius.3GPP_IMSI",
                "radius.3GPP_IMEISV", "radius.Alphion_Mdps_Device_Imei",
                "radius.3GPP_IMSI_MCC_MNC", "radius.3GPP_SGSN_MCC_MNC",
                "radius.3GPP_GGSN_MCC_MNC", "e212.imsi", "e212.mcc", "e212.mnc",
            ])
            if radius_fields:
                cmd = [tshark, "-r", pcap_path, "-Y", "radius", "-T", "fields"]
                for field in radius_fields:
                    cmd += ["-e", field]
                cmd += ["-E", "separator=\t", "-E", "occurrence=a", "-E", "aggregator=,"]
                for line in self._iter_command_lines(cmd, timeout=300, max_lines=200000):
                    if not line.strip():
                        continue
                    parts = line.split("\t")
                    parts += [""] * (len(radius_fields) - len(parts))
                    row = dict(zip(radius_fields, parts[:len(radius_fields)]))
                    username = row.get("radius.User_Name", "")
                    calling = row.get("radius.Calling_Station_Id", "")
                    called = row.get("radius.Called_Station_Id", "")
                    code = row.get("radius.code", "")
                    src = row.get("ip.src") or row.get("ipv6.src")
                    dst = row.get("ip.dst") or row.get("ipv6.dst")
                    framed_ip = (row.get("radius.Framed_IP_Address")
                                 or row.get("radius.Framed-IP-Address")
                                 or row.get("radius.Framed_IPv6_Address"))
                    nas_ip = row.get("radius.NAS_IP_Address") or row.get("radius.NAS_IPv6_Address")
                    imsi = self._compact_join([
                        row.get("radius.3GPP_IMSI", ""),
                        row.get("e212.imsi", ""),
                        *self._subscriber_digits(username, 14, 16),
                    ], limit=3)
                    imei = self._compact_join([
                        row.get("radius.3GPP_IMEISV", ""),
                        row.get("radius.Alphion_Mdps_Device_Imei", ""),
                    ], limit=3)
                    mcc_mnc = self._compact_join([
                        self._format_radius_mcc_mnc(row.get("radius.3GPP_IMSI_MCC_MNC", ""), "IMSI-MCC-MNC"),
                        self._format_radius_mcc_mnc(row.get("radius.3GPP_SGSN_MCC_MNC", ""), "SGSN-MCC-MNC"),
                        self._format_radius_mcc_mnc(row.get("radius.3GPP_GGSN_MCC_MNC", ""), "GGSN-MCC-MNC"),
                        self._format_mobile_area("E212", row.get("e212.mcc", ""), row.get("e212.mnc", ""), "", ""),
                    ], limit=4)
                    radius_rows.append({
                        "frame": row.get("frame.number", ""),
                        "time": row.get("frame.time_epoch", ""),
                        "info": row.get("_ws.col.info", ""),
                        "src_mac": row.get("eth.src", ""),
                        "dst_mac": row.get("eth.dst", ""),
                        "src": src,
                        "dst": dst,
                        "src_port": row.get("udp.srcport", ""),
                        "dst_port": row.get("udp.dstport", ""),
                        "code": code,
                        "code_name": self._radius_code_name(code),
                        "status": "Success" if code in {"2", "5", "41", "44"} else ("Failure" if code in {"3", "42", "45"} else ""),
                        "radius_id": row.get("radius.id", ""),
                        "username": username,
                        "imsi": imsi,
                        "imei": imei,
                        "mcc_mnc": mcc_mnc,
                        "calling_station_id": calling,
                        "called_station_id": called,
                        "nas_ip": nas_ip,
                        "nas_port": row.get("radius.NAS_Port", ""),
                        "nas_port_id": row.get("radius.NAS_Port_Id", ""),
                        "nas_port_type": row.get("radius.NAS_Port_Type", ""),
                        "framed_ip": framed_ip,
                        "acct_session_id": row.get("radius.Acct_Session_Id", ""),
                        "acct_multi_session_id": row.get("radius.Acct_Multi_Session_Id", ""),
                        "acct_status_type": row.get("radius.Acct_Status_Type", ""),
                        "acct_session_time": row.get("radius.Acct_Session_Time", ""),
                        "acct_input_octets": row.get("radius.Acct_Input_Octets", ""),
                        "acct_output_octets": row.get("radius.Acct_Output_Octets", ""),
                        "acct_input_packets": row.get("radius.Acct_Input_Packets", ""),
                        "acct_output_packets": row.get("radius.Acct_Output_Packets", ""),
                        "location_information": self._hex_or_text(row.get("radius.Location_Information", "")),
                        "location_data": self._hex_or_text(row.get("radius.Location_Data", "")),
                        "msisdn": row.get("radius.Alc_MsIsdn", ""),
                        "apn": self._compact_join([
                            row.get("radius.Alc_APN_Name", ""),
                            row.get("radius.Alc_Wlan_APN_Name", ""),
                        ], limit=3),
                        "connection_type": self._radius_connection_type(username),
                        "username_digits": self._digits_only(username),
                        "calling_digits": self._digits_only(calling),
                    })

            gtp_fields = self._filter_tshark_fields([
                "frame.number", "frame.time_epoch", "ip.src", "ip.dst", "ipv6.src", "ipv6.dst",
                "gtpv2.ecgi_eci", "gtpv2.imsi", "e212.imsi", "gtpv2.msisdn",
                "e164.msisdn", "gtp.ext_imeisv", "e212.mcc", "e212.mnc",
                "e212.ecgi.mcc", "e212.ecgi.mnc", "e212.tai.mcc", "e212.tai.mnc",
                "gtpv2.teid", "gtpv2.teid_c",
            ])
            if gtp_fields and "gtpv2.ecgi_eci" in gtp_fields:
                cmd = [tshark, "-r", pcap_path, "-Y", "gtpv2.ecgi_eci", "-T", "fields"]
                for field in gtp_fields:
                    cmd += ["-e", field]
                cmd += ["-E", "separator=\t", "-E", "occurrence=a", "-E", "aggregator=,"]
                for line in self._iter_command_lines(cmd, timeout=300, max_lines=200000):
                    if not line.strip():
                        continue
                    parts = line.split("\t")
                    parts += [""] * (len(gtp_fields) - len(parts))
                    row = dict(zip(gtp_fields, parts[:len(gtp_fields)]))
                    eci = row.get("gtpv2.ecgi_eci", "")
                    if not eci:
                        continue
                    imsi = row.get("gtpv2.imsi") or row.get("e212.imsi")
                    msisdn = row.get("gtpv2.msisdn") or row.get("e164.msisdn")
                    gtp_mcc_mnc = self._compact_join([
                        self._format_mobile_area("PLMN", row.get("e212.ecgi.mcc") or row.get("e212.mcc"),
                                                 row.get("e212.ecgi.mnc") or row.get("e212.mnc"), "", ""),
                        self._format_mobile_area("TAI", row.get("e212.tai.mcc"),
                                                 row.get("e212.tai.mnc"), "", ""),
                    ], limit=3)
                    gtp_rows.append({
                        "frame": row.get("frame.number", ""),
                        "time": row.get("frame.time_epoch", ""),
                        "src": row.get("ip.src") or row.get("ipv6.src"),
                        "dst": row.get("ip.dst") or row.get("ipv6.dst"),
                        "eci": eci,
                        "imsi": self._digits_only(imsi),
                        "imei": row.get("gtp.ext_imeisv", ""),
                        "mcc_mnc": gtp_mcc_mnc,
                        "msisdn": self._digits_only(msisdn),
                        "teid": row.get("gtpv2.teid") or row.get("gtpv2.teid_c"),
                    })

            used = set()
            for r in radius_rows:
                candidates = [
                    ("imsi", r.get("imsi") or r.get("username_digits")),
                    ("msisdn", r.get("calling_digits") or self._digits_only(r.get("msisdn"))),
                ]
                for method, candidate in candidates:
                    if not candidate:
                        continue
                    for g in gtp_rows:
                        if method == "imsi" and candidate != g.get("imsi"):
                            continue
                        if method == "msisdn" and candidate != g.get("msisdn"):
                            continue
                        key = (r.get("frame"), g.get("frame"), method)
                        if key in used:
                            continue
                        used.add(key)
                        delta = self._time_delta(r.get("time"), g.get("time"))
                        correlations.append({
                            "calling_station_id": r.get("calling_station_id", ""),
                            "eci": g.get("eci", ""),
                            "method": method,
                            "radius_frame": r.get("frame", ""),
                            "gtp_frame": g.get("frame", ""),
                            "delta_seconds": "" if delta is None else f"{delta:.3f}",
                            "username": r.get("username", ""),
                            "imsi": r.get("imsi") or (g.get("imsi", "") if method == "imsi" else ""),
                            "imei": r.get("imei") or g.get("imei", ""),
                            "mcc_mnc": r.get("mcc_mnc") or g.get("mcc_mnc", ""),
                            "msisdn": g.get("msisdn", "") if method == "msisdn" else "",
                            "radius_ip": f"{r.get('src', '')}->{r.get('dst', '')}",
                            "gtp_ip": f"{g.get('src', '')}->{g.get('dst', '')}",
                            "radius": r,
                            "gtpv2": g,
                        })

            if not correlations and radius_rows and gtp_rows:
                for r in radius_rows[:1000]:
                    best = None
                    for g in gtp_rows[:1000]:
                        delta = self._time_delta(r.get("time"), g.get("time"))
                        if delta is None or delta > 30:
                            continue
                        if best is None or delta < best[0]:
                            best = (delta, g)
                    if not best:
                        continue
                    delta, g = best
                    correlations.append({
                        "calling_station_id": r.get("calling_station_id", ""),
                        "eci": g.get("eci", ""),
                        "method": "time<=30s",
                        "radius_frame": r.get("frame", ""),
                        "gtp_frame": g.get("frame", ""),
                        "delta_seconds": f"{delta:.3f}",
                        "username": r.get("username", ""),
                        "imsi": r.get("imsi") or g.get("imsi", ""),
                        "imei": r.get("imei") or g.get("imei", ""),
                        "mcc_mnc": r.get("mcc_mnc") or g.get("mcc_mnc", ""),
                        "msisdn": g.get("msisdn", ""),
                        "radius_ip": f"{r.get('src', '')}->{r.get('dst', '')}",
                        "gtp_ip": f"{g.get('src', '')}->{g.get('dst', '')}",
                        "radius": r,
                        "gtpv2": g,
                    })
        except Exception:
            pass
        self.analysis_results["radius_packets"] = radius_rows
        self.analysis_results["radius_correlations"] = correlations

    # ------------------------------------------------------------------
    # SS7 / GSM MAP subscriber and SMS leak analysis
    # ------------------------------------------------------------------
    @staticmethod
    def _compact_join(values, limit=5):
        """Join unique non-empty values for dense SS7 table cells."""
        seen = []
        for value in values:
            for part in str(value or "").split(","):
                text = part.strip()
                if text and text not in seen:
                    seen.append(text)
        if len(seen) > limit:
            return ", ".join(seen[:limit]) + f" +{len(seen) - limit}"
        return ", ".join(seen)

    @staticmethod
    def _hex_or_text(value):
        """Render hex-ish bytes as readable text when possible."""
        text = str(value or "").strip()
        if not text:
            return ""
        cleaned = text.replace(":", "").replace(" ", "")
        if re.fullmatch(r"[0-9A-Fa-f]+", cleaned or "") and len(cleaned) % 2 == 0:
            try:
                decoded = bytes.fromhex(cleaned).decode("utf-8", errors="ignore").strip()
                if decoded and sum(ch.isprintable() for ch in decoded) >= max(1, len(decoded) * 0.7):
                    return decoded
            except ValueError:
                pass
        return text

    @staticmethod
    def _decode_sms_tpdu_text(*values):
        """Best-effort readable SMS text extraction from raw TPDU/RP-UI hex."""
        best = ""
        for value in values:
            text = str(value or "").strip().replace(":", "").replace(" ", "").replace(",", "")
            if not text or not re.fullmatch(r"[0-9A-Fa-f]+", text) or len(text) < 8:
                continue
            try:
                data = bytes.fromhex(text)
            except ValueError:
                continue
            for offset in range(min(len(data), 80)):
                chunk = data[offset:]
                if len(chunk) < 8:
                    continue
                if len(chunk) % 2:
                    chunk = chunk[:-1]
                try:
                    decoded = chunk.decode("utf-16-be", errors="ignore")
                except Exception:
                    continue
                cleaned = "".join(ch if (ch.isprintable() or ch in "\r\n\t") else " " for ch in decoded)
                cleaned = re.sub(r"[ \t]+", " ", cleaned).strip()
                if not cleaned:
                    continue
                runs = re.findall(r"[\w\s\u0600-\u06FF.,:;!?@#%&*()+/\\-]{6,}", cleaned, flags=re.UNICODE)
                for run in runs:
                    run = run.strip()
                    useful = sum(1 for ch in run if ch.isalnum() or "\u0600" <= ch <= "\u06FF")
                    if useful >= 4 and len(run) > len(best):
                        best = run
        return best[:4000]

    @staticmethod
    def _subscriber_digits(value, min_len=10, max_len=17):
        """Find mobile subscriber/device-looking digit strings inside text."""
        found = []
        for match in re.findall(r"\d{%d,%d}" % (min_len, max_len), str(value or "")):
            if match not in found:
                found.append(match)
        return found

    _MCC_COUNTRIES = {
        "202": "Greece", "204": "Netherlands", "206": "Belgium", "208": "France",
        "212": "Monaco", "213": "Andorra", "214": "Spain", "216": "Hungary",
        "218": "Bosnia and Herzegovina", "219": "Croatia", "220": "Serbia",
        "222": "Italy", "226": "Romania", "228": "Switzerland", "230": "Czech Republic",
        "232": "Austria", "234": "United Kingdom", "235": "United Kingdom",
        "238": "Denmark", "240": "Sweden", "242": "Norway", "244": "Finland",
        "250": "Russia", "255": "Ukraine", "260": "Poland", "262": "Germany",
        "268": "Portugal", "270": "Luxembourg", "272": "Ireland", "274": "Iceland",
        "276": "Albania", "278": "Malta", "280": "Cyprus", "282": "Georgia",
        "286": "Turkey", "288": "Faroe Islands", "290": "Greenland",
        "302": "Canada", "310": "United States", "311": "United States",
        "312": "United States", "313": "United States", "314": "United States",
        "315": "United States", "316": "United States", "334": "Mexico",
        "404": "India", "405": "India", "410": "Pakistan", "412": "Afghanistan",
        "413": "Sri Lanka", "414": "Myanmar", "415": "Lebanon", "416": "Jordan",
        "417": "Syria", "418": "Iraq", "419": "Kuwait", "420": "Saudi Arabia",
        "421": "Yemen", "422": "Oman", "424": "United Arab Emirates",
        "425": "Israel", "426": "Bahrain", "427": "Qatar", "428": "Mongolia",
        "429": "Nepal", "430": "United Arab Emirates", "431": "United Arab Emirates",
        "432": "Iran", "434": "Uzbekistan", "436": "Tajikistan",
        "437": "Kyrgyzstan", "438": "Turkmenistan", "440": "Japan", "441": "Japan",
        "450": "South Korea", "454": "Hong Kong", "455": "Macau", "456": "Cambodia",
        "457": "Laos", "460": "China", "466": "Taiwan", "470": "Bangladesh",
        "502": "Malaysia", "505": "Australia", "510": "Indonesia", "515": "Philippines",
        "520": "Thailand", "525": "Singapore", "528": "Brunei", "530": "New Zealand",
        "602": "Egypt", "603": "Algeria", "604": "Morocco", "605": "Tunisia",
        "606": "Libya", "607": "Gambia", "608": "Senegal", "609": "Mauritania",
        "610": "Mali", "611": "Guinea", "612": "Ivory Coast", "613": "Burkina Faso",
        "614": "Niger", "615": "Togo", "616": "Benin", "617": "Mauritius",
        "618": "Liberia", "619": "Sierra Leone", "620": "Ghana", "621": "Nigeria",
        "622": "Chad", "623": "Central African Republic", "624": "Cameroon",
        "625": "Cape Verde", "626": "Sao Tome and Principe",
        "627": "Equatorial Guinea", "628": "Gabon", "629": "Republic of the Congo",
        "630": "Democratic Republic of the Congo", "631": "Angola",
        "632": "Guinea-Bissau", "633": "Seychelles", "634": "Sudan", "635": "Rwanda",
        "636": "Ethiopia", "637": "Somalia", "638": "Djibouti", "639": "Kenya",
        "640": "Tanzania", "641": "Uganda", "642": "Burundi", "643": "Mozambique",
        "645": "Zambia", "646": "Madagascar", "647": "Reunion", "648": "Zimbabwe",
        "649": "Namibia", "650": "Malawi", "651": "Lesotho", "652": "Botswana",
        "653": "Eswatini", "655": "South Africa", "657": "Eritrea",
        "702": "Belize", "704": "Guatemala", "706": "El Salvador", "708": "Honduras",
        "710": "Nicaragua", "712": "Costa Rica", "714": "Panama", "716": "Peru",
        "722": "Argentina", "724": "Brazil", "730": "Chile", "732": "Colombia",
        "734": "Venezuela", "736": "Bolivia", "738": "Guyana", "740": "Ecuador",
        "744": "Paraguay", "746": "Suriname", "748": "Uruguay",
    }
    _MNC_OPERATORS = {
        ("424", "02"): "Etisalat",
        ("424", "03"): "du",
    }

    @classmethod
    def _format_mcc(cls, value):
        text = str(value or "").strip()
        if not text:
            return ""
        country = cls._MCC_COUNTRIES.get(text.zfill(3))
        return f"{text} ({country})" if country else text

    @classmethod
    def _format_mnc(cls, mcc, value):
        text = str(value or "").strip()
        if not text:
            return ""
        mcc_text = str(mcc or "").strip().zfill(3)
        operator = cls._MNC_OPERATORS.get((mcc_text, text)) or cls._MNC_OPERATORS.get((mcc_text, text.zfill(2)))
        return f"{text} ({operator})" if operator else text

    def _format_mobile_area(self, label, mcc, mnc, area_label, area_value):
        """Format a decoded mobile area identity with MCC country/operator context."""
        if not (mcc or mnc or area_value):
            return ""
        parts = []
        if mcc:
            parts.append(f"MCC={self._format_mcc(mcc)}")
        if mnc:
            parts.append(f"MNC={self._format_mnc(mcc, mnc)}")
        if area_value:
            parts.append(f"{area_label}={area_value}")
        return f"{label} " + " ".join(parts)

    def _analyze_ss7_signaling(self, pcap_path):
        """Extract decoded SS7/SIGTRAN packet details using TShark dissectors."""
        records = []
        try:
            tshark = self.tshark_path.get()
            fields = [
                "frame.number", "frame.time_epoch", "_ws.col.protocol", "_ws.col.info",
                "frame.protocols", "ip.src", "ip.dst", "ipv6.src", "ipv6.dst",
                "sctp.srcport", "sctp.dstport", "udp.srcport", "udp.dstport",
                "m3ua.protocol_data_opc", "m3ua.protocol_data_dpc",
                "m3ua.protocol_data_si", "m3ua.protocol_data_ni",
                "m3ua.protocol_data_mp", "m3ua.protocol_data_sls",
                "mtp3.opc", "mtp3.dpc", "mtp3.service_indicator",
                "mtp3.network_indicator", "mtp3.sls",
                "sccp.calling.digits", "sccp.called.digits",
                "sccp.calling.ssn", "sccp.called.ssn",
                "sccp.calling.gt.nai", "sccp.called.gt.nai",
                "sccp.calling.gt.np", "sccp.called.gt.np",
                "sccp.calling.gt.tt", "sccp.called.gt.tt",
                "sccp.message_type", "sccp.slr", "sccp.dlr",
                "tcap.tid", "tcap.otid", "tcap.dtid",
                "tcap.begin", "tcap.continue", "tcap.end", "tcap.abort",
                "tcap.invokeID", "tcap.opcode", "tcap.localValue",
                "tcap.returnResultLast", "tcap.returnError", "tcap.reject",
                "gsm_map.opcode", "gsm_map.localValue", "gsm_map.imsi",
                "gsm_map.sm.imsi", "gsm_map.ss.imsi", "gsm_map.er.imsi",
                "gsm_map.om.imsi", "gsm_map.ms.imsi",
                "gsm_map.ms.imei", "gsm_map.ms.imeisv",
                "gsm_map.msisdn", "gsm_map.sm.msisdn", "gsm_map.ss.msisdn",
                "gsm_map.ms.msisdn", "gsm_map.address.digits",
                "gsm_map.tbcd_digits", "gsm_map.sm.sm_RP_UI",
                "gsm_map.gr.sm_RP_UI", "gsm_old.sm_RP_UI",
                "gsm_sms.sms_text", "gsm_sms.sms_body",
                "gsm_sms.tp-oa", "gsm_sms.tp-da", "gsm_sms.tp-ra",
                "gsm_sms.tp-mti", "gsm_sms.tp-dcs",
                "gsm_map.ussd_string", "gsm_map.ss.ussd_String",
                "gsm_map.apn_str", "gsm_map.ms.apn", "gsm_map.ms.APN",
                "gsm_map.cellGlobalIdOrServiceAreaIdFixedLength",
                "gsm_map.ms.LocationArea", "gsm_map.ms.lac",
                "gsm_map.ms.locationInformation_element",
                "gsm_map.ms.locationInformationGPRS_element",
                "gsm_map.ms.locationInformationEPS_element",
                "gsm_map.ms.targetCellId", "gsm_map.ms.targetRNCId",
                "gsm_map.om.GlobalCellId", "gsm_map.om.E_UTRAN_CGI",
                "gsm_map.om.RAIdentity",
                "gsm_map.ericsson.locationInformation.rat",
                "gsm_map.ericsson.locationInformation.lac",
                "gsm_map.ericsson.locationInformation.ci",
                "gsm_map.ericsson.locationInformation.sac",
                "e212.imsi", "e212.mcc", "e212.mnc",
                "e212.lai.mcc", "e212.lai.mnc", "e212.cgi.mcc", "e212.cgi.mnc",
                "e164.msisdn",
                "isup.cic", "isup.message_type", "isup.calling_party_number.digits",
                "isup.called_party_number.digits", "isup.cause_indicator.cause_value",
                "isup.redirecting_number.digits", "isup.connected_number.digits",
                "bssap.cell_global_id", "bssap.lac", "bssap.ci",
                "gsm_a.dtap.clg_party_bcd_num", "gsm_a.dtap.cld_party_bcd_num",
                "gsm_a.dtap.msg_mm_type", "gsm_a.dtap.msg_gmm_type",
                "gsm_a.dtap.msg_sms_type", "gsm_a.tmsi",
            ]
            fields = self._filter_tshark_fields(fields)
            if not fields:
                self.analysis_results["ss7_signaling"] = records
                return

            proto_filters = []
            for prefix, proto in (
                ("mtp3.", "mtp3"), ("m3ua.", "m3ua"), ("sccp.", "sccp"),
                ("tcap.", "tcap"), ("gsm_map.", "gsm_map"), ("isup.", "isup"),
                ("bssap.", "bssap"), ("gsm_a.", "gsm_a"), ("gsm_sms.", "gsm_sms"),
            ):
                if any(f.startswith(prefix) for f in fields) and proto not in proto_filters:
                    proto_filters.append(proto)
            if not proto_filters:
                self.analysis_results["ss7_signaling"] = records
                return
            display_filter = " || ".join(proto_filters)
            cmd = [tshark, "-r", pcap_path, "-Y", display_filter, "-T", "fields"]
            for field in fields:
                cmd += ["-e", field]
            cmd += ["-E", "separator=\t", "-E", "occurrence=a", "-E", "aggregator=,"]

            for line in self._iter_command_lines(cmd, timeout=300, max_lines=200000):
                if not line.strip():
                    continue
                parts = line.split("\t")
                parts += [""] * (len(fields) - len(parts))
                row = dict(zip(fields, parts[:len(fields)]))

                src = row.get("ip.src") or row.get("ipv6.src") or row.get("m3ua.protocol_data_opc") or row.get("mtp3.opc")
                dst = row.get("ip.dst") or row.get("ipv6.dst") or row.get("m3ua.protocol_data_dpc") or row.get("mtp3.dpc")
                opc = row.get("m3ua.protocol_data_opc") or row.get("mtp3.opc")
                dpc = row.get("m3ua.protocol_data_dpc") or row.get("mtp3.dpc")
                sls = row.get("m3ua.protocol_data_sls") or row.get("mtp3.sls")
                tcap_ids = self._compact_join([
                    f"TID={row.get('tcap.tid')}" if row.get("tcap.tid") else "",
                    f"OTID={row.get('tcap.otid')}" if row.get("tcap.otid") else "",
                    f"DTID={row.get('tcap.dtid')}" if row.get("tcap.dtid") else "",
                    f"Invoke={row.get('tcap.invokeID')}" if row.get("tcap.invokeID") else "",
                ], limit=6)
                map_operation = self._compact_join([
                    row.get("gsm_map.opcode"), row.get("gsm_map.localValue"),
                    row.get("tcap.opcode"), row.get("tcap.localValue"),
                ], limit=4)
                imsi = self._compact_join([
                    row.get("gsm_map.imsi"), row.get("gsm_map.sm.imsi"),
                    row.get("gsm_map.ss.imsi"), row.get("gsm_map.er.imsi"),
                    row.get("gsm_map.om.imsi"), row.get("gsm_map.ms.imsi"),
                    row.get("e212.imsi"),
                ], limit=6)
                imei = self._compact_join([
                    row.get("gsm_map.ms.imei"), row.get("gsm_map.ms.imeisv"),
                ], limit=4)
                msisdn = self._compact_join([
                    row.get("gsm_map.msisdn"), row.get("gsm_map.sm.msisdn"),
                    row.get("gsm_map.ss.msisdn"), row.get("gsm_map.ms.msisdn"),
                    row.get("e164.msisdn"), row.get("gsm_map.address.digits"),
                    row.get("gsm_map.tbcd_digits"),
                ], limit=6)
                mcc_mnc = self._compact_join([
                    self._format_mobile_area("E212", row.get("e212.mcc"), row.get("e212.mnc"), "", ""),
                    self._format_mobile_area("LAI", row.get("e212.lai.mcc"), row.get("e212.lai.mnc"),
                                             "LAC", row.get("gsm_map.ms.lac")),
                    self._format_mobile_area("CGI", row.get("e212.cgi.mcc"), row.get("e212.cgi.mnc"), "", ""),
                ], limit=4)
                location = self._compact_join([
                    row.get("gsm_map.cellGlobalIdOrServiceAreaIdFixedLength"),
                    row.get("gsm_map.ms.LocationArea"),
                    f"LAC={row.get('gsm_map.ms.lac')}" if row.get("gsm_map.ms.lac") else "",
                    self._hex_or_text(row.get("gsm_map.ms.locationInformation_element")),
                    self._hex_or_text(row.get("gsm_map.ms.locationInformationGPRS_element")),
                    self._hex_or_text(row.get("gsm_map.ms.locationInformationEPS_element")),
                    row.get("gsm_map.ms.targetCellId"), row.get("gsm_map.ms.targetRNCId"),
                    row.get("gsm_map.om.GlobalCellId"), row.get("gsm_map.om.E_UTRAN_CGI"),
                    row.get("gsm_map.om.RAIdentity"),
                    row.get("gsm_map.ericsson.locationInformation.rat"),
                    row.get("gsm_map.ericsson.locationInformation.lac"),
                    row.get("gsm_map.ericsson.locationInformation.ci"),
                    row.get("gsm_map.ericsson.locationInformation.sac"),
                    row.get("bssap.cell_global_id"), row.get("bssap.lac"), row.get("bssap.ci"),
                ], limit=10)
                sms_decoded_by_tshark = row.get("gsm_sms.sms_text", "")
                sms_best_effort = "" if sms_decoded_by_tshark else self._decode_sms_tpdu_text(
                    row.get("gsm_sms.sms_body"),
                    row.get("gsm_map.sm.sm_RP_UI"),
                    row.get("gsm_map.gr.sm_RP_UI"),
                    row.get("gsm_old.sm_RP_UI"))
                sms_text = sms_decoded_by_tshark or sms_best_effort
                sms_raw_tpdu = self._compact_join([
                    row.get("gsm_sms.sms_body"),
                    row.get("gsm_map.sm.sm_RP_UI"),
                    row.get("gsm_map.gr.sm_RP_UI"),
                    row.get("gsm_old.sm_RP_UI"),
                ], limit=4)
                sms_text_source = "TShark gsm_sms.sms_text" if sms_decoded_by_tshark else (
                    "Best-effort UCS-2/UTF-16 TPDU decode" if sms_best_effort else "")
                ussd = self._compact_join([
                    row.get("gsm_map.ussd_string"),
                    self._hex_or_text(row.get("gsm_map.ss.ussd_String")),
                ], limit=3)
                call_from = self._compact_join([
                    row.get("isup.calling_party_number.digits"),
                    row.get("isup.redirecting_number.digits"),
                    row.get("gsm_a.dtap.clg_party_bcd_num"),
                    row.get("gsm_sms.tp-oa"),
                ], limit=4)
                call_to = self._compact_join([
                    row.get("isup.called_party_number.digits"),
                    row.get("isup.connected_number.digits"),
                    row.get("gsm_a.dtap.cld_party_bcd_num"),
                    row.get("gsm_sms.tp-da"), row.get("gsm_sms.tp-ra"),
                ], limit=4)
                result_cause = self._compact_join([
                    "TCAP ReturnResult" if row.get("tcap.returnResultLast") else "",
                    "TCAP ReturnError" if row.get("tcap.returnError") else "",
                    "TCAP Reject" if row.get("tcap.reject") else "",
                    "TCAP Abort" if row.get("tcap.abort") else "",
                    f"ISUP cause={row.get('isup.cause_indicator.cause_value')}"
                    if row.get("isup.cause_indicator.cause_value") else "",
                    row.get("gsm_a.dtap.msg_mm_type"),
                    row.get("gsm_a.dtap.msg_gmm_type"),
                    row.get("gsm_a.dtap.msg_sms_type"),
                ], limit=8)
                layers = self._compact_join([
                    row.get("frame.protocols"), row.get("m3ua.protocol_data_si"),
                    row.get("mtp3.service_indicator"), row.get("sccp.message_type"),
                    row.get("isup.message_type"),
                ], limit=5)
                raw_fields = {k: v for k, v in row.items() if str(v or "").strip()}
                records.append({
                    "frame": row.get("frame.number", ""),
                    "time": row.get("frame.time_epoch", ""),
                    "stack": row.get("_ws.col.protocol", ""),
                    "layers": layers,
                    "src": src,
                    "dst": dst,
                    "sctp_srcport": row.get("sctp.srcport", ""),
                    "sctp_dstport": row.get("sctp.dstport", ""),
                    "opc": opc,
                    "dpc": dpc,
                    "sls": sls,
                    "calling_gt": row.get("sccp.calling.digits", ""),
                    "called_gt": row.get("sccp.called.digits", ""),
                    "calling_ssn": row.get("sccp.calling.ssn", ""),
                    "called_ssn": row.get("sccp.called.ssn", ""),
                    "calling_gt_meta": self._compact_join([
                        row.get("sccp.calling.gt.nai"), row.get("sccp.calling.gt.np"),
                        row.get("sccp.calling.gt.tt"),
                    ], limit=3),
                    "called_gt_meta": self._compact_join([
                        row.get("sccp.called.gt.nai"), row.get("sccp.called.gt.np"),
                        row.get("sccp.called.gt.tt"),
                    ], limit=3),
                    "sccp_message_type": row.get("sccp.message_type", ""),
                    "tcap_ids": tcap_ids,
                    "tcap_dialog": self._compact_join([
                        "Begin" if row.get("tcap.begin") else "",
                        "Continue" if row.get("tcap.continue") else "",
                        "End" if row.get("tcap.end") else "",
                        "Abort" if row.get("tcap.abort") else "",
                    ], limit=4),
                    "map_operation": map_operation,
                    "isup_cic": row.get("isup.cic", ""),
                    "isup_message_type": row.get("isup.message_type", ""),
                    "call_from": call_from,
                    "call_to": call_to,
                    "imsi": imsi,
                    "imei": imei,
                    "msisdn": msisdn,
                    "mcc_mnc": mcc_mnc,
                    "location": location,
                    "sms_text": sms_text,
                    "sms_text_source": sms_text_source,
                    "sms_raw_tpdu": sms_raw_tpdu,
                    "sms_from": row.get("gsm_sms.tp-oa", ""),
                    "sms_to": row.get("gsm_sms.tp-da", "") or row.get("gsm_sms.tp-ra", ""),
                    "sms_type": row.get("gsm_sms.tp-mti", ""),
                    "sms_dcs": row.get("gsm_sms.tp-dcs", ""),
                    "ussd": ussd,
                    "apn": self._compact_join([
                        row.get("gsm_map.apn_str"),
                        self._hex_or_text(row.get("gsm_map.ms.apn")),
                        self._hex_or_text(row.get("gsm_map.ms.APN")),
                    ], limit=3),
                    "result_cause": result_cause,
                    "info": row.get("_ws.col.info", ""),
                    "raw_fields": raw_fields,
                })
        except subprocess.TimeoutExpired:
            self.analysis_results.setdefault("analysis_notes", []).append(
                "SS7 signaling extraction stopped by timeout; partial decoded rows were kept.")
        except Exception as e:
            print(f"Error analyzing SS7 signaling: {e}")
        self.analysis_results["ss7_signaling"] = records

    def _analyze_ss7_gsm_map(self, pcap_path):
        """Extract subscriber identifiers, SMS content, and BTS/location leaks."""
        records = []
        try:
            tshark = self.tshark_path.get()
            fields = [
                "frame.number", "frame.time_epoch", "_ws.col.protocol", "_ws.col.info",
                "ip.src", "ip.dst", "ipv6.src", "ipv6.dst",
                "udp.srcport", "udp.dstport",
                "sctp.srcport", "sctp.dstport",
                "m3ua.protocol_data_opc", "m3ua.protocol_data_dpc",
                "mtp3.opc", "mtp3.dpc",
                "sccp.calling.digits", "sccp.called.digits",
                "sccp.calling.ssn", "sccp.called.ssn",
                "tcap.tid", "tcap.otid", "tcap.dtid",
                "gsm_map.imsi", "gsm_map.sm.imsi", "gsm_map.ss.imsi", "gsm_map.er.imsi",
                "gsm_map.om.imsi", "gsm_map.ms.imsi", "e212.imsi",
                "e212.assoc.imsi", "rrc.imsi", "rrc.imsi_GSM_MAP",
                "lte-rrc.imsi", "lte-rrc.IMSI_Digit",
                "nas-eps.emm.imsi_offset", "nas-eps.esm.remote_ue_context_list.ue_context.encr_imsi",
                "nas-5gs.mm.suci.msin", "nas-5gs.mm.suci.nai",
                "e212.mcc", "e212.mnc", "e212.lai.mcc", "e212.lai.mnc",
                "e212.rai.mcc", "e212.rai.mnc", "e212.sai.mcc", "e212.sai.mnc",
                "e212.cgi.mcc", "e212.cgi.mnc", "e212.ecgi.mcc", "e212.ecgi.mnc",
                "e212.tai.mcc", "e212.tai.mnc", "e212.nrcgi.mcc", "e212.nrcgi.mnc",
                "e212.5gstai.mcc", "e212.5gstai.mnc", "e212.serv_net.mcc", "e212.serv_net.mnc",
                "gsm_map.ms.imei", "gsm_map.ms.imeisv", "bssap.imei", "bssap.imeisv",
                "gtp.ext_imeisv", "gtpv2.mei", "diameter.IMEI",
                "diameter.User-Equipment-Info-IMEI", "diameter.User-Equipment-Info-IMEISV",
                "gsm_map.msisdn", "gsm_map.sm.msisdn", "gsm_map.ss.msisdn",
                "gsm_map.ms.msisdn", "e164.msisdn",
                "gsm_map.address.digits", "gsm_map.tbcd_digits", "gsm_a.tmsi",
                "gsm_map.sm.sm_RP_UI", "gsm_map.gr.sm_RP_UI", "gsm_old.sm_RP_UI",
                "gsm_a.rp.tpdu", "gsm_sms.sms_text", "gsm_sms.sms_body",
                "gsm_a.dtap.msg_mm_type", "gsm_a.dtap.msg_gmm_type",
                "gsm_a.dtap.msg_sms_type", "gsm_a.dtap.msg_sm_type",
                "gsm_a.dtap.ciphering_key_sequence_number", "gsm_a.dtap.service_type",
                "gsm_a.gm.gmm.serv_type", "gsm_a.gm.gmm.nsapi",
                "gsm_a.MSC_rev", "gsm_a.ES_IND", "gsm_a.A5_1_algorithm_sup",
                "gsm_a.RF_power_capability", "gsm_a.A5_2_algorithm_sup",
                "gsm_a.A5_3_algorithm_sup", "gsm_a.gm.rf_power_capability",
                "gsm_a.gm.a5_bits", "gsm_a.rr.early_classmark_sending",
                "gsm_a.rr.3g_early_classmark_sending_restriction",
                "gsm_a.gm.gmm.nsapi_5_ul_stat", "gsm_a.gm.gmm.nsapi_6_ul_stat",
                "gsm_a.gm.gmm.nsapi_7_ul_stat", "gsm_a.gm.gmm.nsapi_8_ul_stat",
                "gsm_a.gm.gmm.nsapi_9_ul_stat", "gsm_a.gm.gmm.nsapi_10_ul_stat",
                "gsm_a.gm.gmm.nsapi_11_ul_stat", "gsm_a.gm.gmm.nsapi_12_ul_stat",
                "gsm_a.gm.gmm.nsapi_13_ul_stat", "gsm_a.gm.gmm.nsapi_14_ul_stat",
                "gsm_a.gm.gmm.nsapi_15_ul_stat",
                "gsm_a.dtap.clg_party_bcd_num", "gsm_a.dtap.cld_party_bcd_num",
                "gsm_sms.tp-oa", "gsm_sms.tp-da", "gsm_sms.tp-ra",
                "gsm_sms.tp-mti", "gsm_sms.tp-dcs",
                "gsm_map.ussd_string", "gsm_map.ss.ussd_String",
                "gsm_map.apn_str", "gsm_map.ms.apn", "gsm_map.ms.APN",
                "gsm_a.gm.sm.apn", "gtp.apn", "gtpv2.apn", "diameter.LCS-APN",
                "diameter.Active-APN", "diameter.APN-OI-Replacement",
                "gsm_map.cellGlobalIdOrServiceAreaIdFixedLength",
                "gsm_map.ms.LocationArea", "gsm_map.ms.lac",
                "gsm_map.ms.locationInformation_element",
                "gsm_map.ms.locationInformationGPRS_element",
                "gsm_map.ms.locationInformationEPS_element",
                "gsm_map.ms.targetCellId", "gsm_map.ms.targetRNCId",
                "gsm_map.om.GlobalCellId", "gsm_map.om.E_UTRAN_CGI",
                "gsm_map.om.RAIdentity",
                "gsm_map.ericsson.locationInformation.rat",
                "gsm_map.ericsson.locationInformation.lac",
                "gsm_map.ericsson.locationInformation.ci",
                "gsm_map.ericsson.locationInformation.sac",
                "bssap.cell_global_id", "bssap.lac", "bssap.ci",
                "gsm_a.lac", "gsm_a.bssmap.cell_lac", "gsm_a.bssmap.cell_ci",
                "gsm_a.bssmap.sac", "gsm_a.gm.gmm.rac",
                "lte-rrc.cellIdentity", "lte-rrc.CellIdentity",
                "lte-rrc.cellIdentity_r14", "lte-rrc.cellIdentity_r15",
                "lte-rrc.cellIdentity_r13", "lte-rrc.cellIdentity_r16",
                "lte-rrc.cellIdentity_5GC_r15", "lte-rrc.cellIdentity_13",
                "lte-rrc.physCellId",
                "lte-rrc.PhysCellId", "lte-rrc.sourcePhysCellId",
                "lte-rrc.targetPhysCellId", "lte-rrc.physCellIdNR_r16",
                "lte-rrc.physCellIdNR_r17", "lte-rrc.PhysCellIdNR_r15",
                "lte-rrc.pci_r15",
                "lte-rrc.physCellId_r10", "lte-rrc.physCellId_r12",
                "lte-rrc.physCellId_r13", "lte-rrc.physCellId_r15",
                "lte-rrc.physCellId_r16", "lte-rrc.physCellId_r18",
                "lte-rrc.trackingAreaCode", "lte-rrc.TrackingAreaCode",
                "lte-rrc.trackingAreaCode_r13", "lte-rrc.trackingAreaCode_r15",
                "lte-rrc.trackingAreaCode_r16",
                "lte-rrc.trackingAreaCode_r14", "lte-rrc.trackingAreaCode_5GC_r15",
                "lte-rrc.trackingAreaCode_EPC_r16", "lte-rrc.trackingAreaCode_5GC_r16",
                "lte-rrc.tac_FailedPCell_r12", "nas-eps.emm.tai_tac",
                "nas-5gs.tac", "nas-5gs.andsp.wlansp.3gpp_loc_tac",
                "lte-rrc.ue_Identity", "lte-rrc.ue_Identity_r13",
                "lte-rrc.ue_Identity_r15", "lte-rrc.ue_Identity_r16",
                "lte-rrc.sourceUE_Identity", "lte-rrc.sourceUE_Identity_r13",
                "lte-rrc.c_RNTI", "lte-rrc.c_RNTI_r11",
                "lte-rrc.newUE_Identity", "lte-rrc.newUE_Identity_r16",
                "lte-rrc.resumeIdentity_r13", "lte-rrc.resumeIdentity_r15",
                "lte-rrc.resumeIdentity_r16", "lte-rrc.resumeID_r13",
                "lte-rrc.resumeID_r16", "lte-rrc.truncatedResumeID_r13",
                "lte-rrc.truncated5G_S_TMSI_r16", "lte-rrc.ng_5G_S_TMSI_r15",
                "lte-rrc.ng_5G_S_TMSI_r16", "lte-rrc.ng_5G_S_TMSI_Part1",
                "lte-rrc.ng_5G_S_TMSI_Part2_r15", "lte-rrc.ng_5G_S_TMSI_Bits_r15",
                "lte-rrc.establishmentCause", "lte-rrc.establishmentCause_r13",
                "lte-rrc.establishmentCause_r15", "lte-rrc.establishmentCause_r16",
                "lte-rrc.reestablishmentCause", "lte-rrc.reestablishmentCause_r13",
                "lte-rrc.reestablishmentCause_r14", "lte-rrc.reestablishmentCause_r16",
                "lte-rrc.resumeCause_r13", "lte-rrc.resumeCause_r15",
                "lte-rrc.resumeCause_r16", "lte-rrc.selectedPLMN_Identity",
                "lte-rrc.selectedPLMN_Identity_r13", "lte-rrc.plmn_Index_r12",
                "lte-rrc.plmn_Index_r13", "lte-rrc.plmn_Index_r15",
                "lte-rrc.plmn_Index_r16", "lte-rrc.cn_Domain", "lte-rrc.dedicatedInfoNAS",
                "lte-rrc.DedicatedInfoNAS", "lte-rrc.dedicatedInfoNAS_r13",
                "lte-rrc.dedicatedInfoNAS_r15", "lte-rrc.dedicatedInfoNAS_r16",
                "lte-rrc.nas_Container_r15",
                "rrc.UL_DCCH_Message_element", "rrc.DL_DCCH_Message_element",
                "rrc.UL_CCCH_Message_element", "rrc.DL_CCCH_Message_element",
                "rrc.initialDirectTransfer_element", "rrc.message",
                "rrc.cn_DomainIdentity", "rrc.routingbasis", "rrc.routingparameter",
                "rrc.nas_Message", "rrc.start_Value", "rrc.supportOfCSG",
                "rrc.plmn_Identity_element", "rrc.initialUE_Identity",
                "rrc.CellIdentity", "rrc.cell_Identity", "rrc.cell_id",
                "rrc.URA_Identity", "rrc.rac", "rrc.start_CS", "rrc.start_PS",
                "fp.channel-type", "fp.direction", "fp.cfn", "fp.tfi",
                "fp.dch.quality-estimate", "fp.payload-crc.status",
                "mac.logical_channel_id", "mac.logical_channel",
                "mac.transport_channel_id",
                "rlc.channel.rbid", "rlc.channel.dir", "rlc.channel.ueid",
                "rlc.seq", "rlc.sequence_number",
                "gsm_a.rr.cell_id", "gsm_a.rr.arfcn", "gsm_a.rr.bsic",
                "gsm_a.rr.ec_imsi",
                "gtp.cgi_ci", "gtp.sai_sac", "gtp.rai_rac", "gtp.lac",
                "gtp.target_lac", "gtp.target_ci", "gtp.source_lac", "gtp.source_ci",
                "gtpv2.lac", "gtpv2.uli_cgi_lac", "gtpv2.uli_cgi_ci",
                "gtpv2.sai_lac", "gtpv2.sai_sac", "gtpv2.rai_lac", "gtpv2.rai_rac",
                "gtpv2.tai_tac", "gtpv2.5gs_tai_tac", "gtpv2.ecgi_eci",
                "gtpv2.ncgi_nrci", "gtpv2.uli_lai_lac", "gtpv2.cellid",
                "diameter.EPS-Location-Information", "diameter.MME-Location-Information",
                "diameter.SGSN-Location-Information", "diameter.E-UTRAN-Cell-Global-Identity",
                "diameter.Cell-Global-Identity", "diameter.Location-Area-Identity",
                "diameter.Location-Estimate", "diameter.Location-Information",
                "diameter.Location-Data", "diameter.User-Name", "diameter.Session-Id",
                "diameter.Subscription-Id-Data", "diameter.A-MSISDN",
                "radius.User_Name", "radius.Calling_Station_Id", "radius.Called_Station_Id",
                "radius.Framed_IP_Address", "radius.Framed-IP-Address",
                "radius.Framed_IPv6_Address",
                "radius.NAS_IP_Address", "radius.NAS_IPv6_Address",
                "radius.NAS_Identifier", "radius.NAS_Port_Id", "radius.Acct_Session_Id",
                "radius.Location_Information", "radius.Location_Data",
                "radius.Alc_MsIsdn", "radius.Alc_APN_Name", "radius.Alc_Wlan_APN_Name",
            ]
            fields = self._filter_tshark_fields(fields)
            leak_filter_fields = [
                "gsm_map.imsi", "gsm_map.sm.imsi", "gsm_map.ss.imsi", "gsm_map.er.imsi",
                "gsm_map.om.imsi", "gsm_map.ms.imsi", "e212.imsi", "gsm_a.rr.ec_imsi",
                "e212.assoc.imsi", "rrc.imsi", "rrc.imsi_GSM_MAP",
                "lte-rrc.imsi", "lte-rrc.IMSI_Digit",
                "nas-5gs.mm.suci.msin", "nas-5gs.mm.suci.nai",
                "gsm_map.ms.imei", "gsm_map.ms.imeisv", "bssap.imei", "bssap.imeisv",
                "gtp.ext_imeisv", "gtpv2.mei", "diameter.IMEI",
                "diameter.User-Equipment-Info-IMEI", "diameter.User-Equipment-Info-IMEISV",
                "gsm_map.msisdn", "gsm_map.sm.msisdn", "gsm_map.ss.msisdn",
                "gsm_map.ms.msisdn", "e164.msisdn", "gsm_a.tmsi", "gsm_sms.sms_text",
                "gsm_sms.sms_body", "gsm_map.sm.sm_RP_UI", "gsm_map.gr.sm_RP_UI",
                "gsm_old.sm_RP_UI", "gsm_a.rp.tpdu", "gsm_a.dtap.clg_party_bcd_num",
                "gsm_a.dtap.cld_party_bcd_num", "gsm_a.dtap.msg_mm_type",
                "gsm_a.dtap.msg_gmm_type", "gsm_a.dtap.msg_sms_type",
                "gsm_a.dtap.msg_sm_type", "gsm_a.MSC_rev", "gsm_a.ES_IND",
                "gsm_a.RF_power_capability", "gsm_a.A5_1_algorithm_sup",
                "gsm_map.ussd_string",
                "gsm_map.ss.ussd_String", "gsm_map.apn_str", "gsm_map.ms.apn",
                "gsm_a.gm.sm.apn", "gtp.apn", "gtpv2.apn", "diameter.LCS-APN",
                "diameter.Active-APN", "diameter.A-MSISDN", "radius.User_Name",
                "radius.Calling_Station_Id", "radius.Called_Station_Id",
                "radius.Location_Information", "radius.Location_Data",
                "radius.Alc_MsIsdn", "radius.Alc_APN_Name",
                "gsm_map.cellGlobalIdOrServiceAreaIdFixedLength", "gsm_map.ms.targetCellId",
                "bssap.cell_global_id", "gtpv2.uli_cgi_ci", "gtpv2.ecgi_eci",
                "diameter.E-UTRAN-Cell-Global-Identity", "diameter.Cell-Global-Identity",
                "e212.mcc", "e212.mnc", "e212.lai.mcc", "e212.lai.mnc",
                "e212.rai.mcc", "e212.rai.mnc", "e212.sai.mcc", "e212.sai.mnc",
                "e212.cgi.mcc", "e212.cgi.mnc", "e212.ecgi.mcc", "e212.ecgi.mnc",
                "e212.tai.mcc", "e212.tai.mnc", "e212.nrcgi.mcc", "e212.nrcgi.mnc",
                "gsm_a.bssmap.cell_lac", "gsm_a.bssmap.cell_ci", "gsm_a.bssmap.sac",
                "gsm_a.gm.gmm.rac", "gtpv2.tai_tac", "gtpv2.uli_cgi_lac",
                "gtpv2.uli_cgi_ci", "gtpv2.ecgi_eci",
                "lte-rrc.cellIdentity", "lte-rrc.CellIdentity",
                "lte-rrc.cellIdentity_r14", "lte-rrc.cellIdentity_r15",
                "lte-rrc.cellIdentity_r13", "lte-rrc.cellIdentity_r16",
                "lte-rrc.cellIdentity_5GC_r15", "lte-rrc.trackingAreaCode",
                "lte-rrc.TrackingAreaCode", "lte-rrc.trackingAreaCode_r14",
                "lte-rrc.trackingAreaCode_5GC_r15", "nas-eps.emm.tai_tac",
                "nas-5gs.tac", "rrc.CellIdentity", "rrc.cell_Identity", "rrc.cell_id",
                "rrc.URA_Identity", "rrc.initialUE_Identity",
                "lte-rrc.ue_Identity", "lte-rrc.c_RNTI",
                "lte-rrc.ng_5G_S_TMSI_r15", "lte-rrc.establishmentCause",
                "lte-rrc.dedicatedInfoNAS", "lte-rrc.nas_Container_r15",
                "rrc.initialDirectTransfer_element", "rrc.cn_DomainIdentity",
                "rrc.routingbasis", "rrc.routingparameter",
                "rrc.nas_Message", "rrc.start_Value", "rrc.supportOfCSG",
            ]
            display_terms = [f for f in leak_filter_fields if f in fields]
            if not display_terms:
                self.analysis_results["ss7_gsm_map"] = records
                return
            display_filter = " || ".join(display_terms)
            cmd = [tshark, "-r", pcap_path, "-Y", display_filter, "-T", "fields"]
            for field in fields:
                cmd += ["-e", field]
            cmd += ["-E", "separator=\t", "-E", "occurrence=a", "-E", "aggregator=,"]
            for line in self._iter_command_lines(cmd, timeout=0, max_lines=100000):
                if not line.strip():
                    continue
                parts = line.split("\t")
                parts += [""] * (len(fields) - len(parts))
                row = dict(zip(fields, parts[:len(fields)]))

                imsi = self._compact_join([
                    row.get("gsm_map.imsi"), row.get("gsm_map.sm.imsi"),
                    row.get("gsm_map.ss.imsi"), row.get("gsm_map.er.imsi"),
                    row.get("gsm_map.om.imsi"), row.get("gsm_map.ms.imsi"),
                    row.get("gsm_a.rr.ec_imsi"), row.get("e212.imsi"),
                    row.get("e212.assoc.imsi"), row.get("rrc.imsi"),
                    row.get("rrc.imsi_GSM_MAP"), row.get("lte-rrc.imsi"),
                    row.get("lte-rrc.IMSI_Digit"),
                    *self._subscriber_digits(row.get("radius.User_Name"), 14, 16),
                    *self._subscriber_digits(row.get("diameter.User-Name"), 14, 16),
                    *self._subscriber_digits(row.get("nas-5gs.mm.suci.msin"), 10, 15),
                    *self._subscriber_digits(row.get("nas-5gs.mm.suci.nai"), 10, 16),
                ], limit=6)
                imei = self._compact_join([
                    row.get("gsm_map.ms.imei"), row.get("gsm_map.ms.imeisv"),
                    row.get("bssap.imei"), row.get("bssap.imeisv"),
                    row.get("gtp.ext_imeisv"), row.get("gtpv2.mei"),
                    row.get("diameter.IMEI"),
                    row.get("diameter.User-Equipment-Info-IMEI"),
                    row.get("diameter.User-Equipment-Info-IMEISV"),
                ], limit=6)
                msisdn = self._compact_join([
                    row.get("gsm_map.msisdn"), row.get("gsm_map.sm.msisdn"),
                    row.get("gsm_map.ss.msisdn"), row.get("gsm_map.ms.msisdn"),
                    row.get("e164.msisdn"), row.get("diameter.A-MSISDN"),
                    row.get("radius.Alc_MsIsdn"),
                    row.get("gsm_map.address.digits"), row.get("gsm_map.tbcd_digits"),
                    *self._subscriber_digits(row.get("radius.Calling_Station_Id"), 10, 17),
                    *self._subscriber_digits(row.get("radius.Called_Station_Id"), 10, 17),
                ], limit=6)
                sms_decoded_by_tshark = row.get("gsm_sms.sms_text", "")
                sms_best_effort = "" if sms_decoded_by_tshark else self._decode_sms_tpdu_text(
                    row.get("gsm_sms.sms_body"),
                    row.get("gsm_map.sm.sm_RP_UI"),
                    row.get("gsm_map.gr.sm_RP_UI"),
                    row.get("gsm_old.sm_RP_UI"),
                    row.get("gsm_a.rp.tpdu"))
                sms_text = sms_decoded_by_tshark or sms_best_effort
                sms_text_source = "TShark gsm_sms.sms_text" if sms_decoded_by_tshark else (
                    "Best-effort UCS-2/UTF-16 TPDU decode" if sms_best_effort else "")
                sms_raw = self._compact_join([
                    row.get("gsm_sms.sms_body"), row.get("gsm_map.sm.sm_RP_UI"),
                    row.get("gsm_map.gr.sm_RP_UI"), row.get("gsm_old.sm_RP_UI"),
                    row.get("gsm_a.rp.tpdu"),
                ], limit=4)
                ussd = self._compact_join([
                    row.get("gsm_map.ussd_string"),
                    self._hex_or_text(row.get("gsm_map.ss.ussd_String")),
                ], limit=3)
                apn = self._compact_join([
                    row.get("gsm_map.apn_str"), self._hex_or_text(row.get("gsm_map.ms.apn")),
                    self._hex_or_text(row.get("gsm_map.ms.APN")), row.get("gsm_a.gm.sm.apn"),
                    row.get("gtp.apn"), row.get("gtpv2.apn"), row.get("diameter.LCS-APN"),
                    self._hex_or_text(row.get("diameter.Active-APN")),
                    row.get("diameter.APN-OI-Replacement"), row.get("radius.Alc_APN_Name"),
                    row.get("radius.Alc_Wlan_APN_Name"),
                ], limit=6)
                mcc_mnc_pairs = [
                    (row.get("e212.mcc"), row.get("e212.mnc")),
                    (row.get("e212.lai.mcc"), row.get("e212.lai.mnc")),
                    (row.get("e212.rai.mcc"), row.get("e212.rai.mnc")),
                    (row.get("e212.sai.mcc"), row.get("e212.sai.mnc")),
                    (row.get("e212.cgi.mcc"), row.get("e212.cgi.mnc")),
                    (row.get("e212.ecgi.mcc"), row.get("e212.ecgi.mnc")),
                    (row.get("e212.tai.mcc"), row.get("e212.tai.mnc")),
                    (row.get("e212.nrcgi.mcc"), row.get("e212.nrcgi.mnc")),
                    (row.get("e212.5gstai.mcc"), row.get("e212.5gstai.mnc")),
                    (row.get("e212.serv_net.mcc"), row.get("e212.serv_net.mnc")),
                ]
                mcc_mnc = self._compact_join([
                    self._format_mobile_area("PLMN", mcc, mnc, "", "")
                    for mcc, mnc in mcc_mnc_pairs
                    if mcc or mnc
                ], limit=8)
                lai = self._compact_join([
                    self._format_mobile_area(
                        "LAI", row.get("e212.lai.mcc"), row.get("e212.lai.mnc"),
                        "LAC", row.get("gsm_a.lac")),
                    self._format_mobile_area(
                        "RAI", row.get("e212.rai.mcc"), row.get("e212.rai.mnc"),
                        "RAC", row.get("gsm_a.gm.gmm.rac")),
                ], limit=3)
                classmark = self._compact_join([
                    f"Classmark1 rev={row.get('gsm_a.MSC_rev')}" if row.get("gsm_a.MSC_rev") else "",
                    f"ES={row.get('gsm_a.ES_IND')}" if row.get("gsm_a.ES_IND") else "",
                    f"A5/1={row.get('gsm_a.A5_1_algorithm_sup')}" if row.get("gsm_a.A5_1_algorithm_sup") else "",
                    f"A5/2={row.get('gsm_a.A5_2_algorithm_sup')}" if row.get("gsm_a.A5_2_algorithm_sup") else "",
                    f"A5/3={row.get('gsm_a.A5_3_algorithm_sup')}" if row.get("gsm_a.A5_3_algorithm_sup") else "",
                    f"RF-power={row.get('gsm_a.RF_power_capability')}" if row.get("gsm_a.RF_power_capability") else "",
                    f"GMM RF-power={row.get('gsm_a.gm.rf_power_capability')}" if row.get("gsm_a.gm.rf_power_capability") else "",
                    f"GMM A5bits={row.get('gsm_a.gm.a5_bits')}" if row.get("gsm_a.gm.a5_bits") else "",
                    "early-classmark=true" if row.get("gsm_a.rr.early_classmark_sending") else "",
                    "3g-early-classmark-restricted=true"
                    if row.get("gsm_a.rr.3g_early_classmark_sending_restriction") else "",
                ], limit=10)
                area_code = self._compact_join([
                    f"LAC={v}" for v in [
                        row.get("gsm_map.ms.lac"), row.get("gsm_map.ericsson.locationInformation.lac"),
                        row.get("bssap.lac"), row.get("gsm_a.lac"),
                        row.get("gsm_a.bssmap.cell_lac"), row.get("gtp.lac"),
                        row.get("gtp.target_lac"), row.get("gtp.source_lac"),
                        row.get("gtpv2.lac"), row.get("gtpv2.uli_cgi_lac"),
                        row.get("gtpv2.sai_lac"), row.get("gtpv2.rai_lac"),
                        row.get("gtpv2.uli_lai_lac"),
                        row.get("rrc.URA_Identity"),
                    ] if v
                ] + [
                    f"TAC={v}" for v in [
                        row.get("gtpv2.tai_tac"), row.get("gtpv2.5gs_tai_tac"),
                        row.get("lte-rrc.trackingAreaCode"), row.get("lte-rrc.TrackingAreaCode"),
                        row.get("lte-rrc.trackingAreaCode_r13"),
                        row.get("lte-rrc.trackingAreaCode_r14"),
                        row.get("lte-rrc.trackingAreaCode_r15"),
                        row.get("lte-rrc.trackingAreaCode_r16"),
                        row.get("lte-rrc.trackingAreaCode_5GC_r15"),
                        row.get("lte-rrc.trackingAreaCode_EPC_r16"),
                        row.get("lte-rrc.trackingAreaCode_5GC_r16"),
                        row.get("lte-rrc.tac_FailedPCell_r12"),
                        row.get("nas-eps.emm.tai_tac"), row.get("nas-5gs.tac"),
                        row.get("nas-5gs.andsp.wlansp.3gpp_loc_tac"),
                    ] if v
                ] + [
                    f"RAC={v}" for v in [row.get("gtp.rai_rac"), row.get("gtpv2.rai_rac"), row.get("gsm_a.gm.gmm.rac")] if v
                ] + [
                    f"SAC={v}" for v in [
                        row.get("gsm_map.ericsson.locationInformation.sac"),
                        row.get("gtp.sai_sac"), row.get("gtpv2.sai_sac"),
                        row.get("gsm_a.bssmap.sac"),
                    ] if v
                ] + [
                    f"CI={v}" for v in [
                        row.get("gsm_map.ericsson.locationInformation.ci"),
                        row.get("bssap.ci"), row.get("gsm_a.bssmap.cell_ci"),
                        row.get("gsm_a.rr.cell_id"), row.get("gtp.cgi_ci"),
                        row.get("gtp.target_ci"), row.get("gtp.source_ci"),
                        row.get("gtpv2.uli_cgi_ci"), row.get("gtpv2.ecgi_eci"),
                        row.get("gtpv2.ncgi_nrci"), row.get("gtpv2.cellid"),
                        row.get("rrc.CellIdentity"), row.get("rrc.cell_Identity"),
                        row.get("rrc.cell_id"),
                        row.get("lte-rrc.cellIdentity"), row.get("lte-rrc.CellIdentity"),
                        row.get("lte-rrc.cellIdentity_r13"),
                        row.get("lte-rrc.cellIdentity_r14"),
                        row.get("lte-rrc.cellIdentity_r15"),
                        row.get("lte-rrc.cellIdentity_r16"),
                        row.get("lte-rrc.cellIdentity_5GC_r15"),
                        row.get("lte-rrc.cellIdentity_13"),
                    ] if v
                ] + [
                    f"PCI={v}" for v in [
                        row.get("lte-rrc.physCellId"), row.get("lte-rrc.PhysCellId"),
                        row.get("lte-rrc.sourcePhysCellId"), row.get("lte-rrc.targetPhysCellId"),
                        row.get("lte-rrc.physCellId_r10"),
                        row.get("lte-rrc.physCellId_r12"), row.get("lte-rrc.physCellId_r13"),
                        row.get("lte-rrc.physCellId_r15"), row.get("lte-rrc.physCellId_r16"),
                        row.get("lte-rrc.physCellId_r18"), row.get("lte-rrc.physCellIdNR_r16"),
                        row.get("lte-rrc.physCellIdNR_r17"), row.get("lte-rrc.PhysCellIdNR_r15"),
                        row.get("lte-rrc.pci_r15"),
                    ] if v
                ], limit=12)
                bts_cell = self._compact_join([
                    row.get("gsm_map.cellGlobalIdOrServiceAreaIdFixedLength"),
                    row.get("gsm_map.ms.LocationArea"), row.get("gsm_map.ms.lac"),
                    row.get("gsm_map.ms.targetCellId"), row.get("gsm_map.ms.targetRNCId"),
                    row.get("gsm_map.om.GlobalCellId"), row.get("gsm_map.om.E_UTRAN_CGI"),
                    row.get("gsm_map.om.RAIdentity"),
                    row.get("gsm_map.ericsson.locationInformation.rat"),
                    row.get("gsm_map.ericsson.locationInformation.lac"),
                    row.get("gsm_map.ericsson.locationInformation.ci"),
                    row.get("gsm_map.ericsson.locationInformation.sac"),
                    row.get("bssap.cell_global_id"), row.get("bssap.lac"), row.get("bssap.ci"),
                    row.get("gsm_a.lac"), row.get("gsm_a.bssmap.cell_lac"),
                    row.get("gsm_a.bssmap.cell_ci"), row.get("gsm_a.bssmap.sac"),
                    row.get("gsm_a.gm.gmm.rac"), row.get("gsm_a.rr.cell_id"),
                    row.get("gsm_a.rr.arfcn"), row.get("gsm_a.rr.bsic"),
                    row.get("gtp.cgi_ci"), row.get("gtp.sai_sac"), row.get("gtp.rai_rac"),
                    row.get("gtp.lac"), row.get("gtp.target_lac"), row.get("gtp.target_ci"),
                    row.get("gtp.source_lac"), row.get("gtp.source_ci"),
                    row.get("gtpv2.lac"), row.get("gtpv2.uli_cgi_lac"),
                    row.get("gtpv2.uli_cgi_ci"), row.get("gtpv2.sai_lac"),
                    row.get("gtpv2.sai_sac"), row.get("gtpv2.rai_lac"),
                    row.get("gtpv2.rai_rac"), row.get("gtpv2.tai_tac"),
                    row.get("gtpv2.5gs_tai_tac"), row.get("gtpv2.ecgi_eci"),
                    row.get("gtpv2.ncgi_nrci"), row.get("gtpv2.uli_lai_lac"),
                    row.get("gtpv2.cellid"),
                    row.get("rrc.CellIdentity"), row.get("rrc.cell_Identity"),
                    row.get("rrc.cell_id"), row.get("rrc.URA_Identity"),
                    row.get("lte-rrc.cellIdentity"), row.get("lte-rrc.CellIdentity"),
                    row.get("lte-rrc.cellIdentity_r13"), row.get("lte-rrc.cellIdentity_r14"),
                    row.get("lte-rrc.cellIdentity_r15"), row.get("lte-rrc.cellIdentity_r16"),
                    row.get("lte-rrc.cellIdentity_5GC_r15"), row.get("lte-rrc.physCellId"),
                    row.get("lte-rrc.PhysCellId"), row.get("lte-rrc.sourcePhysCellId"),
                    row.get("lte-rrc.targetPhysCellId"), row.get("lte-rrc.pci_r15"),
                    row.get("lte-rrc.trackingAreaCode"), row.get("lte-rrc.TrackingAreaCode"),
                    row.get("nas-eps.emm.tai_tac"), row.get("nas-5gs.tac"),
                    self._hex_or_text(row.get("diameter.EPS-Location-Information")),
                    self._hex_or_text(row.get("diameter.MME-Location-Information")),
                    self._hex_or_text(row.get("diameter.SGSN-Location-Information")),
                    self._hex_or_text(row.get("diameter.E-UTRAN-Cell-Global-Identity")),
                    self._hex_or_text(row.get("diameter.Cell-Global-Identity")),
                    self._hex_or_text(row.get("diameter.Location-Area-Identity")),
                    self._hex_or_text(row.get("diameter.Location-Estimate")),
                    self._hex_or_text(row.get("diameter.Location-Information")),
                    self._hex_or_text(row.get("diameter.Location-Data")),
                    self._hex_or_text(row.get("radius.Location_Information")),
                    self._hex_or_text(row.get("radius.Location_Data")),
                ], limit=8)
                rrc_identity = self._compact_join([
                    row.get("rrc.initialUE_Identity"), row.get("gsm_a.tmsi"),
                    row.get("lte-rrc.ue_Identity"), row.get("lte-rrc.ue_Identity_r13"),
                    row.get("lte-rrc.ue_Identity_r15"), row.get("lte-rrc.ue_Identity_r16"),
                    row.get("lte-rrc.sourceUE_Identity"), row.get("lte-rrc.sourceUE_Identity_r13"),
                    row.get("lte-rrc.c_RNTI"), row.get("lte-rrc.c_RNTI_r11"),
                    row.get("lte-rrc.newUE_Identity"), row.get("lte-rrc.newUE_Identity_r16"),
                    row.get("lte-rrc.resumeIdentity_r13"), row.get("lte-rrc.resumeIdentity_r15"),
                    row.get("lte-rrc.resumeIdentity_r16"), row.get("lte-rrc.resumeID_r13"),
                    row.get("lte-rrc.resumeID_r16"), row.get("lte-rrc.truncatedResumeID_r13"),
                    row.get("lte-rrc.truncated5G_S_TMSI_r16"), row.get("lte-rrc.ng_5G_S_TMSI_r15"),
                    row.get("lte-rrc.ng_5G_S_TMSI_r16"), row.get("lte-rrc.ng_5G_S_TMSI_Part1"),
                    row.get("lte-rrc.ng_5G_S_TMSI_Part2_r15"), row.get("lte-rrc.ng_5G_S_TMSI_Bits_r15"),
                ], limit=8)
                rrc_cause = self._compact_join([
                    row.get("lte-rrc.establishmentCause"), row.get("lte-rrc.establishmentCause_r13"),
                    row.get("lte-rrc.establishmentCause_r15"), row.get("lte-rrc.establishmentCause_r16"),
                    row.get("lte-rrc.reestablishmentCause"), row.get("lte-rrc.reestablishmentCause_r13"),
                    row.get("lte-rrc.reestablishmentCause_r14"), row.get("lte-rrc.reestablishmentCause_r16"),
                    row.get("lte-rrc.resumeCause_r13"), row.get("lte-rrc.resumeCause_r15"),
                    row.get("lte-rrc.resumeCause_r16"),
                ], limit=6)
                rrc_plmn_selection = self._compact_join([
                    row.get("lte-rrc.selectedPLMN_Identity"), row.get("lte-rrc.selectedPLMN_Identity_r13"),
                    row.get("lte-rrc.plmn_Index_r12"), row.get("lte-rrc.plmn_Index_r13"),
                    row.get("lte-rrc.plmn_Index_r15"), row.get("lte-rrc.plmn_Index_r16"),
                ], limit=6)
                rrc_nas_container = self._compact_join([
                    row.get("rrc.nas_Message"),
                    row.get("lte-rrc.dedicatedInfoNAS"), row.get("lte-rrc.DedicatedInfoNAS"),
                    row.get("lte-rrc.dedicatedInfoNAS_r13"), row.get("lte-rrc.dedicatedInfoNAS_r15"),
                    row.get("lte-rrc.dedicatedInfoNAS_r16"), row.get("lte-rrc.nas_Container_r15"),
                ], limit=3)
                rrc_domain_map = {"0": "cs-domain", "1": "ps-domain"}
                rrc_routing_map = {
                    "0": "localPTMSI",
                    "1": "tMSI",
                    "2": "pTMSI",
                    "3": "iMSIresponsetopaging",
                    "4": "iMSIcauseUEinitiatedEvent",
                }
                dtap_mm_map = {
                    "0x08": "Location Updating Request",
                    "8": "Location Updating Request",
                }
                dtap_gmm_map = {
                    "0x0c": "Service Request",
                    "12": "Service Request",
                }
                rrc_message = self._compact_join([
                    "UL-DCCH" if row.get("rrc.UL_DCCH_Message_element") else "",
                    "DL-DCCH" if row.get("rrc.DL_DCCH_Message_element") else "",
                    "UL-CCCH" if row.get("rrc.UL_CCCH_Message_element") else "",
                    "DL-CCCH" if row.get("rrc.DL_CCCH_Message_element") else "",
                    "initialDirectTransfer" if row.get("rrc.initialDirectTransfer_element") else "",
                    f"msg={row.get('rrc.message')}" if row.get("rrc.message") else "",
                ], limit=6)
                rrc_domain = self._compact_join([
                    rrc_domain_map.get(row.get("rrc.cn_DomainIdentity", ""), row.get("rrc.cn_DomainIdentity", "")),
                    row.get("lte-rrc.cn_Domain"),
                ], limit=3)
                dtap_mm = dtap_mm_map.get(row.get("gsm_a.dtap.msg_mm_type", ""), row.get("gsm_a.dtap.msg_mm_type", ""))
                dtap_gmm = dtap_gmm_map.get(row.get("gsm_a.dtap.msg_gmm_type", ""), row.get("gsm_a.dtap.msg_gmm_type", ""))
                nsapi_pending = self._compact_join([
                    f"NSAPI {n} uplink pending"
                    for n in range(5, 16)
                    if str(row.get(f"gsm_a.gm.gmm.nsapi_{n}_ul_stat", "")).strip() in {"1", "True", "true"}
                ], limit=4)
                nas_message = self._compact_join([
                    dtap_mm, dtap_gmm, row.get("gsm_a.dtap.msg_sms_type"),
                    row.get("gsm_a.dtap.msg_sm_type"),
                    f"NAS={self._hex_or_text(row.get('rrc.nas_Message'))}" if row.get("rrc.nas_Message") else "",
                    f"NSAPI={row.get('gsm_a.gm.gmm.nsapi')}" if row.get("gsm_a.gm.gmm.nsapi") else "",
                    nsapi_pending,
                ], limit=7)
                mobile_identity = self._compact_join([
                    f"IMSI={imsi}" if imsi else "",
                    f"TMSI/P-TMSI={row.get('gsm_a.tmsi')}" if row.get("gsm_a.tmsi") else "",
                    f"IMEI={imei}" if imei else "",
                    f"MSISDN={msisdn}" if msisdn else "",
                    f"RRC UE={rrc_identity}" if rrc_identity else "",
                ], limit=6)
                rrc_context = self._compact_join([
                    f"domain={rrc_domain}" if rrc_domain else "",
                    f"routing={rrc_routing_map.get(row.get('rrc.routingbasis', ''), row.get('rrc.routingbasis', ''))}"
                    if row.get("rrc.routingbasis") else "",
                    f"routingparam={row.get('rrc.routingparameter')}" if row.get("rrc.routingparameter") else "",
                    f"start={row.get('rrc.start_Value')}" if row.get("rrc.start_Value") else "",
                    f"start-CS={row.get('rrc.start_CS')}" if row.get("rrc.start_CS") else "",
                    f"start-PS={row.get('rrc.start_PS')}" if row.get("rrc.start_PS") else "",
                    "supportOfCSG=true" if row.get("rrc.supportOfCSG") else "",
                    f"cause={rrc_cause}" if rrc_cause else "",
                    f"PLMN={rrc_plmn_selection}" if rrc_plmn_selection else "",
                    f"CKSN={row.get('gsm_a.dtap.ciphering_key_sequence_number')}"
                    if row.get("gsm_a.dtap.ciphering_key_sequence_number") else "",
                    f"service={row.get('gsm_a.dtap.service_type') or row.get('gsm_a.gm.gmm.serv_type')}"
                    if (row.get("gsm_a.dtap.service_type") or row.get("gsm_a.gm.gmm.serv_type")) else "",
                ], limit=11)
                radio_context = self._compact_join([
                    f"UDP {row.get('udp.srcport')}->{row.get('udp.dstport')}"
                    if row.get("udp.srcport") or row.get("udp.dstport") else "",
                    f"FP ch={row.get('fp.channel-type')}" if row.get("fp.channel-type") else "",
                    f"dir={row.get('fp.direction')}" if row.get("fp.direction") else "",
                    f"CFN={row.get('fp.cfn')}" if row.get("fp.cfn") else "",
                    f"TFI={row.get('fp.tfi')}" if row.get("fp.tfi") else "",
                    f"quality={row.get('fp.dch.quality-estimate')}" if row.get("fp.dch.quality-estimate") else "",
                    f"crc={row.get('fp.payload-crc.status')}" if row.get("fp.payload-crc.status") else "",
                    f"MAC lch={row.get('mac.logical_channel_id')}" if row.get("mac.logical_channel_id") else "",
                    f"MAC tch={row.get('mac.transport_channel_id')}" if row.get("mac.transport_channel_id") else "",
                    f"RLC rbid={row.get('rlc.channel.rbid')}" if row.get("rlc.channel.rbid") else "",
                    f"RLC dir={row.get('rlc.channel.dir')}" if row.get("rlc.channel.dir") else "",
                    f"UEID={row.get('rlc.channel.ueid')}" if row.get("rlc.channel.ueid") else "",
                    f"seq={row.get('rlc.seq') or row.get('rlc.sequence_number')}"
                    if (row.get("rlc.seq") or row.get("rlc.sequence_number")) else "",
                ], limit=13)

                leaks = []
                if imsi:
                    leaks.append("IMSI")
                if row.get("nas-5gs.mm.suci.msin") or row.get("nas-5gs.mm.suci.nai"):
                    leaks.append("SUCI/SUPI")
                if row.get("gsm_a.tmsi"):
                    leaks.append("TMSI/P-TMSI")
                if imei:
                    leaks.append("IMEI/MEI")
                if msisdn:
                    leaks.append("MSISDN")
                if mcc_mnc:
                    leaks.append("MCC/MNC")
                if lai:
                    leaks.append("LAI")
                if area_code:
                    leaks.append("AREA-CODE")
                if bts_cell:
                    leaks.append("BTS/CELL")
                if classmark:
                    leaks.append("CLASSMARK")
                if rrc_identity:
                    leaks.append("RRC-UE-ID")
                if rrc_context:
                    leaks.append("RRC-CONTEXT")
                if nas_message:
                    leaks.append("NAS/DTAP")
                if rrc_nas_container:
                    leaks.append("RRC-NAS-CONTAINER")
                if sms_text:
                    leaks.append("SMS-TEXT")
                if sms_raw and not sms_text:
                    leaks.append("SMS-RAW-TPDU")
                if ussd:
                    leaks.append("USSD")
                if apn:
                    leaks.append("APN")
                if row.get("radius.User_Name") or row.get("radius.Calling_Station_Id"):
                    leaks.append("RADIUS-ID")
                if row.get("diameter.User-Name") or row.get("diameter.Session-Id"):
                    leaks.append("DIAMETER-ID")

                if not leaks and "gsm_map" not in row.get("_ws.col.protocol", "").lower():
                    # Keep signalling rows only when they expose useful subscriber/SMS data.
                    continue

                src = row.get("ip.src") or row.get("ipv6.src") or row.get("m3ua.protocol_data_opc") or row.get("mtp3.opc")
                dst = row.get("ip.dst") or row.get("ipv6.dst") or row.get("m3ua.protocol_data_dpc") or row.get("mtp3.dpc")
                records.append({
                    "frame": row.get("frame.number", ""),
                    "time": row.get("frame.time_epoch", ""),
                    "stack": row.get("_ws.col.protocol", ""),
                    "operation": row.get("_ws.col.info", ""),
                    "leaks": ", ".join(leaks),
                    "rrc_message": rrc_message,
                    "rrc_domain": rrc_domain,
                    "nas_message": nas_message,
                    "mobile_identity": mobile_identity,
                    "lai": lai,
                    "classmark": classmark,
                    "rrc_context": rrc_context,
                    "radio_context": radio_context,
                    "imsi": imsi,
                    "imei": imei,
                    "msisdn": msisdn,
                    "mcc_mnc": mcc_mnc,
                    "area_code": area_code,
                    "bts_cell": bts_cell,
                    "rrc_identity": rrc_identity,
                    "rrc_cause": rrc_cause,
                    "rrc_plmn_selection": rrc_plmn_selection,
                    "rrc_nas_container": rrc_nas_container,
                    "sms_text": sms_text,
                    "sms_text_source": sms_text_source,
                    "sms_raw_tpdu": sms_raw,
                    "ussd": ussd,
                    "apn": apn,
                    "sms_from": row.get("gsm_sms.tp-oa", ""),
                    "sms_to": row.get("gsm_sms.tp-da", "") or row.get("gsm_sms.tp-ra", ""),
                    "sms_type": row.get("gsm_sms.tp-mti", ""),
                    "sms_dcs": row.get("gsm_sms.tp-dcs", ""),
                    "radius_user": row.get("radius.User_Name", ""),
                    "radius_calling_station": row.get("radius.Calling_Station_Id", ""),
                    "radius_called_station": row.get("radius.Called_Station_Id", ""),
                    "radius_nas": self._compact_join([
                        row.get("radius.NAS_IP_Address"), row.get("radius.NAS_IPv6_Address"),
                        row.get("radius.NAS_Identifier"), row.get("radius.NAS_Port_Id"),
                    ], limit=4),
                    "diameter_user": row.get("diameter.User-Name", ""),
                    "diameter_session": row.get("diameter.Session-Id", ""),
                    "src": src,
                    "dst": dst,
                    "sctp_srcport": row.get("sctp.srcport", ""),
                    "sctp_dstport": row.get("sctp.dstport", ""),
                    "sccp_calling": row.get("sccp.calling.digits", ""),
                    "sccp_called": row.get("sccp.called.digits", ""),
                    "sccp_calling_ssn": row.get("sccp.calling.ssn", ""),
                    "sccp_called_ssn": row.get("sccp.called.ssn", ""),
                    "tcap_tid": self._compact_join([
                        row.get("tcap.tid"), row.get("tcap.otid"), row.get("tcap.dtid")
                    ], limit=3),
                })
        except Exception:
            pass
        self.analysis_results["ss7_gsm_map"] = records

    # ------------------------------------------------------------------
    # VoIP: SIP signalling + RTP media streams
    # ------------------------------------------------------------------
    _RTP_PT = {
        "0": "PCMU/8000", "3": "GSM/8000", "4": "G723/8000", "8": "PCMA/8000",
        "9": "G722/8000", "18": "G729/8000", "96": "dynamic", "97": "dynamic",
        "98": "dynamic", "101": "telephone-event",
    }

    def _analyze_voip(self, pcap_path):
        """Extract SIP messages and aggregate RTP media streams by SSRC."""
        tshark = self.tshark_path.get()
        sip_msgs = []
        sdp_payloads = defaultdict(list)
        sdp_ports = defaultdict(list)
        try:
            sip_fields = self._filter_tshark_fields([
                "frame.number", "frame.time", "ip.src", "ip.dst", "ipv6.src", "ipv6.dst",
                "udp.srcport", "udp.dstport", "tcp.srcport", "tcp.dstport",
                "sip.Method", "sip.Status-Code", "sip.Status-Line",
                "sip.From", "sip.To", "sip.Call-ID",
                "sdp.connection_info.address", "sdp.media.media", "sdp.media.port",
                "sdp.media.proto", "sdp.media.format", "sdp.media_attr",
                "sdp.media_attribute.value", "sdp.fmtp.parameter",
                "sdp.crypto.crypto_suite", "sdp.crypto.master_key", "sdp.crypto.master_salt",
            ])
            cmd_sip = [tshark, "-r", pcap_path, "-Y", "sip", "-T", "fields"]
            for field in sip_fields:
                cmd_sip += ["-e", field]
            cmd_sip += ["-E", "separator=\t", "-E", "occurrence=a", "-E", "aggregator=,"]
            r = subprocess.run(cmd_sip, capture_output=True, text=True,
                               encoding="utf-8", errors="replace", timeout=180)
            for line in r.stdout.split("\n"):
                if not line.strip():
                    continue
                p = line.split("\t")
                p += [""] * (len(sip_fields) - len(p))
                row = dict(zip(sip_fields, p[:len(sip_fields)]))
                method = row.get("sip.Method", "")
                scode = row.get("sip.Status-Code", "")
                sline = row.get("sip.Status-Line", "")
                callid = row.get("sip.Call-ID", "")
                verb = method or (f"{scode} {sline}".strip() if (scode or sline) else "")
                media_proto = row.get("sdp.media.proto", "")
                media_security = "SRTP" if re.search(r"\bSAVP|SAVPF|SRTP\b", media_proto, re.I) else "RTP"
                if row.get("sdp.crypto.crypto_suite") or row.get("sdp.crypto.master_key"):
                    media_security = "SRTP"
                codec_map = self._parse_sdp_codec_map(
                    row.get("sdp.media_attr", ""),
                    row.get("sdp.media_attribute.value", ""),
                    row.get("sdp.fmtp.parameter", ""),
                    row.get("sdp.media.format", ""))
                media_ports = re.findall(r"\d+", row.get("sdp.media.port", ""))
                media_formats = re.findall(r"\d+", row.get("sdp.media.format", ""))
                for port in media_ports:
                    sdp_ports[port].append({
                        "callid": callid,
                        "media_ip": row.get("sdp.connection_info.address", ""),
                        "media_proto": media_proto,
                        "media_security": media_security,
                        "codec_map": codec_map,
                    })
                for pt in media_formats:
                    codec = codec_map.get(pt) or self._RTP_PT.get(pt) or self._rtp_static_payload_name(pt)
                    sdp_payloads[pt].append({
                        "callid": callid,
                        "codec": codec,
                        "media_security": media_security,
                    })
                sip_msgs.append({
                    "frame": row.get("frame.number", ""), "time": row.get("frame.time", ""),
                    "src": row.get("ip.src", "") or row.get("ipv6.src", ""),
                    "dst": row.get("ip.dst", "") or row.get("ipv6.dst", ""),
                    "method": verb, "from": row.get("sip.From", ""), "to": row.get("sip.To", ""),
                    "callid": callid,
                    "sdp_media_ip": row.get("sdp.connection_info.address", ""),
                    "sdp_media_port": row.get("sdp.media.port", ""),
                    "sdp_media_proto": media_proto,
                    "sdp_payloads": row.get("sdp.media.format", ""),
                    "media_security": media_security if media_ports else "",
                })
        except Exception:
            pass

        rtp_streams = {}
        try:
            cmd_rtp = [tshark, "-r", pcap_path, "-Y", "rtp", "-T", "fields",
                       "-e", "ip.src", "-e", "ip.dst",
                       "-e", "ipv6.src", "-e", "ipv6.dst",
                       "-e", "udp.srcport", "-e", "udp.dstport",
                       "-e", "rtp.ssrc", "-e", "rtp.p_type",
                       "-e", "rtp.seq", "-e", "frame.time_epoch",
                       "-E", "separator=\t", "-E", "occurrence=f"]
            r = subprocess.run(cmd_rtp, capture_output=True, text=True,
                               encoding="utf-8", errors="replace", timeout=180)
            for line in r.stdout.split("\n"):
                if not line.strip():
                    continue
                p = line.split("\t")
                p += [""] * (10 - len(p))
                ip4s, ip4d, ip6s, ip6d, sport, dport, ssrc, ptype, seq, tepoch = p[:10]
                if not ssrc:
                    continue
                src = f"{ip4s or ip6s}:{sport}"
                dst = f"{ip4d or ip6d}:{dport}"
                key = (ssrc, src, dst)
                st = rtp_streams.get(key)
                if st is None:
                    codec, callid, media_security = self._resolve_rtp_from_sdp(
                        ptype, sport, dport, sdp_ports, sdp_payloads)
                    st = {"ssrc": ssrc, "src": src, "dst": dst,
                          "payload_type": ptype,
                          "payload": codec,
                          "sip_callid": callid,
                          "media_security": media_security,
                          "packets": 0, "seqs": [], "times": []}
                    rtp_streams[key] = st
                st["packets"] += 1
                try:
                    st["seqs"].append(int(seq))
                except (ValueError, TypeError):
                    pass
                try:
                    st["times"].append(float(tepoch))
                except (ValueError, TypeError):
                    pass
        except Exception:
            pass

        rtp_list = []
        for st in rtp_streams.values():
            seqs = st["seqs"]
            lost = 0
            if len(seqs) >= 2:
                span = max(seqs) - min(seqs) + 1
                lost = max(0, span - len(set(seqs)))
            times = st["times"]
            duration = (max(times) - min(times)) if len(times) >= 2 else 0.0
            # Approximate max jitter from inter-arrival deltas (ms)
            max_jitter = 0.0
            if len(times) >= 3:
                ts = sorted(times)
                deltas = [ts[i + 1] - ts[i] for i in range(len(ts) - 1)]
                mean_d = sum(deltas) / len(deltas)
                max_jitter = max(abs(d - mean_d) for d in deltas) * 1000.0
            rtp_list.append({
                "ssrc": st["ssrc"], "src": st["src"], "dst": st["dst"],
                "payload_type": st.get("payload_type", ""),
                "payload": st["payload"],
                "sip_callid": st.get("sip_callid", ""),
                "media_security": st.get("media_security", "RTP"),
                "packets": st["packets"],
                "lost": lost, "max_jitter": max_jitter, "duration": duration,
            })

        self.analysis_results["sip"] = sip_msgs
        self.analysis_results["rtp"] = rtp_list

    def _resolve_rtp_from_sdp(self, payload_type, src_port, dst_port, sdp_ports, sdp_payloads):
        """Resolve RTP codec and SIP Call-ID using SDP media ports/payload maps."""
        payload_type = str(payload_type or "")
        base_codec = self._RTP_PT.get(payload_type) or self._rtp_static_payload_name(payload_type) or payload_type
        for port in (dst_port, src_port):
            for entry in sdp_ports.get(str(port or ""), []):
                codec = entry.get("codec_map", {}).get(payload_type) or base_codec
                return codec, entry.get("callid", ""), entry.get("media_security", "RTP")
        entries = sdp_payloads.get(payload_type, [])
        if len(entries) == 1:
            entry = entries[0]
            return entry.get("codec") or base_codec, entry.get("callid", ""), entry.get("media_security", "RTP")
        return base_codec, "", "RTP"

    # ------------------------------------------------------------------
    # CCTV: RTSP/ONVIF discovery + best-effort H.264 RTP video decode
    # ------------------------------------------------------------------
    @staticmethod
    def _bytes_from_tshark_hex(value):
        text = str(value or "").replace(":", "").replace(",", "").replace(" ", "").strip()
        if not text or len(text) % 2:
            return b""
        try:
            return bytes.fromhex(text)
        except ValueError:
            return b""

    @staticmethod
    def _h264_has_sps_pps(data):
        """Return whether an Annex-B H.264 byte stream contains SPS and PPS NALs."""
        if not data:
            return False, False
        has_sps = False
        has_pps = False
        for match in re.finditer(rb"\x00\x00\x01|\x00\x00\x00\x01", data):
            start = match.end()
            if start >= len(data):
                continue
            nal_type = data[start] & 0x1F
            has_sps = has_sps or nal_type == 7
            has_pps = has_pps or nal_type == 8
            if has_sps and has_pps:
                break
        return has_sps, has_pps

    @staticmethod
    def _parse_h264_sprop_parameter_sets(value):
        """Decode SDP sprop-parameter-sets into Annex-B SPS/PPS bytes."""
        text = str(value or "")
        match = re.search(r"sprop-parameter-sets\s*=\s*([^;\s,]+(?:,[^;\s,]+)*)", text, re.I)
        if not match:
            return b""
        out = bytearray()
        for item in match.group(1).split(","):
            item = item.strip()
            if not item:
                continue
            try:
                out += b"\x00\x00\x00\x01" + base64.b64decode(item + "=" * (-len(item) % 4))
            except Exception:
                continue
        return bytes(out)

    @staticmethod
    def _parse_sdp_codec_map(*values):
        """Return RTP payload-type -> codec name from SDP rtpmap/fmtp text."""
        codec_by_pt = {}
        text = " ".join(str(v or "") for v in values)
        for pt, codec in re.findall(r"(?:rtpmap:)?\s*(\d{1,3})\s+([A-Za-z0-9_.-]+)\s*/\s*\d+", text, re.I):
            codec_by_pt[pt] = codec.upper()
        for pt, codec in re.findall(r"(?:fmtp:)?\s*(\d{1,3})\s+.*?(H264|H265|HEVC|MP4V-ES|JPEG|MJPEG)", text, re.I):
            codec_by_pt.setdefault(pt, codec.upper())
        return codec_by_pt

    @staticmethod
    def _rtp_static_payload_name(payload_type):
        static_map = {
            "0": "PCMU/G.711 u-law audio",
            "3": "GSM audio",
            "4": "G723 audio",
            "5": "DVI4 audio",
            "6": "DVI4 audio",
            "7": "LPC audio",
            "8": "PCMA/G.711 A-law audio",
            "9": "G722 audio",
            "10": "L16 stereo audio",
            "11": "L16 mono audio",
            "12": "QCELP audio",
            "13": "CN comfort noise",
            "14": "MPA audio",
            "15": "G728 audio",
            "16": "DVI4 audio",
            "17": "DVI4 audio",
            "18": "G729 audio",
            "25": "CelB video",
            "26": "JPEG video",
            "31": "H261 video",
            "32": "MPV video",
            "33": "MP2T audio/video",
            "34": "H263 video",
        }
        return static_map.get(str(payload_type or ""))

    @staticmethod
    def _payload_repetition_ratio(data):
        if not data:
            return 0.0
        from collections import Counter
        return Counter(data).most_common(1)[0][1] / len(data)

    @staticmethod
    def _find_named_executable(names, extra_paths=None):
        """Find an executable from PATH or common Windows install locations."""
        for name in names:
            found = shutil.which(name)
            if found:
                return found
        candidates = list(extra_paths or [])
        if os.name == "nt":
            wanted = {str(name).lower() for name in names}
            roots = [
                os.environ.get("ProgramFiles", ""),
                os.environ.get("ProgramFiles(x86)", ""),
                os.environ.get("LOCALAPPDATA", ""),
                os.environ.get("ProgramData", ""),
            ]
            for root in roots:
                if not root:
                    continue
                if "ffmpeg" in wanted or "ffmpeg.exe" in wanted:
                    candidates.extend([
                        os.path.join(root, "ffmpeg", "bin", "ffmpeg.exe"),
                        os.path.join(root, "chocolatey", "bin", "ffmpeg.exe"),
                    ])
                if "vlc" in wanted or "vlc.exe" in wanted:
                    candidates.extend([
                        os.path.join(root, "VLC", "vlc.exe"),
                        os.path.join(root, "VideoLAN", "VLC", "vlc.exe"),
                    ])
        for path in candidates:
            if path and os.path.exists(path):
                return path
        return ""

    @staticmethod
    def _h264_rtp_payload_to_annexb(payload, state):
        """Convert one RTP H.264 payload to Annex-B bytes. Supports NAL, STAP-A, FU-A."""
        if not payload:
            return b""
        nal_type = payload[0] & 0x1F
        start = b"\x00\x00\x00\x01"
        if 1 <= nal_type <= 23:
            return start + payload
        if nal_type == 24:  # STAP-A
            out = bytearray()
            pos = 1
            while pos + 2 <= len(payload):
                size = struct.unpack("!H", payload[pos:pos + 2])[0]
                pos += 2
                if size <= 0 or pos + size > len(payload):
                    break
                out += start + payload[pos:pos + size]
                pos += size
            return bytes(out)
        if nal_type == 28 and len(payload) >= 2:  # FU-A
            indicator = payload[0]
            header = payload[1]
            fu_start = bool(header & 0x80)
            fu_end = bool(header & 0x40)
            reconstructed = (indicator & 0xE0) | (header & 0x1F)
            if fu_start:
                state["fu"] = bytearray(start + bytes([reconstructed]) + payload[2:])
                return b""
            if "fu" not in state:
                return b""
            state["fu"] += payload[2:]
            if fu_end:
                return bytes(state.pop("fu"))
        return b""

    def _convert_h264_to_mp4(self, h264_path):
        """Convert raw H.264 Annex-B stream to MP4 if ffmpeg is available."""
        ffmpeg = self._find_named_executable(["ffmpeg", "ffmpeg.exe"])
        if not ffmpeg or not h264_path or not os.path.exists(h264_path):
            return "", "ffmpeg not found; raw .h264 saved"
        mp4_path = os.path.splitext(h264_path)[0] + ".mp4"
        try:
            attempts = [
                [ffmpeg, "-y", "-loglevel", "error", "-fflags", "+genpts",
                 "-f", "h264", "-r", "25", "-i", h264_path, "-c:v", "copy", mp4_path],
                [ffmpeg, "-y", "-loglevel", "error", "-fflags", "+genpts",
                 "-f", "h264", "-r", "25", "-i", h264_path, "-c:v", "libx264",
                 "-preset", "veryfast", "-pix_fmt", "yuv420p", mp4_path],
            ]
            last_error = ""
            for cmd in attempts:
                result = subprocess.run(cmd, capture_output=True, text=True,
                                        encoding="utf-8", errors="replace", timeout=240)
                if os.path.exists(mp4_path) and os.path.getsize(mp4_path) > 0:
                    return mp4_path, ""
                last_error = (result.stderr or result.stdout or "").strip()
            return "", last_error or "MP4 conversion failed"
        except Exception as e:
            return "", str(e)

    def _analyze_cctv(self, pcap_path):
        """Detect CCTV-related traffic and decode clear H.264 RTP streams when possible."""
        records = []
        h264_config_by_pt = {}
        h264_config_any = b""
        codec_by_pt = {}
        temp_dir = os.path.join(tempfile.gettempdir(), "pcap_dashboard_cctv")
        os.makedirs(temp_dir, exist_ok=True)
        try:
            tshark = self.tshark_path.get()
            sig_fields = self._filter_tshark_fields([
                "frame.number", "frame.time_epoch", "_ws.col.protocol", "_ws.col.info",
                "ip.src", "ip.dst", "ipv6.src", "ipv6.dst",
                "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport",
                "rtsp.request.method", "rtsp.request.uri", "rtsp.response.code",
                "rtsp.session", "rtsp.transport", "rtsp.content_type",
                "sdp.media", "sdp.media.format", "sdp.connection_info.address",
                "sdp.fmtp.parameter", "sdp.fmtp.h264_packetization_mode",
                "sdp.media_attr", "sdp.media_attribute.value",
                "http.request.method", "http.host", "http.request.uri",
                "http.content_type",
            ])
            sig_filter = (
                'rtsp || sdp || udp.port == 3702 || tcp.port == 554 || '
                'http.content_type matches "(?i)(video|image|multipart|mjpeg)" || '
                'http.request.uri matches "(?i)(onvif|snapshot|mjpg|mjpeg|videostream|axis-cgi|cgi-bin)"'
            )
            if sig_fields:
                cmd = [tshark, "-r", pcap_path, "-Y", sig_filter, "-T", "fields"]
                for field in sig_fields:
                    cmd += ["-e", field]
                cmd += ["-E", "separator=\t", "-E", "occurrence=a", "-E", "aggregator=,"]
                for line in self._iter_command_lines(cmd, timeout=180, max_lines=50000):
                    if not line.strip():
                        continue
                    parts = line.split("\t")
                    parts += [""] * (len(sig_fields) - len(parts))
                    row = dict(zip(sig_fields, parts[:len(sig_fields)]))
                    src = row.get("ip.src") or row.get("ipv6.src")
                    dst = row.get("ip.dst") or row.get("ipv6.dst")
                    sport = row.get("tcp.srcport") or row.get("udp.srcport")
                    dport = row.get("tcp.dstport") or row.get("udp.dstport")
                    proto = row.get("_ws.col.protocol", "")
                    uri = row.get("rtsp.request.uri") or row.get("http.request.uri")
                    method = row.get("rtsp.request.method") or row.get("http.request.method")
                    fmtp = row.get("sdp.fmtp.parameter", "")
                    codec_by_pt.update(self._parse_sdp_codec_map(
                        row.get("sdp.media_attr", ""),
                        row.get("sdp.media_attribute.value", ""),
                        row.get("sdp.media", ""),
                        fmtp,
                    ))
                    sprop = self._parse_h264_sprop_parameter_sets(fmtp)
                    if sprop:
                        h264_config_any = sprop
                        for pt_value in re.findall(r"\d+", row.get("sdp.media.format", "")):
                            h264_config_by_pt.setdefault(pt_value, sprop)
                    codec = self._join_unique([
                        row.get("sdp.media.format"), fmtp, row.get("rtsp.content_type"),
                        row.get("http.content_type")
                    ], limit=4)
                    has_rtsp_structure = any(row.get(k) for k in (
                        "rtsp.request.method", "rtsp.request.uri", "rtsp.response.code",
                        "rtsp.session", "rtsp.transport", "sdp.media",
                        "sdp.fmtp.parameter", "sdp.media_attribute.value"))
                    kind = "ONVIF/WS-Discovery" if "3702" in {sport, dport} else (
                        "RTSP/SDP" if has_rtsp_structure else "Camera-port candidate")
                    notes = self._join_unique([
                        method, uri, row.get("rtsp.response.code"),
                        row.get("rtsp.session"), row.get("rtsp.transport"),
                        row.get("_ws.col.info")
                    ], limit=6)
                    if not has_rtsp_structure and "RTSP" in proto.upper():
                        notes = self._join_unique([
                            notes,
                            "TShark labelled protocol RTSP, but no RTSP request/response/SDP fields were decoded"
                        ], limit=4)
                    records.append({
                        "kind": kind,
                        "frames": row.get("frame.number", ""),
                        "time": row.get("frame.time_epoch", ""),
                        "src": f"{src}:{sport}" if sport else src,
                        "dst": f"{dst}:{dport}" if dport else dst,
                        "protocol": proto,
                        "codec": codec,
                        "payload_type": row.get("sdp.media.format", ""),
                        "ssrc": "",
                        "packets": 1,
                        "decoded": "No",
                        "video_file": "",
                        "notes": notes,
                        "detail": row,
                    })
        except Exception:
            pass

        try:
            tshark = self.tshark_path.get()
            rtp_fields = self._filter_tshark_fields([
                "frame.number", "frame.time_epoch", "ip.src", "ip.dst",
                "ipv6.src", "ipv6.dst", "udp.srcport", "udp.dstport",
                "rtp.ssrc", "rtp.p_type", "rtp.seq", "rtp.timestamp",
                "rtp.marker", "rtp.payload", "h264.nal_unit_type",
                "h264.nal_unit", "h264.start.bit", "h264.end.bit",
            ])
            if "rtp.payload" in rtp_fields:
                cmd = [tshark, "-r", pcap_path, "-Y", "rtp && rtp.payload", "-T", "fields"]
                for field in rtp_fields:
                    cmd += ["-e", field]
                cmd += ["-E", "separator=\t", "-E", "occurrence=f"]
                streams = {}
                for line in self._iter_command_lines(cmd, timeout=300, max_lines=300000):
                    if not line.strip():
                        continue
                    parts = line.split("\t")
                    parts += [""] * (len(rtp_fields) - len(parts))
                    row = dict(zip(rtp_fields, parts[:len(rtp_fields)]))
                    src = row.get("ip.src") or row.get("ipv6.src")
                    dst = row.get("ip.dst") or row.get("ipv6.dst")
                    key = (
                        src, row.get("udp.srcport", ""), dst, row.get("udp.dstport", ""),
                        row.get("rtp.ssrc", ""), row.get("rtp.p_type", "")
                    )
                    streams.setdefault(key, []).append(row)

                def rtp_seq_value(row):
                    try:
                        return int(row.get("rtp.seq") or 0)
                    except (TypeError, ValueError):
                        return 0

                for key, rows in streams.items():
                    src_ip, sport, dst_ip, dport, ssrc, pt = key
                    rows.sort(key=rtp_seq_value)
                    static_payload = self._rtp_static_payload_name(pt)
                    sdp_codec = codec_by_pt.get(str(pt), "")
                    dynamic_pt = str(pt).isdigit() and 96 <= int(pt) <= 127
                    tshark_h264_types = {
                        value.strip()
                        for row in rows
                        for value in str(row.get("h264.nal_unit_type", "") or "").split(",")
                        if value.strip()
                    }
                    h264_allowed = (
                        sdp_codec in {"H264", "H.264"} or
                        bool(tshark_h264_types) or
                        (dynamic_pt and str(pt) in h264_config_by_pt)
                    )
                    state = {}
                    out = bytearray()
                    nal_seen = set()
                    frames = []
                    for row in rows:
                        payload = self._bytes_from_tshark_hex(row.get("rtp.payload", ""))
                        if row.get("frame.number"):
                            frames.append(row.get("frame.number"))
                        if not h264_allowed:
                            continue
                        if payload:
                            nal_seen.add(payload[0] & 0x1F)
                        out += self._h264_rtp_payload_to_annexb(payload, state)

                    if static_payload:
                        codec = static_payload
                    elif sdp_codec:
                        codec = sdp_codec
                    elif h264_allowed and out:
                        codec = "H.264"
                    elif dynamic_pt:
                        codec = "RTP dynamic unknown"
                    else:
                        codec = "RTP"
                    h264_path = ""
                    mp4_path = ""
                    decoded = "No"
                    sample_payload = b""
                    for sample_row in rows[:10]:
                        sample_payload += self._bytes_from_tshark_hex(sample_row.get("rtp.payload", ""))[:200]
                    repetition = self._payload_repetition_ratio(sample_payload)
                    notes_parts = []
                    if static_payload:
                        notes_parts.append(
                            f"Static RTP payload type {pt} = {static_payload}; not H.264 CCTV video")
                    if sdp_codec:
                        notes_parts.append(f"SDP codec: {sdp_codec}")
                    if tshark_h264_types:
                        notes_parts.append(f"TShark H.264 NAL types: {', '.join(sorted(tshark_h264_types))}")
                    elif nal_seen:
                        notes_parts.append(f"Reconstructed H.264 NAL types: {', '.join(str(x) for x in sorted(nal_seen))}")
                    if repetition >= 0.80 and sample_payload:
                        notes_parts.append(
                            f"Low-entropy repeated payload ({repetition:.0%}); likely audio/silence or padding")
                    if not h264_allowed:
                        notes_parts.append("No SDP/TShark evidence that this RTP stream is H.264")
                    notes = self._join_unique(notes_parts, limit=6)

                    sdp_config = h264_config_by_pt.get(str(pt), b"")
                    if sdp_config and not self._h264_has_sps_pps(out)[0]:
                        out = bytearray(sdp_config) + out
                        notes = self._join_unique([notes, "SPS/PPS prepended from SDP"], limit=4)

                    has_sps, has_pps = self._h264_has_sps_pps(out)
                    likely_h264_video = (
                        h264_allowed and
                        dynamic_pt and
                        not static_payload and
                        len(out) >= 4096 and
                        (has_sps or 5 in nal_seen or 1 in nal_seen or 28 in nal_seen) and
                        not ({7, 8}.issuperset(nal_seen) and len(out) < 2048) and
                        repetition < 0.80
                    )
                    if out and likely_h264_video:
                        has_sps, has_pps = self._h264_has_sps_pps(out)
                        if not has_sps or not has_pps:
                            notes = self._join_unique([
                                notes,
                                "SPS/PPS header missing; video may need earlier RTSP/SDP packets"
                            ], limit=4)
                        safe_ssrc = re.sub(r"[^A-Za-z0-9_.-]+", "_", ssrc or "unknown")
                        safe_src = re.sub(r"[^A-Za-z0-9_.-]+", "_", f"{src_ip}_{sport}")
                        h264_path = os.path.join(temp_dir, f"cctv_{safe_src}_{safe_ssrc}.h264")
                        with open(h264_path, "wb") as f:
                            f.write(out)
                        mp4_path, convert_error = self._convert_h264_to_mp4(h264_path)
                        decoded = "MP4" if mp4_path else "H264"
                        if not mp4_path:
                            notes = self._join_unique([
                                notes,
                                convert_error or "MP4 conversion failed; raw .h264 saved"
                            ], limit=4)
                    elif out:
                        codec = "RTP / partial H.264"
                        notes = self._join_unique([
                            notes,
                            f"Only {len(out)} bytes recovered; not enough playable video data"
                        ], limit=4)

                    records.append({
                        "kind": "RTP H.264 Video" if likely_h264_video else "RTP Non-video/Candidate",
                        "frames": self._join_unique([frames[0] if frames else "", frames[-1] if frames else ""], limit=2),
                        "time": rows[0].get("frame.time_epoch", "") if rows else "",
                        "src": f"{src_ip}:{sport}",
                        "dst": f"{dst_ip}:{dport}",
                        "protocol": "RTP",
                        "codec": codec,
                        "payload_type": pt,
                        "ssrc": ssrc,
                        "packets": len(rows),
                        "decoded": decoded,
                        "video_file": mp4_path or h264_path,
                        "h264_file": h264_path,
                        "notes": notes,
                        "detail": {"stream_key": key, "first_packet": rows[0] if rows else {}},
                    })
        except Exception:
            pass

        self.analysis_results["cctv"] = records

    # ------------------------------------------------------------------
    # Satellite / PCAPNG Custom-Block embedded JSON telemetry
    # ------------------------------------------------------------------
    _JSON_OBJ_RE = re.compile(r"\{.*\}")

    def _extract_json_record(self, text):
        """Parse the outermost JSON object embedded in decoded custom-block text."""
        if not text:
            return None
        decoder = json.JSONDecoder()
        for start, ch in enumerate(text):
            if ch != "{":
                continue
            try:
                rec, _ = decoder.raw_decode(text[start:])
                if isinstance(rec, dict) and rec:
                    return rec
            except json.JSONDecodeError:
                continue
        return None

    def _add_satellite_record(self, records, frame_no, epoch_time, text,
                              pen="", extraction_source=""):
        """Parse one possible JSON payload and append it to satellite records."""
        rec = self._extract_json_record(text)
        if rec is None or not isinstance(rec, dict) or not rec:
            return False
        flat = {"frame_no": frame_no, "epoch_time": epoch_time}
        if pen:
            flat["pen"] = pen
        flat.update({str(k): v for k, v in rec.items()})
        if extraction_source:
            flat["extraction_source"] = extraction_source
        records.append(flat)
        return True

    def _analyze_satellite_data_fields(self, tshark, pcap_path, records):
        """Fallback: scan ordinary packet data fields for embedded JSON."""
        cmd = [tshark, "-r", pcap_path,
               "-T", "fields",
               "-e", "frame.number",
               "-e", "frame.time_epoch",
               "-e", "data.data",
               "-E", "separator=\t",
               "-E", "occurrence=f"]
        result = subprocess.run(cmd, capture_output=True, text=True,
                                encoding="utf-8", errors="replace", timeout=1200)
        for line in result.stdout.splitlines():
            if not line.strip():
                continue
            parts = line.split("\t")
            parts += [""] * (3 - len(parts))
            frame_no, epoch_time, hex_data = parts[0], parts[1], parts[2]
            if not hex_data:
                continue
            self._add_satellite_record(records, frame_no, epoch_time,
                                       self._hex_to_text(hex_data),
                                       extraction_source="data.data")

    def _analyze_satellite_verbose_pcapng(self, tshark, pcap_path, records):
        """Fallback: scan verbose PCAPNG packet details for embedded JSON."""
        cmd = [tshark, "-r", pcap_path,
               "-Y", '_ws.col.protocol == "PCAPNG"',
               "-T", "json"]
        result = subprocess.run(cmd, capture_output=True, text=True,
                                encoding="utf-8", errors="replace", timeout=1200)
        if not result.stdout.strip():
            return
        try:
            packets = json.loads(result.stdout)
        except json.JSONDecodeError:
            return

        def walk(value):
            if isinstance(value, dict):
                for v in value.values():
                    yield from walk(v)
            elif isinstance(value, list):
                for v in value:
                    yield from walk(v)
            elif isinstance(value, str):
                yield value

        seen = set()
        for packet in packets:
            layers = packet.get("_source", {}).get("layers", {})
            frame = layers.get("frame", {})
            frame_no = frame.get("frame.number", "")
            epoch_time = frame.get("frame.time_epoch", "")
            pen = layers.get("pcapng", {}).get("pcapng.cb.pen", "")
            for value in walk(layers):
                candidates = [value]
                if re.fullmatch(r"(?:[0-9A-Fa-f]{2}:?){4,}", value):
                    candidates.append(self._hex_to_text(value))
                for candidate in candidates:
                    key = (frame_no, candidate[:200])
                    if key in seen:
                        continue
                    seen.add(key)
                    self._add_satellite_record(records, frame_no, epoch_time,
                                               candidate, pen=pen,
                                               extraction_source="_ws.col.protocol PCAPNG")

    def _has_satellite_telemetry_details(self, records):
        """Return True when extracted records contain actual satellite fields."""
        detail_keys = ("satellite-name", "satellite-sub-network-name",
                       "frequency-band", "comm-ses-id")
        return any(any(str(r.get(k, "")).strip() for k in detail_keys)
                   for r in records)

    def _extract_satellite_records(self, tshark, pcap_path):
        """Extract satellite telemetry records from one capture path."""
        records = []
        # Use pcapng custom-block fields - these work on unmerged source files.
        cmd = [tshark, "-r", pcap_path,
               "-Y", ("pcapng.cb.custom_data || "
                      "pcapng.cb.custom_option.string || "
                      "pcapng.cb.custom_option.data"),
               "-T", "fields",
               "-e", "frame.number",
               "-e", "frame.time_epoch",
               "-e", "pcapng.cb.pen",
               "-e", "pcapng.cb.custom_data",
               "-e", "pcapng.cb.custom_option.string",
               "-e", "pcapng.cb.custom_option.data",
               "-E", "separator=\t",
               "-E", "occurrence=f"]
        result = subprocess.run(cmd, capture_output=True, text=True,
                                encoding="utf-8", errors="replace", timeout=1200)
        for line in result.stdout.splitlines():
            if not line.strip():
                continue
            parts = line.split("\t")
            parts += [""] * (6 - len(parts))
            frame_no, epoch_time, pen, custom_data, custom_option, custom_option_data = parts[:6]
            if custom_data:
                self._add_satellite_record(records, frame_no, epoch_time,
                                           self._hex_to_text(custom_data),
                                           pen=pen,
                                           extraction_source="pcapng.cb.custom_data")
            if custom_option:
                self._add_satellite_record(records, frame_no, epoch_time,
                                           custom_option, pen=pen,
                                           extraction_source="pcapng.cb.custom_option.string")
            if custom_option_data:
                self._add_satellite_record(records, frame_no, epoch_time,
                                           self._hex_to_text(custom_option_data),
                                           pen=pen,
                                           extraction_source="pcapng.cb.custom_option.data")

        if not records:
            self._analyze_satellite_data_fields(tshark, pcap_path, records)
        if not records:
            self._analyze_satellite_verbose_pcapng(tshark, pcap_path, records)
        return records

    def _extract_satellite_from_merge_sources(self, tshark):
        """Recover telemetry from original files when mergecap omits custom blocks."""
        recovered = []
        for src in getattr(self, "merged_source_files", []):
            if not src or not os.path.exists(src):
                continue
            try:
                source_records = self._extract_satellite_records(tshark, src)
            except Exception:
                continue
            for rec in source_records:
                rec = dict(rec)
                rec["capture_source_file"] = os.path.basename(src)
                recovered.append(rec)
        return recovered

    def _analyze_satellite(self, pcap_path):
        """
        Extract embedded JSON telemetry carried in PCAPNG Custom Blocks
        (satellite / iDirect comm-session records). Uses tshark's pcapng
        custom-block dissection fields which work reliably on both original
        and merged PCAPNG files.
        """
        records = []
        try:
            tshark = self.tshark_path.get()
            records = self._extract_satellite_records(tshark, pcap_path)
            if (pcap_path == self.merged_file and
                    not self._has_satellite_telemetry_details(records)):
                recovered = self._extract_satellite_from_merge_sources(tshark)
                if self._has_satellite_telemetry_details(recovered):
                    records = recovered
        except Exception:
            pass
        self.analysis_results["satellite"] = records

    def _update_ui_after_analysis(self):
        """Update UI with analysis results"""
        self.analysis_completed = True
        # Update overview stats
        stats = self.analysis_results.get("stats", {})
        if hasattr(self, "top_kpis"):
            sessions = self.analysis_results.get("logical_sessions", [])
            upload_count = sum(len(s.upload_events) for s in sessions)
            if not upload_count:
                upload_count = sum(1 for s in self.analysis_results.get("sessions", [])
                                   if s.get("classification") in {"Heavy Upload", "Upload Dominant"})
            top_values = {
                "Packets Analyzed": f"{stats.get('total_packets', 0):,}",
                "TLS Connections": f"{len(self.analysis_results.get('tls', {})):,}",
                "Uploads Detected": f"{upload_count:,}",
                "RADIUS Packets": f"{len(self.analysis_results.get('radius_packets', [])):,}",
                "Capture Time": f"{stats.get('duration', 0):.1f}s",
            }
            for key, value in top_values.items():
                if key in self.top_kpis:
                    self.top_kpis[key].config(text=value)
        self.stat_cards["Total Packets"].value_label.config(text=f"{stats.get('total_packets', 0):,}")
        self.stat_cards["Total Bytes"].value_label.config(text=self.format_bytes(stats.get('total_bytes', 0)))
        self.stat_cards["Duration"].value_label.config(text=f"{stats.get('duration', 0):.2f}s")
        self.stat_cards["Unique IPs"].value_label.config(text=f"{stats.get('unique_ips', 0):,}")
        self.stat_cards["Protocols"].value_label.config(text=f"{len(self.analysis_results.get('protocols', {})):,}")
        
        # Update summary
        self.summary_text.config(state=tk.NORMAL)
        self.summary_text.delete("1.0", tk.END)
        summary = self._generate_summary()
        self.summary_text.insert("1.0", summary)
        self.summary_text.config(state=tk.DISABLED)
        
        # Update protocol tree
        self.protocol_tree.delete(*self.protocol_tree.get_children())
        protocols = self.analysis_results.get("protocols", {})
        total_bytes = sum(p.get("bytes", 0) for p in protocols.values())
        for proto, data in sorted(protocols.items(), key=lambda x: x[1].get("bytes", 0), reverse=True):
            pct = (data.get("bytes", 0) / total_bytes * 100) if total_bytes > 0 else 0
            self.protocol_tree.insert("", tk.END, values=(
                proto, f"{data.get('frames', 0):,}",
                self.format_bytes(data.get('bytes', 0)), f"{pct:.1f}%"
            ))
            
        # Update DNS tree
        self.dns_tree.delete(*self.dns_tree.get_children())
        for domain, data in sorted(self.analysis_results.get("dns", {}).items(), 
                                   key=lambda x: x[1]["count"], reverse=True)[:100]:
            self.dns_tree.insert("", tk.END, values=(
                domain, ", ".join(data.get("types", set())),
                ", ".join(list(data.get("responses", set()))[:3]), data.get("count", 0)
            ))
            
        # Update TLS tree
        self.tls_tree.delete(*self.tls_tree.get_children())
        for sni, data in sorted(self.analysis_results.get("tls", {}).items(), 
                                key=lambda x: x[1]["count"], reverse=True):
            self.tls_tree.insert("", tk.END, values=(
                sni, ", ".join(data.get("versions", set())),
                ", ".join(list(data.get("ciphers", set()))[:2]), "", data.get("count", 0)
            ))
            
        # Update sessions tree
        self.sessions_tree.delete(*self.sessions_tree.get_children())
        for i, session in enumerate(self.analysis_results.get("sessions", [])[:500]):
            self.sessions_tree.insert("", tk.END, values=(
                f"Session-{i+1}", session.get("src_ip", ""), session.get("src_port", ""),
                session.get("dst_ip", ""), session.get("dst_port", ""),
                session.get("protocol", ""), session.get("packets", 0),
                self.format_bytes(session.get("bytes", 0)), ""
            ))
            
        # Update raw data
        self.raw_text.delete("1.0", tk.END)
        self.raw_text.insert("1.0", self.analysis_results.get("protocols_raw", ""))

        # Update new analysis tabs
        self._update_http_ui()
        self._update_files_ui()
        self._update_stun_ui()
        self._update_radius_ui()
        self._update_ss7_signaling_ui()
        self._update_ss7_ui()
        self._update_voip_ui()
        self._update_cctv_ui()
        self._update_satellite_ui()

    def _update_http_ui(self):
        """Populate the HTTP Content tab."""
        self.http_tree.delete(*self.http_tree.get_children())
        txns = self.analysis_results.get("http", [])
        leak_count = 0
        for i, t in enumerate(txns):
            leaks = t.get("leaks", [])
            has_secret = any(x in leaks for x in ("CREDENTIALS", "COOKIE", "URI-SECRET"))
            if leaks:
                leak_count += 1
            tag = "leak" if has_secret else ("plain" if leaks else "")
            self.http_tree.insert("", tk.END, iid=str(i), values=(
                t.get("frame", ""), t.get("time", "")[:19], t.get("method", ""),
                t.get("host", ""), (t.get("uri", "") or "")[:120],
                t.get("code", ""), t.get("content_type", ""),
                t.get("length", ""), t.get("leak", "")),
                tags=(tag,) if tag else ())
        self.http_summary.config(
            text=f"HTTP transactions: {len(txns)}   |   Potential leaks: {leak_count}")

    def _update_files_ui(self):
        """Populate the extracted files / images tab."""
        self.files_tree.delete(*self.files_tree.get_children())
        files = self.analysis_results.get("files", [])
        img_count = 0
        for i, f in enumerate(files):
            if f.get("is_image"):
                img_count += 1
            tag = "image" if f.get("is_image") else ""
            self.files_tree.insert("", tk.END, iid=str(i), values=(
                i + 1, f.get("frame", ""), f.get("time", "")[:19],
                f.get("src", ""), f.get("dst", ""), f.get("code", ""),
                f.get("content_type", ""), self.format_bytes(f.get("size", 0)),
                f.get("ext", ""), (f.get("uri", "") or "")[:160]),
                tags=(tag,) if tag else ())
        self.files_summary.config(
            text=f"Extracted files: {len(files)}   Images: {img_count}")

    def on_files_select(self, event):
        """Show file details and image preview for the selected extracted file."""
        sel = self.files_tree.selection()
        if not sel:
            return
        try:
            f = self.analysis_results.get("files", [])[int(sel[0])]
        except (ValueError, IndexError):
            return
        self.files_detail.delete("1.0", tk.END)
        lines = [
            f"Frame:        {f.get('frame','')}",
            f"Time:         {f.get('time','')}",
            f"{f.get('src','')}  ->  {f.get('dst','')}",
            f"Status:       {f.get('code','')}",
            f"Content-Type: {f.get('content_type','')}",
            f"Extracted:    {self.format_bytes(f.get('size',0))}",
            f"Extension:    {f.get('ext','')}",
            f"URI:          {f.get('uri','')}",
            f"Temp path:    {f.get('path','')}",
        ]
        self.files_detail.insert("1.0", "\n".join(lines))

        # Image preview if available and PIL installed
        if f.get("is_image") and f.get("path") and HAS_PIL and os.path.exists(f.get("path")):
            self._show_image_preview(f.get("path"))
        else:
            self.image_preview.config(text="Select an extracted image to preview")

    def _show_image_preview(self, path):
        """Load and display an image preview in the files tab."""
        try:
            img = Image.open(path)
            # Resize to fit preview pane (max ~400x300) preserving aspect ratio
            img.thumbnail((400, 300), Image.LANCZOS)
            photo = ImageTk.PhotoImage(img)
            self.image_preview.config(image=photo, text="")
            self.image_preview.image = photo  # keep reference
        except Exception as e:
            self.image_preview.config(image="", text=f"Cannot preview image:\n{e}")

    def save_extracted_file(self):
        """Save the selected extracted file to a user-chosen location."""
        sel = self.files_tree.selection()
        if not sel:
            messagebox.showinfo("No Selection", "Please select an extracted file first.")
            return
        try:
            f = self.analysis_results.get("files", [])[int(sel[0])]
        except (ValueError, IndexError):
            return
        src = f.get("path", "")
        if not src or not os.path.exists(src):
            messagebox.showerror("Error", "File no longer available. Re-run analysis.")
            return
        default = f"extracted_{os.path.basename(src)}"
        dest = filedialog.asksaveasfilename(
            title="Save Extracted File", initialfile=default,
            defaultextension=f.get("ext", ".bin"))
        if not dest:
            return
        try:
            shutil.copy2(src, dest)
            messagebox.showinfo("Saved", f"File saved to:\n{dest}")
        except Exception as e:
            messagebox.showerror("Save Failed", str(e))

    def view_extracted_image(self):
        """Open the selected image in the default system viewer."""
        sel = self.files_tree.selection()
        if not sel:
            messagebox.showinfo("No Selection", "Please select a file first.")
            return
        try:
            f = self.analysis_results.get("files", [])[int(sel[0])]
        except (ValueError, IndexError):
            return
        path = f.get("path", "")
        if not path or not os.path.exists(path):
            messagebox.showerror("Error", "File no longer available. Re-run analysis.")
            return
        try:
            if os.name == "nt":
                os.startfile(path)
            else:
                viewer = shutil.which("xdg-open") or shutil.which("open")
                if viewer:
                    subprocess.Popen([viewer, path])
                else:
                    messagebox.showinfo("Open", f"File located at:\n{path}")
        except Exception as e:
            messagebox.showerror("Open Failed", str(e))

    def _update_voip_ui(self):
        """Populate the VoIP (SIP/RTP) tab."""
        self.sip_tree.delete(*self.sip_tree.get_children())
        sip = self.analysis_results.get("sip", [])
        for m in sip[:2000]:
            self.sip_tree.insert("", tk.END, values=(
                m.get("frame", ""), m.get("time", "")[:19],
                m.get("src", ""), m.get("dst", ""), m.get("method", ""),
                (m.get("from", "") or "")[:60], (m.get("to", "") or "")[:60],
                m.get("callid", "")))

        self.rtp_tree.delete(*self.rtp_tree.get_children())
        rtp = self.analysis_results.get("rtp", [])
        for i, s in enumerate(rtp):
            tags = []
            if s.get("lost", 0) > 0:
                tags.append("loss")
            if s.get("media_security") == "SRTP":
                tags.append("secure")
            self.rtp_tree.insert("", tk.END, iid=f"rtp-{i}", values=(
                s.get("ssrc", ""), s.get("src", ""), s.get("dst", ""),
                s.get("payload", ""), s.get("sip_callid", ""),
                s.get("media_security", "RTP"),
                s.get("packets", 0), s.get("lost", 0),
                f"{s.get('max_jitter', 0):.1f}", f"{s.get('duration', 0):.2f}"),
                tags=tuple(tags))
        self.voip_summary.config(
            text=f"SIP messages: {len(sip)}   RTP streams: {len(rtp)}")

    def _update_cctv_ui(self):
        """Populate CCTV / camera-video detection and decoded stream results."""
        records = self.analysis_results.get("cctv", [])
        self.cctv_tree.delete(*self.cctv_tree.get_children())
        for i, r in enumerate(records[:5000]):
            decoded = r.get("decoded", "")
            tag = "decoded" if decoded in {"MP4", "H264"} else (
                "warning" if "Candidate" in r.get("kind", "") else "")
            self.cctv_tree.insert("", tk.END, iid=str(i), values=(
                r.get("kind", ""),
                r.get("frames", ""),
                r.get("src", ""),
                r.get("dst", ""),
                r.get("protocol", ""),
                r.get("codec", ""),
                r.get("payload_type", ""),
                r.get("ssrc", ""),
                r.get("packets", ""),
                decoded,
                r.get("video_file", ""),
                (r.get("notes", "") or "")[:220],
            ), tags=(tag,) if tag else ())

        rtp_streams = sum(1 for r in records if r.get("kind") == "RTP H.264 Video")
        decoded_videos = sum(1 for r in records
                             if r.get("kind") == "RTP H.264 Video" and r.get("video_file"))
        self.cctv_summary.config(
            text=(f"CCTV records: {len(records)}   Verified RTP H.264 streams: {rtp_streams}   "
                  f"Decoded/validated videos: {decoded_videos}"))

        self.cctv_detail.delete("1.0", tk.END)
        if records:
            from collections import Counter
            kind_counts = Counter(r.get("kind", "Unknown") for r in records)
            codec_counts = Counter(r.get("codec", "Unknown") for r in records if r.get("codec"))
            lines = ["CCTV / video summary", "=" * 40,
                     f"Records: {len(records)}",
                     f"Verified RTP H.264 streams: {rtp_streams}",
                     f"Decoded/validated video files: {decoded_videos}", ""]
            if kind_counts:
                lines.append("Record types:")
                for kind, count in kind_counts.most_common(10):
                    lines.append(f"  {kind:<22} {count}")
            if codec_counts:
                lines.extend(["", "Codecs / content types:"])
                for codec, count in codec_counts.most_common(10):
                    lines.append(f"  {codec:<32} {count}")
            self.cctv_detail.insert("1.0", "\n".join(lines))
        else:
            self.cctv_detail.insert("1.0",
                "No CCTV / camera-video traffic found in this capture.\n\n"
                "This tab looks for RTSP, SDP, ONVIF/WS-Discovery, HTTP camera "
                "URLs/content-types, and clear RTP H.264 payloads. Encrypted video, "
                "proprietary streams, or RTP that TShark does not decode as RTP may "
                "only show limited metadata or no decoded video.")

    def _update_stun_ui(self):
        """Populate the STUN/TURN transaction tab."""
        self.stun_tree.delete(*self.stun_tree.get_children())
        transactions = self.analysis_results.get("stun_transactions", [])
        packets = self.analysis_results.get("stun_packets", [])
        for i, tx in enumerate(transactions[:5000]):
            self.stun_tree.insert("", tk.END, iid=str(i), values=(
                tx.get("transaction_id", ""), tx.get("application", ""),
                tx.get("frames", ""), tx.get("packets", 0),
                tx.get("methods", ""), tx.get("src", ""), tx.get("dst", ""),
                tx.get("mapped_address", ""), tx.get("username", "")[:80],
                tx.get("software", "")[:80], tx.get("rtt_ms", "")))
        apps = {t.get("application") for t in transactions if t.get("application")}
        self.stun_summary.config(
            text=f"STUN packets: {len(packets)}   Transactions: {len(transactions)}   Applications: {len(apps)}")

        self.stun_detail.delete("1.0", tk.END)
        if transactions:
            from collections import Counter
            app_counts = Counter(t.get("application", "Unknown") for t in transactions)
            lines = ["STUN / TURN transaction summary", "=" * 40,
                     f"Packets: {len(packets)}",
                     f"Transactions: {len(transactions)}", ""]
            lines.append("Applications:")
            for app, count in app_counts.most_common(10):
                lines.append(f"  {app:<30} {count}")
            self.stun_detail.insert("1.0", "\n".join(lines))
        else:
            self.stun_detail.insert("1.0",
                "No STUN/TURN packets found in this capture.\n\n"
                "This tab extracts STUN transaction IDs, mapped addresses, "
                "ICE usernames/software, and application-identification hints.")

    def _update_radius_ui(self):
        """Populate the RADIUS packet and CSID/ECI correlation tab."""
        packets = self.analysis_results.get("radius_packets", [])
        correlations = self.analysis_results.get("radius_correlations", [])

        self.radius_tree.delete(*self.radius_tree.get_children())
        for i, r in enumerate(packets[:5000]):
            code_name = r.get("code_name", "")
            tag = "reject" if "Reject" in code_name or r.get("status") == "Failure" else (
                "accept" if "Accept" in code_name or r.get("status") == "Success" else "")
            self.radius_tree.insert("", tk.END, iid=str(i), values=(
                r.get("frame", ""), r.get("time", ""), code_name,
                r.get("status", ""), r.get("connection_type", ""),
                r.get("src", ""), r.get("dst", ""),
                (r.get("username", "") or "")[:180],
                r.get("imsi", ""), r.get("imei", ""), (r.get("mcc_mnc", "") or "")[:170],
                (r.get("calling_station_id", "") or "")[:150],
                (r.get("called_station_id", "") or "")[:150],
                r.get("nas_ip", ""), r.get("framed_ip", ""),
                r.get("nas_port_type", ""), r.get("acct_session_time", "")),
                tags=(tag,) if tag else ())

        self.radius_corr_tree.delete(*self.radius_corr_tree.get_children())
        for i, c in enumerate(correlations[:5000]):
            self.radius_corr_tree.insert("", tk.END, iid=str(i), values=(
                (c.get("calling_station_id", "") or "")[:160],
                c.get("eci", ""), c.get("method", ""),
                c.get("radius_frame", ""), c.get("gtp_frame", ""),
                c.get("delta_seconds", ""),
                (c.get("username", "") or "")[:180],
                c.get("imsi", ""), c.get("imei", ""), (c.get("mcc_mnc", "") or "")[:170],
                c.get("msisdn", ""),
                c.get("radius_ip", ""), c.get("gtp_ip", "")))

        users = {r.get("username") for r in packets if r.get("username")}
        csids = {r.get("calling_station_id") for r in packets if r.get("calling_station_id")}
        self.radius_summary.config(
            text=(f"RADIUS packets: {len(packets)}   Users: {len(users)}   "
                  f"Calling-Station-Ids: {len(csids)}   CSID/ECI correlations: {len(correlations)}"))

        self.radius_detail.delete("1.0", tk.END)
        if packets or correlations:
            from collections import Counter
            code_counts = Counter(r.get("code_name", "Unknown") for r in packets)
            lines = ["RADIUS summary", "=" * 40,
                     f"Packets: {len(packets)}",
                     f"Unique users: {len(users)}",
                     f"Unique Calling-Station-Ids: {len(csids)}",
                     f"CSID/ECI correlations: {len(correlations)}", ""]
            if code_counts:
                lines.append("Codes:")
                for code, count in code_counts.most_common(10):
                    lines.append(f"  {code:<24} {count}")
            self.radius_detail.insert("1.0", "\n".join(lines))
        else:
            self.radius_detail.insert("1.0",
                "No RADIUS packets found in this capture.\n\n"
                "This tab extracts decoded RADIUS authentication/accounting fields and "
                "correlates Calling-Station-Id with GTPv2 ECI when matching subscriber "
                "keys or close timestamps are present.")

    def _update_ss7_signaling_ui(self):
        """Populate the SS7/SIGTRAN decoded signaling tab."""
        self.ss7_sig_tree.delete(*self.ss7_sig_tree.get_children())
        records = self.analysis_results.get("ss7_signaling", [])
        for i, r in enumerate(records[:5000]):
            has_identity = any(r.get(k) for k in ("imsi", "imei", "msisdn", "location"))
            has_sms = bool(r.get("sms_text"))
            tag = "leak" if has_identity else ("sms" if has_sms else "")
            self.ss7_sig_tree.insert("", tk.END, iid=str(i), values=(
                r.get("frame", ""), r.get("time", ""), r.get("stack", ""),
                (r.get("layers", "") or "")[:140],
                r.get("src", ""), r.get("dst", ""),
                r.get("opc", ""), r.get("dpc", ""), r.get("sls", ""),
                (r.get("calling_gt", "") or "")[:150],
                (r.get("called_gt", "") or "")[:150],
                r.get("calling_ssn", ""), r.get("called_ssn", ""),
                (r.get("tcap_ids", "") or "")[:150],
                (r.get("map_operation", "") or "")[:170],
                r.get("isup_cic", ""),
                (r.get("call_from", "") or "")[:140],
                (r.get("call_to", "") or "")[:140],
                r.get("imsi", ""), r.get("imei", ""), r.get("msisdn", ""),
                (r.get("mcc_mnc", "") or "")[:170],
                (r.get("location", "") or "")[:200],
                (r.get("sms_text", "") or "")[:220],
                (r.get("ussd", "") or "")[:160],
                (r.get("result_cause", "") or "")[:160],
                (r.get("info", "") or "")[:240]),
                tags=(tag,) if tag else ())

        proto_counts = Counter()
        for r in records:
            text = f"{r.get('stack', '')} {r.get('layers', '')}".lower()
            for key in ("mtp3", "m3ua", "sccp", "tcap", "gsm_map", "isup", "bssap", "gsm_a", "gsm_sms"):
                if key in text:
                    proto_counts[key] += 1
        self.ss7_sig_summary.config(
            text=(f"SS7 packets: {len(records)}   "
                  f"MAP: {proto_counts.get('gsm_map', 0)}   "
                  f"TCAP: {proto_counts.get('tcap', 0)}   "
                  f"SCCP: {proto_counts.get('sccp', 0)}   "
                  f"ISUP: {proto_counts.get('isup', 0)}"))

        self.ss7_sig_detail.delete("1.0", tk.END)
        if records:
            identity_count = sum(1 for r in records if r.get("imsi") or r.get("imei") or r.get("msisdn"))
            sms_count = sum(1 for r in records if r.get("sms_text"))
            location_count = sum(1 for r in records if r.get("location"))
            lines = [
                "SS7 / SIGTRAN summary",
                "=" * 40,
                f"Decoded rows: {len(records)}",
                f"Identity rows: {identity_count}",
                f"SMS rows: {sms_count}",
                f"Location rows: {location_count}",
                "",
                "Protocols:",
            ]
            for proto, count in proto_counts.most_common():
                lines.append(f"  {proto:<10} {count}")
            self.ss7_sig_detail.insert("1.0", "\n".join(lines))
        else:
            self.ss7_sig_detail.insert("1.0",
                "No decoded SS7/SIGTRAN packets found.\n\n"
                "This tab uses TShark dissectors for MTP3, M3UA, SCCP, TCAP, "
                "GSM MAP, ISUP, BSSAP/GSM A, and GSM SMS. If the capture carries "
                "SS7 over a proprietary transport or encrypted tunnel, Wireshark/TShark "
                "must be able to decode that stack first.")

    def _update_ss7_ui(self):
        """Populate subscriber identifier, SMS, and mobile-core leak records."""
        self.ss7_tree.delete(*self.ss7_tree.get_children())
        records = self.analysis_results.get("ss7_gsm_map", [])
        leak_count = 0
        for i, r in enumerate(records[:5000]):
            leaks = r.get("leaks", "")
            if leaks:
                leak_count += 1
            tag = "critical" if ("SMS-TEXT" in leaks or "IMSI" in leaks or "IMEI" in leaks) else ("warning" if leaks else "")
            self.ss7_tree.insert("", tk.END, iid=str(i), values=(
                r.get("frame", ""), r.get("time", ""), r.get("stack", ""),
                (r.get("operation", "") or "")[:120], leaks,
                (r.get("rrc_message", "") or "")[:140],
                (r.get("rrc_domain", "") or "")[:80],
                (r.get("nas_message", "") or "")[:170],
                (r.get("mobile_identity", "") or "")[:170],
                (r.get("lai", "") or "")[:200],
                (r.get("classmark", "") or "")[:210],
                (r.get("rrc_context", "") or "")[:200],
                (r.get("radio_context", "") or "")[:220],
                r.get("imsi", ""), r.get("imei", ""), r.get("msisdn", ""),
                r.get("mcc_mnc", ""), (r.get("area_code", "") or "")[:140],
                (r.get("bts_cell", "") or "")[:160],
                (r.get("sms_text", "") or "")[:160],
                r.get("sms_from", ""), r.get("sms_to", ""),
                r.get("apn", ""),
                r.get("src", ""), r.get("dst", "")),
                tags=(tag,) if tag else ())
        self.ss7_summary.config(
            text=f"Subscriber leak records: {len(records)}   Leaks: {leak_count}")

        self.ss7_detail.delete("1.0", tk.END)
        if records:
            from collections import Counter
            leak_counter = Counter()
            for r in records:
                for leak in (r.get("leaks", "") or "").split(","):
                    leak = leak.strip()
                    if leak:
                        leak_counter[leak] += 1
            lines = ["Subscriber leak summary", "=" * 40,
                     f"Records: {len(records)}", f"Leak records: {leak_count}", ""]
            if leak_counter:
                lines.append("Leak indicators:")
                for leak, count in leak_counter.most_common(10):
                    lines.append(f"  {leak:<16} {count}")
            self.ss7_detail.insert("1.0", "\n".join(lines))
        else:
            self.ss7_detail.insert("1.0",
                "No subscriber, SMS, BTS/cell, or mobile-core leak records found.\n\n"
                "This tab uses TShark dissector fields for GSM MAP/SMS, SS7/SIGTRAN, "
                "GSM A/BSSAP, GTP/GTPv2, Diameter, and RADIUS where those decoded "
                "fields are available in the capture.")

    def _update_satellite_ui(self):
        """Populate the Satellite custom-block telemetry tab (dynamic columns)."""
        records = self.analysis_results.get("satellite", [])
        # Build union of columns preserving first-seen order, base cols first.
        cols = list(self._sat_base_cols)
        for r in records:
            for k in r.keys():
                if k not in cols:
                    cols.append(k)
        self.sat_tree.delete(*self.sat_tree.get_children())
        self.sat_tree["columns"] = cols
        width_map = {
            "frame_no": 80,
            "epoch_time": 150,
            "id": 120,
            "type": 120,
            "source": 190,
            "destination": 190,
            "frequency-band": 120,
            "capture_source_file": 190,
            "extraction_source": 190,
            "pen": 80,
            "satellite-name": 180,
            "satellite-sub-network-name": 230,
            "interface": 130,
        }
        numeric_cols = {c for c in cols if c.lower() in {
            "frame_no", "epoch_time", "pen", "count", "size", "length",
            "bytes", "packets", "duration"
        }}
        self._setup_tree_columns(
            self.sat_tree, cols,
            widths=[width_map.get(c, 150) for c in cols],
            numeric_cols=numeric_cols)
        for i, r in enumerate(records[:5000]):
            self.sat_tree.insert("", tk.END, iid=str(i),
                                 values=[r.get(c, "") for c in cols])
        self.sat_summary.config(text=f"Custom-block telemetry records: {len(records)}")

        # Summary panel
        self.sat_detail.delete("1.0", tk.END)
        if records:
            from collections import Counter
            lines = [f"Satellite / Custom-Block telemetry", "=" * 40,
                     f"Total records: {len(records)}", ""]
            for key in ("type", "satellite-name",
                        "satellite-sub-network-name", "interface"):
                vals = Counter(str(r[key]) for r in records if key in r)
                if vals:
                    lines.append(f"By '{key}':")
                    for v, n in vals.most_common(15):
                        lines.append(f"   {v:<40} {n}")
                    lines.append("")
            ids = {r["id"] for r in records if "id" in r}
            if ids:
                lines.append(f"Distinct ids: {len(ids)}")
            times = [r["epoch_time"] for r in records if r.get("epoch_time")]
            if times:
                lines.append(f"Time span: {min(times)} -> {max(times)}")
            self.sat_detail.insert("1.0", "\n".join(lines))
        else:
            self.sat_detail.insert("1.0",
                "No PCAPNG Custom-Block JSON telemetry found in this capture.\n\n"
                "This tab targets satellite/iDirect captures where each frame is a "
                "Custom Block carrying an embedded JSON record. Normal IP/TCP/TLS "
                "captures will show nothing here.")

    def on_http_select(self, event):
        """Show full request/response content for the selected HTTP transaction."""
        sel = self.http_tree.selection()
        if not sel:
            return
        try:
            t = self.analysis_results.get("http", [])[int(sel[0])]
        except (ValueError, IndexError):
            return
        self.http_detail.delete("1.0", tk.END)
        lines = [
            f"Frame:        {t.get('frame','')}",
            f"Time:         {t.get('time','')}",
            f"{t.get('src','')}  ->  {t.get('dst','')}",
            "-" * 60,
        ]
        if t.get("method"):
            lines.append(f"{t.get('method')} {t.get('uri','')}")
            if t.get("host"):
                lines.append(f"Host: {t.get('host')}")
        if t.get("code"):
            lines.append(f"Response: {t.get('code')}")
        if t.get("content_type"):
            lines.append(f"Content-Type: {t.get('content_type')}")
        if t.get("length"):
            lines.append(f"Content-Length: {t.get('length')}")
        if t.get("user_agent"):
            lines.append(f"User-Agent: {t.get('user_agent')}")
        if t.get("referer"):
            lines.append(f"Referer: {t.get('referer')}")
        if t.get("authorization"):
            lines.append(f"Authorization: {t.get('authorization')}")
        if t.get("cookie"):
            lines.append(f"Cookie: {t.get('cookie')}")
        if t.get("set_cookie"):
            lines.append(f"Set-Cookie: {t.get('set_cookie')}")
        if t.get("leaks"):
            lines.append(f"\n[!] Leak indicators: {', '.join(t.get('leaks'))}")
        body = t.get("body", "")
        if body:
            lines += ["", "----- CONTENT / BODY -----", body[:20000]]
        self.http_detail.insert("1.0", "\n".join(lines))

    def on_stun_select(self, event):
        """Show full STUN transaction details for the selected transaction."""
        sel = self.stun_tree.selection()
        if not sel:
            return
        try:
            tx = self.analysis_results.get("stun_transactions", [])[int(sel[0])]
        except (ValueError, IndexError):
            return

        self.stun_detail.delete("1.0", tk.END)
        lines = [
            f"VID / Transaction ID: {tx.get('transaction_id','')}",
            f"Application:    {tx.get('application','')}",
            f"Frames:         {tx.get('frames','')}",
            f"Packets:        {tx.get('packets',0)}",
            f"Method/Class:   {tx.get('methods','')}",
            f"Source:         {tx.get('src','')}",
            f"Destination:    {tx.get('dst','')}",
            f"Mapped Address: {tx.get('mapped_address','')}",
            f"Username:       {tx.get('username','')}",
            f"Realm:          {tx.get('realm','')}",
            f"Software:       {tx.get('software','')}",
            f"RTT (ms):       {tx.get('rtt_ms','')}",
            "",
            "Packets",
            "-" * 70,
        ]
        for pkt in tx.get("packets_detail", []):
            lines.extend([
                f"Frame {pkt.get('frame','')}  time={pkt.get('time','')}",
                f"  {pkt.get('src','')}:{pkt.get('src_port','')} -> {pkt.get('dst','')}:{pkt.get('dst_port','')}",
                f"  {pkt.get('method','')}/{pkt.get('class','')}  len={pkt.get('length','')}  type={pkt.get('message_type','')}",
                f"  response_to={pkt.get('response_to','')} response_in={pkt.get('response_in','')} rtt={pkt.get('rtt','')}",
                f"  mapped={pkt.get('mapped_address','')} username={pkt.get('username','')}",
                f"  software={pkt.get('software','')} realm={pkt.get('realm','')}",
                f"  info={pkt.get('info','')}",
                "",
            ])
        self.stun_detail.insert("1.0", "\n".join(lines))

    def on_radius_select(self, event):
        """Show full RADIUS packet details."""
        sel = self.radius_tree.selection()
        if not sel:
            return
        try:
            r = self.analysis_results.get("radius_packets", [])[int(sel[0])]
        except (ValueError, IndexError):
            return
        self.radius_detail.delete("1.0", tk.END)
        self.radius_detail.insert("1.0", json.dumps(r, indent=2, default=str))

    def on_radius_correlation_select(self, event):
        """Show full RADIUS/GTPv2 correlation details."""
        sel = self.radius_corr_tree.selection()
        if not sel:
            return
        try:
            r = self.analysis_results.get("radius_correlations", [])[int(sel[0])]
        except (ValueError, IndexError):
            return
        self.radius_detail.delete("1.0", tk.END)
        self.radius_detail.insert("1.0", json.dumps(r, indent=2, default=str))

    def on_ss7_signaling_select(self, event):
        """Show full SS7/SIGTRAN packet details."""
        sel = self.ss7_sig_tree.selection()
        if not sel:
            return
        try:
            r = self.analysis_results.get("ss7_signaling", [])[int(sel[0])]
        except (ValueError, IndexError):
            return
        self.ss7_sig_detail.delete("1.0", tk.END)
        self.ss7_sig_detail.insert("1.0", self._format_ss7_signaling_detail(r))

    def _format_ss7_signaling_detail(self, r):
        """Readable detail view for decoded SS7 rows without noisy raw dumps."""
        sections = [
            ("Packet", [
                ("Frame", "frame"), ("Time", "time"), ("Stack", "stack"),
                ("Info", "info"), ("Layers", "layers"),
            ]),
            ("Network / SS7 Routing", [
                ("Source", "src"), ("Destination", "dst"),
                ("SCTP Source Port", "sctp_srcport"), ("SCTP Destination Port", "sctp_dstport"),
                ("OPC", "opc"), ("DPC", "dpc"), ("SLS", "sls"),
            ]),
            ("SCCP / TCAP", [
                ("Calling GT", "calling_gt"), ("Called GT", "called_gt"),
                ("Calling SSN", "calling_ssn"), ("Called SSN", "called_ssn"),
                ("SCCP Message", "sccp_message_type"), ("TCAP IDs", "tcap_ids"),
                ("TCAP Dialog", "tcap_dialog"), ("MAP Operation", "map_operation"),
                ("Result / Cause", "result_cause"),
            ]),
            ("Subscriber / Location", [
                ("IMSI", "imsi"), ("IMEI / IMEISV", "imei"),
                ("MSISDN", "msisdn"), ("MCC / MNC", "mcc_mnc"),
                ("Location", "location"), ("APN", "apn"),
            ]),
            ("SMS / USSD", [
                ("SMS Text", "sms_text"), ("SMS Text Source", "sms_text_source"),
                ("SMS From", "sms_from"), ("SMS To", "sms_to"),
                ("SMS Type", "sms_type"), ("SMS DCS", "sms_dcs"),
                ("USSD", "ussd"),
            ]),
            ("ISUP / Call", [
                ("ISUP CIC", "isup_cic"), ("ISUP Message", "isup_message_type"),
                ("Call From", "call_from"), ("Call To", "call_to"),
            ]),
        ]
        lines = []
        for title, items in sections:
            body = []
            for label, key in items:
                value = r.get(key, "")
                if value:
                    body.append(f"{label:<22}: {value}")
            if body:
                if lines:
                    lines.append("")
                lines.append(title)
                lines.append("-" * len(title))
                lines.extend(body)

        raw_tpdu = r.get("sms_raw_tpdu", "")
        if raw_tpdu and not r.get("sms_text"):
            if lines:
                lines.append("")
            lines.extend([
                "SMS Raw TPDU",
                "------------",
                raw_tpdu[:1200] + ("..." if len(raw_tpdu) > 1200 else ""),
                "",
                "Note: TShark did not expose gsm_sms.sms_text for this packet. "
                "The raw RP-UI/TPDU is kept separately and is not treated as decoded text.",
            ])
        return "\n".join(lines) if lines else json.dumps({k: v for k, v in r.items() if k != "raw_fields"}, indent=2, default=str)

    def on_ss7_select(self, event):
        """Show full subscriber leak record details."""
        sel = self.ss7_tree.selection()
        if not sel:
            return
        try:
            r = self.analysis_results.get("ss7_gsm_map", [])[int(sel[0])]
        except (ValueError, IndexError):
            return
        self.ss7_detail.delete("1.0", tk.END)
        self.ss7_detail.insert("1.0", json.dumps(r, indent=2, default=str))

    def on_cctv_select(self, event):
        """Show full CCTV / decoded-video record details."""
        sel = self.cctv_tree.selection()
        if not sel:
            return
        try:
            r = self.analysis_results.get("cctv", [])[int(sel[0])]
        except (ValueError, IndexError):
            return
        self.cctv_detail.delete("1.0", tk.END)
        self.cctv_detail.insert("1.0", json.dumps(r, indent=2, default=str))

    def open_cctv_video(self):
        """Open the selected decoded CCTV video or raw H.264 stream."""
        sel = self.cctv_tree.selection()
        if not sel:
            messagebox.showinfo("No Selection", "Select a decoded CCTV video row first.")
            return
        try:
            r = self.analysis_results.get("cctv", [])[int(sel[0])]
        except (ValueError, IndexError):
            return
        path = r.get("video_file") or r.get("h264_file")
        if not path:
            messagebox.showinfo(
                "No Video File",
                "This row has CCTV metadata only. No decodable video payload was saved.")
            return
        if not os.path.exists(path):
            messagebox.showerror(
                "Video Missing",
                f"The decoded video file is no longer available:\n{path}\n\n"
                "Re-run analysis to recreate temporary decoded files.")
            return
        try:
            if path.lower().endswith(".h264"):
                mp4_path, convert_error = self._convert_h264_to_mp4(path)
                if mp4_path:
                    r["video_file"] = mp4_path
                    path = mp4_path
                else:
                    vlc = self._find_named_executable(["vlc", "vlc.exe"])
                    if vlc:
                        subprocess.Popen([vlc, path])
                        return
                    messagebox.showwarning(
                        "Raw H.264 Stream",
                        "The decoded output is a raw .h264 stream, not an MP4 container.\n\n"
                        "Windows Media Player usually cannot play raw .h264 files. "
                        "Install ffmpeg so the dashboard can convert it to MP4, or open "
                        "the raw file with VLC.\n\n"
                        f"Raw file:\n{path}\n\n"
                        f"Conversion note:\n{convert_error or r.get('notes', '')}")
                    return
            if os.name == "nt":
                os.startfile(path)
            else:
                viewer = shutil.which("xdg-open") or shutil.which("open")
                if viewer:
                    subprocess.Popen([viewer, path])
                else:
                    messagebox.showinfo("Video File", f"Decoded file:\n{path}")
        except Exception as e:
            messagebox.showerror("Open Failed", str(e))

    def on_satellite_select(self, event):
        """Show the full flattened JSON record for the selected satellite row."""
        sel = self.sat_tree.selection()
        if not sel:
            return
        try:
            r = self.analysis_results.get("satellite", [])[int(sel[0])]
        except (ValueError, IndexError):
            return
        self.sat_detail.delete("1.0", tk.END)
        self.sat_detail.insert("1.0", json.dumps(r, indent=2, default=str))

    def export_http(self):
        """Export HTTP transactions to CSV."""
        txns = self.analysis_results.get("http", [])
        if not txns:
            messagebox.showinfo("No HTTP Data", "No HTTP transactions to export.")
            return
        path = filedialog.asksaveasfilename(
            title="Export HTTP Transactions", defaultextension=".csv",
            filetypes=[("CSV", "*.csv"), ("JSON", "*.json")])
        if not path:
            return
        cols = ["frame", "time", "src", "dst", "method", "host", "uri", "code",
                "content_type", "length", "leak", "authorization", "cookie",
                "set_cookie", "user_agent", "referer"]
        try:
            if path.lower().endswith(".json"):
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(txns, f, indent=2, default=str)
            else:
                with open(path, "w", newline="", encoding="utf-8") as f:
                    w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
                    w.writeheader()
                    w.writerows(txns)
            messagebox.showinfo("Exported", f"HTTP data exported to:\n{path}")
        except Exception as e:
            messagebox.showerror("Export Failed", str(e))

    def export_stun(self):
        """Export STUN transactions to CSV or JSON."""
        txns = self.analysis_results.get("stun_transactions", [])
        if not txns:
            messagebox.showinfo("No STUN Data", "No STUN/TURN transactions to export.")
            return
        path = filedialog.asksaveasfilename(
            title="Export STUN Transactions", defaultextension=".csv",
            filetypes=[("CSV", "*.csv"), ("JSON", "*.json")])
        if not path:
            return
        try:
            if path.lower().endswith(".json"):
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(txns, f, indent=2, default=str)
            else:
                cols = ["transaction_id", "application", "frames", "packets",
                        "methods", "src", "dst", "mapped_address", "username",
                        "realm", "software", "rtt_ms"]
                rows = [{k: tx.get(k, "") for k in cols} for tx in txns]
                with open(path, "w", newline="", encoding="utf-8") as f:
                    w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
                    w.writeheader()
                    w.writerows(rows)
            messagebox.showinfo("Exported", f"STUN data exported to:\n{path}")
        except Exception as e:
            messagebox.showerror("Export Failed", str(e))

    def export_radius(self):
        """Export RADIUS packets and CSID/ECI correlations to CSV or JSON."""
        packets = self.analysis_results.get("radius_packets", [])
        correlations = self.analysis_results.get("radius_correlations", [])
        if not packets and not correlations:
            messagebox.showinfo("No RADIUS Data", "No RADIUS packets or correlations to export.")
            return
        path = filedialog.asksaveasfilename(
            title="Export RADIUS Data", defaultextension=".csv",
            filetypes=[("CSV", "*.csv"), ("JSON", "*.json")])
        if not path:
            return
        try:
            if path.lower().endswith(".json"):
                with open(path, "w", encoding="utf-8") as f:
                    json.dump({
                        "radius_packets": packets,
                        "radius_correlations": correlations,
                    }, f, indent=2, default=str)
            else:
                base, ext = os.path.splitext(path)
                pkt_path = path
                corr_path = f"{base}_csid_eci{ext or '.csv'}"
                packet_cols = [
                    "frame", "time", "src_mac", "dst_mac", "src", "dst",
                    "src_port", "dst_port", "code", "code_name", "status",
                    "radius_id", "username", "imsi", "imei", "mcc_mnc",
                    "calling_station_id", "called_station_id",
                    "nas_ip", "nas_port", "nas_port_id", "nas_port_type",
                    "framed_ip", "acct_session_id", "acct_multi_session_id",
                    "acct_status_type", "acct_session_time", "acct_input_octets",
                    "acct_output_octets", "acct_input_packets", "acct_output_packets",
                    "location_information", "location_data", "msisdn", "apn",
                    "connection_type",
                ]
                corr_cols = [
                    "calling_station_id", "eci", "method", "radius_frame",
                    "gtp_frame", "delta_seconds", "username", "imsi", "imei",
                    "mcc_mnc", "msisdn", "radius_ip", "gtp_ip",
                ]
                with open(pkt_path, "w", newline="", encoding="utf-8") as f:
                    w = csv.DictWriter(f, fieldnames=packet_cols, extrasaction="ignore")
                    w.writeheader()
                    w.writerows(packets)
                with open(corr_path, "w", newline="", encoding="utf-8") as f:
                    w = csv.DictWriter(f, fieldnames=corr_cols, extrasaction="ignore")
                    w.writeheader()
                    w.writerows(correlations)
            messagebox.showinfo("Exported", f"RADIUS data exported to:\n{path}")
        except Exception as e:
            messagebox.showerror("Export Failed", str(e))

    def export_ss7_signaling(self):
        """Export decoded SS7/SIGTRAN records to CSV or JSON."""
        records = self.analysis_results.get("ss7_signaling", [])
        if not records:
            messagebox.showinfo("No SS7 Data", "No decoded SS7/SIGTRAN records to export.")
            return
        path = filedialog.asksaveasfilename(
            title="Export SS7 Signaling", defaultextension=".csv",
            filetypes=[("CSV", "*.csv"), ("JSON", "*.json")])
        if not path:
            return
        try:
            if path.lower().endswith(".json"):
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(records, f, indent=2, default=str)
            else:
                flat_records = []
                cols = []
                for r in records:
                    flat = {k: v for k, v in r.items() if k != "raw_fields"}
                    raw = r.get("raw_fields") or {}
                    for k, v in raw.items():
                        flat[f"raw.{k}"] = v
                    for k in flat.keys():
                        if k not in cols:
                            cols.append(k)
                    flat_records.append(flat)
                with open(path, "w", newline="", encoding="utf-8") as f:
                    w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
                    w.writeheader()
                    w.writerows(flat_records)
            messagebox.showinfo("Exported", f"SS7 signaling data exported to:\n{path}")
        except Exception as e:
            messagebox.showerror("Export Failed", str(e))

    def export_ss7(self):
        """Export subscriber leak records to CSV or JSON."""
        records = self.analysis_results.get("ss7_gsm_map", [])
        if not records:
            messagebox.showinfo("No Subscriber Leak Data", "No subscriber leak records to export.")
            return
        path = filedialog.asksaveasfilename(
            title="Export Subscriber Leaks", defaultextension=".csv",
            filetypes=[("CSV", "*.csv"), ("JSON", "*.json")])
        if not path:
            return
        try:
            if path.lower().endswith(".json"):
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(records, f, indent=2, default=str)
            else:
                cols = []
                for r in records:
                    for k in r.keys():
                        if k not in cols:
                            cols.append(k)
                with open(path, "w", newline="", encoding="utf-8") as f:
                    w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
                    w.writeheader()
                    w.writerows(records)
            messagebox.showinfo("Exported", f"Subscriber leak data exported to:\n{path}")
        except Exception as e:
            messagebox.showerror("Export Failed", str(e))

    def export_cctv(self):
        """Export CCTV / camera-video records to CSV or JSON."""
        records = self.analysis_results.get("cctv", [])
        if not records:
            messagebox.showinfo("No CCTV Data", "No CCTV or decoded-video records to export.")
            return
        path = filedialog.asksaveasfilename(
            title="Export CCTV Data", defaultextension=".csv",
            filetypes=[("CSV", "*.csv"), ("JSON", "*.json")])
        if not path:
            return
        try:
            if path.lower().endswith(".json"):
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(records, f, indent=2, default=str)
            else:
                cols = ["kind", "frames", "time", "src", "dst", "protocol",
                        "codec", "payload_type", "ssrc", "packets", "decoded",
                        "video_file", "h264_file", "notes"]
                rows = [{k: r.get(k, "") for k in cols} for r in records]
                with open(path, "w", newline="", encoding="utf-8") as f:
                    w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
                    w.writeheader()
                    w.writerows(rows)
            messagebox.showinfo("Exported", f"CCTV data exported to:\n{path}")
        except Exception as e:
            messagebox.showerror("Export Failed", str(e))

    def export_satellite(self):
        """Export satellite custom-block telemetry to CSV or JSON."""
        records = self.analysis_results.get("satellite", [])
        if not records:
            messagebox.showinfo("No Telemetry", "No custom-block telemetry to export.")
            return
        path = filedialog.asksaveasfilename(
            title="Export Satellite Telemetry", defaultextension=".csv",
            filetypes=[("CSV", "*.csv"), ("JSON", "*.json")])
        if not path:
            return
        try:
            if path.lower().endswith(".json"):
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(records, f, indent=2, default=str)
            else:
                cols = []
                for r in records:
                    for k in r.keys():
                        if k not in cols:
                            cols.append(k)
                with open(path, "w", newline="", encoding="utf-8") as f:
                    w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
                    w.writeheader()
                    w.writerows(records)
            messagebox.showinfo("Exported", f"Telemetry exported to:\n{path}")
        except Exception as e:
            messagebox.showerror("Export Failed", str(e))

    def export_sip(self):
        """Export SIP signalling messages to CSV or JSON."""
        sip_msgs = self.analysis_results.get("sip", [])
        if not sip_msgs:
            messagebox.showinfo("No SIP Data", "No SIP messages to export.")
            return
        path = filedialog.asksaveasfilename(
            title="Export SIP Signalling", defaultextension=".csv",
            filetypes=[("CSV", "*.csv"), ("JSON", "*.json")])
        if not path:
            return
        cols = ["frame", "time", "src", "dst", "method", "from", "to", "callid"]
        try:
            if path.lower().endswith(".json"):
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(sip_msgs, f, indent=2, default=str)
            else:
                with open(path, "w", newline="", encoding="utf-8") as f:
                    w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
                    w.writeheader()
                    w.writerows(sip_msgs)
            messagebox.showinfo("Exported", f"SIP signalling exported to:\n{path}")
        except Exception as e:
            messagebox.showerror("Export Failed", str(e))

    def _get_selected_rtp_stream(self):
        """Get the selected RTP stream info from the tree."""
        sel = self.rtp_tree.selection()
        if not sel:
            messagebox.showinfo("No Selection", "Please select an RTP stream first.")
            return None
        try:
            iid = sel[0]
            idx = int(str(iid).split("-", 1)[1]) if str(iid).startswith("rtp-") else self.rtp_tree.index(iid)
            rtp_list = self.analysis_results.get("rtp", [])
            if 0 <= idx < len(rtp_list):
                return rtp_list[idx]
        except (ValueError, IndexError):
            pass
        messagebox.showerror("Error", "Could not retrieve selected RTP stream.")
        return None

    def _extract_rtp_to_raw(self, ssrc, src, dst, codec=""):
        """
        Extract raw RTP payload bytes for a specific stream using tshark.
        Returns path to a temporary raw audio file, or None on failure.
        """
        import tempfile
        pcap_path = self.pcap_file.get()
        if not pcap_path:
            return None

        # Parse src/dst to get IP:port
        src_ip, src_port = src.rsplit(":", 1) if ":" in src else (src, "")
        dst_ip, dst_port = dst.rsplit(":", 1) if ":" in dst else (dst, "")

        # Build display filter for this specific RTP stream
        # Handle IPv6 addresses (contain colons)
        if ":" in src_ip and not src_ip.startswith("["):
            # IPv6
            filter_parts = [f"rtp.ssrc == {ssrc}"]
            if src_ip:
                filter_parts.append(f"ipv6.src == {src_ip}")
            if dst_ip:
                filter_parts.append(f"ipv6.dst == {dst_ip}")
        else:
            filter_parts = [f"rtp.ssrc == {ssrc}"]
            if src_ip:
                filter_parts.append(f"ip.src == {src_ip}")
            if dst_ip:
                filter_parts.append(f"ip.dst == {dst_ip}")
        if src_port:
            filter_parts.append(f"udp.srcport == {src_port}")
        if dst_port:
            filter_parts.append(f"udp.dstport == {dst_port}")
        display_filter = " && ".join(filter_parts)

        # Extract RTP payload with ordering/timing fields.
        tshark = self.tshark_path.get()
        cmd = [tshark, "-r", pcap_path, "-Y", display_filter,
               "-T", "fields",
               "-e", "rtp.seq", "-e", "rtp.timestamp",
               "-e", "frame.time_epoch", "-e", "rtp.payload",
               "-E", "separator=\t", "-E", "occurrence=f"]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True,
                                    encoding="utf-8", errors="replace", timeout=120)
            payload_rows = []
            for line in result.stdout.split("\n"):
                if not line.strip():
                    continue
                seq, rtp_ts, frame_ts, payload = (line.split("\t") + [""] * 4)[:4]
                if not payload.strip():
                    continue
                try:
                    seq_value = int(seq)
                except ValueError:
                    seq_value = len(payload_rows)
                try:
                    rtp_ts_value = int(rtp_ts)
                except ValueError:
                    rtp_ts_value = None
                try:
                    frame_ts_value = float(frame_ts)
                except ValueError:
                    frame_ts_value = None
                payload_rows.append({
                    "seq": seq_value,
                    "rtp_ts": rtp_ts_value,
                    "frame_ts": frame_ts_value,
                    "payload": payload.strip(),
                })
            if not payload_rows:
                return None
            payload_rows.sort(key=lambda item: (
                item["rtp_ts"] if item["rtp_ts"] is not None else 0,
                item["seq"]))

            # Convert hex payloads to raw bytes
            raw_data = b""
            seen = set()
            prev_rtp_ts = None
            prev_frame_ts = None
            prev_payload_len = 0
            sample_rate = self._rtp_audio_sample_rate(codec)
            silence_byte = self._rtp_silence_byte(codec)
            for item in payload_rows:
                seq_value = item["seq"]
                if seq_value in seen:
                    continue
                seen.add(seq_value)
                hex_payload = item["payload"]
                hex_clean = hex_payload.replace(":", "")
                try:
                    payload_bytes = bytes.fromhex(hex_clean)
                except ValueError:
                    continue
                if raw_data and silence_byte is not None and sample_rate:
                    gap_samples = 0
                    if item["rtp_ts"] is not None and prev_rtp_ts is not None:
                        expected_ts = prev_rtp_ts + prev_payload_len
                        gap_samples = max(0, item["rtp_ts"] - expected_ts)
                    elif item["frame_ts"] is not None and prev_frame_ts is not None:
                        expected_gap = prev_payload_len / sample_rate
                        gap_seconds = max(0.0, (item["frame_ts"] - prev_frame_ts) - expected_gap)
                        gap_samples = int(gap_seconds * sample_rate)
                    if gap_samples:
                        raw_data += bytes([silence_byte]) * min(gap_samples, sample_rate * 300)
                raw_data += payload_bytes
                prev_rtp_ts = item["rtp_ts"]
                prev_frame_ts = item["frame_ts"]
                prev_payload_len = len(payload_bytes)

            if not raw_data:
                return None

            # Write to temp file
            fd, raw_path = tempfile.mkstemp(suffix=".raw")
            with os.fdopen(fd, "wb") as f:
                f.write(raw_data)
            return raw_path
        except Exception:
            return None

    def _rtp_audio_sample_rate(self, codec):
        """Return RTP audio clock/sample rate for codecs we export as raw bytes."""
        codec_lower = str(codec or "").lower()
        if "g722" in codec_lower:
            return 8000
        if any(token in codec_lower for token in ("pcmu", "pcma", "g.711", "g711")):
            return 8000
        return 0

    def _rtp_silence_byte(self, codec):
        """Return codec silence byte for sparse G.711 RTP streams."""
        codec_lower = str(codec or "").lower()
        if "pcma" in codec_lower or "a-law" in codec_lower or "alaw" in codec_lower:
            return 0xD5
        if "pcmu" in codec_lower or "u-law" in codec_lower or "mulaw" in codec_lower:
            return 0xFF
        return None

    def _rtp_audio_support(self, stream):
        """Return whether this stream can be exported as playable audio."""
        codec = str(stream.get("payload", "") or "")
        media_security = str(stream.get("media_security", "") or "")
        codec_lower = codec.lower()
        if media_security == "SRTP":
            return False, "This stream is SRTP encrypted. Audio/video needs SRTP keys before it can be decoded."
        if "telephone-event" in codec_lower:
            return False, "This is DTMF telephone-event signaling, not voice audio."
        if any(token in codec_lower for token in ("h264", "h265", "hevc", "jpeg", "video")):
            return False, "This RTP stream is video, not voice audio. Use the CCTV/video workflow."
        if "dynamic" in codec_lower or codec.strip().isdigit():
            return False, "The RTP payload type is not mapped to an audio codec by SIP/SDP."
        if any(token in codec_lower for token in ("pcmu", "pcma", "g.711", "g711", "g722")):
            return True, ""
        return False, f"Audio export is not supported for codec: {codec}"

    def _raw_to_wav(self, raw_path, codec, wav_path):
        """
        Convert raw RTP payload to WAV using ffmpeg or sox if available.
        Falls back to simple PCM wrapping for G.711 codecs.
        """
        import struct
        import shutil

        # Determine codec parameters
        codec_lower = codec.lower() if codec else ""
        if "pcmu" in codec_lower or codec == "0":
            # G.711 mu-law
            sample_rate = 8000
            audio_format = 7  # WAVE_FORMAT_MULAW
            bits_per_sample = 8
        elif "pcma" in codec_lower or codec == "8":
            # G.711 A-law
            sample_rate = 8000
            audio_format = 6  # WAVE_FORMAT_ALAW
            bits_per_sample = 8
        elif "g722" in codec_lower or codec == "9":
            sample_rate = 16000
            audio_format = None
            bits_per_sample = 8
        else:
            return False

        # Try ffmpeg first (best codec support)
        ffmpeg = shutil.which("ffmpeg")
        if ffmpeg:
            codec_map = {
                7: "mulaw", 6: "alaw", None: "g722"
            }
            acodec = codec_map.get(audio_format, "mulaw")
            cmd = [ffmpeg, "-y", "-f", acodec, "-ar", str(sample_rate),
                   "-ac", "1", "-i", raw_path, wav_path]
            try:
                subprocess.run(cmd, capture_output=True, timeout=60)
                if os.path.exists(wav_path) and os.path.getsize(wav_path) > 44:
                    return True
            except Exception:
                pass

        # Fallback: wrap raw data in WAV header (works for G.711)
        if audio_format not in (6, 7):
            return False
        try:
            with open(raw_path, "rb") as f:
                raw_data = f.read()

            num_channels = 1
            byte_rate = sample_rate * num_channels * bits_per_sample // 8
            block_align = num_channels * bits_per_sample // 8
            data_size = len(raw_data)

            with open(wav_path, "wb") as f:
                # RIFF header
                f.write(b"RIFF")
                f.write(struct.pack("<I", 36 + data_size))
                f.write(b"WAVE")
                # fmt chunk
                f.write(b"fmt ")
                f.write(struct.pack("<I", 16))  # chunk size
                f.write(struct.pack("<H", audio_format))
                f.write(struct.pack("<H", num_channels))
                f.write(struct.pack("<I", sample_rate))
                f.write(struct.pack("<I", byte_rate))
                f.write(struct.pack("<H", block_align))
                f.write(struct.pack("<H", bits_per_sample))
                # data chunk
                f.write(b"data")
                f.write(struct.pack("<I", data_size))
                f.write(raw_data)
            return True
        except Exception:
            return False

    def play_rtp_stream(self):
        """Extract and play the selected RTP stream audio."""
        import tempfile

        stream = self._get_selected_rtp_stream()
        if not stream:
            return

        ssrc = stream.get("ssrc", "")
        src = stream.get("src", "")
        dst = stream.get("dst", "")
        codec = stream.get("payload", "")
        supported, reason = self._rtp_audio_support(stream)
        if not supported:
            messagebox.showwarning("RTP Audio Not Decodable", reason)
            return

        self.rtp_status.config(text="Extracting RTP payload...")
        self.root.update()

        raw_path = self._extract_rtp_to_raw(ssrc, src, dst, codec)
        if not raw_path:
            self.rtp_status.config(text="")
            messagebox.showerror("Extraction Failed",
                "Could not extract RTP payload for this stream.\n"
                "The stream may be encrypted (SRTP) or use an unsupported codec.")
            return

        # Convert to WAV
        self.rtp_status.config(text="Converting to audio...")
        self.root.update()

        fd, wav_path = tempfile.mkstemp(suffix=".wav")
        os.close(fd)

        if not self._raw_to_wav(raw_path, codec, wav_path):
            self.rtp_status.config(text="")
            os.unlink(raw_path)
            messagebox.showerror("Conversion Failed",
                "Could not convert RTP payload to audio.\n"
                f"Codec: {codec}")
            return

        os.unlink(raw_path)

        # Play the WAV file using system default player
        self.rtp_status.config(text=f"Playing {codec} audio...")
        try:
            if os.name == "nt":
                os.startfile(wav_path)
            else:
                import shutil
                player = shutil.which("xdg-open") or shutil.which("open")
                if player:
                    subprocess.Popen([player, wav_path])
                else:
                    messagebox.showinfo("Audio Exported",
                        f"WAV file created:\n{wav_path}\n\nOpen it with your audio player.")
        except Exception as e:
            messagebox.showinfo("Audio Exported",
                f"WAV file created:\n{wav_path}\n\nOpen it with your audio player.")

        self.root.after(3000, lambda: self.rtp_status.config(text=""))

    def export_rtp_wav(self):
        """Export the selected RTP stream as a WAV file."""
        stream = self._get_selected_rtp_stream()
        if not stream:
            return

        ssrc = stream.get("ssrc", "")
        src = stream.get("src", "")
        dst = stream.get("dst", "")
        codec = stream.get("payload", "")
        supported, reason = self._rtp_audio_support(stream)
        if not supported:
            messagebox.showwarning("RTP Audio Not Decodable", reason)
            return

        # Ask for save location
        default_name = f"rtp_stream_{ssrc}.wav"
        path = filedialog.asksaveasfilename(
            title="Export RTP Stream as WAV",
            defaultextension=".wav",
            initialfile=default_name,
            filetypes=[("WAV Audio", "*.wav")])
        if not path:
            return

        self.rtp_status.config(text="Extracting RTP payload...")
        self.root.update()

        raw_path = self._extract_rtp_to_raw(ssrc, src, dst, codec)
        if not raw_path:
            self.rtp_status.config(text="")
            messagebox.showerror("Extraction Failed",
                "Could not extract RTP payload for this stream.\n"
                "The stream may be encrypted (SRTP) or use an unsupported codec.")
            return

        self.rtp_status.config(text="Converting to WAV...")
        self.root.update()

        if self._raw_to_wav(raw_path, codec, path):
            os.unlink(raw_path)
            self.rtp_status.config(text="")
            messagebox.showinfo("Exported",
                f"RTP stream exported as WAV:\n{path}\n\n"
                f"Codec: {codec}\nSSRC: {ssrc}")
        else:
            os.unlink(raw_path)
            self.rtp_status.config(text="")
            messagebox.showerror("Export Failed",
                "Could not convert RTP payload to WAV format.")

    def _generate_summary(self):
        """Generate analysis summary text"""
        stats = self.analysis_results.get("stats", {})
        protocols = self.analysis_results.get("protocols", {})
        dns = self.analysis_results.get("dns", {})
        tls = self.analysis_results.get("tls", {})
        sessions = self.analysis_results.get("sessions", [])
        satellite = self.analysis_results.get("satellite", [])
        stun_packets = self.analysis_results.get("stun_packets", [])
        stun_transactions = self.analysis_results.get("stun_transactions", [])
        radius_packets = self.analysis_results.get("radius_packets", [])
        radius_correlations = self.analysis_results.get("radius_correlations", [])
        ss7_records = self.analysis_results.get("ss7_gsm_map", [])
        cctv_records = self.analysis_results.get("cctv", [])
        session_mode = self.analysis_results.get("session_analysis_mode", "detailed")
        session_notes = self.analysis_results.get("session_quick_notes", [])
        
        summary = f"""
================================================================================
                         PCAP ANALYSIS SUMMARY
================================================================================

CAPTURE STATISTICS
--------------------------------------------------------------------------------
  Total Packets:       {stats.get('total_packets', 0):,}
  Total Bytes:         {self.format_bytes(stats.get('total_bytes', 0))}
  Capture Duration:    {stats.get('duration', 0):.2f} seconds
  Unique IP Addresses: {stats.get('unique_ips', 0):,}

SATELLITE TELEMETRY
--------------------------------------------------------------------------------
  Telemetry Records:   {len(satellite):,}
"""
        if satellite:
            from collections import Counter

            def add_satellite_values(title, key):
                nonlocal summary
                values = Counter(str(r.get(key, "")).strip()
                                 for r in satellite if str(r.get(key, "")).strip())
                summary += f"  {title}:\n"
                if values:
                    for value, count in values.most_common(10):
                        suffix = f" ({count} records)" if count > 1 else ""
                        summary += f"    - {value}{suffix}\n"
                else:
                    summary += "    - Not found\n"

            add_satellite_values("Satellite Name", "satellite-name")
            add_satellite_values("Satellite Sub-Network", "satellite-sub-network-name")
            add_satellite_values("Frequency Band", "frequency-band")
        else:
            summary += "  Satellite Name:    Not found\n"
            summary += "  Sub-Network Name:  Not found\n"
            summary += "  Frequency Band:    Not found\n"

        summary += f"""
STUN / TURN ANALYSIS
--------------------------------------------------------------------------------
  STUN Packets:       {len(stun_packets):,}
  Transactions:       {len(stun_transactions):,}
"""
        if stun_transactions:
            from collections import Counter
            app_counts = Counter(t.get("application", "Unknown STUN/ICE")
                                 for t in stun_transactions)
            summary += "  Application Identification:\n"
            for app, count in app_counts.most_common(5):
                summary += f"    - {app}: {count} transactions\n"
        else:
            summary += "  Application Identification: Not found\n"

        summary += f"""
RADIUS ANALYSIS
--------------------------------------------------------------------------------
  RADIUS Packets:     {len(radius_packets):,}
  CSID/ECI Matches:   {len(radius_correlations):,}
"""
        if radius_packets:
            from collections import Counter
            code_counts = Counter(r.get("code_name", "Unknown") for r in radius_packets)
            summary += "  RADIUS Codes:\n"
            for code, count in code_counts.most_common(6):
                summary += f"    - {code}: {count} packets\n"
        else:
            summary += "  RADIUS Codes:      Not found\n"

        summary += f"""
SUBSCRIBER / SMS / BTS LEAKS
--------------------------------------------------------------------------------
  Records:            {len(ss7_records):,}
"""
        if ss7_records:
            from collections import Counter
            leak_counter = Counter()
            for r in ss7_records:
                for leak in (r.get("leaks", "") or "").split(","):
                    leak = leak.strip()
                    if leak:
                        leak_counter[leak] += 1
            if leak_counter:
                summary += "  Leak Indicators:\n"
                for leak, count in leak_counter.most_common(8):
                    summary += f"    - {leak}: {count} records\n"
            else:
                summary += "  Leak Indicators: No IMSI/SMS/MSISDN values decoded\n"
        else:
            summary += "  Leak Indicators: Not found\n"

        cctv_rtp = sum(1 for r in cctv_records if r.get("kind") == "RTP H.264 Video")
        cctv_decoded = sum(1 for r in cctv_records
                           if r.get("kind") == "RTP H.264 Video" and r.get("video_file"))
        summary += f"""
CCTV / VIDEO ANALYSIS
--------------------------------------------------------------------------------
  CCTV Records:       {len(cctv_records):,}
  Verified H.264 RTP: {cctv_rtp:,}
  Decoded/Validated:  {cctv_decoded:,}
"""
        if cctv_records:
            from collections import Counter
            kind_counts = Counter(r.get("kind", "Unknown") for r in cctv_records)
            summary += "  Record Types:\n"
            for kind, count in kind_counts.most_common(6):
                summary += f"    - {kind}: {count} records\n"
        else:
            summary += "  Decoded/Validated:  Not found\n"

        summary += f"""
PROTOCOL DISTRIBUTION
--------------------------------------------------------------------------------
  Protocols Detected: {len(protocols)}
"""
        top_protos = sorted(protocols.items(), key=lambda x: x[1].get("bytes", 0), reverse=True)[:5]
        for proto, data in top_protos:
            summary += f"  - {proto}: {data.get('frames', 0):,} packets, {self.format_bytes(data.get('bytes', 0))}\n"
            
        summary += f"""
DNS ANALYSIS
--------------------------------------------------------------------------------
  Unique Domains Queried: {len(dns)}
"""
        top_dns = sorted(dns.items(), key=lambda x: x[1]["count"], reverse=True)[:5]
        for domain, data in top_dns:
            summary += f"  - {domain}: {data['count']} queries\n"
            
        summary += f"""
TLS CONNECTIONS
--------------------------------------------------------------------------------
  Unique TLS Servers: {len(tls)}
"""
        top_tls = sorted(tls.items(), key=lambda x: x[1]["count"], reverse=True)[:5]
        for sni, data in top_tls:
            summary += f"  - {sni}: {data['count']} connections\n"
            
        summary += f"""
SESSION ANALYSIS
--------------------------------------------------------------------------------
  Total Sessions:     {len(sessions)}
  Session Mode:       {session_mode}
"""
        if session_notes:
            summary += "  Notes:\n"
            for note in session_notes[:5]:
                summary += f"    - {note}\n"
        return summary
        
    def _finish_analysis(self):
        """Clean up after analysis"""
        self.is_analyzing = False
        self.progress['value'] = 100
        self.progress_pct.config(text="100%")
        self.analyze_btn.config(state=tk.NORMAL)
        self.update_status("Analysis complete")
        
    def detect_uploads(self):
        """Populate nested Session -> Upload Event tree. Re-runs event detection
        so the current UI settings take effect without re-parsing the PCAP."""
        if not self.analysis_completed and not self.analysis_results:
            messagebox.showwarning("No Data", "Please run analysis first by clicking the Analyze button.")
            return

        logical_sessions = self.analysis_results.get("logical_sessions", [])
        if not logical_sessions:
            transport_flows = self.analysis_results.get("transport_flows", [])
            quick_sessions = self.analysis_results.get("sessions", [])
            session_mode = self.analysis_results.get("session_analysis_mode", "")
            if transport_flows:
                messagebox.showinfo("No Logical Sessions",
                    f"Found {len(transport_flows)} transport flows but no logical sessions.")
            elif quick_sessions:
                self._populate_quick_upload_candidates(quick_sessions, session_mode)
            else:
                messagebox.showinfo("No Sessions",
                    "Analysis completed, but no TCP/UDP sessions were found for upload behavior.\n\n"
                    "This can happen with very small captures, non-IP captures, or captures where "
                    "TShark cannot decode transport flows.")
            return

        # Re-run event detection with current UI settings
        for session in logical_sessions:
            self._detect_upload_events(session)

        self.upload_tree.delete(*self.upload_tree.get_children())
        self._session_lookup = {}   # iid -> ("session"|"event", obj)

        try:
            min_payload = float(self.cfg_min_payload.get())
        except (ValueError, tk.TclError):
            min_payload = 5000

        session_count = 0
        event_total = 0
        for session in logical_sessions:
            # Only show sessions that have at least one detected upload event
            if not session.upload_events:
                continue
            session_count += 1

            streams = session.tcp_streams + session.udp_streams
            streams_str = ",".join(s.split(".")[-1] for s in streams[:6])
            if len(streams) > 6:
                streams_str += f"+{len(streams)-6}"
            duration = session.end_time - session.start_time
            dur_str = f"{duration:.1f}s" if duration < 60 else f"{duration/60:.1f}m"
            server = session.server_name or ",".join(sorted(session.server_ips))

            sess_iid = session.session_id
            self.upload_tree.insert(
                "", tk.END, iid=sess_iid, open=True,
                text=f"{session.session_id}  ({session.client_ip})",
                values=("", session.protocol,
                        server[:38] + "..." if len(server) > 38 else server,
                        streams_str, len(session.upload_events),
                        self.format_bytes(session.total_upload_bytes),
                        self.format_bytes(session.total_download_bytes),
                        dur_str, ""))
            self._session_lookup[sess_iid] = ("session", session)

            # Nested upload events
            for ev in session.upload_events:
                event_total += 1
                ev_iid = ev.event_id
                ev_dur = f"{ev.duration:.1f}s"
                ratio = "∞" if ev.upload_ratio == float('inf') else f"{ev.upload_ratio:.1f}"
                ev_streams = ",".join(s.split(".")[-1] for s in ev.flow_ids)
                self.upload_tree.insert(
                    sess_iid, tk.END, iid=ev_iid,
                    text=f"  ⤷ {ev.event_id.split('-')[-2]}-{ev.event_id.split('-')[-1]}",
                    values=("", ev.protocol, f"ratio {ratio}",
                            ev_streams, ev.num_peaks,
                            self.format_bytes(ev.upload_payload_bytes),
                            self.format_bytes(ev.download_bytes),
                            ev_dur, f"{ev.confidence:.0f}"))
                self._session_lookup[ev_iid] = ("event", ev)

        if session_count == 0:
            messagebox.showinfo("No Upload Events",
                "No upload events detected with the current settings.\n\n"
                f"Total logical sessions: {len(logical_sessions)}\n"
                f"Min payload: {self.format_bytes(int(min_payload))}\n\n"
                "Try lowering 'Min Payload', 'Min Dur', or 'Bytes/s'.")
        else:
            self.update_status(
                f"{event_total} upload events across {session_count} sessions")

    def _populate_quick_upload_candidates(self, sessions, session_mode=""):
        """Show upload candidates from quick conversation stats when detailed bursts are unavailable."""
        self.upload_tree.delete(*self.upload_tree.get_children())
        self._session_lookup = {}

        try:
            min_payload = float(self.cfg_min_payload.get())
        except (ValueError, tk.TclError):
            min_payload = 5000
        try:
            min_ratio = float(self.cfg_min_ratio.get())
        except (ValueError, tk.TclError):
            min_ratio = 1.0

        shown = 0
        for i, session in enumerate(sessions):
            upload = int(session.get("upload_bytes", 0) or 0)
            download = int(session.get("download_bytes", 0) or 0)
            ratio = upload / download if download > 0 else (float("inf") if upload else 0)
            if upload < min_payload or ratio < min_ratio:
                continue
            shown += 1
            iid = f"quick-upload-{i}"
            server = session.get("sni") or session.get("dst_ip", "")
            streams = ",".join((session.get("tcp_streams") or []) + (session.get("udp_streams") or []))
            ratio_text = "inf" if ratio == float("inf") else f"{ratio:.1f}"
            self.upload_tree.insert(
                "", tk.END, iid=iid, open=True,
                text=session.get("session_id", f"Session-{i+1}"),
                values=("", session.get("protocol", ""),
                        server[:38] + "..." if len(server) > 38 else server,
                        streams, 0,
                        self.format_bytes(upload),
                        self.format_bytes(download),
                        "", ratio_text))
            self._session_lookup[iid] = ("quick_session", session)

        self.session_details.config(state=tk.NORMAL)
        self.session_details.delete("1.0", tk.END)
        if shown:
            self.session_details.insert("1.0",
                "Quick upload candidates are shown from conversation totals.\n\n"
                "Detailed burst timing and I/O graph require detailed session mode. "
                "For small .done captures, re-run Analyze with Quick unchecked; "
                "the dashboard now allows detailed mode for non-merged .done files.")
            self.update_status(f"{shown} quick upload candidates shown")
        else:
            self.session_details.insert("1.0",
                "No upload candidates matched the current thresholds.\n\n"
                f"Sessions analyzed: {len(sessions)}\n"
                f"Session mode: {session_mode or 'unknown'}\n"
                f"Min payload: {self.format_bytes(int(min_payload))}\n"
                f"Min Up:Down ratio: {min_ratio}\n\n"
                "Try lowering Min Payload or Up:Down, or re-run analysis in detailed mode.")
            messagebox.showinfo(
                "No Upload Candidates",
                "Analysis completed, but no quick upload candidates matched the current thresholds.\n\n"
                "Try lowering Min Payload or Up:Down.")
        self.session_details.config(state=tk.DISABLED)

    def on_upload_session_select(self, event):
        """Show details + I/O graph when a session or upload event is selected."""
        selection = self.upload_tree.selection()
        if not selection:
            return
        iid = selection[0]
        lookup = getattr(self, "_session_lookup", {})
        if iid not in lookup:
            return
        kind, obj = lookup[iid]

        self.session_details.config(state=tk.NORMAL)
        self.session_details.delete("1.0", tk.END)

        if kind == "session":
            self.session_details.insert("1.0", self._format_session_details(obj))
            self._draw_io_graph(obj, highlight_event=None)
        elif kind == "quick_session":
            self.session_details.insert("1.0", self._format_quick_session_details(obj))
        else:  # event
            # find parent session for graph context
            parent_iid = self.upload_tree.parent(iid)
            parent = lookup.get(parent_iid, (None, None))[1]
            self.session_details.insert("1.0", self._format_event_details(obj))
            if parent:
                self._draw_io_graph(parent, highlight_event=obj)

        self.session_details.config(state=tk.DISABLED)

    def _format_quick_session_details(self, s: dict) -> str:
        upload = int(s.get("upload_bytes", 0) or 0)
        download = int(s.get("download_bytes", 0) or 0)
        ratio = upload / download if download > 0 else (float("inf") if upload else 0)
        ratio_text = "inf" if ratio == float("inf") else f"{ratio:.2f}"
        lines = [
            "=" * 70,
            f"QUICK SESSION: {s.get('session_id', '')}",
            "=" * 70,
            f"Protocol       : {s.get('protocol', '')}",
            f"Source         : {s.get('src_ip', '')}:{s.get('src_port', '')}",
            f"Destination    : {s.get('dst_ip', '')}:{s.get('dst_port', '')}",
            f"Server/SNI     : {s.get('sni', '') or s.get('dst_ip', '')}",
            f"Packets        : {s.get('packets', 0)}",
            "-" * 70,
            f"Upload Bytes   : {self.format_bytes(upload)}",
            f"Download Bytes : {self.format_bytes(download)}",
            f"Up:Down Ratio  : {ratio_text}",
            f"Classification : {s.get('classification', '')}",
            "-" * 70,
            "This row is from quick conversation statistics. Detailed burst timing,",
            "event confidence, and I/O graph require detailed session analysis.",
        ]
        return "\n".join(lines)

    def _format_session_details(self, s: 'LogicalSession') -> str:
        def ts(t):
            return datetime.fromtimestamp(t).strftime('%H:%M:%S.%f')[:-3] if t > 0 else 'N/A'
        lines = [
            "=" * 70,
            f"LOGICAL SESSION: {s.session_id}",
            "=" * 70,
            f"Client IP        : {s.client_ip}",
            f"Client Ports     : {', '.join(sorted(s.client_ports)[:15])}",
            f"Server IPs       : {', '.join(sorted(s.server_ips))}",
            f"Server Name/SNI  : {s.server_name or 'N/A'}",
            f"Protocol         : {s.protocol}",
            f"TCP Streams      : {', '.join(s.tcp_streams) or 'None'}",
            f"UDP Streams      : {', '.join(s.udp_streams) or 'None'}",
            f"QUIC Conn IDs    : {', '.join(sorted(s.quic_connection_ids)) or 'None'}",
            "-" * 70,
            f"Total Upload     : {self.format_bytes(s.total_upload_bytes)}",
            f"Total Download   : {self.format_bytes(s.total_download_bytes)}",
            f"Total Packets    : {s.total_packets:,}",
            f"Duration         : {s.end_time - s.start_time:.2f} s",
            f"First Upload     : {ts(s.upload_events[0].start_time) if s.upload_events else 'N/A'}",
            f"Last Upload      : {ts(s.upload_events[-1].end_time) if s.upload_events else 'N/A'}",
            "-" * 70,
            f"UPLOAD EVENTS    : {len(s.upload_events)}",
        ]
        for ev in s.upload_events:
            lines.append(
                f"  {ev.event_id}: {ts(ev.start_time)}-{ts(ev.end_time)} "
                f"({ev.duration:.1f}s) {self.format_bytes(ev.upload_payload_bytes)} "
                f"conf={ev.confidence:.0f}")
        lines.append("=" * 70)
        return "\n".join(lines)

    def _format_event_details(self, ev: 'UploadEvent') -> str:
        def ts(t):
            return datetime.fromtimestamp(t).strftime('%H:%M:%S.%f')[:-3] if t > 0 else 'N/A'
        ratio = "∞" if ev.upload_ratio == float('inf') else f"{ev.upload_ratio:.2f}"
        return "\n".join([
            "=" * 70,
            f"UPLOAD EVENT: {ev.event_id}",
            "=" * 70,
            f"Session          : {ev.session_id}",
            f"Protocol         : {ev.protocol}",
            f"Flow/Streams     : {', '.join(ev.flow_ids)}",
            f"QUIC Conn IDs    : {', '.join(sorted(ev.quic_cids)) or 'None'}",
            f"Client IP        : {ev.client_ip}",
            f"Client Ports     : {', '.join(sorted(ev.client_ports))}",
            f"Server IP        : {ev.server_ip}",
            f"Server Port      : {ev.server_port}",
            f"Server Name/SNI  : {ev.server_name or 'N/A'}",
            "-" * 70,
            f"Start Time       : {ts(ev.start_time)}",
            f"End Time         : {ts(ev.end_time)}",
            f"Duration         : {ev.duration:.2f} s",
            f"Upload Packets   : {ev.upload_packets:,}",
            f"Upload Payload   : {self.format_bytes(ev.upload_payload_bytes)}",
            f"Download (same)  : {self.format_bytes(ev.download_bytes)}",
            f"Peak Upload Rate : {self.format_bytes(int(ev.peak_upload_bps))}/s",
            f"Avg Upload Rate  : {self.format_bytes(int(ev.avg_upload_bps))}/s",
            f"Upload:Download  : {ratio}",
            f"Traffic Peaks    : {ev.num_peaks}",
            f"Confidence       : {ev.confidence:.0f}/100",
            "-" * 70,
            f"Fingerprint      : {ev.fingerprint}",
            "=" * 70,
        ])

    def _draw_io_graph(self, session: 'LogicalSession', highlight_event=None):
        """Render Wireshark-style I/O graph for a session with event markers."""
        if not HAS_MATPLOTLIB:
            return
        # Clear previous canvas
        if self.io_canvas is not None:
            self.io_canvas.get_tk_widget().destroy()
            self.io_canvas = None
        if not session.io_timeline:
            return

        t0 = session.io_timeline[0][0]
        xs = [t - t0 for (t, u, d, up, dp) in session.io_timeline]
        up_bytes = [u for (t, u, d, up, dp) in session.io_timeline]
        down_bytes = [d for (t, u, d, up, dp) in session.io_timeline]

        c = self.colors
        fig = Figure(figsize=(5, 3), dpi=90, facecolor=c['card_bg'])
        ax = fig.add_subplot(111, facecolor=c['card_bg'])
        ax.plot(xs, up_bytes, color=c['success'], linewidth=1.4, label="Client->Server (upload)")
        ax.plot(xs, down_bytes, color=c['teal'], linewidth=1.1,
                label="Server->Client (download)", alpha=0.8)
        ax.fill_between(xs, up_bytes, color=c['success'], alpha=0.22)

        # Threshold line
        try:
            bucket = float(self.cfg_bucket.get())
            bps_thr = float(self.cfg_bps_threshold.get())
            ax.axhline(bps_thr * bucket, color=c['rose'], linestyle="--",
                       linewidth=0.9, label="Upload threshold")
        except (ValueError, tk.TclError):
            pass

        # Mark all upload events; emphasize highlighted one
        for ev in session.upload_events:
            s = ev.start_time - t0
            e = ev.end_time - t0
            is_hi = (highlight_event is not None and ev.event_id == highlight_event.event_id)
            ax.axvspan(s, e, color=c['warning'] if is_hi else c['teal'],
                       alpha=0.32 if is_hi else 0.12)

        ax.set_xlabel("Time (s)", color=c['muted'], fontsize=8)
        ax.set_ylabel("Bytes / bucket", color=c['muted'], fontsize=8)
        ax.tick_params(colors=c['muted'], labelsize=7)
        ax.grid(True, color=c['border'], linewidth=0.5, alpha=0.5)
        for spine in ax.spines.values():
            spine.set_color(c['border'])
        ax.legend(fontsize=6, facecolor=c['surface2'], edgecolor=c['border'],
                  labelcolor=c['fg'], loc="upper right")
        ax.set_title(f"I/O Graph - {session.session_id}", color=c['fg'], fontsize=9)
        fig.tight_layout()

        self.io_canvas = FigureCanvasTkAgg(fig, master=self.graph_container)
        self.io_canvas.draw()
        self.io_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
                
    def run_specific_analysis(self, analysis_type):
        """Run a specific type of analysis"""
        if not self.pcap_file.get():
            messagebox.showwarning("No File Selected", "Please select a PCAP file first.")
            return
        tab_map = {"protocol": 1, "upload": 2, "dns": 3, "tls": 4, "stun": 8}
        if analysis_type in tab_map:
            self.notebook.select(tab_map[analysis_type])
        self.run_full_analysis()
        
    def filter_sessions(self):
        """Filter sessions based on user input"""
        filter_text = self.session_filter.get().lower()
        sessions = self.analysis_results.get("sessions", [])
        
        self.sessions_tree.delete(*self.sessions_tree.get_children())
        
        for i, session in enumerate(sessions[:500]):
            if filter_text:
                match = any(filter_text in str(v).lower() for v in session.values())
                if not match:
                    continue
                    
            self.sessions_tree.insert("", tk.END, values=(
                f"Session-{i+1}", session.get("src_ip", ""), session.get("src_port", ""),
                session.get("dst_ip", ""), session.get("dst_port", ""),
                session.get("protocol", ""), session.get("packets", 0),
                self.format_bytes(session.get("bytes", 0)), ""
            ))
            
    def on_protocol_select(self, event):
        """Handle protocol selection"""
        selection = self.protocol_tree.selection()
        if selection:
            item = self.protocol_tree.item(selection[0])
            protocol = item["values"][0]
            
            self.protocol_details.delete("1.0", tk.END)
            protocols = self.analysis_results.get("protocols", {})
            if protocol in protocols:
                data = protocols[protocol]
                details = f"""Protocol: {protocol}
----------------------------------------
Frames: {data.get('frames', 0):,}
Bytes: {self.format_bytes(data.get('bytes', 0))}
"""
                self.protocol_details.insert("1.0", details)

    def _protocol_export_rows(self):
        """Return all protocol-distribution rows with percentages."""
        protocols = self.analysis_results.get("protocols", {})
        total_bytes = sum(p.get("bytes", 0) for p in protocols.values())
        rows = []
        for proto, data in sorted(protocols.items(),
                                  key=lambda x: x[1].get("bytes", 0),
                                  reverse=True):
            byte_count = data.get("bytes", 0)
            pct = (byte_count / total_bytes * 100) if total_bytes > 0 else 0
            rows.append({
                "protocol": proto,
                "packets": data.get("frames", 0),
                "bytes": byte_count,
                "bytes_readable": self.format_bytes(byte_count),
                "percentage": f"{pct:.2f}",
            })
        return rows

    def export_protocols(self):
        """Export every protocol detected in the Protocols tab."""
        rows = self._protocol_export_rows()
        if not rows:
            messagebox.showinfo("No Protocol Data", "No protocol distribution to export.")
            return
        path = filedialog.asksaveasfilename(
            title="Export Protocol Distribution", defaultextension=".csv",
            filetypes=[("CSV", "*.csv"), ("JSON", "*.json")])
        if not path:
            return
        try:
            if path.lower().endswith(".json"):
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(rows, f, indent=2, default=str)
            else:
                cols = ["protocol", "packets", "bytes", "bytes_readable", "percentage"]
                with open(path, "w", newline="", encoding="utf-8") as f:
                    w = csv.DictWriter(f, fieldnames=cols)
                    w.writeheader()
                    w.writerows(rows)
            messagebox.showinfo("Exported", f"Protocol distribution exported to:\n{path}")
        except Exception as e:
            messagebox.showerror("Export Failed", str(e))
                
    def export_results(self):
        """Export analysis results as JSON or CSV (based on chosen extension)."""
        if not self.analysis_results:
            messagebox.showwarning("No Data", "No analysis results to export.")
            return

        filename = filedialog.asksaveasfilename(
            title="Export Results",
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("JSON files", "*.json"), ("All files", "*.*")]
        )
        if not filename:
            return

        try:
            if filename.lower().endswith(".csv"):
                rows = self._export_csv(filename)
                messagebox.showinfo("Export Complete",
                                    f"Exported {rows} rows to:\n{filename}")
            else:
                self._export_json(filename)
                messagebox.showinfo("Export Complete", f"Results exported to:\n{filename}")
        except Exception as e:
            messagebox.showerror("Error", f"Export failed: {str(e)}")

    def _export_json(self, filename):
        """Serialize all analysis results to JSON (sets -> lists)."""
        export_data = {}
        for key, value in self.analysis_results.items():
            if key in ("transport_flows", "logical_sessions"):
                continue  # dataclass objects; summarized in CSV instead
            if isinstance(value, dict):
                export_data[key] = {}
                for k, v in value.items():
                    if isinstance(v, dict):
                        export_data[key][k] = {
                            kk: list(vv) if isinstance(vv, set) else vv
                            for kk, vv in v.items()
                        }
                    else:
                        export_data[key][k] = list(v) if isinstance(v, set) else v
            else:
                export_data[key] = value
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(export_data, f, indent=2, default=str)

    @staticmethod
    def _fmt_time(epoch):
        """Format an epoch timestamp to a readable string (blank if 0/invalid)."""
        try:
            if not epoch:
                return ""
            return datetime.fromtimestamp(float(epoch)).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        except (ValueError, OSError, OverflowError):
            return ""

    def _export_csv(self, filename):
        """
        Export protocol distribution, sessions, and nested upload events to CSV.
        Falls back to the legacy session dicts (quick mode) when detailed
        logical sessions are unavailable. Returns the number of data rows.
        """
        headers = [
            "Type", "Session ID", "Event ID", "Protocol",
            "Client IP", "Server IPs", "Server Name/SNI", "Client Ports",
            "Start Time", "End Time", "Duration (s)",
            "Upload Bytes", "Download Bytes", "Packets",
            "Upload Ratio", "Classification", "Confidence (%)",
            "Peak Upload B/s", "Avg Upload B/s", "Num Peaks",
            "TCP Streams", "UDP Streams", "QUIC Conn IDs", "Fingerprint",
            "Protocol Bytes", "Protocol Bytes Readable", "Protocol Percentage",
        ]

        sessions = self.analysis_results.get("logical_sessions", [])
        rows = 0
        with open(filename, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(headers)

            for proto in self._protocol_export_rows():
                writer.writerow([
                    "ProtocolDistribution", "", "", proto["protocol"],
                    "", "", "", "", "", "", "", "", "",
                    proto["packets"], "", "", "", "", "", "", "", "", "", "",
                    proto["bytes"], proto["bytes_readable"], proto["percentage"],
                ])
                rows += 1

            if sessions:
                for s in sessions:
                    dur = (s.end_time - s.start_time) if (s.end_time and s.start_time) else 0
                    writer.writerow([
                        "Session", s.session_id, "", s.protocol,
                        s.client_ip, ",".join(sorted(s.server_ips)), s.server_name,
                        ",".join(sorted(s.client_ports)),
                        self._fmt_time(s.start_time), self._fmt_time(s.end_time),
                        f"{dur:.3f}",
                        s.total_upload_bytes, s.total_download_bytes, s.total_packets,
                        f"{s.upload_ratio:.3f}", s.classification, "",
                        "", "", "",
                        ";".join(s.tcp_streams), ";".join(s.udp_streams),
                        ";".join(sorted(s.quic_connection_ids)), "",
                        "", "", "",
                    ])
                    rows += 1
                    for ev in s.upload_events:
                        writer.writerow([
                            "UploadEvent", s.session_id, ev.event_id, ev.protocol,
                            ev.client_ip, ev.server_ip, ev.server_name,
                            ",".join(sorted(ev.client_ports)),
                            self._fmt_time(ev.start_time), self._fmt_time(ev.end_time),
                            f"{ev.duration:.3f}",
                            ev.upload_payload_bytes, ev.download_bytes, ev.upload_packets,
                            f"{ev.upload_ratio:.3f}", "", f"{ev.confidence:.1f}",
                            f"{ev.peak_upload_bps:.1f}", f"{ev.avg_upload_bps:.1f}",
                            ev.num_peaks,
                            ";".join(ev.flow_ids), "", "", ev.fingerprint,
                            "", "", "",
                        ])
                        rows += 1
            else:
                # Quick-mode fallback: legacy session dicts
                for s in self.analysis_results.get("sessions", []):
                    if not isinstance(s, dict):
                        continue
                    dur = (s.get("end_time", 0) - s.get("start_time", 0))
                    writer.writerow([
                        "Session", s.get("session_id", ""), "", s.get("protocol", ""),
                        s.get("src_ip", ""), s.get("dst_ip", ""), s.get("sni", ""),
                        ",".join(map(str, s.get("client_ports", []))),
                        self._fmt_time(s.get("start_time", 0)),
                        self._fmt_time(s.get("end_time", 0)),
                        f"{dur:.3f}" if dur else "",
                        s.get("upload_bytes", 0), s.get("download_bytes", 0),
                        s.get("packets", 0),
                        f"{s.get('upload_ratio', 0):.3f}", s.get("classification", ""),
                        "", "", "", "",
                        ";".join(map(str, s.get("tcp_streams", []))),
                        ";".join(map(str, s.get("udp_streams", []))),
                        ";".join(map(str, s.get("quic_cids", []))), "",
                        "", "", "",
                    ])
                    rows += 1
        return rows
                
    def configure_tshark(self):
        """Configure TShark path"""
        path = filedialog.askopenfilename(
            title="Select TShark Executable",
            filetypes=[("Executable", "*.exe"), ("All files", "*.*")]
        )
        if path:
            self.tshark_path.set(path)
            
    def show_about(self):
        """Show about dialog"""
        messagebox.showinfo("About", 
            "Satellite Intelligence — Advanced Desktop v1.0\n\n"
            "A comprehensive network analysis tool\n"
            "for analyzing PCAP files.\n\n"
            "Features:\n"
            "- Protocol distribution analysis\n"
            "- Upload behavior detection\n"
            "- DNS query analysis\n"
            "- TLS connection inspection\n"
            "- Session extraction\n"
            "- Export to JSON/CSV"
        )
        
    def update_status(self, message):
        """Update status bar"""
        self.status_label.config(text=message)
        
    @staticmethod
    def format_bytes(bytes_count):
        """Format bytes to human readable string"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_count < 1024:
                return f"{bytes_count:.2f} {unit}"
            bytes_count /= 1024
        return f"{bytes_count:.2f} PB"


def main():
    root = tk.Tk()
    app = PCAPIntelligenceDashboard(root)
    import argparse
    parser = argparse.ArgumentParser(); parser.add_argument('--pcap'); args = parser.parse_args()
    if args.pcap: app.pcap_file.set(args.pcap)
    root.title('Satellite Intelligence — Advanced Desktop / capture scope')
    root.mainloop()


if __name__ == "__main__":
    main()
