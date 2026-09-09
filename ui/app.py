import sys
import asyncio
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QPushButton, QLabel, QLineEdit, 
                             QTableWidget, QTableWidgetItem, QHeaderView, 
                             QMessageBox, QProgressBar, QSplitter, QTextEdit,
                             QFileDialog, QFrame, QTabWidget)
try:
    from PyQt6.QtWebEngineCore import QWebEngineProfile
    from PyQt6.QtWebEngineWidgets import QWebEngineView
    WEBENGINE_AVAILABLE = True
except ImportError:
    WEBENGINE_AVAILABLE = False
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QColor, QFont

import pandas as pd
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter

from utils.export import export_to_csv, export_to_pdf, export_to_json
from core.database import DatabaseManager
from utils.config import Config
from core.privilege_proxy import _has_raw_socket_privilege
import json

class ExportWorker(QThread):
    finished = pyqtSignal(str)
    error = pyqtSignal(str)

    def __init__(self, export_type, devices, path):
        super().__init__()
        self.export_type = export_type
        self.devices = devices
        self.path = path

    def run(self):
        try:
            if self.export_type == "csv":
                export_to_csv(self.devices, self.path)
            elif self.export_type == "pdf":
                export_to_pdf(self.devices, self.path)
            elif self.export_type == "json":
                export_to_json(self.devices, self.path)
            self.finished.emit(f"Successfully exported to {self.path}")
        except Exception as e:
            self.error.emit(str(e))

from core.orchestrator import Orchestrator

class AsyncRunner(QThread):
    progress = pyqtSignal(int, str)
    finished = pyqtSignal(list)
    error = pyqtSignal(str)

    def __init__(self, target):
        super().__init__()
        self.target = target
        
    def run(self):
        try:
            try:
                import uvloop
                asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
            except ImportError:
                pass
            
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            orchestrator = Orchestrator(self.target)
            
            def progress_cb(pct, msg):
                self.progress.emit(pct, msg)
                
            result = loop.run_until_complete(orchestrator.scan_network(progress_cb))
            self.finished.emit(result)
        except Exception as e:
            self.error.emit(str(e))
class MonitorWorker(QThread):
    alert = pyqtSignal(str, dict)   # (event_type, data)
    error = pyqtSignal(str)

    def __init__(self, target: str, interval: int = 300):
        super().__init__()
        self.target = target
        self.interval = interval
        self._loop = None
        self._monitor = None

    def run(self):
        import asyncio
        from core.monitor import NetworkMonitor
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)

        def on_event(event_type, data):
            self.alert.emit(event_type, data)

        self._monitor = NetworkMonitor(self.target, self.interval, callback=on_event)
        try:
            self._loop.run_until_complete(self._monitor.start())
        except Exception as e:
            self.error.emit(str(e))

    def stop_monitor(self):
        if self._monitor:
            self._monitor.stop()
        if self._loop and self._loop.is_running():
            self._loop.call_soon_threadsafe(self._loop.stop)


class NetscanApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Netscan - Enterprise Network Scanner")
        self.resize(1100, 750)
        self.devices = []
        self.db = DatabaseManager()
        self._monitor_worker = None
        self._is_dark_theme = True
        self._scheduler = None
        self.apply_styles()
        self.init_ui()
        self.check_auth()
        


    def init_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(15, 15, 15, 15)
        main_layout.setSpacing(15)
        
        # --- App Banner ---
        banner = QLabel()
        banner.setText('<div style="text-align:center;">'
                       '<h1 style="color: #7aa2f7; margin:0; font-size: 36px; font-weight: 900; letter-spacing: 5px; font-family: sans-serif;">NETSCAN <span style="color:#f7768e;"></span></h1>'
                       '<p style="color: #bb9af7; margin: 0; font-size: 14px; font-weight: bold; letter-spacing: 2px;">DEVELOPED BY VIRUSBABA</p>'
                       '</div>')
        banner.setStyleSheet("""
            QLabel {
                background: #1a1b26;
                border-radius: 12px;
                padding: 20px;
                border: 1px solid #414868;
                border-bottom: 4px solid #7aa2f7;
            }
        """)
        main_layout.addWidget(banner)
        
        # --- Top Bar ---
        top_bar = QHBoxLayout()
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("Enter CIDR, IP, Domain, or 'auto' (e.g. google.com)")
        self.target_input.setStyleSheet("padding: 8px; font-size: 14px; border: 1px solid #ccc; border-radius: 4px;")
        
        self.scan_btn = QPushButton("Start Scan")
        self.scan_btn.setStyleSheet("QPushButton { background-color: #3498db; color: white; font-weight: bold; padding: 8px 15px; border-radius: 4px; border-bottom: 3px solid #2980b9; } QPushButton:pressed { border-bottom: 0px; margin-top: 3px; }")
        self.scan_btn.clicked.connect(self.start_scan)
        
        self.export_csv_btn = QPushButton("Export CSV")
        self.export_csv_btn.setStyleSheet("QPushButton { background-color: #2ecc71; color: white; font-weight: bold; padding: 8px 15px; border-radius: 4px; border-bottom: 3px solid #27ae60; } QPushButton:pressed { border-bottom: 0px; margin-top: 3px; }")
        self.export_csv_btn.clicked.connect(self.export_csv)
        
        self.export_pdf_btn = QPushButton("Export PDF")
        self.export_pdf_btn.setStyleSheet("QPushButton { background-color: #e74c3c; color: white; font-weight: bold; padding: 8px 15px; border-radius: 4px; border-bottom: 3px solid #c0392b; } QPushButton:pressed { border-bottom: 0px; margin-top: 3px; }")
        self.export_pdf_btn.clicked.connect(self.export_pdf)
        
        self.export_json_btn = QPushButton("Export JSON")
        self.export_json_btn.setStyleSheet("QPushButton { background-color: #f39c12; color: white; font-weight: bold; padding: 8px 15px; border-radius: 4px; border-bottom: 3px solid #e67e22; } QPushButton:pressed { border-bottom: 0px; margin-top: 3px; }")
        self.export_json_btn.clicked.connect(self.export_json)

        # Scan Profile Selector
        from PyQt6.QtWidgets import QComboBox
        self.profile_combo = QComboBox()
        self.profile_combo.addItems(list(Config.SCAN_PROFILES.keys()))
        self.profile_combo.setCurrentText(Config.ACTIVE_SCAN_PROFILE)
        self.profile_combo.setToolTip("Select port scanning profile")
        self.profile_combo.setStyleSheet("padding: 6px; font-size: 13px; border-radius: 4px; background: #1f2335; color: #a9b1d6; border: 1px solid #414868;")

        # Monitor Toggle
        self.monitor_btn = QPushButton("▶ Monitor")
        self.monitor_btn.setCheckable(True)
        self.monitor_btn.setStyleSheet("""
            QPushButton { background-color: #414868; color: #a9b1d6; font-weight: bold; padding: 8px 15px; border-radius: 4px; border-bottom: 3px solid #2c3054; }
            QPushButton:checked { background-color: #9ece6a; color: #1a1b26; border-bottom: 3px solid #6a9e4a; }
        """)
        self.monitor_btn.clicked.connect(self.toggle_monitor)

        # Export Topology
        self.export_topo_btn = QPushButton("Export Topology")
        self.export_topo_btn.setStyleSheet("QPushButton { background-color: #bb9af7; color: #1a1b26; font-weight: bold; padding: 8px 15px; border-radius: 4px; border-bottom: 3px solid #9b7ad7; } QPushButton:pressed { border-bottom: 0px; margin-top: 3px; }")
        self.export_topo_btn.clicked.connect(self.export_topology_html)
        self.export_topo_btn.setEnabled(False)
        
        # Theme Toggle + Privilege Indicator
        self.theme_btn = QPushButton("☀️ Light Theme")
        self.theme_btn.setStyleSheet("QPushButton { background-color: #1f2335; color: #a9b1d6; font-weight: bold; padding: 7px 13px; border-radius: 4px; border: 1px solid #414868; }")
        self.theme_btn.clicked.connect(self.toggle_theme)

        is_priv = _has_raw_socket_privilege()
        priv_text = "🔓 Privileged" if is_priv else "🔒 Unprivileged"
        priv_color = "#9ece6a" if is_priv else "#e0af68"
        self.priv_lbl = QLabel(priv_text)
        self.priv_lbl.setStyleSheet(f"font-weight: bold; color: {priv_color}; padding: 7px 10px; border-radius: 4px; background: #1f2335; border: 1px solid #414868;")
        self.priv_lbl.setToolTip("Green = raw-socket access (ARP/SYN available). Orange = limited mode (unprivileged TCP scan only).")

        lbl_target = QLabel("Target Network:")
        lbl_target.setStyleSheet("font-weight: bold; font-size: 14px;")

        top_bar.addWidget(lbl_target)
        top_bar.addWidget(self.target_input)
        top_bar.addWidget(self.profile_combo)
        top_bar.addWidget(self.scan_btn)
        top_bar.addWidget(self.monitor_btn)
        top_bar.addWidget(self.export_csv_btn)
        top_bar.addWidget(self.export_pdf_btn)
        top_bar.addWidget(self.export_json_btn)
        top_bar.addWidget(self.export_topo_btn)
        top_bar.addWidget(self.theme_btn)
        top_bar.addWidget(self.priv_lbl)
        top_bar.addStretch()
        main_layout.addLayout(top_bar)
        
        # --- 3D Dashboard ---
        dashboard_layout = QHBoxLayout()
        dashboard_layout.setSpacing(10)

        def create_3d_card(title, color_hex):
            frame = QFrame()
            frame.setStyleSheet(f"""
                QFrame {{
                    background-color: #1a1b26;
                    border-radius: 10px;
                    border: 1px solid #414868;
                    border-bottom: 4px solid {color_hex};
                }}
            """)
            layout = QVBoxLayout(frame)
            layout.setContentsMargins(10, 10, 10, 10)
            
            lbl_title = QLabel(title)
            lbl_title.setStyleSheet("color: #565f89; font-weight: bold; font-size: 11px; border: none; text-transform: uppercase;")
            lbl_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
            
            lbl_value = QLabel("0")
            lbl_value.setStyleSheet(f"color: {color_hex}; font-weight: 900; font-size: 28px; border: none;")
            lbl_value.setAlignment(Qt.AlignmentFlag.AlignCenter)
            
            layout.addWidget(lbl_title)
            layout.addWidget(lbl_value)
            return frame, lbl_value

        self.card_total, self.lbl_total = create_3d_card("TOTAL", "#7aa2f7")
        self.card_active, self.lbl_active = create_3d_card("ACTIVE", "#9ece6a")
        self.card_inactive, self.lbl_inactive = create_3d_card("OFFLINE", "#565f89")
        self.card_safe, self.lbl_safe = create_3d_card("SECURE", "#73daca")
        self.card_risk, self.lbl_risk = create_3d_card("RISK", "#e0af68")
        self.card_high_risk, self.lbl_high_risk = create_3d_card("CRITICAL", "#f7768e")
        self.card_iot, self.lbl_iot = create_3d_card("IoT", "#bb9af7")
        
        dashboard_layout.addWidget(self.card_total)
        dashboard_layout.addWidget(self.card_active)
        dashboard_layout.addWidget(self.card_inactive)
        dashboard_layout.addWidget(self.card_safe)
        dashboard_layout.addWidget(self.card_risk)
        dashboard_layout.addWidget(self.card_high_risk)
        dashboard_layout.addWidget(self.card_iot)
        main_layout.addLayout(dashboard_layout)
        
        # --- Progress ---
        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        self.lbl_status = QLabel("Ready")
        main_layout.addWidget(self.progress_bar)
        main_layout.addWidget(self.lbl_status)
        
        # --- Splitter (Table + Details) ---
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        self.tabs = QTabWidget()
        self.tabs.setStyleSheet("""
            QTabWidget::pane { border: 1px solid #414868; background-color: #1a1b26; }
            QTabBar::tab { background-color: #16161e; color: #565f89; padding: 8px 20px; border: 1px solid #414868; border-bottom: none; }
            QTabBar::tab:selected { background-color: #1a1b26; color: #7aa2f7; font-weight: bold; }
        """)
        
        self.table = QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels(["IP Address", "Status", "MAC Address", "Device Name / Vendor", "Device Type", "Risk", "Ports"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table.itemSelectionChanged.connect(self.show_details)
        
        self.tabs.addTab(self.table, "Grid View")
        
        # History Table
        history_widget = QWidget()
        history_layout = QVBoxLayout(history_widget)
        history_layout.setContentsMargins(0,0,0,0)
        
        self.history_table = QTableWidget(0, 3)
        self.history_table.setHorizontalHeaderLabels(["Scan Time", "Target Network", "Devices Found"])
        self.history_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.history_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        
        btn_layout = QHBoxLayout()
        self.btn_load_scan = QPushButton("Load Selected Scan")
        self.btn_load_scan.clicked.connect(self.load_history_scan)
        self.btn_compare_scan = QPushButton("Compare Selected Scans")
        self.btn_compare_scan.clicked.connect(self.compare_history_scans)
        self.btn_delete_scan = QPushButton("Delete Selected Scan")
        self.btn_delete_scan.clicked.connect(self.delete_history_scan)
        
        btn_layout.addWidget(self.btn_load_scan)
        btn_layout.addWidget(self.btn_compare_scan)
        btn_layout.addWidget(self.btn_delete_scan)
        
        history_layout.addWidget(self.history_table)
        history_layout.addLayout(btn_layout)
        self.tabs.addTab(history_widget, "Scan History")
        
        if WEBENGINE_AVAILABLE:
            self.topology_view = QWebEngineView()
            self.topology_view.setHtml("<body style='background-color: #1a1b26; color: #a9b1d6; display:flex; justify-content:center; align-items:center; height:100vh; font-family:sans-serif;'><h2>Run a scan to view network topology</h2></body>")
            self.tabs.addTab(self.topology_view, "Topology Map")

        # ── Scheduler Tab ────────────────────────────────────────────────────
        from PyQt6.QtWidgets import QSpinBox, QFormLayout
        scheduler_widget = QWidget()
        sched_layout = QVBoxLayout(scheduler_widget)
        sched_layout.setContentsMargins(12, 12, 12, 12)

        sched_form = QFormLayout()
        self.sched_target_input = QLineEdit()
        self.sched_target_input.setPlaceholderText("e.g. 192.168.1.0/24")
        self.sched_interval_spin = QSpinBox()
        self.sched_interval_spin.setRange(5, 1440)
        self.sched_interval_spin.setValue(30)
        self.sched_interval_spin.setSuffix(" min")
        self.sched_label_input = QLineEdit()
        self.sched_label_input.setPlaceholderText("Optional label (e.g. Home Network)")

        sched_form.addRow("Target:", self.sched_target_input)
        sched_form.addRow("Interval:", self.sched_interval_spin)
        sched_form.addRow("Label:", self.sched_label_input)
        sched_layout.addLayout(sched_form)

        sched_btn_row = QHBoxLayout()
        self.btn_add_schedule = QPushButton("➕ Add Schedule")
        self.btn_add_schedule.clicked.connect(self.add_scheduled_scan)
        self.btn_remove_schedule = QPushButton("🗑 Remove Selected")
        self.btn_remove_schedule.clicked.connect(self.remove_scheduled_scan)
        self.btn_start_scheduler = QPushButton("▶ Start Scheduler")
        self.btn_start_scheduler.setCheckable(True)
        self.btn_start_scheduler.clicked.connect(self.toggle_scheduler)
        sched_btn_row.addWidget(self.btn_add_schedule)
        sched_btn_row.addWidget(self.btn_remove_schedule)
        sched_btn_row.addWidget(self.btn_start_scheduler)
        sched_layout.addLayout(sched_btn_row)

        self.sched_table = QTableWidget(0, 4)
        self.sched_table.setHorizontalHeaderLabels(["Label", "Target", "Interval (min)", "Next Run"])
        self.sched_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        sched_layout.addWidget(self.sched_table)

        self.tabs.addTab(scheduler_widget, "📅 Scheduler")
            
        splitter.addWidget(self.tabs)
        
        self.refresh_history()
        
        # Details Panel
        details_widget = QWidget()
        details_layout = QVBoxLayout(details_widget)
        details_layout.addWidget(QLabel("Device Details"))
        self.details_text = QTextEdit()
        self.details_text.setReadOnly(True)
        details_layout.addWidget(self.details_text)
        splitter.addWidget(details_widget)
        
        splitter.setSizes([450, 650])
        main_layout.addWidget(splitter)
        
    def check_auth(self):
        msg = QMessageBox()
        msg.setIcon(QMessageBox.Icon.Warning)
        msg.setWindowTitle("Authorization Required")
        msg.setText("This is a professional network security tool.\n\nWARNING: Use only on authorized networks (internal networks, labs, or explicitly permitted client networks).\n\nDo you confirm you have authorization?")
        msg.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        ret = msg.exec()
        if ret == QMessageBox.StandardButton.No:
            sys.exit()

    def start_scan(self):
        target = self.target_input.text().strip()
        if not target:
            target = "auto"
            self.target_input.setText("auto")
            
        # Apply selected scan profile to Config
        selected_profile = self.profile_combo.currentText()
        ports = Config.SCAN_PROFILES.get(selected_profile, Config.SCAN_PORTS)
        Config.SCAN_PORTS = ports
        Config.ACTIVE_SCAN_PROFILE = selected_profile

        self.scan_btn.setEnabled(False)
        self.export_csv_btn.setEnabled(False)
        self.export_pdf_btn.setEnabled(False)
        self.progress_bar.setValue(0)
        self.lbl_status.setText(f"Initializing ({selected_profile})...")
        self.table.setRowCount(0)
        self.details_text.clear()
        
        self.runner = AsyncRunner(target)
        self.runner.progress.connect(self.update_progress)
        self.runner.finished.connect(self.scan_complete)
        self.runner.error.connect(self.scan_error)
        self.runner.start()

    def update_progress(self, pct, msg):
        self.progress_bar.setValue(pct)
        self.lbl_status.setText(msg)

    def scan_complete(self, devices):
        self.devices = devices
        
        # Save scan to DB
        target = self.target_input.text().strip() or "auto"
        self.db.save_scan(target, devices)
        self.refresh_history()
        
        self.populate_table()
        self.update_dashboard()
        self.update_topology()
        
        self.progress_bar.setValue(100)
        self.lbl_status.setText(f"Scan complete. Found {len(devices)} active devices.")
        self.scan_btn.setEnabled(True)
        self.export_csv_btn.setEnabled(True)
        self.export_pdf_btn.setEnabled(True)

    def scan_error(self, err):
        self.lbl_status.setText(f"Error: {err}")
        QMessageBox.critical(self, "Error", f"An error occurred during scan:\n{err}")
        self.progress_bar.setValue(0)
        self.scan_btn.setEnabled(True)
        self.export_csv_btn.setEnabled(True)
        self.export_pdf_btn.setEnabled(True)
        self.export_json_btn.setEnabled(True)

    def toggle_monitor(self):
        if self.monitor_btn.isChecked():
            target = self.target_input.text().strip() or "auto"
            interval = Config.MONITOR_INTERVAL
            self.monitor_btn.setText("⏹ Stop Monitor")
            self.lbl_status.setText(f"Continuous monitoring started on {target} (every {interval}s)")
            self._monitor_worker = MonitorWorker(target, interval)
            self._monitor_worker.alert.connect(self.on_monitor_alert)
            self._monitor_worker.error.connect(lambda e: self.lbl_status.setText(f"Monitor error: {e}"))
            self._monitor_worker.start()
        else:
            if self._monitor_worker:
                self._monitor_worker.stop_monitor()
                self._monitor_worker = None
            self.monitor_btn.setText("▶ Monitor")
            self.lbl_status.setText("Continuous monitoring stopped.")

    def on_monitor_alert(self, event_type: str, data: dict):
        ip = data.get("ip", "")
        if event_type == "new_device":
            msg = f"🔔 NEW DEVICE: {ip} ({data.get('vendor', 'Unknown')}) — {data.get('risk_level', 'Low')} Risk"
            QMessageBox.information(self, "Network Change Detected", msg)
        elif event_type == "device_gone":
            msg = f"⚠️ DEVICE OFFLINE: {ip} is no longer responding."
            QMessageBox.warning(self, "Network Change Detected", msg)
        elif event_type == "new_risk_port":
            ports = data.get('new_ports', [])
            msg = f"⚠️ NEW PORTS on {ip}: {', '.join(str(p) for p in ports)} (Risk: {data.get('risk_level', 'Low')})"
            QMessageBox.warning(self, "Network Change Detected", msg)
        # Silently update dashboard on scan_complete events
        self.lbl_status.setText(f"[Monitor] Last scan: {data.get('timestamp', '')} — {data.get('active_count', '?')} active")

    def export_topology_html(self):
        """Export the D3.js topology view as a standalone interactive HTML file."""
        if not WEBENGINE_AVAILABLE or not self.devices:
            QMessageBox.warning(self, "No Data", "Run a scan first to generate the topology.")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export Topology HTML", "netscan_topology.html", "HTML Files (*.html)")
        if not path:
            return
        # Re-generate the full topology HTML string
        nodes = [{"id": "Scanner", "group": 0, "label": "Scanner", "radius": 25, "color": "#7aa2f7"}]
        links = []
        for dev in self.devices:
            if dev.get("status") != "Active":
                continue
            ip = dev.get("ip")
            risk = dev.get("risk_level", "Low")
            color = "#9ece6a"
            if risk == "High": color = "#f7768e"
            elif risk == "Medium": color = "#e0af68"
            elif dev.get("is_iot"): color = "#bb9af7"
            nodes.append({"id": ip, "group": 1, "label": ip, "radius": 15, "color": color})
            links.append({"source": "Scanner", "target": ip, "value": 1})

        # Identical D3 HTML, but embedded with data and a standalone title
        topo_html = f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Netscan Topology — {self.target_input.text().strip() or 'auto'}</title>
<style>body{{margin:0;background:#1a1b26;overflow:hidden;font-family:sans-serif;}}
.node-label{{font-size:10px;fill:#a9b1d6;pointer-events:none;text-anchor:middle;font-weight:bold;}}
#info{{position:fixed;top:10px;left:10px;color:#a9b1d6;font-size:13px;background:#161b22;padding:10px 16px;border-radius:8px;border:1px solid #414868;}}</style>
<script src="https://d3js.org/d3.v7.min.js"></script>
</head>
<body><div id="info">🛡 Netscan Topology | {len(nodes)-1} active devices</div><div id="graph"></div>
<script>
const nodes={json.dumps(nodes)},links={json.dumps(links)};
const W=window.innerWidth,H=window.innerHeight;
const svg=d3.select("#graph").append("svg").attr("width",W).attr("height",H)
  .call(d3.zoom().on("zoom",e=>g.attr("transform",e.transform))).append("g");
const g=svg;const sim=d3.forceSimulation(nodes).force("link",d3.forceLink(links).id(d=>d.id).distance(150)).force("charge",d3.forceManyBody().strength(-300)).force("center",d3.forceCenter(W/2,H/2));
const link=svg.append("g").attr("stroke","#414868").attr("stroke-opacity",0.6).selectAll("line").data(links).join("line").attr("stroke-width",2);
const node=svg.append("g").attr("stroke","#1a1b26").attr("stroke-width",2).selectAll("circle").data(nodes).join("circle").attr("r",d=>d.radius).attr("fill",d=>d.color).call(d3.drag().on("start",(e,d)=>{{if(!e.active)sim.alphaTarget(0.3).restart();d.fx=d.x;d.fy=d.y;}}).on("drag",(e,d)=>{{d.fx=e.x;d.fy=e.y;}}).on("end",(e,d)=>{{if(!e.active)sim.alphaTarget(0);d.fx=null;d.fy=null;}}));
node.append("title").text(d=>d.id);
const labels=svg.append("g").selectAll("text").data(nodes).join("text").attr("class","node-label").attr("dy",d=>d.radius+12).text(d=>d.label);
sim.on("tick",()=>{{link.attr("x1",d=>d.source.x).attr("y1",d=>d.source.y).attr("x2",d=>d.target.x).attr("y2",d=>d.target.y);node.attr("cx",d=>d.x=Math.max(d.radius,Math.min(W-d.radius,d.x))).attr("cy",d=>d.y=Math.max(d.radius,Math.min(H-d.radius,d.y)));labels.attr("x",d=>d.x).attr("y",d=>d.y);}});
</script></body></html>"""
        try:
            with open(path, 'w', encoding='utf-8') as f:
                f.write(topo_html)
            QMessageBox.information(self, "Topology Exported", f"Saved to: {path}")
        except Exception as e:
            QMessageBox.critical(self, "Export Failed", str(e))

    def update_topology(self):
        if not WEBENGINE_AVAILABLE or not self.devices:
            return
            
        nodes = []
        links = []
        
        # Center Node (Scanner/Router)
        nodes.append({"id": "Scanner", "group": 0, "label": "Scanner", "radius": 25, "color": "#7aa2f7"})
        
        for dev in self.devices:
            if dev.get("status") != "Active": continue
            
            ip = dev.get("ip")
            risk = dev.get("risk_level", "Low")
            is_iot = dev.get("is_iot", False)
            
            color = "#9ece6a" # Default green (Safe)
            if risk == "High": color = "#f7768e"
            elif risk == "Medium": color = "#e0af68"
            elif is_iot: color = "#bb9af7"
                
            nodes.append({"id": ip, "group": 1, "label": ip, "radius": 15, "color": color})
            links.append({"source": "Scanner", "target": ip, "value": 1})
            
        import json
        nodes_json = json.dumps(nodes)
        links_json = json.dumps(links)
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <style>
                body {{ margin: 0; background-color: #1a1b26; overflow: hidden; font-family: -apple-system, sans-serif; }}
                .node-label {{ font-size: 10px; fill: #a9b1d6; pointer-events: none; text-anchor: middle; font-weight: bold; }}
            </style>
            <script src="https://d3js.org/d3.v7.min.js"></script>
        </head>
        <body>
            <div id="graph"></div>
            <script>
                const width = window.innerWidth;
                const height = window.innerHeight;
                
                const nodes = {nodes_json};
                const links = {links_json};
                
                const svg = d3.select("#graph").append("svg")
                    .attr("width", width)
                    .attr("height", height)
                    .call(d3.zoom().on("zoom", function (event) {{
                       svg.attr("transform", event.transform)
                    }}))
                    .append("g");
                    
                const simulation = d3.forceSimulation(nodes)
                    .force("link", d3.forceLink(links).id(d => d.id).distance(150))
                    .force("charge", d3.forceManyBody().strength(-300))
                    .force("center", d3.forceCenter(width / 2, height / 2));
                    
                const link = svg.append("g")
                    .attr("stroke", "#414868")
                    .attr("stroke-opacity", 0.6)
                    .selectAll("line")
                    .data(links)
                    .join("line")
                    .attr("stroke-width", d => Math.sqrt(d.value));
                    
                const node = svg.append("g")
                    .attr("stroke", "#1a1b26")
                    .attr("stroke-width", 2)
                    .selectAll("circle")
                    .data(nodes)
                    .join("circle")
                    .attr("r", d => d.radius)
                    .attr("fill", d => d.color)
                    .call(drag(simulation));
                    
                node.append("title").text(d => d.id);
                
                const labels = svg.append("g")
                    .selectAll("text")
                    .data(nodes)
                    .join("text")
                    .attr("class", "node-label")
                    .attr("dy", d => d.radius + 12)
                    .text(d => d.label);

                simulation.on("tick", () => {{
                    link
                        .attr("x1", d => d.source.x)
                        .attr("y1", d => d.source.y)
                        .attr("x2", d => d.target.x)
                        .attr("y2", d => d.target.y);
                        
                    node
                        .attr("cx", d => d.x = Math.max(d.radius, Math.min(width - d.radius, d.x)))
                        .attr("cy", d => d.y = Math.max(d.radius, Math.min(height - d.radius, d.y)));
                        
                    labels
                        .attr("x", d => d.x)
                        .attr("y", d => d.y);
                }});
                
                function drag(simulation) {{
                  function dragstarted(event) {{
                    if (!event.active) simulation.alphaTarget(0.3).restart();
                    event.subject.fx = event.subject.x;
                    event.subject.fy = event.subject.y;
                  }}
                  
                  function dragged(event) {{
                    event.subject.fx = event.x;
                    event.subject.fy = event.y;
                  }}
                  
                  function dragended(event) {{
                    if (!event.active) simulation.alphaTarget(0);
                    event.subject.fx = null;
                    event.subject.fy = null;
                  }}
                  
                  return d3.drag()
                      .on("start", dragstarted)
                      .on("drag", dragged)
                      .on("end", dragended);
                }}
            </script>
        </body>
        </html>
        """
        self.topology_view.setHtml(html_content)

    def populate_table(self):
        active_devices = [dev for dev in self.devices if dev.get("status") == "Active"]
        self.table.setRowCount(len(active_devices))
        for row, dev in enumerate(active_devices):
            ip_item = QTableWidgetItem(dev.get("ip", "Unknown") or "Unknown")
            status_item = QTableWidgetItem(dev.get("status", "Unknown") or "Unknown")
            mac_item = QTableWidgetItem(dev.get("mac", "Unknown") or "Unknown")
            
            # Combine domain/ptr and vendor for the name
            name_parts = []
            domain = dev.get("domain")
            ptr = dev.get("network", {}).get("ptr_record") if isinstance(dev.get("network"), dict) else None
            vendor = dev.get("vendor", "Unknown")
            if domain: name_parts.append(domain)
            elif ptr: name_parts.append(ptr)
            if vendor and vendor != "Unknown": name_parts.append(vendor)
            device_name = " / ".join(name_parts) if name_parts else "Unknown"
            
            vendor_item = QTableWidgetItem(device_name)
            type_item = QTableWidgetItem(dev.get("device_type", "Unknown") or "Unknown")
            risk_item = QTableWidgetItem(dev.get("risk_level", "Unknown") or "Unknown")
            ports = dev.get("open_ports", [])
            ports_item = QTableWidgetItem(str(ports) if ports else "Unknown")
            
            # Colors (Tokyo Night Palette)
            status = dev.get("status")
            risk = dev.get("risk_level", "Low")
            is_iot = dev.get("is_iot", False)
            
            color = QColor(26, 27, 38) # Default BG (#1a1b26)
            text_color = QColor(169, 177, 214) # Default FG (#a9b1d6)
            
            if status == "Inactive":
                text_color = QColor(86, 95, 137) # Muted blue/gray
            elif risk == "High":
                text_color = QColor(247, 118, 142) # Red
            elif risk == "Medium":
                text_color = QColor(224, 175, 104) # Yellow
            elif risk == "Low" and not is_iot:
                text_color = QColor(158, 206, 106) # Green
            elif is_iot:
                text_color = QColor(187, 154, 247) # Magenta
                
            for col, item in enumerate([ip_item, status_item, mac_item, vendor_item, type_item, risk_item, ports_item]):
                item.setBackground(color)
                item.setForeground(text_color)
                self.table.setItem(row, col, item)

    def update_dashboard(self):
        total = len(self.devices)
        active = sum(1 for d in self.devices if d.get("status") == "Active")
        inactive = total - active
        safe = sum(1 for d in self.devices if d.get("status") == "Active" and d.get("risk_level") == "Low" and not d.get("is_iot"))
        med = sum(1 for d in self.devices if d.get("status") == "Active" and d.get("risk_level") == "Medium")
        high = sum(1 for d in self.devices if d.get("status") == "Active" and d.get("risk_level") == "High")
        iot = sum(1 for d in self.devices if d.get("status") == "Active" and d.get("is_iot"))
        
        self.lbl_total.setText(str(total))
        self.lbl_active.setText(str(active))
        self.lbl_inactive.setText(str(inactive))
        self.lbl_safe.setText(str(safe))
        self.lbl_risk.setText(str(med))
        self.lbl_high_risk.setText(str(high))
        self.lbl_iot.setText(str(iot))

    def format_banner(self, banner):
        if not banner:
            return "<i>No banner detected</i>"
        
        # Clean up HTTP headers if present
        lines = banner.split("\n")
        cleaned_lines = []
        for line in lines:
            line = line.strip()
            # skip long cookies or security policies that clutter
            if line.lower().startswith("set-cookie:") or line.lower().startswith("content-security-policy"):
                continue
            if len(line) > 100:
                line = line[:97] + "..."
            cleaned_lines.append(line)
            if len(cleaned_lines) >= 8: # keep it short
                cleaned_lines.append("...")
                break
                
        # HTML escape
        import html
        return html.escape("\n".join(cleaned_lines)).replace("\n", "<br>")

    def show_details(self):
        selected = self.table.selectedItems()
        if not selected:
            return
        row = selected[0].row()
        dev = self.devices[row]
        
        status = dev.get('status', 'Inactive')
        risk = dev.get('risk_level', 'Low')
        risk_score = dev.get('risk_score', 0)
        
        badge_status = "#9ece6a" if status == "Active" else "#565f89"
        
        if risk == "High": badge_risk = "#f7768e"
        elif risk == "Medium": badge_risk = "#e0af68"
        else: badge_risk = "#73daca"
        
        # Color for risk score
        if risk_score >= 70: score_color = "#f7768e"
        elif risk_score >= 30: score_color = "#e0af68"
        else: score_color = "#73daca"
        
        html_content = f"""
        <style>
            body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #0b0f19; color: #a9b1d6; padding: 8px; }}
            h2 {{ color: #7aa2f7; border-bottom: 1px solid #1f2335; padding-bottom: 8px; margin-top: 0; font-size: 18px; letter-spacing: 1px; }}
            .card {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 16px; margin-bottom: 16px; }}
            .badge {{ padding: 4px 10px; font-weight: bold; color: #ffffff; border-radius: 12px; font-size: 12px; vertical-align: middle; text-transform: uppercase; letter-spacing: 0.5px; box-shadow: 0 0 5px rgba(0,0,0,0.5); }}
            .section-title {{ font-weight: 800; color: #bb9af7; text-transform: uppercase; font-size: 13px; margin-bottom: 12px; border-bottom: 1px solid #30363d; padding-bottom: 6px; letter-spacing: 1px; }}
            .row {{ margin-bottom: 8px; font-size: 14px; line-height: 1.4; }}
            .key {{ font-weight: bold; color: #565f89; display: inline-block; width: 140px; text-transform: capitalize; vertical-align: top; }}
            .val {{ color: #c0caf5; display: inline-block; max-width: calc(100% - 150px); word-wrap: break-word; }}
            pre {{ background: #0f111a; color: #9ece6a; padding: 12px; border-radius: 6px; border-left: 3px solid #7aa2f7; font-family: 'Courier New', Courier, monospace; font-size: 12px; white-space: pre-wrap; }}
        </style>

        <div class="card">
            <h2 style="display:flex; justify-content:space-between; align-items:center;">
                <span>IP: <span style="color:#ffffff;">{dev.get('ip')}</span></span>
                <span>
                    <span class="badge" style="background:{badge_status};">{status}</span>
                    <span class="badge" style="background:{score_color}; margin-left:5px;">SCORE: {risk_score}</span>
                </span>
            </h2>
        </div>
        """
        
        domain = dev.get('domain')
        if domain:
            html_content += f'<div class="row"><span class="key">Domain:</span> <span class="val">{domain}</span></div>'
            
        hardware = dev.get('hardware')
        if hardware:
            for k, v in hardware.items():
                html_content += f'<div class="row"><span class="key">{k.replace("_", " ")}:</span> <span class="val">{v}</span></div>'
                
        html_content += "</div>"
        
        if status == "Active":
            # Risk & Device Profile Card
            html_content += f"""
            <div class="card">
                <div class="section-title">Risk & Profiling</div>
                <div class="row"><span class="key">Risk Level:</span> <span class="badge" style="background:{badge_risk};">{risk}</span></div>
            """
            
            if dev.get('device_type'):
                html_content += f'<div class="row"><span class="key">Device Type:</span> <span class="val">{dev.get("device_type")}</span></div>'
                
            for r in dev.get('risk_reasons', []):
                html_content += f'<div class="row" style="color:#f7768e; padding-left: 140px;"> - {r}</div>'
                
            if dev.get('is_iot') and dev.get("iot_reason"):
                html_content += f'<div class="row"><span class="key">IoT Reason:</span> <span class="val">{dev.get("iot_reason")}</span></div>'
            html_content += "</div>"
            
            # Web Intelligence Card
            web_intel = dev.get('web_intelligence')
            if web_intel:
                html_content += '<div class="card"><div class="section-title">Web Intelligence</div>'
                for port, data in web_intel.items():
                    html_content += f'<div class="row" style="margin-top:10px;"><span class="badge" style="background:#2ac3de; color:#1a1b26;">PORT {port}</span></div>'
                    if "http" in data:
                        h = data["http"]
                        html_content += f'<div class="row"><span class="key">Server:</span> <span class="val" style="color:#73daca;">{h.get("server")}</span></div>'
                        if h.get("technologies"):
                            html_content += f'<div class="row"><span class="key">Tech:</span> <span class="val">{", ".join(h.get("technologies"))}</span></div>'
                        
                        sec = h.get("security_headers", {})
                        if sec:
                            html_content += '<div style="margin-left:20px; font-size:12px; color:#565f89; margin-top:5px;">'
                            for head, val in sec.items():
                                color = "#9ece6a" if val != "Missing" else "#f7768e"
                                html_content += f'<div>{head}: <span style="color:{color};">{val}</span></div>'
                            html_content += '</div>'
                    
                    if "tls" in data:
                        t = data["tls"]
                        if "error" not in t:
                            html_content += f'<div class="row"><span class="key">TLS:</span> <span class="val" style="color:#bb9af7;">{t.get("version")} ({t.get("cipher")})</span></div>'
                        else:
                            html_content += f'<div class="row"><span class="key">TLS:</span> <span class="val" style="color:#f7768e;">{t.get("error")}</span></div>'
                html_content += "</div>"
            
            # Network Info Card
            network = dev.get('network')
            if network:
                html_content += '<div class="card"><div class="section-title">Network Information</div>'
                for k, v in network.items():
                    html_content += f'<div class="row"><span class="key">{k.replace("_", " ")}:</span> <span class="val">{v}</span></div>'
                html_content += '</div>'
                
            # Geolocation Card
            geo = dev.get('geo')
            if geo:
                html_content += '<div class="card"><div class="section-title">Geolocation</div>'
                for k, v in geo.items():
                    html_content += f'<div class="row"><span class="key">{k.replace("_", " ")}:</span> <span class="val">{v}</span></div>'
                html_content += '</div>'
                
            # DNS Intelligence Card
            dns = dev.get('dns')
            if dns:
                html_content += '<div class="card"><div class="section-title">DNS Intelligence</div>'
                for k, records in dns.items():
                    html_content += f'<div class="row"><span class="key">{k.replace("_", " ").upper()}:</span>'
                    html_content += f'<span class="val">'
                    for r in records:
                        html_content += f'<span style="display:block; margin-bottom: 3px;">{r}</span>'
                    html_content += '</span></div>'
                html_content += '</div>'
                
            # Device Services Card
            device = dev.get('device')
            if device:
                os_guess = device.get('os_guess')
                open_ports = device.get('open_ports', [])
                banners = device.get('banners', [])
                
                html_content += '<div class="card"><div class="section-title">Services & Ports</div>'
                if os_guess:
                    html_content += f'<div class="row"><span class="key">OS Guess:</span> <span class="val">{os_guess}</span></div>'
                    
                if open_ports:
                    html_content += f'<div class="row"><span class="key">Total Open:</span> <span class="val">{len(open_ports)}</span></div>'
                    for port, banner in zip(open_ports, banners):
                        html_content += f'<div class="row" style="margin-top: 15px;"><span class="badge" style="background:#414868; box-shadow:none;">PORT {port}</span></div>'
                        html_content += f'<pre>{self.format_banner(banner)}</pre>'
                html_content += '</div>'
        else:
            html_content += f"""
            <div class="card">
                <div class="row" style="color: #565f89; font-style: italic; text-align: center; padding: 20px 0;">
                    This target is unreachable or currently offline.
                </div>
            </div>
            """
            
        self.details_text.setHtml(html_content)

    def export_csv(self):
        if not self.devices:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Save CSV", "", "CSV Files (*.csv)")
        if path:
            self.export_csv_btn.setEnabled(False)
            self.export_csv_btn.setText("Exporting...")
            self.csv_worker = ExportWorker("csv", self.devices, path)
            self.csv_worker.finished.connect(self._on_export_finished)
            self.csv_worker.error.connect(self._on_export_error)
            self.csv_worker.start()

    def export_pdf(self):
        if not self.devices:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Save PDF", "", "PDF Files (*.pdf)")
        if path:
            self.export_pdf_btn.setEnabled(False)
            self.export_pdf_btn.setText("Exporting...")
            self.pdf_worker = ExportWorker("pdf", self.devices, path)
            self.pdf_worker.finished.connect(self._on_export_finished)
            self.pdf_worker.error.connect(self._on_export_error)
            self.pdf_worker.start()

    def export_json(self):
        if not self.devices:
            QMessageBox.warning(self, "No Data", "No scan results to export.")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Save JSON", "", "JSON Files (*.json)")
        if path:
            self.export_csv_btn.setEnabled(False)
            self.export_pdf_btn.setEnabled(False)
            self.export_json_btn.setEnabled(False)
            self.export_json_btn.setText("Exporting...")
            self.export_worker = ExportWorker("json", self.devices, path)
            self.export_worker.finished.connect(self._on_export_finished)
            self.export_worker.error.connect(self._on_export_error)
            self.export_worker.start()

    def _on_export_finished(self, msg):
        self.export_csv_btn.setEnabled(True)
        self.export_csv_btn.setText("Export CSV")
        self.export_pdf_btn.setEnabled(True)
        self.export_pdf_btn.setText("Export PDF")
        self.export_json_btn.setEnabled(True)
        self.export_json_btn.setText("Export JSON")
        QMessageBox.information(self, "Export Complete", msg)
        
    def _on_export_error(self, err_msg):
        self.export_csv_btn.setEnabled(True)
        self.export_csv_btn.setText("Export CSV")
        self.export_pdf_btn.setEnabled(True)
        self.export_pdf_btn.setText("Export PDF")
        self.export_json_btn.setEnabled(True)
        self.export_json_btn.setText("Export JSON")
        QMessageBox.critical(self, "Error", f"Failed to export: {err_msg}")

    def refresh_history(self):
        history = self.db.get_history()
        self.history_table.setRowCount(0)
        for row, scan in enumerate(history):
            self.history_table.insertRow(row)
            self.history_table.setItem(row, 0, QTableWidgetItem(str(scan["scan_time"])))
            self.history_table.setItem(row, 1, QTableWidgetItem(str(scan["target_network"])))
            self.history_table.setItem(row, 2, QTableWidgetItem(str(scan["device_count"])))

    def load_history_scan(self):
        selected = self.history_table.selectedItems()
        if not selected: return
        scan_time = self.history_table.item(selected[0].row(), 0).text()
        
        scan_data = self.db.get_scan_by_time(scan_time)
        if not scan_data: return
        devices = [json.loads(row["full_json"]) for row in scan_data]
        self.devices = devices
        
        self.populate_table()
        self.update_dashboard()
        if WEBENGINE_AVAILABLE:
            self.update_topology()
            
        self.tabs.setCurrentIndex(0) # Switch back to Grid View
        self.export_csv_btn.setEnabled(True)
        self.export_pdf_btn.setEnabled(True)
        self.export_json_btn.setEnabled(True)
        self.export_topo_btn.setEnabled(WEBENGINE_AVAILABLE)
        QMessageBox.information(self, "History Loaded", f"Loaded scan from {scan_time}")

    def compare_history_scans(self):
        selected = self.history_table.selectedItems()
        if not selected: return
        
        # Get unique rows
        rows = list(set([item.row() for item in selected]))
        if len(rows) != 2:
            QMessageBox.warning(self, "Compare Scans", "Please select exactly two scans to compare.\nYou can select multiple by holding Ctrl/Cmd.")
            return
            
        time1 = self.history_table.item(rows[0], 0).text()
        time2 = self.history_table.item(rows[1], 0).text()
        
        # Sort so old is first
        times = sorted([time1, time2])
        old_time, new_time = times[0], times[1]
        
        diff = self.db.get_diff(old_time, new_time)
        
        msg = f"<b>Comparison Report</b><br><br>"
        msg += f"<b>Older Scan:</b> {old_time}<br>"
        msg += f"<b>Newer Scan:</b> {new_time}<br><br>"
        
        msg += f"<b>Added Devices ({len(diff['added'])}):</b><br>"
        msg += ", ".join(diff['added']) if diff['added'] else "None"
        msg += "<br><br>"
        
        msg += f"<b>Removed Devices ({len(diff['removed'])}):</b><br>"
        msg += ", ".join(diff['removed']) if diff['removed'] else "None"
        msg += "<br><br>"
        
        msg += f"<b>Changed Devices ({len(diff['changed'])}):</b><br>"
        msg += ", ".join(diff['changed']) if diff['changed'] else "None"
        
        QMessageBox.information(self, "Scan Comparison", msg)
        
    def delete_history_scan(self):
        selected = self.history_table.selectedItems()
        if not selected: return
        scan_time = self.history_table.item(selected[0].row(), 0).text()
        
        reply = QMessageBox.question(self, 'Delete Scan', f"Are you sure you want to delete scan from {scan_time}?",
                                     QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, QMessageBox.StandardButton.No)
        
        if reply == QMessageBox.StandardButton.Yes:
            self.db.delete_scan(scan_time)
            self.refresh_history()
            QMessageBox.information(self, "Deleted", "Scan history deleted.")

    # ─── Theme Toggle ─────────────────────────────────────────────────────────

    def toggle_theme(self):
        """Switch between Tokyo Night (dark) and a clean light theme."""
        self._is_dark_theme = not self._is_dark_theme
        self.apply_styles()
        if self._is_dark_theme:
            self.theme_btn.setText("☀️ Light Theme")
        else:
            self.theme_btn.setText("🌙 Dark Theme")

    def apply_styles(self):
        """Apply the current dark/light theme to the app."""
        if self._is_dark_theme:
            self.setStyleSheet("""
                QMainWindow, QWidget {
                    background-color: #1a1b26; color: #a9b1d6;
                    font-family: 'Inter', 'Segoe UI', sans-serif; font-size: 13px;
                }
                QLineEdit, QTextEdit, QComboBox, QSpinBox {
                    background-color: #16161e; color: #c0caf5; border: 1px solid #414868;
                    border-radius: 4px; padding: 6px 10px;
                }
                QPushButton {
                    background-color: #7aa2f7; color: #1a1b26; font-weight: bold;
                    border-radius: 5px; padding: 8px 16px; border: none;
                }
                QPushButton:hover { background-color: #6b8ef0; }
                QPushButton:disabled { background-color: #414868; color: #565f89; }
                QHeaderView::section { background-color: #1f2335; color: #7aa2f7; font-weight: bold; border: 1px solid #414868; padding: 5px; }
                QTableWidget { background-color: #1a1b26; alternate-background-color: #1f2335; gridline-color: #2a2d3e; }
                QScrollBar:vertical { background-color: #1a1b26; width: 8px; }
                QScrollBar::handle:vertical { background-color: #414868; border-radius: 4px; }
                QProgressBar { background-color: #1f2335; border: 1px solid #414868; border-radius: 4px; }
                QProgressBar::chunk { background-color: #7aa2f7; }
                QLabel#status_bar { color: #565f89; }
            """)
        else:
            # Light theme
            self.setStyleSheet("""
                QMainWindow, QWidget {
                    background-color: #f5f5f5; color: #24292e;
                    font-family: 'Inter', 'Segoe UI', sans-serif; font-size: 13px;
                }
                QLineEdit, QTextEdit, QComboBox, QSpinBox {
                    background-color: #ffffff; color: #24292e; border: 1px solid #d1d5db;
                    border-radius: 4px; padding: 6px 10px;
                }
                QPushButton {
                    background-color: #0366d6; color: #ffffff; font-weight: bold;
                    border-radius: 5px; padding: 8px 16px; border: none;
                }
                QPushButton:hover { background-color: #0255b3; }
                QPushButton:disabled { background-color: #d1d5db; color: #9ca3af; }
                QHeaderView::section { background-color: #e5e7eb; color: #374151; font-weight: bold; border: 1px solid #d1d5db; padding: 5px; }
                QTableWidget { background-color: #ffffff; alternate-background-color: #f9fafb; gridline-color: #e5e7eb; }
                QScrollBar:vertical { background-color: #f5f5f5; width: 8px; }
                QScrollBar::handle:vertical { background-color: #d1d5db; border-radius: 4px; }
                QProgressBar { background-color: #e5e7eb; border: 1px solid #d1d5db; border-radius: 4px; }
                QProgressBar::chunk { background-color: #0366d6; }
            """)

    # ─── Scheduler Methods ────────────────────────────────────────────────────

    def add_scheduled_scan(self):
        """Add a recurring scan to the scheduler."""
        target = self.sched_target_input.text().strip()
        interval = self.sched_interval_spin.value()
        label = self.sched_label_input.text().strip() or target

        if not target:
            QMessageBox.warning(self, "Scheduler", "Please enter a target network.")
            return

        if self._scheduler is None:
            from core.scheduler import ScanScheduler
            self._scheduler = ScanScheduler(scan_callback=self._scheduled_scan_run)

        self._scheduler.add_recurring(target, interval, label=label, start_now=False)
        self.refresh_schedule_table()
        QMessageBox.information(self, "Scheduler", f"Scan scheduled for '{label}' every {interval} minutes.")

    def remove_scheduled_scan(self):
        """Remove selected job from scheduler table."""
        selected = self.sched_table.selectedItems()
        if not selected:
            QMessageBox.warning(self, "Scheduler", "Select a job to remove.")
            return
        label = self.sched_table.item(selected[0].row(), 0).text()
        if self._scheduler:
            removed = self._scheduler.remove_job(label)
            if removed:
                self.refresh_schedule_table()
                QMessageBox.information(self, "Scheduler", f"Job '{label}' removed.")

    def toggle_scheduler(self, checked: bool):
        """Start or stop the background scheduler."""
        if checked:
            if self._scheduler is None:
                from core.scheduler import ScanScheduler
                self._scheduler = ScanScheduler(scan_callback=self._scheduled_scan_run)
            self._scheduler.start()
            self.btn_start_scheduler.setText("⏹ Stop Scheduler")
        else:
            if self._scheduler:
                self._scheduler.stop()
            self.btn_start_scheduler.setText("▶ Start Scheduler")

    def refresh_schedule_table(self):
        """Refresh the scheduler table from the active scheduler jobs."""
        if self._scheduler is None:
            return
        jobs = self._scheduler.list_jobs()
        self.sched_table.setRowCount(len(jobs))
        for i, job in enumerate(jobs):
            self.sched_table.setItem(i, 0, QTableWidgetItem(job["label"]))
            self.sched_table.setItem(i, 1, QTableWidgetItem(job["target"]))
            self.sched_table.setItem(i, 2, QTableWidgetItem(str(job["interval_minutes"])))
            self.sched_table.setItem(i, 3, QTableWidgetItem(job["next_run"]))

    async def _scheduled_scan_run(self, target: str, label: str):
        """Callback invoked by the scheduler when a scan is due."""
        from PyQt6.QtCore import QMetaObject, Q_ARG
        # Queue the scan on the main UI thread
        QMetaObject.invokeMethod(
            self, "_run_scan_from_scheduler",
            Qt.ConnectionType.QueuedConnection,
            Q_ARG(str, target),
            Q_ARG(str, label),
        )


def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    window = NetscanApp()
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
