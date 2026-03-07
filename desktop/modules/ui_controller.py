"""
=============================================================================
Module: UIController
Purpose: Main PyQt6 application window. Provides the IT admin interface for
         selecting targets, choosing wipe standards, monitoring progress, and
         viewing/exporting certificates. Orchestrates all other modules.
Inputs:  User actions via PyQt6 signals
Outputs: Drives SecureWipeEngine, CertificateBuilder, DigitalSigner,
         PDFRenderer, RegistryClient, AuditLogger, ReportExporter
Dependencies: PyQt6 (pip), all desktop modules
=============================================================================
"""

import os
import sys
import threading
from pathlib import Path
from typing import List, Optional

try:
    from PyQt6.QtWidgets import (
        QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
        QPushButton, QLabel, QFileDialog, QComboBox,
        QProgressBar, QTextEdit, QTableWidget, QTableWidgetItem,
        QHeaderView, QMessageBox, QStatusBar, QGroupBox,
        QCheckBox, QLineEdit, QTabWidget, QSplitter,
        QFrame, QApplication,
    )
    from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
    from PyQt6.QtGui import QFont, QColor, QPalette, QIcon
    HAS_QT = True
except ImportError:
    HAS_QT = False

from .secure_wipe_engine import SecureWipeEngine, WipeStandard
from .hash_verifier import HashVerifier
from .file_scanner import FileScanner
from .certificate_builder import CertificateBuilder
from .digital_signer import DigitalSigner
from .compliance_mapper import ComplianceMapper
from .audit_logger import AuditLogger, AuditEventType
from .key_manager import KeyManager
from .registry_client import RegistryClient
from .report_exporter import ReportExporter, ExportFormat


class WipeWorker(QThread if HAS_QT else threading.Thread):
    """
    Background worker that executes the full wipe pipeline.
    Runs in a separate thread to keep the UI responsive.
    Emits signals for progress updates and completion.
    """
    if HAS_QT:
        progress_updated = pyqtSignal(int, str)   # (percent, status_message)
        pass_completed   = pyqtSignal(int, int, bool)  # (pass_num, total, verified)
        wipe_completed   = pyqtSignal(dict)        # signed cert dict
        wipe_failed      = pyqtSignal(str)         # error message

    def __init__(self, targets: list, standard: WipeStandard, config: dict):
        if HAS_QT:
            super().__init__()
        else:
            super().__init__(daemon=True)
        self.targets = targets
        self.standard = standard
        self.config = config
        self._certificates = []

    def run(self):
        """Execute the full wipe pipeline for all targets."""
        try:
            scanner = FileScanner()
            hasher = HashVerifier()
            wiper = SecureWipeEngine()
            mapper = ComplianceMapper()
            builder = CertificateBuilder(
                organization=self.config.get("organization", "Unknown Org"),
                portal_domain=self.config.get("portal_domain", "https://verify.example.com"),
                public_key_url=self.config.get("public_key_url", ""),
                public_key_fingerprint=self.config.get("public_key_fingerprint", ""),
            )
            signer = DigitalSigner()
            key_mgr = KeyManager()

            total = len(self.targets)

            for idx, target_path in enumerate(self.targets):
                # Step 1: Scan target
                if HAS_QT:
                    self.progress_updated.emit(
                        int((idx / total) * 10),
                        f"Scanning {target_path}..."
                    )
                scan = scanner.scan(target_path)
                if not scan.entries:
                    continue
                entry = scan.entries[0]

                # Step 2: Pre-wipe hash
                if HAS_QT:
                    self.progress_updated.emit(
                        int((idx / total) * 10 + 5),
                        f"Computing pre-wipe hash for {Path(target_path).name}..."
                    )
                if entry.type == "file":
                    hash_before = hasher.hash_file(target_path)
                else:
                    hash_before = hasher.hash_directory(target_path)

                # Step 3: Wipe
                def progress_cb(pass_num, total_passes, bytes_done, total_bytes):
                    pct = int((idx / total) * 100 + (bytes_done / total_bytes) * (100 / total))
                    if HAS_QT:
                        self.progress_updated.emit(
                            min(pct, 95),
                            f"Wiping {Path(target_path).name} — Pass {pass_num}/{total_passes} "
                            f"({bytes_done/1024/1024:.1f} MB / {total_bytes/1024/1024:.1f} MB)"
                        )

                if entry.type == "file":
                    wipe_result = wiper.wipe(target_path, self.standard, progress_cb)
                else:
                    # Wipe each file in the folder sequentially
                    from .secure_wipe_engine import WipeResult, PassDetail
                    import time as _time
                    combined_passes = []
                    total_dur = 0.0
                    all_verified = True
                    for fpath in entry.children:
                        r = wiper.wipe(fpath, self.standard)
                        combined_passes.extend(r.pass_detail)
                        total_dur += r.duration_seconds
                        if not r.verified:
                            all_verified = False
                    wipe_result = WipeResult(
                        standard_applied=self.standard.value,
                        passes_completed=len(combined_passes),
                        passes_total=len(combined_passes),
                        pass_detail=combined_passes,
                        duration_seconds=total_dur,
                        verified=all_verified,
                        file_path=target_path,
                        file_size_bytes=entry.size_bytes,
                    )

                # Step 4: Post-wipe hash
                if entry.type == "file":
                    hash_after = hasher.hash_file(target_path)
                else:
                    hash_after = hasher.hash_directory(target_path)

                # Step 5: Compliance mapping
                compliance = mapper.map(
                    standard=self.standard,
                    media_type=entry.device_type,
                )

                # Step 6: Build certificate
                cert = builder.build(
                    file_entry=entry,
                    wipe_result=wipe_result,
                    hash_before=hash_before,
                    hash_after=hash_after,
                    compliance_mappings=compliance,
                    chain_position=idx + 1,
                )

                # Step 7: Sign
                private_key, public_pem, fingerprint = key_mgr.load_keypair(
                    key_name=self.config.get("key_name", "secureerase_signing"),
                    password=self.config.get("key_password"),
                )
                signed_cert = signer.sign(cert, private_key_pem=private_key.private_bytes(
                    encoding=__import__("cryptography.hazmat.primitives.serialization",
                                       fromlist=["Encoding"]).Encoding.PEM,
                    format=__import__("cryptography.hazmat.primitives.serialization",
                                      fromlist=["PrivateFormat"]).PrivateFormat.PKCS8,
                    encryption_algorithm=__import__(
                        "cryptography.hazmat.primitives.serialization",
                        fromlist=["NoEncryption"]
                    ).NoEncryption(),
                ))

                self._certificates.append(signed_cert)
                if HAS_QT:
                    self.progress_updated.emit(
                        int(((idx + 1) / total) * 100),
                        f"Completed: {Path(target_path).name}"
                    )
                    self.wipe_completed.emit(signed_cert)

        except Exception as exc:
            if HAS_QT:
                self.wipe_failed.emit(str(exc))
            else:
                raise


class UIController(QMainWindow if HAS_QT else object):
    """
    Main application window for SecureErase Pro.

    Layout:
    ┌─────────────────────────────────────────────────────────┐
    │  SecureErase Pro                        [Admin] [Settings]│
    ├───────────────┬─────────────────────────────────────────┤
    │               │  Target Files              [+ Add] [- Rm]│
    │  Standard:    │  ┌──────────────────────────────────────┐│
    │  [DoD 3-pass] │  │ /path/to/file.doc   12.3 MB  HDD    ││
    │               │  │ /path/to/folder/    450 MB   SSD  ⚠  ││
    │  [Start Wipe] │  └──────────────────────────────────────┘│
    │  [Cancel]     │  Progress: [████████░░░░] 67%  Pass 2/3  │
    │               ├─────────────────────────────────────────┤
    │  Queue: 0     │  Certificates | Log                       │
    │               │  [cert list / audit log table]           │
    └───────────────┴─────────────────────────────────────────┘
    """

    def __init__(self):
        if not HAS_QT:
            raise ImportError(
                "UIController requires PyQt6: pip install PyQt6"
            )
        super().__init__()
        self.setWindowTitle("SecureErase Pro v0.1.0")
        self.setMinimumSize(1000, 700)

        self._targets: List[str] = []
        self._certificates: List[dict] = []
        self._wipe_worker: Optional[WipeWorker] = None
        self._config = self._load_config()

        self._init_modules()
        self._init_ui()
        self._start_registry_retry_timer()

    def _init_modules(self):
        """Initialize core modules."""
        self.audit_logger = AuditLogger()
        self.key_manager = KeyManager()
        self.report_exporter = ReportExporter()

        # Ensure signing keys exist
        try:
            self.key_manager.load_keypair(
                key_name=self._config.get("key_name", "secureerase_signing")
            )
        except FileNotFoundError:
            from .key_manager import KeyType
            self.key_manager.generate_keypair(KeyType.RSA_4096)

        # Audit: app started
        self.audit_logger.log_event(AuditEventType.APP_STARTED, {
            "config_keys": list(self._config.keys()),
        })

        # Verify audit chain on startup
        chain_result = self.audit_logger.verify_chain()
        if not chain_result["valid"]:
            self.audit_logger.log_event(AuditEventType.CHAIN_BROKEN, chain_result)

    def _init_ui(self):
        """Build the main UI layout."""
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QHBoxLayout(central)

        # --- Left panel (controls) ---
        left_panel = QWidget()
        left_panel.setFixedWidth(200)
        left_layout = QVBoxLayout(left_panel)
        left_layout.setAlignment(Qt.AlignmentFlag.AlignTop)

        # Standard selector
        std_label = QLabel("Wipe Standard:")
        std_label.setFont(QFont("Arial", 9, QFont.Weight.Bold))
        self.standard_combo = QComboBox()
        for std in WipeStandard:
            self.standard_combo.addItem(std.value, std)
        # Default to DoD 3-pass
        for i in range(self.standard_combo.count()):
            if "3-pass" in self.standard_combo.itemText(i):
                self.standard_combo.setCurrentIndex(i)
                break

        # Action buttons
        self.start_btn = QPushButton("▶  Start Wipe")
        self.start_btn.setStyleSheet(
            "QPushButton { background-color: #1A237E; color: white; "
            "border-radius: 4px; padding: 8px; font-weight: bold; }"
            "QPushButton:hover { background-color: #283593; }"
            "QPushButton:disabled { background-color: #9E9E9E; }"
        )
        self.start_btn.clicked.connect(self._on_start_wipe)

        self.cancel_btn = QPushButton("✕  Cancel")
        self.cancel_btn.setEnabled(False)
        self.cancel_btn.clicked.connect(self._on_cancel_wipe)

        self.export_btn = QPushButton("⬇  Export Certs")
        self.export_btn.setEnabled(False)
        self.export_btn.clicked.connect(self._on_export_certs)

        # Queue status
        self.queue_label = QLabel("Pending uploads: 0")
        self.queue_label.setStyleSheet("color: #607D8B; font-size: 9px;")

        left_layout.addWidget(std_label)
        left_layout.addWidget(self.standard_combo)
        left_layout.addSpacing(12)
        left_layout.addWidget(self.start_btn)
        left_layout.addWidget(self.cancel_btn)
        left_layout.addSpacing(8)
        left_layout.addWidget(self.export_btn)
        left_layout.addSpacing(20)
        left_layout.addWidget(self.queue_label)

        # --- Right panel ---
        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)

        # Target files section
        target_group = QGroupBox("Target Files")
        target_group_layout = QVBoxLayout(target_group)

        target_btn_row = QHBoxLayout()
        add_file_btn = QPushButton("+ Add File")
        add_file_btn.clicked.connect(self._on_add_file)
        add_folder_btn = QPushButton("+ Add Folder")
        add_folder_btn.clicked.connect(self._on_add_folder)
        remove_btn = QPushButton("− Remove Selected")
        remove_btn.clicked.connect(self._on_remove_selected)
        target_btn_row.addWidget(add_file_btn)
        target_btn_row.addWidget(add_folder_btn)
        target_btn_row.addWidget(remove_btn)
        target_btn_row.addStretch()

        self.target_table = QTableWidget(0, 4)
        self.target_table.setHorizontalHeaderLabels(["Path", "Size", "Device", "Status"])
        self.target_table.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeMode.Stretch
        )
        self.target_table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows
        )

        target_group_layout.addLayout(target_btn_row)
        target_group_layout.addWidget(self.target_table)

        # Progress section
        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        self.status_label = QLabel("Ready")
        self.status_label.setStyleSheet("color: #607D8B;")

        # Bottom tabs: Certificates | Audit Log
        self.tabs = QTabWidget()

        self.cert_table = QTableWidget(0, 5)
        self.cert_table.setHorizontalHeaderLabels(
            ["Certificate ID", "Target", "Standard", "Issued At", "Verified"]
        )
        self.cert_table.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeMode.Stretch
        )
        self.cert_table.cellDoubleClicked.connect(self._on_cert_double_click)

        self.log_view = QTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setFont(QFont("Courier New", 8))

        self.tabs.addTab(self.cert_table, "Certificates")
        self.tabs.addTab(self.log_view, "Audit Log")

        right_layout.addWidget(target_group)
        right_layout.addWidget(self.progress_bar)
        right_layout.addWidget(self.status_label)
        right_layout.addWidget(self.tabs)

        main_layout.addWidget(left_panel)
        main_layout.addWidget(right_panel)

        # Status bar
        self.setStatusBar(QStatusBar())
        self.statusBar().showMessage("SecureErase Pro — Ready")

    def _on_add_file(self):
        """Open file picker and add selected files to target table."""
        paths, _ = QFileDialog.getOpenFileNames(
            self, "Select Files to Wipe", str(Path.home())
        )
        for path in paths:
            self._add_target(path)

    def _on_add_folder(self):
        """Open folder picker and add selected folder to target table."""
        path = QFileDialog.getExistingDirectory(
            self, "Select Folder to Wipe", str(Path.home())
        )
        if path:
            self._add_target(path)

    def _add_target(self, path: str):
        """Add a path to the target list and table."""
        if path in self._targets:
            return
        self._targets.append(path)

        row = self.target_table.rowCount()
        self.target_table.insertRow(row)

        # Get size
        try:
            from .file_scanner import FileScanner
            scan = FileScanner().scan(path)
            size_str = f"{scan.total_size_bytes / 1024 / 1024:.1f} MB"
            device = scan.entries[0].device_type if scan.entries else "?"
            warnings = len(scan.warnings)
        except Exception:
            size_str = "?"
            device = "?"
            warnings = 0

        self.target_table.setItem(row, 0, QTableWidgetItem(path))
        self.target_table.setItem(row, 1, QTableWidgetItem(size_str))
        device_item = QTableWidgetItem(device)
        if device in ("SSD", "NVMe"):
            device_item.setForeground(QColor("#E65100"))  # Orange warning
        self.target_table.setItem(row, 2, device_item)
        status = "⚠ Warnings" if warnings else "Ready"
        self.target_table.setItem(row, 3, QTableWidgetItem(status))

    def _on_remove_selected(self):
        """Remove selected rows from the target table."""
        selected_rows = sorted(
            set(idx.row() for idx in self.target_table.selectedIndexes()),
            reverse=True,
        )
        for row in selected_rows:
            path = self.target_table.item(row, 0).text()
            self._targets.remove(path)
            self.target_table.removeRow(row)

    def _on_start_wipe(self):
        """Start the wipe operation."""
        if not self._targets:
            QMessageBox.warning(self, "No Targets", "Add at least one file or folder to wipe.")
            return

        standard = self.standard_combo.currentData()

        # Confirm with user
        confirm = QMessageBox.question(
            self,
            "Confirm Wipe",
            f"This will permanently and irreversibly destroy {len(self._targets)} "
            f"target(s) using {standard.value}.\n\n"
            "This operation CANNOT be undone.\n\nProceed?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if confirm != QMessageBox.StandardButton.Yes:
            return

        self.start_btn.setEnabled(False)
        self.cancel_btn.setEnabled(True)
        self.progress_bar.setValue(0)

        self._wipe_worker = WipeWorker(self._targets.copy(), standard, self._config)
        self._wipe_worker.progress_updated.connect(self._on_progress_update)
        self._wipe_worker.wipe_completed.connect(self._on_cert_received)
        self._wipe_worker.wipe_failed.connect(self._on_wipe_failed)
        self._wipe_worker.finished.connect(self._on_wipe_finished)
        self._wipe_worker.start()

        self.audit_logger.log_event(AuditEventType.WIPE_STARTED, {
            "targets": self._targets,
            "standard": standard.value,
        })

    def _on_cancel_wipe(self):
        """Terminate the wipe worker."""
        if self._wipe_worker and self._wipe_worker.isRunning():
            self._wipe_worker.terminate()
            self._wipe_worker.wait(3000)
            self.status_label.setText("Wipe cancelled by operator.")
            self.audit_logger.log_event(AuditEventType.WIPE_FAILED, {
                "reason": "Cancelled by operator"
            })
        self.start_btn.setEnabled(True)
        self.cancel_btn.setEnabled(False)

    def _on_progress_update(self, percent: int, message: str):
        self.progress_bar.setValue(percent)
        self.status_label.setText(message)
        self.statusBar().showMessage(message)

    def _on_cert_received(self, cert: dict):
        """Received a completed, signed certificate from the worker."""
        self._certificates.append(cert)

        row = self.cert_table.rowCount()
        self.cert_table.insertRow(row)
        self.cert_table.setItem(row, 0, QTableWidgetItem(cert.get("certificate_id", "")))
        self.cert_table.setItem(row, 1, QTableWidgetItem(
            cert.get("target", {}).get("path", "")
        ))
        self.cert_table.setItem(row, 2, QTableWidgetItem(
            cert.get("wipe_operation", {}).get("standard_applied", "")
        ))
        self.cert_table.setItem(row, 3, QTableWidgetItem(cert.get("generated_at", "")))
        verified = cert.get("wipe_operation", {}).get("verified", False)
        v_item = QTableWidgetItem("✓ Yes" if verified else "✗ No")
        v_item.setForeground(QColor("#2ECC71" if verified else "#E74C3C"))
        self.cert_table.setItem(row, 4, v_item)

        self.export_btn.setEnabled(True)
        self.audit_logger.log_event(AuditEventType.CERTIFICATE_ISSUED, {
            "certificate_id": cert.get("certificate_id"),
            "standard": cert.get("wipe_operation", {}).get("standard_applied"),
        })

    def _on_wipe_failed(self, error: str):
        QMessageBox.critical(self, "Wipe Failed", f"An error occurred:\n\n{error}")
        self.audit_logger.log_event(AuditEventType.WIPE_FAILED, {"error": error})

    def _on_wipe_finished(self):
        self.start_btn.setEnabled(True)
        self.cancel_btn.setEnabled(False)
        self.progress_bar.setValue(100)
        self.status_label.setText(
            f"Complete — {len(self._certificates)} certificate(s) issued."
        )
        self.audit_logger.log_event(AuditEventType.WIPE_COMPLETED, {
            "certificates_issued": len(self._certificates),
        })

    def _on_export_certs(self):
        """Export all certificates to a ZIP archive."""
        export_dir = QFileDialog.getExistingDirectory(
            self, "Select Export Directory", str(Path.home() / "Desktop")
        )
        if not export_dir:
            return

        result = self.report_exporter.export_batch(
            certs=[(c, None) for c in self._certificates],
            output_dir=export_dir,
            export_format=ExportFormat.ZIP_BOTH,
        )
        QMessageBox.information(
            self,
            "Export Complete",
            f"Exported {result.file_count} certificate(s) to:\n{result.output_path}",
        )
        self.audit_logger.log_event(AuditEventType.EXPORT_COMPLETED, {
            "output_path": result.output_path,
            "file_count": result.file_count,
        })

    def _on_cert_double_click(self, row: int, col: int):
        """Show full certificate JSON in a dialog."""
        if row < len(self._certificates):
            import json as _json
            cert = self._certificates[row]
            dialog = QMessageBox(self)
            dialog.setWindowTitle(f"Certificate {cert.get('certificate_id', '')}")
            dialog.setText(
                f"<pre style='font-size:8px'>"
                f"{_json.dumps(cert, indent=2)[:2000]}..."
                f"</pre>"
            )
            dialog.exec()

    def _start_registry_retry_timer(self):
        """Start a background timer to retry pending registry uploads."""
        if self._config.get("portal_api_url") and self._config.get("portal_api_key"):
            self._registry_client = RegistryClient(
                api_url=self._config["portal_api_url"],
                api_key=self._config["portal_api_key"],
            )
            self._retry_timer = QTimer()
            self._retry_timer.setInterval(5 * 60 * 1000)  # 5 minutes
            self._retry_timer.timeout.connect(self._on_retry_timer)
            self._retry_timer.start()
        else:
            self._registry_client = None

    def _on_retry_timer(self):
        """Background retry of pending registry uploads."""
        if self._registry_client:
            count = self._registry_client.get_queue_count()
            self.queue_label.setText(f"Pending uploads: {count}")
            if count > 0:
                threading.Thread(
                    target=self._registry_client.retry_pending, daemon=True
                ).start()

    def _load_config(self) -> dict:
        """Load application config from a JSON file or environment variables."""
        config_path = Path.home() / ".secureerase" / "config.json"
        if config_path.exists():
            import json as _json
            with open(config_path) as f:
                return _json.load(f)
        return {
            "organization": os.getenv("SECUREERASE_ORG", "My Organization"),
            "portal_domain": os.getenv("SECUREERASE_PORTAL", "https://verify.example.com"),
            "public_key_url": os.getenv("SECUREERASE_PUBKEY_URL", ""),
            "public_key_fingerprint": os.getenv("SECUREERASE_PUBKEY_FP", ""),
            "portal_api_url": os.getenv("SECUREERASE_API_URL", ""),
            "portal_api_key": os.getenv("SECUREERASE_API_KEY", ""),
            "key_name": "secureerase_signing",
            "key_password": None,
        }
