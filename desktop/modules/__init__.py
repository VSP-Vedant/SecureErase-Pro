"""
SecureErase Pro — Desktop Application Modules

Import order matters due to cross-module dependencies:
  hash_verifier, secure_wipe_engine, ssd_handler → (no internal deps)
  compliance_mapper → secure_wipe_engine
  file_scanner → (no internal deps)
  certificate_builder → hash_verifier, secure_wipe_engine, compliance_mapper
  digital_signer → certificate_builder
  audit_logger → (no internal deps)
  key_manager → (no internal deps)
  pdf_renderer → (no internal deps)
  registry_client → (no internal deps)
  report_exporter → (no internal deps)
  ui_controller → all of the above
"""

from .hash_verifier import HashVerifier, HashResult
from .secure_wipe_engine import SecureWipeEngine, WipeStandard, WipeResult, PassDetail
from .ssd_handler import SSDHandler, SSDEraseMethod, SSDEraseResult
from .compliance_mapper import ComplianceMapper, ComplianceMapping, DataClassification
from .file_scanner import FileScanner, FileEntry, ScanResult
from .certificate_builder import CertificateBuilder
from .digital_signer import DigitalSigner, SignatureAlgorithm
from .audit_logger import AuditLogger, AuditEventType, AuditEntry
from .key_manager import KeyManager, KeyType, KeyPairInfo
from .pdf_renderer import PDFRenderer
from .registry_client import RegistryClient, RegistrationResult
from .report_exporter import ReportExporter, ExportFormat, ExportResult

__all__ = [
    "HashVerifier", "HashResult",
    "SecureWipeEngine", "WipeStandard", "WipeResult", "PassDetail",
    "SSDHandler", "SSDEraseMethod", "SSDEraseResult",
    "ComplianceMapper", "ComplianceMapping", "DataClassification",
    "FileScanner", "FileEntry", "ScanResult",
    "CertificateBuilder",
    "DigitalSigner", "SignatureAlgorithm",
    "AuditLogger", "AuditEventType", "AuditEntry",
    "KeyManager", "KeyType", "KeyPairInfo",
    "PDFRenderer",
    "RegistryClient", "RegistrationResult",
    "ReportExporter", "ExportFormat", "ExportResult",
]
