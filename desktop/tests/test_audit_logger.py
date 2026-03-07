"""
Tests: AuditLogger
"""
import sys, os, json, tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))


def test_audit_chain_integrity(tmp_path, monkeypatch):
    """Log 5 events and verify the HMAC chain is intact."""
    log_file = tmp_path / "audit.log"
    monkeypatch.setenv("AUDIT_LOG_PATH", str(log_file))
    monkeypatch.setenv("AUDIT_HMAC_KEY", "0" * 64)

    from desktop.modules.audit_logger import AuditLogger
    logger = AuditLogger(str(log_file), hmac_key=bytes.fromhex("0" * 64))

    for i in range(5):
        logger.log_event("wipe_complete", {"cert_id": f"cert-{i}", "standard": "test"})

    assert logger.verify_chain()


def test_tampered_log_fails_verification(tmp_path, monkeypatch):
    """Modify a log entry and confirm chain verification fails."""
    log_file = tmp_path / "audit.log"
    from desktop.modules.audit_logger import AuditLogger
    logger = AuditLogger(str(log_file), hmac_key=b"x" * 32)

    logger.log_event("wipe_complete", {"cert_id": "abc"})
    logger.log_event("registry_upload", {"cert_id": "abc"})

    # Tamper: overwrite middle of file
    content = log_file.read_text()
    lines = content.strip().split("\n")
    if len(lines) >= 1:
        entry = json.loads(lines[0])
        entry["data"]["cert_id"] = "TAMPERED"
        lines[0] = json.dumps(entry)
    log_file.write_text("\n".join(lines) + "\n")

    assert not logger.verify_chain()