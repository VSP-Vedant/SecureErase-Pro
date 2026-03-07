"""
=============================================================================
Module: ComplianceMapper
Purpose: Map a completed wipe operation to all applicable compliance
         frameworks and standards. Returns a structured list of
         ComplianceMapping objects that populate the 'compliance_mapping'
         array in the JSON certificate.
Inputs:  WipeStandard enum, media type ('HDD'|'SSD'|'NVMe'), data
         classification level (optional), SSD erase method (optional)
Outputs: List[ComplianceMapping]
Dependencies: None (pure Python; uses static mapping from Phase 2 matrix)
Compliance: All frameworks in Phase 2 matrix
=============================================================================
"""

from dataclasses import dataclass, asdict
from enum import Enum
from typing import List, Optional

from .secure_wipe_engine import WipeStandard


class DataClassification(str, Enum):
    """Data sensitivity classification levels used by enterprise policies."""
    UNCLASSIFIED    = "unclassified"
    INTERNAL        = "internal"
    CONFIDENTIAL    = "confidential"
    SECRET          = "secret"
    TOP_SECRET      = "top_secret"
    PERSONAL_DATA   = "personal_data"   # GDPR-scope personal information
    PII             = "pii"             # Personally identifiable information
    PHI             = "phi"             # Protected health information
    CARDHOLDER_DATA = "cardholder_data" # PCI-DSS scope


@dataclass
class ComplianceMapping:
    """
    Single compliance framework mapping.
    Maps 1:1 to entries in the certificate 'compliance_mapping' array.
    """
    standard: str
    version: str
    control_reference: str
    satisfied: bool
    notes: str

    def to_dict(self) -> dict:
        return asdict(self)


# ---------------------------------------------------------------------------
# Master compliance mapping table.
# Structure: {WipeStandard: {framework_key: (satisfied_func, notes_func)}}
#
# Each framework entry is a tuple of:
#   - satisfied: bool or callable(media_type, classification) -> bool
#   - notes: str describing what this standard requires and any caveats
# ---------------------------------------------------------------------------

# Frameworks that are ALWAYS satisfied regardless of standard,
# as long as a documented wipe occurred with certificate evidence:
_ALWAYS_SATISFIED_FRAMEWORKS = {
    "SOC2_CC6_5": ComplianceMapping(
        standard="SOC 2",
        version="2017 Trust Services Criteria",
        control_reference="CC6.5",
        satisfied=True,
        notes="Logical and physical asset disposal documented with signed certificate.",
    ),
}

# Per-standard compliance mappings
_STANDARD_COMPLIANCE_MAP = {

    WipeStandard.NIST_800_88_CLEAR: {
        "NIST_800_88_CLEAR": ComplianceMapping(
            standard="NIST SP 800-88",
            version="Rev.1 (2014)",
            control_reference="Section 2.3 - Clear",
            satisfied=True,
            notes="Clear applied: logical technique using read/write commands. "
                  "Suitable for magnetic media and ATA HDDs. "
                  "NOT sufficient for SSDs — Purge required for flash storage.",
        ),
        "NIST_800_53_MP6": ComplianceMapping(
            standard="NIST SP 800-53 Rev.5",
            version="Rev.5",
            control_reference="MP-6",
            satisfied=True,
            notes="Media sanitized per NIST 800-88 Clear. Satisfies MP-6 for non-classified media.",
        ),
        "ISO_27001_A810": ComplianceMapping(
            standard="ISO/IEC 27001:2022",
            version="2022",
            control_reference="Annex A.8.10 - Information deletion",
            satisfied=True,
            notes="Deletion documented with signed certificate per A.8.10 requirements.",
        ),
        "GDPR_ART5_ART17": ComplianceMapping(
            standard="GDPR",
            version="2016/679",
            control_reference="Article 5(1)(e) storage limitation; Article 17 right to erasure",
            satisfied=True,
            notes="Data rendered inaccessible. Certificate provides demonstrable evidence "
                  "for compliance with erasure obligations under GDPR Articles 5 and 17.",
        ),
        "HIPAA_164_310": ComplianceMapping(
            standard="HIPAA",
            version="45 CFR",
            control_reference="§164.310(d)(2)(i) - Disposal",
            satisfied=True,
            notes="Electronic media sanitized. Certificate documents disposal of ePHI-bearing media.",
        ),
        "ISO_27040": ComplianceMapping(
            standard="ISO/IEC 27040",
            version="2015",
            control_reference="Section 5.4 - Media sanitization",
            satisfied=True,
            notes="Sanitization method documented with evidence per ISO/IEC 27040.",
        ),
    },

    WipeStandard.NIST_800_88_PURGE: {
        "NIST_800_88_PURGE": ComplianceMapping(
            standard="NIST SP 800-88",
            version="Rev.1 (2014)",
            control_reference="Section 2.4 - Purge",
            satisfied=True,
            notes="Purge applied via hardware command (ATA Secure Erase / NVMe Format --ses=2). "
                  "Suitable for SSDs, NVMe, and flash media. Satisfies Purge requirement.",
        ),
        "NIST_800_53_MP6": ComplianceMapping(
            standard="NIST SP 800-53 Rev.5",
            version="Rev.5",
            control_reference="MP-6",
            satisfied=True,
            notes="Media purged per NIST 800-88 Purge. Satisfies MP-6 for classified media on SSDs.",
        ),
        "ISO_27001_A810": ComplianceMapping(
            standard="ISO/IEC 27001:2022",
            version="2022",
            control_reference="Annex A.8.10 - Information deletion",
            satisfied=True,
            notes="Deletion documented with signed certificate per A.8.10 requirements.",
        ),
        "GDPR_ART5_ART17": ComplianceMapping(
            standard="GDPR",
            version="2016/679",
            control_reference="Article 5(1)(e) storage limitation; Article 17 right to erasure",
            satisfied=True,
            notes="Data rendered inaccessible via hardware Purge. Certificate provides "
                  "demonstrable evidence for compliance with GDPR erasure obligations.",
        ),
        "HIPAA_164_310": ComplianceMapping(
            standard="HIPAA",
            version="45 CFR",
            control_reference="§164.310(d)(2)(i) - Disposal",
            satisfied=True,
            notes="Electronic media purged via hardware command. Certificate documents disposal.",
        ),
        "ISO_27040": ComplianceMapping(
            standard="ISO/IEC 27040",
            version="2015",
            control_reference="Section 5.4 - Media sanitization",
            satisfied=True,
            notes="Purge via hardware command satisfies ISO/IEC 27040 for flash media.",
        ),
    },

    WipeStandard.DOD_5220_22M_3PASS: {
        "DOD_5220_22M": ComplianceMapping(
            standard="DoD 5220.22-M",
            version="ECE 3-pass",
            control_reference="Chapter 8 - Clearing and Sanitization",
            satisfied=True,
            notes="3-pass DoD standard: 0x00, 0xFF, random with read-back verification.",
        ),
        "NIST_800_88_CLEAR": ComplianceMapping(
            standard="NIST SP 800-88",
            version="Rev.1 (2014)",
            control_reference="Section 2.3 - Clear",
            satisfied=True,
            notes="DoD 3-pass exceeds NIST 800-88 Clear requirements.",
        ),
        "NIST_800_53_MP6": ComplianceMapping(
            standard="NIST SP 800-53 Rev.5",
            version="Rev.5",
            control_reference="MP-6",
            satisfied=True,
            notes="Media sanitized to DoD standard; satisfies MP-6.",
        ),
        "ISO_27001_A810": ComplianceMapping(
            standard="ISO/IEC 27001:2022",
            version="2022",
            control_reference="Annex A.8.10",
            satisfied=True,
            notes="Deletion documented per A.8.10.",
        ),
        "GDPR_ART5_ART17": ComplianceMapping(
            standard="GDPR",
            version="2016/679",
            control_reference="Article 5(1)(e); Article 17",
            satisfied=True,
            notes="3-pass overwrite renders data irreversible. Certificate provides GDPR evidence.",
        ),
        "HIPAA_164_310": ComplianceMapping(
            standard="HIPAA",
            version="45 CFR",
            control_reference="§164.310(d)(2)(i)",
            satisfied=True,
            notes="DoD 3-pass sanitization satisfies HIPAA disposal requirements.",
        ),
        "PCI_DSS_9_4_6": ComplianceMapping(
            standard="PCI-DSS",
            version="v4.0",
            control_reference="Requirement 9.4.6",
            satisfied=True,
            notes="Electronic media with cardholder data rendered unrecoverable via DoD 3-pass.",
        ),
        "CCPA": ComplianceMapping(
            standard="CCPA",
            version="Cal. Civ. Code §1798.105",
            control_reference="Consumer deletion obligation",
            satisfied=True,
            notes="Consumer PI deleted via DoD 3-pass. Certificate supports audit obligation.",
        ),
        "ISO_27040": ComplianceMapping(
            standard="ISO/IEC 27040",
            version="2015",
            control_reference="Section 5.4",
            satisfied=True,
            notes="Sanitization method and evidence documented per ISO/IEC 27040.",
        ),
    },

    WipeStandard.GUTMANN_35PASS: {
        "GUTMANN": ComplianceMapping(
            standard="Gutmann 35-pass",
            version="1996",
            control_reference="Peter Gutmann - USENIX Security 1996",
            satisfied=True,
            notes="35-pass pattern covering MFM/RLL encoding residues. "
                  "Note: Gutmann himself acknowledged that passes 5–31 are "
                  "only relevant for specific pre-2001 encoding schemes. "
                  "For modern drives, DoD 7-pass or NIST Purge is sufficient.",
        ),
        "NIST_800_88_CLEAR": ComplianceMapping(
            standard="NIST SP 800-88", version="Rev.1 (2014)",
            control_reference="Section 2.3 - Clear", satisfied=True,
            notes="Gutmann 35-pass far exceeds NIST 800-88 Clear requirements.",
        ),
        "NIST_800_53_MP6": ComplianceMapping(
            standard="NIST SP 800-53 Rev.5", version="Rev.5",
            control_reference="MP-6", satisfied=True,
            notes="Gutmann 35-pass satisfies MP-6.",
        ),
        "ISO_27001_A810": ComplianceMapping(
            standard="ISO/IEC 27001:2022", version="2022",
            control_reference="Annex A.8.10", satisfied=True,
            notes="Deletion documented per A.8.10.",
        ),
        "GDPR_ART5_ART17": ComplianceMapping(
            standard="GDPR", version="2016/679",
            control_reference="Article 5(1)(e); Article 17", satisfied=True,
            notes="Gutmann 35-pass renders data irreversibly inaccessible.",
        ),
        "HIPAA_164_310": ComplianceMapping(
            standard="HIPAA", version="45 CFR",
            control_reference="§164.310(d)(2)(i)", satisfied=True,
            notes="35-pass sanitization satisfies HIPAA disposal requirements.",
        ),
        "PCI_DSS_9_4_6": ComplianceMapping(
            standard="PCI-DSS", version="v4.0",
            control_reference="Requirement 9.4.6", satisfied=True,
            notes="35-pass erasure renders cardholder data unrecoverable.",
        ),
        "CCPA": ComplianceMapping(
            standard="CCPA", version="Cal. Civ. Code §1798.105",
            control_reference="Consumer deletion obligation", satisfied=True,
            notes="Gutmann 35-pass satisfies CCPA deletion obligations.",
        ),
        "ISO_27040": ComplianceMapping(
            standard="ISO/IEC 27040", version="2015",
            control_reference="Section 5.4", satisfied=True,
            notes="Method and evidence documented per ISO/IEC 27040.",
        ),
    },

    WipeStandard.SCHNEIER_7PASS: {
        "SCHNEIER": ComplianceMapping(
            standard="Schneier 7-pass",
            version="Applied Cryptography, 1996",
            control_reference="Bruce Schneier - Applied Cryptography",
            satisfied=True,
            notes="7-pass: 0x00, 0xFF, then 5 passes of cryptographically random data.",
        ),
        "NIST_800_88_CLEAR": ComplianceMapping(
            standard="NIST SP 800-88", version="Rev.1 (2014)",
            control_reference="Section 2.3 - Clear", satisfied=True,
            notes="Schneier 7-pass exceeds NIST 800-88 Clear.",
        ),
        "NIST_800_53_MP6": ComplianceMapping(
            standard="NIST SP 800-53 Rev.5", version="Rev.5",
            control_reference="MP-6", satisfied=True, notes="Satisfies MP-6.",
        ),
        "ISO_27001_A810": ComplianceMapping(
            standard="ISO/IEC 27001:2022", version="2022",
            control_reference="Annex A.8.10", satisfied=True,
            notes="Documented per A.8.10.",
        ),
        "GDPR_ART5_ART17": ComplianceMapping(
            standard="GDPR", version="2016/679",
            control_reference="Article 5(1)(e); Article 17", satisfied=True,
            notes="7-pass renders data irreversible under GDPR.",
        ),
        "HIPAA_164_310": ComplianceMapping(
            standard="HIPAA", version="45 CFR",
            control_reference="§164.310(d)(2)(i)", satisfied=True,
            notes="Satisfies HIPAA disposal.",
        ),
        "PCI_DSS_9_4_6": ComplianceMapping(
            standard="PCI-DSS", version="v4.0",
            control_reference="Requirement 9.4.6", satisfied=True,
            notes="7-pass renders CHD unrecoverable.",
        ),
        "CCPA": ComplianceMapping(
            standard="CCPA", version="Cal. Civ. Code §1798.105",
            control_reference="Consumer deletion obligation", satisfied=True,
            notes="Satisfies CCPA deletion obligations.",
        ),
        "ISO_27040": ComplianceMapping(
            standard="ISO/IEC 27040", version="2015",
            control_reference="Section 5.4", satisfied=True,
            notes="Documented per ISO/IEC 27040.",
        ),
    },

    WipeStandard.AFSSI_5020: {
        "AFSSI_5020": ComplianceMapping(
            standard="AFSSI-5020",
            version="Air Force System Security Instruction 5020",
            control_reference="Section 3 - Sanitization",
            satisfied=True,
            notes="3-pass USAF standard: 0x00, 0xFF, random.",
        ),
        "NIST_800_88_CLEAR": ComplianceMapping(
            standard="NIST SP 800-88", version="Rev.1 (2014)",
            control_reference="Section 2.3 - Clear", satisfied=True,
            notes="AFSSI-5020 satisfies NIST 800-88 Clear.",
        ),
        "NIST_800_53_MP6": ComplianceMapping(
            standard="NIST SP 800-53 Rev.5", version="Rev.5",
            control_reference="MP-6", satisfied=True, notes="Satisfies MP-6.",
        ),
        "ISO_27001_A810": ComplianceMapping(
            standard="ISO/IEC 27001:2022", version="2022",
            control_reference="Annex A.8.10", satisfied=True, notes="Documented per A.8.10.",
        ),
        "GDPR_ART5_ART17": ComplianceMapping(
            standard="GDPR", version="2016/679",
            control_reference="Article 5(1)(e); Article 17", satisfied=True,
            notes="3-pass erasure satisfies GDPR deletion evidence requirement.",
        ),
        "HIPAA_164_310": ComplianceMapping(
            standard="HIPAA", version="45 CFR",
            control_reference="§164.310(d)(2)(i)", satisfied=True, notes="Satisfies HIPAA disposal.",
        ),
    },

    WipeStandard.AR_380_19: {
        "AR_380_19": ComplianceMapping(
            standard="AR 380-19",
            version="Army Regulation 380-19",
            control_reference="Appendix F - Media Sanitization",
            satisfied=True,
            notes="US Army 3-pass: random, random, 0x97. Used for classified system media.",
        ),
        "NIST_800_88_CLEAR": ComplianceMapping(
            standard="NIST SP 800-88", version="Rev.1 (2014)",
            control_reference="Section 2.3 - Clear", satisfied=True,
            notes="AR 380-19 satisfies NIST 800-88 Clear.",
        ),
        "NIST_800_53_MP6": ComplianceMapping(
            standard="NIST SP 800-53 Rev.5", version="Rev.5",
            control_reference="MP-6", satisfied=True, notes="Satisfies MP-6.",
        ),
    },

    WipeStandard.NAVSO_P5239_26: {
        "NAVSO_P5239_26": ComplianceMapping(
            standard="NAVSO P-5239-26",
            version="Department of the Navy",
            control_reference="Section 3 - Sanitization Procedures",
            satisfied=True,
            notes="US Navy 3-pass: 0x01, 0x27FFFFFF, random.",
        ),
        "NIST_800_53_MP6": ComplianceMapping(
            standard="NIST SP 800-53 Rev.5", version="Rev.5",
            control_reference="MP-6", satisfied=True, notes="Satisfies MP-6.",
        ),
    },

    WipeStandard.HMG_IS5_BASELINE: {
        "HMG_IS5_BASELINE": ComplianceMapping(
            standard="HMG IS5",
            version="Infosec Standard 5 - Baseline",
            control_reference="UK NCSC - Baseline",
            satisfied=True,
            notes="UK Government baseline: single zero-write. "
                  "For OFFICIAL classification tier.",
        ),
        "ISO_27001_A810": ComplianceMapping(
            standard="ISO/IEC 27001:2022", version="2022",
            control_reference="Annex A.8.10", satisfied=True, notes="Documented per A.8.10.",
        ),
        "GDPR_ART5_ART17": ComplianceMapping(
            standard="GDPR", version="2016/679",
            control_reference="Article 5(1)(e); Article 17", satisfied=True,
            notes="Single-pass zero-write with certificate provides GDPR erasure evidence.",
        ),
    },

    WipeStandard.HMG_IS5_ENHANCED: {
        "HMG_IS5_ENHANCED": ComplianceMapping(
            standard="HMG IS5",
            version="Infosec Standard 5 - Enhanced",
            control_reference="UK NCSC - Enhanced",
            satisfied=True,
            notes="UK Government enhanced: 3-pass (0x00, 0xFF, random) with read-back. "
                  "For SECRET classification tier.",
        ),
        "NIST_800_88_CLEAR": ComplianceMapping(
            standard="NIST SP 800-88", version="Rev.1 (2014)",
            control_reference="Section 2.3 - Clear", satisfied=True,
            notes="HMG IS5 Enhanced satisfies NIST 800-88 Clear.",
        ),
        "ISO_27001_A810": ComplianceMapping(
            standard="ISO/IEC 27001:2022", version="2022",
            control_reference="Annex A.8.10", satisfied=True, notes="Documented per A.8.10.",
        ),
        "GDPR_ART5_ART17": ComplianceMapping(
            standard="GDPR", version="2016/679",
            control_reference="Article 5(1)(e); Article 17", satisfied=True,
            notes="3-pass satisfies GDPR erasure evidence requirement.",
        ),
    },

    WipeStandard.DOD_5220_22M_7PASS: {
        "DOD_5220_22M_7PASS": ComplianceMapping(
            standard="DoD 5220.22-M",
            version="NISPOM 7-pass",
            control_reference="Chapter 8 - ECE variant",
            satisfied=True,
            notes="7-pass DoD: 0x00, 0xFF, random, 0x96, 0x00, 0xFF, random.",
        ),
        "NIST_800_88_CLEAR": ComplianceMapping(
            standard="NIST SP 800-88", version="Rev.1 (2014)",
            control_reference="Section 2.3 - Clear", satisfied=True,
            notes="DoD 7-pass far exceeds NIST 800-88 Clear.",
        ),
        "NIST_800_53_MP6": ComplianceMapping(
            standard="NIST SP 800-53 Rev.5", version="Rev.5",
            control_reference="MP-6", satisfied=True, notes="Satisfies MP-6.",
        ),
        "ISO_27001_A810": ComplianceMapping(
            standard="ISO/IEC 27001:2022", version="2022",
            control_reference="Annex A.8.10", satisfied=True, notes="Documented per A.8.10.",
        ),
        "GDPR_ART5_ART17": ComplianceMapping(
            standard="GDPR", version="2016/679",
            control_reference="Article 5(1)(e); Article 17", satisfied=True,
            notes="7-pass renders data irreversible under GDPR.",
        ),
        "HIPAA_164_310": ComplianceMapping(
            standard="HIPAA", version="45 CFR",
            control_reference="§164.310(d)(2)(i)", satisfied=True,
            notes="Satisfies HIPAA disposal.",
        ),
        "PCI_DSS_9_4_6": ComplianceMapping(
            standard="PCI-DSS", version="v4.0",
            control_reference="Requirement 9.4.6", satisfied=True,
            notes="7-pass renders CHD unrecoverable.",
        ),
        "CCPA": ComplianceMapping(
            standard="CCPA", version="Cal. Civ. Code §1798.105",
            control_reference="Consumer deletion obligation", satisfied=True,
            notes="Satisfies CCPA deletion obligations.",
        ),
        "ISO_27040": ComplianceMapping(
            standard="ISO/IEC 27040", version="2015",
            control_reference="Section 5.4", satisfied=True,
            notes="Documented per ISO/IEC 27040.",
        ),
    },

    WipeStandard.ZERO_FILL: {
        "ZERO_FILL": ComplianceMapping(
            standard="Single-pass zero-write",
            version="N/A",
            control_reference="Fast wipe — not a formal standard",
            satisfied=True,
            notes="Single zero-write pass. Suitable for non-sensitive data disposal. "
                  "NOT recommended for sensitive, classified, or regulated data. "
                  "Certificate explicitly notes this limitation.",
        ),
        "GDPR_ART5_ART17": ComplianceMapping(
            standard="GDPR",
            version="2016/679",
            control_reference="Article 5(1)(e); Article 17",
            satisfied=True,
            notes="Single-pass zero-write may satisfy GDPR for low-sensitivity data. "
                  "For HIGH sensitivity PII, use DoD 3-pass or NIST Purge.",
        ),
    },
}


class ComplianceMapper:
    """
    Maps a completed wipe operation to all applicable compliance frameworks.

    Usage:
        mapper = ComplianceMapper()
        mappings = mapper.map(
            standard=WipeStandard.DOD_5220_22M_3PASS,
            media_type="HDD",
            classification=DataClassification.PII,
        )
    """

    def map(
        self,
        standard: WipeStandard,
        media_type: str = "HDD",
        classification: Optional[DataClassification] = None,
    ) -> List[ComplianceMapping]:
        """
        Return list of ComplianceMapping objects for the given wipe operation.

        Args:
            standard: The WipeStandard that was applied.
            media_type: 'HDD', 'SSD', 'NVMe', or 'unknown'.
            classification: Optional data classification of the wiped target.

        Returns:
            List[ComplianceMapping] — all applicable frameworks and their
            satisfaction status for this operation.
        """
        base_mappings = dict(_STANDARD_COMPLIANCE_MAP.get(standard, {}))

        # Always include SOC 2 CC6.5 since we generate a certificate
        base_mappings["SOC2_CC6_5"] = ComplianceMapping(
            standard="SOC 2",
            version="2017 Trust Services Criteria",
            control_reference="CC6.5",
            satisfied=True,
            notes="Logical asset disposal documented with signed certificate.",
        )

        # SSD caveat: software multi-pass does NOT satisfy NIST Purge for SSDs.
        # Downgrade any NIST_800_88_CLEAR mapping if media is SSD and method
        # is software-only (not SSDHandler hardware Purge).
        if media_type in ("SSD", "NVMe") and standard != WipeStandard.NIST_800_88_CLEAR:
            if "NIST_800_88_CLEAR" in base_mappings:
                m = base_mappings["NIST_800_88_CLEAR"]
                base_mappings["NIST_800_88_CLEAR"] = ComplianceMapping(
                    standard=m.standard,
                    version=m.version,
                    control_reference=m.control_reference,
                    satisfied=False,
                    notes=(
                        "WARNING: Software multi-pass wipe on SSD/NVMe does NOT "
                        "satisfy NIST SP 800-88 Rev.1 Purge. Use SSDHandler with "
                        "ATA Secure Erase or NVMe Format --ses=2 for SSD Purge compliance."
                    ),
                )

        # PCI-DSS note for cardholder data
        if classification == DataClassification.CARDHOLDER_DATA:
            if "PCI_DSS_9_4_6" not in base_mappings:
                base_mappings["PCI_DSS_9_4_6"] = ComplianceMapping(
                    standard="PCI-DSS",
                    version="v4.0",
                    control_reference="Requirement 9.4.6",
                    satisfied=(standard in {
                        WipeStandard.DOD_5220_22M_3PASS,
                        WipeStandard.DOD_5220_22M_7PASS,
                        WipeStandard.GUTMANN_35PASS,
                        WipeStandard.SCHNEIER_7PASS,
                    }),
                    notes="PCI-DSS Req. 9.4.6: electronic media with CHD must be rendered "
                          "unrecoverable. Multi-pass overwrite standards satisfy this requirement.",
                )

        # GDPR enforcement for personal/PII data — ensure GDPR is always present
        if classification in (
            DataClassification.PERSONAL_DATA,
            DataClassification.PII,
            DataClassification.PHI,
        ):
            if "GDPR_ART5_ART17" not in base_mappings:
                base_mappings["GDPR_ART5_ART17"] = ComplianceMapping(
                    standard="GDPR",
                    version="2016/679",
                    control_reference="Article 5(1)(e); Article 17",
                    satisfied=True,
                    notes="Personal data rendered inaccessible. Certificate provides "
                          "demonstrable evidence of erasure for GDPR compliance.",
                )

        return list(base_mappings.values())


# ---------------------------------------------------------------------------
# Module-level constants and convenience functions
# ---------------------------------------------------------------------------

# STANDARDS: list of all WipeStandard enum values — useful for UI dropdowns
# and test parametrize decorators.
STANDARDS = list(WipeStandard)

_default_mapper = ComplianceMapper()


def map_to_frameworks(
    standard,
    media_type: str = "HDD",
    classification=None,
) -> list:
    """
    Module-level wrapper: map a wipe standard to compliance frameworks.
    Accepts WipeStandard enum OR a string value.
    Returns a list of dicts (not dataclass instances) for easy test/JSON use.
    Unknown standards return an empty list.
    """
    # Coerce string → WipeStandard enum; return [] for unknown values
    if not isinstance(standard, WipeStandard):
        try:
            standard = WipeStandard(standard)
        except ValueError:
            return []

    # Normalize media_type casing
    media_norm = media_type.upper() if media_type else "HDD"
    if media_norm not in ("HDD", "SSD", "NVME", "UNKNOWN"):
        media_norm = "HDD"

    # Normalize classification
    cls_norm = None
    if classification:
        try:
            cls_norm = DataClassification(classification)
        except ValueError:
            # Map plain strings like "personal_data" → enum
            _map = {
                "personal_data": DataClassification.PERSONAL_DATA,
                "pii": DataClassification.PII,
                "general": None,
                "confidential": DataClassification.CONFIDENTIAL,
                "cardholder_data": DataClassification.CARDHOLDER_DATA,
                "phi": DataClassification.PHI,
            }
            cls_norm = _map.get(str(classification).lower())

    results = _default_mapper.map(
        standard=standard,
        media_type=media_norm,
        classification=cls_norm,
    )
    # Return list of dicts for easy subscript access in tests and JSON serialization
    return [r.to_dict() for r in results]
