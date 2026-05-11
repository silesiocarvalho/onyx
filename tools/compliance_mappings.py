"""
compliance_mappings.py
Static crosswalk: CIS Check Point Benchmark v1.1.0 → NIST CSF 2.0,
ISO/IEC 27001:2022, PCI DSS v4.0.1, MITRE ATT&CK v15.

Source PDFs live in security-compliance/ for reference.
Mappings are curated by hand against published crosswalks.
"""

FRAMEWORKS: dict[str, dict] = {
    "nist_csf": {
        "id":      "nist_csf",
        "name":    "NIST CSF 2.0",
        "version": "2.0",
        "abbr":    "NIST",
    },
    "iso_27001": {
        "id":      "iso_27001",
        "name":    "ISO/IEC 27001:2022",
        "version": "2022",
        "abbr":    "ISO",
    },
    "pci_dss": {
        "id":      "pci_dss",
        "name":    "PCI DSS",
        "version": "v4.0.1",
        "abbr":    "PCI",
    },
    "mitre_attack": {
        "id":      "mitre_attack",
        "name":    "MITRE ATT&CK",
        "version": "v15",
        "abbr":    "ATT&CK",
    },
    "gdpr": {
        "id":      "gdpr",
        "name":    "GDPR",
        "version": "2018",
        "abbr":    "GDPR",
    },
    "hipaa": {
        "id":      "hipaa",
        "name":    "HIPAA Security Rule",
        "version": "45 CFR Part 164",
        "abbr":    "HIPAA",
    },
    "soc2": {
        "id":      "soc2",
        "name":    "SOC 2 TSC",
        "version": "2017",
        "abbr":    "SOC2",
    },
}

NIST_CSF_LABELS: dict[str, str] = {
    "GV.PO-01": "Cybersecurity policy established",
    "ID.AM-01": "Hardware assets inventoried",
    "PR.AA-01": "Identities and credentials managed",
    "PR.AA-02": "Identities proofed and bound to credentials",
    "PR.AA-03": "Users and hardware authenticated",
    "PR.AA-05": "Access permissions managed (least privilege)",
    "PR.DS-02": "Data in transit protected",
    "PR.DS-11": "Backups created, protected, and tested",
    "PR.IR-01": "Networks protected from unauthorized access",
    "PR.IR-04": "Adequate resource capacity maintained",
    "PR.PS-01": "Configuration management performed",
    "PR.PS-04": "Log records generated for monitoring",
    "PR.PS-05": "Unauthorized software execution prevented",
    "DE.CM-01": "Networks monitored for adverse events",
    "DE.CM-03": "Computing activities monitored",
    "DE.AE-02": "Adverse events analyzed",
    "RC.RP-01": "Recovery plan executed after incident",
}

MITRE_ATTACK_LABELS: dict[str, str] = {
    "T1040":     "Network Sniffing",
    "T1046":     "Network Service Discovery",
    "T1070":     "Indicator Removal",
    "T1078":     "Valid Accounts",
    "T1098":     "Account Manipulation",
    "T1110":     "Brute Force",
    "T1133":     "External Remote Services",
    "T1190":     "Exploit Public-Facing Application",
    "T1499":     "Endpoint Denial of Service",
    "T1531":     "Account Access Removal",
    "T1552":     "Unsecured Credentials",
    "T1557":     "Adversary-in-the-Middle",
    "T1562":     "Impair Defenses",
    "T1562.001": "Impair Defenses: Disable or Modify Tools",
    "T1568":     "Dynamic Resolution",
    "T1599":     "Network Boundary Bridging",
}

# ---------------------------------------------------------------------------
# CIS Check Point Benchmark v1.1.0  →  framework controls
# ---------------------------------------------------------------------------
CHECKPOINT_CIS_MAPPINGS: dict[str, dict[str, list[str]]] = {

    # ── Section 1 — Account Management ────────────────────────────────────
    "1.1": {
        "nist_csf":     ["PR.AA-01", "PR.AA-05"],
        "iso_27001":    ["A.5.17", "A.8.5"],
        "pci_dss":      ["8.3.6"],
        "mitre_attack": ["T1110", "T1078"],
    },
    "1.2": {
        "nist_csf":     ["PR.AA-05"],
        "iso_27001":    ["A.5.17", "A.8.5"],
        "pci_dss":      ["8.3.6"],
        "mitre_attack": ["T1110"],
    },
    "1.3": {
        "nist_csf":     ["PR.AA-05"],
        "iso_27001":    ["A.5.17", "A.8.5"],
        "pci_dss":      ["8.3.6"],
        "mitre_attack": ["T1110"],
    },
    "1.4a": {
        "nist_csf":     ["PR.AA-05"],
        "iso_27001":    ["A.5.17"],
        "pci_dss":      ["8.3.7"],
        "mitre_attack": ["T1110"],
    },
    "1.4b": {
        "nist_csf":     ["PR.AA-05"],
        "iso_27001":    ["A.5.17"],
        "pci_dss":      ["8.3.7"],
        "mitre_attack": ["T1110"],
    },
    "1.5": {
        "nist_csf":     ["PR.AA-05"],
        "iso_27001":    ["A.5.17"],
        "pci_dss":      ["8.3.9"],
        "mitre_attack": ["T1078", "T1552"],
    },
    "1.6": {
        "nist_csf":     ["PR.AA-05"],
        "iso_27001":    ["A.5.17"],
        "pci_dss":      ["8.3.9"],
        "mitre_attack": ["T1078"],
    },
    "1.7": {
        "nist_csf":     ["PR.AA-05"],
        "iso_27001":    ["A.5.18"],
        "pci_dss":      ["8.2.6"],
        "mitre_attack": ["T1078"],
    },
    "1.8": {
        "nist_csf":     ["PR.AA-05"],
        "iso_27001":    ["A.5.18", "A.8.2"],
        "pci_dss":      ["8.2.5"],
        "mitre_attack": ["T1078", "T1098"],
    },
    "1.9": {
        "nist_csf":     ["PR.AA-05"],
        "iso_27001":    ["A.5.18", "A.8.2"],
        "pci_dss":      ["8.2.5"],
        "mitre_attack": ["T1078"],
    },
    "1.10": {
        "nist_csf":     ["PR.AA-05"],
        "iso_27001":    ["A.5.17"],
        "pci_dss":      ["8.2.3"],
        "mitre_attack": ["T1078", "T1552"],
    },
    "1.11": {
        "nist_csf":     ["PR.AA-02", "PR.AA-03"],
        "iso_27001":    ["A.8.5"],
        "pci_dss":      ["8.3.4"],
        "mitre_attack": ["T1110"],
    },
    "1.12": {
        "nist_csf":     ["PR.AA-02", "PR.AA-03"],
        "iso_27001":    ["A.8.5"],
        "pci_dss":      ["8.3.4"],
        "mitre_attack": ["T1110"],
    },
    "1.13": {
        "nist_csf":     ["PR.AA-02", "PR.AA-03"],
        "iso_27001":    ["A.8.5"],
        "pci_dss":      ["8.3.4"],
        "mitre_attack": ["T1110"],
    },

    # ── Section 2.1 — System Configuration ────────────────────────────────
    "2.1.1": {
        "nist_csf":     ["GV.PO-01"],
        "iso_27001":    ["A.5.1"],
        "pci_dss":      ["2.2.1"],
        "mitre_attack": ["T1078"],
    },
    "2.1.2": {
        "nist_csf":     ["GV.PO-01"],
        "iso_27001":    ["A.5.1"],
        "pci_dss":      ["2.2.1"],
        "mitre_attack": [],
    },
    "2.1.3": {
        "nist_csf":     ["DE.CM-03", "PR.PS-04"],
        "iso_27001":    ["A.8.15"],
        "pci_dss":      ["10.2.1"],
        "mitre_attack": ["T1562"],
    },
    "2.1.4": {
        "nist_csf":     ["PR.PS-01"],
        "iso_27001":    ["A.8.9"],
        "pci_dss":      ["2.2.1"],
        "mitre_attack": ["T1562.001"],
    },
    "2.1.5": {
        "nist_csf":     ["PR.PS-01", "ID.AM-01"],
        "iso_27001":    ["A.8.20", "A.8.22"],
        "pci_dss":      ["1.2.1"],
        "mitre_attack": ["T1133", "T1046"],
    },
    "2.1.6": {
        "nist_csf":     ["PR.PS-01"],
        "iso_27001":    ["A.8.20"],
        "pci_dss":      ["2.2.1"],
        "mitre_attack": ["T1568"],
    },
    "2.1.7": {
        "nist_csf":     ["PR.PS-01", "PR.IR-01"],
        "iso_27001":    ["A.8.20"],
        "pci_dss":      ["1.2.1"],
        "mitre_attack": ["T1133", "T1046"],
    },
    "2.1.8": {
        "nist_csf":     ["ID.AM-01", "PR.PS-01"],
        "iso_27001":    ["A.8.9"],
        "pci_dss":      ["2.2.1"],
        "mitre_attack": [],
    },
    "2.1.9": {
        "nist_csf":     ["PR.PS-01", "PR.IR-01"],
        "iso_27001":    ["A.8.20", "A.8.21"],
        "pci_dss":      ["2.2.7", "8.2.1"],
        "mitre_attack": ["T1021", "T1040", "T1552"],
    },
    "2.1.10": {
        "nist_csf":     ["PR.PS-01", "PR.IR-01"],
        "iso_27001":    ["A.8.20"],
        "pci_dss":      ["1.2.1"],
        "mitre_attack": ["T1557"],
    },

    # ── Section 2.2 — SNMP ────────────────────────────────────────────────
    "2.2.1": {
        "nist_csf":     ["PR.PS-01", "PR.AA-05"],
        "iso_27001":    ["A.8.20", "A.8.21"],
        "pci_dss":      ["2.2.1", "2.2.7"],
        "mitre_attack": ["T1040", "T1046", "T1562"],
    },
    "2.2.2": {
        "nist_csf":     ["PR.PS-01", "PR.DS-02"],
        "iso_27001":    ["A.8.20", "A.8.21"],
        "pci_dss":      ["2.2.7"],
        "mitre_attack": ["T1040", "T1046"],
    },
    "2.2.3": {
        "nist_csf":     ["DE.CM-01"],
        "iso_27001":    ["A.8.16"],
        "pci_dss":      ["10.7"],
        "mitre_attack": ["T1562"],
    },
    "2.2.4": {
        "nist_csf":     ["DE.CM-01"],
        "iso_27001":    ["A.8.16"],
        "pci_dss":      ["10.7"],
        "mitre_attack": ["T1562"],
    },

    # ── Section 2.3 — NTP / Time ───────────────────────────────────────────
    "2.3.1": {
        "nist_csf":     ["PR.PS-01"],
        "iso_27001":    ["A.8.17"],
        "pci_dss":      ["10.6.1"],
        "mitre_attack": ["T1070"],
    },
    "2.3.2": {
        "nist_csf":     ["PR.PS-01"],
        "iso_27001":    ["A.8.17"],
        "pci_dss":      ["10.6.2"],
        "mitre_attack": ["T1070"],
    },

    # ── Section 2.4 — Backup ──────────────────────────────────────────────
    "2.4.1": {
        "nist_csf":     ["PR.DS-11", "PR.IR-04", "RC.RP-01"],
        "iso_27001":    ["A.8.13"],
        "pci_dss":      ["12.3.4"],
        "mitre_attack": ["T1490"],
    },
    "2.4.3": {
        "nist_csf":     ["PR.DS-11", "PR.IR-04", "RC.RP-01"],
        "iso_27001":    ["A.8.13"],
        "pci_dss":      ["12.3.4"],
        "mitre_attack": ["T1490"],
    },

    # ── Section 2.5 — Session / Access / Auth ─────────────────────────────
    "2.5.1": {
        "nist_csf":     ["PR.AA-05"],
        "iso_27001":    ["A.8.3"],
        "pci_dss":      ["8.2.8"],
        "mitre_attack": ["T1078"],
    },
    "2.5.2": {
        "nist_csf":     ["PR.AA-05"],
        "iso_27001":    ["A.8.3"],
        "pci_dss":      ["8.2.8"],
        "mitre_attack": ["T1078"],
    },
    "2.5.3": {
        "nist_csf":     ["PR.DS-02"],
        "iso_27001":    ["A.8.24"],
        "pci_dss":      ["4.2.1"],
        "mitre_attack": ["T1040", "T1557"],
    },
    "2.5.4": {
        "nist_csf":     ["PR.AA-02", "PR.AA-05"],
        "iso_27001":    ["A.5.16", "A.8.5"],
        "pci_dss":      ["8.6.1"],
        "mitre_attack": ["T1078", "T1110"],
    },
    "2.5.5": {
        "nist_csf":     ["PR.AA-05", "PR.IR-01"],
        "iso_27001":    ["A.5.15", "A.8.3"],
        "pci_dss":      ["1.3.1", "7.2.1"],
        "mitre_attack": ["T1133", "T1021"],
    },

    # ── Section 2.6 — Logging ─────────────────────────────────────────────
    "2.6.1": {
        "nist_csf":     ["DE.CM-01", "PR.PS-04"],
        "iso_27001":    ["A.8.15"],
        "pci_dss":      ["10.2.1"],
        "mitre_attack": ["T1070", "T1562"],
    },
    "2.6.2": {
        "nist_csf":     ["DE.CM-01", "DE.AE-02"],
        "iso_27001":    ["A.8.15"],
        "pci_dss":      ["10.3.3"],
        "mitre_attack": ["T1070"],
    },
    "2.6.3": {
        "nist_csf":     ["DE.CM-01", "PR.PS-04"],
        "iso_27001":    ["A.8.15"],
        "pci_dss":      ["10.2.1"],
        "mitre_attack": ["T1070", "T1562"],
    },

    # ── Section 3 — Firewall Policy ───────────────────────────────────────
    "3.1": {
        "nist_csf":     ["PR.PS-05", "PR.IR-01"],
        "iso_27001":    ["A.8.20", "A.8.22"],
        "pci_dss":      ["1.3.1", "1.3.2"],
        "mitre_attack": ["T1133", "T1190"],
    },
    "3.2": {
        "nist_csf":     ["PR.PS-05", "PR.IR-01"],
        "iso_27001":    ["A.8.20"],
        "pci_dss":      ["1.3.1", "1.3.2"],
        "mitre_attack": ["T1133", "T1190"],
    },
    "3.3": {
        "nist_csf":     ["GV.PO-01", "PR.PS-01"],
        "iso_27001":    ["A.5.37"],
        "pci_dss":      ["1.2.1"],
        "mitre_attack": [],
    },
    "3.4": {
        "nist_csf":     ["DE.CM-01"],
        "iso_27001":    ["A.8.16"],
        "pci_dss":      ["10.4.1"],
        "mitre_attack": ["T1562"],
    },
    "3.5": {
        "nist_csf":     ["PR.AA-05", "PR.IR-01"],
        "iso_27001":    ["A.5.15", "A.8.3"],
        "pci_dss":      ["1.3.1", "7.2.1"],
        "mitre_attack": ["T1133", "T1190"],
    },
    "3.6": {
        "nist_csf":     ["PR.AA-05", "PR.IR-01"],
        "iso_27001":    ["A.5.15", "A.8.3"],
        "pci_dss":      ["1.3.1", "1.3.2"],
        "mitre_attack": ["T1133", "T1190"],
    },
    "3.7": {
        "nist_csf":     ["PR.AA-05", "PR.IR-01"],
        "iso_27001":    ["A.5.15", "A.8.3"],
        "pci_dss":      ["1.3.1"],
        "mitre_attack": ["T1046"],
    },
    "3.8": {
        "nist_csf":     ["DE.CM-01", "PR.PS-04"],
        "iso_27001":    ["A.8.15", "A.8.16"],
        "pci_dss":      ["10.2.1", "10.2.4"],
        "mitre_attack": ["T1070", "T1562"],
    },
    "3.9": {
        "nist_csf":     ["DE.CM-01", "PR.PS-04"],
        "iso_27001":    ["A.8.15"],
        "pci_dss":      ["10.2.1"],
        "mitre_attack": ["T1070"],
    },
    "3.10": {
        "nist_csf":     ["PR.PS-05", "PR.IR-01"],
        "iso_27001":    ["A.8.20", "A.8.21"],
        "pci_dss":      ["1.3.3"],
        "mitre_attack": ["T1499", "T1557"],
    },
    "3.11": {
        "nist_csf":     ["PR.PS-05", "PR.IR-01"],
        "iso_27001":    ["A.8.20", "A.8.21"],
        "pci_dss":      ["1.3.3"],
        "mitre_attack": ["T1499", "T1040"],
    },
    "3.12": {
        "nist_csf":     ["PR.PS-05", "PR.IR-01"],
        "iso_27001":    ["A.8.20"],
        "pci_dss":      ["1.3.3"],
        "mitre_attack": ["T1557", "T1599"],
    },
    "3.13": {
        "nist_csf":     ["DE.CM-01", "PR.IR-04"],
        "iso_27001":    ["A.8.6"],
        "pci_dss":      ["10.7.1"],
        "mitre_attack": ["T1499"],
    },
    "3.14": {
        "nist_csf":     ["PR.PS-05", "PR.IR-01"],
        "iso_27001":    ["A.8.20", "A.8.21"],
        "pci_dss":      ["1.2.1"],
        "mitre_attack": ["T1599", "T1557"],
    },
    "3.15": {
        "nist_csf":     ["PR.PS-05", "PR.IR-01"],
        "iso_27001":    ["A.8.20", "A.8.21"],
        "pci_dss":      ["1.2.1"],
        "mitre_attack": ["T1046"],
    },
    "3.16": {
        "nist_csf":     ["PR.PS-05", "PR.IR-01"],
        "iso_27001":    ["A.8.20", "A.8.21"],
        "pci_dss":      ["1.2.1"],
        "mitre_attack": ["T1046"],
    },
    "3.17": {
        "nist_csf":     ["PR.PS-05", "PR.IR-01"],
        "iso_27001":    ["A.8.20"],
        "pci_dss":      ["1.2.1"],
        "mitre_attack": ["T1046", "T1040"],
    },
    "3.18": {
        "nist_csf":     ["PR.PS-01", "PR.IR-01"],
        "iso_27001":    ["A.8.20"],
        "pci_dss":      ["1.3.1"],
        "mitre_attack": ["T1599"],
    },
    "3.19": {
        "nist_csf":     ["PR.PS-01", "PR.IR-01"],
        "iso_27001":    ["A.8.20"],
        "pci_dss":      ["1.3.1"],
        "mitre_attack": ["T1557"],
    },
    "3.20": {
        "nist_csf":     ["DE.CM-01", "DE.AE-02"],
        "iso_27001":    ["A.8.15", "A.8.16"],
        "pci_dss":      ["10.2.1", "10.7.1"],
        "mitre_attack": ["T1070", "T1562"],
    },
}


GDPR_LABELS: dict[str, str] = {
    "Art.5.1.f": "Integrity and confidentiality principle",
    "Art.25":    "Data protection by design and by default",
    "Art.32":    "Security of processing",
    "Art.33":    "Notification of personal data breach",
}

HIPAA_LABELS: dict[str, str] = {
    "§164.308(a)(1)":       "Security Management Process",
    "§164.308(a)(3)":       "Workforce Access Management",
    "§164.308(a)(5)":       "Security Awareness and Training",
    "§164.308(a)(7)":       "Contingency Plan",
    "§164.312(a)(1)":       "Access Control",
    "§164.312(a)(2)(iii)":  "Automatic Logoff",
    "§164.312(a)(2)(iv)":   "Encryption and Decryption",
    "§164.312(b)":          "Audit Controls",
    "§164.312(c)(1)":       "Integrity Controls",
    "§164.312(d)":          "Person or Entity Authentication",
    "§164.312(e)(1)":       "Transmission Security",
}

SOC2_TSC_LABELS: dict[str, str] = {
    "CC6.1": "Logical Access Security",
    "CC6.2": "Credential Registration and Management",
    "CC6.3": "Access Restrictions and Permissions",
    "CC6.6": "External Threat Protections",
    "CC6.7": "Transmission Protection",
    "CC6.8": "Malicious Software Prevention",
    "CC7.1": "System Operations Monitoring",
    "CC7.2": "System Anomaly Detection",
    "CC8.1": "Change Management Controls",
    "A1.2":  "System Recovery and Availability",
}

# ---------------------------------------------------------------------------
# GDPR / HIPAA / SOC 2 mappings — kept separate from CHECKPOINT_CIS_MAPPINGS
# so the original CIS crosswalk is not polluted. get_annotations() merges both.
# Covers all 61 CIS controls + Phase A (NAT/RQ/CERT) + Phase B (LOG) controls.
# ---------------------------------------------------------------------------
REGULATORY_MAPPINGS: dict[str, dict[str, list[str]]] = {
    # ── Section 1 — Password Policy ──────────────────────────────────────────
    "1.1":  {"gdpr": ["Art.32"], "hipaa": ["§164.312(d)", "§164.308(a)(5)"], "soc2": ["CC6.1", "CC6.2"]},
    "1.2":  {"gdpr": ["Art.32"], "hipaa": ["§164.312(d)"],                   "soc2": ["CC6.2"]},
    "1.3":  {"gdpr": ["Art.32"], "hipaa": ["§164.312(d)"],                   "soc2": ["CC6.2"]},
    "1.4a": {"gdpr": ["Art.32"], "hipaa": ["§164.312(d)"],                   "soc2": ["CC6.2"]},
    "1.4b": {"gdpr": ["Art.32"], "hipaa": ["§164.312(d)"],                   "soc2": ["CC6.2"]},
    "1.5":  {"gdpr": ["Art.32"], "hipaa": ["§164.312(d)", "§164.308(a)(3)"], "soc2": ["CC6.2"]},
    "1.6":  {"gdpr": ["Art.32"], "hipaa": ["§164.312(d)"],                   "soc2": ["CC6.2"]},
    "1.7":  {"gdpr": ["Art.32"], "hipaa": ["§164.308(a)(3)"],                "soc2": ["CC6.2"]},
    "1.8":  {"gdpr": ["Art.25", "Art.32"], "hipaa": ["§164.308(a)(3)"],      "soc2": ["CC6.2", "CC6.3"]},
    "1.9":  {"gdpr": ["Art.25", "Art.32"], "hipaa": ["§164.308(a)(3)"],      "soc2": ["CC6.2", "CC6.3"]},
    "1.10": {"gdpr": ["Art.32"], "hipaa": ["§164.312(d)"],                   "soc2": ["CC6.2"]},
    "1.11": {"gdpr": ["Art.32"], "hipaa": ["§164.312(d)", "§164.308(a)(5)"], "soc2": ["CC6.1"]},
    "1.12": {"gdpr": ["Art.32"], "hipaa": ["§164.312(a)(2)(iii)", "§164.308(a)(5)"], "soc2": ["CC6.1"]},
    "1.13": {"gdpr": ["Art.32"], "hipaa": ["§164.312(a)(2)(iii)"],           "soc2": ["CC6.1"]},
    # ── Section 2.1 — General Settings ───────────────────────────────────────
    "2.1.1":  {"gdpr": ["Art.32"],          "hipaa": ["§164.308(a)(5)"],               "soc2": ["CC6.1"]},
    "2.1.2":  {"gdpr": ["Art.32"],          "hipaa": ["§164.308(a)(5)"],               "soc2": ["CC6.1"]},
    "2.1.3":  {"gdpr": ["Art.32"],          "hipaa": ["§164.312(b)"],                  "soc2": ["CC7.1"]},
    "2.1.4":  {"gdpr": ["Art.32"],          "hipaa": ["§164.308(a)(7)"],               "soc2": ["CC8.1"]},
    "2.1.5":  {"gdpr": ["Art.25", "Art.32"],"hipaa": ["§164.312(a)(1)"],               "soc2": ["CC6.6"]},
    "2.1.6":  {"gdpr": ["Art.32"],          "hipaa": ["§164.312(e)(1)"],               "soc2": ["CC6.6"]},
    "2.1.7":  {"gdpr": ["Art.25", "Art.32"],"hipaa": ["§164.312(a)(1)"],               "soc2": ["CC6.6"]},
    "2.1.8":  {"gdpr": ["Art.32"],          "hipaa": ["§164.308(a)(1)"],               "soc2": ["CC6.1"]},
    "2.1.9":  {"gdpr": ["Art.32"],          "hipaa": ["§164.312(e)(1)", "§164.312(a)(2)(iv)"], "soc2": ["CC6.7"]},
    "2.1.10": {"gdpr": ["Art.25", "Art.32"],"hipaa": ["§164.312(a)(1)"],               "soc2": ["CC6.6"]},
    # ── Section 2.2 — SNMP ───────────────────────────────────────────────────
    "2.2.1": {"gdpr": ["Art.32"],           "hipaa": ["§164.312(e)(1)"],               "soc2": ["CC6.6", "CC6.7"]},
    "2.2.2": {"gdpr": ["Art.32"],           "hipaa": ["§164.312(e)(1)"],               "soc2": ["CC6.7"]},
    "2.2.3": {"gdpr": ["Art.32", "Art.33"], "hipaa": ["§164.312(b)"],                  "soc2": ["CC7.1"]},
    "2.2.4": {"gdpr": ["Art.32", "Art.33"], "hipaa": ["§164.312(b)"],                  "soc2": ["CC7.1"]},
    # ── Section 2.3 — NTP ────────────────────────────────────────────────────
    "2.3.1": {"gdpr": ["Art.32"],           "hipaa": ["§164.312(b)"],                  "soc2": ["CC7.1"]},
    "2.3.2": {"gdpr": ["Art.32"],           "hipaa": ["§164.312(b)"],                  "soc2": ["CC7.1"]},
    # ── Section 2.4 — Backup ─────────────────────────────────────────────────
    "2.4.1": {"gdpr": ["Art.32"],           "hipaa": ["§164.308(a)(7)"],               "soc2": ["A1.2"]},
    "2.4.2": {"gdpr": ["Art.32"],           "hipaa": ["§164.308(a)(7)"],               "soc2": ["A1.2"]},
    "2.4.3": {"gdpr": ["Art.32"],           "hipaa": ["§164.308(a)(7)"],               "soc2": ["A1.2"]},
    # ── Section 2.5 — Authentication ─────────────────────────────────────────
    "2.5.1": {"gdpr": ["Art.25", "Art.32"], "hipaa": ["§164.312(a)(2)(iii)"],          "soc2": ["CC6.1"]},
    "2.5.2": {"gdpr": ["Art.25", "Art.32"], "hipaa": ["§164.312(a)(2)(iii)"],          "soc2": ["CC6.1"]},
    "2.5.3": {"gdpr": ["Art.32"],           "hipaa": ["§164.312(e)(1)"],               "soc2": ["CC6.7"]},
    "2.5.4": {"gdpr": ["Art.32"],           "hipaa": ["§164.312(d)", "§164.308(a)(3)"],"soc2": ["CC6.1", "CC6.2"]},
    "2.5.5": {"gdpr": ["Art.25", "Art.32"], "hipaa": ["§164.312(a)(1)"],               "soc2": ["CC6.3", "CC6.6"]},
    # ── Section 2.6 — Logging ────────────────────────────────────────────────
    "2.6.1": {"gdpr": ["Art.32", "Art.33"], "hipaa": ["§164.312(b)"],                  "soc2": ["CC7.1"]},
    "2.6.2": {"gdpr": ["Art.32", "Art.33"], "hipaa": ["§164.312(b)"],                  "soc2": ["CC7.1"]},
    "2.6.3": {"gdpr": ["Art.32", "Art.33"], "hipaa": ["§164.312(b)"],                  "soc2": ["CC7.1"]},
    # ── Section 3 — Firewall Secure Settings ─────────────────────────────────
    "3.1":  {"gdpr": ["Art.25", "Art.32"], "hipaa": ["§164.312(a)(1)"],                "soc2": ["CC6.3", "CC6.6"]},
    "3.2":  {"gdpr": ["Art.25", "Art.32"], "hipaa": ["§164.312(a)(1)"],                "soc2": ["CC6.3"]},
    "3.3":  {"gdpr": ["Art.32"],           "hipaa": ["§164.308(a)(1)"],                "soc2": ["CC8.1"]},
    "3.4":  {"gdpr": ["Art.32"],           "hipaa": ["§164.312(b)"],                   "soc2": ["CC7.1", "CC7.2"]},
    "3.5":  {"gdpr": ["Art.25", "Art.32"], "hipaa": ["§164.312(a)(1)"],                "soc2": ["CC6.3", "CC6.6"]},
    "3.6":  {"gdpr": ["Art.25", "Art.32"], "hipaa": ["§164.312(a)(1)"],                "soc2": ["CC6.3", "CC6.6"]},
    "3.7":  {"gdpr": ["Art.25", "Art.32"], "hipaa": ["§164.312(a)(1)"],                "soc2": ["CC6.3"]},
    "3.8":  {"gdpr": ["Art.32", "Art.33"], "hipaa": ["§164.312(b)"],                   "soc2": ["CC7.1"]},
    "3.9":  {"gdpr": ["Art.32", "Art.33"], "hipaa": ["§164.312(b)"],                   "soc2": ["CC7.1"]},
    "3.10": {"gdpr": ["Art.32"],           "hipaa": ["§164.312(c)(1)"],                "soc2": ["CC6.6"]},
    "3.11": {"gdpr": ["Art.32"],           "hipaa": ["§164.312(c)(1)"],                "soc2": ["CC6.6"]},
    "3.12": {"gdpr": ["Art.32"],           "hipaa": ["§164.312(c)(1)"],                "soc2": ["CC6.6"]},
    "3.13": {"gdpr": ["Art.32"],           "hipaa": ["§164.312(b)"],                   "soc2": ["A1.2", "CC7.1"]},
    "3.14": {"gdpr": ["Art.25", "Art.32"], "hipaa": ["§164.312(a)(1)"],                "soc2": ["CC6.6"]},
    "3.15": {"gdpr": ["Art.25", "Art.32"], "hipaa": ["§164.312(a)(1)"],                "soc2": ["CC6.6"]},
    "3.16": {"gdpr": ["Art.25", "Art.32"], "hipaa": ["§164.312(a)(1)"],                "soc2": ["CC6.6"]},
    "3.17": {"gdpr": ["Art.25", "Art.32"], "hipaa": ["§164.312(a)(1)"],                "soc2": ["CC6.6"]},
    "3.18": {"gdpr": ["Art.32"],           "hipaa": ["§164.312(e)(1)"],                "soc2": ["CC6.6"]},
    "3.19": {"gdpr": ["Art.32"],           "hipaa": ["§164.312(e)(1)"],                "soc2": ["CC6.6"]},
    "3.20": {"gdpr": ["Art.32", "Art.33"], "hipaa": ["§164.312(b)"],                   "soc2": ["CC7.1"]},
    # ── Phase A — NAT Rulebase Quality ───────────────────────────────────────
    "NAT-1": {"gdpr": ["Art.32"],           "hipaa": ["§164.308(a)(1)"],               "soc2": ["CC7.2"]},
    "NAT-2": {"gdpr": ["Art.25", "Art.32"], "hipaa": ["§164.312(a)(1)"],               "soc2": ["CC6.6"]},
    "NAT-3": {"gdpr": ["Art.32", "Art.33"], "hipaa": ["§164.312(b)"],                  "soc2": ["CC7.1"]},
    # ── Phase A — Rulebase Quality ────────────────────────────────────────────
    "RQ-1":  {"gdpr": ["Art.25", "Art.32"], "hipaa": ["§164.312(a)(1)"],               "soc2": ["CC6.3"]},
    "RQ-2":  {"gdpr": ["Art.32"],           "hipaa": ["§164.308(a)(1)"],               "soc2": ["CC7.2"]},
    "RQ-3":  {"gdpr": ["Art.25", "Art.32"], "hipaa": ["§164.312(a)(1)"],               "soc2": ["CC6.6"]},
    "RQ-4":  {"gdpr": ["Art.32"],           "hipaa": ["§164.312(b)"],                  "soc2": ["CC6.8", "CC7.2"]},
    # ── Phase A — Certificate Inventory ──────────────────────────────────────
    "CERT-1": {"gdpr": ["Art.32"],          "hipaa": ["§164.312(e)(1)"],               "soc2": ["CC6.7"]},
    # ── Phase B — Log Retention & SIEM ───────────────────────────────────────
    "LOG-1": {"gdpr": ["Art.32", "Art.33"], "hipaa": ["§164.312(b)"],                  "soc2": ["CC7.1"]},
    "LOG-2": {"gdpr": ["Art.32", "Art.33"], "hipaa": ["§164.312(b)"],                  "soc2": ["CC7.1", "CC7.2"]},
    # ── Phase C — Identity & Access Management ────────────────────────────────
    "IAM-1": {"gdpr": ["Art.25", "Art.32"], "hipaa": ["§164.308(a)(3)", "§164.312(a)(1)"], "soc2": ["CC6.1", "CC6.2", "CC6.3"]},
    "IAM-2": {"gdpr": ["Art.25", "Art.32"], "hipaa": ["§164.308(a)(3)"],               "soc2": ["CC6.2", "CC6.3"]},
    "IAM-3": {"gdpr": ["Art.32"],           "hipaa": ["§164.312(d)"],                  "soc2": ["CC6.1"]},
    # ── Phase C — Architecture & Segmentation ────────────────────────────────
    "ARCH-1": {"gdpr": ["Art.25", "Art.32"], "hipaa": ["§164.312(a)(1)"],              "soc2": ["CC6.3", "CC6.6"]},
}


def get_annotations(control_id: str, selected_frameworks: list[str]) -> dict[str, list[str]]:
    """Return compliance control IDs for a check, filtered to selected frameworks.

    Merges CHECKPOINT_CIS_MAPPINGS (NIST/ISO/PCI/ATT&CK) with REGULATORY_MAPPINGS
    (GDPR/HIPAA/SOC2) so both legacy and new frameworks work from one call.
    Returns an empty dict if control_id is not mapped or no frameworks selected.
    """
    if not selected_frameworks:
        return {}
    mapping = {
        **CHECKPOINT_CIS_MAPPINGS.get(control_id, {}),
        **REGULATORY_MAPPINGS.get(control_id, {}),
    }
    return {fw: mapping.get(fw, []) for fw in selected_frameworks if fw in FRAMEWORKS}


def annotate_findings(findings: list[dict], selected_frameworks: list[str]) -> list[dict]:
    """Add a `compliance` key to each finding dict (non-destructive — copies)."""
    if not selected_frameworks:
        return findings
    result = []
    for f in findings:
        f = dict(f)
        f["compliance"] = get_annotations(f.get("control_id", ""), selected_frameworks)
        result.append(f)
    return result
