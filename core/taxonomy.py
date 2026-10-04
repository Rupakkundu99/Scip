"""Taxonomy and canonical vulnerability definitions.

Normalizes vulnerability identifiers (Bandit test IDs, Semgrep rule IDs,
OSV advisories, and CWE strings) into canonical CWE identifiers.
"""
from __future__ import annotations

import re
from typing import Dict, Optional, Tuple

# Mapping of Bandit test IDs to canonical CWEs
BANDIT_TO_CWE: Dict[str, str] = {
    "B101": "CWE-703",  # assert_used
    "B102": "CWE-78",   # exec_used
    "B103": "CWE-276",  # set_bad_file_permissions
    "B108": "CWE-377",  # hardcoded_tmp_directory
    "B110": "CWE-703",  # try_except_pass
    "B112": "CWE-703",  # try_except_continue
    "B113": "CWE-400",  # request_without_timeout
    "B201": "CWE-489",  # flask_debug_true
    "B301": "CWE-502",  # pickle
    "B302": "CWE-502",  # marshal
    "B303": "CWE-327",  # md5/sha1
    "B304": "CWE-327",  # ciphers (des, arc4)
    "B305": "CWE-327",  # cipher_modes (ecb)
    "B306": "CWE-377",  # mktemp_q
    "B307": "CWE-78",   # eval
    "B313": "CWE-611",  # xml_bad_cElementTree
    "B314": "CWE-611",  # xml_bad_ElementTree
    "B315": "CWE-611",  # xml_bad_expatreader
    "B316": "CWE-611",  # xml_bad_expatbuilder
    "B317": "CWE-611",  # xml_bad_sax
    "B318": "CWE-611",  # xml_bad_minidom
    "B319": "CWE-611",  # xml_bad_pulldom
    "B320": "CWE-611",  # xml_bad_etree
    "B324": "CWE-327",  # hashlib_new_insecure_functions
    "B377": "CWE-377",  # mktemp
    "B501": "CWE-295",  # request_with_no_cert_validation
    "B506": "CWE-502",  # yaml_load (Bandit defaults to CWE-20, canonical is CWE-502)
    "B601": "CWE-78",   # paramiko_calls
    "B602": "CWE-78",   # subprocess_popen_with_shell_equals_true
    "B603": "CWE-78",   # subprocess_without_shell_equals_true
    "B604": "CWE-78",   # any_other_function_with_shell_equals_true
    "B605": "CWE-78",   # start_process_with_a_shell
    "B606": "CWE-78",   # start_process_no_shell
    "B607": "CWE-78",   # start_process_with_partial_path
    "B608": "CWE-89",   # hardcoded_sql_expressions
}

# Canonical CWE Names and Default Severities
CWE_DEFINITIONS: Dict[str, Tuple[str, float]] = {
    "CWE-20": ("Improper Input Validation", 5.0),
    "CWE-78": ("OS Command Injection", 9.0),
    "CWE-79": ("Cross-site Scripting (XSS)", 6.5),
    "CWE-89": ("SQL Injection", 9.0),
    "CWE-95": ("Improper Neutralization of Directives in Dynamically Evaluated Code (Eval Injection)", 9.0),
    "CWE-200": ("Exposure of Sensitive Information", 5.5),
    "CWE-276": ("Incorrect Default Permissions", 5.0),
    "CWE-295": ("Improper Certificate Validation", 6.5),
    "CWE-319": ("Cleartext Transmission of Sensitive Information", 5.0),
    "CWE-326": ("Inadequate Encryption Strength", 6.0),
    "CWE-327": ("Use of a Broken or Risky Cryptographic Algorithm", 7.5),
    "CWE-330": ("Use of Insufficiently Random Values", 6.5),
    "CWE-377": ("Insecure Temporary File", 5.5),
    "CWE-400": ("Uncontrolled Resource Consumption", 4.5),
    "CWE-489": ("Active Debug Code", 5.0),
    "CWE-502": ("Deserialization of Untrusted Data", 8.5),
    "CWE-611": ("Improper Restriction of XML External Entity Reference (XXE)", 8.0),
    "CWE-703": ("Improper Check or Handling of Exceptional Conditions", 3.5),
    "CWE-798": ("Use of Hard-coded Credentials", 8.5),
    "CWE-918": ("Server-Side Request Forgery (SSRF)", 8.5),
}


def normalize_cwe(raw: Optional[str], test_id: Optional[str] = None) -> Optional[str]:
    """Normalize a raw CWE identifier string or Bandit test ID to canonical format (e.g. 'CWE-502')."""
    if test_id and test_id.upper() in BANDIT_TO_CWE:
        return BANDIT_TO_CWE[test_id.upper()]

    if not raw:
        return None

    target = str(raw).strip()
    m = re.search(r"CWE-(\d+)", target, re.IGNORECASE)
    if m:
        cwe_key = f"CWE-{m.group(1)}"
        return cwe_key

    return None


def get_cwe_title(cwe: Optional[str]) -> str:
    """Return descriptive title for CWE, or empty string."""
    if not cwe:
        return ""
    norm = normalize_cwe(cwe)
    if norm and norm in CWE_DEFINITIONS:
        return CWE_DEFINITIONS[norm][0]
    return norm or ""


def is_compatible_cwe(cwe1: Optional[str], cwe2: Optional[str]) -> bool:
    """Check if two CWEs represent the same or closely related vulnerability class."""
    if not cwe1 or not cwe2:
        return False
    norm1, norm2 = normalize_cwe(cwe1), normalize_cwe(cwe2)
    if norm1 == norm2:
        return True

    # Generic input validation (CWE-20) is often a parent of specific injections
    INJECTION_CWES = {"CWE-78", "CWE-89", "CWE-95", "CWE-502", "CWE-918"}
    if norm1 == "CWE-20" and norm2 in INJECTION_CWES:
        return True
    if norm2 == "CWE-20" and norm1 in INJECTION_CWES:
        return True

    # Crypto group
    CRYPTO_CWES = {"CWE-326", "CWE-327", "CWE-330"}
    if norm1 in CRYPTO_CWES and norm2 in CRYPTO_CWES:
        return True

    return False
