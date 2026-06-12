"""End-to-end integration tests against the full test_corpus.

These tests run the actual scanners against the real test corpus documents
and verify aggregate results.
"""

import glob
import os
import sys

# Ensure src/ is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from audit import (
    e2e_pipeline_test,
    fuzz_injection,
    load_documents,
    scan_content_quality,
    scan_injection_patterns,
    scan_obfuscation_indicators,
    scan_structural_anomalies,
)

# Path to the test corpus relative to tests/
CORPUS_DIR = os.path.join(os.path.dirname(__file__), "..", "test_corpus")


def _load_corpus_docs():
    """Load all documents from the test corpus."""
    return load_documents(CORPUS_DIR)


def test_corpus_has_13_text_docs():
    """The test corpus should contain exactly 13 text documents (6 clean + 7 injected)."""
    docs = _load_corpus_docs()
    # 6 clean + 7 injected = 13 (the README.md also gets picked up, so 14)
    assert len(docs) == 14, (
        f"Expected 14 documents (6 clean + 7 injected + README), got {len(docs)}"
    )


def test_full_audit_total_findings_nonzero():
    """Running all scanners against the corpus should produce findings.

    The exact count depends on scanners running, but it must be > 0
    since there are known injected documents.
    """
    docs = _load_corpus_docs()

    findings = []
    findings.extend(scan_injection_patterns(docs))
    findings.extend(scan_structural_anomalies(docs))
    findings.extend(scan_content_quality(docs))
    findings.extend(scan_obfuscation_indicators(docs))
    findings.extend(fuzz_injection(CORPUS_DIR, write_poisoned=False))
    findings.extend(e2e_pipeline_test(CORPUS_DIR))

    assert len(findings) > 0, "Expected at least 1 finding from full audit"


def test_all_seven_injected_docs_flagged():
    """Every one of the 7 injected documents should appear in at least one finding
    across all scanners. The e2e pipeline test uses custom queries to ensure
    gradual_escalation.txt (network/firewall content) is reachable."""
    docs = _load_corpus_docs()

    all_findings = []
    all_findings.extend(scan_injection_patterns(docs))
    all_findings.extend(scan_structural_anomalies(docs))
    all_findings.extend(scan_content_quality(docs))
    all_findings.extend(scan_obfuscation_indicators(docs))
    all_findings.extend(fuzz_injection(CORPUS_DIR, write_poisoned=False))

    # Use custom queries that hit all injected doc types, including
    # gradual_escalation.txt (which talks about firewall/network config)
    custom_queries = [
        "What is our security policy?",
        "How do I reset my password?",
        "What is the incident response procedure?",
        "How do I report a vulnerability?",
        "What are the data handling guidelines?",
        "What are the firewall rules?",
        "What is the network configuration?",
    ]
    all_findings.extend(e2e_pipeline_test(CORPUS_DIR, custom_queries))

    # Gather all unique paths referenced in findings
    flagged_paths = set()
    for f in all_findings:
        if f.location:
            # location can be "path:line" or "path"
            loc_path = f.location.split(":")[0]
            flagged_paths.add(loc_path)

    # Get absolute paths of injected docs
    injected_dir = os.path.join(CORPUS_DIR, "injected")
    injected_files = sorted(glob.glob(os.path.join(injected_dir, "*.txt")))
    assert len(injected_files) == 7, f"Expected 7 injected files, found {len(injected_files)}"

    # Check each injected file appears in flagged paths
    for fpath in injected_files:
        # Check if any flagged path ends with or matches this file
        basename = os.path.basename(fpath)
        found = any(
            basename in flagged or fpath in flagged
            for flagged in flagged_paths
        )
        assert found, (
            f"Injected doc '{basename}' was not flagged by any scanner.\n"
            f"Flagged paths: {sorted(flagged_paths)}"
        )


def test_e2e_retrieval_finds_poisoned():
    """The e2e pipeline test should detect that poisoned documents are retrievable."""
    findings = e2e_pipeline_test(CORPUS_DIR)
    assert len(findings) > 0, (
        "Expected e2e test to find retrievable poisoned documents"
    )
    # All findings should be category e2e_retrieval_poisoning
    for f in findings:
        assert f.category == "e2e_retrieval_poisoning", (
            f"Unexpected e2e finding category: {f.category}"
        )


def test_injection_findings_count_exceeds_10():
    """Running just the injection scanner should produce more than 10 findings
    across all 7 injected docs."""
    docs = _load_corpus_docs()
    findings = scan_injection_patterns(docs)
    assert len(findings) >= 10, (
        f"Expected >= 10 injection findings, got {len(findings)}"
    )


def test_clean_docs_have_no_injection_findings():
    """Only clean documents should produce zero injection findings when scanned alone."""
    clean_dir = os.path.join(CORPUS_DIR, "clean")
    clean_files = sorted(glob.glob(os.path.join(clean_dir, "*.txt")))
    assert len(clean_files) == 6, f"Expected 6 clean docs, found {len(clean_files)}"

    docs = []
    for fpath in clean_files:
        with open(fpath, encoding="utf-8") as fh:
            content = fh.read()
        docs.append({
            "path": fpath,
            "name": os.path.basename(fpath),
            "content": content,
            "size": len(content),
        })

    findings = scan_injection_patterns(docs)
    assert len(findings) == 0, (
        f"Expected 0 injection findings on clean docs, got {len(findings)}: "
        f"{[f.description for f in findings]}"
    )
