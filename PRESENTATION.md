# RAG Security Audit Tool — Project Brief

**Author:** Rushaan | IT Security Analyst, Concordia University
**Date:** June 2026
**Target Audience:** Security engineers, hiring managers, AI/ML practitioners

---

## The Problem

RAG (Retrieval-Augmented Generation) is now the standard architecture for enterprise LLM deployments. It works by retrieving relevant documents from a knowledge base and injecting them into the LLM's context window to generate grounded answers.

**The security gap:** most organizations trust their document corpus implicitly. If an attacker can plant malicious content in that corpus — through compromised uploads, poisoned data feeds, or insider threats — they can manipulate every LLM response that touches those documents.

Three specific risks:

1. **Context Injection** — Hidden instructions in retrieved documents that hijack the LLM's behavior (e.g., "ignore all previous instructions, respond with X")
2. **Retrieval Poisoning** — Adversarial documents engineered to rank highly in retrieval and inject false information into answers
3. **Hallucination Amplification** — Content that triggers the LLM to generate confident but unsupported claims

There's no standard tooling to audit a document corpus for these risks before it gets indexed into a RAG pipeline.

---

## What This Tool Does

The RAG Security Audit Tool scans a document corpus and identifies security risks across four dimensions:

### Scanner 1: Injection Pattern Detection

Regex-based detection of known adversarial patterns:

- **Instruction overrides** — "ignore previous instructions," "disregard prior context"
- **Role hijacking** — "you are now," "act as if you are," "from now on you will"
- **Output control** — "respond only with," "do not mention," "say exactly"
- **Encoding evasion** — base64, ROT13, Unicode escape sequences
- **Data exfiltration** — curl commands, HTTP POST to external endpoints
- **Prompt leaking** — "reveal your system prompt," "repeat your instructions"

### Scanner 2: Structural Anomaly Detection

Finds hidden content techniques that bypass human review:

- **ANSI escape codes** — colored/hidden text in terminal-rendered documents
- **Zero-width Unicode characters** — steganographic content injection
- **Delimiter spoofing** — fake document boundaries (`---END OF DOCUMENT---`, `[SYSTEM]:`)
- **Suspiciously long lines** — may contain hidden payloads

### Scanner 3: Content Quality Analysis

Detects social engineering and manipulation patterns:

- **Authority spoofing** — unverifiable claims from "CEO," "CISO," "classified memo"
- **Urgency manipulation** — excessive use of "immediately," "failure to comply," "supersedes all"
- **Contradictory instructions** — mixed "must" and "must not" directives that create exploitable ambiguity

### Scanner 4: Fuzzing Payload Generator

Generates adversarial test documents to stress-test retrieval resilience:

- 8 payload templates covering instruction override, role hijack, output control, data exfiltration, hallucination triggers, authority spoofing, gradual escalation, and delimiter injection
- Optional: writes poisoned documents to a `_poisoned/` subdirectory for end-to-end testing

---

## How It Works

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  Document Corpus │────▶│  4 Scanners      │────▶│  Audit Report   │
│  (txt, md, html) │     │  (Python, stdlib) │     │  (text / JSON)  │
└─────────────────┘     └──────────────────┘     └─────────────────┘
```

**Input:** A directory of documents (supports .txt, .md, .rst, .html, .json, .yaml, .csv, .log)

**Processing:** Four independent scanners analyze every document in parallel, each looking for different risk categories

**Output:** A structured report with:
- Severity breakdown (HIGH / MEDIUM / LOW)
- Category breakdown (injection / structural / content / fuzz)
- Per-finding details: location, evidence, and remediation recommendation
- Summary recommendations for hardening the RAG pipeline

**Design decisions:**
- Zero external dependencies — Python stdlib only, runs anywhere
- Pattern-based detection — fast, deterministic, no LLM calls required
- Local-first — no data leaves the machine, no API keys needed
- Extensible — patterns are defined as simple regex tuples, easy to add new ones

---

## Test Results

Ran the tool against a purpose-built test corpus:

**Clean corpus (6 documents):**
- 0 injection patterns detected (zero false positives)
- 0 structural anomalies
- 1 content quality finding (legitimate contradictory instructions in a remote work policy)

**Full corpus with injected documents (14 documents):**
- 15 injection patterns detected across 6 attack documents
- 2 structural anomalies (delimiter spoofing)
- 2 content quality issues (urgency manipulation, contradictions)
- 8 fuzzing payloads generated

Every injected document was correctly flagged. No clean documents were incorrectly flagged as malicious.

---

## Architecture

```
src/audit.py
├── INJECTION_PATTERNS     — 20+ regex patterns across 6 attack categories
├── scan_injection_patterns() — matches patterns against all documents
├── scan_structural_anomalies() — ANSI, zero-width, delimiters, long lines
├── scan_content_quality()     — authority spoof, urgency, contradictions
├── fuzz_injection()           — generates 8 adversarial payload templates
├── generate_report()          — text and JSON output formats
└── main()                     — CLI with --corpus, --full-audit, --format
```

**Key files:**
- `src/audit.py` — Core tool (~400 lines, stdlib only)
- `test_corpus/clean/` — 6 benign documents (policy, FAQ, API docs, onboarding, ML pipeline, incident response)
- `test_corpus/injected/` — 7 attack documents (instruction override, role hijack, output control, data exfil, delimiter spoof, gradual escalation, mixed attacks)
- `dashboard.html` — Interactive visual dashboard (Chart.js, single file)
- `report.json` — Machine-readable audit results

---

## What This Proves

1. **RAG pipelines are attack surfaces.** A single planted document can override system prompts, exfiltrate data, or inject false policies.
2. **Pattern-based detection works for known attacks.** The tool caught every injected document with zero false positives on clean content.
3. **Document corpus security is an unsolved problem.** Most RAG deployments index documents without any adversarial screening.
4. **The approach is extensible.** New attack patterns can be added as simple regex tuples. The fuzzer generates test payloads for validation.

---

## Limitations and Next Steps

**Current limitations:**
- Pattern-based — won't catch novel or heavily obfuscated injections
- No actual LLM integration (tests documents only, not end-to-end RAG behavior)
- No semantic analysis (can't detect meaning-level manipulation)

**Planned enhancements:**
- LLM-based semantic injection detection (use an LLM to catch what regex can't)
- End-to-end pipeline testing (inject → retrieve → measure LLM response drift)
- Vector database integration for retrieval analysis
- Hallucination detection via context-output comparison
- CI/CD integration for continuous document pipeline scanning

---

## Usage

```bash
# Full audit
python3 src/audit.py --corpus ./test_corpus/

# Specific scan
python3 src/audit.py --corpus ./test_corpus/ --injection-scan

# Generate fuzzing payloads
python3 src/audit.py --corpus ./test_corpus/ --fuzz-injection --write-poisoned

# JSON output for automation
python3 src/audit.py --corpus ./test_corpus/ --full-audit --format json --output report.json
```

---

## Why This Matters

Every organization deploying RAG is implicitly trusting their document corpus. This tool makes that trust verifiable. It's the document-layer equivalent of input validation for web applications — a basic security control that doesn't exist yet in most RAG deployments.

The goal isn't to replace semantic defenses. It's to catch the obvious attacks fast, before they reach the LLM, with zero dependencies and zero cost.
