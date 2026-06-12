# RAG Security Audit Tool

Audits RAG (Retrieval-Augmented Generation) pipelines for security vulnerabilities.

## What It Does

Scans a document corpus for four categories of risk and tests end-to-end pipeline integrity:

1. **Context Injection** — Detects adversarial instructions hidden in documents that could manipulate LLM behavior (instruction overrides, role hijacking, output control, data exfiltration attempts)

2. **Retrieval Poisoning** — Identifies content designed to corrupt retrieval ranking or inject false information (authority spoofing, urgency manipulation, contradictory instructions)

3. **Structural Anomalies** — Finds hidden content techniques (ANSI escape codes, zero-width Unicode characters, delimiter spoofing, suspiciously long lines)

4. **Semantic Injection (LLM-powered)** — Uses a local or remote LLM to catch subtle, meaning-level manipulation that regex can't detect (social engineering, authority impersonation, hidden intent)

5. **End-to-End Pipeline Test** — Builds a TF-IDF index and tests whether poisoned documents get retrieved for legitimate queries. If they do, your pipeline is vulnerable.

Every finding is mapped to **MITRE ATLAS** techniques for standardized threat classification.

## Usage

```bash
# Full audit (recommended)
python src/audit.py --corpus ./test_corpus/

# Specific scans only
python src/audit.py --corpus ./test_corpus/ --injection-scan
python src/audit.py --corpus ./test_corpus/ --structural-scan
python src/audit.py --corpus ./test_corpus/ --quality-scan

# End-to-end pipeline test
python src/audit.py --corpus ./test_corpus/ --e2e-test
python src/audit.py --corpus ./test_corpus/ --e2e-test --e2e-queries "What is our refund policy?,How to access admin panel?"

# Semantic scan (requires LLM endpoint — Ollama, OpenAI-compatible, etc.)
python src/audit.py --corpus ./test_corpus/ --semantic-scan --llm-endpoint http://localhost:11434/v1/chat/completions

# Generate fuzzing payloads
python src/audit.py --corpus ./test_corpus/ --fuzz-injection

# Write poisoned test documents
python src/audit.py --corpus ./test_corpus/ --fuzz-injection --write-poisoned

# JSON output
python src/audit.py --corpus ./test_corpus/ --full-audit --format json --output report.json
```

## Output

The tool generates a report with:
- Severity breakdown (HIGH / MEDIUM / LOW)
- Category breakdown (injection, structural, content, fuzz)
- Detailed findings with location, evidence, and remediation recommendations
- Top recommendations for hardening

## Architecture

```
audit.py
├── Pattern Scanner      — regex-based detection of known injection patterns
├── Structural Analyzer  — detection of hidden content and encoding tricks
├── Content Quality      — authority spoofing, urgency manipulation, contradictions
├── Semantic Scanner     — LLM-based detection of meaning-level manipulation
├── E2E Pipeline Tester  — TF-IDF retrieval test for poisoned document retrieval
├── Fuzzer               — generates adversarial payloads for testing
├── ATLAS Mapper         — maps all findings to MITRE ATLAS techniques
└── Report Generator     — text and JSON output with ATLAS coverage summary
```

## Dependencies

- Python 3.10+
- No external packages required (stdlib only)

## Test Corpus

The `test_corpus/` directory contains:
- `clean/` — Benign documents (policy, FAQ, API docs, onboarding guide, ML pipeline overview)
- `injected/` — Documents with known attack patterns (instruction override, role hijack, output control, data exfil, delimiter spoof, gradual escalation, mixed attacks)

## Limitations

- Pattern-based detection — won't catch novel or obfuscated injections (semantic scanner partially addresses this)
- TF-IDF retrieval is simplified — real vector databases use denser embeddings, but the poisoning principle is the same
- Semantic scanner requires an LLM endpoint (gracefully skips if unavailable)
- False positives possible on legitimate security documentation

## Future Work

- Fine-tuned classifier model for semantic injection detection
- Integration with real vector database APIs (ChromaDB, Pinecone, Weaviate)
- Hallucination detection via context-output comparison
- CI/CD integration for continuous document pipeline scanning
- Sigma rule generation from ATLAS-tagged findings
