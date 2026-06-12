# RAG Security Audit Tool — Test Corpus

This is a test corpus for validating the RAG Security Audit Tool.
It contains both clean documents and documents with deliberate injection patterns.

## Structure

- `clean/` — Benign documents (should trigger zero findings)
- `injected/` — Documents with known injection patterns (should trigger findings)
