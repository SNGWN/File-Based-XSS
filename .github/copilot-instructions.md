# AI Coding Agent Project Instructions

Focus: This repo hosts two related offensive security research tools (PDF-XSS and Excel-XSS) for generating and analyzing file-based XSS / sandbox‑escape payloads. Your job is to extend/maintain payload generation, testing, export, and analysis utilities without breaking the strict repo structure or research orientation.

## 1. High-Level Architecture
- Root separates two independent sub‑tools:
  - `PDF-XSS/` → Active, versioned (v4.1 gen / v3.0 test / v3.0 analysis). Core scripts: `pdf_xss_generator.py`, `payload_tester.py`, `results_analyzer.py`, per‑browser JSON payload stores (`chrome.json`, etc.), and developer docs (`DEVELOPER_GUIDE.md`). Output PDFs go to `PDF-XSS/Files/`.
  - `Excel-XSS/` → Payload research exporter (`export_to_excel.py`) turning JSON payload DB into multi‑sheet, formatted Excel workbooks. Uses pandas + openpyxl; other code is pure stdlib.
- No shared Python package layer: each directory is a self‑contained CLI tool. Avoid introducing cross‑imports; keep zero external deps for PDF tool.

## 2. Conventions & Patterns
- Payload JSON schema (PDF): keys: `id, category, browser, technique, payload, description, risk_level, cve_reference?`. Placeholders `{url}` or hardcoded sample URLs are replaced at runtime (see `substitute_url_in_payload`). Preserve this placeholder strategy when adding payloads.
- Single PDF generation model: `pdf_xss_generator.py` now ALWAYS emits one PDF per browser selection containing all payloads (one payload per page). Do not re‑introduce legacy multi‑file mode.
- Output naming (PDF): `{browser}_all_payloads_<timestamp>.pdf`. Keep stable for any automation/analysis.
- Excel export naming: `excel_browser_payload_database_<timestamp>.xlsx`. Sheet titles are semantic and referenced in logs—preserve names when extending.
- Testing / scoring logic lives in `payload_tester.py`; weight distribution (syntax 40%, category 40%, compatibility 20%) is a core heuristic—if changed, update docs + analyzer.
- Risk & category scoring matrices are hardcoded; new categories must add: (a) category_scores, (b) documentation in README/DEVELOPER_GUIDE, (c) any analyzer logic.
- PDF tool must remain dependency‑free (stdlib only). Excel tool may use `pandas`, `openpyxl` only (avoid expanding unless essential and justified).

## 3. Typical Workflows
- List browsers / counts: `python3 pdf_xss_generator.py --list-browsers`.
- Generate Chrome PDF with substituted exfil URL: `python3 pdf_xss_generator.py -b chrome -u http://collaborator.test`.
- Limit payloads (dev sanity): `--count 5`.
- Validate payload quality & produce report: `python3 payload_tester.py -b all --report` → outputs `test_report_<timestamp>.json` in working dir.
- (Excel) Export research workbook: `cd Excel-XSS && pip install -r requirements.txt && python3 export_to_excel.py`.

## 4. Adding / Modifying PDF Payloads
1. Edit the correct browser JSON (no mixing browsers).
2. Ensure unique `id` naming pattern (`<browser>_<category>_<###>` or existing style) and meaningful `technique` slug.
3. Keep `{url}` placeholder or recognized sample URL so runtime substitution still works.
4. Run: `python3 payload_tester.py -b <browser>` and verify no syntax / category / compatibility regressions.
5. Generate sample: `python3 pdf_xss_generator.py -b <browser> --count 3` and manually open to confirm page rendering & embedded text visibility.
6. Update docs only if adding new category / risk semantics.

## 5. Safe Change Guidelines
- Do NOT add heavy libs to PDF tool (maintain portability & research reproducibility).
- Preserve log emojis & phrasing where feasible—downstream parsing may be loose but relies on recognizable tokens (e.g., "✅ Loaded", "📊", "🚀").
- Keep functions pure & small; new helpers should mirror existing naming (`verb_noun`), return tuples `(result, status)` only if needed (see patterns in tester script).
- When extending scoring, add unit‑style inline validation prints rather than external frameworks (project deliberately avoids formal test harness).

## 6. Common Pitfalls to Avoid
- Reverting to multi‑file PDF mode or renaming output directory `Files/`.
- Introducing circular logic by importing Excel tooling into PDF scripts.
- Hard‑substituting real exfil URLs in JSON (must stay placeholders for ethical use and substitution).
- Expanding requirements for Excel tool without explaining rationale in PR / documentation.

## 7. Extension Ideas (If Requested Only)
- Optional flag to emit minimal JSON summary alongside generated PDF (same filename stem). Default OFF to avoid altering current behavior.
- Lightweight analyzer enhancement to flag duplicate `hash_payload` collisions.
- Add dry‑run mode to tester (`--summary-only`) to speed large payload sets.

## 8. Quick Reference Key Files
- `PDF-XSS/pdf_xss_generator.py` (single-file PDF builder & URL substitution)
- `PDF-XSS/payload_tester.py` (syntax/category/compat scoring pipeline)
- `PDF-XSS/results_analyzer.py` (post‑processing & recommendations)
- `PDF-XSS/DEVELOPER_GUIDE.md` (payload schema & contribution flow)
- `Excel-XSS/export_to_excel.py` (multi‑sheet workbook assembly)

## 9. When Unsure
Prefer reading existing script banner docstrings & mirror style; ask before altering scoring heuristics, category taxonomy, or output naming.

---
Provide feedback if any workflow is missing or if you need deeper guidance on analyzer internals or JSON schema evolution.
