# PDF-XSS Generator v4.3

Renderer-focused PDF payload generation for authorized security testing.

This tool keeps the Python side intentionally small: it loads browser-specific payload JSON, normalizes placeholders and metadata, optionally runs payload QA, and emits a single byte-correct PDF with one payload per page. The main research surface is the payload corpus, with priority on primary browser renderers:

- **Chrome / Edge**: PDFium
- **Firefox**: PDF.js
- **Safari**: PDFKit
- **Adobe Reader / Acrobat**: secondary track

## Scope

- **Stdlib only** for the PDF tool
- **Single PDF per browser selection**
- **One payload per page**
- **Renderer-aware metadata normalization**
- **Research-backed profile selection**
- **Built-in payload QA** for duplicate IDs, duplicate payload hashes, hardcoded callback URLs, and category coverage

## Files

```text
PDF-XSS/
├── pdf_xss_generator.py
├── config.json
├── chrome.json
├── firefox.json
├── safari.json
├── edge.json
├── adobe.json
├── requirements.txt
└── Files/
```

## Quick start

```bash
cd PDF-XSS

# List supported renderers and payload counts
python3 pdf_xss_generator.py --list-browsers

# List research-backed selection profiles
python3 pdf_xss_generator.py --list-profiles

# Generate a Chrome/PDFium test file
python3 pdf_xss_generator.py -b chrome -u http://collector.test

# Generate a high-signal cross-renderer sample
python3 pdf_xss_generator.py -b all -u http://collector.test --profile high-signal --count 12

# Generate a smaller Firefox/PDF.js sample
python3 pdf_xss_generator.py -b firefox -u http://collector.test --count 10

# Run payload QA across every browser dataset
python3 pdf_xss_generator.py -b all --validate-payloads

# Save the QA report to JSON
python3 pdf_xss_generator.py -b all --validate-payloads --report-file payload_report.json
```

## CLI

| Flag | Description |
| --- | --- |
| `-b, --browser` | `chrome`, `firefox`, `safari`, `adobe`, `edge`, or `all` |
| `-u, --url` | Controlled callback or navigation target used for placeholder substitution |
| `-o, --output-dir` | Output directory for generated PDFs |
| `--count` | Limit payload count in generated output |
| `--pdf-version` | PDF version to emit (`1.0`-`2.0`) |
| `--list-browsers` | Show browser targets and payload counts without requiring `--url` |
| `--list-profiles` | Show research-backed payload profiles |
| `--validate-payloads` | Run payload QA instead of generating a PDF |
| `--profile` | Filter generation to a research-backed profile such as `high-signal`, `blind-oast`, `sbx`, `pdfjs`, `bridge-probes`, `upload-preview`, or `aggressive-research` |
| `--report-file` | Save QA output as JSON |
| `--log-level` | `DEBUG`, `INFO`, `WARNING`, or `ERROR` |
| `--log-file` | Optional log file path |

## Output model

Generated files use:

```text
{selection}_all_payloads_{timestamp}.pdf
```

Examples:

- `chrome_all_payloads_20260505_155816.pdf`
- `all_all_payloads_20260505_160102.pdf`

Each page includes:

- normalized payload metadata,
- renderer, research tier, and validation stage,
- method family, signal strength, and boundary target,
- delivery-path and blind-validation hints,
- expected signal and user-gesture hints,
- the runtime payload with `{url}` substituted.

## Payload dataset model

Each browser JSON file contains:

1. top-level browser metadata,
2. optional default payload metadata,
3. a `payloads` array.

Example:

```json
{
  "metadata": {
    "browser": "chrome",
    "renderer": "PDFium",
    "default_payload_metadata": {
      "trigger": "document_open",
      "preconditions": ["JavaScript enabled in the embedded PDF viewer"]
    }
  },
  "payloads": [
    {
      "id": "chrome_dom_access_001",
      "category": "dom_access",
      "browser": "chrome",
      "technique": "parent_window_navigation",
      "payload": "try { parent.location = '{url}'; } catch (e) {}",
      "description": "Parent window reachability probe",
      "risk_level": "high",
      "research_tier": "validation"
    }
  ]
}
```

### Normalization behavior

The generator normalizes known sample callback URLs to the canonical `{url}` token at runtime. It also enriches payloads with renderer-focused fields when they are missing:

- `renderer`
- `method_family`
- `signal_strength`
- `validation_stage`
- `trigger`
- `requires_user_gesture`
- `expected_signal`
- `delivery_paths`
- `blind_channels`
- `host_context`
- `boundary_target`
- `evidence_level`
- `profile_tags`
- `source_tags`
- `preconditions`
- `bug_bounty_value`
- `stability`
- `research_tier`
- `payload_hash`

Duplicate source IDs are normalized in memory so generated PDFs and QA reports remain stable even when the raw dataset still needs cleanup.

Top-level browser metadata can also carry curation hints such as:

- `validation_focus_categories`
- `aggressive_focus_categories`
- `sbx_focus`
- `recommended_profiles`
- `preferred_delivery_paths`
- `research_highlights`
- `recommended_validation_payloads`
- `recommended_aggressive_payloads`

These are intended to keep the primary SBX workflow obvious for PDFium, PDF.js, and PDFKit without adding more generator complexity.

## Research-backed profiles

The tool now exposes a small set of selection profiles based on repeated public research patterns:

- `high-signal`: strongest practical validation and boundary probes first
- `blind-oast`: payloads suited to collaborator/callback-first validation
- `sbx`: sandbox-boundary, bridge, and escape-adjacent probes
- `pdfjs`: prioritize Firefox/PDF.js and hosted viewer-context checks
- `bridge-probes`: prioritize WebView, `postMessage`, and message-handler paths
- `upload-preview`: prioritize inline preview, admin review, and downstream render paths
- `aggressive-research`: lower-stability research payloads after validation succeeds

The profiles are intentionally lightweight. They filter the existing corpus instead of introducing a separate orchestration layer.

## Payload QA

`--validate-payloads` builds a summary across the selected dataset and reports:

- duplicate source IDs,
- duplicate normalized payload hashes,
- hardcoded callback URLs that were normalized to `{url}`,
- unsupported or unexpected categories,
- per-browser category and research-tier coverage.

This is meant to keep the payload corpus usable without introducing a separate testing framework.

## Workflow notes

For practical bug-bounty use:

1. Identify the likely renderer first.
2. Start with **validation-tier** payloads and a controlled callback target.
3. Use a profile such as `high-signal`, `blind-oast`, or `pdfjs` to reduce noise.
4. Use `--count` to keep the initial file small.
5. Record the observed signal per renderer, delivery path, and host application.
6. Escalate to **aggressive** research-tier payloads only in explicitly authorized testing.

## Configuration

`config.json` is used for:

- default output directory,
- default PDF version,
- max requested payload count,
- browser-to-renderer mapping,
- supported category definitions.

The config file is intentionally small and limited to runtime behavior. Payload curation and SBX guidance live in the browser JSON metadata instead.

## Safety

This repository is for **authorized security testing and research only**. Test only with explicit permission and prefer low-risk validation payloads before attempting more invasive behavior.
